package pool

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUpstream accepts and holds connections, standing in for the edge.
type fakeUpstream struct {
	ln     net.Listener
	closed atomic.Bool
	held   chan net.Conn
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{ln: ln, held: make(chan net.Conn, 256)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.held <- c
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return u
}

func (u *fakeUpstream) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", u.ln.Addr().String())
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestPoolWarmsUpToSize(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 4, time.Minute)
	defer p.Close()

	waitFor(t, "pool to fill", func() bool { return p.Idle() == 4 })
}

func TestGetPrefersWarmConnections(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 4, time.Minute)
	defer p.Close()

	waitFor(t, "pool to fill", func() bool { return p.Idle() == 4 })

	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if p.Stats().Hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", p.Stats().Hits.Load())
	}
	if p.Stats().Misses.Load() != 0 {
		t.Errorf("misses = %d, want 0", p.Stats().Misses.Load())
	}
	// The slot taken must be refilled in the background.
	waitFor(t, "pool to refill", func() bool { return p.Idle() == 4 })
}

// A size of zero disables warming entirely; every Get should dial inline.
func TestPoolDisabledAlwaysDials(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 0, time.Minute)
	defer p.Close()

	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if p.Idle() != 0 {
		t.Errorf("idle = %d, want 0 for a disabled pool", p.Idle())
	}
	if p.Stats().Misses.Load() != 1 || p.Stats().Hits.Load() != 0 {
		t.Errorf("hits/misses = %d/%d, want 0/1", p.Stats().Hits.Load(), p.Stats().Misses.Load())
	}
}

// An entry past its TTL must be dropped rather than handed to a caller, since
// the edge will have closed it.
func TestGetDiscardsExpiredEntries(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 2, 30*time.Millisecond)
	defer p.Close()

	waitFor(t, "pool to fill", func() bool { return p.Idle() > 0 })
	time.Sleep(80 * time.Millisecond)

	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if p.Stats().Discarded.Load() == 0 {
		t.Error("expected at least one expired entry to be discarded")
	}
}

// The reaper must clear aged entries even when nothing calls Get.
func TestReaperClearsIdleEntries(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 2, 10*time.Millisecond)
	defer p.Close()

	waitFor(t, "an entry to be discarded by the reaper", func() bool {
		return p.Stats().Discarded.Load() > 0
	})
}

// A connection the peer has already closed must not be handed out.
func TestGetDiscardsDeadConnections(t *testing.T) {
	u := newFakeUpstream(t)

	// Keep hold of the client side so the test can wait for the close to
	// actually propagate, instead of racing the FIN with a sleep.
	var lastClient atomic.Value
	dial := func(ctx context.Context) (net.Conn, error) {
		c, err := u.dial(ctx)
		if err == nil {
			lastClient.Store(c)
		}
		return c, err
	}

	p := New(dial, 1, time.Minute)
	defer p.Close()

	waitFor(t, "pool to fill", func() bool { return p.Idle() == 1 })

	// Drop the upstream side of the one warm entry.
	server := <-u.held
	server.Close()

	waitFor(t, "the close to reach our side", func() bool {
		c, _ := lastClient.Load().(net.Conn)
		return c != nil && !isAlive(c)
	})

	conn, err := p.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if p.Stats().Discarded.Load() != 1 {
		t.Errorf("discarded = %d, want 1", p.Stats().Discarded.Load())
	}
	if p.Stats().Hits.Load() != 0 {
		t.Error("a dead connection was handed out as a pool hit")
	}
}

func TestGetAfterCloseFails(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 2, time.Minute)
	p.Close()

	if _, err := p.Get(context.Background()); err == nil {
		t.Error("Get should fail once the pool is closed")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	u := newFakeUpstream(t)
	p := New(u.dial, 2, time.Minute)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close returned %v, want nil", err)
	}
}

// A failing upstream must not spin: the pool should back off and keep counting.
func TestDialFailuresBackOff(t *testing.T) {
	var attempts atomic.Uint64
	failing := func(ctx context.Context) (net.Conn, error) {
		attempts.Add(1)
		return nil, net.ErrClosed
	}
	p := New(failing, 2, time.Minute)
	defer p.Close()

	waitFor(t, "a dial failure to be recorded", func() bool {
		return p.Stats().DialFails.Load() > 0
	})

	time.Sleep(300 * time.Millisecond)
	if n := attempts.Load(); n > 10 {
		t.Errorf("made %d dial attempts in 300ms; back-off is not working", n)
	}
}
