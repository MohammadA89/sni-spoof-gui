//go:build windows

// Package tunnel exposes the spoofed transport as a local TCP listener.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/config"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/netutil"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/pool"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/relay"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/spoof"
)

// upstreamDialTimeout bounds one inline upstream dial when the pool is empty.
const upstreamDialTimeout = 15 * time.Second

// Stats are the live counters the UI polls.
type Stats struct {
	Accepted  atomic.Uint64
	Failed    atomic.Uint64
	Active    atomic.Int64
	BytesUp   atomic.Uint64
	BytesDown atomic.Uint64
}

// Tunnel accepts local TCP connections and relays each one over a freshly
// spoofed connection to the edge.
//
// It carries no protocol of its own. A client such as Xray or v2rayN is pointed
// at the listener with its own server config, and its TLS handshake, its SNI
// and its proxy protocol all travel through untouched. This app only ensures
// the TCP path underneath them is one DPI has already waved through.
type Tunnel struct {
	cfg    config.Config
	engine *spoof.Engine
	pool   *pool.Pool
	logf   func(string, ...any)

	ln     net.Listener
	router *router
	stats  Stats

	mu      sync.Mutex
	running bool

	errMu    sync.Mutex
	lastErr  string
	errCount int

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New prepares a tunnel from cfg. Nothing is opened until Start is called.
func New(cfg config.Config, logf func(string, ...any)) (*Tunnel, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Tunnel{cfg: cfg, logf: logf}, nil
}

// Start opens the WinDivert handle, warms the pool and begins accepting.
// It requires administrator rights.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return errors.New("tunnel: already running")
	}

	edge, err := t.cfg.Transport.PrimaryEdge()
	if err != nil {
		return err
	}
	iface, err := netutil.DefaultInterfaceIPv4(edge)
	if err != nil {
		return err
	}
	t.logf("routing to %s via interface %s", edge, iface)

	rt, err := newRouter(t.cfg.Transport.EdgeIPs, t.logf)
	if err != nil {
		return err
	}
	t.router = rt
	if n := len(rt.all()); n > 1 {
		t.logf("%d ranked routes available for failover", n)
	}

	var engine *spoof.Engine
	var dial pool.DialFunc

	if t.cfg.Transport.Spoof {
		engine, err = spoof.NewEngine(spoof.Config{
			InterfaceIP: iface,
			EdgeIP:      edge,
			EdgePort:    uint16(t.cfg.Transport.EdgePort),
			FakeSNI:     t.cfg.Transport.FakeSNI,
			Mode:        spoof.Mode(t.cfg.Transport.Mode),
			InjectDelay: t.cfg.Transport.InjectDelay(),
			PortLow:     uint16(t.cfg.Transport.PortLow),
			PortHigh:    uint16(t.cfg.Transport.PortHigh),
			// Every ranked address has to be capturable, or a failover would
			// switch to a route whose handshakes are never injected.
			AnyEdge: len(rt.all()) > 1,
			OnEvent: func(msg string) { t.logf("%s", msg) },
		})
		if err != nil {
			return err
		}
		if err := engine.Start(); err != nil {
			return err
		}
		dial = func(ctx context.Context) (net.Conn, error) {
			conn, err := engine.DialTo(ctx, rt.current())
			if err != nil {
				rt.failure()
				return nil, err
			}
			rt.success()
			return conn, nil
		}
	} else {
		t.logf("spoofing is OFF: relaying straight through, for comparison only")
		dial = func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			addr := net.JoinHostPort(rt.current().String(), strconv.Itoa(t.cfg.Transport.EdgePort))
			conn, err := d.DialContext(ctx, "tcp4", addr)
			if err != nil {
				rt.failure()
				return nil, err
			}
			rt.success()
			if tc, ok := conn.(*net.TCPConn); ok {
				_ = tc.SetNoDelay(true)
			}
			return conn, nil
		}
	}

	ln, err := net.Listen("tcp", t.cfg.Listener.Addr())
	if err != nil {
		if engine != nil {
			engine.Close()
		}
		return fmt.Errorf("tunnel: listen on %s: %w", t.cfg.Listener.Addr(), err)
	}

	t.engine = engine
	t.ln = ln
	t.ctx, t.cancel = context.WithCancel(context.Background())

	size := 0
	if t.cfg.Pool.Enabled {
		size = t.cfg.Pool.Size
	}
	t.pool = pool.New(dial, size, t.cfg.Pool.TTL())

	t.running = true
	t.wg.Add(1)
	go t.acceptLoop()

	t.logf("listening on %s, relaying to %s:%d", t.cfg.Listener.Addr(), rt.current(), t.cfg.Transport.EdgePort)
	return nil
}

// Stop closes the listener and tears down the engine and pool. In-flight
// relays are cut: the listener socket closing is what clients notice.
func (t *Tunnel) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running {
		return nil
	}
	t.running = false

	t.cancel()
	err := t.ln.Close()
	t.wg.Wait()
	t.pool.Close()
	if t.engine != nil {
		if cerr := t.engine.Close(); err == nil {
			err = cerr
		}
	}
	t.logf("tunnel stopped")
	return err
}

// Running reports whether the tunnel is accepting connections.
func (t *Tunnel) Running() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.running
}

// Stats returns the live counter block.
func (t *Tunnel) Stats() *Stats { return &t.stats }

// PoolIdle reports how many warm connections are ready.
func (t *Tunnel) PoolIdle() int {
	if t.pool == nil {
		return 0
	}
	return t.pool.Idle()
}

// CurrentEdge reports the address in use, which may differ from the configured
// first entry once a failover has happened.
func (t *Tunnel) CurrentEdge() string {
	if t.router == nil {
		return ""
	}
	return t.router.current().String()
}

// Rotations reports how many times the route has moved.
func (t *Tunnel) Rotations() int {
	if t.router == nil {
		return 0
	}
	return t.router.rotations()
}

// EngineStats exposes the spoofing counters, or nil when stopped.
func (t *Tunnel) EngineStats() *spoof.Stats {
	if t.engine == nil {
		return nil
	}
	return t.engine.Stats()
}

// PoolStats exposes the pool counters, or nil when stopped.
func (t *Tunnel) PoolStats() *pool.Stats {
	if t.pool == nil {
		return nil
	}
	return t.pool.Stats()
}

// noteRelayError logs relay failures without flooding. A client that retries
// hard produces the same error dozens of times a second, and one line per
// attempt buries everything else in the log.
func (t *Tunnel) noteRelayError(err error) {
	msg := err.Error()
	// Strip the addresses so repeats of the same underlying failure collapse
	// together rather than each looking unique.
	if i := strings.Index(msg, ": read "); i >= 0 {
		if j := strings.Index(msg[i:], ": wsarecv"); j >= 0 {
			msg = msg[:i] + msg[i+j:]
		}
	}

	t.errMu.Lock()
	same := msg == t.lastErr
	t.lastErr = msg
	t.errCount++
	n := t.errCount
	if !same {
		t.errCount = 1
		n = 1
	}
	t.errMu.Unlock()

	// Report the first occurrence, then only at widening intervals.
	if n == 1 || n == 10 || n%100 == 0 {
		if n == 1 {
			t.logf("%s", msg)
		} else {
			t.logf("%s (x%d)", msg, n)
		}
	}
}

func (t *Tunnel) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			if t.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			t.logf("accept failed: %v", err)
			continue
		}
		t.stats.Accepted.Add(1)
		t.wg.Add(1)
		go t.handle(conn)
	}
}

func (t *Tunnel) handle(client net.Conn) {
	defer t.wg.Done()

	if tc, ok := client.(*net.TCPConn); ok {
		// The client side carries the same interactive traffic as the upstream
		// side, so it needs Nagle off just as much.
		_ = tc.SetNoDelay(true)
	}

	ctx, cancel := context.WithTimeout(t.ctx, upstreamDialTimeout)
	edge, err := t.pool.Get(ctx)
	cancel()
	if err != nil {
		t.stats.Failed.Add(1)
		t.logf("upstream dial failed: %v", err)
		client.Close()
		return
	}

	t.stats.Active.Add(1)
	defer t.stats.Active.Add(-1)

	var counters relay.Counters
	relayErr := relay.Pipe(client, edge, &counters)

	t.stats.BytesUp.Add(counters.Up.Load())
	t.stats.BytesDown.Add(counters.Down.Load())

	if relayErr != nil {
		t.noteRelayError(relayErr)
	}
}
