//go:build windows

package tunnel

import (
	"sync"
	"testing"
	"time"
)

// settle back-dates the last rotation so the router will act on failures again,
// standing in for the rotateSettle window having passed.
func settle(r *router) {
	r.mu.Lock()
	r.moved = time.Now().Add(-2 * rotateSettle)
	r.mu.Unlock()
}

func testRouter(t *testing.T, ips ...string) *router {
	t.Helper()
	r, err := newRouter(ips, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRouterStartsOnFirstEntry(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2")
	if got := r.current().String(); got != "1.1.1.1" {
		t.Errorf("current = %s, want the first ranked entry", got)
	}
}

// A single failure is normal on a healthy path; only a streak means the route
// itself has gone bad.
func TestRouterToleratesIsolatedFailures(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2")
	for i := 0; i < 10; i++ {
		r.failure()
		r.failure()
		r.success()
	}
	if got := r.current().String(); got != "1.1.1.1" {
		t.Errorf("route moved to %s despite successes in between", got)
	}
	if r.rotations() != 0 {
		t.Errorf("rotations = %d, want 0", r.rotations())
	}
}

func TestRouterSwitchesAfterStreak(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2", "3.3.3.3")
	for i := 0; i < failuresBeforeSwitch; i++ {
		r.failure()
	}
	if got := r.current().String(); got != "2.2.2.2" {
		t.Errorf("current = %s, want 2.2.2.2 after a failure streak", got)
	}
	if r.rotations() != 1 {
		t.Errorf("rotations = %d, want 1", r.rotations())
	}
}

func TestRouterWrapsAround(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2")
	for round := 0; round < 2; round++ {
		settle(r)
		for i := 0; i < failuresBeforeSwitch; i++ {
			r.failure()
		}
	}
	if got := r.current().String(); got != "1.1.1.1" {
		t.Errorf("current = %s, want to wrap back to the first entry", got)
	}
}

// With nowhere to move, rotating would just churn the pool for nothing.
func TestRouterDoesNotRotateWithOneRoute(t *testing.T) {
	r := testRouter(t, "1.1.1.1")
	for i := 0; i < failuresBeforeSwitch*3; i++ {
		if r.failure() {
			t.Fatal("a single-route router should never report a switch")
		}
	}
	if got := r.current().String(); got != "1.1.1.1" {
		t.Errorf("current = %s", got)
	}
}

// The streak resets on a switch, so the new route gets a full allowance rather
// than being abandoned on its first stumble.
func TestRouterResetsStreakOnSwitch(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2", "3.3.3.3")
	for i := 0; i < failuresBeforeSwitch; i++ {
		r.failure()
	}
	r.failure()
	if got := r.current().String(); got != "2.2.2.2" {
		t.Errorf("current = %s, want to stay on 2.2.2.2 after one failure", got)
	}
}

func TestNewRouterRejectsBadInput(t *testing.T) {
	for name, ips := range map[string][]string{
		"empty":     {},
		"not an IP": {"example.com"},
		"ipv6":      {"2606:4700::1"},
	} {
		if _, err := newRouter(ips, nil); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// The failure this guards against is a burst, not a streak: every connection a
// client opens at once fails at once, and each failure describes the route as
// it was when that dial started. Counting all of them would walk the whole
// ranked list in a single second and give no alternative a chance to be tried.
func TestRouterIgnoresConcurrentFailureBurst(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.failure()
		}()
	}
	wg.Wait()

	if got := r.rotations(); got != 1 {
		t.Errorf("rotations = %d, want exactly 1 for a single burst", got)
	}
	if got := r.current().String(); got != "2.2.2.2" {
		t.Errorf("current = %s, want the next route after one rotation", got)
	}
}

// A route that keeps failing across separate bursts is still abandoned; the
// settle window delays the next move, it does not prevent it.
func TestRouterStillRotatesAcrossBursts(t *testing.T) {
	r := testRouter(t, "1.1.1.1", "2.2.2.2", "3.3.3.3")
	for round := 0; round < 2; round++ {
		settle(r)
		for i := 0; i < failuresBeforeSwitch; i++ {
			r.failure()
		}
	}
	if got := r.current().String(); got != "3.3.3.3" {
		t.Errorf("current = %s, want 3.3.3.3 after two separate bursts", got)
	}
	if got := r.rotations(); got != 2 {
		t.Errorf("rotations = %d, want 2", got)
	}
}
