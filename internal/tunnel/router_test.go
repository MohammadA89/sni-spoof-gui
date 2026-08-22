//go:build windows

package tunnel

import "testing"

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
	for i := 0; i < failuresBeforeSwitch*2; i++ {
		r.failure()
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
