//go:build windows

package tunnel

import (
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// failuresBeforeSwitch is how many consecutive dial failures on the current
// edge are tolerated before moving to the next one.
//
// One failure means nothing - a single reset happens on a healthy path. Three
// in a row without a success in between is a route that has stopped working,
// and the alternatives were already verified when they were chosen, so moving
// is cheap.
const failuresBeforeSwitch = 3

// rotateSettle is how long a freshly chosen route is left alone before it can
// be blamed for anything.
//
// Failures arrive concurrently: a client opening fifty connections at once
// against a dead edge produces fifty failures within the same second, all of
// them started before the first one was reported. Counting each toward the
// streak would rotate through every alternative in a single burst and land back
// on the dead one having given none of them a connection to prove itself with.
// Ignoring failures for a moment after a switch means one burst costs one
// rotation.
const rotateSettle = 2 * time.Second

// router holds the ranked edge addresses and decides when to move on.
//
// Auto mode verifies several addresses and keeps the runners-up precisely so
// that a route going bad does not end the session. Without this the extra
// addresses would sit in the config unused, and a dead edge would mean the user
// has to reconnect by hand.
type router struct {
	mu     sync.Mutex
	edges  []netip.Addr
	idx    int
	fails  int
	logf   func(string, ...any)
	rotate int       // how many times the route has moved, for stats
	moved  time.Time // when the route last changed
}

func newRouter(ips []string, logf func(string, ...any)) (*router, error) {
	edges := make([]netip.Addr, 0, len(ips))
	for _, s := range ips {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("tunnel: edge IP %q is not an IP address", s)
		}
		if !addr.Is4() {
			return nil, fmt.Errorf("tunnel: edge IP %q is not IPv4", s)
		}
		edges = append(edges, addr)
	}
	if len(edges) == 0 {
		return nil, fmt.Errorf("tunnel: no edge IPs configured")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &router{edges: edges, logf: logf}, nil
}

// current returns the address in use.
func (r *router) current() netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.edges[r.idx]
}

// success clears the failure streak. A route only counts as bad when it fails
// repeatedly with nothing working in between.
func (r *router) success() {
	r.mu.Lock()
	r.fails = 0
	r.mu.Unlock()
}

// failure records a failed dial and rotates the route once the streak is long
// enough. It reports whether the route moved.
func (r *router) failure() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.edges) == 1 {
		return false
	}
	// A dial that was already in flight when the route moved says nothing
	// about the route it is being reported against.
	if !r.moved.IsZero() && time.Since(r.moved) < rotateSettle {
		return false
	}

	r.fails++
	if r.fails < failuresBeforeSwitch {
		return false
	}

	from := r.edges[r.idx]
	r.idx = (r.idx + 1) % len(r.edges)
	r.fails = 0
	r.rotate++
	r.moved = time.Now()
	r.logf("route %s failed %d times in a row, switching to %s", from, failuresBeforeSwitch, r.edges[r.idx])
	return true
}

// rotations reports how often the route has moved.
func (r *router) rotations() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotate
}

// all returns the ranked list, for display.
func (r *router) all() []netip.Addr {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]netip.Addr, len(r.edges))
	copy(out, r.edges)
	return out
}
