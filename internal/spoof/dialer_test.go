//go:build windows

package spoof

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// A port collision has to be recognised through the wrapping the dial path adds,
// or DialTo gives up on the first collision instead of taking the next port.
func TestIsPortCollision(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"registration collision": {fmt.Errorf("%w: port %d", ErrPortBusy, 45001), true},
		"kernel address in use":  {fmt.Errorf("dial: %w", windows.WSAEADDRINUSE), true},
		"timeout":                {errors.New("i/o timeout"), false},
		"nil":                    {nil, false},
	}
	for name, c := range cases {
		if got := isPortCollision(c.err); got != c.want {
			t.Errorf("%s: isPortCollision = %v, want %v", name, got, c.want)
		}
	}
}

// The cursor has to walk the range rather than sit on one port, since a busy
// port is the one case a retry is meant to escape.
func TestPortCursorAdvances(t *testing.T) {
	p := portCursor{low: 45000, high: 45009}
	seen := make(map[uint16]bool)
	for i := 0; i < 10; i++ {
		port := p.take()
		if port < p.low || port > p.high {
			t.Fatalf("port %d is outside %d-%d", port, p.low, p.high)
		}
		if seen[port] {
			t.Fatalf("port %d repeated within one pass over the range", port)
		}
		seen[port] = true
	}
}
