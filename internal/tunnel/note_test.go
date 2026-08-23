//go:build windows

package tunnel

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

func recordingTunnel() (*Tunnel, *[]string) {
	var mu sync.Mutex
	lines := make([]string, 0, 16)
	t := &Tunnel{logf: func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}}
	return t, &lines
}

// Every relayed connection has its own local port, so the same underlying
// failure arrives with a different address each time. Before these were
// stripped, one dead edge produced one distinct-looking line per connection and
// filled the log with hundreds of them.
func TestNoteErrorCollapsesByAddress(t *testing.T) {
	tun, lines := recordingTunnel()

	for port := 3000; port < 3120; port++ {
		tun.noteError(fmt.Errorf("edge closed: write tcp 127.0.0.1:40443->127.0.0.1:%d: wsasend: reset", port))
	}

	if len(*lines) > 3 {
		t.Fatalf("logged %d lines for one repeated failure: %v", len(*lines), *lines)
	}
	if len(*lines) == 0 {
		t.Fatal("the first occurrence should always be reported")
	}
	first := (*lines)[0]
	if strings.Contains(first, "3000") || strings.Contains(first, "40443") {
		t.Errorf("addresses should be stripped from the collapsed line, got %q", first)
	}
	if !strings.Contains(first, "<addr>") {
		t.Errorf("expected the address placeholder in %q", first)
	}
	last := (*lines)[len(*lines)-1]
	if !strings.Contains(last, "(x") {
		t.Errorf("repeats should be reported with a count, got %q", last)
	}
}

// Collapsing must not hide a second, different failure behind the first.
func TestNoteErrorReportsDistinctFailures(t *testing.T) {
	tun, lines := recordingTunnel()

	tun.noteError(errors.New("upstream dial failed: i/o timeout"))
	tun.noteError(errors.New("edge closed: connection reset"))

	if len(*lines) != 2 {
		t.Fatalf("want both distinct failures reported, got %v", *lines)
	}
}
