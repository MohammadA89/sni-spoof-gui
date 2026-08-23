//go:build windows

package sysproxy

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// preserve redirects the package at a scratch registry key for the duration of
// one test, and deletes it afterwards.
//
// The real key is deliberately left untouched: a test run must not rewrite the
// developer's own proxy configuration, and a test that failed halfway would
// leave it rewritten. Everything below still goes through the same registry
// calls the app uses.
func preserve(t *testing.T) {
	t.Helper()

	path := fmt.Sprintf(`Software\sni-spoofing-advance\test-%d-%s`, os.Getpid(), t.Name())
	path = strings.ReplaceAll(path, "/", "_")

	k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.ALL_ACCESS)
	if err != nil {
		t.Skipf("cannot create a scratch registry key: %v", err)
	}
	k.Close()

	real := settingsKey
	settingsKey = path
	t.Cleanup(func() {
		settingsKey = real
		if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
			t.Errorf("could not remove the scratch key %s: %v", path, err)
		}
	})
}

func TestEnableThenRestoreRoundTrips(t *testing.T) {
	preserve(t)

	before, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	previous, err := Enable("127.0.0.1:10809", "")
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	// Enable has to report what it displaced, or the caller has nothing to
	// restore and can only blanket-disable.
	if previous != before {
		t.Errorf("Enable reported %+v as the previous state, want %+v", previous, before)
	}

	during, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !during.Enabled {
		t.Error("the proxy should be enabled")
	}
	if during.Server != "127.0.0.1:10809" {
		t.Errorf("server = %q", during.Server)
	}
	if during.Bypass == "" {
		t.Error("an empty bypass list would send localhost through the proxy too")
	}

	if err := Restore(previous); err != nil {
		t.Fatalf("restore: %v", err)
	}
	after, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	// This is the property that matters most: a user who had their own proxy
	// configured must find it exactly as they left it.
	if after != before {
		t.Errorf("after restore = %+v, want %+v", after, before)
	}
}

// Restoring must put back the previous *server* too, not just the flag. Only
// checking Enabled would let a restore quietly rewrite someone's proxy address.
func TestRestorePutsBackTheServerNotJustTheFlag(t *testing.T) {
	preserve(t)

	want := State{Enabled: true, Server: "10.0.0.1:3128", Bypass: "<local>"}
	if err := Set(want); err != nil {
		t.Fatalf("set: %v", err)
	}

	previous, err := Enable("127.0.0.1:10809", "")
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if err := Restore(previous); err != nil {
		t.Fatalf("restore: %v", err)
	}

	got, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != want {
		t.Errorf("after restore = %+v, want %+v", got, want)
	}
}

func TestDisableLeavesTheServerAlone(t *testing.T) {
	preserve(t)

	if err := Set(State{Enabled: true, Server: "10.0.0.1:3128", Bypass: "<local>"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := Disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}

	got, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Enabled {
		t.Error("the proxy should be off")
	}
	// The address stays so the user can switch it back on themselves.
	if got.Server != "10.0.0.1:3128" {
		t.Errorf("server = %q, want it left alone", got.Server)
	}
}

// A scheme would be written through verbatim and silently break every
// application that reads the value, so it is refused rather than cleaned up.
func TestEnableRejectsAURL(t *testing.T) {
	preserve(t)

	_, err := Enable("http://127.0.0.1:10809", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "host:port") {
		t.Errorf("the error should say what is wanted, got %v", err)
	}
}

func TestEnableRejectsAnEmptyAddress(t *testing.T) {
	preserve(t)

	if _, err := Enable("", ""); err == nil {
		t.Error("expected an error")
	}
}

// A never-configured key reads as "no proxy" rather than failing: that is the
// normal state on a fresh machine, not an error to show anyone.
func TestGetOnAnUnconfiguredKeyIsEmpty(t *testing.T) {
	preserve(t)

	s, err := Get()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if s.Enabled || s.Server != "" || s.Bypass != "" {
		t.Errorf("got %+v, want the zero value", s)
	}
}

func TestDefaultBypassCoversLocalTraffic(t *testing.T) {
	for _, want := range []string{"localhost", "127.*", "192.168.*", "<local>"} {
		if !strings.Contains(DefaultBypass, want) {
			t.Errorf("the default bypass list is missing %q", want)
		}
	}
}
