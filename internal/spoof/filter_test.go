//go:build windows

package spoof

import (
	"net/netip"
	"strings"
	"testing"
)

func testConfig(anyEdge bool, mode Mode) Config {
	c := Config{
		InterfaceIP: netip.MustParseAddr("10.0.0.5"),
		EdgeIP:      netip.MustParseAddr("104.17.0.1"),
		FakeSNI:     "auth.vercel.com",
		Mode:        mode,
		AnyEdge:     anyEdge,
	}
	c.applyDefaults()
	return c
}

// Both filters have to match the SYN-ACK coming back, where the edge port is
// the *source* and our bound port is the destination. Getting this backwards
// makes the engine wait forever for a packet it filtered out, and every dial
// times out with no obvious cause.
func TestFilterMatchesBothHandshakeDirections(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantOut string
		wantIn  string
	}{
		{
			name:    "single edge",
			cfg:     testConfig(false, ModeFast),
			wantOut: "ip.SrcAddr == 10.0.0.5 and ip.DstAddr == 104.17.0.1 and tcp.DstPort == 443",
			wantIn:  "ip.SrcAddr == 104.17.0.1 and ip.DstAddr == 10.0.0.5 and tcp.SrcPort == 443",
		},
		{
			name:    "any edge",
			cfg:     testConfig(true, ModeFast),
			wantOut: "ip.SrcAddr == 10.0.0.5 and tcp.DstPort == 443",
			wantIn:  "ip.DstAddr == 10.0.0.5 and tcp.SrcPort == 443",
		},
	} {
		cfg := tc.cfg
		f := cfg.buildFilter()
		if !strings.Contains(f, tc.wantOut) {
			t.Errorf("%s: outbound clause missing\n  filter: %s\n  want:   %s", tc.name, f, tc.wantOut)
		}
		if !strings.Contains(f, tc.wantIn) {
			t.Errorf("%s: inbound clause missing\n  filter: %s\n  want:   %s", tc.name, f, tc.wantIn)
		}
	}
}

// A port condition that applies to the whole expression rather than per
// direction is the specific mistake that broke the scanner, so guard it.
func TestAnyEdgeFilterHasNoSharedPortTerm(t *testing.T) {
	cfg := testConfig(true, ModeFast)
	f := cfg.buildFilter()
	// The edge port must appear once per direction, never as a top-level term.
	if strings.Contains(f, "tcp.Syn and tcp.DstPort ==") {
		t.Errorf("edge port is applied to both directions at once:\n%s", f)
	}
	if n := strings.Count(f, "tcp.DstPort == 443"); n != 1 {
		t.Errorf("expected exactly one outbound edge-port test, got %d:\n%s", n, f)
	}
	if n := strings.Count(f, "tcp.SrcPort == 443"); n != 1 {
		t.Errorf("expected exactly one inbound edge-port test, got %d:\n%s", n, f)
	}
}

// Fast mode must not pull anything but SYNs into user space; that is the whole
// performance argument for this design.
func TestFastFilterIsSynOnly(t *testing.T) {
	for _, anyEdge := range []bool{false, true} {
		cfg := testConfig(anyEdge, ModeFast)
		f := cfg.buildFilter()
		if !strings.Contains(f, "tcp.Syn") {
			t.Errorf("anyEdge=%v: filter does not restrict to SYN:\n%s", anyEdge, f)
		}
		if strings.Contains(f, "PayloadLength") {
			t.Errorf("anyEdge=%v: fast mode should not capture non-SYN packets:\n%s", anyEdge, f)
		}
	}
}

func TestSafeFilterAlsoCapturesBareAcks(t *testing.T) {
	cfg := testConfig(false, ModeSafe)
	f := cfg.buildFilter()
	if !strings.Contains(f, "tcp.PayloadLength == 0") {
		t.Errorf("safe mode must capture the acknowledging ACK:\n%s", f)
	}
}

func TestAnyEdgeSkipsEdgeIPValidation(t *testing.T) {
	c := Config{
		InterfaceIP: netip.MustParseAddr("10.0.0.5"),
		FakeSNI:     "auth.vercel.com",
		AnyEdge:     true,
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Errorf("AnyEdge should not require a fixed edge IP: %v", err)
	}

	c.AnyEdge = false
	if err := c.validate(); err == nil {
		t.Error("a fixed-edge engine must still require an edge IP")
	}
}

// AnyPort is what lets one engine serve dials to whatever port a user config
// names. Both edge-port tests have to disappear: leaving either one behind
// silently drops one direction of every handshake to any other port, and the
// symptom is a dial that times out waiting for an injection.
func TestAnyPortDropsBothEdgePortTests(t *testing.T) {
	for _, anyEdge := range []bool{false, true} {
		cfg := testConfig(anyEdge, ModeFast)
		cfg.AnyPort = true
		f := cfg.buildFilter()

		if strings.Contains(f, "tcp.DstPort == 443") {
			t.Errorf("anyEdge=%v: outbound edge-port test survived AnyPort:\n%s", anyEdge, f)
		}
		if strings.Contains(f, "tcp.SrcPort == 443") {
			t.Errorf("anyEdge=%v: inbound edge-port test survived AnyPort:\n%s", anyEdge, f)
		}
		// A dangling separator means the expression is malformed, and
		// WinDivert rejects the whole filter at Open time.
		for _, bad := range []string{"and )", "( and", "and and", "  "} {
			if strings.Contains(f, bad) {
				t.Errorf("anyEdge=%v: malformed filter contains %q:\n%s", anyEdge, bad, f)
			}
		}
	}
}

// With the port tests gone, the source port range is the only thing left
// distinguishing our handshakes, so it must still be applied per direction.
func TestAnyPortKeepsSourceRangePerDirection(t *testing.T) {
	cfg := testConfig(true, ModeFast)
	cfg.AnyPort = true
	f := cfg.buildFilter()

	wantOut := "ip.SrcAddr == 10.0.0.5 and tcp.SrcPort >= 45000 and tcp.SrcPort <= 54999"
	wantIn := "ip.DstAddr == 10.0.0.5 and tcp.DstPort >= 45000 and tcp.DstPort <= 54999"
	if !strings.Contains(f, wantOut) {
		t.Errorf("outbound clause missing\n  filter: %s\n  want:   %s", f, wantOut)
	}
	if !strings.Contains(f, wantIn) {
		t.Errorf("inbound clause missing\n  filter: %s\n  want:   %s", f, wantIn)
	}
}

// A fixed edge IP with AnyPort narrows by address instead, and the pair must
// stay well-formed once the trailing port tests are removed.
func TestAnyPortSingleEdgeKeepsAddressPair(t *testing.T) {
	cfg := testConfig(false, ModeFast)
	cfg.AnyPort = true
	f := cfg.buildFilter()

	wantOut := "ip.SrcAddr == 10.0.0.5 and ip.DstAddr == 104.17.0.1)"
	wantIn := "ip.SrcAddr == 104.17.0.1 and ip.DstAddr == 10.0.0.5)"
	if !strings.Contains(f, wantOut) {
		t.Errorf("outbound clause missing\n  filter: %s\n  want:   %s", f, wantOut)
	}
	if !strings.Contains(f, wantIn) {
		t.Errorf("inbound clause missing\n  filter: %s\n  want:   %s", f, wantIn)
	}
}
