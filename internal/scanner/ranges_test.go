package scanner

import (
	"net/netip"
	"testing"
)

func TestSampleRangesStaysInsideCIDRs(t *testing.T) {
	cidrs := []string{"104.16.0.0/13", "188.114.96.0/20", "131.0.72.0/22"}
	got, err := SampleRanges(cidrs, 300)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 300 {
		t.Fatalf("sampled %d addresses, want 300", len(got))
	}

	prefixes := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefixes[i] = netip.MustParsePrefix(c)
	}
	for _, a := range got {
		inside := false
		for _, p := range prefixes {
			if p.Contains(a) {
				inside = true
				break
			}
		}
		if !inside {
			t.Errorf("%s is outside every configured range", a)
		}
	}
}

func TestSampleRangesIsUnique(t *testing.T) {
	got, err := SampleRanges([]string{"104.16.0.0/13"}, 500)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[netip.Addr]bool, len(got))
	for _, a := range got {
		if seen[a] {
			t.Fatalf("%s sampled twice", a)
		}
		seen[a] = true
	}
}

// Network and broadcast addresses are not usable edges, so they must not be
// offered as candidates.
func TestSampleRangesSkipsNetworkAndBroadcast(t *testing.T) {
	// A /24 is small enough that 200 draws will hit the edges if they are not
	// excluded.
	got, err := SampleRanges([]string{"192.0.2.0/24"}, 200)
	if err != nil {
		t.Fatal(err)
	}
	network := netip.MustParseAddr("192.0.2.0")
	broadcast := netip.MustParseAddr("192.0.2.255")
	for _, a := range got {
		if a == network || a == broadcast {
			t.Errorf("sampled reserved address %s", a)
		}
	}
}

func TestSampleRangesSpreadsAcrossBlocks(t *testing.T) {
	// A huge block and a tiny one: sampling weighted by size would starve the
	// tiny one entirely.
	cidrs := []string{"104.16.0.0/13", "131.0.72.0/22"}
	got, err := SampleRanges(cidrs, 40)
	if err != nil {
		t.Fatal(err)
	}
	small := netip.MustParsePrefix("131.0.72.0/22")
	count := 0
	for _, a := range got {
		if small.Contains(a) {
			count++
		}
	}
	if count == 0 {
		t.Error("the small block was never sampled")
	}
}

func TestSampleRangesRejectsBadInput(t *testing.T) {
	if _, err := SampleRanges([]string{"not-a-cidr"}, 10); err == nil {
		t.Error("expected an error for a malformed CIDR")
	}
	if _, err := SampleRanges([]string{"2606:4700::/32"}, 10); err == nil {
		t.Error("expected an error for an IPv6 range")
	}
	if _, err := SampleRanges(nil, 10); err == nil {
		t.Error("expected an error when there are no ranges")
	}
	if got, err := SampleRanges([]string{"104.16.0.0/13"}, 0); err != nil || got != nil {
		t.Errorf("a zero sample should return nothing, got %v %v", got, err)
	}
}

func TestBundledRangesParse(t *testing.T) {
	for _, c := range CloudflareV4 {
		if _, err := netip.ParsePrefix(c); err != nil {
			t.Errorf("bundled range %q does not parse: %v", c, err)
		}
	}
}

func TestSNIResultWorks(t *testing.T) {
	if !(SNIResult{Attempts: 3, Successes: 3}).Works() {
		t.Error("3/3 should count as working")
	}
	if (SNIResult{Attempts: 3, Successes: 2}).Works() {
		t.Error("2/3 should not count as working; intermittent is worse than useless")
	}
	if (SNIResult{}).Works() {
		t.Error("an untried candidate should not count as working")
	}
}
