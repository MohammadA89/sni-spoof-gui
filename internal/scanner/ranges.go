package scanner

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net/netip"
)

// CloudflareV4 are Cloudflare's published IPv4 ranges. They are bundled rather
// than fetched, because the fetch would have to travel the very path the user
// is trying to get working.
//
// Source: https://www.cloudflare.com/ips-v4
var CloudflareV4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

// SampleRanges draws n random addresses spread across the given CIDR blocks.
//
// Sampling beats enumeration by a wide margin here: the bundled ranges hold
// several million addresses, and any edge in a block behaves much like its
// neighbours, so a scattered sample finds a good one just as fast.
func SampleRanges(cidrs []string, n int) ([]netip.Addr, error) {
	if n <= 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("scanner: bad range %q: %w", c, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("scanner: range %q is not IPv4", c)
		}
		prefixes = append(prefixes, p)
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("scanner: no ranges to sample")
	}

	seen := make(map[netip.Addr]struct{}, n)
	out := make([]netip.Addr, 0, n)

	// Spread the sample evenly over the blocks rather than by block size, so a
	// /22 gets looked at as well as a /13.
	for len(out) < n {
		for _, p := range prefixes {
			if len(out) >= n {
				break
			}
			addr, err := randomInPrefix(p)
			if err != nil {
				return nil, err
			}
			if _, dup := seen[addr]; dup {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out, nil
}

// randomInPrefix picks a uniformly random usable address inside p.
func randomInPrefix(p netip.Prefix) (netip.Addr, error) {
	base := p.Masked().Addr().As4()
	start := binary.BigEndian.Uint32(base[:])
	size := uint32(1) << (32 - p.Bits())

	// Skip the network and broadcast addresses on anything wider than a /31.
	lo, span := start, size
	if size > 2 {
		lo, span = start+1, size-2
	}

	nBig, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("scanner: read random: %w", err)
	}

	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], lo+uint32(nBig.Int64()))
	return netip.AddrFrom4(buf), nil
}

// FakeSNICandidates are names worth trying as the injected SNI.
//
// A good candidate is somewhere a filter is unlikely to block outright:
// infrastructure and CDN endpoints that ordinary browsing depends on. Which
// ones actually work is network-specific, which is exactly why they get probed
// rather than hard-coded to one choice.
var FakeSNICandidates = []string{
	"auth.vercel.com",
	"www.speedtest.net",
	"mci.ir",
	"www.digikala.com",
	"cdn.jsdelivr.net",
	"ajax.googleapis.com",
	"fonts.gstatic.com",
	"api.hcaptcha.com",
	"assets.msn.com",
	"static.cloudflareinsights.com",
	"www.snapp.ir",
	"aparat.com",
}
