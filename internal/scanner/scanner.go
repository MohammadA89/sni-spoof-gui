//go:build windows

// Package scanner finds clean edge IPs and workable fake SNIs, and checks
// whether a given edge will actually serve a given domain.
package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/spoof"
)

// Tunable bounds for a scan.
const (
	// DefaultProbeConcurrency is how many plain TCP probes run at once. The
	// first phase is pure connect latency, so it can go wide.
	DefaultProbeConcurrency = 256

	// DefaultVerifyConcurrency is deliberately much lower: each verification
	// spoofs a handshake, and a burst of injections is both slower and more
	// conspicuous than a trickle.
	DefaultVerifyConcurrency = 8

	probeTimeout  = 2 * time.Second
	verifyTimeout = 12 * time.Second
)

// IPResult is one candidate edge address after scanning.
type IPResult struct {
	IP string `json:"ip"`

	// LatencyMs is the plain TCP connect time. Negative means unreachable.
	LatencyMs int `json:"latencyMs"`

	// TLSMs is the time to complete a real TLS handshake over a spoofed
	// connection. Zero means the address was never verified.
	TLSMs int `json:"tlsMs"`

	// Verified means a real TLS session completed through the spoofed
	// transport, which is the only result that proves the address is usable.
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
}

// SNIResult is one fake SNI candidate after probing.
type SNIResult struct {
	SNI       string `json:"sni"`
	Successes int    `json:"successes"`
	Attempts  int    `json:"attempts"`
	MeanMs    int    `json:"meanMs"`
	Error     string `json:"error,omitempty"`
}

// Works reports whether every attempt with this SNI succeeded.
func (r SNIResult) Works() bool { return r.Attempts > 0 && r.Successes == r.Attempts }

// DomainResult answers whether an edge serves a particular domain.
type DomainResult struct {
	Domain   string `json:"domain"`
	Edge     string `json:"edge"`
	Served   bool   `json:"served"`
	TLSMs    int    `json:"tlsMs"`
	Protocol string `json:"protocol,omitempty"`
	Error    string `json:"error,omitempty"`
}

// Progress reports how far a scan has got, for a UI progress bar.
type Progress struct {
	Phase string `json:"phase"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// Options configures a scan.
type Options struct {
	Ranges []string
	Sample int

	// Verify is how many of the fastest addresses get a full spoofed TLS
	// handshake. Latency alone does not prove an address is usable.
	Verify int

	// Domain is the name used for verification handshakes. It has to be one the
	// edge actually serves, or every verification fails for the wrong reason.
	Domain  string
	FakeSNI string
	Port    uint16

	ProbeConcurrency  int
	VerifyConcurrency int

	OnProgress func(Progress)
}

func (o *Options) applyDefaults() {
	if len(o.Ranges) == 0 {
		o.Ranges = CloudflareV4
	}
	if o.Sample <= 0 {
		o.Sample = 400
	}
	if o.Verify <= 0 {
		o.Verify = 10
	}
	if o.Domain == "" {
		o.Domain = "hcaptcha.com"
	}
	if o.FakeSNI == "" {
		o.FakeSNI = "auth.vercel.com"
	}
	if o.Port == 0 {
		o.Port = 443
	}
	if o.ProbeConcurrency <= 0 {
		o.ProbeConcurrency = DefaultProbeConcurrency
	}
	if o.VerifyConcurrency <= 0 {
		o.VerifyConcurrency = DefaultVerifyConcurrency
	}
}

func (o *Options) report(phase string, done, total int) {
	if o.OnProgress != nil {
		o.OnProgress(Progress{Phase: phase, Done: done, Total: total})
	}
}

// ScanIPs finds usable edge addresses.
//
// It runs in two phases because the two questions are different and cost
// different amounts. Reachability and latency are cheap and can be asked of
// hundreds of addresses at once. Whether an address will carry a spoofed
// session is expensive to ask and only worth asking of the ones that answered
// quickly. Sorting by latency alone would happily recommend an address that
// resets every real connection.
func ScanIPs(ctx context.Context, engine *spoof.Engine, opts Options) ([]IPResult, error) {
	opts.applyDefaults()

	candidates, err := SampleRanges(opts.Ranges, opts.Sample)
	if err != nil {
		return nil, err
	}

	results := probeLatency(ctx, candidates, opts)

	// Keep only what answered, fastest first.
	alive := make([]IPResult, 0, len(results))
	for _, r := range results {
		if r.LatencyMs >= 0 {
			alive = append(alive, r)
		}
	}
	sort.Slice(alive, func(i, j int) bool { return alive[i].LatencyMs < alive[j].LatencyMs })

	if engine == nil || len(alive) == 0 {
		return alive, nil
	}

	n := opts.Verify
	if n > len(alive) {
		n = len(alive)
	}
	verifyTop(ctx, alive[:n], engine, opts)

	// A verified address always outranks an unverified one, however fast the
	// unverified one looked.
	sort.SliceStable(alive, func(i, j int) bool {
		if alive[i].Verified != alive[j].Verified {
			return alive[i].Verified
		}
		return alive[i].LatencyMs < alive[j].LatencyMs
	})
	return alive, nil
}

// probeLatency measures plain TCP connect time to every candidate.
func probeLatency(ctx context.Context, candidates []netip.Addr, opts Options) []IPResult {
	results := make([]IPResult, len(candidates))
	sem := make(chan struct{}, opts.ProbeConcurrency)
	var wg sync.WaitGroup
	var done atomic.Int64

	for i, addr := range candidates {
		wg.Add(1)
		go func(i int, addr netip.Addr) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = IPResult{IP: addr.String(), LatencyMs: -1, Error: "cancelled"}
				return
			}

			r := IPResult{IP: addr.String(), LatencyMs: -1}
			target := net.JoinHostPort(addr.String(), fmt.Sprint(opts.Port))

			start := time.Now()
			d := net.Dialer{Timeout: probeTimeout}
			conn, err := d.DialContext(ctx, "tcp4", target)
			if err == nil {
				r.LatencyMs = int(time.Since(start).Milliseconds())
				conn.Close()
			} else {
				r.Error = err.Error()
			}
			results[i] = r

			if n := done.Add(1); n%16 == 0 || int(n) == len(candidates) {
				opts.report("latency", int(n), len(candidates))
			}
		}(i, addr)
	}
	wg.Wait()
	opts.report("latency", len(candidates), len(candidates))
	return results
}

// verifyTop completes a real TLS session over a spoofed connection to each of
// the given addresses, filling in TLSMs and Verified in place.
func verifyTop(ctx context.Context, top []IPResult, engine *spoof.Engine, opts Options) {
	sem := make(chan struct{}, opts.VerifyConcurrency)
	var wg sync.WaitGroup
	var done atomic.Int64

	for i := range top {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			addr, err := netip.ParseAddr(top[i].IP)
			if err != nil {
				top[i].Error = err.Error()
				return
			}
			elapsed, perr := spoofedHandshake(ctx, engine, addr, opts.Domain)
			if perr != nil {
				top[i].Error = perr.Error()
			} else {
				top[i].Verified = true
				top[i].TLSMs = int(elapsed.Milliseconds())
				top[i].Error = ""
			}

			n := done.Add(1)
			opts.report("verify", int(n), len(top))
		}(i)
	}
	wg.Wait()
}

// spoofedHandshake dials edge through the spoofing engine and completes a real
// TLS handshake for domain, returning how long the handshake took.
func spoofedHandshake(ctx context.Context, engine *spoof.Engine, edge netip.Addr, domain string) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	conn, err := engine.DialTo(ctx, edge)
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	start := time.Now()
	_, err = handshake(conn, domain)
	if err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// handshake completes a real TLS handshake presenting domain as the SNI, using
// a Chrome fingerprint so a failure points at the transport rather than at the
// handshake looking like a Go program.
func handshake(conn net.Conn, domain string) (*utls.UConn, error) {
	_ = conn.SetDeadline(time.Now().Add(verifyTimeout))
	c := utls.UClient(conn, &utls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
	}, utls.HelloChrome_Auto)
	if err := c.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS: %w", err)
	}
	return c, nil
}

// ProbeSNIs measures which fake SNIs carry a session on this network.
//
// The fake SNI is the one thing DPI is meant to act on, so which names work is
// a property of the network rather than of the tool. Each candidate is tried
// several times: a name that works once and fails twice is worse than useless,
// because the failures look like an unrelated fault later on.
func ProbeSNIs(ctx context.Context, iface, edge netip.Addr, port uint16, domain string, candidates []string, attempts int, onProgress func(Progress)) ([]SNIResult, error) {
	if len(candidates) == 0 {
		candidates = FakeSNICandidates
	}
	if attempts <= 0 {
		attempts = 3
	}

	results := make([]SNIResult, 0, len(candidates))
	for i, sni := range candidates {
		if ctx.Err() != nil {
			break
		}
		if onProgress != nil {
			onProgress(Progress{Phase: "sni", Done: i, Total: len(candidates)})
		}

		r := SNIResult{SNI: sni, Attempts: attempts}
		if sni == domain {
			// Using the real name as the fake one defeats the whole mechanism.
			r.Error = "same as the verification domain"
			results = append(results, r)
			continue
		}

		// One engine per candidate, because the fake SNI is baked into the
		// engine config and the injected record is built from it.
		engine, err := spoof.NewEngine(spoof.Config{
			InterfaceIP: iface,
			EdgeIP:      edge,
			EdgePort:    port,
			FakeSNI:     sni,
		})
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		if err := engine.Start(); err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}

		var total time.Duration
		for a := 0; a < attempts && ctx.Err() == nil; a++ {
			elapsed, perr := spoofedHandshake(ctx, engine, edge, domain)
			if perr != nil {
				if r.Error == "" {
					r.Error = perr.Error()
				}
				continue
			}
			r.Successes++
			total += elapsed
		}
		engine.Close()

		if r.Successes > 0 {
			r.MeanMs = int((total / time.Duration(r.Successes)).Milliseconds())
			if r.Successes == r.Attempts {
				r.Error = ""
			}
		}
		results = append(results, r)
	}

	// Fully working names first, then by how quickly they handshake.
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Works() != results[j].Works() {
			return results[i].Works()
		}
		if results[i].Successes != results[j].Successes {
			return results[i].Successes > results[j].Successes
		}
		return results[i].MeanMs < results[j].MeanMs
	})

	if onProgress != nil {
		onProgress(Progress{Phase: "sni", Done: len(candidates), Total: len(candidates)})
	}
	return results, nil
}

// CheckDomain answers the question that decides whether a given client config
// can work at all: does this edge address serve that domain?
//
// A config whose server sits behind a different CDN will be reset by this edge
// no matter how well the spoofing works, so checking here saves guessing in the
// client later.
func CheckDomain(ctx context.Context, engine *spoof.Engine, edge netip.Addr, domain string) DomainResult {
	res := DomainResult{Domain: domain, Edge: edge.String()}

	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	conn, err := engine.DialTo(ctx, edge)
	if err != nil {
		res.Error = fmt.Sprintf("dial: %v", err)
		return res
	}
	defer conn.Close()

	start := time.Now()
	c, err := handshake(conn, domain)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Served = true
	res.TLSMs = int(time.Since(start).Milliseconds())

	state := c.ConnectionState()
	res.Protocol = state.NegotiatedProtocol
	if res.Protocol == "" {
		res.Protocol = "no-alpn"
	}
	return res
}
