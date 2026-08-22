//go:build windows

package main

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/netutil"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/scanner"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/spoof"
)

// scanPortWindow is how many source ports a scan reserves for itself.
const scanPortWindow = 800

// scanState guards a single in-flight scan.
type scanState struct {
	mu     sync.Mutex
	cancel context.CancelFunc
}

// scanPortRange picks a source port window that does not overlap the tunnel's.
//
// Two WinDivert handles whose filters both match our SYNs would each capture
// the same packet, and a scan running alongside a live tunnel could end up
// injecting twice into one handshake. Keeping the port ranges disjoint keeps
// the two filters from ever matching the same traffic.
func scanPortRange(low, high int) (uint16, uint16, error) {
	if high+scanPortWindow <= 65535 {
		return uint16(high + 1), uint16(high + scanPortWindow), nil
	}
	if low-scanPortWindow > 1024 {
		return uint16(low - scanPortWindow), uint16(low - 1), nil
	}
	return 0, 0, fmt.Errorf("no free source port window outside %d-%d; narrow the configured range", low, high)
}

// newScanEngine builds a spoofing engine that can dial any candidate address.
func (a *App) newScanEngine(edge netip.Addr, anyEdge bool) (*spoof.Engine, netip.Addr, error) {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	iface, err := netutil.DefaultInterfaceIPv4(edge)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	low, high, err := scanPortRange(cfg.Transport.PortLow, cfg.Transport.PortHigh)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	engine, err := spoof.NewEngine(spoof.Config{
		InterfaceIP: iface,
		EdgeIP:      edge,
		EdgePort:    uint16(cfg.Transport.EdgePort),
		FakeSNI:     cfg.Transport.FakeSNI,
		Mode:        spoof.ModeFast,
		InjectDelay: cfg.Transport.InjectDelay(),
		PortLow:     low,
		PortHigh:    high,
		AnyEdge:     anyEdge,
	})
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if err := engine.Start(); err != nil {
		return nil, netip.Addr{}, err
	}
	return engine, iface, nil
}

// beginScan installs a cancellable context, replacing any scan already running.
func (a *App) beginScan() context.Context {
	a.scan.mu.Lock()
	defer a.scan.mu.Unlock()
	if a.scan.cancel != nil {
		a.scan.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.scan.cancel = cancel
	return ctx
}

// CancelScan stops the running scan, if any.
func (a *App) CancelScan() {
	a.scan.mu.Lock()
	defer a.scan.mu.Unlock()
	if a.scan.cancel != nil {
		a.scan.cancel()
		a.scan.cancel = nil
	}
}

func (a *App) emitProgress(p scanner.Progress) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "scanProgress", p)
	}
}

// ScanIPs searches the configured ranges for usable edge addresses.
func (a *App) ScanIPs(sample, verify int) ([]scanner.IPResult, error) {
	ctx := a.beginScan()

	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	// Any reachable address will do as the engine's nominal edge; AnyEdge is
	// what actually lets it dial the candidates.
	seed, err := cfg.Transport.PrimaryEdge()
	if err != nil {
		return nil, err
	}

	engine, _, err := a.newScanEngine(seed, true)
	if err != nil {
		a.log("scan cannot start: %v", err)
		return nil, err
	}
	defer engine.Close()

	a.log("scanning %d addresses, verifying the best %d against %s", sample, verify, cfg.Transport.EdgeDomain)

	results, err := scanner.ScanIPs(ctx, engine, scanner.Options{
		Sample:     sample,
		Verify:     verify,
		Domain:     cfg.Transport.EdgeDomain,
		FakeSNI:    cfg.Transport.FakeSNI,
		Port:       uint16(cfg.Transport.EdgePort),
		OnProgress: a.emitProgress,
	})
	if err != nil {
		a.log("scan failed: %v", err)
		return nil, err
	}

	var verified int
	for _, r := range results {
		if r.Verified {
			verified++
		}
	}
	a.log("scan finished: %d reachable, %d verified", len(results), verified)
	return results, nil
}

// ProbeSNIs measures which fake SNI names carry a session on this network.
func (a *App) ProbeSNIs(attempts int) ([]scanner.SNIResult, error) {
	ctx := a.beginScan()

	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	edge, err := cfg.Transport.PrimaryEdge()
	if err != nil {
		return nil, err
	}
	iface, err := netutil.DefaultInterfaceIPv4(edge)
	if err != nil {
		return nil, err
	}

	a.log("probing fake SNI candidates against %s via %s", cfg.Transport.EdgeDomain, edge)

	results, err := scanner.ProbeSNIs(ctx, iface, edge, uint16(cfg.Transport.EdgePort),
		cfg.Transport.EdgeDomain, nil, attempts, a.emitProgress)
	if err != nil {
		a.log("SNI probe failed: %v", err)
		return nil, err
	}

	var working int
	for _, r := range results {
		if r.Works() {
			working++
		}
	}
	a.log("SNI probe finished: %d of %d candidates worked every time", working, len(results))
	return results, nil
}

// CheckDomain reports whether the current edge will serve a domain.
//
// This is the check that explains why one client config works and another does
// not: the edge only answers for names it fronts, so a config pointing at a
// server behind some other CDN is reset no matter how well spoofing works.
func (a *App) CheckDomain(domain string) (scanner.DomainResult, error) {
	if domain == "" {
		return scanner.DomainResult{}, fmt.Errorf("enter a domain, such as the address field from your client config")
	}

	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	edge, err := cfg.Transport.PrimaryEdge()
	if err != nil {
		return scanner.DomainResult{}, err
	}

	engine, _, err := a.newScanEngine(edge, false)
	if err != nil {
		return scanner.DomainResult{}, err
	}
	defer engine.Close()

	res := scanner.CheckDomain(context.Background(), engine, edge, domain)
	if res.Served {
		a.log("%s is served by %s (%dms, %s)", domain, edge, res.TLSMs, res.Protocol)
	} else {
		a.log("%s is NOT served by %s: %s", domain, edge, res.Error)
	}
	return res, nil
}

// ApplyEdgeIPs replaces the configured edge list, best first, and persists it.
func (a *App) ApplyEdgeIPs(ips []string) error {
	if len(ips) == 0 {
		return fmt.Errorf("select at least one address")
	}
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	cfg.Transport.EdgeIPs = ips
	return a.SaveConfig(cfg)
}

// ApplyFakeSNI sets the fake SNI and persists it.
func (a *App) ApplyFakeSNI(sni string) error {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	cfg.Transport.FakeSNI = sni
	return a.SaveConfig(cfg)
}

// SNICandidates returns the names the prober will try.
func (a *App) SNICandidates() []string {
	return scanner.FakeSNICandidates
}
