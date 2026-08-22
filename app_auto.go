//go:build windows

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/config"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/scanner"
)

// Auto mode trades a few seconds at connect time for a route that has been
// shown to work, rather than one that merely looks fast. These are deliberately
// smaller than a manual scan: this runs while the user waits.
const (
	autoSample = 160
	autoVerify = 6
	autoKeep   = 8
	autoBudget = 45 * time.Second
)

// AutoStatus tells the UI what auto mode is doing.
type AutoStatus struct {
	Active  bool   `json:"active"`
	Message string `json:"message"`
	Done    int    `json:"done"`
	Total   int    `json:"total"`
}

func (a *App) emitAuto(s AutoStatus) {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "autoStatus", s)
	}
}

// autoSelectRoute finds a working edge and writes it to the config, best first.
//
// Only verified addresses are adopted. An address that answered a bare TCP
// connect quickly has proved nothing: the failure mode this is meant to avoid
// is exactly an edge that accepts the handshake and then resets every real
// session. If nothing verifies, the configured route is left untouched and the
// caller connects with it, which is no worse than not having run at all.
func (a *App) autoSelectRoute() error {
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	seed, err := cfg.Transport.PrimaryEdge()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), autoBudget)
	defer cancel()

	a.emitAuto(AutoStatus{Active: true, Message: "starting"})
	defer a.emitAuto(AutoStatus{Active: false})

	engine, _, err := a.newScanEngine(seed, true)
	if err != nil {
		return fmt.Errorf("auto: %w", err)
	}
	defer engine.Close()

	a.log("auto: looking for the best route")

	results, err := scanner.ScanIPs(ctx, engine, scanner.Options{
		Sample:  autoSample,
		Verify:  autoVerify,
		Domain:  cfg.Transport.EdgeDomain,
		FakeSNI: cfg.Transport.FakeSNI,
		Port:    uint16(cfg.Transport.EdgePort),
		OnProgress: func(p scanner.Progress) {
			msg := "measuring latency"
			if p.Phase == "verify" {
				msg = "verifying candidates"
			}
			a.emitAuto(AutoStatus{Active: true, Message: msg, Done: p.Done, Total: p.Total})
		},
	})
	if err != nil {
		return fmt.Errorf("auto: %w", err)
	}

	best := make([]string, 0, autoKeep)
	for _, r := range results {
		if r.Verified {
			best = append(best, r.IP)
			if len(best) >= autoKeep {
				break
			}
		}
	}
	if len(best) == 0 {
		a.log("auto: nothing verified, keeping %s", cfg.Transport.EdgeIPs[0])
		return nil
	}

	a.mu.Lock()
	a.cfg.Transport.EdgeIPs = best
	updated := a.cfg
	a.mu.Unlock()

	// Persisted directly rather than through SaveConfig, which would log a
	// "restart to apply" note that is wrong here: the tunnel starts next.
	if err := config.Save(a.configPath, updated); err != nil {
		a.log("auto: could not save the chosen route: %v", err)
	}
	a.log("auto: chose %s (%d verified alternatives held for failover)", best[0], len(best)-1)
	return nil
}
