//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/config"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/profiles"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/sysproxy"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/tunnel"
)

// statsInterval is how often the backend pushes a snapshot to the UI. Half a
// second is fast enough for a live throughput graph without flooding the bridge.
const statsInterval = 500 * time.Millisecond

// logCapacity bounds the in-memory log ring shown in the UI.
const logCapacity = 500

// App is the object Wails binds to the frontend. Every exported method here is
// callable from TypeScript.
type App struct {
	ctx context.Context

	mu     sync.Mutex
	cfg    config.Config
	tun    *tunnel.Tunnel
	client *client
	store  *profiles.Store
	logs   []LogEntry

	// proxySet records that this app turned the Windows proxy on, and
	// proxyPrev what was configured before. Both are needed to put the setting
	// back rather than merely switch it off.
	proxySet  bool
	proxyPrev sysproxy.State
	lastAt    time.Time
	lastUp    uint64
	lastDn    uint64

	configPath string
	scan       scanState
}

// LogEntry is one line in the UI log view.
type LogEntry struct {
	Time    string `json:"time"`
	Message string `json:"message"`
}

// Snapshot is the periodic state push the dashboard renders.
type Snapshot struct {
	Running bool `json:"running"`

	Accepted uint64 `json:"accepted"`
	Active   int64  `json:"active"`
	Failed   uint64 `json:"failed"`

	BytesUp   uint64 `json:"bytesUp"`
	BytesDown uint64 `json:"bytesDown"`

	// Instantaneous rates in bytes per second, derived between pushes so the
	// frontend never has to keep its own history to draw the graph.
	RateUp   float64 `json:"rateUp"`
	RateDown float64 `json:"rateDown"`

	PoolIdle      int    `json:"poolIdle"`
	PoolHits      uint64 `json:"poolHits"`
	PoolMisses    uint64 `json:"poolMisses"`
	PoolDiscarded uint64 `json:"poolDiscarded"`

	Injected  uint64 `json:"injected"`
	Confirmed uint64 `json:"confirmed"`
	SpoofFail uint64 `json:"spoofFail"`

	Edge     string `json:"edge"`
	Listener string `json:"listener"`

	// ClientMode reports which of the two shapes is running, so the dashboard
	// can show the inbound addresses instead of a relay listener.
	ClientMode bool   `json:"clientMode"`
	SocksAddr  string `json:"socksAddr"`
	HTTPAddr   string `json:"httpAddr"`
	Profile    string `json:"profile"`

	// Passthru counts dials the engine could not spoof - UDP and IPv6 - which
	// is the number to look at when traffic works but feels unprotected.
	Passthru    uint64 `json:"passthru"`
	ResolveFail uint64 `json:"resolveFail"`
}

// NewApp builds the bound application object.
func NewApp() *App {
	return &App{
		cfg:        config.Default(),
		configPath: defaultConfigPath(),
		logs:       make([]LogEntry, 0, logCapacity),
	}
}

// defaultConfigPath puts the config next to the executable, which is what a
// portable Windows app is expected to do.
func defaultConfigPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(exe), "config.json")
}

// startup is called by Wails once the frontend is ready.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	if cfg, err := config.Load(a.configPath); err == nil {
		a.mu.Lock()
		a.cfg = cfg
		a.mu.Unlock()
		a.log("loaded config from %s", a.configPath)
	} else if !os.IsNotExist(errUnwrapPath(err)) {
		a.log("using defaults: %v", err)
	}

	go a.pushLoop(ctx)
}

// shutdown is called by Wails as the window closes. Stopping the tunnel here
// matters: it releases the WinDivert handle and the driver reference.
func (a *App) shutdown(ctx context.Context) {
	// Same reasoning as in Stop, and it matters more here: an app that exits
	// leaving the system proxy pointed at itself leaves the machine unable to
	// browse, with nothing running to explain why.
	if err := a.clearSystemProxy(); err != nil {
		a.log("system proxy: %v", err)
	}
	a.stopClient()

	a.mu.Lock()
	tun := a.tun
	a.tun = nil
	a.mu.Unlock()

	if tun != nil {
		_ = tun.Stop()
	}
}

// GetConfig returns the current configuration.
func (a *App) GetConfig() config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// SaveConfig validates and persists a configuration. A running tunnel keeps its
// old settings until it is restarted, which is stated back to the UI rather
// than silently applied.
func (a *App) SaveConfig(cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	running := a.tun != nil
	a.mu.Unlock()

	if err := config.Save(a.configPath, cfg); err != nil {
		return err
	}
	a.log("config saved to %s", a.configPath)
	if running {
		a.log("restart the tunnel for the new settings to take effect")
	}
	return nil
}

// DefaultConfig returns a fresh default configuration, for the reset button.
func (a *App) DefaultConfig() config.Config {
	return config.Default()
}

// Start brings the connection up.
//
// Which of the two shapes it takes depends on config.Client.Enabled: either the
// built-in client, where an embedded xray runs the user's own config and dials
// through the spoofing engine, or the plain relay listener that an external
// client is pointed at.
func (a *App) Start() error {
	a.mu.Lock()
	if a.tun != nil || a.client != nil {
		a.mu.Unlock()
		return fmt.Errorf("already running")
	}
	auto := a.cfg.Transport.Auto
	useClient := a.cfg.Client.Enabled
	a.mu.Unlock()

	// Auto mode picks a clean edge address. In client mode that only matters
	// for a config marked as being behind a CDN, so the scan - which the user
	// waits through - is skipped unless one is selected. loadProfiles takes the
	// lock itself, so this cannot be folded into the block above.
	if useClient {
		store := a.loadProfiles()
		a.mu.Lock()
		e, ok := store.ActiveEntry()
		a.mu.Unlock()
		auto = auto && ok && e.EdgeOverride
	}

	// Route selection happens before the tunnel opens its own WinDivert handle,
	// so the two never have overlapping capture filters.
	if auto {
		if err := a.autoSelectRoute(); err != nil {
			// A failed search is not a failed connect: fall through and use
			// whatever route is configured.
			a.log("auto: %v; using the configured route", err)
		}
	}

	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()

	if useClient {
		if err := a.startClient(cfg); err != nil {
			a.log("cannot start: %v", err)
			return err
		}
		return nil
	}

	tun, err := tunnel.New(cfg, a.log)
	if err != nil {
		a.log("cannot start: %v", err)
		return err
	}
	if err := tun.Start(); err != nil {
		a.log("cannot start: %v", err)
		return err
	}

	a.mu.Lock()
	a.tun = tun
	a.lastAt = time.Time{}
	a.lastUp, a.lastDn = 0, 0
	a.mu.Unlock()
	return nil
}

// Stop takes the connection down, whichever shape it has.
func (a *App) Stop() error {
	// The system proxy goes first. Leaving Windows pointed at a port that is
	// about to close would break the user's browsing entirely, and they would
	// have no reason to connect it to having pressed disconnect here.
	if err := a.clearSystemProxy(); err != nil {
		a.log("system proxy: %v", err)
	}
	a.stopClient()

	a.mu.Lock()
	tun := a.tun
	a.tun = nil
	a.mu.Unlock()

	if tun == nil {
		return nil
	}
	return tun.Stop()
}

// GetLogs returns the buffered log lines, newest last.
func (a *App) GetLogs() []LogEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]LogEntry, len(a.logs))
	copy(out, a.logs)
	return out
}

// ClearLogs empties the log buffer.
func (a *App) ClearLogs() {
	a.mu.Lock()
	a.logs = a.logs[:0]
	a.mu.Unlock()
}

// GetSnapshot returns the current state, for the initial render before the
// first pushed update arrives.
func (a *App) GetSnapshot() Snapshot {
	return a.snapshot()
}

// log records a line and forwards it to the UI.
func (a *App) log(format string, args ...any) {
	entry := LogEntry{
		Time:    time.Now().Format("15:04:05"),
		Message: fmt.Sprintf(format, args...),
	}

	a.mu.Lock()
	if len(a.logs) >= logCapacity {
		// Drop the oldest line; the ring is for the UI, not an audit trail.
		a.logs = append(a.logs[:0], a.logs[1:]...)
	}
	a.logs = append(a.logs, entry)
	a.mu.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "log", entry)
	}
}

// pushLoop emits a snapshot on a fixed interval. Pushing rather than letting
// the frontend poll keeps the two in step and avoids a request per redraw.
func (a *App) pushLoop(ctx context.Context) {
	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.EventsEmit(ctx, "stats", a.snapshot())
		}
	}
}

func (a *App) snapshot() Snapshot {
	a.mu.Lock()
	tun := a.tun
	cl := a.client
	cfg := a.cfg
	store := a.store
	lastAt, lastUp, lastDn := a.lastAt, a.lastUp, a.lastDn
	a.mu.Unlock()

	s := Snapshot{
		Listener:   cfg.Listener.Addr(),
		ClientMode: cfg.Client.Enabled,
	}
	if len(cfg.Transport.EdgeIPs) > 0 {
		s.Edge = fmt.Sprintf("%s:%d", cfg.Transport.EdgeIPs[0], cfg.Transport.EdgePort)
	}
	if cfg.Client.Enabled {
		s.SocksAddr = fmt.Sprintf("%s:%d", cfg.Listener.Host, cfg.Client.SocksPort)
		s.HTTPAddr = fmt.Sprintf("%s:%d", cfg.Listener.Host, cfg.Client.HTTPPort)
		if store != nil {
			if p, _, err := store.ActiveProfile(); err == nil {
				s.Profile = p.Label()
				s.Edge = p.Endpoint()
			}
		}
	}

	if cl != nil {
		s.Running = true
		ds := cl.dialer.Stats()
		// There is no relay in the middle here, so the counters come from the
		// dialer and the engine: connections spoofed, connections that could
		// not be, and the traffic the dialer's own wrappers tallied.
		s.Accepted = ds.Spoofed.Load()
		s.Failed = ds.DialFail.Load()
		s.Passthru = ds.PassedThru.Load()
		s.ResolveFail = ds.ResolveFail.Load()
		s.BytesUp = ds.BytesUp.Load()
		s.BytesDown = ds.BytesDown.Load()
		if es := cl.engine.Stats(); es != nil {
			s.Injected = es.Injected.Load()
			s.Confirmed = es.Confirmed.Load()
			s.SpoofFail = es.Failed.Load()
			s.Active = es.ActiveFlows.Load()
		}
		// Deliberately falls through to the shared rate calculation below, so
		// the throughput graph works the same way in both modes.
	} else if tun == nil {
		return s
	} else {
		s.Running = tun.Running()
		ts := tun.Stats()
		s.Accepted = ts.Accepted.Load()
		s.Active = ts.Active.Load()
		s.Failed = ts.Failed.Load()
		s.BytesUp = ts.BytesUp.Load()
		s.BytesDown = ts.BytesDown.Load()
		s.PoolIdle = tun.PoolIdle()

		if ps := tun.PoolStats(); ps != nil {
			s.PoolHits = ps.Hits.Load()
			s.PoolMisses = ps.Misses.Load()
			s.PoolDiscarded = ps.Discarded.Load()
		}
		if es := tun.EngineStats(); es != nil {
			s.Injected = es.Injected.Load()
			s.Confirmed = es.Confirmed.Load()
			s.SpoofFail = es.Failed.Load()
		}
	}

	// Derive rates from the delta since the previous push. On the relay path
	// the byte counters only move when a relay finishes, so these are averages
	// over the window rather than a true instantaneous rate.
	now := time.Now()
	if !lastAt.IsZero() {
		if elapsed := now.Sub(lastAt).Seconds(); elapsed > 0 {
			s.RateUp = float64(s.BytesUp-lastUp) / elapsed
			s.RateDown = float64(s.BytesDown-lastDn) / elapsed
		}
	}
	a.mu.Lock()
	a.lastAt, a.lastUp, a.lastDn = now, s.BytesUp, s.BytesDown
	a.mu.Unlock()

	return s
}

// errUnwrapPath digs a *os.PathError out of a wrapped error so os.IsNotExist
// can see it; config.Load wraps read failures with context.
func errUnwrapPath(err error) error {
	for err != nil {
		if pe, ok := err.(*os.PathError); ok {
			return pe
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return nil
}
