//go:build windows

package main

import (
	"fmt"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/sysproxy"
)

// SystemProxyState is what the UI shows for the system proxy toggle.
type SystemProxyState struct {
	// Enabled is whether Windows currently has a proxy configured at all,
	// including one this app did not set.
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`

	// Ours reports whether this app is the one that turned it on, which is
	// what decides whether the toggle may safely put it back.
	Ours bool `json:"ours"`
}

// GetSystemProxy reports the current Windows proxy setting.
func (a *App) GetSystemProxy() SystemProxyState {
	s, err := sysproxy.Get()
	if err != nil {
		a.log("system proxy: %v", err)
		return SystemProxyState{}
	}

	a.mu.Lock()
	ours := a.proxySet
	a.mu.Unlock()

	return SystemProxyState{Enabled: s.Enabled, Server: s.Server, Ours: ours}
}

// SetSystemProxy points Windows at the local HTTP inbound, or puts back what
// was configured before.
//
// The HTTP inbound rather than the SOCKS one: the Windows setting is read by
// WinINET, and what it expects there is an HTTP proxy.
func (a *App) SetSystemProxy(on bool) error {
	a.mu.Lock()
	cfg := a.cfg
	already := a.proxySet
	a.mu.Unlock()

	if !on {
		return a.clearSystemProxy()
	}
	if already {
		return nil
	}
	if !cfg.Client.Enabled {
		return fmt.Errorf("the system proxy needs the built-in client; the relay listener carries no HTTP proxy")
	}

	addr := fmt.Sprintf("%s:%d", cfg.Listener.Host, cfg.Client.HTTPPort)
	previous, err := sysproxy.Enable(addr, "")
	if err != nil {
		a.log("system proxy: %v", err)
		return err
	}

	a.mu.Lock()
	a.proxyPrev = previous
	a.proxySet = true
	a.mu.Unlock()

	a.log("windows is now using %s as its proxy", addr)
	return nil
}

// clearSystemProxy restores whatever was configured before this app touched it.
//
// Restoring rather than simply disabling is the whole point: a user who had
// their own proxy set would otherwise find it silently switched off, and a
// proxy left pointing at a closed port breaks browsing entirely until they go
// and find the setting themselves.
func (a *App) clearSystemProxy() error {
	a.mu.Lock()
	ours := a.proxySet
	previous := a.proxyPrev
	a.proxySet = false
	a.mu.Unlock()

	if !ours {
		// Nothing of ours to undo. Turning the proxy off anyway would be
		// meddling with a setting the user made themselves.
		return nil
	}

	if err := sysproxy.Restore(previous); err != nil {
		a.log("system proxy: could not restore the previous setting: %v", err)
		return err
	}
	if previous.Enabled {
		a.log("windows proxy restored to %s", previous.Server)
	} else {
		a.log("windows proxy turned off again")
	}
	return nil
}
