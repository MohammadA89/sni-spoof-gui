//go:build windows

// Package sysproxy points Windows at a local proxy, and puts back what was
// there before.
//
// Everything here is per-user: the settings live under HKEY_CURRENT_USER, so no
// elevation is needed for this even though the rest of the app requires it for
// WinDivert.
//
// The part that is easy to get wrong is not the registry write but the two
// steps around it. Applications that use WinINET - which includes Chrome, Edge
// and anything using the system settings - cache the proxy configuration and
// will not notice a change until they are told, so a write with no notification
// appears to do nothing. And a proxy that is enabled and then left behind when
// the app exits breaks the user's browsing until they find the setting
// themselves, which is why the previous values are saved and restored rather
// than simply cleared.
package sysproxy

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// settingsKey is where WinINET keeps the per-user proxy configuration.
//
// It is a variable rather than a constant so tests can point at a scratch key.
// Exercising this package against the real one would mean a test run rewriting
// the developer's own proxy configuration, and a test that fails halfway would
// leave it rewritten.
var settingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// DefaultBypass keeps local traffic off the proxy. "<local>" covers hostnames
// with no dot in them, which is what Windows uses for the local intranet.
const DefaultBypass = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// wininet options for the notification that makes running applications reload.
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet             = windows.NewLazySystemDLL("wininet.dll")
	procInternetSetOpts = wininet.NewProc("InternetSetOptionW")
)

// State is the proxy configuration as Windows holds it.
type State struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Bypass  string `json:"bypass"`
}

// Get reads the current settings.
func Get() (State, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.QUERY_VALUE)
	if err != nil {
		return State{}, fmt.Errorf("sysproxy: open settings: %w", err)
	}
	defer k.Close()

	var s State
	// A missing value is the normal "never configured" state, not a failure,
	// so absent values leave the zero value in place.
	if v, _, err := k.GetIntegerValue("ProxyEnable"); err == nil {
		s.Enabled = v != 0
	}
	if v, _, err := k.GetStringValue("ProxyServer"); err == nil {
		s.Server = v
	}
	if v, _, err := k.GetStringValue("ProxyOverride"); err == nil {
		s.Bypass = v
	}
	return s, nil
}

// Set writes the settings and notifies WinINET.
func Set(s State) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, settingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("sysproxy: open settings for writing: %w", err)
	}
	defer k.Close()

	var enable uint32
	if s.Enabled {
		enable = 1
	}
	if err := k.SetDWordValue("ProxyEnable", enable); err != nil {
		return fmt.Errorf("sysproxy: set ProxyEnable: %w", err)
	}
	// The server and bypass values are written even when disabling, so that
	// restoring a previous state puts back exactly what was there.
	if err := k.SetStringValue("ProxyServer", s.Server); err != nil {
		return fmt.Errorf("sysproxy: set ProxyServer: %w", err)
	}
	if err := k.SetStringValue("ProxyOverride", s.Bypass); err != nil {
		return fmt.Errorf("sysproxy: set ProxyOverride: %w", err)
	}

	notifyChanged()
	return nil
}

// Enable points Windows at addr, which is a host:port such as 127.0.0.1:10809.
//
// It returns the settings that were in place beforehand. Keeping them is the
// caller's job and it matters: without them, turning the proxy off later would
// mean clearing whatever the user had configured for their own reasons.
func Enable(addr, bypass string) (previous State, err error) {
	if addr == "" {
		return State{}, fmt.Errorf("sysproxy: no proxy address given")
	}
	// A scheme here would be written through verbatim and silently break every
	// application that reads the value.
	if strings.Contains(addr, "://") {
		return State{}, fmt.Errorf("sysproxy: proxy address %q must be host:port, without a scheme", addr)
	}
	if bypass == "" {
		bypass = DefaultBypass
	}

	previous, err = Get()
	if err != nil {
		return State{}, err
	}
	if err := Set(State{Enabled: true, Server: addr, Bypass: bypass}); err != nil {
		return State{}, err
	}
	return previous, nil
}

// Restore puts back a state captured by Enable.
func Restore(previous State) error {
	return Set(previous)
}

// Disable turns the proxy off without touching the stored server address, for
// the case where no previous state was captured.
func Disable() error {
	current, err := Get()
	if err != nil {
		return err
	}
	current.Enabled = false
	return Set(current)
}

// notifyChanged tells running applications to re-read the settings.
//
// Without this the registry holds the new value and every already-running
// browser keeps using the old one, which looks exactly like the feature not
// working. Failures are ignored deliberately: the settings are written either
// way, and a browser restart picks them up.
func notifyChanged() {
	procInternetSetOpts.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOpts.Call(0, internetOptionRefresh, 0, 0)
}
