//go:build windows

// Package autostart manages the run-at-login entry for the app.
package autostart

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// runKey is the per-user startup list. HKCU rather than HKLM deliberately: the
// app needs elevation to run, and a machine-wide entry would fire a UAC prompt
// at every login for every account on the machine.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// valueName identifies our entry in the Run key.
const valueName = "SNI-Spoofing-Advance"

// Enabled reports whether the current executable is registered to start at login.
func Enabled() (bool, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false, fmt.Errorf("autostart: open registry key: %w", err)
	}
	defer k.Close()

	got, _, err := k.GetStringValue(valueName)
	if err == registry.ErrNotExist {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("autostart: read value: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		return got != "", nil
	}
	// A stale entry pointing at an older location is not "enabled" for this
	// build; reporting it as such would leave the toggle on while the entry
	// launches something else.
	return strings.EqualFold(strings.Trim(got, `"`), exe), nil
}

// SetEnabled adds or removes the startup entry for the current executable.
func SetEnabled(on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("autostart: open registry key: %w", err)
	}
	defer k.Close()

	if !on {
		if err := k.DeleteValue(valueName); err != nil && err != registry.ErrNotExist {
			return fmt.Errorf("autostart: remove value: %w", err)
		}
		return nil
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("autostart: locate executable: %w", err)
	}
	// Quoted so a path containing spaces is not split into arguments.
	if err := k.SetStringValue(valueName, `"`+exe+`"`); err != nil {
		return fmt.Errorf("autostart: write value: %w", err)
	}
	return nil
}
