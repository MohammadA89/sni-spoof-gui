//go:build windows

package main

import (
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/autostart"
)

// GetAutostart reports whether this build is registered to start at login.
func (a *App) GetAutostart() bool {
	on, err := autostart.Enabled()
	if err != nil {
		a.log("autostart: %v", err)
		return false
	}
	return on
}

// SetAutostart adds or removes the run-at-login entry.
func (a *App) SetAutostart(on bool) error {
	if err := autostart.SetEnabled(on); err != nil {
		a.log("autostart: %v", err)
		return err
	}
	if on {
		a.log("will start with Windows")
	} else {
		a.log("will no longer start with Windows")
	}
	return nil
}

// MinimiseToTray hides the window. The tunnel keeps running: closing the window
// is not the same as disconnecting, and a user who minimised mid-session would
// not expect their traffic to stop.
func (a *App) MinimiseToTray() {
	if a.ctx != nil {
		wruntime.WindowHide(a.ctx)
	}
}

// ShowWindow brings the window back from the tray.
func (a *App) ShowWindow() {
	if a.ctx != nil {
		wruntime.WindowShow(a.ctx)
		wruntime.WindowUnminimise(a.ctx)
	}
}

// Quit stops the tunnel and exits.
func (a *App) Quit() {
	if a.ctx != nil {
		wruntime.Quit(a.ctx)
	}
}
