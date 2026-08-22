//go:build windows

package main

import (
	_ "embed"

	"github.com/energye/systray"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed build/windows/icon.ico
var trayIcon []byte

// startTray puts an icon in the notification area.
//
// The window can then be closed without ending the session: a user who shuts
// the window mid-transfer almost never means "drop my connections", so closing
// hides instead, and the tray icon is what makes the app reachable again.
func (a *App) startTray() {
	systray.Run(a.onTrayReady, func() {})
}

func (a *App) onTrayReady() {
	systray.SetIcon(trayIcon)
	systray.SetTitle("SNI Spoofing Advance")
	systray.SetTooltip("SNI Spoofing Advance")

	show := systray.AddMenuItem("Show", "Open the window")
	systray.AddSeparator()
	connect := systray.AddMenuItem("Connect", "Start the tunnel")
	disconnect := systray.AddMenuItem("Disconnect", "Stop the tunnel")
	systray.AddSeparator()
	quit := systray.AddMenuItem("Quit", "Stop and exit")

	show.Click(a.ShowWindow)
	systray.SetOnClick(func(menu systray.IMenu) { a.ShowWindow() })

	connect.Click(func() {
		if err := a.Start(); err != nil {
			a.log("tray: %v", err)
		}
	})
	disconnect.Click(func() {
		if err := a.Stop(); err != nil {
			a.log("tray: %v", err)
		}
	})
	quit.Click(func() {
		if a.ctx != nil {
			wruntime.Quit(a.ctx)
		}
	})
}
