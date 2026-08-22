//go:build windows

// Command SNI-Spoofing-Advance is the desktop front end for the spoofing
// transport.
//
// The window is a control panel: it configures and supervises the same tunnel
// that cmd/sniproxy runs headlessly. Point a client such as v2rayN or Xray at
// the listener address and leave the rest of its config alone.
//
// Based on patterniha/SNI-Spoofing (GPL-3.0).
package main

import (
	"context"
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewApp()

	// The tray owns its own message loop, so it runs alongside the webview
	// rather than inside it.
	go app.startTray()

	err := wails.Run(&options.App{
		Title:     "SNI Spoofing Advance",
		Width:     1100,
		Height:    720,
		MinWidth:  920,
		MinHeight: 620,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		OnStartup:  app.startup,
		OnShutdown: app.shutdown,
		// Closing the window hides it instead of quitting. The tunnel keeps
		// running, and the tray icon is how it comes back.
		OnBeforeClose: func(ctx context.Context) bool {
			wruntime.WindowHide(ctx)
			return true
		},
		// A second launch surfaces the running window rather than starting a
		// rival instance that would fight over the WinDivert handle.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "sni-spoofing-advance-8f2c1a",
			OnSecondInstanceLaunch: func(options.SecondInstanceData) {
				app.ShowWindow()
			},
		},
		Bind: []any{
			app,
		},
		Windows: &windows.Options{
			// The UI paints its own dark chrome, so let the frame follow it
			// rather than flashing white on launch.
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
		},
	})
	if err != nil {
		panic(err)
	}
}
