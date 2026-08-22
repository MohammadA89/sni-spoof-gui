//go:build windows

// Command sniproxy runs the spoofing transport as a local TCP listener.
//
// Point a client such as v2rayN or Xray at the listener address instead of the
// real server address, leaving the rest of its config alone. Everything the
// client sends - its TLS handshake, its own SNI, its proxy protocol - travels
// through untouched; this process only ensures the TCP path underneath has
// already been waved through by DPI.
//
//	sniproxy -edge 104.17.0.1 -fake-sni auth.vercel.com
//
// Run it from an elevated prompt; WinDivert installs a kernel driver.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/config"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/tunnel"
)

func main() {
	var (
		configPath = flag.String("config", "", "path to a config file (an upstream config.json is migrated automatically)")
		listen     = flag.String("listen", "", "listener address override, host:port")
		edge       = flag.String("edge", "", "edge IP override")
		fakeSNI    = flag.String("fake-sni", "", "fake SNI override")
		mode       = flag.String("mode", "", "capture mode override: fast or safe")
		poolSize   = flag.Int("pool", -1, "warm connection count override, 0 disables pooling")
		noSpoof    = flag.Bool("no-spoof", false, "relay without injecting, to compare against a spoofed run")
		save       = flag.String("save", "", "write the effective config to this path and exit")
	)
	flag.Parse()

	cfg := config.Default()
	if *configPath != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			fatalf("%v", err)
		}
		cfg = loaded
	}
	if err := applyOverrides(&cfg, *listen, *edge, *fakeSNI, *mode, *poolSize, *noSpoof); err != nil {
		fatalf("%v", err)
	}
	if err := cfg.Validate(); err != nil {
		fatalf("%v", err)
	}

	if *save != "" {
		if err := config.Save(*save, cfg); err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("wrote %s\n", *save)
		return
	}

	logger := log.New(os.Stdout, "", log.Ltime)
	t, err := tunnel.New(cfg, func(format string, args ...any) {
		logger.Printf(format, args...)
	})
	if err != nil {
		fatalf("%v", err)
	}
	if err := t.Start(); err != nil {
		fatalf("%v\n\nWinDivert needs administrator rights. Run this from an elevated prompt.", err)
	}

	fmt.Printf("\n  Point your client at %s\n", cfg.Listener.Addr())
	fmt.Printf("  Relaying to %s:%d, fake SNI %q\n\n", cfg.Transport.EdgeIPs[0], cfg.Transport.EdgePort, cfg.Transport.FakeSNI)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			fmt.Println("\nshutting down")
			if err := t.Stop(); err != nil {
				fatalf("%v", err)
			}
			return
		case <-ticker.C:
			printStats(logger, t)
		}
	}
}

func applyOverrides(cfg *config.Config, listen, edge, fakeSNI, mode string, poolSize int, noSpoof bool) error {
	if listen != "" {
		host, port, err := splitHostPort(listen)
		if err != nil {
			return err
		}
		cfg.Listener.Host, cfg.Listener.Port = host, port
	}
	if edge != "" {
		cfg.Transport.EdgeIPs = []string{edge}
	}
	if fakeSNI != "" {
		cfg.Transport.FakeSNI = fakeSNI
	}
	if mode != "" {
		cfg.Transport.Mode = mode
	}
	if noSpoof {
		cfg.Transport.Spoof = false
	}
	if poolSize >= 0 {
		cfg.Pool.Enabled = poolSize > 0
		if poolSize > 0 {
			cfg.Pool.Size = poolSize
		}
	}
	return nil
}

func splitHostPort(s string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("bad -listen %q: expected host:port", s)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("bad -listen %q: %w", s, err)
	}
	return host, port, nil
}

func printStats(logger *log.Logger, t *tunnel.Tunnel) {
	s := t.Stats()
	line := fmt.Sprintf("accepted %d, active %d, failed %d, up %s, down %s, pool idle %d",
		s.Accepted.Load(), s.Active.Load(), s.Failed.Load(),
		humanBytes(s.BytesUp.Load()), humanBytes(s.BytesDown.Load()), t.PoolIdle())

	if ps := t.PoolStats(); ps != nil {
		line += fmt.Sprintf(" (hits %d, misses %d, discarded %d)",
			ps.Hits.Load(), ps.Misses.Load(), ps.Discarded.Load())
	}
	if es := t.EngineStats(); es != nil {
		line += fmt.Sprintf(" | injected %d, failed %d", es.Injected.Load(), es.Failed.Load())
	}
	logger.Println(line)
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
