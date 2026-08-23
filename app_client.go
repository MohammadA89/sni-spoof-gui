//go:build windows

package main

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	xnet "github.com/xtls/xray-core/common/net"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/config"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/netutil"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/profiles"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/share"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/spoof"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/xray"
)

// resolveTTL is how long the dialer remembers a server address. It collapses
// the burst of dials a browser makes without pinning a stale answer for long.
const resolveTTL = 5 * time.Minute

// routeProbe is only used to ask the operating system which local interface
// would be used to reach the internet, when the config's own server cannot be
// resolved. No packet is sent to it.
var routeProbe = netip.MustParseAddr("1.1.1.1")

// client holds a running built-in client: the spoofing engine underneath and
// the xray instance on top.
type client struct {
	engine   *spoof.Engine
	dialer   *xray.SpoofDialer
	instance *xray.Instance
}

func (c *client) close() {
	// Order matters. The instance goes first so nothing is still dialling when
	// the engine's WinDivert handle is released.
	if c.instance != nil {
		_ = c.instance.Close()
	}
	if c.engine != nil {
		_ = c.engine.Close()
	}
}

// startClient brings up the built-in client for the selected config.
func (a *App) startClient(cfg config.Config) error {
	var profile *share.Profile
	var entry profiles.Entry

	if cfg.Client.Direct {
		// No server, so nothing to select and nothing to validate. Every dial
		// still goes through the engine; only the destination changes.
		a.log("direct mode: no server, spoofing connections to their real destination")
		a.log("this cannot help with a site that blocks this country by address")
	} else {
		store := a.loadProfiles()
		p, e, err := store.ActiveProfile()
		if err != nil {
			return err
		}
		if err := p.Validate(); err != nil {
			return err
		}
		for _, w := range p.Warnings {
			a.log("note: %s", w)
		}
		profile, entry = p, e
	}

	// The interface address has to match the one in the capture filter, or the
	// engine never sees its own handshakes. Resolving the server first means
	// asking about the route that will actually be used.
	//
	// Note the ordering problem this creates and why it is acceptable: the
	// engine does not exist yet, so this first lookup cannot be spoofed. It is
	// one DoH request over an ordinary connection, and its only job is to pick
	// an interface. Every later lookup goes through the dialer installed below.
	resolver := xray.NewCachingResolver(a.newResolver(cfg), resolveTTL)
	probe := routeProbe
	if profile != nil {
		// With a server, ask about the route to it: that is the one the
		// connections will actually take. Direct mode has no single
		// destination, so the default route stands in.
		if addr, rerr := resolver.LookupIPv4(context.Background(), profile.Address); rerr == nil {
			probe = addr
		} else {
			a.log("could not resolve %s yet (%v); using the default route to pick an interface", profile.Address, rerr)
		}
	}

	iface, err := netutil.DefaultInterfaceIPv4(probe)
	if err != nil {
		return err
	}

	engine, err := spoof.NewEngine(spoof.Config{
		InterfaceIP: iface,
		EdgeIP:      probe,
		EdgePort:    uint16(cfg.Transport.EdgePort),
		FakeSNI:     cfg.Transport.FakeSNI,
		Mode:        spoof.Mode(cfg.Transport.Mode),
		InjectDelay: cfg.Transport.InjectDelay(),
		PortLow:     uint16(cfg.Transport.PortLow),
		PortHigh:    uint16(cfg.Transport.PortHigh),
		// The destination is now whatever the config names, on whatever port it
		// names, so neither can be pinned in the filter.
		AnyEdge: true,
		AnyPort: true,
		OnEvent: func(msg string) { a.log("%s", msg) },
	})
	if err != nil {
		return err
	}
	if err := engine.Start(); err != nil {
		return err
	}

	var override xray.Override
	if profile != nil && entry.EdgeOverride {
		edge, eerr := cfg.Transport.PrimaryEdge()
		if eerr != nil {
			engine.Close()
			return fmt.Errorf("this config is set to use a scanned edge, but no edge address is configured: %w", eerr)
		}
		override = edgeOverride(profile, edge)
		a.log("dialling %s at the scanned edge %s, keeping its own SNI", profile.Address, edge)
	}

	dialer, err := xray.New(xray.Options{
		Engine:   engine,
		Resolver: resolver,
		Override: override,
		Logf:     a.log,
	})
	if err != nil {
		engine.Close()
		return err
	}

	inst, err := xray.Start(xray.InstanceOptions{
		Profile:   profile,
		Direct:    cfg.Client.Direct,
		Listen:    cfg.Listener.Host,
		SocksPort: cfg.Client.SocksPort,
		HTTPPort:  cfg.Client.HTTPPort,
		DoH:       cfg.Client.DoH,
		LogLevel:  cfg.Log.Level,
	}, dialer)
	if err != nil {
		engine.Close()
		return err
	}

	a.mu.Lock()
	a.client = &client{engine: engine, dialer: dialer, instance: inst}
	a.lastAt = time.Time{}
	a.mu.Unlock()

	if profile != nil {
		a.log("connected using %s", profile.Redacted())
	} else {
		a.log("connected in direct mode")
	}
	a.log("socks on %s:%d, http on %s:%d", cfg.Listener.Host, cfg.Client.SocksPort,
		cfg.Listener.Host, cfg.Client.HTTPPort)
	return nil
}

// newResolver builds the resolver the dialer uses for the config's own server
// address.
//
// This is the name most worth lying about: a wrong answer here points the
// spoofed connection at a machine that is not there, and it looks like a dead
// config rather than like DNS. A DoH failure falls back to the system resolver
// rather than refusing to connect, because a resolver that is merely
// unreachable should not be the reason nothing works.
func (a *App) newResolver(cfg config.Config) xray.Resolver {
	if cfg.Client.DoH == "" || cfg.Client.DoH == "off" {
		a.log("resolving through the system resolver; local DNS answers are trusted as-is")
		return xray.SystemResolver{}
	}
	r, err := xray.NewDoHResolver(xray.DoHOptions{Endpoint: cfg.Client.DoH})
	if err != nil {
		a.log("DoH is misconfigured (%v); falling back to the system resolver", err)
		return xray.SystemResolver{}
	}
	a.log("resolving over DoH at %s", cfg.Client.DoH)
	return xray.FallbackResolver{Primary: r, Secondary: xray.SystemResolver{}}
}

// edgeOverride redirects only the config's own server, and only when the
// destination port matches.
//
// Scoping it this tightly is the point: with the built-in client every
// connection xray makes passes through the dialer, including whatever the user
// is actually browsing. Redirecting all of that to a Cloudflare edge would send
// unrelated traffic to the wrong place.
func edgeOverride(p *share.Profile, edge netip.Addr) xray.Override {
	host := p.Address
	port := p.Port
	return func(dest xnet.Destination) (netip.Addr, bool) {
		if uint16(dest.Port) != port {
			return netip.Addr{}, false
		}
		if dest.Address.Family().IsDomain() {
			return edge, dest.Address.Domain() == host
		}
		return edge, dest.Address.IP().String() == host
	}
}

// stopClient tears the built-in client down.
func (a *App) stopClient() {
	a.mu.Lock()
	c := a.client
	a.client = nil
	a.mu.Unlock()

	if c != nil {
		c.close()
		a.log("client stopped")
	}
}
