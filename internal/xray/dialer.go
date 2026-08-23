//go:build windows

// Package xray runs an embedded xray-core whose outbound connections are dialled
// through the spoofing engine.
//
// The hook is xray's own extension point: internet.UseAlternativeSystemDialer
// replaces the dialer every transport ultimately calls. That is what lets a
// user config be used verbatim - no address rewriting, no local relay hop, no
// pinning the app to a single edge - because the spoof stops being a
// destination and becomes a property of how connections are made.
package xray

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// Dialer is the subset of *spoof.Engine this package needs. Keeping it an
// interface is what makes the routing decisions below testable: the real engine
// needs an open WinDivert handle and administrator rights, neither of which
// belongs in a unit test.
type Dialer interface {
	DialToPort(ctx context.Context, addr netip.Addr, port uint16) (xnet.Conn, error)
}

// Resolver turns a hostname into an IPv4 address. The spoofing engine works on
// addresses, so a destination that arrives as a domain has to be resolved
// before it can be dialled - and resolving it here, rather than letting the OS
// do it inside the dial, is also what allows a DoH resolver to be substituted
// for a local one that lies.
type Resolver interface {
	LookupIPv4(ctx context.Context, host string) (netip.Addr, error)
}

// Override rewrites where a destination is actually dialled while leaving the
// config - and therefore the SNI the peer is asked for - untouched. It is how a
// Cloudflare-fronted config reaches a scanned clean edge IP instead of whatever
// address the link named.
//
// Returning ok=false leaves the destination alone.
type Override func(dest xnet.Destination) (addr netip.Addr, ok bool)

// Stats are the counters the UI reads.
type Stats struct {
	Spoofed     atomic.Uint64
	PassedThru  atomic.Uint64
	Overridden  atomic.Uint64
	ResolveFail atomic.Uint64
	DialFail    atomic.Uint64

	// BytesUp and BytesDown count what crosses every connection this dialer
	// hands out. With the built-in client there is no relay in the middle to
	// count for us, and without this the dashboard's throughput graph would sit
	// flat at zero while traffic flows.
	//
	// These are wire bytes, so they include the proxy protocol's own overhead
	// rather than only the payload the application sees.
	BytesUp   atomic.Uint64
	BytesDown atomic.Uint64
}

// countingConn tallies traffic without otherwise touching the connection.
//
// Writing towards the server is upload and reading from it is download, which
// is the same orientation the relay path reports, so the two modes cannot
// disagree about which direction is which.
type countingConn struct {
	xnet.Conn
	stats *Stats
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.stats.BytesDown.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.stats.BytesUp.Add(uint64(n))
	}
	return n, err
}

// SpoofDialer implements internet.SystemDialer on top of the spoofing engine.
//
// Not every dial can be spoofed, and the ones that cannot must still work. UDP
// and IPv6 both fall through to the dialer xray would otherwise have used,
// because the engine is TCP-over-IPv4 only. Falling through rather than failing
// matters more than it looks: xray's DNS and any QUIC transport ride UDP, and
// refusing those would break the instance rather than merely leaving it
// unspoofed.
type SpoofDialer struct {
	engine   Dialer
	fallback internet.SystemDialer
	resolver Resolver
	override Override
	logf     func(string, ...any)
	stats    Stats
}

// Options configure a SpoofDialer. Only Engine is required.
type Options struct {
	Engine   Dialer
	Resolver Resolver
	Override Override

	// Fallback receives the dials that cannot be spoofed. When nil, xray's own
	// default dialer is used, which is almost always what is wanted.
	Fallback internet.SystemDialer

	Logf func(string, ...any)
}

// New builds a SpoofDialer. It does not install it; see Install.
func New(opt Options) (*SpoofDialer, error) {
	if opt.Engine == nil {
		return nil, fmt.Errorf("xray: a spoofing engine is required")
	}
	d := &SpoofDialer{
		engine:   opt.Engine,
		fallback: opt.Fallback,
		resolver: opt.Resolver,
		override: opt.Override,
		logf:     opt.Logf,
	}
	if d.fallback == nil {
		d.fallback = &internet.DefaultSystemDialer{}
	}
	if d.resolver == nil {
		d.resolver = SystemResolver{}
	}
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}
	return d, nil
}

// Stats returns the live counter block.
func (d *SpoofDialer) Stats() *Stats { return &d.stats }

// DestIpAddress implements internet.SystemDialer. Returning nil leaves xray to
// use the destination from the configuration; this dialer redirects per dial
// instead, so there is no single address to report.
func (d *SpoofDialer) DestIpAddress() xnet.IP { return nil }

// Dial implements internet.SystemDialer.
func (d *SpoofDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	addr, ok := d.spoofTarget(ctx, dest)
	if !ok {
		d.stats.PassedThru.Add(1)
		// sockopt has to be handed on, or xray's own socket options silently
		// stop applying to everything that falls through here.
		conn, err := d.fallback.Dial(ctx, src, dest, sockopt)
		if err != nil {
			return nil, err
		}
		// Counted too: these bytes are just as real, and leaving them out
		// would make the throughput read low whenever UDP is in play.
		return d.count(conn), nil
	}

	conn, err := d.engine.DialToPort(ctx, addr, uint16(dest.Port))
	if err != nil {
		d.stats.DialFail.Add(1)
		return nil, fmt.Errorf("xray: spoofed dial to %s:%d failed: %w", addr, dest.Port, err)
	}
	d.stats.Spoofed.Add(1)
	return d.count(conn), nil
}

// count wraps a connection so its traffic is tallied.
func (d *SpoofDialer) count(conn xnet.Conn) xnet.Conn {
	if conn == nil {
		return nil
	}
	return &countingConn{Conn: conn, stats: &d.stats}
}

// spoofTarget decides whether a destination can be spoofed, and to which
// address. The false return is not an error: it means "this one goes through
// the ordinary dialer".
func (d *SpoofDialer) spoofTarget(ctx context.Context, dest xnet.Destination) (netip.Addr, bool) {
	if dest.Network != xnet.Network_TCP {
		return netip.Addr{}, false
	}

	// An override wins over both the configured address and DNS: the whole
	// point is to reach a different address than the config names.
	if d.override != nil {
		if addr, ok := d.override(dest); ok && addr.Is4() {
			d.stats.Overridden.Add(1)
			return addr, true
		}
	}

	switch {
	case dest.Address.Family().IsIPv4():
		addr, ok := netip.AddrFromSlice(dest.Address.IP().To4())
		return addr, ok

	case dest.Address.Family().IsIPv6():
		// The engine builds IPv4 packets only. Handing it a v6 destination
		// would fail every time, so this goes straight through.
		return netip.Addr{}, false

	case dest.Address.Family().IsDomain():
		addr, err := d.resolver.LookupIPv4(ctx, dest.Address.Domain())
		if err != nil {
			// A failed lookup falls through rather than failing the dial: the
			// ordinary dialer may still resolve it, and an unspoofed
			// connection beats no connection.
			d.stats.ResolveFail.Add(1)
			d.logf("could not resolve %s for spoofing (%v); dialing it unspoofed", dest.Address.Domain(), err)
			return netip.Addr{}, false
		}
		return addr, true
	}
	return netip.Addr{}, false
}

// installMu guards the process-wide dialer slot. UseAlternativeSystemDialer
// writes a package-level variable in xray, so installing from two places at
// once would leave whichever lost the race silently bypassed.
var installMu sync.Mutex

// Install routes every xray dial in this process through d, and returns a
// function that puts the default dialer back.
//
// The slot is global to xray-core, so this affects any instance running in the
// process. Restoring on shutdown matters: a stopped tunnel must not leave a
// dialer behind that holds a closed engine.
func Install(d *SpoofDialer) (restore func()) {
	installMu.Lock()
	defer installMu.Unlock()

	internet.UseAlternativeSystemDialer(d)
	var once sync.Once
	return func() {
		once.Do(func() {
			installMu.Lock()
			defer installMu.Unlock()
			// Passing nil restores xray's DefaultSystemDialer.
			internet.UseAlternativeSystemDialer(nil)
		})
	}
}
