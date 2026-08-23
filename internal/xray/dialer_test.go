//go:build windows

package xray

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
)

// fakeEngine records what it was asked to dial and hands back a closed pipe.
type fakeEngine struct {
	calls []string
	err   error
}

func (f *fakeEngine) DialToPort(_ context.Context, addr netip.Addr, port uint16) (xnet.Conn, error) {
	f.calls = append(f.calls, netip.AddrPortFrom(addr, port).String())
	if f.err != nil {
		return nil, f.err
	}
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

// fakeFallback records the dials that were not spoofed.
type fakeFallback struct {
	calls   []string
	sockopt []*internet.SocketConfig
}

func (f *fakeFallback) Dial(_ context.Context, _ xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (xnet.Conn, error) {
	f.calls = append(f.calls, dest.String())
	f.sockopt = append(f.sockopt, sockopt)
	client, server := net.Pipe()
	server.Close()
	return client, nil
}

func (f *fakeFallback) DestIpAddress() xnet.IP { return nil }

type fakeResolver struct {
	addr netip.Addr
	err  error
	hits int
}

func (f *fakeResolver) LookupIPv4(context.Context, string) (netip.Addr, error) {
	f.hits++
	return f.addr, f.err
}

func newTestDialer(t *testing.T, opt Options) (*SpoofDialer, *fakeEngine, *fakeFallback) {
	t.Helper()
	eng := &fakeEngine{}
	fb := &fakeFallback{}
	if opt.Engine == nil {
		opt.Engine = eng
	}
	if opt.Fallback == nil {
		opt.Fallback = fb
	}
	d, err := New(opt)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d, eng, fb
}

func tcpDest(t *testing.T, host string, port uint16) xnet.Destination {
	t.Helper()
	return xnet.Destination{
		Address: xnet.ParseAddress(host),
		Port:    xnet.Port(port),
		Network: xnet.Network_TCP,
	}
}

func TestIPv4TCPIsSpoofed(t *testing.T) {
	d, eng, fb := newTestDialer(t, Options{})

	conn, err := d.Dial(context.Background(), nil, tcpDest(t, "104.17.0.1", 443), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(eng.calls) != 1 || eng.calls[0] != "104.17.0.1:443" {
		t.Errorf("engine calls = %v, want [104.17.0.1:443]", eng.calls)
	}
	if len(fb.calls) != 0 {
		t.Errorf("nothing should have fallen through, got %v", fb.calls)
	}
	if got := d.Stats().Spoofed.Load(); got != 1 {
		t.Errorf("Spoofed = %d, want 1", got)
	}
}

// UDP and IPv6 have to keep working. The engine builds IPv4 TCP packets and
// nothing else, and refusing these would break xray's DNS rather than merely
// leaving it unspoofed.
func TestUnspoofableDestinationsFallThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		dest xnet.Destination
	}{
		{"udp", xnet.Destination{Address: xnet.ParseAddress("8.8.8.8"), Port: 53, Network: xnet.Network_UDP}},
		{"ipv6", tcpDest(t, "2606:4700::1111", 443)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, eng, fb := newTestDialer(t, Options{})

			conn, err := d.Dial(context.Background(), nil, tc.dest, nil)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			conn.Close()

			if len(eng.calls) != 0 {
				t.Errorf("the engine should not have been used: %v", eng.calls)
			}
			if len(fb.calls) != 1 {
				t.Errorf("fallback calls = %v, want one", fb.calls)
			}
			if got := d.Stats().PassedThru.Load(); got != 1 {
				t.Errorf("PassedThru = %d, want 1", got)
			}
		})
	}
}

// Dropping sockopt on the fall-through path would silently stop xray's own
// socket options from applying to everything that is not spoofed.
func TestFallthroughKeepsSockopt(t *testing.T) {
	d, _, fb := newTestDialer(t, Options{})
	want := &internet.SocketConfig{Mark: 42}

	dest := xnet.Destination{Address: xnet.ParseAddress("8.8.8.8"), Port: 53, Network: xnet.Network_UDP}
	conn, err := d.Dial(context.Background(), nil, dest, want)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(fb.sockopt) != 1 || fb.sockopt[0] != want {
		t.Errorf("sockopt was not passed through: %v", fb.sockopt)
	}
}

func TestDomainIsResolvedThenSpoofed(t *testing.T) {
	res := &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")}
	d, eng, fb := newTestDialer(t, Options{Resolver: res})

	conn, err := d.Dial(context.Background(), nil, tcpDest(t, "example.com", 8443), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(eng.calls) != 1 || eng.calls[0] != "1.2.3.4:8443" {
		t.Errorf("engine calls = %v, want [1.2.3.4:8443]", eng.calls)
	}
	if len(fb.calls) != 0 {
		t.Errorf("nothing should have fallen through: %v", fb.calls)
	}
}

// A lookup that fails must not fail the dial: the ordinary dialer may still
// resolve it, and an unspoofed connection beats no connection.
func TestResolveFailureFallsThrough(t *testing.T) {
	res := &fakeResolver{err: errors.New("no such host")}
	d, eng, fb := newTestDialer(t, Options{Resolver: res})

	conn, err := d.Dial(context.Background(), nil, tcpDest(t, "example.com", 443), nil)
	if err != nil {
		t.Fatalf("dial should have fallen through, not failed: %v", err)
	}
	conn.Close()

	if len(eng.calls) != 0 {
		t.Errorf("the engine should not have been used: %v", eng.calls)
	}
	if len(fb.calls) != 1 {
		t.Errorf("fallback calls = %v, want one", fb.calls)
	}
	if got := d.Stats().ResolveFail.Load(); got != 1 {
		t.Errorf("ResolveFail = %d, want 1", got)
	}
}

// The Cloudflare-fronted case: dial a scanned clean edge instead of the address
// the config names, without touching the config or the SNI it will ask for.
func TestOverrideRedirectsWithoutTouchingTheConfig(t *testing.T) {
	edge := netip.MustParseAddr("188.114.98.0")
	d, eng, _ := newTestDialer(t, Options{
		Resolver: &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")},
		Override: func(xnet.Destination) (netip.Addr, bool) { return edge, true },
	})

	conn, err := d.Dial(context.Background(), nil, tcpDest(t, "config.example.com", 443), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(eng.calls) != 1 || eng.calls[0] != "188.114.98.0:443" {
		t.Errorf("engine calls = %v, want the override address", eng.calls)
	}
	if got := d.Stats().Overridden.Load(); got != 1 {
		t.Errorf("Overridden = %d, want 1", got)
	}
}

// An override that declines has to leave the destination alone rather than
// blocking the dial.
func TestOverrideDecliningLeavesDestinationAlone(t *testing.T) {
	d, eng, _ := newTestDialer(t, Options{
		Override: func(xnet.Destination) (netip.Addr, bool) { return netip.Addr{}, false },
	})

	conn, err := d.Dial(context.Background(), nil, tcpDest(t, "104.17.0.1", 443), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if len(eng.calls) != 1 || eng.calls[0] != "104.17.0.1:443" {
		t.Errorf("engine calls = %v, want the original address", eng.calls)
	}
}

// A failing engine must report, not fall through. Silently dialling unspoofed
// would look like success while doing the one thing the app exists to avoid.
func TestEngineFailureIsReported(t *testing.T) {
	eng := &fakeEngine{err: errors.New("no free source port")}
	d, _, fb := newTestDialer(t, Options{Engine: eng})

	if _, err := d.Dial(context.Background(), nil, tcpDest(t, "104.17.0.1", 443), nil); err == nil {
		t.Fatal("expected the dial to fail")
	}
	if len(fb.calls) != 0 {
		t.Errorf("a failed spoof must not quietly fall through: %v", fb.calls)
	}
	if got := d.Stats().DialFail.Load(); got != 1 {
		t.Errorf("DialFail = %d, want 1", got)
	}
}

func TestNewRequiresAnEngine(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Error("an engine is required")
	}
}

func TestCachingResolverCollapsesABurst(t *testing.T) {
	inner := &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")}
	c := NewCachingResolver(inner, time.Minute)

	for i := 0; i < 10; i++ {
		addr, err := c.LookupIPv4(context.Background(), "example.com")
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if addr.String() != "1.2.3.4" {
			t.Fatalf("addr = %s", addr)
		}
	}
	if inner.hits != 1 {
		t.Errorf("inner resolver hit %d times, want 1", inner.hits)
	}

	c.Forget("example.com")
	if _, err := c.LookupIPv4(context.Background(), "example.com"); err != nil {
		t.Fatalf("lookup after Forget: %v", err)
	}
	if inner.hits != 2 {
		t.Errorf("Forget should force a fresh lookup, hits = %d", inner.hits)
	}
}

func TestCachingResolverZeroTTLDisablesCaching(t *testing.T) {
	inner := &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")}
	c := NewCachingResolver(inner, 0)

	for i := 0; i < 3; i++ {
		if _, err := c.LookupIPv4(context.Background(), "example.com"); err != nil {
			t.Fatalf("lookup: %v", err)
		}
	}
	if inner.hits != 3 {
		t.Errorf("caching should be off, hits = %d, want 3", inner.hits)
	}
}

func TestSystemResolverPassesLiteralsThrough(t *testing.T) {
	addr, err := SystemResolver{}.LookupIPv4(context.Background(), "104.17.0.1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "104.17.0.1" {
		t.Errorf("addr = %s", addr)
	}
	// An IPv6 literal is not an error the caller should retry; it is simply
	// not spoofable, and the message has to say so.
	if _, err := (SystemResolver{}).LookupIPv4(context.Background(), "2606:4700::1111"); err == nil {
		t.Error("an IPv6 literal should be rejected")
	}
}

// Install writes a process-wide slot in xray, so it has to put the default
// back when the tunnel stops - otherwise a stopped engine stays wired in.
func TestInstallRestoresTheDefaultDialer(t *testing.T) {
	d, _, _ := newTestDialer(t, Options{})

	restore := Install(d)
	dest := tcpDest(t, "104.17.0.1", 443)
	if _, err := internet.DialSystem(context.Background(), dest, nil); err != nil {
		t.Fatalf("dial through the installed dialer: %v", err)
	}
	if got := d.Stats().Spoofed.Load(); got != 1 {
		t.Fatalf("the installed dialer was not used, Spoofed = %d", got)
	}

	restore()
	restore() // must be safe to call twice

	before := d.Stats().Spoofed.Load()
	// Nothing is listening, so this fails - the point is only that it no
	// longer reaches our dialer.
	conn, err := internet.DialSystem(context.Background(), tcpDest(t, "127.0.0.1", 1), nil)
	if err == nil {
		conn.Close()
	}
	if got := d.Stats().Spoofed.Load(); got != before {
		t.Errorf("the dialer is still installed after restore")
	}
}
