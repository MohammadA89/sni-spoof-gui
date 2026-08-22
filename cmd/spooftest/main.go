//go:build windows

// Command spooftest validates the SNI-spoofing transport end to end.
//
// It is the risk gate for the project: it answers whether injecting a fake
// ClientHello with a deliberately wrong sequence number, driven off a SYN-only
// WinDivert filter, is enough to carry a real TLS session through DPI.
//
// No server of your own is needed. The test dials a clean edge IP, spoofs the
// handshake, then completes a genuine TLS session against a public domain that
// edge already serves:
//
//	spooftest -domain hcaptcha.com -control
//
// Run it from an elevated prompt; WinDivert installs a kernel driver.
//
// The -control flag repeats the run with spoofing switched off, and that
// comparison is the whole point. If the control also succeeds, this path is not
// being filtered and the run proves nothing - try a domain or edge IP that is
// actually blocked for you. If the control fails and the spoofed run succeeds,
// the transport works.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/netutil"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/spoof"
)

func main() {
	var (
		domain   = flag.String("domain", "hcaptcha.com", "domain to complete a real TLS session with; also used to find an edge IP")
		edgeStr  = flag.String("edge", "", "edge IP to connect to (default: resolve -domain)")
		edgePort = flag.Uint("port", 443, "edge port")
		fakeSNI  = flag.String("fake-sni", "auth.vercel.com", "SNI carried by the injected record")
		modeStr  = flag.String("mode", "fast", "capture mode: fast or safe")
		count    = flag.Int("n", 5, "number of connections to attempt")
		delay    = flag.Duration("inject-delay", spoof.DefaultInjectDelay, "wait after SYN-ACK before injecting")
		control  = flag.Bool("control", false, "also run a control group with spoofing disabled")
		verbose  = flag.Bool("v", false, "log engine events")
	)
	flag.Parse()

	if *domain == "" {
		fatalf("-domain is required")
	}
	if *domain == *fakeSNI {
		fatalf("-domain and -fake-sni are both %q; the fake SNI must be a different name", *domain)
	}

	edge, err := resolveEdge(*edgeStr, *domain)
	if err != nil {
		fatalf("%v", err)
	}
	iface, err := netutil.DefaultInterfaceIPv4(edge)
	if err != nil {
		fatalf("%v", err)
	}

	fmt.Printf("interface   %s\n", iface)
	fmt.Printf("edge        %s:%d\n", edge, *edgePort)
	fmt.Printf("real SNI    %s  (what the peer sees)\n", *domain)
	fmt.Printf("fake SNI    %s  (what DPI sees)\n", *fakeSNI)
	fmt.Printf("mode        %s, inject delay %s\n\n", *modeStr, *delay)

	if *control {
		fmt.Println("== control: no spoofing ==")
		run(*count, *domain, func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr(edge, uint16(*edgePort)))
		})
		fmt.Println()
	}

	fmt.Println("== spoofed ==")
	cfg := spoof.Config{
		InterfaceIP: iface,
		EdgeIP:      edge,
		EdgePort:    uint16(*edgePort),
		FakeSNI:     *fakeSNI,
		Mode:        spoof.Mode(*modeStr),
		InjectDelay: *delay,
	}
	if *verbose {
		cfg.OnEvent = func(msg string) { fmt.Printf("  [engine] %s\n", msg) }
	}

	engine, err := spoof.NewEngine(cfg)
	if err != nil {
		fatalf("%v", err)
	}
	if err := engine.Start(); err != nil {
		fatalf("%v\n\nWinDivert needs administrator rights. Run this from an elevated prompt.", err)
	}
	defer engine.Close()

	if *verbose {
		fmt.Printf("  filter: %s\n", engine.Filter())
	}

	run(*count, *domain, engine.Dial)

	s := engine.Stats()
	fmt.Printf("\nengine: %d packets seen, %d injected, %d confirmed, %d failed\n",
		s.PacketsSeen.Load(), s.Injected.Load(), s.Confirmed.Load(), s.Failed.Load())
}

// resolveEdge returns the edge IP to use, either the explicit one or the first
// IPv4 address the domain resolves to.
func resolveEdge(explicit, domain string) (netip.Addr, error) {
	if explicit != "" {
		a, err := netip.ParseAddr(explicit)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("bad -edge: %w", err)
		}
		if !a.Is4() {
			return netip.Addr{}, fmt.Errorf("-edge %q is not IPv4", explicit)
		}
		return a, nil
	}

	ips, err := net.LookupIP(domain)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolve %s: %w (pass -edge to skip DNS)", domain, err)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			a, _ := netip.AddrFromSlice(v4)
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no IPv4 address", domain)
}

func addr(ip netip.Addr, port uint16) string {
	return net.JoinHostPort(ip.String(), fmt.Sprint(port))
}

type result struct {
	dial, tlsTime time.Duration
	proto         string // negotiated TLS version and ALPN
	status        string
	err           error

	// handshook records that TLS completed, which is the signal that actually
	// matters. An HTTP failure afterwards is a much weaker result than a
	// handshake failure, and the two must not be reported alike.
	handshook bool
}

// run performs count attempts using dial, reporting each one.
func run(count int, domain string, dial func(context.Context) (net.Conn, error)) {
	results := make([]result, 0, count)
	for i := 0; i < count; i++ {
		results = append(results, attempt(domain, dial))
		report(i, results[i])
	}
	summarise(results)
}

func attempt(domain string, dial func(context.Context) (net.Conn, error)) result {
	var r result
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	start := time.Now()
	conn, err := dial(ctx)
	r.dial = time.Since(start)
	if err != nil {
		r.err = fmt.Errorf("dial: %w", err)
		return r
	}
	defer conn.Close()

	// The TLS handshake is the real verdict on the transport: completing one
	// means the peer accepted our stream and DPI let the real SNI through.
	start = time.Now()
	c, err := handshake(conn, domain)
	r.tlsTime = time.Since(start)
	if err != nil {
		r.err = err
		return r
	}
	r.handshook = true

	state := c.ConnectionState()
	r.proto = fmt.Sprintf("%s/%s", tlsVersion(state.Version), alpn(state.NegotiatedProtocol))

	// An HTTP exchange on top is a bonus check that the connection stays up
	// once it carries a request, not just a handshake.
	r.status, r.err = request(c, domain, state.NegotiatedProtocol)
	return r
}

// handshake completes a real TLS handshake presenting domain as the SNI.
//
// uTLS with a Chrome fingerprint keeps JA3-based filtering out of the picture,
// so a failure points at the transport rather than at the handshake looking
// like a Go program. ALPN is pinned to HTTP/1.1 because this tool speaks it
// directly; left to the Chrome preset it also offers h2, and a Cloudflare edge
// will happily pick that and answer in binary frames.
func handshake(conn net.Conn, domain string) (*utls.UConn, error) {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	c := utls.UClient(conn, &utls.Config{
		ServerName: domain,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}, utls.HelloChrome_Auto)
	if err := c.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return c, nil
}

func request(c *utls.UConn, domain, negotiated string) (string, error) {
	if negotiated == "h2" {
		// The peer insisted on HTTP/2 despite our ALPN. The handshake already
		// told us what we needed, so do not pretend to parse HTTP/1 frames.
		return "(h2, request skipped)", nil
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))

	req := "HEAD / HTTP/1.1\r\n" +
		"Host: " + domain + "\r\n" +
		"User-Agent: spooftest\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := c.Write([]byte(req)); err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	resp.Body.Close()
	return resp.Status, nil
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func alpn(p string) string {
	if p == "" {
		return "no-alpn"
	}
	return p
}

func report(i int, r result) {
	switch {
	case !r.handshook:
		fmt.Printf("  #%d  dial %8s  FAIL %v\n",
			i+1, r.dial.Round(time.Millisecond), r.err)
	case r.err != nil:
		// The transport did its job; only the HTTP exchange on top failed.
		fmt.Printf("  #%d  dial %8s  tls %8s  [%s]  handshake OK, http failed: %v\n",
			i+1, r.dial.Round(time.Millisecond), r.tlsTime.Round(time.Millisecond), r.proto, r.err)
	default:
		fmt.Printf("  #%d  dial %8s  tls %8s  [%s]  %s\n",
			i+1, r.dial.Round(time.Millisecond), r.tlsTime.Round(time.Millisecond), r.proto, r.status)
	}
}

func summarise(results []result) {
	var handshook, full int
	var totalDial, totalTLS time.Duration
	for _, r := range results {
		if r.handshook {
			handshook++
			totalDial += r.dial
			totalTLS += r.tlsTime
			if r.err == nil {
				full++
			}
		}
	}
	if handshook == 0 {
		fmt.Printf("  -> 0/%d completed a TLS handshake\n", len(results))
		return
	}
	fmt.Printf("  -> %d/%d completed a TLS handshake (%d also completed HTTP), mean dial %s, mean tls %s\n",
		handshook, len(results), full,
		(totalDial / time.Duration(handshook)).Round(time.Millisecond),
		(totalTLS / time.Duration(handshook)).Round(time.Millisecond))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
