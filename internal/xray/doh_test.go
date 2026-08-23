//go:build windows

package xray

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// dohServer answers RFC 8484 queries with the records it is given.
func dohServer(t *testing.T, answer func(q dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode)) *httptest.Server {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Content-Type"); got != "application/dns-message" {
			t.Errorf("Content-Type = %q, want application/dns-message", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}

		var p dnsmessage.Parser
		if _, err := p.Start(body); err != nil {
			t.Errorf("query is malformed: %v", err)
			return
		}
		q, err := p.Question()
		if err != nil {
			t.Errorf("no question: %v", err)
			return
		}

		answers, rcode := answer(q)
		reply := dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, RCode: rcode},
			Questions: []dnsmessage.Question{q},
			Answers:   answers,
		}
		packed, err := reply.Pack()
		if err != nil {
			t.Errorf("pack reply: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func aRecord(name string, ip [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   300,
		},
		Body: &dnsmessage.AResource{A: ip},
	}
}

// testResolver points a DoHResolver at a test server, trusting its certificate.
func testResolver(t *testing.T, srv *httptest.Server) *DoHResolver {
	t.Helper()
	r, err := NewDoHResolver(DoHOptions{Endpoint: srv.URL + "/dns-query"})
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	r.client = srv.Client()
	return r
}

func TestDoHResolvesAnA(t *testing.T) {
	srv := dohServer(t, func(q dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		if q.Type != dnsmessage.TypeA {
			t.Errorf("query type = %v, want A", q.Type)
		}
		if got := q.Name.String(); got != "example.com." {
			t.Errorf("query name = %q, want example.com.", got)
		}
		return []dnsmessage.Resource{aRecord("example.com.", [4]byte{93, 184, 216, 34})}, dnsmessage.RCodeSuccess
	})

	addr, err := testResolver(t, srv).LookupIPv4(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "93.184.216.34" {
		t.Errorf("addr = %s, want 93.184.216.34", addr)
	}
}

// Resolvers return the whole CNAME chain plus the final A records in one
// answer section, so the first A is the answer and there is no chain to chase.
func TestDoHSkipsCNAMEsAndTakesTheFirstA(t *testing.T) {
	srv := dohServer(t, func(q dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		return []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("www.example.com."),
					Type:  dnsmessage.TypeCNAME,
					Class: dnsmessage.ClassINET,
					TTL:   300,
				},
				Body: &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
			},
			aRecord("cdn.example.net.", [4]byte{1, 2, 3, 4}),
			aRecord("cdn.example.net.", [4]byte{5, 6, 7, 8}),
		}, dnsmessage.RCodeSuccess
	})

	addr, err := testResolver(t, srv).LookupIPv4(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "1.2.3.4" {
		t.Errorf("addr = %s, want the first A record 1.2.3.4", addr)
	}
}

func TestDoHReportsNXDOMAIN(t *testing.T) {
	srv := dohServer(t, func(dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		return nil, dnsmessage.RCodeNameError
	})

	_, err := testResolver(t, srv).LookupIPv4(context.Background(), "nope.example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "NXDOMAIN") {
		t.Errorf("error should name the rcode, got %v", err)
	}
}

// An empty answer is not an error from the server's point of view, so it has to
// be turned into one here or the dialer would get a zero address.
func TestDoHReportsAnEmptyAnswer(t *testing.T) {
	srv := dohServer(t, func(dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		return nil, dnsmessage.RCodeSuccess
	})

	_, err := testResolver(t, srv).LookupIPv4(context.Background(), "empty.example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "no IPv4") {
		t.Errorf("error = %v", err)
	}
}

func TestDoHReportsAnHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	r := testResolver(t, srv)
	_, err := r.LookupIPv4(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should carry the status, got %v", err)
	}
}

// A literal must not produce a lookup at all: doing one would be a round trip
// per dial for an answer already in hand.
func TestDoHPassesLiteralsThroughWithoutQuerying(t *testing.T) {
	var queried bool
	srv := dohServer(t, func(dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		queried = true
		return nil, dnsmessage.RCodeSuccess
	})

	r := testResolver(t, srv)
	addr, err := r.LookupIPv4(context.Background(), "104.17.0.1")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "104.17.0.1" {
		t.Errorf("addr = %s", addr)
	}
	if queried {
		t.Error("a literal address should not reach the resolver")
	}

	if _, err := r.LookupIPv4(context.Background(), "2606:4700::1111"); err == nil {
		t.Error("an IPv6 literal should be rejected as unspoofable")
	}
}

// The Dial hook is what puts the resolver's own traffic on the spoofed path.
func TestDoHUsesTheSuppliedDialer(t *testing.T) {
	srv := dohServer(t, func(dnsmessage.Question) ([]dnsmessage.Resource, dnsmessage.RCode) {
		return []dnsmessage.Resource{aRecord("example.com.", [4]byte{9, 9, 9, 9})}, dnsmessage.RCodeSuccess
	})

	var dialed int
	r, err := NewDoHResolver(DoHOptions{
		Endpoint: srv.URL + "/dns-query",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed++
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	// Keep the custom dialer, but trust the test server's certificate.
	r.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if _, err := r.LookupIPv4(context.Background(), "example.com"); err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if dialed == 0 {
		t.Error("the supplied dialer was not used")
	}
}

func TestNewDoHResolverRejectsBadEndpoints(t *testing.T) {
	for _, tc := range []struct{ name, endpoint string }{
		// Plain HTTP would defeat the entire point: the query and its answer
		// would be as readable as the DNS it replaces.
		{"http", "http://1.1.1.1/dns-query"},
		{"not a url", "://nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDoHResolver(DoHOptions{Endpoint: tc.endpoint}); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

// An IP-literal endpoint needs no bootstrap, and that is what keeps the
// resolver from recursing into itself.
func TestLiteralEndpointNeedsNoBootstrap(t *testing.T) {
	r, err := NewDoHResolver(DoHOptions{Endpoint: "https://1.1.1.1/dns-query"})
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	if r.bootstrap != nil {
		t.Error("an IP-literal endpoint should not carry a bootstrap resolver")
	}

	named, err := NewDoHResolver(DoHOptions{Endpoint: "https://dns.example.com/dns-query"})
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	if named.bootstrap == nil {
		t.Error("a hostname endpoint must have something to resolve it with")
	}
}

func TestDefaultEndpointIsUsedWhenEmpty(t *testing.T) {
	r, err := NewDoHResolver(DoHOptions{})
	if err != nil {
		t.Fatalf("NewDoHResolver: %v", err)
	}
	if r.endpoint != DefaultDoH {
		t.Errorf("endpoint = %q, want %q", r.endpoint, DefaultDoH)
	}
}

// A DoH endpoint that cannot be reached must not become the reason nothing
// connects, so the system resolver is tried next.
func TestFallbackResolverUsesTheSecondary(t *testing.T) {
	primary := &fakeResolver{err: errors.New("doh unreachable")}
	secondary := &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")}

	var logged int
	f := FallbackResolver{
		Primary:   primary,
		Secondary: secondary,
		Logf:      func(string, ...any) { logged++ },
	}

	addr, err := f.LookupIPv4(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "1.2.3.4" {
		t.Errorf("addr = %s", addr)
	}
	// Silently degrading to the resolver being worked around is exactly the
	// thing that must stay visible.
	if logged != 1 {
		t.Errorf("the fallback was not reported, logged = %d", logged)
	}
}

func TestFallbackResolverPrefersThePrimary(t *testing.T) {
	primary := &fakeResolver{addr: netip.MustParseAddr("9.9.9.9")}
	secondary := &fakeResolver{addr: netip.MustParseAddr("1.2.3.4")}

	addr, err := FallbackResolver{Primary: primary, Secondary: secondary}.
		LookupIPv4(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if addr.String() != "9.9.9.9" {
		t.Errorf("addr = %s, want the primary's answer", addr)
	}
	if secondary.hits != 0 {
		t.Error("the secondary should not have been consulted")
	}
}

func TestFallbackResolverWithNoSecondaryReportsTheError(t *testing.T) {
	f := FallbackResolver{Primary: &fakeResolver{err: errors.New("nope")}}
	if _, err := f.LookupIPv4(context.Background(), "example.com"); err == nil {
		t.Error("expected the primary's error")
	}
}
