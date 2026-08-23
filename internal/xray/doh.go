//go:build windows

package xray

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dohTimeout bounds one lookup. It is short because a dial is waiting on it and
// a slow resolver should fall back rather than stall the connection.
const dohTimeout = 6 * time.Second

// maxDoHResponse caps how much of a reply is read. A DNS answer is small, and
// without a cap a hostile or broken endpoint could stream indefinitely into
// memory.
const maxDoHResponse = 64 << 10

// DoHResolver resolves over HTTPS (RFC 8484).
//
// It exists because the address of the config's own server is the single name
// most worth lying about: a resolver that returns the wrong address for it
// sends the spoofed connection to a machine that is not there, and the failure
// looks like a dead config rather than like DNS.
//
// The endpoint should be an IP literal, such as https://1.1.1.1/dns-query. That
// is not only about trust - it is what keeps this from recursing. A hostname
// endpoint would itself need resolving, and the resolver doing that resolution
// is this one.
type DoHResolver struct {
	endpoint string
	client   *http.Client

	// bootstrap resolves the endpoint's own hostname when it is not an IP
	// literal. Nil when the endpoint is a literal, which is the intended case.
	bootstrap Resolver
}

// DoHOptions configure a DoHResolver.
type DoHOptions struct {
	// Endpoint is the DoH URL. Empty means DefaultDoH.
	Endpoint string

	// Dial, when set, is used for the resolver's own connections. Pointing it
	// at the spoofing engine is the point: the DoH request is as visible to DPI
	// as anything else, and there is no recursion risk as long as Endpoint is
	// an IP literal.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Bootstrap resolves a hostname endpoint. Defaults to the system resolver.
	Bootstrap Resolver
}

// NewDoHResolver builds a resolver for the given endpoint.
func NewDoHResolver(opt DoHOptions) (*DoHResolver, error) {
	if opt.Endpoint == "" {
		opt.Endpoint = DefaultDoH
	}
	u, err := url.Parse(opt.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("xray: DoH endpoint %q is not a URL: %w", opt.Endpoint, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("xray: DoH endpoint %q must be https", opt.Endpoint)
	}

	r := &DoHResolver{endpoint: opt.Endpoint}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		// A hostname endpoint needs something to resolve it with.
		r.bootstrap = opt.Bootstrap
		if r.bootstrap == nil {
			r.bootstrap = SystemResolver{}
		}
	}

	transport := &http.Transport{
		// Reused connections matter here: without them every lookup pays a TLS
		// handshake, and in the spoofed case a fresh injection too.
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: dohTimeout,
	}
	if opt.Dial != nil {
		transport.DialContext = opt.Dial
	} else if r.bootstrap != nil {
		transport.DialContext = r.dialViaBootstrap
	}
	r.client = &http.Client{Transport: transport, Timeout: dohTimeout}
	return r, nil
}

// dialViaBootstrap resolves a hostname endpoint with the bootstrap resolver
// rather than letting the Go dialer use the system one.
func (r *DoHResolver) dialViaBootstrap(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip, err := r.bootstrap.LookupIPv4(ctx, host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// LookupIPv4 implements Resolver.
func (r *DoHResolver) LookupIPv4(ctx context.Context, host string) (netip.Addr, error) {
	// An address needs no lookup, and asking for one would be a round trip per
	// dial for nothing.
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr, nil
		}
		return netip.Addr{}, fmt.Errorf("xray: %s is IPv6, which cannot be spoofed", host)
	}

	query, err := buildQuery(host)
	if err != nil {
		return netip.Addr{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, dohTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(query))
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := r.client.Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("xray: DoH lookup for %s: %w", host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("xray: DoH lookup for %s returned %s", host, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("xray: DoH lookup for %s: %w", host, err)
	}
	return firstA(body, host)
}

// buildQuery encodes an A query for host.
func buildQuery(host string) ([]byte, error) {
	name, err := dnsmessage.NewName(dnsutilFQDN(host))
	if err != nil {
		return nil, fmt.Errorf("xray: %q is not a usable hostname: %w", host, err)
	}
	msg := dnsmessage.Message{
		// RFC 8484 asks for ID 0, so that identical queries cache identically
		// over HTTP.
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	return msg.Pack()
}

// dnsutilFQDN appends the root label, which dnsmessage requires.
func dnsutilFQDN(host string) string {
	if len(host) > 0 && host[len(host)-1] == '.' {
		return host
	}
	return host + "."
}

// rcodeText renders a DNS response code as something worth showing a user.
// The stringer on dnsmessage.RCode yields Go identifiers like
// "RCodeNameError", which say nothing to the person whose config will not
// connect.
func rcodeText(code dnsmessage.RCode) string {
	switch code {
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN (no such name)"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL (the resolver could not answer)"
	case dnsmessage.RCodeFormatError:
		return "FORMERR (the resolver rejected the query)"
	case dnsmessage.RCodeRefused:
		return "REFUSED (the resolver declined to answer)"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP (the resolver does not support this query)"
	default:
		return code.String()
	}
}

// firstA returns the first A record in a reply.
//
// CNAME chains are followed implicitly: resolvers return the whole chain plus
// the final A records in one answer section, so taking the first A is enough
// and there is no need to chase names ourselves.
func firstA(body []byte, host string) (netip.Addr, error) {
	var p dnsmessage.Parser
	header, err := p.Start(body)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("xray: DoH reply for %s is malformed: %w", host, err)
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return netip.Addr{}, fmt.Errorf("xray: DoH lookup for %s failed: %s", host, rcodeText(header.RCode))
	}
	if err := p.SkipAllQuestions(); err != nil {
		return netip.Addr{}, err
	}

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return netip.Addr{}, fmt.Errorf("xray: DoH reply for %s is malformed: %w", host, err)
		}
		if h.Type != dnsmessage.TypeA {
			if err := p.SkipAnswer(); err != nil {
				return netip.Addr{}, err
			}
			continue
		}
		res, err := p.AResource()
		if err != nil {
			return netip.Addr{}, err
		}
		return netip.AddrFrom4(res.A), nil
	}
	return netip.Addr{}, fmt.Errorf("xray: %s has no IPv4 address", host)
}
