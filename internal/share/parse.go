package share

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseLink turns one share link into a Profile.
//
// The grammar is the de-facto one every GUI client implements rather than
// anything standardised, so this is deliberately forgiving about case and
// about the older spellings of transport names, and strict only where being
// lenient would produce a profile that fails later for a reason the user
// cannot see.
func ParseLink(raw string) (*Profile, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("share: empty link")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("share: not a valid link: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case ProtoVLESS, ProtoTrojan:
	case "vmess", "ss", "ssr", "hysteria", "hysteria2", "hy2", "tuic":
		return nil, fmt.Errorf("share: %s:// links are not supported yet", scheme)
	default:
		return nil, fmt.Errorf("share: unknown link type %q", u.Scheme)
	}

	p := &Profile{
		Protocol: scheme,
		Name:     u.Fragment,
		Raw:      raw,
	}

	if u.User == nil || u.User.Username() == "" {
		if scheme == ProtoVLESS {
			return nil, fmt.Errorf("share: vless link has no UUID")
		}
		return nil, fmt.Errorf("share: trojan link has no password")
	}
	p.ID = u.User.Username()

	p.Address = u.Hostname()
	if p.Address == "" {
		return nil, fmt.Errorf("share: link has no server address")
	}
	port, err := parsePort(u.Port())
	if err != nil {
		return nil, err
	}
	p.Port = port

	q := u.Query()
	if err := applyStream(p, q); err != nil {
		return nil, err
	}
	applySecurity(p, q)

	if scheme == ProtoVLESS {
		p.Flow = q.Get("flow")
		p.Encryption = q.Get("encryption")
		if p.Encryption == "" {
			p.Encryption = "none"
		}
	} else if flow := q.Get("flow"); flow != "" {
		p.Flow = flow
	}

	return p, nil
}

func parsePort(s string) (uint16, error) {
	if s == "" {
		return 0, fmt.Errorf("share: link has no port")
	}
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("share: port %q is not a number between 1 and 65535", s)
	}
	if n == 0 {
		return 0, fmt.Errorf("share: port 0 is not dialable")
	}
	return uint16(n), nil
}

// applyStream reads the transport parameters. It rejects the transports this
// xray version has removed, because the alternative is an import that succeeds
// and a connection that fails much later with an error from deep inside the
// core.
func applyStream(p *Profile, q url.Values) error {
	switch strings.ToLower(q.Get("type")) {
	case "", "tcp", "raw":
		p.Network = NetworkRAW
	case "ws", "websocket":
		p.Network = NetworkWS
	case "grpc":
		p.Network = NetworkGRPC
	case "httpupgrade":
		p.Network = NetworkHTTPUpgrade
	case "xhttp", "splithttp":
		p.Network = NetworkXHTTP
	case "kcp", "mkcp":
		p.Network = NetworkKCP
	case "http", "h2", "h3":
		return fmt.Errorf("share: the HTTP/2 transport was removed from xray; this config needs an xhttp link instead")
	case "quic":
		return fmt.Errorf("share: the QUIC transport was removed from xray; this config needs an xhttp link instead")
	default:
		return fmt.Errorf("share: unknown transport type %q", q.Get("type"))
	}

	p.Path = q.Get("path")
	p.Host = q.Get("host")

	switch p.Network {
	case NetworkGRPC:
		p.ServiceName = q.Get("serviceName")
		p.MultiMode = strings.EqualFold(q.Get("mode"), "multi")
	case NetworkKCP:
		p.Seed = q.Get("seed")
		p.HeaderType = headerType(q)
		if p.Seed != "" || p.HeaderType != "" {
			p.warn("mKCP seed and header were removed from xray; this config cannot be used")
		}
	case NetworkRAW:
		p.HeaderType = headerType(q)
	case NetworkXHTTP:
		// xhttp carries its mode in the same parameter gRPC uses for a
		// different meaning, so it is read here rather than shared above.
		if mode := q.Get("mode"); mode != "" && !strings.EqualFold(mode, "auto") {
			p.warn("xhttp mode %q is not applied yet; the connection will use xray's default", mode)
		}
	}
	return nil
}

func headerType(q url.Values) string {
	h := strings.ToLower(q.Get("headerType"))
	if h == "none" {
		return ""
	}
	return h
}

// applySecurity reads the TLS/REALITY parameters.
func applySecurity(p *Profile, q url.Values) {
	switch strings.ToLower(q.Get("security")) {
	case "", "none":
		p.Security = SecurityNone
	case "tls":
		p.Security = SecurityTLS
	case "reality":
		p.Security = SecurityReality
	case "xtls":
		// XTLS as a *security* value predates REALITY and is long gone. The
		// flow parameter is where XTLS lives now.
		p.Security = SecurityTLS
		p.warn(`security=xtls is obsolete; importing it as plain TLS`)
	default:
		p.Security = SecurityNone
		p.warn("unknown security %q; importing it as no TLS", q.Get("security"))
	}

	p.SNI = q.Get("sni")
	if p.SNI == "" {
		// Falling back to the Host header matches what the GUI clients do, and
		// without it a ws+tls link with no sni verifies against the IP.
		p.SNI = q.Get("host")
	}
	p.Fingerprint = strings.ToLower(q.Get("fp"))

	if alpn := q.Get("alpn"); alpn != "" {
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				p.ALPN = append(p.ALPN, a)
			}
		}
	}

	switch q.Get("allowInsecure") {
	case "1", "true":
		p.AllowInsecure = true
		// xray removed allowInsecure outright: emitting it now is a hard
		// startup error, so the flag is recorded and dropped rather than
		// passed on. Say so, because a config that relied on it will fail the
		// certificate check and the reason has to be visible.
		p.warn("allowInsecure was removed from xray and is being ignored; a self-signed certificate will now fail")
	}

	if p.Security == SecurityReality {
		p.PublicKey = q.Get("pbk")
		p.ShortID = q.Get("sid")
		p.SpiderX = q.Get("spx")
		if p.PublicKey == "" {
			p.warn("reality link carries no public key (pbk); it will not start")
		}
		if p.SNI == "" {
			p.warn("reality link carries no SNI; it will not start")
		}
		switch p.Network {
		case NetworkRAW, NetworkXHTTP, NetworkGRPC:
		default:
			p.warn("xray supports REALITY only over raw, xhttp and grpc, not %s; this config cannot be used", p.Network)
		}
	}
}

// ParseError reports one link in a batch that could not be read, keeping the
// rest of the batch usable. A subscription with one bad entry should import
// the other forty, not fail wholesale.
type ParseError struct {
	Line int
	Text string
	Err  error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e ParseError) Unwrap() error { return e.Err }

// ParseMany reads a pasted block or a fetched subscription body: one link per
// line, optionally with the whole body base64-encoded, which is how nearly
// every subscription is served.
func ParseMany(text string) ([]*Profile, []ParseError) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}
	if !strings.Contains(text, "://") {
		if decoded, ok := decodeBase64(text); ok {
			text = decoded
		}
	}

	var profiles []*Profile
	var errs []ParseError

	for i, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		p, err := ParseLink(line)
		if err != nil {
			errs = append(errs, ParseError{Line: i + 1, Text: line, Err: err})
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, errs
}

// decodeBase64 tries the four encodings a subscription might arrive in. They
// differ only in alphabet and padding, and servers are not consistent about
// either, so all four are tried rather than guessed at.
func decodeBase64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil && strings.Contains(string(out), "://") {
			return string(out), true
		}
	}
	return "", false
}
