// Package share turns the links people paste around - vless://, trojan:// - into
// xray-core outbound configuration.
//
// xray-core does not parse share links. That has always been the GUI client's
// job, which is why every one of them ships its own parser, and it is why this
// package has to exist before a config can be pasted into this app instead of
// into v2rayN.
//
// Nothing here talks to the network or to xray. A Profile is a plain value: the
// parser produces one from a link, and Outbound turns one into the JSON xray
// loads. That split is what lets the whole path be tested without a running
// core.
package share

import (
	"fmt"
	"strings"
)

// Protocol names as they appear in both the link scheme and the xray outbound.
const (
	ProtoVLESS  = "vless"
	ProtoTrojan = "trojan"
)

// Security modes for the stream. These are the values xray expects verbatim.
const (
	SecurityNone    = "none"
	SecurityTLS     = "tls"
	SecurityReality = "reality"
)

// Transport names, normalised to the modern spellings xray prefers. The older
// aliases (tcp, websocket, splithttp, mkcp) are accepted by the parser and
// rewritten to these.
const (
	NetworkRAW         = "raw"
	NetworkWS          = "ws"
	NetworkGRPC        = "grpc"
	NetworkHTTPUpgrade = "httpupgrade"
	NetworkXHTTP       = "xhttp"
	NetworkKCP         = "kcp"
)

// Profile is one server, normalised away from the link syntax it arrived in.
//
// It deliberately holds only what a client needs to dial: the fields a link can
// carry that xray would reject or ignore are dropped at parse time, with a
// Warning recorded rather than a silent omission.
type Profile struct {
	// Name is the link's fragment - the label the user sees in the list.
	Name string

	Protocol string
	Address  string
	Port     uint16

	// ID is the VLESS UUID or the Trojan password. One field, because both
	// protocols carry exactly one credential and nothing downstream benefits
	// from keeping them apart.
	ID string

	// Encryption is VLESS's own field, almost always "none". It is carried
	// through rather than assumed, because xray has begun using it for real.
	Encryption string

	// Flow is the XTLS flow control, e.g. "xtls-rprx-vision", or empty.
	Flow string

	Security      string
	SNI           string
	ALPN          []string
	Fingerprint   string
	AllowInsecure bool

	// PublicKey, ShortID and SpiderX are REALITY's parameters, arriving in
	// links as pbk, sid and spx.
	PublicKey string
	ShortID   string
	SpiderX   string

	Network string

	// Path and Host serve ws, httpupgrade, xhttp and the raw HTTP header
	// disguise. Which of them is meaningful depends on Network.
	Path string
	Host string

	// ServiceName and MultiMode belong to gRPC.
	ServiceName string
	MultiMode   bool

	// HeaderType is the raw transport's disguise, "http" or empty.
	HeaderType string

	// Seed is mKCP's obfuscation seed.
	Seed string

	// Warnings records what was dropped or looks wrong. A link that parses is
	// not necessarily a link that will work, and the difference belongs in
	// front of the user rather than in a log nobody reads.
	Warnings []string

	// Raw is the original link, kept so the list can be re-exported and so a
	// parser bug can be reproduced from what the user actually pasted.
	Raw string
}

// Label returns the display name, falling back to the endpoint when the link
// carried no fragment. A list of entries all called "" is useless.
func (p *Profile) Label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.Endpoint()
}

// Endpoint returns "host:port".
func (p *Profile) Endpoint() string {
	return fmt.Sprintf("%s:%d", p.Address, p.Port)
}

// Redacted describes the profile without its credential, for logs and for
// anything the user might screenshot into a support thread. The UUID or
// password is the one field here that is worth stealing.
func (p *Profile) Redacted() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", p.Protocol, p.Endpoint())
	if p.Security != "" && p.Security != SecurityNone {
		fmt.Fprintf(&b, " %s", p.Security)
	}
	if p.Network != "" {
		fmt.Fprintf(&b, "/%s", p.Network)
	}
	if p.SNI != "" {
		fmt.Fprintf(&b, " sni=%s", p.SNI)
	}
	if p.Name != "" {
		fmt.Fprintf(&b, " (%s)", p.Name)
	}
	return b.String()
}

// warn appends a warning, skipping exact duplicates so a link with the same
// problem in two places does not say it twice.
func (p *Profile) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	for _, existing := range p.Warnings {
		if existing == msg {
			return
		}
	}
	p.Warnings = append(p.Warnings, msg)
}
