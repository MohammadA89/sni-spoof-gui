package share

import (
	"encoding/json"
	"fmt"
)

// The JSON below is shaped against xray-core's infra/conf structs, and the
// field names were taken from that package rather than from documentation:
//
//   - REALITY takes a singular "shortId"; the plural "shortIds" is rejected
//     outright on the client side.
//   - "publicKey" is still read, with the newer "password" simply overwriting
//     it when both are present, so the name every share link already uses is
//     the one emitted here.
//   - "rawSettings" and "xhttpSettings" are aliases that overwrite the older
//     "tcpSettings" and "splithttpSettings" during Build.
//   - "allowInsecure" is a removed feature and now fails at startup, so it is
//     never emitted. The parser warns instead.

// Outbound is one xray outbound entry.
type Outbound struct {
	Tag            string          `json:"tag,omitempty"`
	Protocol       string          `json:"protocol"`
	Settings       any             `json:"settings"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
}

// StreamSettings is the transport half of an outbound.
type StreamSettings struct {
	Network  string `json:"network"`
	Security string `json:"security,omitempty"`

	TLSSettings     *tlsSettings     `json:"tlsSettings,omitempty"`
	RealitySettings *realitySettings `json:"realitySettings,omitempty"`

	RawSettings         *rawSettings         `json:"rawSettings,omitempty"`
	WSSettings          *wsSettings          `json:"wsSettings,omitempty"`
	GRPCSettings        *grpcSettings        `json:"grpcSettings,omitempty"`
	HTTPUpgradeSettings *httpUpgradeSettings `json:"httpupgradeSettings,omitempty"`
	XHTTPSettings       *xhttpSettings       `json:"xhttpSettings,omitempty"`
	KCPSettings         *kcpSettings         `json:"kcpSettings,omitempty"`
}

type tlsSettings struct {
	ServerName  string   `json:"serverName,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

type realitySettings struct {
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint,omitempty"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId,omitempty"`
	SpiderX     string `json:"spiderX,omitempty"`
}

type rawSettings struct {
	Header *rawHeader `json:"header,omitempty"`
}

type rawHeader struct {
	Type    string         `json:"type"`
	Request *rawHTTPHeader `json:"request,omitempty"`
}

type rawHTTPHeader struct {
	Path    []string            `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
}

type wsSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type grpcSettings struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
	Authority   string `json:"authority,omitempty"`
}

type httpUpgradeSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type xhttpSettings struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type kcpSettings struct {
	Seed   string     `json:"seed,omitempty"`
	Header *rawHeader `json:"header,omitempty"`
}

type vlessSettings struct {
	Vnext []vlessVnext `json:"vnext"`
}

type vlessVnext struct {
	Address string      `json:"address"`
	Port    uint16      `json:"port"`
	Users   []vlessUser `json:"users"`
}

type vlessUser struct {
	ID         string `json:"id"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow,omitempty"`
}

type trojanSettings struct {
	Servers []trojanServer `json:"servers"`
}

type trojanServer struct {
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
	Password string `json:"password"`
	Flow     string `json:"flow,omitempty"`
}

// Outbound builds the xray outbound for this profile. tag names it, so routing
// rules and the API can refer to it.
func (p *Profile) Outbound(tag string) (*Outbound, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	ob := &Outbound{Tag: tag, Protocol: p.Protocol}

	switch p.Protocol {
	case ProtoVLESS:
		enc := p.Encryption
		if enc == "" {
			enc = "none"
		}
		ob.Settings = vlessSettings{Vnext: []vlessVnext{{
			Address: p.Address,
			Port:    p.Port,
			Users:   []vlessUser{{ID: p.ID, Encryption: enc, Flow: p.Flow}},
		}}}
	case ProtoTrojan:
		ob.Settings = trojanSettings{Servers: []trojanServer{{
			Address:  p.Address,
			Port:     p.Port,
			Password: p.ID,
			Flow:     p.Flow,
		}}}
	default:
		return nil, fmt.Errorf("share: cannot build an outbound for %q", p.Protocol)
	}

	ob.StreamSettings = p.stream()
	return ob, nil
}

// JSON renders the outbound the way xray's config loader expects it.
func (p *Profile) JSON(tag string) ([]byte, error) {
	ob, err := p.Outbound(tag)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(ob, "", "  ")
}

// Validate reports the problems that would stop xray from starting, so an
// import can be rejected while the user is still looking at the paste box
// rather than three screens later.
func (p *Profile) Validate() error {
	if p.Address == "" {
		return fmt.Errorf("share: profile has no server address")
	}
	if p.Port == 0 {
		return fmt.Errorf("share: profile has no port")
	}
	if p.ID == "" {
		return fmt.Errorf("share: profile has no credential")
	}
	if p.Security == SecurityReality {
		if p.PublicKey == "" {
			return fmt.Errorf("share: reality needs a public key (pbk)")
		}
		if p.SNI == "" {
			return fmt.Errorf("share: reality needs an SNI")
		}
		// xray's stream builder refuses REALITY over anything else, and the
		// message it produces names transports by their display names rather
		// than the ones the link used.
		switch p.Network {
		case NetworkRAW, NetworkXHTTP, NetworkGRPC:
		default:
			return fmt.Errorf("share: xray supports REALITY only over raw, xhttp and grpc, not %s", p.Network)
		}
	}
	// mKCP's seed and header disguise were removed outright. A link carrying
	// either cannot be run at all: the server is expecting an obfuscation this
	// build can no longer produce, so importing it would only fail later.
	if p.Network == NetworkKCP && (p.Seed != "" || p.HeaderType != "") {
		return fmt.Errorf("share: mKCP seed and header were removed from xray, so this link cannot be used")
	}
	return nil
}

func (p *Profile) stream() *StreamSettings {
	network := p.Network
	if network == "" {
		network = NetworkRAW
	}
	s := &StreamSettings{Network: network}

	switch p.Security {
	case SecurityTLS:
		s.Security = SecurityTLS
		s.TLSSettings = &tlsSettings{
			ServerName:  p.SNI,
			ALPN:        p.ALPN,
			Fingerprint: p.Fingerprint,
		}
	case SecurityReality:
		s.Security = SecurityReality
		s.RealitySettings = &realitySettings{
			ServerName:  p.SNI,
			Fingerprint: p.Fingerprint,
			PublicKey:   p.PublicKey,
			ShortID:     p.ShortID,
			SpiderX:     p.SpiderX,
		}
	}

	switch network {
	case NetworkRAW:
		// Only the HTTP disguise needs settings; a bare raw stream is the
		// default and an empty rawSettings object would just be noise.
		if h := p.httpHeader(); h != nil {
			s.RawSettings = &rawSettings{Header: h}
		}
	case NetworkWS:
		s.WSSettings = &wsSettings{Path: p.Path, Host: p.Host}
	case NetworkGRPC:
		s.GRPCSettings = &grpcSettings{
			ServiceName: p.ServiceName,
			MultiMode:   p.MultiMode,
			Authority:   p.Host,
		}
	case NetworkHTTPUpgrade:
		s.HTTPUpgradeSettings = &httpUpgradeSettings{Path: p.Path, Host: p.Host}
	case NetworkXHTTP:
		s.XHTTPSettings = &xhttpSettings{Path: p.Path, Host: p.Host}
	case NetworkKCP:
		// Seed and header are deliberately not carried over; Validate has
		// already rejected any profile that has them.
		s.KCPSettings = &kcpSettings{}
	}
	return s
}

// httpHeader builds the raw/mKCP header disguise, or nil when there is none.
func (p *Profile) httpHeader() *rawHeader {
	if p.HeaderType == "" || p.HeaderType == "none" {
		return nil
	}
	h := &rawHeader{Type: p.HeaderType}
	if p.HeaderType != "http" {
		// mKCP's other disguises (srtp, utp, wechat-video, dtls, wireguard)
		// are a type name and nothing else.
		return h
	}
	req := &rawHTTPHeader{}
	if p.Path != "" {
		req.Path = []string{p.Path}
	}
	if p.Host != "" {
		req.Headers = map[string][]string{"Host": {p.Host}}
	}
	if req.Path != nil || req.Headers != nil {
		h.Request = req
	}
	return h
}
