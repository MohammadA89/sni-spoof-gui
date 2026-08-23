//go:build windows

package xray

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	// xray registers its protocols, transports and apps in init functions, and
	// core.New fails with "not registered" for anything that was never linked
	// in. Importing the whole distro is what makes an embedded core behave like
	// the standalone binary.
	//
	// This is also where the binary size comes from. Trimming it to just the
	// handlers the share package can produce is possible, but a missing
	// registration surfaces as a runtime failure on a user's machine rather
	// than a build error here, so breadth wins until size actually hurts.
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/share"
)

// Outbound tags, referenced by the routing rules below.
const (
	TagProxy  = "proxy"
	TagDirect = "direct"
	TagBlock  = "block"
)

// Default local ports. These are v2rayN's, deliberately: someone moving to this
// app keeps whatever browser or system proxy setting they already have.
const (
	DefaultSocksPort = 10808
	DefaultHTTPPort  = 10809
)

// DefaultDoH resolves names that xray itself looks up. Note that this does not
// cover the config's own server address: that is resolved by the SpoofDialer's
// Resolver, before xray is involved at all. Point both at DoH to close the gap.
const DefaultDoH = "https://1.1.1.1/dns-query"

// privateRanges are routed direct rather than into the proxy.
//
// They are spelled out as CIDRs on purpose. The usual "geoip:private" would
// make xray load geoip.dat from its asset path, and shipping and locating that
// file is a problem this package does not need to have.
var privateRanges = []string{
	"127.0.0.0/8",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// InstanceOptions describe the instance to build. Only Profile is required.
type InstanceOptions struct {
	Profile *share.Profile

	// Listen, SocksPort and HTTPPort define the local inbounds. Binding
	// anywhere but a loopback address turns the machine into an open proxy,
	// so the default stays 127.0.0.1.
	Listen    string
	SocksPort int
	HTTPPort  int

	// DoH is the resolver xray uses. Empty means DefaultDoH; "off" leaves xray
	// with the local resolver only.
	DoH string

	// LogLevel is xray's own, one of debug/info/warning/error/none.
	LogLevel string

	// DirectDomains and DirectIPs bypass the proxy. Plain domains and CIDRs
	// only - "geosite:" and "geoip:" prefixes need the .dat files.
	DirectDomains []string
	DirectIPs     []string
}

func (o *InstanceOptions) applyDefaults() {
	if o.Listen == "" {
		o.Listen = "127.0.0.1"
	}
	if o.SocksPort == 0 {
		o.SocksPort = DefaultSocksPort
	}
	if o.HTTPPort == 0 {
		o.HTTPPort = DefaultHTTPPort
	}
	if o.DoH == "" {
		o.DoH = DefaultDoH
	}
	if o.LogLevel == "" {
		o.LogLevel = "warning"
	}
}

func (o *InstanceOptions) validate() error {
	if o.Profile == nil {
		return fmt.Errorf("xray: no profile selected")
	}
	if err := o.Profile.Validate(); err != nil {
		return err
	}
	if o.SocksPort == o.HTTPPort {
		return fmt.Errorf("xray: the socks and http inbounds cannot share port %d", o.SocksPort)
	}
	for _, p := range []int{o.SocksPort, o.HTTPPort} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("xray: local port %d is out of range", p)
		}
	}
	return nil
}

// BuildConfig renders the xray configuration for opt. It is separate from Start
// so the result can be inspected, shown to the user, and tested without
// starting anything.
func BuildConfig(opt InstanceOptions) ([]byte, error) {
	opt.applyDefaults()
	if err := opt.validate(); err != nil {
		return nil, err
	}

	proxy, err := opt.Profile.Outbound(TagProxy)
	if err != nil {
		return nil, err
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": opt.LogLevel},
		"inbounds": []any{
			map[string]any{
				"tag":      "socks-in",
				"listen":   opt.Listen,
				"port":     opt.SocksPort,
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": true},
				// Sniffing recovers the hostname from the traffic itself, which
				// is what lets the direct rules below match on domains at all -
				// a SOCKS client that resolves names itself hands over a bare
				// IP and nothing would match.
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    true,
				},
			},
			map[string]any{
				"tag":      "http-in",
				"listen":   opt.Listen,
				"port":     opt.HTTPPort,
				"protocol": "http",
				"settings": map[string]any{},
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    true,
				},
			},
		},
		"outbounds": []any{
			proxy,
			map[string]any{"tag": TagDirect, "protocol": "freedom", "settings": map[string]any{}},
			map[string]any{"tag": TagBlock, "protocol": "blackhole", "settings": map[string]any{}},
		},
		"routing": map[string]any{
			// AsIs, because resolving before routing would need the geo files
			// to be worth anything, and it doubles every lookup.
			"domainStrategy": "AsIs",
			"rules":          routingRules(opt),
		},
	}

	if opt.DoH != "off" {
		cfg["dns"] = map[string]any{
			"servers": []any{opt.DoH, "localhost"},
			// The spoofing engine is IPv4-only, so an AAAA answer would produce
			// a destination it has to hand straight back to the ordinary
			// dialer. Asking for A records keeps traffic on the spoofed path.
			"queryStrategy": "UseIPv4",
		}
	}

	return json.MarshalIndent(cfg, "", "  ")
}

// routingRules returns the rules, most specific first. Anything unmatched falls
// to the first outbound, which is the proxy.
func routingRules(opt InstanceOptions) []any {
	rules := []any{
		map[string]any{
			"type":        "field",
			"ip":          privateRanges,
			"outboundTag": TagDirect,
		},
	}
	if len(opt.DirectDomains) > 0 {
		rules = append(rules, map[string]any{
			"type":        "field",
			"domain":      opt.DirectDomains,
			"outboundTag": TagDirect,
		})
	}
	if len(opt.DirectIPs) > 0 {
		rules = append(rules, map[string]any{
			"type":        "field",
			"ip":          opt.DirectIPs,
			"outboundTag": TagDirect,
		})
	}
	return rules
}

// Instance is a running xray core with the spoofing dialer installed.
type Instance struct {
	mu      sync.Mutex
	inst    *xcore.Instance
	restore func()
	config  []byte
}

// Start builds the configuration, installs the dialer and starts the core.
//
// The dialer is installed before the core starts, not after. xray dials during
// start-up - the DNS client is the obvious one - and a dial that happens in the
// gap would go out unspoofed, which is precisely the thing the app exists to
// prevent.
func Start(opt InstanceOptions, d *SpoofDialer) (*Instance, error) {
	if d == nil {
		return nil, fmt.Errorf("xray: a spoofing dialer is required")
	}

	blob, err := BuildConfig(opt)
	if err != nil {
		return nil, err
	}
	cfg, err := serial.LoadJSONConfig(bytes.NewReader(blob))
	if err != nil {
		return nil, fmt.Errorf("xray: load config: %w", err)
	}
	inst, err := xcore.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("xray: build instance: %w", err)
	}

	restore := Install(d)
	if err := inst.Start(); err != nil {
		restore()
		_ = inst.Close()
		return nil, fmt.Errorf("xray: start: %w", err)
	}

	return &Instance{inst: inst, restore: restore, config: blob}, nil
}

// Config returns the configuration this instance was started from.
func (i *Instance) Config() []byte {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]byte, len(i.config))
	copy(out, i.config)
	return out
}

// Close stops the core and puts xray's default dialer back. It is safe to call
// more than once.
func (i *Instance) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.inst == nil {
		return nil
	}
	err := i.inst.Close()
	i.inst = nil
	// Restoring after the core has stopped, so nothing can dial into a
	// dialer whose engine is about to be torn down.
	if i.restore != nil {
		i.restore()
		i.restore = nil
	}
	return err
}
