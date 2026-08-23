//go:build windows

package xray

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/share"
)

const testLink = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@edge.example.com:8443" +
	"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome" +
	"&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179e30d4fc2" +
	"&flow=xtls-rprx-vision&encryption=none#Test"

func testProfile(t *testing.T) *share.Profile {
	t.Helper()
	p, err := share.ParseLink(testLink)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func buildConfig(t *testing.T, opt InstanceOptions) map[string]any {
	t.Helper()
	if opt.Profile == nil {
		opt.Profile = testProfile(t)
	}
	blob, err := BuildConfig(opt)
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, blob)
	}
	return out
}

// The configuration has to survive xray's own loader and builder. Everything
// else in this file checks intent; this checks that the core accepts it.
func TestBuiltConfigIsAcceptedByXray(t *testing.T) {
	blob, err := BuildConfig(InstanceOptions{Profile: testProfile(t)})
	if err != nil {
		t.Fatalf("BuildConfig: %v", err)
	}

	cfg, err := serial.LoadJSONConfig(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("xray could not load the config: %v\n%s", err, blob)
	}
	// New builds every inbound, outbound and routing rule without opening a
	// socket; Start is what would bind ports, and this test does not.
	inst, err := xcore.New(cfg)
	if err != nil {
		t.Fatalf("xray could not build the instance: %v\n%s", err, blob)
	}
	if err := inst.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestInboundsUseTheRequestedPorts(t *testing.T) {
	m := buildConfig(t, InstanceOptions{SocksPort: 1080, HTTPPort: 1081})

	inbounds, ok := m["inbounds"].([]any)
	if !ok || len(inbounds) != 2 {
		t.Fatalf("expected two inbounds, got %v", m["inbounds"])
	}
	for i, want := range []float64{1080, 1081} {
		in := inbounds[i].(map[string]any)
		if in["port"] != want {
			t.Errorf("inbound %d port = %v, want %v", i, in["port"], want)
		}
		// Binding anywhere but loopback would turn the machine into an open
		// proxy for anything that can reach it.
		if in["listen"] != "127.0.0.1" {
			t.Errorf("inbound %d listens on %v, want 127.0.0.1", i, in["listen"])
		}
	}
}

// Unmatched traffic goes to the first outbound, so the proxy has to be first.
// Putting direct first would send everything straight out unproxied while
// still looking like a working config.
func TestProxyIsTheDefaultOutbound(t *testing.T) {
	m := buildConfig(t, InstanceOptions{})

	outbounds, ok := m["outbounds"].([]any)
	if !ok || len(outbounds) == 0 {
		t.Fatal("no outbounds")
	}
	first := outbounds[0].(map[string]any)
	if first["tag"] != TagProxy {
		t.Errorf("first outbound is %v, want %q", first["tag"], TagProxy)
	}
	if first["protocol"] != "vless" {
		t.Errorf("first outbound protocol = %v", first["protocol"])
	}
}

func TestPrivateRangesGoDirect(t *testing.T) {
	m := buildConfig(t, InstanceOptions{})

	rules := m["routing"].(map[string]any)["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("no routing rules")
	}
	first := rules[0].(map[string]any)
	if first["outboundTag"] != TagDirect {
		t.Errorf("private ranges route to %v, want %q", first["outboundTag"], TagDirect)
	}

	ips := first["ip"].([]any)
	var found bool
	for _, ip := range ips {
		if ip == "192.168.0.0/16" {
			found = true
		}
		// geoip: prefixes would make xray load geoip.dat from its asset path,
		// which this package deliberately does not depend on.
		if s, _ := ip.(string); strings.HasPrefix(s, "geoip:") {
			t.Errorf("rule uses %q, which needs geoip.dat", s)
		}
	}
	if !found {
		t.Errorf("private ranges do not include the LAN: %v", ips)
	}
}

func TestDirectDomainsAndIPsBecomeRules(t *testing.T) {
	m := buildConfig(t, InstanceOptions{
		DirectDomains: []string{"example.ir"},
		DirectIPs:     []string{"5.5.5.0/24"},
	})

	rules := m["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("expected three rules, got %d", len(rules))
	}
	if got := rules[1].(map[string]any)["domain"].([]any)[0]; got != "example.ir" {
		t.Errorf("domain rule = %v", got)
	}
	if got := rules[2].(map[string]any)["ip"].([]any)[0]; got != "5.5.5.0/24" {
		t.Errorf("ip rule = %v", got)
	}
}

// The engine builds IPv4 packets only, so an AAAA answer produces a
// destination the dialer has to hand straight back unspoofed.
func TestDNSAsksForIPv4Only(t *testing.T) {
	m := buildConfig(t, InstanceOptions{})

	dns, ok := m["dns"].(map[string]any)
	if !ok {
		t.Fatal("no dns section")
	}
	if dns["queryStrategy"] != "UseIPv4" {
		t.Errorf("queryStrategy = %v, want UseIPv4", dns["queryStrategy"])
	}
	if servers := dns["servers"].([]any); servers[0] != DefaultDoH {
		t.Errorf("first resolver = %v, want %q", servers[0], DefaultDoH)
	}
}

func TestDoHCanBeTurnedOff(t *testing.T) {
	m := buildConfig(t, InstanceOptions{DoH: "off"})
	if _, present := m["dns"]; present {
		t.Error(`DoH "off" should leave the dns section out entirely`)
	}
}

// Sniffing is what lets the direct rules match on domains: a SOCKS client that
// resolves names itself hands over a bare IP, and nothing would match.
func TestSniffingIsEnabledForRoutingOnly(t *testing.T) {
	m := buildConfig(t, InstanceOptions{})

	for _, in := range m["inbounds"].([]any) {
		s, ok := in.(map[string]any)["sniffing"].(map[string]any)
		if !ok {
			t.Fatalf("inbound %v has no sniffing block", in.(map[string]any)["tag"])
		}
		if s["enabled"] != true {
			t.Error("sniffing should be enabled")
		}
		// routeOnly keeps the sniffed name out of the destination itself, so
		// the proxy still receives what the client actually asked for.
		if s["routeOnly"] != true {
			t.Error("sniffing should be routeOnly")
		}
	}
}

func TestBuildConfigRejectsBadOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  InstanceOptions
		want string
	}{
		{"no profile", InstanceOptions{}, "no profile"},
		{"clashing ports", InstanceOptions{Profile: testProfile(t), SocksPort: 1080, HTTPPort: 1080}, "cannot share port"},
		{"port out of range", InstanceOptions{Profile: testProfile(t), SocksPort: 70000}, "out of range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildConfig(tc.opt)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A profile xray would reject has to be caught here rather than at start.
func TestBuildConfigRejectsAnUnbuildableProfile(t *testing.T) {
	p, err := share.ParseLink("vless://id@h:443?type=ws&security=reality&sni=a.com&pbk=k")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := BuildConfig(InstanceOptions{Profile: p}); err == nil {
		t.Error("REALITY over websocket should not build a config")
	}
}

func TestStartRequiresADialer(t *testing.T) {
	if _, err := Start(InstanceOptions{Profile: testProfile(t)}, nil); err == nil {
		t.Error("Start without a dialer should fail")
	}
}
