package share

import (
	"encoding/json"
	"testing"
)

// decode renders a profile and reads it back as a generic map, so the
// assertions below are about the JSON xray will actually see rather than about
// our own struct fields.
func decode(t *testing.T, link string) map[string]any {
	t.Helper()
	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	blob, err := p.JSON("proxy")
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, blob)
	}
	return out
}

func dig(t *testing.T, m map[string]any, path ...string) any {
	t.Helper()
	var cur any = m
	for i, key := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%v: %q is not an object", path[:i], path[i-1])
		}
		cur, ok = obj[key]
		if !ok {
			t.Fatalf("missing key %q at %v", key, path[:i+1])
		}
	}
	return cur
}

// REALITY's field names are the ones most easily got wrong, and every one of
// these is load-bearing: xray rejects the plural "shortIds" on a client, and a
// misspelled key is silently ignored rather than reported.
func TestRealityOutboundFieldNames(t *testing.T) {
	m := decode(t, "vless://uuid@example.com:8443?type=tcp&security=reality"+
		"&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=SHORT&spx=%2F&flow=xtls-rprx-vision")

	if got := dig(t, m, "protocol"); got != "vless" {
		t.Errorf("protocol = %v", got)
	}
	if got := dig(t, m, "streamSettings", "security"); got != "reality" {
		t.Errorf("security = %v", got)
	}

	r, ok := dig(t, m, "streamSettings", "realitySettings").(map[string]any)
	if !ok {
		t.Fatal("realitySettings is not an object")
	}
	for key, want := range map[string]string{
		"serverName":  "www.microsoft.com",
		"fingerprint": "chrome",
		"publicKey":   "PUBKEY",
		"shortId":     "SHORT",
		"spiderX":     "/",
	} {
		if r[key] != want {
			t.Errorf("realitySettings.%s = %v, want %q", key, r[key], want)
		}
	}
	if _, bad := r["shortIds"]; bad {
		t.Error(`"shortIds" is rejected by xray on the client side; only "shortId" may be emitted`)
	}

	user, ok := dig(t, m, "settings", "vnext").([]any)
	if !ok || len(user) != 1 {
		t.Fatal("vnext should hold exactly one server")
	}
	u := user[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if u["id"] != "uuid" {
		t.Errorf("id = %v", u["id"])
	}
	if u["flow"] != "xtls-rprx-vision" {
		t.Errorf("flow = %v", u["flow"])
	}
	if u["encryption"] != "none" {
		t.Errorf("encryption = %v, want none", u["encryption"])
	}
}

// The transport key has to match the network name, and "raw"/"xhttp" are the
// spellings this xray version aliases the older ones onto.
func TestTransportSettingsKeyMatchesNetwork(t *testing.T) {
	for _, tc := range []struct {
		name    string
		link    string
		network string
		key     string
	}{
		{"websocket", "vless://id@h:443?type=ws&path=%2Fa&host=b.com", NetworkWS, "wsSettings"},
		{"grpc", "vless://id@h:443?type=grpc&serviceName=svc&mode=multi", NetworkGRPC, "grpcSettings"},
		{"httpupgrade", "vless://id@h:443?type=httpupgrade&path=%2Fa", NetworkHTTPUpgrade, "httpupgradeSettings"},
		{"xhttp", "vless://id@h:443?type=xhttp&path=%2Fa", NetworkXHTTP, "xhttpSettings"},
		// Bare mKCP only: a seed or header makes the profile unbuildable, which
		// TestRejectedBeforeXraySeesThem covers.
		{"kcp", "vless://id@h:443?type=kcp", NetworkKCP, "kcpSettings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := decode(t, tc.link)
			if got := dig(t, m, "streamSettings", "network"); got != tc.network {
				t.Errorf("network = %v, want %q", got, tc.network)
			}
			if _, ok := dig(t, m, "streamSettings").(map[string]any)[tc.key]; !ok {
				t.Errorf("missing %s for network %q", tc.key, tc.network)
			}
		})
	}
}

// The older aliases must normalise, so two links that mean the same thing do
// not produce two different-looking configs.
func TestLegacyTransportNamesNormalise(t *testing.T) {
	for _, tc := range []struct{ link, want string }{
		{"vless://id@h:443?type=tcp", NetworkRAW},
		{"vless://id@h:443?type=raw", NetworkRAW},
		{"vless://id@h:443", NetworkRAW},
		{"vless://id@h:443?type=websocket", NetworkWS},
		{"vless://id@h:443?type=splithttp", NetworkXHTTP},
		{"vless://id@h:443?type=mkcp", NetworkKCP},
	} {
		m := decode(t, tc.link)
		if got := dig(t, m, "streamSettings", "network"); got != tc.want {
			t.Errorf("%s: network = %v, want %q", tc.link, got, tc.want)
		}
	}
}

// A bare raw stream needs no settings object at all; emitting an empty one is
// noise in a config the user may well read.
func TestBareRawStreamHasNoSettingsObject(t *testing.T) {
	m := decode(t, "vless://id@h:443?type=tcp&security=none")
	if _, present := dig(t, m, "streamSettings").(map[string]any)["rawSettings"]; present {
		t.Error("a raw stream with no header disguise should not emit rawSettings")
	}
}

func TestRawHTTPHeaderDisguise(t *testing.T) {
	m := decode(t, "vless://id@h:443?type=tcp&headerType=http&host=a.com&path=%2Fx")

	hdr, ok := dig(t, m, "streamSettings", "rawSettings", "header").(map[string]any)
	if !ok {
		t.Fatal("header is not an object")
	}
	if hdr["type"] != "http" {
		t.Errorf("header type = %v", hdr["type"])
	}
	req, ok := hdr["request"].(map[string]any)
	if !ok {
		t.Fatal("request is not an object")
	}
	// Both are lists in xray's schema, not scalars.
	if p, ok := req["path"].([]any); !ok || len(p) != 1 || p[0] != "/x" {
		t.Errorf("path = %v, want [\"/x\"]", req["path"])
	}
	host, ok := req["headers"].(map[string]any)["Host"].([]any)
	if !ok || len(host) != 1 || host[0] != "a.com" {
		t.Errorf("Host header = %v, want [\"a.com\"]", req["headers"])
	}
}

func TestTrojanOutbound(t *testing.T) {
	m := decode(t, "trojan://secret@example.com:443?security=tls&sni=example.com")

	if got := dig(t, m, "protocol"); got != "trojan" {
		t.Errorf("protocol = %v", got)
	}
	servers, ok := dig(t, m, "settings", "servers").([]any)
	if !ok || len(servers) != 1 {
		t.Fatal("servers should hold exactly one entry")
	}
	s := servers[0].(map[string]any)
	if s["password"] != "secret" {
		t.Errorf("password = %v", s["password"])
	}
	if s["port"] != float64(443) {
		t.Errorf("port = %v", s["port"])
	}
	if got := dig(t, m, "streamSettings", "tlsSettings", "serverName"); got != "example.com" {
		t.Errorf("serverName = %v", got)
	}
}

// Plain TLS must not emit a realitySettings block and vice versa; xray reads
// whichever one is present regardless of the security value.
func TestSecurityBlocksAreExclusive(t *testing.T) {
	tls := dig(t, decode(t, "vless://id@h:443?security=tls&sni=a.com"), "streamSettings").(map[string]any)
	if _, bad := tls["realitySettings"]; bad {
		t.Error("a TLS profile emitted realitySettings")
	}
	reality := dig(t, decode(t, "vless://id@h:443?security=reality&sni=a.com&pbk=k"), "streamSettings").(map[string]any)
	if _, bad := reality["tlsSettings"]; bad {
		t.Error("a REALITY profile emitted tlsSettings")
	}
}

func TestNoSecurityEmitsNeitherBlock(t *testing.T) {
	s := dig(t, decode(t, "vless://id@h:443"), "streamSettings").(map[string]any)
	if _, bad := s["security"]; bad {
		t.Errorf("security should be omitted entirely when there is none: %v", s)
	}
	if _, bad := s["tlsSettings"]; bad {
		t.Error("emitted tlsSettings with no security")
	}
}
