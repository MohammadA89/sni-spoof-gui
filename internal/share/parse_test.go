package share

import (
	"encoding/base64"
	"strings"
	"testing"
)

// The case the whole feature exists for: a VLESS + REALITY link as v2rayN
// hands it out.
func TestParseVLESSReality(t *testing.T) {
	link := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:8443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=6ba85179e30d4fc2&spx=%2F" +
		"&flow=xtls-rprx-vision&encryption=none#My%20Server"

	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, c := range []struct{ name, got, want string }{
		{"protocol", p.Protocol, ProtoVLESS},
		{"address", p.Address, "example.com"},
		{"id", p.ID, "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{"security", p.Security, SecurityReality},
		{"sni", p.SNI, "www.microsoft.com"},
		{"fingerprint", p.Fingerprint, "chrome"},
		{"publicKey", p.PublicKey, "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"},
		{"shortID", p.ShortID, "6ba85179e30d4fc2"},
		{"spiderX", p.SpiderX, "/"},
		{"flow", p.Flow, "xtls-rprx-vision"},
		{"network", p.Network, NetworkRAW},
		{"name", p.Name, "My Server"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if p.Port != 8443 {
		t.Errorf("port = %d, want 8443", p.Port)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("a well-formed link should warn about nothing, got %v", p.Warnings)
	}
}

func TestParseVLESSWebSocketTLS(t *testing.T) {
	link := "vless://uuid-here@1.2.3.4:443?type=ws&security=tls&path=%2Fchat&host=cdn.example.com&alpn=h2%2Chttp%2F1.1#ws"

	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Network != NetworkWS {
		t.Errorf("network = %q, want %q", p.Network, NetworkWS)
	}
	if p.Path != "/chat" {
		t.Errorf("path = %q, want /chat", p.Path)
	}
	if p.Host != "cdn.example.com" {
		t.Errorf("host = %q, want cdn.example.com", p.Host)
	}
	// No sni parameter, so the Host header is the only name available to
	// verify against; falling back to it is what the GUI clients do.
	if p.SNI != "cdn.example.com" {
		t.Errorf("sni = %q, want the host fallback cdn.example.com", p.SNI)
	}
	if want := []string{"h2", "http/1.1"}; len(p.ALPN) != 2 || p.ALPN[0] != want[0] || p.ALPN[1] != want[1] {
		t.Errorf("alpn = %v, want %v", p.ALPN, want)
	}
}

func TestParseTrojan(t *testing.T) {
	p, err := ParseLink("trojan://p%40ssw0rd@example.com:443?security=tls&sni=example.com#t")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.Protocol != ProtoTrojan {
		t.Errorf("protocol = %q, want trojan", p.Protocol)
	}
	// The password is percent-encoded in the link and must arrive decoded, or
	// authentication fails in a way that looks like a dead server.
	if p.ID != "p@ssw0rd" {
		t.Errorf("password = %q, want p@ssw0rd", p.ID)
	}
}

// The transports xray removed have to be rejected at import. Accepting them
// produces a profile that fails at start-up with an error from deep inside the
// core, long after the user has stopped looking at the link.
func TestParseRejectsRemovedTransports(t *testing.T) {
	for _, typ := range []string{"http", "h2", "quic"} {
		_, err := ParseLink("vless://id@h:443?type=" + typ)
		if err == nil {
			t.Errorf("type=%s: expected an error", typ)
			continue
		}
		if !strings.Contains(err.Error(), "removed") {
			t.Errorf("type=%s: error should say the transport was removed, got %v", typ, err)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, tc := range []struct{ name, link string }{
		{"empty", ""},
		{"no scheme", "example.com:443"},
		{"unknown scheme", "http://example.com"},
		{"no uuid", "vless://@example.com:443"},
		{"no port", "vless://id@example.com"},
		{"port not a number", "vless://id@example.com:https"},
		{"port zero", "vless://id@example.com:0"},
	} {
		if _, err := ParseLink(tc.link); err == nil {
			t.Errorf("%s: expected an error for %q", tc.name, tc.link)
		}
	}
}

// vmess and shadowsocks are common enough that "unknown link type" would be a
// confusing thing to show; they get their own message.
func TestParseNamesUnsupportedProtocols(t *testing.T) {
	for _, scheme := range []string{"vmess", "ss", "hysteria2", "tuic"} {
		_, err := ParseLink(scheme + "://whatever")
		if err == nil {
			t.Fatalf("%s: expected an error", scheme)
		}
		if !strings.Contains(err.Error(), "not supported yet") {
			t.Errorf("%s: want a 'not supported yet' message, got %v", scheme, err)
		}
	}
}

// allowInsecure now fails xray at startup, so it must be dropped rather than
// forwarded - and the user has to be told, because the config relied on it.
func TestAllowInsecureIsRecordedButWarned(t *testing.T) {
	p, err := ParseLink("vless://id@h:443?security=tls&allowInsecure=1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.AllowInsecure {
		t.Error("allowInsecure should be recorded on the profile")
	}
	if len(p.Warnings) == 0 {
		t.Fatal("dropping allowInsecure must produce a warning")
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "allowInsecure") {
		t.Errorf("warning should name allowInsecure, got %v", p.Warnings)
	}

	blob, err := p.JSON("x")
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	if strings.Contains(string(blob), "allowInsecure") {
		t.Errorf("allowInsecure must never reach the xray config:\n%s", blob)
	}
}

// A reality link missing pbk or sni parses - so the user can see the entry and
// what is wrong with it - but must not build.
func TestRealityMissingFieldsWarnsThenFailsToBuild(t *testing.T) {
	p, err := ParseLink("vless://id@h:443?security=reality&sni=a.com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(p.Warnings) == 0 {
		t.Error("a reality link with no pbk should warn")
	}
	if _, err := p.Outbound("x"); err == nil {
		t.Error("a reality profile with no public key must not build")
	}
}

func TestParseManyPlainList(t *testing.T) {
	text := strings.Join([]string{
		"vless://a@h1:443?security=reality&sni=x.com&pbk=k#one",
		"",
		"# a comment",
		"trojan://pw@h2:443#two",
		"vless://@broken:443",
	}, "\n")

	profiles, errs := ParseMany(text)
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want 2", len(profiles))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(errs), errs)
	}
	// One bad entry must not cost the user the other forty.
	if errs[0].Line != 5 {
		t.Errorf("error reported on line %d, want 5", errs[0].Line)
	}
	if profiles[0].Name != "one" || profiles[1].Name != "two" {
		t.Errorf("names = %q, %q; want one, two", profiles[0].Name, profiles[1].Name)
	}
}

// Subscriptions arrive base64-encoded, and servers are inconsistent about the
// alphabet and the padding.
func TestParseManyBase64Subscription(t *testing.T) {
	plain := "vless://a@h1:443#one\ntrojan://pw@h2:443#two"
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		profiles, errs := ParseMany(enc.EncodeToString([]byte(plain)))
		if len(errs) != 0 {
			t.Errorf("unexpected errors: %v", errs)
		}
		if len(profiles) != 2 {
			t.Errorf("got %d profiles, want 2", len(profiles))
		}
	}
}

func TestRedactedHidesCredential(t *testing.T) {
	p, err := ParseLink("vless://b831381d-6324-4d53-ad4f-8cda48b30811@h:443?security=reality&sni=a.com&pbk=k#name")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if strings.Contains(p.Redacted(), p.ID) {
		t.Errorf("Redacted leaked the UUID: %s", p.Redacted())
	}
	if !strings.Contains(p.Redacted(), "h:443") {
		t.Errorf("Redacted should still identify the server: %s", p.Redacted())
	}
}
