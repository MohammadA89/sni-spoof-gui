package share

import (
	"encoding/json"
	"strings"
	"testing"

	xconf "github.com/xtls/xray-core/infra/conf"
)

// These tests hand the generated JSON to xray-core's own configuration
// builder. Everything else in this package checks the JSON against what the
// source says the field names are; this checks it against the code that
// actually reads them.
//
// It matters because xray ignores keys it does not recognise. A misspelled
// "shortId" or a settings block under the wrong transport name does not fail
// anywhere - it silently produces a connection configured differently from
// what the link asked for, which is the least debuggable outcome available.
//
// The parameters below have to be genuinely well-formed: the builder decodes
// the REALITY public key and insists on 32 bytes, parses the short ID as hex,
// and validates the UUID.
const (
	testUUID   = "b831381d-6324-4d53-ad4f-8cda48b30811"
	testPubKey = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	testShort  = "6ba85179e30d4fc2"
)

// build runs a link all the way through: parse, render, then xray's builder.
func build(t *testing.T, link string) {
	t.Helper()

	p, err := ParseLink(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	blob, err := p.JSON("proxy")
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	var oc xconf.OutboundDetourConfig
	if err := json.Unmarshal(blob, &oc); err != nil {
		t.Fatalf("xray could not unmarshal our outbound: %v\n%s", err, blob)
	}
	if _, err := oc.Build(); err != nil {
		t.Fatalf("xray rejected our outbound: %v\n%s", err, blob)
	}
}

// The configuration this whole feature exists to run.
func TestXrayBuildsVLESSReality(t *testing.T) {
	build(t, "vless://"+testUUID+"@edge.example.com:8443"+
		"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome"+
		"&pbk="+testPubKey+"&sid="+testShort+"&spx=%2F"+
		"&flow=xtls-rprx-vision&encryption=none#Reality")
}

func TestXrayBuildsEveryTransport(t *testing.T) {
	for _, tc := range []struct{ name, link string }{
		{"raw", "vless://" + testUUID + "@h.example.com:443?type=tcp&security=tls&sni=h.example.com"},
		{"raw+http", "vless://" + testUUID + "@h.example.com:80?type=tcp&headerType=http&host=a.com&path=%2Fx"},
		{"ws", "vless://" + testUUID + "@h.example.com:443?type=ws&security=tls&path=%2Fchat&host=cdn.example.com"},
		{"grpc", "vless://" + testUUID + "@h.example.com:443?type=grpc&security=tls&serviceName=svc&mode=multi&sni=h.example.com"},
		{"httpupgrade", "vless://" + testUUID + "@h.example.com:443?type=httpupgrade&security=tls&path=%2Fa&host=b.com"},
		{"xhttp", "vless://" + testUUID + "@h.example.com:443?type=xhttp&security=tls&path=%2Fa&host=b.com"},
		{"kcp", "vless://" + testUUID + "@h.example.com:443?type=kcp"},
		{"trojan", "trojan://p%40ssw0rd@h.example.com:443?security=tls&sni=h.example.com"},
		{"reality+grpc", "vless://" + testUUID + "@h.example.com:443?type=grpc&security=reality&sni=a.com&pbk=" + testPubKey + "&sid=" + testShort + "&serviceName=svc"},
		{"reality+xhttp", "vless://" + testUUID + "@h.example.com:443?type=xhttp&security=reality&sni=a.com&pbk=" + testPubKey + "&sid=" + testShort + "&path=%2Fx"},
	} {
		t.Run(tc.name, func(t *testing.T) { build(t, tc.link) })
	}
}

// Both of these were found by this file rather than by reading the source, and
// both are cases xray rejects at build time. Catching them at import means the
// user is told while looking at the link, instead of watching a config that
// imported cleanly refuse to start.
func TestRejectedBeforeXraySeesThem(t *testing.T) {
	for _, tc := range []struct{ name, link, want string }{
		{
			name: "reality over websocket",
			link: "vless://" + testUUID + "@h.example.com:443?type=ws&security=reality&sni=a.com&pbk=" + testPubKey + "&sid=" + testShort,
			want: "REALITY only over raw, xhttp and grpc",
		},
		{
			name: "reality over httpupgrade",
			link: "vless://" + testUUID + "@h.example.com:443?type=httpupgrade&security=reality&sni=a.com&pbk=" + testPubKey,
			want: "REALITY only over raw, xhttp and grpc",
		},
		{
			name: "mkcp with seed",
			link: "vless://" + testUUID + "@h.example.com:443?type=kcp&seed=abc",
			want: "mKCP seed and header were removed",
		},
		{
			name: "mkcp with header",
			link: "vless://" + testUUID + "@h.example.com:443?type=kcp&headerType=srtp",
			want: "mKCP seed and header were removed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseLink(tc.link)
			if err != nil {
				t.Fatalf("the link should still parse, so the user can see it: %v", err)
			}
			if len(p.Warnings) == 0 {
				t.Error("import should warn about a config that cannot run")
			}
			err = p.Validate()
			if err == nil {
				t.Fatal("Validate accepted a profile xray will reject")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// Every fingerprint a link may carry has to be one xray knows, or the build
// fails on a value the user copied from a working client.
func TestXrayAcceptsCommonFingerprints(t *testing.T) {
	for _, fp := range []string{"", "chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"} {
		link := "vless://" + testUUID + "@h.example.com:443?security=reality&sni=a.com" +
			"&pbk=" + testPubKey + "&sid=" + testShort
		if fp != "" {
			link += "&fp=" + fp
		}
		t.Run("fp="+fp, func(t *testing.T) { build(t, link) })
	}
}

// The check that justifies the whole file: prove xray really does ignore a
// misspelled key rather than reporting it, so the tests above are load-bearing
// and not just decoration.
func TestXraySilentlyIgnoresUnknownKeys(t *testing.T) {
	blob := []byte(`{
	  "protocol": "vless",
	  "settings": {"vnext": [{"address": "h.example.com", "port": 443,
	    "users": [{"id": "` + testUUID + `", "encryption": "none"}]}]},
	  "streamSettings": {
	    "network": "raw",
	    "security": "reality",
	    "realitySettings": {"serverName": "a.com", "publicKey": "` + testPubKey + `",
	      "shortIdTypo": "` + testShort + `", "nonsenseKey": 12345}
	  }
	}`)

	var oc xconf.OutboundDetourConfig
	if err := json.Unmarshal(blob, &oc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, err := oc.Build(); err != nil {
		t.Fatalf("expected the misspelled keys to be ignored, but the build failed: %v", err)
	}
}

// allowInsecure is past its removal date, so confirm that emitting it really
// would be fatal - that is the reason the renderer drops it.
func TestXrayRejectsAllowInsecure(t *testing.T) {
	blob := []byte(`{
	  "protocol": "vless",
	  "settings": {"vnext": [{"address": "h.example.com", "port": 443,
	    "users": [{"id": "` + testUUID + `", "encryption": "none"}]}]},
	  "streamSettings": {"network": "raw", "security": "tls",
	    "tlsSettings": {"serverName": "a.com", "allowInsecure": true}}
	}`)

	var oc xconf.OutboundDetourConfig
	if err := json.Unmarshal(blob, &oc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	_, err := oc.Build()
	if err == nil {
		t.Skip("this xray build still accepts allowInsecure; the renderer drops it either way")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "allowinsecure") {
		t.Logf("allowInsecure rejected, message does not name it: %v", err)
	}
}
