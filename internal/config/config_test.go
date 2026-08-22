package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultIsUsableAsIs(t *testing.T) {
	// Unlike the pre-pivot design, nothing here needs a server or a domain, so
	// a fresh install should start without the user editing anything.
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(*Config){
		"empty listener host":    func(c *Config) { c.Listener.Host = "" },
		"listener port zero":     func(c *Config) { c.Listener.Port = 0 },
		"listener port huge":     func(c *Config) { c.Listener.Port = 70000 },
		"no edge IPs":            func(c *Config) { c.Transport.EdgeIPs = nil },
		"edge not an IP":         func(c *Config) { c.Transport.EdgeIPs = []string{"example.com"} },
		"edge is IPv6":           func(c *Config) { c.Transport.EdgeIPs = []string{"2606:4700::1"} },
		"edge port out of range": func(c *Config) { c.Transport.EdgePort = 0 },
		"empty fake SNI":         func(c *Config) { c.Transport.FakeSNI = "" },
		"unknown mode":           func(c *Config) { c.Transport.Mode = "turbo" },
		"inverted port range":    func(c *Config) { c.Transport.PortLow, c.Transport.PortHigh = 60000, 50000 },
		"pool size zero":         func(c *Config) { c.Pool.Size = 0 },
		"pool ttl zero":          func(c *Config) { c.Pool.TTLSeconds = 0 },
	}
	for name, mutate := range cases {
		c := Default()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}

// A listener bound inside the source port range could be taken by an outgoing
// relay connection, so it is rejected rather than left to fail intermittently.
func TestValidateRejectsListenerInsideSourcePortRange(t *testing.T) {
	c := Default()
	c.Listener.Port = c.Transport.PortLow + 10
	err := c.Validate()
	if err == nil {
		t.Fatal("expected an error for a listener inside the source port range")
	}
	if !strings.Contains(err.Error(), "source port range") {
		t.Errorf("error should explain the collision, got: %v", err)
	}
}

// A disabled pool must not be validated against size or TTL rules.
func TestValidateSkipsPoolChecksWhenDisabled(t *testing.T) {
	c := Default()
	c.Pool.Enabled = false
	c.Pool.Size = 0
	c.Pool.TTLSeconds = 0
	if err := c.Validate(); err != nil {
		t.Errorf("disabled pool should not be validated: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	want := Default()
	want.Transport.EdgeIPs = []string{"188.114.98.0", "104.16.0.1"}
	want.Transport.FakeSNI = "www.speedtest.net"
	want.Pool.Size = 16

	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Transport.EdgeIPs) != 2 || got.Transport.EdgeIPs[1] != "104.16.0.1" {
		t.Errorf("edge IPs did not round-trip: %v", got.Transport.EdgeIPs)
	}
	if got.Pool.Size != 16 || got.Transport.FakeSNI != want.Transport.FakeSNI {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// A file written by an older build may lack fields; those must fall back to
// defaults rather than zero values that fail validation.
func TestLoadFillsMissingFieldsFromDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.json")
	partial := `{"transport":{"edge_ips":["104.16.0.1"]}}`
	if err := os.WriteFile(path, []byte(partial), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Listener.Port != Default().Listener.Port {
		t.Errorf("listener port = %d, want default %d", got.Listener.Port, Default().Listener.Port)
	}
	if got.Transport.FakeSNI != Default().Transport.FakeSNI {
		t.Errorf("fake SNI = %q, want default", got.Transport.FakeSNI)
	}
	if got.Transport.EdgeIPs[0] != "104.16.0.1" {
		t.Errorf("explicit field was overwritten: %v", got.Transport.EdgeIPs)
	}
	if err := got.Validate(); err != nil {
		t.Errorf("partial config should validate after defaults are applied: %v", err)
	}
}

func TestListenerAddr(t *testing.T) {
	l := Listener{Host: "127.0.0.1", Port: 40443}
	if got := l.Addr(); got != "127.0.0.1:40443" {
		t.Errorf("Addr() = %q, want 127.0.0.1:40443", got)
	}
}

func TestMigrateLegacy(t *testing.T) {
	legacy := `{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com"
}`
	if !IsLegacyFile([]byte(legacy)) {
		t.Fatal("upstream config.json not recognised as legacy")
	}
	got, err := MigrateLegacy([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if got.Transport.EdgeIPs[0] != "188.114.98.0" {
		t.Errorf("edge IP = %v", got.Transport.EdgeIPs)
	}
	if got.Transport.FakeSNI != "auth.vercel.com" {
		t.Errorf("fake SNI = %q", got.Transport.FakeSNI)
	}
	if got.Listener.Host != "0.0.0.0" || got.Listener.Port != 40443 {
		t.Errorf("listener = %s, want 0.0.0.0:40443", got.Listener.Addr())
	}
	// Every legacy field maps across, so the result should be usable directly.
	if err := got.Validate(); err != nil {
		t.Errorf("migrated config should be valid: %v", err)
	}
}

// Load must notice an upstream config.json and convert it, rather than
// silently producing a default config because none of the keys matched.
func TestLoadMigratesLegacyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"LISTEN_HOST":"127.0.0.1","LISTEN_PORT":40443,"CONNECT_IP":"104.16.0.1","CONNECT_PORT":443,"FAKE_SNI":"mci.ir"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Transport.EdgeIPs[0] != "104.16.0.1" || got.Transport.FakeSNI != "mci.ir" {
		t.Errorf("legacy file was not migrated on load: %+v", got.Transport)
	}
}

func TestMigrateLegacyRejectsForeignJSON(t *testing.T) {
	if _, err := MigrateLegacy([]byte(`{"hello":"world"}`)); err == nil {
		t.Error("expected an error for unrelated JSON")
	}
	if IsLegacyFile([]byte(`{"hello":"world"}`)) {
		t.Error("unrelated JSON should not be detected as legacy")
	}
}

func TestJSONTagsAreStable(t *testing.T) {
	// The UI and any hand-edited file depend on these names.
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"listener"`, `"port"`, `"edge_ips"`, `"edge_domain"`,
		`"fake_sni"`, `"mode"`, `"inject_delay_ms"`, `"ttl_seconds"`,
	} {
		if !strings.Contains(string(data), key) {
			t.Errorf("marshalled config is missing key %s", key)
		}
	}
}

func TestDurationHelpers(t *testing.T) {
	c := Default()
	if got := c.Transport.InjectDelay().Milliseconds(); got != int64(c.Transport.InjectDelayMs) {
		t.Errorf("InjectDelay() = %dms, want %dms", got, c.Transport.InjectDelayMs)
	}
	if got := int(c.Pool.TTL().Seconds()); got != c.Pool.TTLSeconds {
		t.Errorf("TTL() = %ds, want %ds", got, c.Pool.TTLSeconds)
	}
}
