// Package config defines the on-disk configuration and its defaults.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the whole application configuration as persisted to disk.
//
// The app is a transport, not a proxy: it opens a DPI-evading TCP path to an
// edge IP and relays bytes over it verbatim. Whatever protocol runs inside -
// VLESS, Trojan, plain TLS - is the business of the client pointed at the
// listener, so none of it appears here.
type Config struct {
	Listener  Listener  `json:"listener"`
	Transport Transport `json:"transport"`
	Pool      Pool      `json:"pool"`
	Log       Log       `json:"log"`
	Client    Client    `json:"client"`
}

// Client configures the built-in proxy client.
//
// With it enabled the app stops being only a transport: an embedded xray-core
// runs the user's own imported config, and every connection it makes is dialled
// through the spoofing engine. The comment above about carrying no protocol
// still describes the other mode, which is kept because pointing an external
// client at a local listener is a perfectly good way to work and costs nothing
// to leave in place.
type Client struct {
	// Enabled selects the built-in client over the plain relay listener.
	Enabled bool `json:"enabled"`

	// SocksPort and HTTPPort are the local inbounds a browser or the system
	// proxy points at. They default to v2rayN's, so an existing browser setting
	// keeps working unchanged.
	SocksPort int `json:"socks_port"`
	HTTPPort  int `json:"http_port"`

	// DoH is the resolver xray uses for names it looks up itself. "off"
	// leaves it with the local resolver.
	DoH string `json:"doh"`
}

// Listener is the local endpoint clients connect to.
type Listener struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Addr returns the host:port the listener binds to.
func (l Listener) Addr() string {
	return fmt.Sprintf("%s:%d", l.Host, l.Port)
}

// Transport configures the DPI-evading TCP layer.
type Transport struct {
	// EdgeIPs are candidate edge addresses, best first. These are the "clean"
	// IPs: addresses that answer on 443 and are not themselves blocked.
	EdgeIPs  []string `json:"edge_ips"`
	EdgePort int      `json:"edge_port"`

	// EdgeDomain is a domain the edge IPs actually serve, such as hcaptcha.com.
	// It is not used for relaying - the client supplies its own SNI - but the
	// health check and the IP scanner need a name the edge will complete a TLS
	// handshake for.
	EdgeDomain string `json:"edge_domain"`

	// FakeSNI is the innocuous name carried by the injected record. It is what
	// DPI sees and classifies the connection on, and it must differ from
	// whatever the client really asks for.
	FakeSNI string `json:"fake_sni"`

	// Mode is "fast" (SYN-only capture, data plane stays in the kernel) or
	// "safe" (also waits for the peer to acknowledge the injected record).
	Mode string `json:"mode"`

	// Auto makes Connect pick the route itself: it scans for a clean IP,
	// verifies the best candidates with a real spoofed session, and starts on
	// the winner. Without it the first entry in EdgeIPs is used as given.
	Auto bool `json:"auto"`

	// Spoof turns the injection off while still relaying, which is the only
	// way to tell a broken transport apart from a config whose domain the edge
	// simply does not serve. If a client fails both with and without spoofing,
	// the transport is not the problem.
	Spoof bool `json:"spoof"`

	InjectDelayMs int `json:"inject_delay_ms"`
	PortLow       int `json:"port_low"`
	PortHigh      int `json:"port_high"`
}

// Pool configures pre-warmed connections.
type Pool struct {
	// Enabled trades a few idle connections for near-zero connect latency: a
	// pooled entry has already paid the TCP handshake and the injection delay.
	Enabled bool `json:"enabled"`
	Size    int  `json:"size"`

	// TTLSeconds must stay below the edge idle timeout. A warm connection has
	// not started a TLS handshake yet, and an edge will eventually drop one
	// that stays silent.
	TTLSeconds int `json:"ttl_seconds"`
}

// Log configures diagnostics.
type Log struct {
	Level string `json:"level"`
}

// Default returns a configuration with every field populated to a sane value.
func Default() Config {
	return Config{
		Listener: Listener{
			Host: "127.0.0.1",
			Port: 40443,
		},
		Transport: Transport{
			EdgeIPs:       []string{"188.114.98.0"},
			EdgePort:      443,
			EdgeDomain:    "hcaptcha.com",
			FakeSNI:       "auth.vercel.com",
			Mode:          "fast",
			Auto:          true,
			Spoof:         true,
			InjectDelayMs: 1,
			PortLow:       45000,
			PortHigh:      54999,
		},
		Pool: Pool{
			Enabled:    true,
			Size:       8,
			TTLSeconds: 30,
		},
		Log: Log{Level: "info"},
		Client: Client{
			Enabled:   true,
			SocksPort: 10808,
			HTTPPort:  10809,
			DoH:       "https://1.1.1.1/dns-query",
		},
	}
}

// InjectDelay returns the configured delay as a duration.
func (t Transport) InjectDelay() time.Duration {
	return time.Duration(t.InjectDelayMs) * time.Millisecond
}

// TTL returns the configured pool entry lifetime as a duration.
func (p Pool) TTL() time.Duration {
	return time.Duration(p.TTLSeconds) * time.Second
}

// PrimaryEdge returns the first configured edge IP.
func (t Transport) PrimaryEdge() (netip.Addr, error) {
	if len(t.EdgeIPs) == 0 {
		return netip.Addr{}, fmt.Errorf("config: no edge IPs configured")
	}
	return netip.ParseAddr(t.EdgeIPs[0])
}

// Validate reports the first problem that would stop the app from starting.
// It checks the whole config up front rather than failing lazily at connect
// time, so the UI can show one clear message before anything is torn up.
func (c *Config) Validate() error {
	if c.Listener.Host == "" {
		return fmt.Errorf("config: listener host is required")
	}
	if c.Listener.Port <= 0 || c.Listener.Port > 65535 {
		return fmt.Errorf("config: listener port %d is out of range", c.Listener.Port)
	}

	if len(c.Transport.EdgeIPs) == 0 {
		return fmt.Errorf("config: at least one edge IP is required")
	}
	for _, s := range c.Transport.EdgeIPs {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return fmt.Errorf("config: edge IP %q is not an IP address", s)
		}
		if !addr.Is4() {
			return fmt.Errorf("config: edge IP %q is not IPv4", s)
		}
	}
	if c.Transport.EdgePort <= 0 || c.Transport.EdgePort > 65535 {
		return fmt.Errorf("config: edge_port %d is out of range", c.Transport.EdgePort)
	}
	if c.Transport.FakeSNI == "" {
		return fmt.Errorf("config: fake_sni is required")
	}
	switch c.Transport.Mode {
	case "fast", "safe":
	default:
		return fmt.Errorf("config: mode %q must be \"fast\" or \"safe\"", c.Transport.Mode)
	}
	if c.Transport.PortLow <= 0 || c.Transport.PortHigh > 65535 || c.Transport.PortLow > c.Transport.PortHigh {
		return fmt.Errorf("config: source port range %d-%d is invalid", c.Transport.PortLow, c.Transport.PortHigh)
	}
	// The source port range doubles as the listener-collision guard: binding the
	// listener inside it would let a relayed connection steal the listener port.
	if c.Listener.Port >= c.Transport.PortLow && c.Listener.Port <= c.Transport.PortHigh {
		return fmt.Errorf("config: listener port %d falls inside the source port range %d-%d",
			c.Listener.Port, c.Transport.PortLow, c.Transport.PortHigh)
	}

	if c.Client.Enabled {
		if c.Client.SocksPort <= 0 || c.Client.SocksPort > 65535 {
			return fmt.Errorf("config: client socks_port %d is out of range", c.Client.SocksPort)
		}
		if c.Client.HTTPPort <= 0 || c.Client.HTTPPort > 65535 {
			return fmt.Errorf("config: client http_port %d is out of range", c.Client.HTTPPort)
		}
		if c.Client.SocksPort == c.Client.HTTPPort {
			return fmt.Errorf("config: client socks_port and http_port cannot both be %d", c.Client.SocksPort)
		}
		// Same reasoning as the listener check above: an inbound bound inside
		// the source port range could have its port stolen by an outgoing
		// spoofed connection.
		for name, port := range map[string]int{"socks_port": c.Client.SocksPort, "http_port": c.Client.HTTPPort} {
			if port >= c.Transport.PortLow && port <= c.Transport.PortHigh {
				return fmt.Errorf("config: client %s %d falls inside the source port range %d-%d",
					name, port, c.Transport.PortLow, c.Transport.PortHigh)
			}
		}
	}

	if c.Pool.Enabled {
		if c.Pool.Size <= 0 {
			return fmt.Errorf("config: pool size %d must be positive when the pool is enabled", c.Pool.Size)
		}
		if c.Pool.TTLSeconds <= 0 {
			return fmt.Errorf("config: pool ttl_seconds %d must be positive", c.Pool.TTLSeconds)
		}
	}
	return nil
}

// Load reads a configuration file, filling any absent field from Default so an
// older or partial file still starts.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if IsLegacyFile(data) {
		return MigrateLegacy(data)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes the configuration atomically, so an interrupted write cannot
// leave the user with an unparseable file and no way back into the app.
func Save(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("config: create directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("config: write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: replace %s: %w", path, err)
	}
	return nil
}

// legacyConfig is the flat config.json used by the reference Python project.
type legacyConfig struct {
	ListenHost  *string `json:"LISTEN_HOST"`
	ListenPort  *int    `json:"LISTEN_PORT"`
	ConnectIP   *string `json:"CONNECT_IP"`
	ConnectPort *int    `json:"CONNECT_PORT"`
	FakeSNI     *string `json:"FAKE_SNI"`
}

// MigrateLegacy converts an upstream config.json into a Config. Every legacy
// field has a direct equivalent here, so the result is immediately usable.
func MigrateLegacy(data []byte) (Config, error) {
	var legacy legacyConfig
	if err := json.Unmarshal(data, &legacy); err != nil {
		return Config{}, fmt.Errorf("config: parse legacy config: %w", err)
	}
	if legacy.ConnectIP == nil && legacy.FakeSNI == nil {
		return Config{}, fmt.Errorf("config: this does not look like an upstream config.json")
	}

	cfg := Default()
	if legacy.ListenHost != nil && *legacy.ListenHost != "" {
		cfg.Listener.Host = *legacy.ListenHost
	}
	if legacy.ListenPort != nil && *legacy.ListenPort > 0 {
		cfg.Listener.Port = *legacy.ListenPort
	}
	if legacy.ConnectIP != nil && *legacy.ConnectIP != "" {
		cfg.Transport.EdgeIPs = []string{*legacy.ConnectIP}
	}
	if legacy.ConnectPort != nil && *legacy.ConnectPort > 0 {
		cfg.Transport.EdgePort = *legacy.ConnectPort
	}
	if legacy.FakeSNI != nil && *legacy.FakeSNI != "" {
		cfg.Transport.FakeSNI = *legacy.FakeSNI
	}
	return cfg, nil
}

// IsLegacyFile reports whether data looks like an upstream config.json.
func IsLegacyFile(data []byte) bool {
	s := string(data)
	return strings.Contains(s, `"CONNECT_IP"`) || strings.Contains(s, `"FAKE_SNI"`)
}
