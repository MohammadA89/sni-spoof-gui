//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"time"

	xproxy "golang.org/x/net/proxy"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/health"
)

// ConnectionTest is the answer to "is the config I selected actually working".
type ConnectionTest struct {
	// Proxied is the request made through the local inbound. It is the one
	// that matters.
	Proxied health.Result `json:"proxied"`

	// Direct is the same request made without the proxy, for comparison.
	//
	// It is what turns a bare success into proof. An exit address equal to the
	// direct one means traffic went around the proxy rather than through it,
	// and a direct request that also fails means the network is down rather
	// than the config being bad.
	Direct health.Result `json:"direct"`

	// Verdict is the plain-language conclusion, already reasoned out here so
	// the UI does not have to re-derive it.
	Verdict string `json:"verdict"`
	Working bool   `json:"working"`

	Profile string `json:"profile"`
}

// TestConnection makes one real request through the running client and reports
// what came back.
//
// It deliberately goes through the live inbound rather than standing up a
// parallel engine: what the user wants to know is whether *their* traffic is
// working, and a separate path could succeed while the real one does not.
func (a *App) TestConnection() (ConnectionTest, error) {
	a.mu.Lock()
	cl := a.client
	cfg := a.cfg
	a.mu.Unlock()

	if cl == nil {
		if !cfg.Client.Enabled {
			return ConnectionTest{}, fmt.Errorf("this test needs the built-in client; the relay listener has no proxy to send a request through")
		}
		return ConnectionTest{}, fmt.Errorf("connect first, then run the test")
	}

	var out ConnectionTest
	if store := a.loadProfiles(); store != nil {
		if p, _, err := store.ActiveProfile(); err == nil {
			out.Profile = p.Label()
		}
	}

	socks := fmt.Sprintf("%s:%d", cfg.Listener.Host, cfg.Client.SocksPort)
	dial, err := socksDialer(socks)
	if err != nil {
		return ConnectionTest{}, err
	}

	ctx := context.Background()
	a.log("testing the connection through %s", socks)

	out.Proxied = health.Check(ctx, dial, "")
	out.Direct = health.Check(ctx, directDial, "")
	out.Verdict, out.Working = verdict(out)

	a.log("test: %s", out.Verdict)
	return out, nil
}

// socksDialer builds a dialer that goes through the local SOCKS inbound.
//
// Names are left for the proxy to resolve. Resolving them here would test a
// path the user's browser never takes, and would leak the lookup to the local
// resolver besides.
func socksDialer(addr string) (health.DialFunc, error) {
	d, err := xproxy.SOCKS5("tcp", addr, nil, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the local proxy at %s: %w", addr, err)
	}
	ctxDialer, ok := d.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("the SOCKS dialer does not support cancellation")
	}
	return ctxDialer.DialContext, nil
}

func directDial(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	return d.DialContext(ctx, network, addr)
}

// verdict reasons about the pair of results.
//
// The comparison is what makes the test worth anything. A proxied request that
// succeeds proves only that something answered; it is the exit address
// differing from the direct one that proves the traffic went through the
// server.
func verdict(t ConnectionTest) (string, bool) {
	switch {
	case t.Proxied.OK && t.Direct.OK &&
		t.Proxied.ExitIP != "" && t.Proxied.ExitIP == t.Direct.ExitIP:
		// Same address both ways: the request went around the proxy, or the
		// proxy is forwarding straight out.
		return fmt.Sprintf("traffic is NOT going through the server: it exits from %s either way", t.Proxied.ExitIP), false

	case t.Proxied.OK && t.Proxied.ExitIP != "":
		return fmt.Sprintf("working: %d ms, exiting from %s", t.Proxied.LatencyMs, t.Proxied.ExitIP), true

	case t.Proxied.OK:
		// Reachable, but the endpoint did not say where from.
		return fmt.Sprintf("working: %d ms", t.Proxied.LatencyMs), true

	case !t.Direct.OK:
		// Both failed, so the config is not the thing to blame yet.
		return fmt.Sprintf("cannot tell: the test endpoint is unreachable with or without the proxy (%s)", t.Direct.Error), false

	default:
		return fmt.Sprintf("not working: %s", t.Proxied.Error), false
	}
}
