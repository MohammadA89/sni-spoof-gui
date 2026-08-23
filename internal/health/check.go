// Package health answers the only question a user actually has: is the config
// I selected carrying traffic right now.
//
// It answers it by using the connection rather than inspecting it. Counters can
// look healthy while nothing works - a spoofed TCP connection that the server
// then resets still increments "spoofed" - so the check makes a real request
// through the local inbound and reports what came back.
package health

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultEndpoint returns the caller's apparent address, which is what makes
// the result meaningful: an exit address that differs from the user's own is
// proof the traffic went through the server rather than around it.
const DefaultEndpoint = "https://1.1.1.1/cdn-cgi/trace"

// DefaultTimeout bounds one check. A config that needs longer than this is not
// one anybody will want to browse through.
const DefaultTimeout = 15 * time.Second

// maxBody caps the response read. The trace endpoint returns a few hundred
// bytes; anything larger is a captive portal or a hijacked response.
const maxBody = 16 << 10

// Result is what the UI shows.
type Result struct {
	// OK means a request completed end to end.
	OK bool `json:"ok"`

	// LatencyMs is the round trip for the whole request, including the TLS
	// handshake, so it is not a ping - it is what a page load starts with.
	LatencyMs int64 `json:"latencyMs"`

	// ExitIP is the address the far end saw, when the endpoint reports one.
	ExitIP string `json:"exitIp"`

	// Error is a human-readable failure, empty when OK.
	Error string `json:"error,omitempty"`
}

// DialFunc opens a connection to addr. It is how the caller decides whether the
// check goes through the proxy or around it.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Check makes one request through dial and reports what happened.
//
// A failure is returned in Result rather than as an error: "this config does
// not work" is the answer the caller asked for, not a fault in asking.
func Check(ctx context.Context, dial DialFunc, endpoint string) Result {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dial,
			// One connection, used once. Reuse would make a second check
			// measure a warm socket and report a latency the user will never
			// actually see.
			DisableKeepAlives: true,
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{Error: err.Error()}
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{LatencyMs: time.Since(start).Milliseconds(), Error: readable(err)}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	elapsed := time.Since(start)

	if err != nil {
		return Result{LatencyMs: elapsed.Milliseconds(), Error: readable(err)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return Result{
			LatencyMs: elapsed.Milliseconds(),
			Error:     fmt.Sprintf("the endpoint answered %s", resp.Status),
		}
	}

	return Result{
		OK:        true,
		LatencyMs: elapsed.Milliseconds(),
		ExitIP:    exitIP(string(body)),
	}
}

// exitIP pulls the address out of a Cloudflare trace body, which is a list of
// key=value lines. An endpoint that reports something else still counts as
// reachable; it just cannot show where the traffic came out.
func exitIP(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			return v
		}
	}
	// Some endpoints return the bare address and nothing else.
	if trimmed := strings.TrimSpace(body); net.ParseIP(trimmed) != nil {
		return trimmed
	}
	return ""
}

// readable turns the transport's error into something worth showing.
//
// The raw text is a wrapped chain ending in a Windows socket error, and the
// part a user can act on - refused, timed out, reset - is buried in the middle
// of it.
func readable(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context deadline exceeded"), strings.Contains(msg, "Client.Timeout"):
		return "timed out: the server accepted nothing within the time limit"
	case strings.Contains(msg, "refused"):
		return "the local proxy refused the connection: is it running?"
	case strings.Contains(msg, "reset"):
		return "the connection was reset: the server closed it mid-request"
	case strings.Contains(msg, "socks"):
		return "the local SOCKS proxy rejected the request: " + msg
	}
	return msg
}
