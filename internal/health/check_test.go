package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dialTo returns a DialFunc that ignores the requested address and connects to
// target instead, which is how these tests point a check at a local server.
func dialTo(target string) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
}

func traceServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckReportsSuccessAndExitIP(t *testing.T) {
	srv := traceServer(t, "fl=123abc\nh=1.1.1.1\nip=203.0.113.7\nts=1700000000\n")

	res := Check(context.Background(), dialTo(srv.Listener.Addr().String()), srv.URL)
	if !res.OK {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.ExitIP != "203.0.113.7" {
		t.Errorf("exit IP = %q, want 203.0.113.7", res.ExitIP)
	}
	if res.Error != "" {
		t.Errorf("error should be empty on success: %q", res.Error)
	}
}

// An endpoint that returns only the address still has to work: not every
// service speaks Cloudflare's trace format.
func TestCheckReadsABareAddress(t *testing.T) {
	srv := traceServer(t, "198.51.100.4\n")

	res := Check(context.Background(), dialTo(srv.Listener.Addr().String()), srv.URL)
	if !res.OK {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.ExitIP != "198.51.100.4" {
		t.Errorf("exit IP = %q", res.ExitIP)
	}
}

// Reachable but unrecognisable output still counts as reachable; it just
// cannot show where the traffic came out.
func TestCheckSucceedsWithoutAnExitIP(t *testing.T) {
	srv := traceServer(t, "hello, this is not a trace\n")

	res := Check(context.Background(), dialTo(srv.Listener.Addr().String()), srv.URL)
	if !res.OK {
		t.Fatalf("expected success, got %+v", res)
	}
	if res.ExitIP != "" {
		t.Errorf("exit IP = %q, want empty", res.ExitIP)
	}
}

func TestCheckReportsAnHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadGateway)
	}))
	defer srv.Close()

	res := Check(context.Background(), dialTo(srv.Listener.Addr().String()), srv.URL)
	if res.OK {
		t.Fatal("a 502 is not a working connection")
	}
	if !strings.Contains(res.Error, "502") {
		t.Errorf("error should carry the status, got %q", res.Error)
	}
}

// A failure is a Result, not an error return: "this config does not work" is
// the answer the caller asked for, not a fault in asking.
func TestCheckReportsADialFailureInTheResult(t *testing.T) {
	dial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}

	res := Check(context.Background(), dial, "https://example.invalid/trace")
	if res.OK {
		t.Fatal("expected failure")
	}
	if res.Error == "" {
		t.Error("a failure must say why")
	}
}

// The raw transport error is a wrapped chain ending in a socket error; the part
// a user can act on has to survive to the surface.
func TestErrorsAreMadeReadable(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"refused", `dial tcp 127.0.0.1:10808: connectex: connection refused`, "is it running?"},
		{"timeout", `context deadline exceeded`, "timed out"},
		{"reset", `read tcp: wsarecv: connection was forcibly reset`, "reset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := readable(errors.New(tc.raw))
			if !strings.Contains(got, tc.want) {
				t.Errorf("readable(%q) = %q, want it to mention %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestUnrecognisedErrorsPassThrough(t *testing.T) {
	if got := readable(errors.New("something odd")); got != "something odd" {
		t.Errorf("got %q, want the original text", got)
	}
}

// A slow endpoint must not hang the UI behind it.
func TestCheckHonoursACancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	res := Check(ctx, dialTo(srv.Listener.Addr().String()), srv.URL)
	if res.OK {
		t.Fatal("expected the check to fail")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("the check ignored the deadline, took %s", elapsed)
	}
}

func TestExitIPIgnoresOtherTraceFields(t *testing.T) {
	// "sip=" and "warp=ip" both contain the substring being looked for; only
	// the real key may match.
	body := "warp=off\nsip=none\ngateway=off\nip=203.0.113.9\n"
	if got := exitIP(body); got != "203.0.113.9" {
		t.Errorf("exitIP = %q, want 203.0.113.9", got)
	}
}
