//go:build windows

package spoof

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// DefaultSpoofTimeout bounds how long Dial waits for the handshake to be
// spoofed before giving up. The reference implementation uses 2s; we allow a
// little more headroom for slow paths to the edge.
const DefaultSpoofTimeout = 3 * time.Second

// socketBufferSize is applied to both directions of every outgoing connection.
// The default Windows autotuned buffer is too small to keep a high
// bandwidth-delay-product path to a distant edge full.
const socketBufferSize = 512 * 1024

// maxPortAttempts bounds how many source ports Dial will try before failing.
// Explicit binds can collide with a port still in TIME_WAIT or held by another
// process, and walking a few candidates is cheaper than surfacing the error.
//
// Under a burst of simultaneous dials the window of ports in flight is wide, so
// this has to be comfortably larger than the number of dials the tunnel lets
// run at once, or a burst exhausts the attempts rather than the range.
const maxPortAttempts = 64

// ErrPortBusy reports that the chosen source port already has a flow behind it.
// It is a transient collision between two simultaneous dials, not a fault:
// the next port works, so DialTo retries rather than failing the connection.
var ErrPortBusy = errors.New("spoof: source port is already being tracked")

// portCursor rotates through the configured range so consecutive dials do not
// retry the same busy port.
type portCursor struct {
	low, high uint16
	next      atomic.Uint32
}

func (p *portCursor) take() uint16 {
	span := uint32(p.high) - uint32(p.low) + 1
	return uint16(uint32(p.low) + p.next.Add(1)%span)
}

// Dial opens a TCP connection to the configured edge and primes it against DPI
// before returning.
//
// Ordering matters: the flow has to be registered before connect() emits the
// SYN, or the capture loop sees a SYN with no flow behind it and ignores the
// handshake entirely. That is why the source port is bound explicitly rather
// than left to the ephemeral allocator - we cannot register a port we do not
// yet know.
//
// The returned connection has completed its TCP handshake and had the fake
// ClientHello injected, but carries no application bytes yet. The caller is
// expected to start a real TLS handshake on it immediately.
func (e *Engine) Dial(ctx context.Context) (net.Conn, error) {
	return e.DialTo(ctx, e.cfg.EdgeIP)
}

// DialTo is Dial against a specific edge address on the configured edge port,
// for callers that manage more than one - the scanner probing candidates, or
// failover across a ranked list. The engine must have been built with AnyEdge
// for addresses other than the configured one to be captured.
func (e *Engine) DialTo(ctx context.Context, edge netip.Addr) (net.Conn, error) {
	return e.DialToPort(ctx, edge, e.cfg.EdgePort)
}

// DialToPort is DialTo against an arbitrary destination port, for callers whose
// destination comes from a user config rather than from this package's own
// configuration. The engine must have been built with AnyPort, or the capture
// filter will not match a handshake to any port but the configured one and the
// dial times out waiting for an injection that never happens.
func (e *Engine) DialToPort(ctx context.Context, edge netip.Addr, port uint16) (net.Conn, error) {
	if e.handle == nil {
		return nil, errors.New("spoof: engine is not started")
	}
	if !edge.Is4() {
		return nil, fmt.Errorf("spoof: edge %q is not IPv4", edge)
	}
	if port == 0 {
		return nil, errors.New("spoof: destination port 0 is not dialable")
	}
	if port != e.cfg.EdgePort && !e.cfg.AnyPort {
		return nil, fmt.Errorf("spoof: engine is pinned to port %d; rebuild it with AnyPort to dial %d", e.cfg.EdgePort, port)
	}
	var lastErr error
	for attempt := 0; attempt < maxPortAttempts; attempt++ {
		conn, err := e.dialOnce(ctx, edge, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// Only a port collision is worth another port; anything else will
		// fail the same way on every port.
		if !isPortCollision(err) {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("spoof: no free source port after %d attempts: %w", maxPortAttempts, lastErr)
}

func (e *Engine) dialOnce(ctx context.Context, edge netip.Addr, dstPort uint16) (net.Conn, error) {
	port := e.ports.take()

	f, err := e.register(port, edge, dstPort)
	if err != nil {
		return nil, err
	}
	registered := true
	defer func() {
		if registered {
			e.unregister(port)
		}
	}()

	d := net.Dialer{
		LocalAddr: &net.TCPAddr{IP: e.cfg.InterfaceIP.AsSlice(), Port: int(port)},
		Control:   controlSocket,
		KeepAlive: 15 * time.Second,
	}
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(edge.String(), fmt.Sprint(dstPort)))
	if err != nil {
		return nil, err
	}

	tuneConn(conn)

	timeout := time.NewTimer(DefaultSpoofTimeout)
	defer timeout.Stop()

	select {
	case <-f.done:
		if f.err != nil {
			conn.Close()
			return nil, f.err
		}
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	case <-timeout.C:
		conn.Close()
		// A timeout here almost always means the capture loop never saw the
		// handshake: wrong interface IP, or the filter does not match.
		return nil, fmt.Errorf("spoof: timed out after %s waiting for the fake record to be injected (mode %s)", DefaultSpoofTimeout, e.cfg.Mode)
	}

	// The spoof is done; stop tracking so the port can be reused and the
	// capture loop stops looking this flow up.
	e.unregister(port)
	registered = false
	return conn, nil
}

// controlSocket runs on the raw socket after creation but before bind. Windows
// honours SO_REUSEADDR for binding a source port still lingering in TIME_WAIT,
// which is what keeps a bounded port range usable under connection churn.
func controlSocket(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_REUSEADDR, 1); err != nil {
			setErr = fmt.Errorf("spoof: set SO_REUSEADDR: %w", err)
			return
		}
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_RCVBUF, socketBufferSize); err != nil {
			setErr = fmt.Errorf("spoof: set SO_RCVBUF: %w", err)
			return
		}
		if err := windows.SetsockoptInt(h, windows.SOL_SOCKET, windows.SO_SNDBUF, socketBufferSize); err != nil {
			setErr = fmt.Errorf("spoof: set SO_SNDBUF: %w", err)
			return
		}
	})
	if err != nil {
		return err
	}
	return setErr
}

// tuneConn applies the connection settings that matter for interactive latency.
// Go enables TCP_NODELAY by default, but the reference implementation never set
// it, so Nagle could hold small writes for up to 40ms.
func tuneConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetNoDelay(true)
	_ = tc.SetKeepAlive(true)
	_ = tc.SetKeepAlivePeriod(15 * time.Second)
}

// isPortCollision reports whether err means "this source port is taken, try
// another one".
//
// Two distinct collisions land here. ErrPortBusy is ours: another in-flight
// dial holds the same port in the engine flow table. WSAEADDRINUSE is the
// kernel's, and on Windows it usually arrives from connectex rather than bind -
// SO_REUSEADDR lets the bind through, and the 4-tuple is only found to be
// duplicated when the connection to the edge is actually attempted. Both mean
// the same thing to the caller, and both are cured by the next port.
func isPortCollision(err error) bool {
	return errors.Is(err, ErrPortBusy) || isAddrInUse(err)
}

func isAddrInUse(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || errors.Is(err, windows.WSAEADDRINUSE)
}
