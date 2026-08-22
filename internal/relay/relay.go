// Package relay copies bytes between two connections.
package relay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// bufferSize is the per-direction copy buffer. 64KB matches the largest TCP
// segment batch Windows will hand up in one read, so larger buffers buy nothing.
const bufferSize = 64 * 1024

// buffers recycles copy buffers. The reference implementation allocates a fresh
// object on every read, which at line rate means a steady stream of garbage.
var buffers = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

// halfCloser is implemented by TCP connections, which can signal end-of-stream
// in one direction while still reading in the other.
type halfCloser interface {
	CloseWrite() error
}

// Counters accumulate transferred bytes for the UI.
type Counters struct {
	Up   atomic.Uint64 // client -> edge
	Down atomic.Uint64 // edge -> client
}

// Pipe copies in both directions until both are finished, then returns.
//
// Each direction is shut down independently: when one side reaches EOF we
// half-close the peer's write side and let the other direction keep draining.
// The reference implementation closes both sockets on the first EOF, which
// truncates whatever was still in flight the other way - a real source of
// corrupted downloads.
//
// Both connections are closed before Pipe returns. The returned error is the
// first non-EOF failure seen, or nil for a clean shutdown.
func Pipe(client, edge net.Conn, c *Counters) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var upErr, downErr error

	go func() {
		defer wg.Done()
		n, err := copyBuffer(edge, client)
		if c != nil {
			c.Up.Add(uint64(n))
		}
		if err != nil {
			// Naming the side that failed is the difference between a usable
			// log line and a wall of identical wsarecv errors: a client-side
			// failure means the local app gave up, an edge-side one means the
			// far end rejected us.
			upErr = fmt.Errorf("client closed: %w", err)
		}
		closeWrite(edge)
	}()

	go func() {
		defer wg.Done()
		n, err := copyBuffer(client, edge)
		if c != nil {
			c.Down.Add(uint64(n))
		}
		if err != nil {
			downErr = fmt.Errorf("edge closed: %w", err)
		}
		closeWrite(client)
	}()

	wg.Wait()
	client.Close()
	edge.Close()

	if downErr != nil {
		return downErr
	}
	return upErr
}

// copyBuffer moves bytes from src to dst using a pooled buffer. It reports EOF
// and "use of closed network connection" as success, since both are how a
// normal shutdown surfaces.
//
// The loop is written out rather than delegated to io.CopyBuffer because
// *net.TCPConn implements io.ReaderFrom: io.CopyBuffer would take that path,
// ignore the buffer we passed, and allocate a fresh one per call. On Windows
// there is no socket-to-socket zero-copy to gain from that path anyway.
func copyBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bp := buffers.Get().(*[]byte)
	defer buffers.Put(bp)
	buf := *bp

	var total int64
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			total += int64(nw)
			if werr != nil {
				return total, ignoreShutdown(werr)
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			return total, ignoreShutdown(rerr)
		}
	}
}

// ignoreShutdown maps the errors that represent an ordinary end of stream to nil.
func ignoreShutdown(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// closeWrite signals end-of-stream to the peer without tearing the whole
// connection down, so the opposite direction can finish.
func closeWrite(conn net.Conn) {
	if hc, ok := conn.(halfCloser); ok {
		_ = hc.CloseWrite()
		return
	}
	// Not half-closable: a full close is the only way to unblock the peer.
	_ = conn.Close()
}
