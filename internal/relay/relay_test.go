package relay

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// pipePair returns two connected TCP connections.
func pipePair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var server net.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server, _ = ln.Accept()
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if server == nil {
		t.Fatal("accept failed")
	}
	return client, server
}

func TestPipeMovesBothDirections(t *testing.T) {
	clientSide, relayClient := pipePair(t)
	relayEdge, edgeSide := pipePair(t)

	var counters Counters
	done := make(chan error, 1)
	go func() { done <- Pipe(relayClient, relayEdge, &counters) }()

	upPayload := []byte("request from the client")
	downPayload := []byte("response from the edge")

	if _, err := clientSide.Write(upPayload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(upPayload))
	if _, err := io.ReadFull(edgeSide, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, upPayload) {
		t.Errorf("upstream: got %q, want %q", got, upPayload)
	}

	if _, err := edgeSide.Write(downPayload); err != nil {
		t.Fatal(err)
	}
	got = make([]byte, len(downPayload))
	if _, err := io.ReadFull(clientSide, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, downPayload) {
		t.Errorf("downstream: got %q, want %q", got, downPayload)
	}

	clientSide.Close()
	edgeSide.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return after both sides closed")
	}

	if counters.Up.Load() != uint64(len(upPayload)) {
		t.Errorf("up counter = %d, want %d", counters.Up.Load(), len(upPayload))
	}
	if counters.Down.Load() != uint64(len(downPayload)) {
		t.Errorf("down counter = %d, want %d", counters.Down.Load(), len(downPayload))
	}
}

// This is the bug the reference implementation has: it closes both sockets when
// either direction ends, so data still travelling the other way is lost. A
// half-close must let the opposite direction drain.
func TestPipeHalfCloseDrainsOppositeDirection(t *testing.T) {
	clientSide, relayClient := pipePair(t)
	relayEdge, edgeSide := pipePair(t)

	done := make(chan error, 1)
	go func() { done <- Pipe(relayClient, relayEdge, nil) }()

	// The client finishes sending and half-closes, as an HTTP client would.
	if _, err := clientSide.Write([]byte("GET / HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	clientSide.(*net.TCPConn).CloseWrite()

	// The edge must still observe EOF and be able to reply afterwards.
	if _, err := io.ReadAll(edgeSide); err != nil {
		t.Fatalf("edge did not see a clean EOF: %v", err)
	}

	payload := bytes.Repeat([]byte("late response body "), 4096)
	go func() {
		edgeSide.Write(payload)
		edgeSide.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("client received %d bytes after half-close, want %d", len(got), len(payload))
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pipe did not return")
	}
}

func TestPipeLargeTransferIsIntact(t *testing.T) {
	clientSide, relayClient := pipePair(t)
	relayEdge, edgeSide := pipePair(t)

	go Pipe(relayClient, relayEdge, nil)

	payload := make([]byte, 4<<20) // 4MB, well past one buffer
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	go func() {
		edgeSide.Write(payload)
		edgeSide.(*net.TCPConn).CloseWrite()
	}()

	got, err := io.ReadAll(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("received %d bytes, want %d; contents differ", len(got), len(payload))
	}
}
