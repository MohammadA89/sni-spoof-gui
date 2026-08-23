//go:build windows

package spoof

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	divert "github.com/imgk/divert-go"
)

// Mode selects how much of the handshake the engine watches.
type Mode string

const (
	// ModeFast captures only SYN packets. Everything else - data segments and
	// pure ACKs alike - stays on the kernel fast path and never reaches user
	// space, which is what lets the relay run at line rate. The cost is that
	// there is no confirmation the peer accepted the injected record; a broken
	// spoof surfaces later as a failed TLS handshake instead.
	ModeFast Mode = "fast"

	// ModeSafe additionally captures zero-payload ACKs on our source ports so
	// the dialer can wait for the peer to acknowledge the injected record, the
	// way the reference Python implementation does. Slower under load, because
	// every pure ACK of every active connection round-trips through user space.
	ModeSafe Mode = "safe"
)

// DefaultInjectDelay is how long the engine waits after passing the SYN-ACK
// along before injecting the fake record. The delay exists so the operating
// system own handshake ACK reaches the wire first: a DPI box tracking
// connection state may discard payload that arrives before the handshake
// completes. The reference implementation waits 1ms at the equivalent point.
const DefaultInjectDelay = time.Millisecond

// Config describes a spoofing engine bound to one local interface and one edge IP.
type Config struct {
	InterfaceIP netip.Addr
	EdgeIP      netip.Addr
	EdgePort    uint16
	FakeSNI     string
	Mode        Mode
	InjectDelay time.Duration

	// PortLow and PortHigh bound the source ports the dialer binds to. Both
	// modes bind explicitly, because a flow has to be registered under its
	// source port before connect() emits the SYN. In ModeSafe the range also
	// narrows the capture filter to our own connections.
	PortLow, PortHigh uint16

	// AnyEdge widens the capture to every destination on EdgePort within the
	// source port range, instead of the single EdgeIP. The scanner needs this:
	// probing a hundred candidate addresses would otherwise mean opening and
	// closing a hundred WinDivert handles. Each flow still records the edge it
	// actually dialled, so injection stays per-connection.
	AnyEdge bool

	// AnyPort drops the EdgePort tests as well, leaving the source port range
	// as the only thing that distinguishes our handshakes. It is for callers
	// that dial whatever address and port a user config names rather than one
	// configured edge, where the destination port is not known up front.
	//
	// It is deliberately separate from AnyEdge, because it is the wider of the
	// two: the bound range overlaps the Windows dynamic port range, so SYNs
	// belonging to other processes now reach the capture loop. They cost a
	// user-space round trip each and are then re-injected untouched - dispatch
	// ignores any port with no flow behind it - but the narrower filter is
	// worth keeping wherever the destination port is fixed.
	AnyPort bool

	// OnEvent, if set, receives human-readable engine events for the UI log.
	OnEvent func(string)
}

func (c *Config) applyDefaults() {
	if c.EdgePort == 0 {
		c.EdgePort = 443
	}
	if c.Mode == "" {
		c.Mode = ModeFast
	}
	if c.InjectDelay == 0 {
		c.InjectDelay = DefaultInjectDelay
	}
	// A wide range keeps explicit binds viable under churn, since a closed
	// source port lingers in TIME_WAIT for minutes.
	if c.PortLow == 0 {
		c.PortLow = 45000
	}
	if c.PortHigh == 0 {
		c.PortHigh = 54999
	}
}

func (c *Config) validate() error {
	if !c.InterfaceIP.Is4() {
		return fmt.Errorf("spoof: interface IP %q is not IPv4", c.InterfaceIP)
	}
	if !c.AnyEdge && !c.EdgeIP.Is4() {
		return fmt.Errorf("spoof: edge IP %q is not IPv4", c.EdgeIP)
	}
	if c.Mode != ModeFast && c.Mode != ModeSafe {
		return fmt.Errorf("spoof: unknown mode %q", c.Mode)
	}
	if c.PortLow > c.PortHigh {
		return fmt.Errorf("spoof: port range %d-%d is inverted", c.PortLow, c.PortHigh)
	}
	if _, err := RandomClientHello(c.FakeSNI); err != nil {
		return err
	}
	return nil
}

// buildFilter returns the WinDivert filter expression for the configured mode.
//
// The SYN-only expression is the single most important performance decision in
// this package. The reference implementation matches every TCP packet between
// the interface and the edge IP, so the entire data plane is dragged through
// user space one packet at a time. Because we synthesise the fake record from
// scratch rather than cloning the handshake ACK, we only ever need to see the
// two SYN packets.
func (c *Config) buildFilter() string {
	// Each direction needs its own port test. The edge port is the destination
	// on the way out and the source on the way back, so a single shared
	// "tcp.DstPort == edge" term would silently exclude every SYN-ACK - which
	// is exactly the packet the injection waits for. Under AnyPort both tests
	// drop out entirely and the source port range carries the whole filter.
	outPort, inPort := "", ""
	if !c.AnyPort {
		outPort = fmt.Sprintf("tcp.DstPort == %d and ", c.EdgePort)
		inPort = fmt.Sprintf("tcp.SrcPort == %d and ", c.EdgePort)
	}

	if c.AnyEdge {
		return fmt.Sprintf(
			"tcp and tcp.Syn and ((ip.SrcAddr == %s and %stcp.SrcPort >= %d and tcp.SrcPort <= %d) or (ip.DstAddr == %s and %stcp.DstPort >= %d and tcp.DstPort <= %d))",
			c.InterfaceIP, outPort, c.PortLow, c.PortHigh,
			c.InterfaceIP, inPort, c.PortLow, c.PortHigh,
		)
	}
	// Trailing terms here, so the separator hangs off the front of the test
	// rather than the back of the address pair.
	outPair, inPair := "", ""
	if !c.AnyPort {
		outPair = fmt.Sprintf(" and tcp.DstPort == %d", c.EdgePort)
		inPair = fmt.Sprintf(" and tcp.SrcPort == %d", c.EdgePort)
	}
	pair := fmt.Sprintf(
		"((ip.SrcAddr == %s and ip.DstAddr == %s%s) or (ip.SrcAddr == %s and ip.DstAddr == %s%s))",
		c.InterfaceIP, c.EdgeIP, outPair, c.EdgeIP, c.InterfaceIP, inPair,
	)
	if c.Mode == ModeFast {
		return "tcp and tcp.Syn and " + pair
	}
	// ModeSafe also needs the peer acknowledgement of the injected record.
	// Restricting to our bound source ports keeps unrelated connections to the
	// same edge IP out of user space.
	ack := fmt.Sprintf(
		"(tcp.Ack and tcp.PayloadLength == 0 and ((tcp.SrcPort >= %d and tcp.SrcPort <= %d) or (tcp.DstPort >= %d and tcp.DstPort <= %d)))",
		c.PortLow, c.PortHigh, c.PortLow, c.PortHigh,
	)
	return "tcp and (tcp.Syn or " + ack + ") and " + pair
}

// flow tracks one outgoing connection through its handshake.
type flow struct {
	srcPort uint16
	edgeIP  netip.Addr
	// dstPort is recorded per flow rather than read from the engine config,
	// because one engine now serves dials to whatever port a user config
	// names. The injected record has to carry the port this flow actually
	// dialled, or it lands on a connection the peer has never heard of.
	dstPort  uint16
	fakeData []byte

	mu         sync.Mutex
	synSeq     uint32
	haveSYN    bool
	synAckSeq  uint32
	haveSYNACK bool
	injected   bool
	ttl        uint8
	window     uint16
	ipid       uint16
	outAddr    divert.Address // captured from our own SYN, for injecting outbound

	done chan struct{}
	err  error
	once sync.Once
}

// finish resolves the flow exactly once. A nil err means the spoof is complete.
func (f *flow) finish(err error) {
	f.once.Do(func() {
		f.err = err
		close(f.done)
	})
}

// Stats holds cumulative engine counters surfaced to the UI.
type Stats struct {
	PacketsSeen atomic.Uint64
	Injected    atomic.Uint64
	Confirmed   atomic.Uint64
	Failed      atomic.Uint64
	ActiveFlows atomic.Int64
}

// Engine owns the WinDivert handle and drives fake-record injection.
type Engine struct {
	cfg    Config
	filter string

	handle *divert.Handle

	mu    sync.RWMutex
	flows map[uint16]*flow

	ports   portCursor
	stats   Stats
	closing atomic.Bool
	wg      sync.WaitGroup
}

// NewEngine validates cfg and prepares an engine. Start must be called to open
// the WinDivert handle.
func NewEngine(cfg Config) (*Engine, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Engine{
		cfg:    cfg,
		filter: cfg.buildFilter(),
		flows:  make(map[uint16]*flow),
		ports:  portCursor{low: cfg.PortLow, high: cfg.PortHigh},
	}, nil
}

// Filter returns the WinDivert expression in use, for logging and diagnostics.
func (e *Engine) Filter() string { return e.filter }

// Mode returns the configured capture mode.
func (e *Engine) Mode() Mode { return e.cfg.Mode }

// Config returns a copy of the engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// Stats returns the live counter block.
func (e *Engine) Stats() *Stats { return &e.stats }

func (e *Engine) logf(format string, args ...any) {
	if e.cfg.OnEvent != nil {
		e.cfg.OnEvent(fmt.Sprintf(format, args...))
	}
}

// Start opens the WinDivert handle and begins the capture loop. It requires
// administrator rights, since WinDivert installs a kernel driver.
func (e *Engine) Start() error {
	h, err := divert.Open(e.filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		return fmt.Errorf("spoof: open WinDivert (needs administrator): %w", err)
	}
	// A deep queue absorbs bursts of simultaneous handshakes without the driver
	// dropping packets while we are busy injecting.
	if err := h.SetParam(divert.QueueLength, divert.QueueLengthMax); err != nil {
		e.logf("could not raise WinDivert queue length: %v", err)
	}
	if err := h.SetParam(divert.QueueTime, divert.QueueTimeMax); err != nil {
		e.logf("could not raise WinDivert queue time: %v", err)
	}
	e.handle = h

	e.wg.Add(1)
	go e.captureLoop()
	e.logf("spoof engine started in %s mode: %s", e.cfg.Mode, e.filter)
	return nil
}

// Close shuts the capture loop down and releases the WinDivert handle.
func (e *Engine) Close() error {
	if !e.closing.CompareAndSwap(false, true) {
		return nil
	}
	if e.handle == nil {
		return nil
	}
	// Shutdown unblocks the in-flight Recv so the loop can exit.
	_ = e.handle.Shutdown(divert.ShutdownBoth)
	err := e.handle.Close()
	e.wg.Wait()

	e.mu.Lock()
	for _, f := range e.flows {
		f.finish(errors.New("spoof: engine shut down"))
	}
	e.flows = make(map[uint16]*flow)
	e.mu.Unlock()
	return err
}

// register starts tracking the handshake on srcPort. It must be called before
// the connect() that emits the SYN, otherwise the capture loop sees a SYN with
// no flow behind it and ignores it.
func (e *Engine) register(srcPort uint16, edge netip.Addr, dstPort uint16) (*flow, error) {
	fake, err := RandomClientHello(e.cfg.FakeSNI)
	if err != nil {
		return nil, err
	}
	f := &flow{
		srcPort:  srcPort,
		edgeIP:   edge,
		dstPort:  dstPort,
		fakeData: fake,
		done:     make(chan struct{}),
	}
	e.mu.Lock()
	if _, exists := e.flows[srcPort]; exists {
		e.mu.Unlock()
		return nil, fmt.Errorf("%w: port %d", ErrPortBusy, srcPort)
	}
	e.flows[srcPort] = f
	e.mu.Unlock()
	e.stats.ActiveFlows.Add(1)
	return f, nil
}

// unregister stops tracking srcPort. Safe to call more than once.
func (e *Engine) unregister(srcPort uint16) {
	e.mu.Lock()
	f, ok := e.flows[srcPort]
	delete(e.flows, srcPort)
	e.mu.Unlock()
	if ok {
		e.stats.ActiveFlows.Add(-1)
		f.finish(errors.New("spoof: flow cancelled"))
	}
}

func (e *Engine) captureLoop() {
	defer e.wg.Done()
	buf := make([]byte, 65535)
	var addr divert.Address

	for {
		n, err := e.handle.Recv(buf, &addr)
		if err != nil {
			if e.closing.Load() {
				return
			}
			e.logf("WinDivert recv failed: %v", err)
			return
		}
		if n == 0 {
			continue
		}
		e.stats.PacketsSeen.Add(1)

		if pkt, perr := ParseIPv4TCP(buf[:n]); perr == nil {
			e.dispatch(pkt, &addr)
		}

		// Every captured packet is re-injected unmodified. We observe the
		// handshake; we never hold it up or drop it.
		if _, err := e.handle.Send(buf[:n], &addr); err != nil && !e.closing.Load() {
			e.logf("WinDivert send failed: %v", err)
		}
	}
}

// dispatch routes a captured packet to its flow. It must not block: the capture
// loop is single-threaded, so any delay here stalls the handshake it is watching.
func (e *Engine) dispatch(pkt *TCPPacket, addr *divert.Address) {
	outbound := pkt.SrcIP == e.cfg.InterfaceIP

	port := pkt.DstPort
	if outbound {
		port = pkt.SrcPort
	}
	e.mu.RLock()
	f, ok := e.flows[port]
	e.mu.RUnlock()
	if !ok {
		return // not one of ours
	}

	switch {
	case pkt.Has(FlagRST):
		e.stats.Failed.Add(1)
		f.finish(errors.New("spoof: peer reset the connection during the handshake"))

	case outbound && pkt.IsSYN():
		f.mu.Lock()
		f.synSeq, f.haveSYN = pkt.Seq, true
		f.ttl, f.window, f.ipid = pkt.TTL, pkt.Window, pkt.IPID
		// The outbound SYN address carries the correct interface index and
		// direction, which we reuse when injecting.
		f.outAddr = *addr
		f.mu.Unlock()

	case !outbound && pkt.IsSYNACK():
		f.mu.Lock()
		ready := f.haveSYN && !f.haveSYNACK
		if ready {
			f.synAckSeq, f.haveSYNACK = pkt.Seq, true
		}
		f.mu.Unlock()
		if ready {
			// Injection sleeps, so it cannot run on the capture loop.
			go e.injectAfterDelay(f)
		}

	case !outbound && e.cfg.Mode == ModeSafe && pkt.Has(FlagACK) && len(pkt.Payload) == 0:
		f.mu.Lock()
		injected, synSeq, synAckSeq := f.injected, f.synSeq, f.synAckSeq
		f.mu.Unlock()
		if injected && pkt.Ack == synSeq+1 && pkt.Seq == synAckSeq+1 {
			e.stats.Confirmed.Add(1)
			f.finish(nil)
		}
	}
}

// injectAfterDelay synthesises and sends the fake ClientHello.
//
// The record goes out with a sequence number one full payload *behind* the
// connection real starting point, so it lands entirely before the window the
// peer is willing to accept. A DPI box reassembling the stream sees a
// ClientHello for the innocuous SNI and classifies the flow on it; the peer TCP
// stack sees an already-acknowledged range, discards the payload, and answers
// with a bare ACK. The real ClientHello then follows on an untouched connection.
func (e *Engine) injectAfterDelay(f *flow) {
	select {
	case <-time.After(e.cfg.InjectDelay):
	case <-f.done:
		return
	}

	f.mu.Lock()
	synSeq, synAckSeq := f.synSeq, f.synAckSeq
	ttl, window, ipid := f.ttl, f.window, f.ipid
	addr := f.outAddr
	f.injected = true
	f.mu.Unlock()

	fake := &TCPPacket{
		SrcIP:   e.cfg.InterfaceIP,
		DstIP:   f.edgeIP,
		SrcPort: f.srcPort,
		DstPort: f.dstPort,
		// The whole trick: start the record before the acceptable window.
		Seq:     synSeq + 1 - uint32(len(f.fakeData)),
		Ack:     synAckSeq + 1,
		Flags:   FlagPSH | FlagACK,
		Window:  window,
		TTL:     ttl,
		IPID:    ipid + 1,
		Payload: f.fakeData,
	}

	raw, err := fake.Marshal()
	if err != nil {
		e.stats.Failed.Add(1)
		f.finish(fmt.Errorf("spoof: build fake record: %w", err))
		return
	}
	// Belt and braces: WinDivert recomputes both checksums in place, so a slip
	// in our own arithmetic cannot put a corrupt packet on the wire.
	divert.CalcChecksums(raw, &addr, 0)

	if _, err := e.handle.Send(raw, &addr); err != nil {
		e.stats.Failed.Add(1)
		f.finish(fmt.Errorf("spoof: inject fake record: %w", err))
		return
	}
	e.stats.Injected.Add(1)

	// In fast mode there is no acknowledgement to wait for: the record is out,
	// and the dialer may proceed immediately.
	if e.cfg.Mode == ModeFast {
		f.finish(nil)
	}
}
