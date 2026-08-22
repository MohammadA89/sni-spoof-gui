// Package pool keeps pre-warmed upstream connections ready to hand out.
package pool

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialFunc opens one new upstream connection.
type DialFunc func(context.Context) (net.Conn, error)

// dialTimeout bounds a single background warm-up dial.
const dialTimeout = 15 * time.Second

// Bounds on how often expired idle entries are swept out. Without a reaper a
// pool that is never read from would hold connections past their TTL. The
// actual interval tracks the TTL, so a short TTL is honoured promptly instead
// of leaving stale entries to be handed out for seconds afterwards.
const (
	maxReapInterval = 5 * time.Second
	minReapInterval = 50 * time.Millisecond
)

// probeTimeout bounds the liveness read. Every handout pays it, which is a
// deliberate trade: it is one millisecond against the ~100ms of TCP handshake
// and injection delay the pool exists to avoid, and skipping the check for
// young entries would let a connection the edge reset seconds ago be handed to
// a client that then fails for no visible reason.
const probeTimeout = time.Millisecond

// reapInterval returns the sweep period for a given entry lifetime.
func reapInterval(ttl time.Duration) time.Duration {
	d := ttl / 2
	if d > maxReapInterval {
		return maxReapInterval
	}
	if d < minReapInterval {
		return minReapInterval
	}
	return d
}

// Stats are the counters the UI shows.
type Stats struct {
	Hits      atomic.Uint64 // served from the pool
	Misses    atomic.Uint64 // had to dial inline
	Discarded atomic.Uint64 // expired or found dead before handout
	DialFails atomic.Uint64
}

// Pool hands out connections that have already completed their TCP handshake
// and had the fake record injected.
//
// This is what removes the visible cost of the transport. A cold connection
// pays two round trips for the TCP handshake plus the injection delay before it
// can carry a single byte; a pooled one has paid all of that already, so the
// client's connect returns essentially instantly.
type Pool struct {
	dial DialFunc
	size int
	ttl  time.Duration

	idle  chan *entry
	fill  chan struct{}
	stats Stats

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	closed atomic.Bool
}

type entry struct {
	conn net.Conn
	born time.Time
}

func (e *entry) expired(ttl time.Duration) bool {
	return time.Since(e.born) >= ttl
}

// usable reports whether the entry may be handed to a caller.
func (e *entry) usable(ttl time.Duration) bool {
	return !e.expired(ttl) && isAlive(e.conn)
}

// New starts a pool that maintains up to size warm connections. A size of zero
// or less disables warming: Get then always dials inline.
func New(dial DialFunc, size int, ttl time.Duration) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{
		dial:   dial,
		size:   size,
		ttl:    ttl,
		ctx:    ctx,
		cancel: cancel,
	}
	if size > 0 {
		p.idle = make(chan *entry, size)
		p.fill = make(chan struct{}, 1)
		p.wg.Add(2)
		go p.fillLoop()
		go p.reapLoop()
	}
	return p
}

// Get returns a ready connection, preferring a warm one.
//
// Warm entries are validated before handout: an entry past its TTL, or one the
// peer has already closed, is discarded rather than handed to a caller who
// would then see an unexplained failure. The edge will eventually drop an idle
// connection that never starts a TLS handshake, so this check is load-bearing.
func (p *Pool) Get(ctx context.Context) (net.Conn, error) {
	if p.closed.Load() {
		return nil, errors.New("pool: closed")
	}
	for p.idle != nil {
		select {
		case e := <-p.idle:
			p.requestFill()
			if !e.usable(p.ttl) {
				e.conn.Close()
				p.stats.Discarded.Add(1)
				continue
			}
			p.stats.Hits.Add(1)
			return e.conn, nil
		default:
		}
		break
	}

	p.stats.Misses.Add(1)
	p.requestFill()
	return p.dial(ctx)
}

// Close tears the pool down and drops every idle connection.
func (p *Pool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	p.cancel()
	p.wg.Wait()
	if p.idle != nil {
		for {
			select {
			case e := <-p.idle:
				e.conn.Close()
			default:
				return nil
			}
		}
	}
	return nil
}

// Stats returns the live counters.
func (p *Pool) Stats() *Stats { return &p.stats }

// Idle reports how many warm connections are currently available.
func (p *Pool) Idle() int {
	if p.idle == nil {
		return 0
	}
	return len(p.idle)
}

// fillTrigger is a single-slot signal; a pending request coalesces with a new one.
var fillTrigger = struct{}{}

func (p *Pool) requestFill() {
	select {
	case p.fill <- fillTrigger:
	default:
	}
}

// fillLoop keeps the idle channel topped up. Warm-ups run one at a time so a
// burst of misses cannot open a storm of simultaneous handshakes to the edge.
func (p *Pool) fillLoop() {
	defer p.wg.Done()
	for {
		if len(p.idle) >= p.size {
			select {
			case <-p.ctx.Done():
				return
			case <-p.fill:
				continue
			case <-time.After(time.Second):
				continue
			}
		}

		ctx, cancel := context.WithTimeout(p.ctx, dialTimeout)
		conn, err := p.dial(ctx)
		cancel()
		if err != nil {
			p.stats.DialFails.Add(1)
			select {
			case <-p.ctx.Done():
				return
			// Back off before retrying so a broken path does not spin.
			case <-time.After(time.Second):
			}
			continue
		}

		select {
		case p.idle <- &entry{conn: conn, born: time.Now()}:
		default:
			// Filled up while we were dialling.
			conn.Close()
		case <-p.ctx.Done():
			conn.Close()
			return
		}
	}
}

// reapLoop drops entries that have aged out even when nothing is calling Get.
func (p *Pool) reapLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(reapInterval(p.ttl))
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			for i := len(p.idle); i > 0; i-- {
				select {
				case e := <-p.idle:
					if !e.usable(p.ttl) {
						e.conn.Close()
						p.stats.Discarded.Add(1)
						p.requestFill()
						continue
					}
					// Still good: put it back.
					select {
					case p.idle <- e:
					default:
						e.conn.Close()
					}
				default:
					i = 0
				}
			}
		}
	}
}

// isAlive reports whether conn still looks usable.
//
// The deadline has to be in the future, not the present. Setting it to
// time.Now() makes Go check the deadline before touching the socket and report
// a timeout without ever polling, so every connection - dead ones included -
// would look alive.
//
// A timeout is therefore the healthy answer: a warm entry has had only the
// injected record written to it and is waiting for the client to start its own
// handshake, so it should be open and completely quiet. EOF, a reset, or
// readable bytes all mean it is not safe to hand out.
//
// The read consumes nothing on the happy path, because on the happy path there
// is nothing to read.
func isAlive(conn net.Conn) bool {
	if err := conn.SetReadDeadline(time.Now().Add(probeTimeout)); err != nil {
		return false
	}
	defer conn.SetReadDeadline(time.Time{})

	var probe [1]byte
	_, err := conn.Read(probe[:])

	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
