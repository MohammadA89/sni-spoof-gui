//go:build windows

package xray

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// SystemResolver resolves through the operating system. It is the default, and
// it is the weakest option available: on a network where DNS is tampered with,
// the address it returns for a config's hostname may be the wrong one, and the
// spoofed connection would then be pointed at a server that is not there.
//
// It exists so the dialer works out of the box. A DoH resolver belongs in front
// of it wherever the answers cannot be trusted.
type SystemResolver struct{}

// LookupIPv4 implements Resolver.
func (SystemResolver) LookupIPv4(ctx context.Context, host string) (netip.Addr, error) {
	// A hostname that is already an address needs no lookup, and asking the
	// resolver for one is a needless round trip on every dial.
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() {
			return addr, nil
		}
		return netip.Addr{}, fmt.Errorf("xray: %s is IPv6, which cannot be spoofed", host)
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a.Is4() {
			return a.Unmap(), nil
		}
		if a.Is4In6() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("xray: %s has no IPv4 address", host)
}

// FallbackResolver tries Primary and falls back to Secondary.
//
// It exists so a DoH endpoint that is unreachable does not become the reason
// nothing connects. The trade is deliberate and worth stating: on a network
// that blocks DoH outright, every lookup quietly ends up on the local resolver,
// which is the one being worked around. A failure is logged rather than
// silently swallowed for exactly that reason.
type FallbackResolver struct {
	Primary   Resolver
	Secondary Resolver

	// Logf, if set, reports each fallback.
	Logf func(string, ...any)
}

// LookupIPv4 implements Resolver.
func (f FallbackResolver) LookupIPv4(ctx context.Context, host string) (netip.Addr, error) {
	addr, err := f.Primary.LookupIPv4(ctx, host)
	if err == nil {
		return addr, nil
	}
	if f.Secondary == nil {
		return netip.Addr{}, err
	}
	if f.Logf != nil {
		f.Logf("falling back to the system resolver for %s: %v", host, err)
	}
	return f.Secondary.LookupIPv4(ctx, host)
}

// CachingResolver remembers answers for a while.
//
// Without it every dial to a config with a hostname pays a lookup, and a
// browser opening thirty connections at once pays thirty. The TTL is a fixed
// window rather than the record's own, because the point here is to collapse a
// burst, not to be a correct DNS cache.
type CachingResolver struct {
	inner Resolver
	ttl   time.Duration

	mu      sync.Mutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	addr    netip.Addr
	expires time.Time
}

// NewCachingResolver wraps inner. A ttl of zero disables caching entirely,
// which is useful when chasing a resolution problem.
func NewCachingResolver(inner Resolver, ttl time.Duration) *CachingResolver {
	if inner == nil {
		inner = SystemResolver{}
	}
	return &CachingResolver{
		inner:   inner,
		ttl:     ttl,
		entries: make(map[string]cacheEntry),
	}
}

// LookupIPv4 implements Resolver.
func (c *CachingResolver) LookupIPv4(ctx context.Context, host string) (netip.Addr, error) {
	if c.ttl <= 0 {
		return c.inner.LookupIPv4(ctx, host)
	}

	now := time.Now()
	c.mu.Lock()
	if e, ok := c.entries[host]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.addr, nil
	}
	c.mu.Unlock()

	// Deliberately outside the lock: a slow or hanging lookup must not block
	// every other dial in the process.
	addr, err := c.inner.LookupIPv4(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}

	c.mu.Lock()
	c.entries[host] = cacheEntry{addr: addr, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return addr, nil
}

// Forget drops a cached answer, so a route that has started failing can be
// re-resolved without restarting.
func (c *CachingResolver) Forget(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}
