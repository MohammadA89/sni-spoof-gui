// Package netutil holds small networking helpers shared across the app.
package netutil

import (
	"fmt"
	"net"
	"net/netip"
)

// DefaultInterfaceIPv4 reports the local IPv4 address the operating system
// would use to reach target. It opens an unconnected UDP socket, so no packets
// are sent and no handshake happens - the kernel just resolves the route.
//
// This mirrors get_default_interface_ipv4 in the reference implementation, and
// its result must match the address used in the WinDivert filter, or the
// capture loop will never see our handshakes.
func DefaultInterfaceIPv4(target netip.Addr) (netip.Addr, error) {
	if !target.Is4() {
		return netip.Addr{}, fmt.Errorf("netutil: target %q is not IPv4", target)
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(target.String(), "53"))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("netutil: resolve route to %s: %w", target, err)
	}
	defer conn.Close()

	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return netip.Addr{}, fmt.Errorf("netutil: unexpected local address type %T", conn.LocalAddr())
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return netip.Addr{}, fmt.Errorf("netutil: cannot parse local address %v", local.IP)
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("netutil: route to %s resolves to non-IPv4 %s", target, addr)
	}
	return addr, nil
}
