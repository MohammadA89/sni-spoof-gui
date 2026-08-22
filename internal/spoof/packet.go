package spoof

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// TCP header flag bits.
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
)

const (
	ipv4HeaderLen = 20
	tcpHeaderLen  = 20 // no options; every packet we build is optionless
	protoTCP      = 6
)

// TCPPacket is the subset of an IPv4+TCP packet this package reads or writes.
// Options are deliberately not modelled: we only ever parse handshake packets
// for their sequence numbers, and the packets we build carry no options.
type TCPPacket struct {
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	Seq, Ack         uint32
	Flags            uint8
	Window           uint16
	TTL              uint8
	IPID             uint16
	Payload          []byte
}

func (p *TCPPacket) Has(f uint8) bool { return p.Flags&f != 0 }

// IsSYN reports whether this is a bare SYN (the client's first handshake packet).
func (p *TCPPacket) IsSYN() bool {
	return p.Has(FlagSYN) && !p.Has(FlagACK) && !p.Has(FlagRST) && !p.Has(FlagFIN)
}

// IsSYNACK reports whether this is the server's SYN-ACK.
func (p *TCPPacket) IsSYNACK() bool {
	return p.Has(FlagSYN) && p.Has(FlagACK) && !p.Has(FlagRST) && !p.Has(FlagFIN)
}

// ParseIPv4TCP decodes an IPv4 TCP packet as delivered by WinDivert. The
// returned Payload aliases b; callers that retain it must copy first.
func ParseIPv4TCP(b []byte) (*TCPPacket, error) {
	if len(b) < ipv4HeaderLen {
		return nil, fmt.Errorf("spoof: packet is %d bytes, too short for an IPv4 header", len(b))
	}
	if v := b[0] >> 4; v != 4 {
		return nil, fmt.Errorf("spoof: IP version %d, want 4", v)
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipv4HeaderLen || len(b) < ihl {
		return nil, fmt.Errorf("spoof: bad IPv4 header length %d", ihl)
	}
	if b[9] != protoTCP {
		return nil, fmt.Errorf("spoof: IP protocol %d, want TCP", b[9])
	}

	// Trust the IP total length over the buffer length: WinDivert may hand us a
	// buffer with trailing slack.
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total < ihl || total > len(b) {
		total = len(b)
	}

	tcp := b[ihl:total]
	if len(tcp) < tcpHeaderLen {
		return nil, fmt.Errorf("spoof: TCP segment is %d bytes, too short for a header", len(tcp))
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < tcpHeaderLen || dataOff > len(tcp) {
		return nil, fmt.Errorf("spoof: bad TCP data offset %d", dataOff)
	}

	return &TCPPacket{
		SrcIP:   netip.AddrFrom4([4]byte(b[12:16])),
		DstIP:   netip.AddrFrom4([4]byte(b[16:20])),
		SrcPort: binary.BigEndian.Uint16(tcp[0:2]),
		DstPort: binary.BigEndian.Uint16(tcp[2:4]),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Ack:     binary.BigEndian.Uint32(tcp[8:12]),
		Flags:   tcp[13],
		Window:  binary.BigEndian.Uint16(tcp[14:16]),
		TTL:     b[8],
		IPID:    binary.BigEndian.Uint16(b[4:6]),
		Payload: tcp[dataOff:],
	}, nil
}

// Marshal serialises the packet with both checksums computed. The result is
// ready to hand to WinDivert's Send.
func (p *TCPPacket) Marshal() ([]byte, error) {
	if !p.SrcIP.Is4() || !p.DstIP.Is4() {
		return nil, fmt.Errorf("spoof: Marshal needs IPv4 addresses, got %s -> %s", p.SrcIP, p.DstIP)
	}
	total := ipv4HeaderLen + tcpHeaderLen + len(p.Payload)
	if total > 0xffff {
		return nil, fmt.Errorf("spoof: packet would be %d bytes, exceeds IPv4 maximum", total)
	}
	b := make([]byte, total)

	src, dst := p.SrcIP.As4(), p.DstIP.As4()

	// IPv4 header.
	b[0] = 4<<4 | ipv4HeaderLen/4
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	binary.BigEndian.PutUint16(b[4:6], p.IPID)
	b[6] = 0x40 // Don't Fragment, matching what Windows emits
	b[8] = p.TTL
	b[9] = protoTCP
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[10:12], onesComplement(b[:ipv4HeaderLen], 0))

	// TCP header.
	tcp := b[ipv4HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], p.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], p.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], p.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], p.Ack)
	tcp[12] = tcpHeaderLen / 4 << 4
	tcp[13] = p.Flags
	binary.BigEndian.PutUint16(tcp[14:16], p.Window)
	copy(tcp[tcpHeaderLen:], p.Payload)

	// TCP checksum covers a pseudo-header of src, dst, protocol and length.
	var pseudo uint32
	pseudo += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
	pseudo += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
	pseudo += uint32(protoTCP) + uint32(len(tcp))
	binary.BigEndian.PutUint16(tcp[16:18], onesComplement(tcp, pseudo))

	return b, nil
}

// onesComplement computes the internet checksum (RFC 1071) over b, folding in
// an already-accumulated initial sum.
func onesComplement(b []byte, initial uint32) uint16 {
	sum := initial
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
