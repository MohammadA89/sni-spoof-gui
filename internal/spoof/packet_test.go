package spoof

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func samplePacket(payload []byte) *TCPPacket {
	return &TCPPacket{
		SrcIP:   netip.MustParseAddr("192.168.1.50"),
		DstIP:   netip.MustParseAddr("188.114.98.0"),
		SrcPort: 51234,
		DstPort: 443,
		Seq:     0xDEADBEEF,
		Ack:     0x12345678,
		Flags:   FlagPSH | FlagACK,
		Window:  64240,
		TTL:     128,
		IPID:    0xABCD,
		Payload: payload,
	}
}

func TestMarshalParseRoundTrip(t *testing.T) {
	want := samplePacket([]byte("hello spoofed world"))
	raw, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIPv4TCP(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.SrcIP != want.SrcIP || got.DstIP != want.DstIP {
		t.Errorf("addrs: got %s->%s, want %s->%s", got.SrcIP, got.DstIP, want.SrcIP, want.DstIP)
	}
	if got.SrcPort != want.SrcPort || got.DstPort != want.DstPort {
		t.Errorf("ports: got %d->%d, want %d->%d", got.SrcPort, got.DstPort, want.SrcPort, want.DstPort)
	}
	if got.Seq != want.Seq || got.Ack != want.Ack {
		t.Errorf("seq/ack: got %d/%d, want %d/%d", got.Seq, got.Ack, want.Seq, want.Ack)
	}
	if got.Flags != want.Flags || got.Window != want.Window || got.TTL != want.TTL || got.IPID != want.IPID {
		t.Errorf("header fields differ: got %+v", got)
	}
	if string(got.Payload) != string(want.Payload) {
		t.Errorf("payload: got %q, want %q", got.Payload, want.Payload)
	}
}

// A correct internet checksum makes the sum over the covered bytes fold to zero.
func TestMarshalChecksumsVerify(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("odd length!"), make([]byte, ClientHelloSize)} {
		raw, err := samplePacket(payload).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if s := onesComplement(raw[:ipv4HeaderLen], 0); s != 0 {
			t.Errorf("payload len %d: IPv4 checksum verifies to %#04x, want 0", len(payload), s)
		}

		tcp := raw[ipv4HeaderLen:]
		src, dst := raw[12:16], raw[16:20]
		var pseudo uint32
		pseudo += uint32(binary.BigEndian.Uint16(src[0:2])) + uint32(binary.BigEndian.Uint16(src[2:4]))
		pseudo += uint32(binary.BigEndian.Uint16(dst[0:2])) + uint32(binary.BigEndian.Uint16(dst[2:4]))
		pseudo += uint32(protoTCP) + uint32(len(tcp))
		if s := onesComplement(tcp, pseudo); s != 0 {
			t.Errorf("payload len %d: TCP checksum verifies to %#04x, want 0", len(payload), s)
		}
	}
}

func TestFlagPredicates(t *testing.T) {
	syn := &TCPPacket{Flags: FlagSYN}
	synack := &TCPPacket{Flags: FlagSYN | FlagACK}
	rst := &TCPPacket{Flags: FlagSYN | FlagRST}
	if !syn.IsSYN() || syn.IsSYNACK() {
		t.Error("bare SYN misclassified")
	}
	if !synack.IsSYNACK() || synack.IsSYN() {
		t.Error("SYN-ACK misclassified")
	}
	if rst.IsSYN() || rst.IsSYNACK() {
		t.Error("SYN+RST should be neither")
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	good, err := samplePacket([]byte("x")).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":   good[:10],
		"not ipv4":    append([]byte{6 << 4}, good[1:]...),
		"not tcp":     func() []byte { b := append([]byte(nil), good...); b[9] = 17; return b }(),
		"bad ihl":     func() []byte { b := append([]byte(nil), good...); b[0] = 4<<4 | 2; return b }(),
		"bad dataoff": func() []byte { b := append([]byte(nil), good...); b[ipv4HeaderLen+12] = 0x10; return b }(),
	}
	for name, b := range cases {
		if _, err := ParseIPv4TCP(b); err == nil {
			t.Errorf("%s: expected an error, got nil", name)
		}
	}
}
