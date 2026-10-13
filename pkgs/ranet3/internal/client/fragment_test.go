// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// babelGroup is the address every Babel speaker listens on, RFC 8966 section 4
var babelGroup = netip.MustParseAddr("ff02::1:6")

// udpPacket is an IPv6 packet from src to dst carrying payload in UDP from port sport to dport
// with the checksum RFC 8200 section 8.1 makes mandatory, and a hop limit of 64
func udpPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	raw := make([]byte, 40+8+len(payload))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:], uint16(8+len(payload)))
	raw[6], raw[7] = 17, 64
	copy(raw[8:], src.AsSlice())
	copy(raw[24:], dst.AsSlice())
	udp := raw[40:]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	length := binary.BigEndian.AppendUint16(nil, uint16(len(udp)))
	pseudo := slices.Concat(raw[8:40], []byte{0, 0}, length, []byte{0, 0, 0, 17})
	checksum := ^uint16(packet.Sum(packet.Sum(0, pseudo), udp))
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:], checksum)
	return raw
}

// babelFrom is a Babel packet from src to the group of udp octets of UDP with its header, padded out with PadN
// it carries nothing a speaker acts on, so a neighbor's state stays as it was but for the address it heard the neighbor from
func babelFrom(src netip.Addr, udp int) []byte {
	var tlvs []babel.RawTLV
	for padding := udp - 8 - 4; padding > 0; {
		if padding == 1 {
			tlvs = append(tlvs, babel.RawTLV{Type: babel.TLVPad1})
			break
		}
		body := min(padding-2, 255)
		tlvs = append(tlvs, babel.RawTLV{Type: babel.TLVPadN, Body: make([]byte, body)})
		padding -= 2 + body
	}
	raw := udpPacket(src, babelGroup, babel.Port, babel.Port, babel.EncodePacket(tlvs))
	raw[7] = 1 // link-local multicast is never forwarded, RFC 8966 section 4
	return raw
}

// fragmentsOf cuts raw, an unfragmented IPv6 packet, into two fragments of identification id at offset at of its fragmentable part, as RFC 8200 section 4.5 cuts one
func fragmentsOf(raw []byte, id uint32, at int) [][]byte {
	var fragments [][]byte
	for _, part := range [][2]int{{0, at}, {at, len(raw) - 40}} {
		f := slices.Concat(raw[:40], make([]byte, 8), raw[40+part[0]:40+part[1]])
		binary.BigEndian.PutUint16(f[4:], uint16(8+part[1]-part[0]))
		f[6], f[40] = 44, raw[6]
		field := uint16(part[0])
		if part[1] < len(raw)-40 {
			field |= 1
		}
		binary.BigEndian.PutUint16(f[42:], field)
		binary.BigEndian.PutUint32(f[44:], id)
		fragments = append(fragments, f)
	}
	return fragments
}

// the metrics name each neighbor whose session sent a Babel packet in fragments, how large the largest was once whole, and the datagrams dropped and why
// a neighbor that sent none has no samples
func TestMetricsNameTheNeighborsThatSendBabelPacketsInFragments(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := babel.New(babel.Config{}, babel.Routes{}, babel.Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peers := make(map[string]*netstack.Peer)
	for _, id := range []string{"cutting", "whole"} {
		peers[id] = netstack.NewPeer(id, func(raw []byte, _ byte) ([]byte, error) { return raw, nil }, func([]byte) error { return nil })
		handle := speaker.AddPeer(peers[id])
		t.Cleanup(handle.Close)
	}
	raw := babelFrom(netip.MustParseAddr("fe80::2"), 1443)
	for _, f := range fragmentsOf(raw, 1, 1336) {
		speaker.Receive(peers["cutting"], f)
	}
	// a second datagram whose last fragment overlaps its first
	speaker.Receive(peers["cutting"], fragmentsOf(raw, 2, 1336)[0])
	speaker.Receive(peers["cutting"], fragmentsOf(raw, 2, 8)[1])
	speaker.Receive(peers["whole"], babelFrom(netip.MustParseAddr("fe80::3"), 1443))

	c := &Client{speaker: speaker, sessions: newSessionSet(), Mesh: mesh}
	var out bytes.Buffer
	c.Metrics(&out)
	var got []string
	for line := range strings.Lines(out.String()) {
		if strings.Contains(line, "_babel_reassembl") {
			got = append(got, strings.TrimSuffix(line, "\n"))
		}
	}
	want := []string{
		"# HELP ranet3_babel_reassembled_total Babel packets a neighbor's session sent in fragments that this node put back together and read.",
		"# TYPE ranet3_babel_reassembled_total counter",
		`ranet3_babel_reassembled_total{peer="cutting"} 1`,
		"# HELP ranet3_babel_reassembled_largest_bytes The largest of them, a whole IPv6 packet with its headers.",
		"# TYPE ranet3_babel_reassembled_largest_bytes gauge",
		`ranet3_babel_reassembled_largest_bytes{peer="cutting"} 1483`,
		"# HELP ranet3_babel_reassembly_dropped_total Babel packets a neighbor's session sent in fragments that this node dropped rather than read, by reason: a fragment overlapping another, a first fragment without the UDP header, a malformed fragment, a datagram still incomplete after its time, one that gave its place or its storage to another of the same neighbor, or one refused while the neighbor's other datagrams, all younger than 1 second, held every place or the storage it needed.",
		"# TYPE ranet3_babel_reassembly_dropped_total counter",
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="overlap"} 1`,
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="header"} 0`,
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="malformed"} 0`,
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="timeout"} 0`,
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="evicted"} 0`,
		`ranet3_babel_reassembly_dropped_total{peer="cutting",reason="refused"} 0`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("the reassembly series read\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
