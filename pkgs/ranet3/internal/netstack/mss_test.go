// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// tcpPacket is one whole IP packet carrying a TCP header with flags, options and a payload of payload bytes, its checksum valid
// field is IPv4's flags and fragment offset, and extension puts a destination options header in front of TCP under IPv6
// offset, when not zero, is the data offset written in place of the one the options take
func tcpPacket(family int, field uint16, extension bool, flags byte, options []byte, offset byte, payload int) []byte {
	ipHeader := 20
	if family == 6 {
		ipHeader = 40
		if extension {
			ipHeader += 8
		}
	}
	tcp := make([]byte, tcpHeaderLen+len(options)+payload)
	binary.BigEndian.PutUint16(tcp[0:], 40000)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	binary.BigEndian.PutUint32(tcp[4:], 0x01020304)
	if offset == 0 {
		offset = byte((tcpHeaderLen + len(options)) / 4)
	}
	tcp[12] = offset << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	copy(tcp[tcpHeaderLen:], options)
	for i := tcpHeaderLen + len(options); i < len(tcp); i++ {
		tcp[i] = byte(i * 7)
	}
	raw := make([]byte, ipHeader+len(tcp))
	if family == 4 {
		raw[0] = 0x45
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		binary.BigEndian.PutUint16(raw[6:], field)
		raw[8], raw[9] = 64, tcpProtocol
		copy(raw[12:], []byte{10, 1, 0, 1, 10, 2, 0, 9})
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
	} else {
		raw[0] = 0x60
		binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-40))
		raw[6], raw[7] = tcpProtocol, 64
		copy(raw[8:], tooBigSource[6].AsSlice())
		copy(raw[24:], tooBigDestination[6].AsSlice())
		if extension {
			raw[6] = 60
			raw[40] = tcpProtocol
			raw[42], raw[43] = 1, 4
		}
	}
	copy(raw[ipHeader:], tcp)
	binary.BigEndian.PutUint16(raw[ipHeader+tcpChecksum:], tcpSum(raw, ipHeader))
	return raw
}

// tcpSum is the checksum of the TCP segment at offset in raw, computed afresh over RFC 9293's pseudo-header with the field itself as zero
func tcpSum(raw []byte, offset int) uint16 {
	segment := bytes.Clone(raw[offset:])
	binary.BigEndian.PutUint16(segment[tcpChecksum:], 0)
	var pseudo []byte
	if raw[0]>>4 == 4 {
		pseudo = append(bytes.Clone(raw[12:20]), 0, tcpProtocol, byte(len(segment)>>8), byte(len(segment)))
	} else {
		pseudo = append(bytes.Clone(raw[8:40]), binary.BigEndian.AppendUint32(nil, uint32(len(segment)))...)
		pseudo = append(pseudo, 0, 0, 0, tcpProtocol)
	}
	return ^uint16(packet.Sum(packet.Sum(0, pseudo), segment))
}

// a SYN read off the tun has its MSS clamped to what its peer's session carries, less the IP and TCP headers
// and a steered one inside the header steering put on it, against the session less that header too
func TestReaderClampsTheMSSOfASYNToItsSession(t *testing.T) {
	const session = 1300
	for _, family := range []int{4, 6} {
		for segments := range 3 {
			steering := steerBothFrom(t, segments)
			syn := tcpPacket(family, 0, false, synFlag, []byte{optionMSS, mssLen, 0x05, 0xb4}, 0, 0)
			b, peer, _ := readOff(t, syn, steering, session)
			if b.peers[0] != peer {
				t.Fatalf("an IPv%d SYN under %d segments did not go to its peer", family, segments)
			}
			inner := b.packets[0][steering.Overhead():]
			offset := 20
			if family == 6 {
				offset = 40
			}
			want := session - steering.Overhead() - offset - tcpHeaderLen
			if got := int(binary.BigEndian.Uint16(inner[offset+tcpHeaderLen+2:])); got != want {
				t.Errorf("an IPv%d SYN under %d segments carries an MSS of %d, want %d", family, segments, got, want)
			}
			if got, want := binary.BigEndian.Uint16(inner[offset+tcpChecksum:]), tcpSum(inner, offset); got != want {
				t.Errorf("an IPv%d SYN under %d segments carries the checksum %#04x, want %#04x", family, segments, got, want)
			}
		}
	}
}

// a read off the tun counts each SYN whose MSS it lowers, and none whose MSS already fits the session
func TestReaderCountsTheSYNsItClamps(t *testing.T) {
	const session = 1300
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	m.startSegmentReports()
	peer := (&recordingPeer{}).peer(t, "peer")
	peer.SetMTU(session)
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), peer)
	var syns [][]byte
	for _, family := range []int{4, 6} {
		for _, mss := range []uint16{1460, 536} {
			syns = append(syns, tcpPacket(family, 0, false, synFlag, binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, mss), 0, 0))
		}
	}
	b := newOutboundBatch(len(syns))
	fill(b, syns...)
	m.classify(b)
	if got := m.MSSClamped(); got != 2 {
		t.Errorf("a read of four SYNs, two offering more than a %d byte session takes, counted %d clamps, want 2", session, got)
	}
}

// a SYN or SYN-ACK that an End.DT46 of this node takes out of its outer header reaches the tun with its MSS lowered to what the session it came through carries
// less the IP and TCP headers, its checksum updated with it
// the session's own clamp sees only the outer IPv6 packet, which would let the MSS the headend left for its own sessions reach the far end
// and a delivery for no session, as the headend's own answers are, leaves the MSS as it came
func TestExitClampsTheMSSOfASYNToTheSessionItArrivedThrough(t *testing.T) {
	const session, offered = 1300, 8800
	exit := segAddr("3fff:1:69c:8c6::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []int{4, 6} {
		header := 20
		if family == 6 {
			header = 40
		}
		// ACK is the flag at 0x10, RFC 9293 section 3.1
		for _, flags := range []byte{synFlag, synFlag | 0x10} {
			for _, mtu := range []int{session, 0} {
				inner := tcpPacket(family, 0, false, flags, binary.BigEndian.AppendUint16([]byte{optionMSS, mssLen}, offered), 0, 0)
				outer, err := srv6.Encapsulate(inner, segAddr("3fff:1:69c:98d0::1"), []netip.Addr{exit})
				if err != nil {
					t.Fatal(err)
				}
				dev := &recordingDevice{writes: make(chan recordedWrite, 1)}
				m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
				m.setDevice(dev)
				m.SetSegments(table)
				m.DeliverInboundBatch(framed(outer), mtu)
				want, clamps := bytes.Clone(inner), uint64(0)
				if mtu != 0 {
					binary.BigEndian.PutUint16(want[header+tcpHeaderLen+2:], uint16(mtu-header-tcpHeaderLen))
					binary.BigEndian.PutUint16(want[header+tcpChecksum:], tcpSum(want, header))
					clamps = 1
				}
				if got := m.MSSClamped(); got != clamps {
					t.Errorf("an IPv%d packet flagged %#02x through a %d byte session counted %d clamps, want %d", family, flags, mtu, got, clamps)
				}
				// one device is written to before the delivery returns
				select {
				case write := <-dev.writes:
					if len(write.packets) != 1 || !bytes.Equal(write.packets[0], want) {
						t.Errorf("an IPv%d packet flagged %#02x offering %d through a %d byte session reached the tun as %x, want %x", family, flags, offered, mtu, write.packets, want)
					}
				default:
					t.Errorf("an IPv%d packet flagged %#02x steered to the exit never reached the tun", family, flags)
				}
			}
		}
	}
}
