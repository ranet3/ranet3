// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/packet"
)

// unsolicitedSYN is RFC 5382 REQ-4: a SYN from the server's side to the exit's
// uplink address at a port no mapping holds is answered by nothing for
// unsolicitedWait. Where the arm declares ResetsUnsolicitedSYN, it is reset at
// once.
func (r *rows) unsolicitedSYN(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Uplink, unsolicitedPort)
	declared, limited := r.limits[ResetsUnsolicitedSYN]
	began := time.Now()
	conn, err := tryDial(r.network.Server, netip.AddrPort{}, to, unsolicitedWait)
	took := time.Since(began)
	if conn != nil {
		_ = conn.Close()
	}
	if limited {
		t.Logf("declared in %s: %s", declared.Row, declared.Reason)
		if !errors.Is(err, syscall.ECONNREFUSED) || took > quietPeriod {
			t.Errorf("the SYN to %s got %v after %s, want a reset within %s", to, err, took, quietPeriod)
		}
		return
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("the SYN to %s got %v after %s, want no answer within %s", to, err, took, unsolicitedWait)
	}
}

// portRanges is RFC 4787 REQ-3 and REQ-3a: the leaf's datagram and one from
// another address of the overlay, from one port to one server endpoint, are
// read from two endpoints, since REQ-3 rules out port overloading, from ports
// below 1024 where they left from port 500, and from ports of 1024 or above
// where they left from port 40000. The other address is one no node holds, so
// row 6's spare holds nothing more.
func (r *rows) portRanges(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, rangesPort)
	server := r.listenUDP(t, to)
	other := r.unheld()
	for _, port := range []uint16{lowRangePort, highRangePort} {
		var first netip.AddrPort
		for _, source := range []netip.Addr{r.family.Leaf, other} {
			from := netip.AddrPortFrom(source, port)
			data := []byte(fmt.Sprintf("from %s over %s", from, r.family.Name))
			sent := datagram(from, to, leafTTL, data)
			read := receiveFrom(t, udpReader(server), data, func() { r.exit.hand([][]byte{sent}) })
			if read.Addr() != r.seen() || (read.Port() < 1024) != (port < 1024) {
				t.Errorf("the server read the datagram from %s from %s, want a port of its range on %s", from, read, r.seen())
			}
			if read == first {
				t.Errorf("the server read the datagrams from the leaf's and from %s, both from port %d, from one endpoint %s, the port overloading RFC 4787 REQ-3 rules out", other, port, read)
			}
			first = read
		}
	}
}

// unheld is an address of the overlay that neither the leaf, the spare nor
// the exit holds
func (r *rows) unheld() netip.Addr {
	for a := r.family.Overlay.Addr().Next(); r.family.Overlay.Contains(a); a = a.Next() {
		if a != r.family.Leaf && a != r.family.Spare && !slices.Contains(r.family.Exit, a) {
			return a
		}
	}
	panic("the overlay holds no address but the leaf's, the spare's and the exit's")
}

// fragments is RFC 4787 REQ-14: a datagram cut into three fragments, handed
// last first, reaches the server whole from the class's address
func (r *rows) fragments(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, fragmentsPort)
	server := r.listenUDP(t, to)
	data := make([]byte, 3*fragmentSize-8)
	copy(data, "cut in three over "+r.family.Name)
	sent := fragment(datagram(netip.AddrPortFrom(r.family.Leaf, leafFragmentsPort), to, leafTTL, data))
	slices.Reverse(sent)
	if from := receiveFrom(t, udpReader(server), data, func() { r.exit.hand(sent) }); from.Addr() != r.seen() {
		t.Errorf("the server read the fragmented datagram from %s, want %s", from, r.seen())
	}
}

// fragment cuts raw, whose transport part is a whole number of fragmentSize,
// into fragments of fragmentSize, RFC 791 section 3.2 in IPv4 and RFC 8200
// section 4.5 in IPv6, under one identification
func fragment(raw []byte) [][]byte {
	length := headerLength(raw)
	header, rest := raw[:length], raw[length:]
	v4 := raw[0]>>4 == 4
	var out [][]byte
	for offset := 0; offset < len(rest); offset += fragmentSize {
		part := rest[offset : offset+fragmentSize]
		more := offset+fragmentSize < len(rest)
		if v4 {
			f := append(slices.Clone(header), part...)
			binary.BigEndian.PutUint16(f[2:], uint16(len(f)))
			binary.BigEndian.PutUint16(f[4:], fragmentID)
			flags := uint16(offset / 8)
			if more {
				// MF, the third bit of the flags
				flags |= 0x2000
			}
			binary.BigEndian.PutUint16(f[6:], flags)
			f[10], f[11] = 0, 0
			binary.BigEndian.PutUint16(f[10:], ^uint16(packet.Sum(0, f[:length])))
			out = append(out, f)
			continue
		}
		f := slices.Clone(header)
		next := f[6]
		f[6] = syscall.IPPROTO_FRAGMENT
		field := uint16(offset)
		if more {
			// M, the low bit of the offset's word
			field |= 1
		}
		f = append(f, next, 0)
		f = binary.BigEndian.AppendUint16(f, field)
		f = binary.BigEndian.AppendUint32(f, fragmentID)
		f = append(f, part...)
		binary.BigEndian.PutUint16(f[4:], uint16(len(f)-length))
		out = append(out, f)
	}
	return out
}

// errorKeepsMapping is RFC 4787 REQ-12 in UDP and RFC 5382 REQ-10 in TCP: an
// ICMP error about a flow ends neither the flow nor its mapping
func (r *rows) errorKeepsMapping(t *testing.T) {
	t.Run("udp", r.errorKeepsUDP)
	t.Run("tcp", r.errorKeepsTCP)
}

// errorKeepsUDP is REQ-12's leg: the leaf's socket opens a mapping toward the
// server, and its datagram to a port of the server's nothing listens on draws
// the server's port unreachable through the exit. The server, listening there
// once it came, sends to the mapping first, and the leaf reads that datagram,
// which only the flow the error was about carries, before the socket's next
// datagram reaches the server from the same mapping.
func (r *rows) errorKeepsUDP(t *testing.T) {
	from := netip.AddrPortFrom(r.family.Leaf, leafKeepsPort)
	leaf := r.bindUDP(t, from)
	opened := netip.AddrPortFrom(r.family.Server, keepsPort)
	data := []byte("opens the mapping over " + r.family.Name)
	mapping := receiveFrom(t, udpReader(r.listenUDP(t, opened)), data, func() { _, _ = leaf.WriteToUDPAddrPort(data, opened) })

	closed := netip.AddrPortFrom(r.family.Server, keepsClosedPort)
	refused := []byte("to the closed port over " + r.family.Name)
	quoted := datagram(from, closed, leafTTL, refused)
	if !r.await(func() { _, _ = leaf.WriteToUDPAddrPort(refused, closed) }, func(packet []byte) bool {
		a, ok := readAnswer(packet)
		return ok && a.from == r.family.Server && a.is(r.v6(), portUnreachable) && quotes(a.quote, quoted)
	}) {
		t.Fatalf("no port unreachable from %s quoting the leaf's datagram came back within %s", r.family.Server, stepBudget)
	}
	server := r.listenUDP(t, closed)
	first := []byte("from the closed port after its port unreachable over " + r.family.Name)
	if got := receiveFrom(t, udpReader(leaf), first, func() { _, _ = server.WriteToUDPAddrPort(first, mapping) }); got != closed {
		t.Errorf("the leaf read the server's datagram to its mapping %s from %s, want %s", mapping, got, closed)
	}
	after := []byte("after the port unreachable over " + r.family.Name)
	if again := receiveFrom(t, udpReader(server), after, func() { _, _ = leaf.WriteToUDPAddrPort(after, closed) }); again != mapping {
		t.Errorf("after the port unreachable the server read the leaf's socket from %s, want its mapping %s", again, mapping)
	}
}

// errorKeepsTCP is REQ-10's leg: the leaf connects to the server, and the
// server's side sends the connection's mapping a time exceeded quoting the
// leaf's next segment as it leaves the exit. The error reaches the leaf, whose
// stack takes it as a soft error, and the connection then carries data each
// way.
func (r *rows) errorKeepsTCP(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, keepsTCPPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafKeepsTCPPort)
	mark := r.exit.handedCount()
	leaf, server := r.connect(t, listen(t, r.network.Server, to), to, local)
	opened := []byte("opens the connection over " + r.family.Name)
	write(t, leaf, opened)
	readFull(t, server, opened)
	seq, ack, ok := nextSequence(r.exit.handedSince(mark), local, to)
	if !ok {
		t.Fatalf("the leaf handed no segment from %s to %s", local, to)
	}
	mapping := addrPort(server.RemoteAddr())
	protocol := syscall.IPPROTO_ICMP
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	icmp := r.serverIP(t, protocol, r.family.Server)
	// ACK, the flag a segment of an established connection carries
	exceeded := icmpError(r.family.Server, mapping.Addr(), hopExceeded, segment(mapping, to, seq, ack, 0x10, nil))
	if !r.await(func() {
		_, _ = icmp.WriteToIP(exceeded[headerLength(exceeded):], &net.IPAddr{IP: mapping.Addr().AsSlice()})
	}, func(packet []byte) bool {
		a, ok := readAnswer(packet)
		q, inner := quoted(a.quote)
		return ok && inner && a.is(r.v6(), hopExceeded) && q.protocol == syscall.IPPROTO_TCP && q.src == local.Addr() && q.dst == to.Addr() &&
			len(q.payload) >= 4 && binary.BigEndian.Uint16(q.payload) == local.Port() && binary.BigEndian.Uint16(q.payload[2:]) == to.Port()
	}) {
		t.Fatalf("no time exceeded quoting the connection from %s to %s reached the leaf within %s", local, to, stepBudget)
	}
	after := []byte("after the time exceeded over " + r.family.Name)
	write(t, server, after)
	readFull(t, leaf, after)
	write(t, leaf, after)
	readFull(t, server, after)
}
