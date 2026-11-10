// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
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
		r.verdict()
		return
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Errorf("the SYN to %s got %v after %s, want no answer within %s", to, err, took, unsolicitedWait)
	}
	r.verdict()
}

// portRanges is RFC 4787 REQ-3 toward one server endpoint and REQ-3a: the
// leaf's datagram and one from another address of the overlay, from one port
// to one server endpoint, are read from two endpoints, since one endpoint for
// both is REQ-3's port overloading, from ports below 1024 where they left from
// port 500, and from ports of 1024 or above where they left from port 40000,
// REQ-3a's ranges. The other address is one no node holds, so row 6's spare
// holds nothing more. Where the arm declares NoLowPorts, every datagram is read
// from a port of 1024 or above. Toward two destinations, REQ-3's port
// overloading is portClash's.
func (r *rows) portRanges(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, rangesPort)
	server := r.listenUDP(t, to)
	other := r.unheld()
	declared, high := r.limits[NoLowPorts]
	if high {
		t.Logf("declared in %s: %s", declared.Row, declared.Reason)
	}
	for _, port := range []uint16{lowRangePort, highRangePort} {
		var first netip.AddrPort
		for _, source := range []netip.Addr{r.family.Leaf, other} {
			from := netip.AddrPortFrom(source, port)
			data := []byte(fmt.Sprintf("from %s over %s", from, r.family.Name))
			sent := datagram(from, to, leafTTL, data)
			read := receiveFrom(t, udpReader(server), data, func() { r.exit.hand([][]byte{sent}) })
			if read.Addr() != r.seen() || (read.Port() < 1024) != (port < 1024 && !high) {
				t.Errorf("the server read the datagram from %s from %s, want a port of its range on %s", from, read, r.seen())
			}
			if read == first {
				t.Errorf("the server read the datagrams from the leaf's and from %s, both from port %d toward one server, from one endpoint %s, the port overloading RFC 4787 REQ-3 rules out", other, port, read)
			}
			first = read
		}
	}
	r.verdict()
}

// portClash is one port of two inside endpoints, in UDP and in TCP: the leaf's
// flow from the port to the server, then another inside endpoint's from the
// same port to the second server, then the leaf's from the port to the second
// server, each flow's mapping held while the next is made. The first two are
// read from two endpoints, since port overloading is ruled out, and the third
// from the first's endpoint, since a mapping that changes is. Where the arm
// declares the protocol's overloading, the first two are read from one
// endpoint, and where it declares its remap, the third from another than the
// first's.
func (r *rows) portClash(t *testing.T) {
	t.Run("udp", r.udpClash)
	t.Run("tcp", r.tcpClash)
	r.verdict()
}

// udpClash is portClash in UDP, RFC 4787 REQ-3, REQ-1 and REQ-11, the other
// inside endpoint an address of the overlay that no node holds
func (r *rows) udpClash(t *testing.T) {
	first, second := netip.AddrPortFrom(r.family.Server, clashPort), netip.AddrPortFrom(r.family.Second, clashPort)
	servers := map[netip.AddrPort]*net.UDPConn{first: r.listenUDP(t, first), second: r.listenUDP(t, second)}
	leaf, other := netip.AddrPortFrom(r.family.Leaf, leafClashPort), netip.AddrPortFrom(r.unheld(), leafClashPort)
	read := func(from, to netip.AddrPort) netip.AddrPort {
		data := []byte(fmt.Sprintf("from %s to %s over %s", from, to, r.family.Name))
		sent := datagram(from, to, leafTTL, data)
		got := receiveFrom(t, udpReader(servers[to]), data, func() { r.exit.hand([][]byte{sent}) })
		if got.Addr() != r.seen() {
			t.Errorf("%s read the datagram from %s from %s, want %s", to, from, got, r.seen())
		}
		return got
	}
	r.clash(t, [3]netip.AddrPort{read(leaf, first), read(other, second), read(leaf, second)}, other.Addr(),
		clashRule{OverloadsPorts, "RFC 4787 REQ-3 rules out", RemapsOnClash, "RFC 4787 REQ-1 and REQ-11 rule out"})
}

// tcpClash is portClash in TCP, RFC 5382 REQ-7 and REQ-1, the other inside
// endpoint the spare address, each connection open until the step ends
func (r *rows) tcpClash(t *testing.T) {
	first, second := netip.AddrPortFrom(r.family.Server, clashPort), netip.AddrPortFrom(r.family.Second, clashPort)
	listeners := map[netip.AddrPort]*net.TCPListener{first: listen(t, r.network.Server, first), second: listen(t, r.network.Server, second)}
	leaf, other := netip.AddrPortFrom(r.family.Leaf, leafClashPort), netip.AddrPortFrom(r.family.Spare, leafClashPort)
	read := func(from, to netip.AddrPort) netip.AddrPort {
		_, server := r.connect(t, listeners[to], to, from)
		return addrPort(server.RemoteAddr())
	}
	r.clash(t, [3]netip.AddrPort{read(leaf, first), read(other, second), read(leaf, second)}, other.Addr(),
		clashRule{OverloadsTCPPorts, "RFC 5382 REQ-7 rules out", RemapsTCPOnClash, "RFC 5382 REQ-1 rules out"})
}

// clashRule is the limits that declare a protocol's departures in portClash,
// and the requirements that rule each out, as a failure names them
type clashRule struct {
	overloads   Limit
	overloading string
	remaps      Limit
	remapping   string
}

// clash holds the endpoints the servers read portClash's three flows from,
// other's the second, to rule as the arm declares its limits
func (r *rows) clash(t *testing.T, flows [3]netip.AddrPort, other netip.Addr, rule clashRule) {
	t.Helper()
	opened, shared, moved := flows[0], flows[1], flows[2]
	if declared, overloads := r.limits[rule.overloads]; overloads {
		t.Logf("declared in %s: %s", declared.Row, declared.Reason)
		if shared != opened {
			t.Errorf("the servers read the leaf's port from %s and %s's from %s, want one endpoint, as the arm declares", opened, other, shared)
		}
	} else if shared == opened {
		t.Errorf("the servers read the leaf's port and %s's from one endpoint %s, the port overloading %s", other, opened, rule.overloading)
	}
	if declared, remaps := r.limits[rule.remaps]; remaps {
		t.Logf("declared in %s: %s", declared.Row, declared.Reason)
		if moved == opened {
			t.Errorf("once %s held the port toward the second server the leaf's port reached it from %s, its endpoint toward the server, want another, as the arm declares", other, moved)
		}
	} else if moved != opened {
		t.Errorf("once %s held the port toward the second server the leaf's port reached it from %s and the server from %s, the changed mapping %s", other, moved, opened, rule.remapping)
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
	r.verdict()
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
	r.verdict()
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
// way. A backend that terminates carries its own connection to the server,
// whose next sequence number the server's side reads off the wire, and the
// error quoting it reaches the host's connection and never the leaf, so the
// row holds that connection and the leaf's to carrying data each way after it.
func (r *rows) errorKeepsTCP(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, keepsTCPPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafKeepsTCPPort)
	mark := r.exit.handedCount()
	leaf, server := r.connect(t, listen(t, r.network.Server, to), to, local)
	var wire *net.IPConn
	if r.terminates {
		wire = r.serverIP(t, syscall.IPPROTO_TCP, r.family.Server)
	}
	opened := []byte("opens the connection over " + r.family.Name)
	write(t, leaf, opened)
	readFull(t, server, opened)
	mapping := addrPort(server.RemoteAddr())
	seq, ack, ok := nextSequence(r.exit.handedSince(mark), local, to)
	if r.terminates {
		seq, ack, ok = wireSequence(ipReader(wire), mapping, to, opened)
	}
	if !ok {
		t.Fatalf("no segment from %s to %s carried the data the connection opened with", local, to)
	}
	protocol := syscall.IPPROTO_ICMP
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	icmp := r.serverIP(t, protocol, r.family.Server)
	// ACK, the flag a segment of an established connection carries
	exceeded := icmpError(r.family.Server, mapping.Addr(), hopExceeded, segment(mapping, to, seq, ack, 0x10, nil))
	if r.terminates {
		if _, err := icmp.WriteToIP(exceeded[headerLength(exceeded):], &net.IPAddr{IP: mapping.Addr().AsSlice()}); err != nil {
			t.Fatalf("send the time exceeded to %s: %v", mapping.Addr(), err)
		}
		// within which the host's stack has taken the error and an exit
		// watching its connection's errors would have reset the leaf
		time.Sleep(quietPeriod)
		r.carriesBothWays(t, leaf, server)
		return
	}
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
	r.carriesBothWays(t, leaf, server)
}

// carriesBothWays holds a connection to carrying data each way after the time
// exceeded
func (r *rows) carriesBothWays(t *testing.T, leaf, server *net.TCPConn) {
	t.Helper()
	after := []byte("after the time exceeded over " + r.family.Name)
	write(t, server, after)
	readFull(t, leaf, after)
	write(t, leaf, after)
	readFull(t, server, after)
}

// wireSequence is the sequence number the next segment from from to to takes
// and the acknowledgment it carries, read off the wire from the segment that
// carried data
func wireSequence(read reader, from, to netip.AddrPort, data []byte) (seq, ack uint32, ok bool) {
	buf := make([]byte, readSize)
	for by := time.Now().Add(stepBudget); ; {
		n, source, err := read(buf, by)
		if err != nil {
			return 0, 0, false
		}
		segment := buf[:n]
		if source.Addr() != from.Addr() || n < 20 || binary.BigEndian.Uint16(segment) != from.Port() || binary.BigEndian.Uint16(segment[2:]) != to.Port() {
			continue
		}
		offset := transportLength(parsed{protocol: syscall.IPPROTO_TCP, payload: segment})
		if offset > n || !bytes.Equal(segment[offset:], data) {
			continue
		}
		return binary.BigEndian.Uint32(segment[4:]) + uint32(len(data)), binary.BigEndian.Uint32(segment[8:]), true
	}
}
