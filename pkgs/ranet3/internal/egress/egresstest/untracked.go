// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// untracked holds that a packet out of the mesh no flow is tracked for, an
// extended echo request of RFC 8335 or a segment past a live connection's
// window, is dropped and counted under a class that translates and leaves
// from the leaf's own address under none.
func (r *rows) untracked(t *testing.T) {
	translated := r.class != None
	began := time.Now()
	r.exit.awaitStatus(t, "waiting for a pass after the step began", func(s egress.Status) bool { return s.PassAt.After(began) })
	before := r.dropped(r.exit.Status())

	protocol := syscall.IPPROTO_ICMP
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	icmp := r.serverIP(t, protocol, r.family.Server)
	data := []byte("an extended echo request over " + r.family.Name)
	r.exit.hand([][]byte{query(r.family.Leaf, r.family.Server, byte(ipv4.ICMPTypeExtendedEchoRequest), byte(ipv6.ICMPTypeExtendedEchoRequest), untrackedEchoID, data)})
	r.arrived(t, "the extended echo request", ipReader(icmp), func(message []byte) bool {
		return len(message) >= 8 && bytes.Equal(message[8:], data)
	}, translated)

	to := netip.AddrPortFrom(r.family.Server, untrackedPort)
	listener, tcp := r.listen(t, to), r.serverIP(t, syscall.IPPROTO_TCP, r.family.Server)
	mark := r.exit.handedCount()
	leaf, server := r.connect(t, listener, to, netip.AddrPort{})
	opened := []byte("opens the connection over " + r.family.Name)
	write(t, leaf, opened)
	readFull(t, server, opened)
	from := addrPort(leaf.LocalAddr())
	seq, ack, ok := nextSequence(r.exit.handedSince(mark), from, to)
	if !ok {
		t.Fatalf("the leaf handed no segment from %s to %s", from, to)
	}
	past := []byte("past the tracked window over " + r.family.Name)
	// ACK and PSH, a data segment's flags, 2^30 past the next sequence number,
	// beyond any window the connection advertises
	r.exit.hand([][]byte{segment(from, to, seq+1<<30, ack, 0x18, past)})
	r.arrived(t, "the segment past the tracked window", ipReader(tcp), func(received []byte) bool {
		offset := transportLength(parsed{protocol: syscall.IPPROTO_TCP, payload: received})
		return len(received) >= 20 && offset <= len(received) && bytes.Equal(received[offset:], past)
	}, translated)
	after := []byte("after the segment past the window over " + r.family.Name)
	write(t, leaf, after)
	readFull(t, server, after)

	want := before
	if translated {
		want += 2
	}
	r.awaitDropped(t, before, want)
}

// untrackedInto holds that a packet into the mesh under return no flow is
// tracked for, an extended echo request, a port unreachable about a datagram
// no flow carried or a segment past a live connection's window, is dropped and
// counted under every class, since the exit translates whatever enters the
// mesh. The server stands for a host behind the exit.
func (r *rows) untrackedInto(t *testing.T) {
	began := time.Now()
	r.exit.awaitStatus(t, "waiting for a pass after the step began", func(s egress.Status) bool { return s.PassAt.After(began) })
	before := r.dropped(r.exit.Status())
	back := len(r.network.Back())
	toLeaf := &net.IPAddr{IP: r.family.Leaf.AsSlice()}

	protocol := syscall.IPPROTO_ICMP
	if r.v6() {
		protocol = syscall.IPPROTO_ICMPV6
	}
	icmp := r.serverIP(t, protocol, r.family.Server)
	echoed := []byte("an extended echo request into the mesh over " + r.family.Name)
	request := query(r.family.Server, r.family.Leaf, byte(ipv4.ICMPTypeExtendedEchoRequest), byte(ipv6.ICMPTypeExtendedEchoRequest), intoUntrackedEchoID, echoed)
	quoted := []byte("a datagram no flow carried over " + r.family.Name)
	unmatched := icmpError(r.family.Server, r.family.Leaf, portUnreachable,
		datagram(netip.AddrPortFrom(r.family.Leaf, leafUnmatchedPort), netip.AddrPortFrom(r.family.Server, unmatchedPort), leafTTL, quoted))
	for _, sent := range [][]byte{request, unmatched} {
		if _, err := icmp.WriteToIP(sent[headerLength(sent):], toLeaf); err != nil {
			t.Fatalf("send from the server to %s: %v", r.family.Leaf, err)
		}
	}

	to := netip.AddrPortFrom(r.family.Leaf, intoUntrackedPort)
	listener := open(t, r.network.Leaf, "listen at the leaf's "+to.String(), func() (*net.TCPListener, error) {
		return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(to))
	})
	dialer := net.Dialer{Timeout: stepBudget, LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(r.family.Server, 0))}
	server := open(t, r.network.Server, "connect from the server to "+to.String(), func() (*net.TCPConn, error) {
		conn, err := dialer.Dial("tcp", to.String())
		if err != nil {
			return nil, err
		}
		return conn.(*net.TCPConn), nil
	})
	leaf := accept(t, listener)
	opened := []byte("opens the connection into the mesh over " + r.family.Name)
	write(t, server, opened)
	readFull(t, leaf, opened)
	from := addrPort(leaf.RemoteAddr())
	seq, ack, ok := nextSequence(r.network.Back()[back:], from, to)
	if !ok {
		t.Fatalf("no segment from %s to %s came into the mesh", from, to)
	}
	past := []byte("past the tracked window into the mesh over " + r.family.Name)
	beyond := segment(addrPort(server.LocalAddr()), to, seq+1<<30, ack, 0x18, past)
	if _, err := r.serverIP(t, syscall.IPPROTO_TCP, r.family.Server).WriteToIP(beyond[headerLength(beyond):], toLeaf); err != nil {
		t.Fatalf("send from the server to %s: %v", r.family.Leaf, err)
	}
	after := []byte("after the segment past the window into the mesh over " + r.family.Name)
	write(t, server, after)
	readFull(t, leaf, after)

	time.Sleep(quietPeriod)
	for _, packet := range r.network.Back()[back:] {
		p, ok := parse(packet)
		for what, data := range map[string][]byte{"the extended echo request": echoed, "the port unreachable": quoted, "the segment past the tracked window": past} {
			if ok && bytes.Contains(p.payload, data) {
				t.Errorf("%s came into the mesh from %s, where the exit translates what enters it", what, p.src)
			}
		}
	}
	r.awaitDropped(t, before, before+3)
}

// awaitDropped waits for a pass after now whose count of the family's packets
// dropped is want, before of them counted before the step
func (r *rows) awaitDropped(t *testing.T, before, want uint64) {
	t.Helper()
	sent := time.Now()
	for deadline := time.Now().Add(stepBudget); ; time.Sleep(pollInterval) {
		s := r.exit.Status()
		if s.PassAt.After(sent) && r.dropped(s) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Status counts %d packets dropped in %s, %d of them before the step, want %d", r.dropped(s), r.family.Name, before, want)
		}
	}
}

// arrived reads the server's packets of one protocol for one that match takes,
// a quiet period long where the class translates, since none may come, and
// fails the step unless it read none where the class translates and one from
// the leaf's own address where it does not
func (r *rows) arrived(t *testing.T, what string, read reader, match func(packet []byte) bool, translated bool) {
	t.Helper()
	wait := stepBudget
	if translated {
		wait = quietPeriod
	}
	buf := make([]byte, readSize)
	for by := time.Now().Add(wait); ; {
		n, from, err := read(buf, by)
		if err != nil {
			break
		}
		if !match(buf[:n]) {
			continue
		}
		switch {
		case translated:
			t.Errorf("the server read %s from %s, where a class that translates sends nothing out under the leaf's own address", what, from.Addr())
		case from.Addr() != r.family.Leaf:
			t.Errorf("the server read %s from %s, want the leaf's own address %s", what, from.Addr(), r.family.Leaf)
		}
		return
	}
	if !translated {
		t.Errorf("the server read no %s within %s, want it from the leaf's own address %s", what, wait, r.family.Leaf)
	}
}

// nextSequence is the sequence number the next segment from from to to takes
// and the acknowledgment it carries, from the last such segment of packets
func nextSequence(packets [][]byte, from, to netip.AddrPort) (seq, ack uint32, ok bool) {
	for _, packet := range packets {
		p, parsed := parse(packet)
		if !parsed || p.protocol != syscall.IPPROTO_TCP || p.src != from.Addr() || p.dst != to.Addr() || len(p.payload) < 20 ||
			binary.BigEndian.Uint16(p.payload) != from.Port() || binary.BigEndian.Uint16(p.payload[2:]) != to.Port() {
			continue
		}
		seq = binary.BigEndian.Uint32(p.payload[4:]) + uint32(len(p.payload)-transportLength(p))
		// a SYN and a FIN, the bits 0x02 and 0x01, each take a sequence number
		if p.payload[13]&0x03 != 0 {
			seq++
		}
		ack, ok = binary.BigEndian.Uint32(p.payload[8:]), true
	}
	return seq, ack, ok
}

// dropped is the family's count of packets dropped for want of a tracked flow in s
func (r *rows) dropped(s egress.Status) uint64 {
	if r.v6() {
		return s.Dropped6
	}
	return s.Dropped4
}
