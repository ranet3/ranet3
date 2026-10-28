// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
	"time"
)

// filtering is RFC 4787 REQ-8. The leaf's datagram to the server opens a
// mapping, and the server sends to it from another port, which endpoint
// independent and address dependent filtering both carry to the leaf. Where
// the arm declares PortDependentFiltering, neither that datagram nor one from
// another address of the server's side reaches the leaf, and the exit's own
// stack refuses each, as a host with no socket at the mapping's port does.
func (r *rows) filtering(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, filteringPort)
	server := r.listenUDP(t, to)
	leaf := r.bindUDP(t, netip.AddrPortFrom(r.family.Leaf, leafFilteringPort))
	opened := []byte("opens the mapping over " + r.family.Name)
	mapping := receiveFrom(t, udpReader(server), opened, func() { _, _ = leaf.WriteToUDPAddrPort(opened, to) })
	otherPort := netip.AddrPortFrom(r.family.Server, filteringOtherPort)
	declared, limited := r.limits[PortDependentFiltering]
	if !limited {
		stranger := r.dialFromServer(t, otherPort, mapping)
		sent := []byte("from another port of the server's over " + r.family.Name)
		if from := receiveFrom(t, udpReader(leaf), sent, func() { _, _ = stranger.Write(sent) }); from != otherPort {
			t.Errorf("the leaf read the datagram to its mapping from %s, want %s", from, otherPort)
		}
		return
	}
	t.Logf("declared in %s: %s", declared.Row, declared.Reason)
	for _, from := range []netip.AddrPort{otherPort, netip.AddrPortFrom(r.family.Second, filteringPort)} {
		stranger := r.dialFromServer(t, from, mapping)
		sent := []byte("from " + from.String() + " over " + r.family.Name)
		if !refusedOn(t, stranger, sent) {
			t.Errorf("the datagram from %s to the leaf's mapping %s was not refused within %s", from, mapping, stepBudget)
		}
		if got, ok := readOnce(leaf, sent, quietPeriod); ok {
			t.Errorf("the leaf read the datagram from %s to its mapping from %s, which the arm declares it does not carry", from, got)
		}
	}
}

// hairpinning is RFC 4787 REQ-9. The leaf's own address opens a mapping toward
// the server, and the spare address sends to that mapping's external address
// and port, which a NAT that hairpins carries to the leaf's own address from
// the spare's mapping, the class's address, as REQ-9a has it. Where the arm
// declares NoHairpinning, the exit takes the datagram as its own and its stack
// refuses it, port unreachable from the mapping's address, the leaf's own
// address never reading it. Taken so, the datagram is no flow through the
// exit, so row 6 still finds the spare address holding none.
func (r *rows) hairpinning(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, hairpinPort)
	server := r.listenUDP(t, to)
	leaf := r.bindUDP(t, netip.AddrPortFrom(r.family.Leaf, leafHairpinPort))
	opened := []byte("opens the mapping over " + r.family.Name)
	mapping := receiveFrom(t, udpReader(server), opened, func() { _, _ = leaf.WriteToUDPAddrPort(opened, to) })
	data := []byte("from the spare address to the leaf's mapping over " + r.family.Name)
	sent := datagram(netip.AddrPortFrom(r.family.Spare, spareHairpinPort), mapping, leafTTL, data)
	declared, limited := r.limits[NoHairpinning]
	if !limited {
		if from := receiveFrom(t, udpReader(leaf), data, func() { r.exit.hand([][]byte{sent}) }); from.Addr() != r.seen() {
			t.Errorf("the leaf read the hairpinned datagram from %s, want the spare's mapping on %s", from, r.seen())
		}
		return
	}
	t.Logf("declared in %s: %s", declared.Row, declared.Reason)
	r.answered(t, "port unreachable from the mapping's address", sent, portUnreachable, func(a netip.Addr) bool { return a == mapping.Addr() }, 0)
	if from, ok := readOnce(leaf, data, quietPeriod); ok {
		t.Errorf("the leaf read the spare's datagram to its mapping from %s, which the arm declares it does not carry", from)
	}
}

// tcpFiltering is RFC 5382 REQ-3, TCP's filtering. The leaf, listening on its
// port, connects from it to the server, which opens a mapping, and the server
// connects to that mapping from another port, which endpoint independent and
// address dependent filtering both carry to the leaf's listener. Where the arm
// declares PortDependentFiltering, that connection and one from another
// address of the server's side are reset by the exit, and the leaf accepts
// neither.
func (r *rows) tcpFiltering(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, filteringTCPPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafFilteringTCPPort)
	listener := listen(t, r.network.Leaf, local)
	_, opened := r.connect(t, listen(t, r.network.Server, to), to, local)
	mapping := addrPort(opened.RemoteAddr())
	otherPort := netip.AddrPortFrom(r.family.Server, filteringOtherTCPPort)
	declared, limited := r.limits[PortDependentFiltering]
	if !limited {
		conn, err := tryDial(r.network.Server, otherPort, mapping, stepBudget)
		if err != nil {
			t.Fatalf("connect from %s to the leaf's mapping %s: %v", otherPort, mapping, err)
		}
		_ = conn.Close()
		if from := addrPort(accept(t, listener).RemoteAddr()); from != otherPort {
			t.Errorf("the leaf accepted the connection to its mapping from %s, want %s", from, otherPort)
		}
		return
	}
	t.Logf("declared in %s: %s", declared.Row, declared.Reason)
	for _, from := range []netip.AddrPort{otherPort, netip.AddrPortFrom(r.family.Second, filteringTCPPort)} {
		conn, err := tryDial(r.network.Server, from, mapping, stepBudget)
		if conn != nil {
			_ = conn.Close()
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Errorf("the connection from %s to the leaf's mapping %s got %v, want reset", from, mapping, err)
		}
	}
	acceptsNothing(t, listener)
}

// tcpHairpinning is RFC 5382 REQ-8, TCP's hairpinning. The leaf, listening on
// its port, connects from it to the server, which opens a mapping, and the
// spare address connects to that mapping, which a NAT that hairpins carries to
// the leaf's listener from the spare's mapping. Where the arm declares
// NoHairpinning, the exit takes the connection as its own and resets it from
// the mapping's address at once, the leaf accepting nothing. Taken so, it is
// no flow through the exit, so row 6 still finds the spare holding none.
func (r *rows) tcpHairpinning(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, hairpinTCPPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafHairpinTCPPort)
	listener := listen(t, r.network.Leaf, local)
	_, opened := r.connect(t, listen(t, r.network.Server, to), to, local)
	mapping := addrPort(opened.RemoteAddr())
	spare := netip.AddrPortFrom(r.family.Spare, spareHairpinTCPPort)
	declared, limited := r.limits[NoHairpinning]
	back := len(r.network.Back())
	conn, err := tryDial(r.network.Leaf, spare, mapping, stepBudget)
	if conn != nil {
		t.Cleanup(func() { _ = conn.Close() })
	}
	if !limited {
		if err != nil {
			t.Fatalf("connect from the spare %s to the leaf's mapping %s: %v", spare, mapping, err)
		}
		if from := addrPort(accept(t, listener).RemoteAddr()); from.Addr() != r.seen() {
			t.Errorf("the leaf accepted the hairpinned connection from %s, want the spare's mapping on %s", from, r.seen())
		}
		return
	}
	t.Logf("declared in %s: %s", declared.Row, declared.Reason)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("the spare's connection to the leaf's mapping %s got %v, want reset", mapping, err)
	}
	if !slices.ContainsFunc(r.network.Back()[back:], func(packet []byte) bool {
		p, ok := parse(packet)
		// RST is the bit 0x04 of the flags in octet 13, RFC 9293 section 3.1
		return ok && p.src == mapping.Addr() && p.protocol == syscall.IPPROTO_TCP && len(p.payload) >= 20 &&
			binary.BigEndian.Uint16(p.payload) == mapping.Port() && p.payload[13]&0x04 != 0
	}) {
		t.Errorf("no reset from the mapping %s came back toward the spare", mapping)
	}
	acceptsNothing(t, listener)
}

// simultaneousOpen is RFC 5382 REQ-2a, section 4.2: a NAT MUST handle a TCP
// simultaneous open. The leaf, connected from its port to the server, learns
// its mapping from the server, then connects from that port to the server's
// simultaneousPort, whose SYN the server's side drops as a peer behind a NAT
// holding no mapping yet would. The server then connects from that port to
// the mapping, and its SYN reaches the leaf's, which both connections open on
// and carry data each way over.
func (r *rows) simultaneousOpen(t *testing.T) {
	learned := netip.AddrPortFrom(r.family.Server, simultaneousMappingPort)
	local := netip.AddrPortFrom(r.family.Leaf, leafSimultaneousPort)
	_, opened := r.connect(t, listen(t, r.network.Server, learned), learned, local)
	mapping := addrPort(opened.RemoteAddr())
	at := netip.AddrPortFrom(r.family.Server, simultaneousPort)
	type dialed struct {
		conn *net.TCPConn
		err  error
	}
	leafSide := make(chan dialed, 1)
	go func() {
		conn, err := tryDial(r.network.Leaf, local, at, stepBudget)
		leafSide <- dialed{conn, err}
	}()
	// past which the leaf's SYN has crossed the exit and made the flow the
	// server's SYN is a reply of
	time.Sleep(unansweredDial)
	server, err := tryDial(r.network.Server, at, mapping, stepBudget)
	leaf := <-leafSide
	for _, conn := range []*net.TCPConn{server, leaf.conn} {
		if conn != nil {
			t.Cleanup(func() { _ = conn.Close() })
		}
	}
	if err != nil || leaf.err != nil {
		t.Fatalf("the server's connection from %s to the leaf's mapping %s got %v and the leaf's to %s got %v, want both open", at, mapping, err, at, leaf.err)
	}
	data := []byte("over a simultaneous open in " + r.family.Name)
	write(t, server, data)
	readFull(t, leaf.conn, data)
	write(t, leaf.conn, data)
	readFull(t, server, data)
}

// dialFromServer opens a socket of the server's side at local, connected to to
func (r *rows) dialFromServer(t *testing.T, local, to netip.AddrPort) *net.UDPConn {
	return open(t, r.network.Server, "open a socket of the server's at "+local.String(), func() (*net.UDPConn, error) {
		return net.DialUDP("udp", net.UDPAddrFromAddrPort(local), net.UDPAddrFromAddrPort(to))
	})
}

// acceptsNothing holds that listener accepts no connection within quietPeriod
func acceptsNothing(t *testing.T, listener *net.TCPListener) {
	t.Helper()
	if err := listener.SetDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	if conn, err := listener.AcceptTCP(); err == nil {
		t.Errorf("the leaf accepted a connection from %s, which the arm declares it does not carry", conn.RemoteAddr())
		_ = conn.Close()
	}
}
