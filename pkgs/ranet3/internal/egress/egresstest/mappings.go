// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"net"
	"net/netip"
	"testing"
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

// dialFromServer opens a socket of the server's side at local, connected to to
func (r *rows) dialFromServer(t *testing.T, local, to netip.AddrPort) *net.UDPConn {
	return open(t, r.network.Server, "open a socket of the server's at "+local.String(), func() (*net.UDPConn, error) {
		return net.DialUDP("udp", net.UDPAddrFromAddrPort(local), net.UDPAddrFromAddrPort(to))
	})
}
