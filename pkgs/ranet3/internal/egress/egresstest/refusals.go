// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egresstest

import (
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// icmpNotCarried is RFC 5508 section 7's REQ-10c, which IPv4 alone has: a NAT
// SHOULD NOT support Source Quench or Information Request and Reply. The
// leaf's quench quoting the server's datagram and its information request
// reach the server not at all, and the server's quench to the leaf's mapping
// reaches the leaf not at all, while an echo still crosses.
func (r *rows) icmpNotCarried(t *testing.T) {
	to := netip.AddrPortFrom(r.family.Server, quenchPort)
	from := netip.AddrPortFrom(r.family.Leaf, leafQuenchPort)
	server := r.listenUDP(t, to)
	leaf := r.bindUDP(t, from)
	opened := []byte("opens the mapping over " + r.family.Name)
	mapping := receiveFrom(t, udpReader(server), opened, func() { _, _ = leaf.WriteToUDPAddrPort(opened, to) })
	icmp := r.serverIP(t, syscall.IPPROTO_ICMP, r.family.Server)

	quench := message{kind4: 4}
	out := []struct {
		what string
		sent []byte
	}{
		{"the leaf's source quench", icmpError(r.family.Leaf, r.family.Server, quench, datagram(to, from, leafTTL, []byte("the server's datagram")))},
		{"the leaf's information request", query(r.family.Leaf, r.family.Server, 15, 0, informationID, []byte("an information request"))},
	}
	for _, step := range out {
		r.exit.hand([][]byte{step.sent})
		if readsICMP(icmp, step.sent[headerLength(step.sent)]) {
			t.Errorf("the server read %s, which the exit does not carry", step.what)
		}
	}

	back := len(r.network.Back())
	in := icmpError(r.family.Server, mapping.Addr(), quench, datagram(mapping, to, leafTTL, opened))
	if _, err := icmp.WriteToIP(in[headerLength(in):], &net.IPAddr{IP: mapping.Addr().AsSlice()}); err != nil {
		t.Fatalf("send the server's source quench to %s: %v", mapping, err)
	}
	time.Sleep(quietPeriod)
	for _, packet := range r.network.Back()[back:] {
		if p, ok := parse(packet); ok && p.protocol == syscall.IPPROTO_ICMP && len(p.payload) > 0 && p.payload[0] == 4 {
			t.Errorf("the server's source quench to the leaf's mapping %s reached the leaf from %s", mapping, p.src)
		}
	}
	r.echoTo(t, r.family.Server, quenchEchoID)
}

// readsICMP is whether the server reads an ICMP message of type kind within
// quietPeriod
func readsICMP(icmp *net.IPConn, kind byte) bool {
	buf := make([]byte, readSize)
	for by := time.Now().Add(quietPeriod); ; {
		n, _, err := ipReader(icmp)(buf, by)
		if err != nil {
			return false
		}
		if n > 0 && buf[0] == kind {
			return true
		}
	}
}
