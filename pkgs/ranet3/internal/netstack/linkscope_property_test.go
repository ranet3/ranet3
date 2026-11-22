// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"math"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// scopeFate names where a session's packet ends by its destination's class and its source
type scopeFate int

const (
	fateTun scopeFate = iota
	fateForwarded
	fateGroup
	fateMartian
)

// scopeClass builds a destination of one class by its leading bits and names the fate of a packet to it from a source no router refuses
// routed is a class the table decides, which an unspecified source makes a martian, where the other classes meet their fate unless the source is mapped
// RFC 4291 section 2.7 puts every IPv6 group under ff00::/8 and section 2.5.6 link-local unicast under fe80::/10, RFC 1112 section 4 the IPv4 groups under 224.0.0.0/4
// RFC 1812 section 5.3.5 names 255.255.255.255 the limited broadcast, and RFC 4291 section 2.5.5.2 maps an IPv4 address under ::ffff:0:0/96
type scopeClass struct {
	name   string
	family int
	build  func(tc hegel.TestCase) netip.Addr
	fate   scopeFate
	routed bool
}

// drawBytes draws n bytes
func drawBytes(tc hegel.TestCase, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		v := hegel.Draw(tc, hegel.Integers[uint64](0, math.MaxUint64))
		for i := 0; i < 8 && len(out) < n; i++ {
			out = append(out, byte(v>>(8*i)))
		}
	}
	return out
}

func addr16(raw []byte) netip.Addr { return netip.AddrFrom16([16]byte(raw)) }

var scopeClasses = []scopeClass{
	{"an IPv6 group of any flags and scope", 6, func(tc hegel.TestCase) netip.Addr {
		raw := drawBytes(tc, 16)
		raw[0], raw[1] = 0xff, raw[1]&0xf0|byte(hegel.Draw(tc, pbt.Spanning(0, 15)))
		return addr16(raw)
	}, fateGroup, false},
	{"an IPv4 group", 4, func(tc hegel.TestCase) netip.Addr {
		raw := drawBytes(tc, 4)
		raw[0] = byte(hegel.Draw(tc, pbt.Spanning(224, 239)))
		return netip.AddrFrom4([4]byte(raw))
	}, fateGroup, false},
	{"the limited broadcast", 4, func(hegel.TestCase) netip.Addr { return netip.AddrFrom4([4]byte{255, 255, 255, 255}) }, fateGroup, false},
	{"IPv6 link-local unicast", 6, func(tc hegel.TestCase) netip.Addr {
		raw := drawBytes(tc, 16)
		raw[0], raw[1] = 0xfe, 0x80|byte(hegel.Draw(tc, pbt.Spanning(0, 0x3f)))
		return addr16(raw)
	}, fateMartian, false},
	{"a mapped group, limited broadcast or link-local address", 6, func(tc hegel.TestCase) netip.Addr {
		raw := drawBytes(tc, 16)
		copy(raw, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		switch hegel.Draw(tc, pbt.Spanning(0, 2)) {
		case 0:
			raw[12] = byte(hegel.Draw(tc, pbt.Spanning(224, 239)))
		case 1:
			copy(raw[12:], []byte{255, 255, 255, 255})
		default:
			raw[12], raw[13] = 169, 254
		}
		return addr16(raw)
	}, fateMartian, false},
	{"IPv4 link-local", 4, func(tc hegel.TestCase) netip.Addr {
		raw := drawBytes(tc, 4)
		raw[0], raw[1] = 169, 254
		return netip.AddrFrom4([4]byte(raw))
	}, fateMartian, false},
	{"this node's own IPv4", 4, func(hegel.TestCase) netip.Addr { return transitOwn[4] }, fateTun, true},
	{"this node's own IPv6", 6, func(hegel.TestCase) netip.Addr { return transitOwn[6] }, fateTun, true},
	{"another node's IPv4", 4, func(hegel.TestCase) netip.Addr { return transitFar[4] }, fateForwarded, true},
	{"another node's IPv6", 6, func(hegel.TestCase) netip.Addr { return transitFar[6] }, fateForwarded, true},
}

// over drawn batches a session delivers, of destinations in every class above, from the sender, the unspecified address or a mapped source, under a default of each family to another peer
// and to an IPv6 class the table does not decide from a drawn IPv6 link-local source too, whose fate is the class's
// the tun takes exactly the packets to this node's own from the sender, in their order
// every packet to a group or the limited broadcast from a non-mapped source is dropped and counted session_multicast, so none reaches the tun or a peer
// a mapped source or destination, a link-local destination of either family, and the unspecified source to a destination the table decides, is a martian, and nothing is answered
// every batch also holds both mapped endpoints, their native neighbors and a genuine source of each family, and Explain must name each modeled fate
func TestDecisionWritesNoGroupToTheTun(t *testing.T) {
	checkCases(t, func(ht *propertyCase) {
		n := newTransitNode(ht, DefaultMTU)
		n.m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), n.outPeer)
		n.m.Routes.Set(netip.Prefix{}, segPrefix("0.0.0.0/0"), n.outPeer)
		var packets, wantTun [][]byte
		var drawn []string
		var want TransitCounters
		add := func(source, destination netip.Addr, fate scopeFate) {
			raw := udpPacket(source, destination, 100, false)
			packets = append(packets, raw)
			drawn = append(drawn, source.String()+" to "+destination.String())
			decision, reason := TraceDrop, ""
			switch fate {
			case fateTun:
				wantTun = append(wantTun, raw)
				want.Delivered++
				decision = TraceDeliver
			case fateForwarded:
				want.Forwarded++
				decision = TraceForward
			case fateGroup:
				want.SessionMulticast++
				reason = "session_multicast"
			case fateMartian:
				want.Martian++
				reason = "martian"
			}
			if got := n.m.Explain(raw); got.Decision != decision || got.Reason != reason {
				ht.Fatalf("%s to %s: explanation %+v, want %s/%s", source, destination, got, decision, reason)
			}
		}
		for _, source := range []netip.Addr{mapped(netip.IPv4Unspecified()), mapped(segAddr("255.255.255.255"))} {
			add(source, transitFar[6], fateMartian)
		}
		for _, source := range []netip.Addr{segAddr("::fffe:ffff:ffff"), segAddr("::1:0:0:0"), transitSender[6]} {
			add(source, transitFar[6], fateForwarded)
		}
		add(transitSender[4], transitFar[4], fateForwarded)
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			class := scopeClasses[hegel.Draw(ht, pbt.Spanning(0, len(scopeClasses)-1))]
			destination := class.build(ht)
			source := transitSender[class.family]
			kinds := 1
			if class.family == 6 {
				kinds = 2
				// a link-local source to a destination the table decides would draw code 2 on the session, which the fates here do not model
				if !class.routed {
					kinds = 3
				}
			}
			kind := hegel.Draw(ht, pbt.Spanning(0, kinds))
			switch kind {
			case 1:
				source = map[int]netip.Addr{4: netip.IPv4Unspecified(), 6: netip.IPv6Unspecified()}[class.family]
			case 2:
				source = mapped(netip.AddrFrom4([4]byte(drawBytes(ht, 4))))
			case 3:
				raw := drawBytes(ht, 16)
				raw[0], raw[1] = 0xfe, 0x80|byte(hegel.Draw(ht, pbt.Spanning(0, 0x3f)))
				source = addr16(raw)
			}
			fate := class.fate
			if kind == 2 || kind == 1 && class.routed {
				fate = fateMartian
			}
			add(source, destination, fate)
		}
		tun, out, back := n.deliver(ht, packets...)
		if !slices.EqualFunc(tun, wantTun, bytes.Equal) {
			ht.Fatalf("of %q the tun took %x, want %x", drawn, tun, wantTun)
		}
		if uint64(len(out)) != want.Forwarded || len(back) != 0 {
			ht.Fatalf("of %q the next hop was sent %d and the sender %d, want %d and none", drawn, len(out), len(back), want.Forwarded)
		}
		if got := n.m.TransitCounters(); got != want {
			ht.Fatalf("of %q the decision counted %+v, want %+v", drawn, got, want)
		}
	})
}
