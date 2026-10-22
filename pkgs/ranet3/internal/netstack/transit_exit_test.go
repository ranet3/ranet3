// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// exitShapes are the ways a node advertises the internet of each family, each counting as a default with the overlay
var exitShapes = []struct {
	name     string
	prefixes map[int][]netip.Prefix
}{
	{"a default", map[int][]netip.Prefix{4: {segPrefix("0.0.0.0/0")}, 6: {segPrefix("::/0")}}},
	{"a pair of halves", map[int][]netip.Prefix{
		4: {segPrefix("0.0.0.0/1"), segPrefix("128.0.0.0/1")},
		6: {segPrefix("::/1"), segPrefix("8000::/1")},
	}},
	{"four quarters", map[int][]netip.Prefix{
		4: {segPrefix("0.0.0.0/2"), segPrefix("64.0.0.0/2"), segPrefix("128.0.0.0/2"), segPrefix("192.0.0.0/2")},
		6: {segPrefix("::/2"), segPrefix("4000::/2"), segPrefix("8000::/2"), segPrefix("c000::/2")},
	}},
}

// transitStranger is an internet host no route of the mesh holds
var transitStranger = map[int]netip.Addr{4: segAddr("203.0.113.66"), 6: segAddr("2001:db8:66::6")}

// an exit egresses through every way of advertising the internet, a default, a pair of halves and four quarters, each counting as a default
// a packet from a source the mesh routes reaches the tun, from a peer's source, from inside a hold, from its own LAN or from an address cap.table assigns it, while its family's translation is ready
// and while it is not, one through a prefix cap.egress advertises is dropped and counted not ready, whatever the egress device's readiness says
// where cap.route announces the prefix instead it reaches the tun whatever the readiness, since no translation stands behind it
// an overlay address inside the prefix that no route holds is answered as no route and never egressed
// a packet from a source the mesh routes no reply to is dropped and counted with no answer
// and so is every packet from it this node answers, expired, refused, held or for an overlay address, since only the exit's default reaches the source
// an IPv4 link-local destination is a martian, never in the tun, and an IPv6 one goes to the tun as link scope does
func TestDecisionEgressesAtAnExit(t *testing.T) {
	for _, family := range []int{4, 6} {
		hostCode := map[int]byte{4: 1, 6: 0}[family]
		lan := map[int]netip.Prefix{4: segPrefix("198.51.100.128/25"), 6: segPrefix("2001:db8:7::/48")}[family]
		onTheLAN := map[int]netip.Addr{4: segAddr("198.51.100.130"), 6: segAddr("2001:db8:7::130")}[family]
		assigned := map[int]netip.Addr{4: segAddr("198.51.100.7"), 6: segAddr("2001:db8:8::7")}[family]
		linkLocal := map[int]netip.Addr{4: segAddr("169.254.169.254"), 6: segAddr("fe80::a9fe:a9fe")}[family]
		for _, shape := range exitShapes {
			for _, advertised := range []bool{true, false} {
				for _, c := range []struct {
					name        string
					from, to    netip.Addr
					hops        byte
					transitOff  bool
					ready       bool
					tun, answer bool
					want        TransitCounters
				}{
					{name: "from a peer's source", from: transitSender[family], to: transitNowhere[family], ready: true, tun: true, want: TransitCounters{Delivered: 1}},
					{name: "from inside a hold", from: transitHeldHost[family], to: transitNowhere[family], ready: true, tun: true, want: TransitCounters{Delivered: 1}},
					{name: "from its own LAN", from: onTheLAN, to: transitNowhere[family], ready: true, tun: true, want: TransitCounters{Delivered: 1}},
					{name: "from an address cap.table assigns it", from: assigned, to: transitNowhere[family], ready: true, tun: true, want: TransitCounters{Delivered: 1}},
					{name: "to an overlay address no route holds", from: transitSender[family], to: transitUnrouted[family], ready: true, answer: true, want: TransitCounters{NoRoute: 1, Answered: 1}},
					{name: "from a source the mesh routes no reply to", from: transitStranger[family], to: transitNowhere[family], ready: true, want: TransitCounters{UnroutedSource: 1}},
					{name: "expired from a source the mesh routes no reply to", from: transitStranger[family], to: transitFar[family], hops: 1, ready: true, want: TransitCounters{Expired: 1}},
					{name: "refused from a source the mesh routes no reply to", from: transitStranger[family], to: transitFar[family], transitOff: true, ready: true, want: TransitCounters{Refused: 1}},
					{name: "held from a source the mesh routes no reply to", from: transitStranger[family], to: transitHeldHost[family], ready: true, want: TransitCounters{Held: 1}},
					{name: "to an overlay address no route holds from a source the mesh routes no reply to", from: transitStranger[family], to: transitUnrouted[family], ready: true, want: TransitCounters{NoRoute: 1}},
					{name: "to a link-local address", from: transitSender[family], to: linkLocal, ready: true, tun: family == 6,
						want: map[int]TransitCounters{4: {Martian: 1}, 6: {Delivered: 1}}[family]},
					{name: "while the translation is not ready", from: transitSender[family], to: transitNowhere[family], tun: !advertised,
						want: map[bool]TransitCounters{true: {NotReady: 1}, false: {Delivered: 1}}[advertised]},
				} {
					t.Run(fmt.Sprintf("IPv%d %s advertised %t %s", family, shape.name, advertised, c.name), func(t *testing.T) {
						n := newTransitNode(t, DefaultMTU)
						for _, prefix := range shape.prefixes[family] {
							n.m.Routes.Set(netip.Prefix{}, prefix, Local)
						}
						n.m.Routes.Set(netip.Prefix{}, lan, Local)
						n.m.Routes.Set(netip.Prefix{}, hostPrefix(assigned), Assigned)
						if advertised {
							n.m.SetEgressPrefixes(shape.prefixes[family])
						}
						n.m.SetTransit(!c.transitOff)
						// the egress device's word says the opposite, which the decision does not read
						n.m.SetAdvertisedReady(c.ready, c.ready)
						n.m.SetEgressReady(!c.ready, !c.ready)
						raw := udpPacket(c.from, c.to, 200, true)
						if c.hops != 0 {
							raw = withTTL(raw, c.hops)
						}
						tun, out, back := n.deliver(t, raw)
						if c.tun != (len(tun) == 1) || c.tun && !bytes.Equal(tun[0], raw) || len(out) != 0 {
							t.Errorf("the tun took %x and the next hop was sent %x, want the packet in the tun %v", tun, out, c.tun)
						}
						if c.answer != (len(back) == 1) {
							t.Fatalf("the sender was sent %x, want an answer %v", back, c.answer)
						}
						if c.answer {
							checkError(t, back[0], raw, transitOwn[family], noRouteType[family], hostCode)
						}
						if got := n.m.TransitCounters(); got != c.want {
							t.Errorf("the decision counted %+v, want %+v", got, c.want)
						}
					})
				}
			}
		}
	}
}

// a batch keeps each source and destination pair's answer for the egress check, so packets from a source the mesh routes and from one it does not
// interleaved in one batch, and past as many pairs as the batch keeps, are each judged by their own source
func TestDecisionJudgesEachSourceOfABatchByItsOwn(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newTransitNode(t, DefaultMTU)
			n.m.Routes.Set(netip.Prefix{}, exitShapes[0].prefixes[family][0], Local)
			routed := udpPacket(transitSender[family], transitNowhere[family], 100, true)
			packets := [][]byte{udpPacket(transitStranger[family], transitNowhere[family], 100, true), routed}
			for i := range egressPairs + 1 {
				stranger := transitStranger[family].AsSlice()
				stranger[len(stranger)-1] = byte(100 + i)
				from, _ := netip.AddrFromSlice(stranger)
				packets = append(packets, udpPacket(from, transitNowhere[family], 100, true))
			}
			packets = append(packets, routed)
			tun, _, _ := n.deliver(t, packets...)
			if len(tun) != 2 || !bytes.Equal(tun[0], routed) || !bytes.Equal(tun[1], routed) {
				t.Errorf("the tun took %d packets, want the two from the source the mesh routes", len(tun))
			}
			if got, want := n.m.TransitCounters(), (TransitCounters{Delivered: 2, UnroutedSource: egressPairs + 2}); got != want {
				t.Errorf("the batch counted %+v, want %+v", got, want)
			}
		})
	}
}

// a source only another exit's default covers is one the mesh routes no reply to, entries counting as a default passed over
// so an exit holding a quarter-sized default of its own refuses a packet from it, though a learned route covers it
func TestDecisionPassesOverAnotherExitsDefaultForTheSource(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			own := map[int]netip.Prefix{4: segPrefix("200.0.0.0/6"), 6: segPrefix("2000::/4")}[family]
			other := map[int]netip.Prefix{4: segPrefix("196.0.0.0/6"), 6: segPrefix("3000::/4")}[family]
			stranger := map[int]netip.Addr{4: segAddr("198.51.100.66"), 6: segAddr("3fff::99")}[family]
			n := newTransitNode(t, DefaultMTU)
			n.m.Routes.Set(netip.Prefix{}, own, Local)
			n.m.Routes.Set(netip.Prefix{}, other, n.outPeer)
			tun, out, back := n.deliver(t, udpPacket(stranger, transitNowhere[family], 100, true))
			if len(tun) != 0 || len(out) != 0 || len(back) != 0 {
				t.Errorf("the tun took %d packets, the next hop was sent %d and the sender %d, want none", len(tun), len(out), len(back))
			}
			if got, want := n.m.TransitCounters(), (TransitCounters{UnroutedSource: 1}); got != want {
				t.Errorf("the decision counted %+v, want %+v", got, want)
			}
		})
	}
}

// a prefix shorter than the floor that the overlay covers counts as no default, schema.CapturesTheMachine
// so the node holding it delivers a packet for it from any source, the source check and the overlay's answer passing it by
func TestDecisionDeliversThroughAShortPrefixTheOverlayCovers(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			short := map[int]netip.Prefix{4: segPrefix("192.0.0.0/4"), 6: segPrefix("3000::/4")}[family]
			n := newTransitNode(t, DefaultMTU)
			n.m.SetOverlay([]schema.Prefix{schema.PrefixFrom(short)})
			n.m.Routes.Set(netip.Prefix{}, short, Local)
			raw := udpPacket(transitStranger[family], transitUnrouted[family], 100, true)
			tun, out, back := n.deliver(t, raw)
			if len(tun) != 1 || !bytes.Equal(tun[0], raw) || len(out) != 0 || len(back) != 0 {
				t.Errorf("the tun took %d packets, the next hop was sent %d and the sender %d, want the packet in the tun alone", len(tun), len(out), len(back))
			}
			if got, want := n.m.TransitCounters(), (TransitCounters{Delivered: 1}); got != want {
				t.Errorf("the decision counted %+v, want %+v", got, want)
			}
		})
	}
}

// a leaf network announced from a source prefix, as RFC 9079 has it, is routed for a reply from inside that prefix and for none from outside it
// so an exit egresses the leaf's packet to an internet host inside the source prefix and refuses its packet to one outside it
// the two interleaved in one batch from one source are each judged by their own destination
func TestDecisionEgressesFromASourceRoutedFromItsDestination(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			leaves := map[int]netip.Prefix{4: segPrefix("192.0.2.64/28"), 6: segPrefix("3fff:0:0:40::/64")}[family]
			from := map[int]netip.Prefix{4: segPrefix("203.0.113.0/25"), 6: segPrefix("2001:db8::/48")}[family]
			outside := map[int]netip.Addr{4: segAddr("203.0.113.200"), 6: segAddr("2001:db8:1::5")}[family]
			n := newTransitNode(t, DefaultMTU)
			n.m.Routes.Set(netip.Prefix{}, exitShapes[0].prefixes[family][0], Local)
			n.m.Routes.Set(from, leaves, n.fromPeer)
			leaf := leaves.Addr().Next().Next()
			inside := udpPacket(leaf, transitNowhere[family], 100, true)
			tun, out, back := n.deliver(t, inside, udpPacket(leaf, outside, 100, true), inside)
			if len(tun) != 2 || !bytes.Equal(tun[0], inside) || !bytes.Equal(tun[1], inside) || len(out) != 0 || len(back) != 0 {
				t.Errorf("the tun took %d packets, the next hop was sent %d and the sender %d, want the two to %s in the tun alone", len(tun), len(out), len(back), transitNowhere[family])
			}
			if got, want := n.m.TransitCounters(), (TransitCounters{Delivered: 2, UnroutedSource: 1}); got != want {
				t.Errorf("the batch counted %+v, want %+v", got, want)
			}
		})
	}
}
