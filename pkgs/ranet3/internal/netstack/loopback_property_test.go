// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the model's classes below are written from their RFCs and call no predicate of the package, and a source no router forwards is one noSessionReaches holds
// a destination no router forwards, the groups apart: IPv4 network 0, 127/8, 169.254/16 and 240/4, IPv6 ::, ::1 and fe80::/10, and the IPv4-mapped block
var addrModelRefusedDestination = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::ffff:0:0/96"),
}

// a group or the limited broadcast, native or IPv4-mapped, which a read is dropped for before anything else
var addrModelGroups = []netip.Prefix{
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"), netip.MustParsePrefix("ff00::/8"), netip.MustParsePrefix("::ffff:224.0.0.0/100"),
}

// the overlay unroutedMesh writes, inside which a source this node does not own is forged
var addrModelOverlay = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("3fff::/20")}

func inBlocks(blocks []netip.Prefix, address netip.Addr) bool {
	return slices.ContainsFunc(blocks, func(block netip.Prefix) bool { return block.Contains(address) })
}

// addrModelAddresses are the addresses the property draws on purpose: each edge of unroutableAnchors with the address on either side
// the IPv4-mapped groups' ends, the mapped limited broadcast, loopback and link-local, an IPv6 link-local host, documentation addresses and this node's own
var addrModelAddresses = func() []netip.Addr {
	var out []netip.Addr
	for _, anchor := range unroutableAnchors {
		swept := edges(anchor)
		for _, address := range append(swept, swept[0].Prev(), swept[1].Next()) {
			if address.IsValid() && !inBlocks(addrModelOverlay, address) {
				out = append(out, address.WithZone(""))
			}
		}
	}
	for _, s := range []string{"::ffff:224.0.0.0", "::ffff:224.0.0.1", "::ffff:239.255.255.255", "::ffff:240.0.0.0", "::ffff:255.255.255.255", "::ffff:127.0.0.1", "::ffff:169.254.1.1",
		"fe80::9", "198.51.100.9", "203.0.113.9", "2001:db8::9"} {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}()

// drawAddress draws an address of the family v6 names, one of addrModelAddresses or any address outside the overlay
func drawAddress(ht *hegel.T, v6 bool) netip.Addr {
	if hegel.Draw(ht, hegel.Booleans()) {
		var family []netip.Addr
		for _, address := range addrModelAddresses {
			if address.Is6() == v6 {
				family = append(family, address)
			}
		}
		return family[hegel.Draw(ht, hegel.Integers(0, len(family)-1))]
	}
	raw := drawBytes(ht, 16)
	address := netip.AddrFrom16([16]byte(raw))
	if !v6 {
		address = netip.AddrFrom4([4]byte(raw[12:]))
	}
	if inBlocks(addrModelOverlay, address) {
		return map[bool]netip.Addr{false: segAddr("198.51.100.77"), true: segAddr("2001:db8::77")}[v6]
	}
	return address
}

// the kinds of entry the model's table holds
const (
	addrModelPeer = iota
	addrModelSegment
	addrModelLocal
)

type addrModelEntry struct {
	prefix netip.Prefix
	kind   int
}

// addrModelCounts is an entry counting as a default, which the edge passes over: a default, or one holding the unspecified address
// every other entry the model draws is a host route or a /64
func addrModelCounts(prefix netip.Prefix) bool {
	return prefix.Bits() == 0 || prefix.Contains(netip.IPv4Unspecified()) || prefix.Contains(netip.IPv6Unspecified())
}

// addrModelLookup is the longest of entries holding address, and whether one does
func addrModelLookup(entries []addrModelEntry, address netip.Addr) (addrModelEntry, bool) {
	var best addrModelEntry
	found := false
	for _, entry := range entries {
		if entry.prefix.Contains(address) && (!found || entry.prefix.Bits() > best.prefix.Bits()) {
			best, found = entry, true
		}
	}
	return best, found
}

// what the model has a read meet
const (
	addrModelMulticast = iota
	addrModelForged
	addrModelUnowned
	addrModelMartian
	addrModelBeyondScope
	addrModelSteered
	addrModelForwarded
	addrModelDelivered
	addrModelUnrouted
)

// a read off the tun meets what an independent model of address classes and roles says, drawn over a valid UDP packet with room under the MTU
// its source and destination each over the edges of the special-purpose blocks with the address on either side, the IPv4-mapped groups, the reversed ownership and any address of its family
// the route toward the destination a peer's counting as no default, a default, this node's own or none, ownedOnly, the tun holding the destination, and a steer to the destination
// the model holds a group before the lookup, the edge's forged and unowned-source drops from the drawn table and ownership, a held read with a refused address written back and never steered
// a refused read dropped martian with no answer, code 2 for an IPv6 link-local source toward a destination a router forwards, and every other read steered, forwarded, written back or left unrouted
// it holds the peer that took the read and what it took, the tun's writes, the counters, the trace's record and ExplainRead to the model, so a mesh sending nothing fails where the model forwards
// and for a read the model forwards a receiver's Explain names no martian, a second check that runs the package's own predicates
// before anything is drawn the first and last address of every class is tried as the source toward a documentation address and as the destination from this node's own
// under each route, with and without a steer, ownedOnly and not
// what plain UDP cannot carry, a routing header, a SID of this node's and a carried packet, the example tests above hold
func TestTunReadMeetsTheModelOfAddressesNoRouterForwards(t *testing.T) {
	check := func(tb testing.TB, src, dst netip.Addr, route int, held, steer, ownedOnly, traced bool) {
		tb.Helper()
		if held {
			route = 3
		}
		entries := []addrModelEntry{{hostPrefix(ownSource[4]), addrModelLocal}, {hostPrefix(ownSource[6]), addrModelLocal}}
		switch route {
		case 1:
			entries = append(entries, addrModelEntry{hostPrefix(dst), addrModelPeer})
		case 2:
			entries = append(entries, addrModelEntry{netip.PrefixFrom(map[bool]netip.Addr{false: netip.IPv4Unspecified(), true: netip.IPv6Unspecified()}[dst.Is6()], 0), addrModelPeer})
		case 3:
			entries = append(entries, addrModelEntry{hostPrefix(dst), addrModelLocal})
		}
		var steering *srv6.SteerTable
		if steer {
			var err error
			if steering, err = srv6.NewSteerTable([]srv6.Steer{{To: schema.PrefixFrom(hostPrefix(dst)), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:b:0:100::1")); err != nil {
				steer, steering = false, nil
			} else {
				entries = append(entries, addrModelEntry{netip.MustParsePrefix("3fff:1::/64"), addrModelSegment})
			}
		}
		tunHolds := []netip.Addr{ownSource[4], ownSource[6]}
		if held {
			tunHolds = append(tunHolds, dst)
		}
		build := func(_ testing.TB, peers namedPeers) (*Mesh, *recordingDevice) {
			m, dev := unroutedMesh(tb, func(r *RouteTable) {
				for _, entry := range entries[2:] {
					switch entry.kind {
					case addrModelPeer:
						r.Set(netip.Prefix{}, entry.prefix, peers.peer(tb, "peer"))
					case addrModelSegment:
						r.Set(netip.Prefix{}, entry.prefix, peers.peer(tb, "segment"))
					case addrModelLocal:
						r.Set(netip.Prefix{}, entry.prefix, Local)
					}
				}
			})
			dev.writes = make(chan recordedWrite, 2)
			m.SetTunAddresses(tunHolds)
			m.ownedOnly = ownedOnly
			if steering != nil {
				m.SetSteering(steering)
			}
			return m, dev
		}

		// the model
		toward, isRoute := addrModelLookup(entries, dst)
		back, isBack := addrModelLookup(entries, src)
		owned := isBack && back.kind == addrModelLocal && !addrModelCounts(back.prefix)
		forged := isBack && !addrModelCounts(back.prefix) && back.kind != addrModelLocal || inBlocks(addrModelOverlay, src) && !owned
		leaves := isRoute && addrModelCounts(toward.prefix)
		isHeld := isRoute && toward.kind == addrModelLocal && slices.Contains(tunHolds, dst)
		refused := inBlocks(noSessionReaches, src) || inBlocks(addrModelRefusedDestination, dst)
		fromLink := !isHeld && netip.MustParsePrefix("fe80::/10").Contains(src) && !inBlocks(addrModelRefusedDestination, dst)
		skip := refused && !isHeld
		var want int
		switch {
		case inBlocks(addrModelGroups, dst):
			want = addrModelMulticast
		case forged:
			want = addrModelForged
		case !owned && !skip && (leaves || ownedOnly):
			want = addrModelUnowned
		case skip && !fromLink:
			want = addrModelMartian
		case fromLink:
			want = addrModelBeyondScope
		case steer && !(isHeld && refused):
			want = addrModelSteered
		case isRoute && toward.kind == addrModelPeer:
			want = addrModelForwarded
		case isHeld:
			want = addrModelDelivered
		default:
			want = addrModelUnrouted
		}

		raw := udpPacket(src, dst, 200, false)
		got := readOn(tb, build, raw, traced)
		var to string
		var counted TransitCounters
		var decision TraceDecision
		var reason, answer string
		written := 0
		switch want {
		case addrModelMulticast:
			counted, decision, reason = TransitCounters{Multicast: 1}, TraceDrop, "multicast"
		case addrModelForged:
			counted, decision, reason = TransitCounters{Forged: 1}, TraceDrop, "forged"
		case addrModelUnowned:
			counted, decision, reason = TransitCounters{UnownedSource: 1}, TraceDrop, "unowned_source"
		case addrModelMartian:
			counted, decision, reason = TransitCounters{Martian: 1}, TraceDrop, "martian"
		case addrModelBeyondScope:
			// RFC 4443 section 2.4 (e.6) gives fe80::, the Subnet-Router anycast address, no error
			counted, decision, reason, answer = TransitCounters{Martian: 1, Answered: 1}, TraceAnswer, "martian", "beyond_scope"
			written = 1
			if src == netip.MustParseAddr("fe80::") {
				counted.Answered, written = 0, 0
			}
		case addrModelSteered:
			to, decision = "segment", TraceForward
		case addrModelForwarded:
			to, decision = "peer", TraceForward
			receiver, _ := recordingMesh(tb)
			receiver.SetOverlay(transitOverlay)
			if explained := receiver.Explain(raw); explained.Reason == "martian" {
				tb.Fatalf("a read from %s to %s the model forwards is one a receiver's Explain names a martian", src, dst)
			}
		case addrModelDelivered:
			counted, decision, written = TransitCounters{Delivered: 1}, TraceDeliver, 1
		case addrModelUnrouted:
			// the model leaves the answer to a read no route takes to the tests of that answer, and holds ExplainRead and the trace to each other
			if got.counted.Martian != 0 || got.counted.Delivered != 0 || got.explained.Decision == TraceForward || got.explained.Reason == "martian" {
				tb.Fatalf("a read from %s to %s the model leaves unrouted counted %+v and ExplainRead names %v %q", src, dst, got.counted, got.explained.Decision, got.explained.Reason)
			}
			counted, written = got.counted, len(got.written)
			decision, reason, answer = got.explained.Decision, got.explained.Reason, got.explained.Answer
		}
		if got.to != to || got.counted != counted || len(got.written) != written {
			tb.Fatalf("a read from %s to %s, route %d, held %t, steered %t, ownedOnly %t, went to %q, put %d packets into the tun and counted %+v, want %q, %d and %+v",
				src, dst, route, held, steer, ownedOnly, got.to, len(got.written), got.counted, to, written, counted)
		}
		if to != "" && (len(got.sent) != 1 || !bytes.HasSuffix(got.sent[0], raw)) {
			tb.Fatalf("a read from %s to %s: the peer %q took %d packets, want the read alone", src, dst, to, len(got.sent))
		}
		if got.explained.Decision != decision || got.explained.Reason != reason || got.explained.Answer != answer {
			tb.Fatalf("a read from %s to %s: ExplainRead names %v %q answering %q, want %v %q answering %q", src, dst, got.explained.Decision, got.explained.Reason, got.explained.Answer, decision, reason, answer)
		}
		if traced && (len(got.records) != 1 || got.records[0].Decision != decision || got.records[0].Reason != reason || got.records[0].Answer != answer) {
			tb.Fatalf("a read from %s to %s: the trace took %+v, want one record of %v %q answering %q", src, dst, got.records, decision, reason, answer)
		}
	}
	documentation := map[bool]netip.Addr{false: segAddr("198.51.100.9"), true: segAddr("2001:db8::9")}
	for _, class := range slices.Concat(noSessionReaches, addrModelRefusedDestination, addrModelGroups) {
		for _, address := range edges(class) {
			address = address.WithZone("")
			for route := 1; route <= 4; route++ {
				for _, steer := range []bool{false, true} {
					for _, ownedOnly := range []bool{false, true} {
						// route 4 is a route of this node's own to an address the tun holds
						check(t, address, documentation[address.Is6()], min(route, 3), route == 4, steer, ownedOnly, ownedOnly != steer)
						check(t, ownSource[map[bool]int{false: 4, true: 6}[address.Is6()]], address, min(route, 3), route == 4, steer, ownedOnly, ownedOnly == steer)
					}
				}
			}
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		v6 := hegel.Draw(ht, hegel.Booleans())
		family := map[bool]int{false: 4, true: 6}[v6]
		src, dst := drawAddress(ht, v6), drawAddress(ht, v6)
		if hegel.Draw(ht, hegel.Booleans()) {
			src = ownSource[family]
		}
		route := hegel.Draw(ht, pbt.Spanning(0, 3))
		held, steer := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		ownedOnly, traced := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		check(ht, src, dst, route, held, steer, ownedOnly, traced)
	})
}
