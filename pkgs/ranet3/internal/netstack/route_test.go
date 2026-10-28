// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

func mustAddr(s string) netip.Addr     { return netip.MustParseAddr(s) }
func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestRouteTableOrdinaryLookup(t *testing.T) {
	rt := NewRouteTable()
	a := &Peer{ID: "a"}
	b := &Peer{ID: "b"}

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/8"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.1.0.0/16"), b)

	// Longest destination prefix wins regardless of order installed.
	// the length comes in IPv4's own bits
	peer, verdict, match := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.1.2.3"))
	if verdict != RoutePeer || peer != b || match.Bits != 16 {
		t.Fatalf("got %v, %v under /%d; want b, peer under /16", peer, verdict, match.Bits)
	}
	peer, verdict, match = rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.9.9.9"))
	if verdict != RoutePeer || peer != a || match.Bits != 8 {
		t.Fatalf("got %v, %v under /%d; want a, peer under /8", peer, verdict, match.Bits)
	}
	if peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("192.168.1.1")); verdict != RouteNone || peer != nil {
		t.Fatalf("got %v, %v; want no route", peer, verdict)
	}
}

func TestRouteTableSourceSpecificTakesPriorityAtEqualDestSpecificity(t *testing.T) {
	rt := NewRouteTable()
	any := &Peer{ID: "any"}
	specific := &Peer{ID: "specific"}

	dest := mustPrefix("2001:db8::/64")
	rt.Set(netip.Prefix{}, dest, any)
	rt.Set(mustPrefix("2001:db8:1::/48"), dest, specific)

	// Source falls inside the source-specific entry's prefix: it must win
	// even though both entries match the same destination.
	peer, verdict, _ := rt.Resolve(mustAddr("2001:db8:1::5"), mustAddr("2001:db8::1"))
	if verdict != RoutePeer || peer != specific {
		t.Fatalf("got %v, %v; want specific, peer", peer, verdict)
	}

	// Source falls outside the source-specific entry: falls back to the
	// any-source (ordinary) route, not "no match".
	peer, verdict, _ = rt.Resolve(mustAddr("2001:db8:2::5"), mustAddr("2001:db8::1"))
	if verdict != RoutePeer || peer != any {
		t.Fatalf("got %v, %v; want any, peer", peer, verdict)
	}
}

func TestRouteTableDestSpecificityBeatsSourceSpecificity(t *testing.T) {
	rt := NewRouteTable()
	broad := &Peer{ID: "broad"}
	narrow := &Peer{ID: "narrow"}

	// RFC 9079 section 4: "routing table entry R1 is preferred to routing
	// table entry R2 when either R1's destination prefix is more specific than
	// R2's or the destination prefixes are equal and R1's source prefix is more
	// specific than R2's"
	rt.Set(mustPrefix("2001:db8:1::/48"), mustPrefix("2001:db8::/32"), broad)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8::/48"), narrow)

	peer, verdict, _ := rt.Resolve(mustAddr("2001:db8:1::5"), mustAddr("2001:db8::1"))
	if verdict != RoutePeer || peer != narrow {
		t.Fatalf("got %v, %v; want narrow (more specific destination), peer", peer, verdict)
	}
}

func TestRouteTableSetReplacesSameKey(t *testing.T) {
	rt := NewRouteTable()
	a := &Peer{ID: "a"}
	b := &Peer{ID: "b"}
	dest := mustPrefix("10.0.0.0/24")

	rt.Set(netip.Prefix{}, dest, a)
	rt.Set(netip.Prefix{}, dest, b) // same (src, dst) key, must replace, not duplicate

	if debug := rt.Debug(); len(debug) != 1 {
		t.Fatalf("expected exactly one entry after replace, got %v", debug)
	}
	peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.0.0.5"))
	if verdict != RoutePeer || peer != b {
		t.Fatalf("got %v, %v; want b, peer", peer, verdict)
	}
}

func TestRouteTableSourceSpecificAndOrdinaryCoexistIndependently(t *testing.T) {
	rt := NewRouteTable()
	any := &Peer{ID: "any"}
	specific := &Peer{ID: "specific"}
	dest := mustPrefix("10.0.0.0/24")

	rt.Set(netip.Prefix{}, dest, any)
	rt.Set(mustPrefix("192.168.0.0/16"), dest, specific)
	if debug := rt.Debug(); len(debug) != 2 {
		t.Fatalf("expected both entries to coexist, got %v", debug)
	}

	// Removing the source-specific one must not disturb the ordinary one.
	rt.Remove(mustPrefix("192.168.0.0/16"), dest)
	peer, verdict, _ := rt.Resolve(mustAddr("192.168.1.1"), mustAddr("10.0.0.5"))
	if verdict != RoutePeer || peer != any {
		t.Fatalf("got %v, %v; want any (fallback survives), peer", peer, verdict)
	}
}

func TestRouteTableRemovePeer(t *testing.T) {
	rt := NewRouteTable()
	a := &Peer{ID: "a"}
	b := &Peer{ID: "b"}
	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/24"), a)
	rt.Set(mustPrefix("192.168.0.0/16"), mustPrefix("10.0.0.0/24"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.1.0.0/24"), b)

	rt.RemovePeer(a)

	if _, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.0.0.5")); verdict != RouteNone {
		t.Fatalf("expected a's routes to be gone, got %v", verdict)
	}
	if _, verdict, _ := rt.Resolve(mustAddr("192.168.1.1"), mustAddr("10.0.0.5")); verdict != RouteNone {
		t.Fatalf("expected a's source-specific route to be gone too, got %v", verdict)
	}
	if peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.1.0.5")); verdict != RoutePeer || peer != b {
		t.Fatalf("b's route should be unaffected, got %v, %v", peer, verdict)
	}
}

func TestAddrsOfIPv4(t *testing.T) {
	raw := make([]byte, 20)
	raw[0] = 0x45
	raw[3] = byte(len(raw))
	copy(raw[12:16], mustAddr("10.1.2.3").AsSlice())
	copy(raw[16:20], mustAddr("10.4.5.6").AsSlice())

	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if src != mustAddr("10.1.2.3") || dst != mustAddr("10.4.5.6") {
		t.Fatalf("got src=%s dst=%s", src, dst)
	}
	if nh != 4 {
		t.Fatalf("next header = %d, want 4 (IPv4)", nh)
	}
}

func TestAddrsOfIPv6(t *testing.T) {
	raw := make([]byte, 40)
	raw[0] = 0x60
	copy(raw[8:24], mustAddr("2001:db8::1").AsSlice())
	copy(raw[24:40], mustAddr("2001:db8::2").AsSlice())

	src, dst, nh, ok := addrsOf(raw)
	if !ok {
		t.Fatal("expected ok")
	}
	if src != mustAddr("2001:db8::1") || dst != mustAddr("2001:db8::2") {
		t.Fatalf("got src=%s dst=%s", src, dst)
	}
	if nh != 41 {
		t.Fatalf("next header = %d, want 41 (IPv6)", nh)
	}
}

func TestAddrsOfRejectsShortOrUnknownPackets(t *testing.T) {
	if _, _, _, ok := addrsOf(nil); ok {
		t.Fatal("expected reject on empty input")
	}
	if _, _, _, ok := addrsOf([]byte{0x45, 0, 0}); ok {
		t.Fatal("expected reject on truncated IPv4 header")
	}
	if _, _, _, ok := addrsOf([]byte{0x00}); ok {
		t.Fatal("expected reject on unknown IP version")
	}
	if _, _, _, ok := addrsOf(make([]byte, 20)); ok {
		t.Fatal("expected reject on invalid IPv4 length")
	}
	invalidIPv6 := make([]byte, 41)
	invalidIPv6[0] = 0x60
	if _, _, _, ok := addrsOf(invalidIPv6); ok {
		t.Fatal("expected reject on invalid IPv6 length")
	}
}

// Prefixes that share ever longer common prefixes make the destination trie
// fork, and each address still resolves to the one that covers it most
// precisely.
func TestRouteTableTrieRealBranching(t *testing.T) {
	rt := NewRouteTable()
	root := &Peer{ID: "root"}
	mid := &Peer{ID: "mid"}
	narrow := &Peer{ID: "narrow"}
	other := &Peer{ID: "other"}

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/8"), root)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.0.0/10"), mid)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.5.0/24"), narrow)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), other)

	cases := []struct {
		addr string
		want *Peer
	}{
		{"10.64.5.7", narrow},
		{"10.64.9.1", mid},
		{"10.200.0.1", other},
		{"10.1.2.3", root},
	}
	for _, c := range cases {
		peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr(c.addr))
		if verdict != RoutePeer || peer != c.want {
			t.Fatalf("resolve(%s): got %v, %v; want %s", c.addr, peer, verdict, c.want.ID)
		}
	}
	if _, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("11.0.0.1")); verdict != RouteNone {
		t.Fatalf("expected no route outside 10.0.0.0/8 entirely, got %v", verdict)
	}
}

// Removing one of two routes that fork from a branch node with no route of its
// own leaves the other resolving, and the branch node goes with the route.
func TestRouteTableTrieCompactionPreservesSiblings(t *testing.T) {
	rt := NewRouteTable()
	a := &Peer{ID: "a"}
	b := &Peer{ID: "b"}
	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), b)

	rt.Remove(netip.Prefix{}, mustPrefix("10.0.0.0/9"))

	if _, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.1.2.3")); verdict != RouteNone {
		t.Fatalf("removed route still resolves as %v", verdict)
	}
	peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.129.0.1"))
	if verdict != RoutePeer || peer != b {
		t.Fatalf("sibling route corrupted by removal: got %v, %v; want b, peer", peer, verdict)
	}

	debug := rt.Debug()
	if len(debug) != 1 {
		t.Fatalf("expected exactly one remaining route after compaction, got %v", debug)
	}
}

// RemovePeer leaves every other peer's routes in place in both families' tries.
func TestRouteTableTrieRemovePeerCompactsAcrossFamilies(t *testing.T) {
	rt := NewRouteTable()
	a := &Peer{ID: "a"}
	b := &Peer{ID: "b"}

	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.128.0.0/9"), a)
	rt.Set(netip.Prefix{}, mustPrefix("10.64.0.0/10"), b)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:1::/48"), a)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:2::/48"), b)

	rt.RemovePeer(a)

	for _, addr := range []string{"10.1.2.3", "10.200.0.1", "2001:db8:1::5"} {
		if _, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr(addr)); verdict != RouteNone {
			t.Fatalf("a's route for %s should be gone, got %v", addr, verdict)
		}
	}
	if peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("10.64.1.1")); verdict != RoutePeer || peer != b {
		t.Fatalf("b's IPv4 route should be unaffected, got %v, %v", peer, verdict)
	}
	if peer, verdict, _ := rt.Resolve(mustAddr("1.2.3.4"), mustAddr("2001:db8:2::5")); verdict != RoutePeer || peer != b {
		t.Fatalf("b's IPv6 route should be unaffected, got %v, %v", peer, verdict)
	}
}

// The hold stops a packet for a retracted prefix following a shorter one
// instead, and a mirror of this table has to hold it for the same reason.
func TestSnapshotCarriesUnreachableHold(t *testing.T) {
	rt := NewRouteTable()
	peer := &Peer{ID: "peer"}
	held := netip.MustParsePrefix("2001:db8:1::/48")
	rt.Set(netip.Prefix{}, netip.MustParsePrefix("2001:db8::/48"), peer)
	rt.Set(netip.Prefix{}, held, Unreachable)

	var found bool
	for _, route := range rt.Snapshot() {
		if route.Destination == held {
			found = true
			if route.Value != Unreachable {
				t.Errorf("the hold for %s came back as a route through %v", held, route.Value)
			}
		}
	}
	if !found {
		t.Errorf("the hold for %s was left out of the snapshot, so a mirror deletes it", held)
	}
	if peer, verdict, _ := rt.Resolve(netip.Addr{}, held.Addr().Next()); verdict != RouteHeld || peer != nil {
		t.Errorf("a packet for a held prefix resolved as %v, %v rather than held", peer, verdict)
	}
}

// Changed is how the reconciler learns a route moved without waiting out its
// periodic sweep, which at the default interval is thirty seconds of the
// kernel disagreeing with the mesh.
func TestEveryTableChangeWakesReconciler(t *testing.T) {
	rt := NewRouteTable()
	peer := &Peer{ID: "peer"}
	drain := func() {
		select {
		case <-rt.Changed():
		default:
		}
	}
	for name, change := range map[string]func(){
		"set":        func() { rt.Set(netip.Prefix{}, netip.MustParsePrefix("10.0.0.0/8"), peer) },
		"remove":     func() { rt.Remove(netip.Prefix{}, netip.MustParsePrefix("10.0.0.0/8")) },
		"removePeer": func() { rt.RemovePeer(peer) },
	} {
		t.Run(name, func(t *testing.T) {
			rt.Set(netip.Prefix{}, netip.MustParsePrefix("10.0.0.0/8"), peer)
			drain()
			change()
			select {
			case <-rt.Changed():
			default:
				t.Errorf("a %s left the reconciler asleep until its next sweep", name)
			}
		})
	}
}

// Snapshot hands out the unreachable holds with the sentinel as their value,
// which is not a Peer anything can send through.
func TestSnapshotHandsOutTheHoldAsASentinel(t *testing.T) {
	table := NewRouteTable()
	dest := netip.MustParsePrefix("fd00:5::/64")
	table.Set(netip.Prefix{}, dest, Unreachable)

	held := false
	for _, route := range table.Snapshot() {
		if route.Destination != dest {
			continue
		}
		held = true
		if route.Value != Unreachable {
			t.Errorf("the hold for %v came back as %v, which a caller would send through", dest, route.Value)
		}
	}
	if !held {
		t.Fatal("the snapshot does not carry the hold at all, so a mirror would fall through to a shorter prefix")
	}
	if _, verdict, _ := table.Resolve(netip.Addr{}, dest.Addr().Next()); verdict != RouteHeld {
		t.Errorf("a lookup landing on the hold resolved as %v", verdict)
	}
}

// Resolve gives each kind of entry its own verdict, Assigned the one Local
// gets, and a peer only with a route through one.
func TestResolveAnswersEachVerdict(t *testing.T) {
	rt := NewRouteTable()
	peer := &Peer{ID: "peer"}
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:1::/48"), peer)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:2::/48"), Unreachable)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:3::/48"), Local)
	rt.Set(netip.Prefix{}, mustPrefix("192.0.2.0/24"), Local)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:5::1/128"), Assigned)
	rt.Set(netip.Prefix{}, mustPrefix("198.51.100.7/32"), Assigned)
	for _, test := range []struct {
		to     string
		peer   *Peer
		want   Verdict
		wanted string
	}{
		{"2001:db8:1::1", peer, RoutePeer, "the peer"},
		{"2001:db8:2::1", nil, RouteHeld, "held"},
		{"2001:db8:3::1", nil, RouteLocal, "this node's"},
		{"192.0.2.1", nil, RouteLocal, "this node's"},
		{"2001:db8:5::1", nil, RouteLocal, "this node's"},
		{"198.51.100.7", nil, RouteLocal, "this node's"},
		{"2001:db8:4::1", nil, RouteNone, "no route"},
		{"198.51.100.1", nil, RouteNone, "no route"},
	} {
		if got, verdict, _ := rt.Resolve(netip.Addr{}, mustAddr(test.to)); got != test.peer || verdict != test.want {
			t.Errorf("a packet to %s resolved as verdict %d through %v, want %s", test.to, verdict, got, test.wanted)
		}
	}
}

// A new overlay or a new set of the prefixes cap.egress advertises flags again
// the entries the table already holds, each flag off and on again, and leaves
// the other flag as it was.
func TestOverlayAndEgressFlagTheEntriesAlreadyHeldAgain(t *testing.T) {
	rt := NewRouteTable()
	peer := &Peer{ID: "peer"}
	// a split internet in each family, counting as a default but inside an overlay holding it
	rt.Set(netip.Prefix{}, mustPrefix("2000::/3"), peer)
	rt.Set(netip.Prefix{}, mustPrefix("64.0.0.0/2"), peer)
	// this node's own prefix from any source, from one source, and a peer's
	rt.Set(netip.Prefix{}, mustPrefix("3fff:a::/48"), Local)
	rt.Set(mustPrefix("3fff:b::/48"), mustPrefix("3fff:a::/48"), Local)
	rt.Set(netip.Prefix{}, mustPrefix("3fff:c::/48"), peer)
	probes := []struct {
		from, to netip.Addr
		entry    string
	}{
		{netip.Addr{}, mustAddr("2001:db8::1"), "2000::/3"},
		{netip.Addr{}, mustAddr("64.0.0.1"), "64.0.0.0/2"},
		{netip.Addr{}, mustAddr("3fff:a::1"), "this node's 3fff:a::/48 from any source"},
		{mustAddr("3fff:b::1"), mustAddr("3fff:a::1"), "this node's 3fff:a::/48 from 3fff:b::/48"},
		{netip.Addr{}, mustAddr("3fff:c::1"), "the peer's 3fff:c::/48"},
	}
	covering := []schema.Prefix{schema.PrefixFrom(mustPrefix("2000::/3")), schema.PrefixFrom(mustPrefix("64.0.0.0/2"))}
	elsewhere := []schema.Prefix{schema.PrefixFrom(mustPrefix("fd00::/8")), schema.PrefixFrom(mustPrefix("10.0.0.0/8"))}
	advertised := []netip.Prefix{mustPrefix("3fff:a::/48"), mustPrefix("3fff:c::/48")}
	for _, step := range []struct {
		name    string
		change  func()
		counted []bool
		egress  []bool
	}{
		{"with no overlay and nothing advertised", func() {}, []bool{true, true, false, false, false}, []bool{false, false, false, false, false}},
		{"under an overlay holding both splits", func() { rt.SetOverlay(covering) }, []bool{false, false, false, false, false}, []bool{false, false, false, false, false}},
		{"advertising this node's and the peer's prefix", func() { rt.SetEgress(advertised) }, []bool{false, false, false, false, false}, []bool{false, false, true, false, false}},
		{"under an overlay elsewhere", func() { rt.SetOverlay(elsewhere) }, []bool{true, true, false, false, false}, []bool{false, false, true, false, false}},
		{"advertising nothing", func() { rt.SetEgress(nil) }, []bool{true, true, false, false, false}, []bool{false, false, false, false, false}},
	} {
		step.change()
		for i, probe := range probes {
			_, _, match := rt.Resolve(probe.from, probe.to)
			if match.Counted != step.counted[i] || match.Egress != step.egress[i] {
				t.Errorf("%s, %s answers counted %v and egress %v, want %v and %v",
					step.name, probe.entry, match.Counted, match.Egress, step.counted[i], step.egress[i])
			}
		}
	}
}

// RFC 8966 section 3.5.4: "packets destined to an address within P MUST NOT
// be forwarded by following a route for a shorter prefix". A prefix held
// inside one of this node's own is answered held, never delivered here by the
// covering entry, and the rest of the covering prefix stays this node's.
func TestResolveHoldsARetractedPrefixInsideALocalOne(t *testing.T) {
	for _, covering := range []string{"::/0", "2001:db8::/32"} {
		rt := NewRouteTable()
		rt.Set(netip.Prefix{}, mustPrefix(covering), Local)
		rt.Set(netip.Prefix{}, mustPrefix("2001:db8:1::/48"), Unreachable)
		if _, verdict, _ := rt.Resolve(netip.Addr{}, mustAddr("2001:db8:1::1")); verdict != RouteHeld {
			t.Errorf("a packet for a prefix held inside %s resolved as %v", covering, verdict)
		}
		if _, verdict, _ := rt.Resolve(netip.Addr{}, mustAddr("2001:db8:2::1")); verdict != RouteLocal {
			t.Errorf("a packet for %s outside the hold resolved as %v", covering, verdict)
		}
	}
}

// A learned route to a more specific prefix wins over this node's own
// covering one, which is longest-prefix forwarding as Babel selects it, and an
// exit's own default answers only what nothing more specific covers.
func TestResolvePrefersALearnedMoreSpecificOverLocal(t *testing.T) {
	rt := NewRouteTable()
	peer := &Peer{ID: "peer"}
	rt.Set(netip.Prefix{}, mustPrefix("::/0"), Local)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8::/32"), peer)
	if got, verdict, _ := rt.Resolve(netip.Addr{}, mustAddr("2001:db8::1")); verdict != RoutePeer || got != peer {
		t.Errorf("a packet for the learned prefix resolved as %v, %v", got, verdict)
	}
	if got, verdict, _ := rt.Resolve(netip.Addr{}, mustAddr("2001:db9::1")); verdict != RouteLocal || got != nil {
		t.Errorf("a packet only the default covers resolved as %v, %v", got, verdict)
	}
}

// RFC 9079 section 4: an implementation "MUST choose routing table entries by
// using destination-first ordering", whichever of a peer, a hold or this node
// each source-specific entry holds.
func TestResolveOrdersSourceSpecificKeysDestinationFirst(t *testing.T) {
	transit := mustPrefix("2001:db8:a::/48")
	inside, outside := mustAddr("2001:db8:a::1"), mustAddr("2001:db8:b::1")
	rt := NewRouteTable()
	peer, other := &Peer{ID: "peer"}, &Peer{ID: "other"}
	// an exit's own default from its transit prefix
	rt.Set(transit, mustPrefix("::/0"), Local)
	// a learned destination more specific than the default, from no source
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:5::/48"), peer)
	// one destination held from the transit prefix and this node's from any other
	rt.Set(transit, mustPrefix("2001:db8:6::/48"), Unreachable)
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:6::/48"), Local)
	// one destination this node's from any source and a peer's from the transit prefix
	rt.Set(netip.Prefix{}, mustPrefix("2001:db8:7::/48"), Local)
	rt.Set(transit, mustPrefix("2001:db8:7::/48"), other)
	for _, test := range []struct {
		from, to netip.Addr
		peer     *Peer
		want     Verdict
		wanted   string
	}{
		{inside, mustAddr("2001:4860::8888"), nil, RouteLocal, "this node's"},
		{outside, mustAddr("2001:4860::8888"), nil, RouteNone, "no route"},
		{netip.Addr{}, mustAddr("2001:4860::8888"), nil, RouteNone, "no route"},
		{inside, mustAddr("2001:db8:5::1"), peer, RoutePeer, "the peer"},
		{inside, mustAddr("2001:db8:6::1"), nil, RouteHeld, "held"},
		{outside, mustAddr("2001:db8:6::1"), nil, RouteLocal, "this node's"},
		{inside, mustAddr("2001:db8:7::1"), other, RoutePeer, "the other peer"},
		{outside, mustAddr("2001:db8:7::1"), nil, RouteLocal, "this node's"},
	} {
		if got, verdict, _ := rt.Resolve(test.from, test.to); got != test.peer || verdict != test.want {
			t.Errorf("a packet from %v to %v resolved as verdict %d through %v, want %s", test.from, test.to, verdict, got, test.wanted)
		}
	}
}

// The debug dump names an entry holding Local or Assigned as this node's, a
// hold as unreachable and a route as its peer.
func TestDebugNamesALocalEntryThisNode(t *testing.T) {
	rt := NewRouteTable()
	rt.Set(netip.Prefix{}, mustPrefix("10.0.0.0/8"), &Peer{ID: "a"})
	rt.Set(netip.Prefix{}, mustPrefix("10.1.0.0/16"), Local)
	rt.Set(netip.Prefix{}, mustPrefix("10.2.0.0/16"), Unreachable)
	rt.Set(netip.Prefix{}, mustPrefix("10.3.0.1/32"), Assigned)
	rt.Set(mustPrefix("2001:db8:a::/48"), mustPrefix("::/0"), Local)
	want := []string{
		"10.0.0.0/8 via a",
		"10.1.0.0/16 via this node",
		"10.2.0.0/16 via unreachable",
		"10.3.0.1/32 via this node",
		"::/0 from 2001:db8:a::/48 via this node",
	}
	if got := rt.Debug(); !slices.Equal(got, want) {
		t.Errorf("the dump is\n%q\nwant\n%q", got, want)
	}
}

// A read of the tun sends nothing the table answers held or this node's
// through a peer, though a covering route leads to one. Inside the hold RFC
// 8966 section 3.5.4 says "packets destined to an address within P MUST NOT
// be forwarded by following a route for a shorter prefix", and the others are
// packets for this node.
func TestReadSendsNothingTheTableAnswersHeldOrLocal(t *testing.T) {
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	peer := (&recordingPeer{}).peer(t, "peer")
	m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), peer)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b::/64"), Unreachable)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:c::/64"), Local)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:e::9/128"), Assigned)
	source := tooBigSource[6]
	ownHosts(m, tooBigSource)
	b := newOutboundBatch(4)
	fill(b,
		udpPacket(source, segAddr("3fff:b::9"), 100, false),
		udpPacket(source, segAddr("3fff:c::9"), 100, false),
		udpPacket(source, segAddr("3fff:e::9"), 100, false),
		udpPacket(source, segAddr("3fff:d::9"), 100, false))
	m.classify(b)
	if b.peers[0] != nil || b.peers[1] != nil || b.peers[2] != nil {
		t.Errorf("a packet to a held prefix went to %v, one to this node's own prefix to %v and one to its assigned address to %v",
			b.peers[0], b.peers[1], b.peers[2])
	}
	if b.peers[3] != peer || len(b.peerOrder) != 1 {
		t.Errorf("a packet only the default covers went to %v of %v", b.peers[3], b.peerOrder)
	}
}

// A waypoint drops a segment whose next segment the table answers held or
// this node's, rather than forwarding it by a covering route.
func TestWaypointDropsASegmentTheTableAnswersHeldOrLocal(t *testing.T) {
	after := segAddr("3fff:b:0:206::1")
	for _, value := range []*Peer{Unreachable, Local, Assigned} {
		session, next := sessionOf(t, DefaultMTU)
		m, _ := waypointOf(t, after, session)
		m.Routes.Set(netip.Prefix{}, segPrefix("3fff:b:0:206::/64"), session)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(after, 128), value)
		left, _ := m.applySegments(framed(steeredThrough(t, udpPacket(tooBigSource[6], tooBigDestination[6], 200, false), after)), DefaultMTU, nil)
		if len(left) != 0 {
			t.Fatalf("a segment whose next one is %s reached the tun", value.ID)
		}
		if sent := next.packets(t); len(sent) != 0 {
			t.Errorf("a segment whose next one is %s went on by the covering route", value.ID)
		}
		if counters := m.SegmentCounters(); counters.Dropped != 1 || counters.Forwarded != 0 {
			t.Errorf("a segment whose next one is %s counted %+v", value.ID, counters)
		}
	}
}

// An answer to a source the table answers held or this node's goes to no peer,
// though a covering route leads back to the node that sent the segment.
func TestAnswerGoesNowhereTheTableAnswersHeldOrLocal(t *testing.T) {
	after := segAddr("3fff:b:0:206::1")
	source := tooBigSource[6]
	for _, value := range []*Peer{Unreachable, Local, Assigned} {
		session, _ := sessionOf(t, srv6.MinimumIPv6MTU+srv6.Overhead(2))
		m, sender := waypointOf(t, after, session)
		m.Routes.Set(netip.Prefix{}, segPrefix("::/0"), sender.sender)
		m.Routes.Set(netip.Prefix{}, netip.PrefixFrom(source, 128), value)
		m.applySegments(framed(steeredThrough(t, udpPacket(source, tooBigDestination[6], DefaultMTU, false), after)), DefaultMTU, nil)
		if answers := sender.packets(t); len(answers) != 0 {
			t.Errorf("an answer to a source that is %s went back by the covering route", value.ID)
		}
		if got := m.TooBigAnswered(); got != 0 {
			t.Errorf("an answer to a source that is %s counted %d sent", value.ID, got)
		}
	}
}
