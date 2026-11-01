// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
)

// everySource is an overlay admitting every outer source, for a table whose
// tests do not reach the overlay's bound
var everySource = []schema.Prefix{schema.MustPrefix("::/0")}

// A packet not addressed to one of this node's segments costs a map lookup and
// goes where it was going, which is almost every packet on the mesh.
func TestPacketsForSomebodyElsePassThrough(t *testing.T) {
	table, err := NewLocalTable([]Segment{{SID: saddr("3fff:b:0:106::1"), Behavior: BehaviorEndDT46}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"an ordinary v6 packet":    innerV6("payload"),
		"an ordinary v4 packet":    innerV4("payload"),
		"a short buffer":           {0x60},
		"an empty one":             {},
		"a segment list elsewhere": segmentRouted(t),
	} {
		t.Run(name, func(t *testing.T) {
			if result := table.Handle(raw); result.Action != ActionPass {
				t.Errorf("Handle returned %v, want ActionPass", result.Action)
			}
		})
	}
	// A nil table answers for nothing without a caller having to ask.
	var absent *LocalTable
	if result := absent.Handle(segmentRouted(t)); result.Action != ActionPass {
		t.Errorf("a nil table returned %v", result.Action)
	}
	if absent.Segments() != nil {
		t.Error("a nil table reported segments")
	}
}

// A waypoint moves the packet to the next segment and says where it now goes,
// and which of this node's segments the packet reached, the address an answer
// about the packet may come from. An exit hands back what was inside. Both are
// reached only by a packet whose current segment is this node's.
func TestWaypointAndExitActOnTheirOwnSegments(t *testing.T) {
	waypoint := addr("3fff:b:0:106::2")
	exit := addr("3fff:b:0:206::1")
	table, err := NewLocalTable([]Segment{
		{SID: schema.AddrFrom(waypoint), Behavior: BehaviorEnd},
		{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46},
	}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	inner := innerV6("payload")
	raw, err := Encapsulate(inner, addr("3fff:b:0:100::1"), []netip.Addr{waypoint, exit})
	if err != nil {
		t.Fatal(err)
	}

	forwarded := table.Handle(raw)
	if forwarded.Action != ActionForward {
		t.Fatalf("the waypoint returned %v (%v)", forwarded.Action, forwarded.Err)
	}
	if forwarded.Next != exit {
		t.Fatalf("the waypoint forwarded to %s, want the next segment %s", forwarded.Next, exit)
	}
	if forwarded.SID != waypoint {
		t.Errorf("the waypoint names %s as the segment the packet reached, want %s", forwarded.SID, waypoint)
	}
	if got := netip.AddrFrom16([16]byte(raw[24:40])); got != exit {
		t.Errorf("the packet's destination is %s, so it was not rewritten in place", got)
	}

	// The same table now sees the same packet as the exit, which happens when
	// one node holds both segments.
	delivered := table.Handle(raw)
	if delivered.Action != ActionDeliver {
		t.Fatalf("the exit returned %v (%v)", delivered.Action, delivered.Err)
	}
	if delivered.Family != NextHeaderIPv6 || !bytes.Equal(delivered.Inner, inner) {
		t.Error("the exit delivered something other than the packet that was sent")
	}
}

// A packet addressed to one of this node's segments that cannot be acted on is
// dropped with its refusal rather than written to the tun, where it would arrive
// as an undeliverable IPv6 packet addressed to an address of ours.
// RFC 8986 section 4.1.1 S04: "Send an ICMP Parameter Problem to the Source Address with Code 4 (SR Upper-layer Header Error) and Pointer set to the offset of the Upper-Layer header"
// for an upper-layer header local configuration does not allow, which at a waypoint is every one, with no routing header or past one at segments left 0
// section 4.8 S03: "Send an ICMP Parameter Problem to the Source Address with Code 0 (Erroneous header field encountered) and Pointer set to the Segments Left field" for an exit reached with segments left
func TestSegmentsOfOursThatCannotBeActedOnAreRefusedAtTheirField(t *testing.T) {
	sid := addr("3fff:b:0:106::2")
	waypoint, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(sid), Behavior: BehaviorEnd}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	plain := innerV6("payload")
	copy(plain[24:], addr16(sid))
	if result := waypoint.Handle(plain); result.Action != ActionDrop || !refusedWith(result.Err, icmpUpperLayer, ipv6HeaderLen) {
		t.Errorf("a plain packet to a waypoint returned %v (%v), want code 4 at its upper-layer header", result.Action, result.Err)
	}
	arrived := segmentRouted(t)
	copy(arrived[24:], addr16(sid))
	if result := waypoint.Handle(arrived); result.Action != ActionDrop || !refusedWith(result.Err, icmpUpperLayer, ipv6HeaderLen+srhFixedLen+2*addrLen) {
		t.Errorf("a finished path at a waypoint returned %v (%v), want code 4 at the inner packet", result.Action, result.Err)
	}

	// from sources an egress segment allows
	exitSID, source := addr("3fff:b:0:206::1"), addr("3fff:b:0:100::1")
	for name, segment := range map[string]Segment{
		"delivering to the mesh": {SID: schema.AddrFrom(exitSID), Behavior: BehaviorEndDT46},
		"egress": {SID: schema.AddrFrom(exitSID), Behavior: BehaviorEndDT46, Deliver: DeliverEgress,
			Allow: []schema.Prefix{schema.MustPrefix("3fff:b:0:100::/60"), schema.MustPrefix("3fff:a::/64")}},
	} {
		t.Run(name, func(t *testing.T) {
			exit, err := NewLocalTable([]Segment{segment}, everySource)
			if err != nil {
				t.Fatal(err)
			}
			midPath, err := Encapsulate(innerV6("payload"), source, []netip.Addr{exitSID, addr("3fff:b:0:506::1")})
			if err != nil {
				t.Fatal(err)
			}
			result := exit.Handle(midPath)
			if result.Action != ActionDrop || !refusedWith(result.Err, icmpErroneousHeader, ipv6HeaderLen+segmentsLeftInHeader) {
				t.Errorf("an exit in the middle of a path returned %v (%v), want code 0 at Segments Left", result.Action, result.Err)
			}
		})
	}
}

// figure4 is RFC 6040 section 4.2's Figure 4, by the arriving inner ECN field and then the outer, in the figure's order of Not-ECT, ECT(0), ECT(1) and CE
// figureDrop marks its one cell that drops the packet
var figure4 = [4][4]uint8{
	{0b00, 0b00, 0b00, figureDrop},
	{0b10, 0b10, 0b01, 0b11},
	{0b01, 0b01, 0b01, 0b11},
	{0b11, 0b11, 0b11, 0b11},
}

const figureDrop = 0xff

// figureOrder is the codepoints in Figure 4's order, RFC 3168 section 5's 00, 10, 01 and 11
var figureOrder = [4]uint8{0b00, 0b10, 0b01, 0b11}

// figureUnused marks the cells Figure 4 marks (!!!) or (!), the currently unused combinations
var figureUnused = [4][4]bool{
	{false, true, true, true},
	{false, false, false, false},
	{false, true, false, false},
	{false, false, true, false},
}

// RFC 6040 section 4.2: "a compliant tunnel egress MUST set the outgoing ECN field to the codepoint at the intersection of the appropriate arriving inner header (row) and outer header (column) in Figure 4 (the IPv4 header checksum also changes whenever the ECN field is changed)"
// and "If the inner ECN field is Not-ECT and the outer ECN field is CE, the decapsulator MUST drop the packet."
// an End.DT46 delivering to the mesh or to egress hands on each inner packet of either family with the figure's field, an IPv4 header's checksum still valid, or drops it at that cell
// and it reports each combination the figure marks currently unused, which "the decapsulator SHOULD log", the dropped one among them with the packet it drops
func TestExitDecapsulatesTheECNFieldByRFC6040(t *testing.T) {
	exit, source := addr("3fff:b:0:206::1"), addr("3fff:b:0:100::1")
	for name, segment := range map[string]Segment{
		"delivering to the mesh": {SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46},
		"egress": {SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress,
			Allow: []schema.Prefix{schema.MustPrefix("3fff:b:0:100::/60"), schema.MustPrefix("3fff:a::/64"), schema.MustPrefix("203.0.113.0/24")}},
	} {
		table, err := NewLocalTable([]Segment{segment}, everySource)
		if err != nil {
			t.Fatal(err)
		}
		for row, innerField := range figureOrder {
			for column, outerField := range figureOrder {
				for _, family := range []int{4, 6} {
					inner := innerV6("payload")
					inner[1] |= innerField << 4
					if family == 4 {
						inner = innerV4("payload")
						inner[1] = innerField
						binary.BigEndian.PutUint16(inner[10:], ^uint16(packet.Sum(0, inner[:20])))
					}
					raw, err := Encapsulate(inner, source, []netip.Addr{exit})
					if err != nil {
						t.Fatal(err)
					}
					raw[1] = raw[1]&^0b11_0000 | outerField<<4
					result := table.Handle(raw)
					want := figure4[row][column]
					if result.Unused != figureUnused[row][column] {
						t.Errorf("%s IPv%d: inner %02b under outer %02b reported unused %t, Figure 4 marks it %t", name, family, innerField, outerField, result.Unused, figureUnused[row][column])
					}
					if want == figureDrop {
						if result.Action != ActionDrop || result.Err != ErrECNDropped || result.Inner == nil {
							t.Errorf("%s IPv%d: inner %02b under outer %02b returned %v (%v) carrying %d octets, want the drop with its packet", name, family, innerField, outerField, result.Action, result.Err, len(result.Inner))
						}
						continue
					}
					if result.Action == ActionDrop {
						t.Fatalf("%s IPv%d: inner %02b under outer %02b was dropped: %v", name, family, innerField, outerField, result.Err)
					}
					got := result.Inner[1] >> 4 & 0b11
					if family == 4 {
						got = result.Inner[1] & 0b11
						if sum := packet.Sum(0, result.Inner[:20]); sum != 0xffff {
							t.Errorf("%s IPv4: inner %02b under outer %02b left a header summing to %#x, want its checksum valid", name, innerField, outerField, sum)
						}
					}
					if got != want {
						t.Errorf("%s IPv%d: inner %02b under outer %02b delivered %02b, want %02b", name, family, innerField, outerField, got, want)
					}
				}
			}
		}
	}
}

// An egress segment hands egress only a packet whose outer and inner
// sources both lie in its allow list, so it is never an open proxy. A packet
// not of the version the Next Header in front of it names is refused at its
// first octet rather than read for a source, and a sender outside the list is
// refused before its header is parsed, so it is never answered about the
// header.
func TestEgressSegmentCarriesOnlyTheSourcesItAllows(t *testing.T) {
	exit := addr("3fff:b:0:206::3")
	table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: []schema.Prefix{
		schema.MustPrefix("3fff:b:0:100::/60"),
		schema.MustPrefix("3fff:a::/64"),
		schema.MustPrefix("203.0.113.0/24"),
	}}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	listed, unlisted := addr("3fff:b:0:100::1"), addr("3fff:b:0:600::1")
	sourced := func(inner []byte, source netip.Addr) []byte {
		offset := 8
		if source.Is4() {
			offset = 12
		}
		copy(inner[offset:], source.AsSlice())
		return inner
	}
	encapsulated := func(outer netip.Addr, inner []byte) []byte {
		raw, err := Encapsulate(inner, outer, []netip.Addr{exit})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	// a v6 packet whose source carries 203.0.113.10 where a v4 header keeps its source
	announced := encapsulated(listed, sourced(innerV6("payload"), addr("3fff:b:cb00:710a::1")))
	announced[ipv6HeaderLen] = NextHeaderIPv4
	// segments left past the last entry, which an exit answers with a parameter problem
	broken := encapsulated(unlisted, innerV6("payload"))
	broken[ipv6HeaderLen+3] = 5
	for name, c := range map[string]struct {
		raw    []byte
		family uint8
		// answered is a refusal at the inner packet's first octet
		answered bool
	}{
		"a v6 packet from inside":     {encapsulated(listed, innerV6("payload")), NextHeaderIPv6, false},
		"a v4 packet from inside":     {encapsulated(listed, innerV4("payload")), NextHeaderIPv4, false},
		"an outer source outside":     {encapsulated(unlisted, innerV6("payload")), 0, false},
		"a v6 inner source outside":   {encapsulated(listed, sourced(innerV6("payload"), addr("3fff:b::1"))), 0, false},
		"a v4 inner source outside":   {encapsulated(listed, sourced(innerV4("payload"), addr("198.51.100.1"))), 0, false},
		"a v6 packet announced as v4": {announced, 0, true},
		"an unlisted broken header":   {broken, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			inner := slices.Clone(c.raw[Overhead(1):])
			result := table.Handle(c.raw)
			switch {
			case c.answered && (result.Action != ActionDrop || !refusedWith(result.Err, icmpErroneousHeader, Overhead(1))):
				t.Errorf("Handle returned %v (%v), want a refusal at the inner packet's first octet, %d", result.Action, result.Err, Overhead(1))
			case c.family == 0 && !c.answered && (result.Action != ActionDrop || !errors.Is(result.Err, ErrSourceRefused)):
				t.Errorf("Handle returned %v (%v), want a refusal of the source", result.Action, result.Err)
			case c.family != 0 && (result.Action != ActionEgress || result.Family != c.family || !bytes.Equal(result.Inner, inner)):
				t.Errorf("Handle returned %v of family %d (%v), want the inner packet of family %d for egress",
					result.Action, result.Family, result.Err, c.family)
			}
		})
	}
}

// An allow entry outside the overlay admits an inner source alone: a LAN behind
// the node an outer source names, in either family, is carried, and an outer
// source an entry reaching past the overlay holds is refused where no entry
// inside the overlay holds it
func TestEgressSegmentTakesAnEntryOutsideTheOverlayForInnerSourcesAlone(t *testing.T) {
	exit := addr("3fff:b:0:206::3")
	table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: []schema.Prefix{
		schema.MustPrefix("3fff:b:0:100::/60"),
		schema.MustPrefix("2001:db8:f3::/64"),
		schema.MustPrefix("203.0.113.64/28"),
		schema.MustPrefix("3ff0::/12"),
	}}}, []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")})
	if err != nil {
		t.Fatal(err)
	}
	sourced := func(inner []byte, source netip.Addr) []byte {
		offset := 8
		if source.Is4() {
			offset = 12
		}
		copy(inner[offset:], source.AsSlice())
		return inner
	}
	for name, c := range map[string]struct {
		outer, inner netip.Addr
		family       uint8
	}{
		"a v6 LAN host behind a listed node":                   {addr("3fff:b:0:100::1"), addr("2001:db8:f3::20"), NextHeaderIPv6},
		"a v4 LAN host behind a listed node":                   {addr("3fff:b:0:100::1"), addr("203.0.113.70"), NextHeaderIPv4},
		"a listed node's own source":                           {addr("3fff:b:0:100::1"), addr("3fff:b:0:100::1"), NextHeaderIPv6},
		"an outer source only an entry past the overlay holds": {addr("3fff:b:0:600::1"), addr("3fff:b:0:100::1"), 0},
		"an outer source in an entry outside the overlay":      {addr("2001:db8:f3::20"), addr("2001:db8:f3::20"), 0},
		"a LAN source outside the list":                        {addr("3fff:b:0:100::1"), addr("2001:db8:f4::20"), 0},
	} {
		t.Run(name, func(t *testing.T) {
			inner := innerV6("payload")
			if c.inner.Is4() {
				inner = innerV4("payload")
			}
			raw, err := Encapsulate(sourced(inner, c.inner), c.outer, []netip.Addr{exit})
			if err != nil {
				t.Fatal(err)
			}
			want := slices.Clone(raw[Overhead(1):])
			result := table.Handle(raw)
			switch {
			case c.family == 0 && (result.Action != ActionDrop || !errors.Is(result.Err, ErrSourceRefused)):
				t.Errorf("from %s and %s Handle returned %v (%v), want a refusal of the source", c.outer, c.inner, result.Action, result.Err)
			case c.family != 0 && (result.Action != ActionEgress || result.Family != c.family || !bytes.Equal(result.Inner, want)):
				t.Errorf("from %s and %s Handle returned %v of family %d (%v), want the inner packet of family %d for egress", c.outer, c.inner, result.Action, result.Family, result.Err, c.family)
			}
		})
	}
}

// Every SID refuses a packet whose outer source lies outside the overlay,
// whatever it delivers to and before its header is parsed, so a host beyond
// the mesh is never answered, and acts on one from inside. The egress
// segment's allow list holds the outside source, so the overlay alone refuses
// it there. A table holding a SID and no IPv6 prefix of the overlay is refused.
func TestEverySIDRefusesAnOuterSourceOutsideTheOverlay(t *testing.T) {
	waypoint, exit, egress := addr("3fff:b:0:106::2"), addr("3fff:b:0:206::1"), addr("3fff:b:0:206::3")
	segments := []Segment{
		{SID: schema.AddrFrom(waypoint), Behavior: BehaviorEnd},
		{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46},
		{SID: schema.AddrFrom(egress), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: []schema.Prefix{
			schema.MustPrefix("2001:db8::/32"), schema.MustPrefix("3fff:a::/64"),
		}},
	}
	table, err := NewLocalTable(segments, []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")})
	if err != nil {
		t.Fatal(err)
	}
	inside, outside := addr("3fff:a::1"), addr("2001:db8:f::2")
	for name, c := range map[string]struct {
		path   []netip.Addr
		broken bool
		acts   Action
	}{
		"End":                         {[]netip.Addr{waypoint, exit}, false, ActionForward},
		"End.DT46 delivering to mesh": {[]netip.Addr{exit}, false, ActionDeliver},
		"an egress segment":           {[]netip.Addr{egress}, false, ActionEgress},
		// segments left past the last entry, which a source inside is answered about
		"End with a broken header": {[]netip.Addr{waypoint, exit}, true, ActionDrop},
	} {
		t.Run(name, func(t *testing.T) {
			for _, source := range []netip.Addr{inside, outside} {
				inner := innerV6("payload")
				copy(inner[8:], addr16(inside))
				raw, err := Encapsulate(inner, source, c.path)
				if err != nil {
					t.Fatal(err)
				}
				if c.broken {
					raw[ipv6HeaderLen+3] = 5
				}
				result := table.Handle(raw)
				switch {
				case source == outside && (result.Action != ActionDrop || !errors.Is(result.Err, ErrSourceRefused)):
					t.Errorf("from %s outside the overlay Handle returned %v (%v), want a refusal of the source", source, result.Action, result.Err)
				case source == inside && (result.Action != c.acts || errors.Is(result.Err, ErrSourceRefused)):
					t.Errorf("from %s inside the overlay Handle returned %v (%v), want %v", source, result.Action, result.Err, c.acts)
				}
			}
		})
	}
	if _, err := NewLocalTable(segments, []schema.Prefix{schema.MustPrefix("198.18.0.0/15")}); err == nil ||
		err.Error() != "srv6: cap.segment local 3fff:b:0:106::2 would refuse every packet, since overlay holds no IPv6 prefix to admit an outer source from" {
		t.Errorf("a table under an overlay of IPv4 alone was built with %v", err)
	}
	if table, err := NewLocalTable(nil, nil); table != nil || err != nil {
		t.Errorf("no segments under no overlay built %v (%v), want no table", table, err)
	}
}

// The dataplane reads the table's allow list without a lock, so a caller that
// changes the slice it passed in must not change what the table lets through.
func TestEgressAllowListSurvivesTheCallerChangingItsSlice(t *testing.T) {
	exit := addr("3fff:b:0:206::3")
	allow := make([]schema.Prefix, 1, 2)
	allow[0] = schema.MustPrefix("3fff:a::/64")
	table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: allow}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	packet := func(source netip.Addr) []byte {
		inner := innerV6("payload")
		copy(inner[8:], addr16(source))
		raw, err := Encapsulate(inner, source, []netip.Addr{exit})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	listed, unlisted := addr("3fff:a::1"), addr("3fff:b::1")
	before := map[netip.Addr]Action{}
	for _, source := range []netip.Addr{listed, unlisted} {
		before[source] = table.Handle(packet(source)).Action
	}
	if before[listed] != ActionEgress || before[unlisted] != ActionDrop {
		t.Fatalf("before any change the table answered %v", before)
	}

	allow[0] = schema.MustPrefix("3fff:b::/64")
	// what an append to the caller's slice would write
	allow[:cap(allow)][1] = schema.MustPrefix("3fff:b::/63")
	for source, want := range before {
		if got := table.Handle(packet(source)).Action; got != want {
			t.Errorf("after the caller changed its slice, a packet from %s returned %v, want %v", source, got, want)
		}
	}
}

// A configuration whose two halves disagree about what this node does, or that
// names something not implemented, is refused at startup rather than skipped.
// Each refusal names the segment.
func TestLocalTableRefusesWhatItCannotAnswerFor(t *testing.T) {
	for name, segments := range map[string][]Segment{
		"a v4 segment":     {{SID: saddr("203.0.113.10"), Behavior: BehaviorEnd}},
		"a duplicate":      {{SID: saddr("2001:db8::1"), Behavior: BehaviorEnd}, {SID: saddr("2001:db8::1"), Behavior: BehaviorEndDT46}},
		"a behavior of no": {{SID: saddr("2001:db8::1"), Behavior: 0}},
		"one not written":  {{SID: saddr("2001:db8::1"), Behavior: Behavior(99)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLocalTable(segments, everySource)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if !strings.Contains(err.Error(), segments[0].SID.String()) {
				t.Errorf("the refusal %q does not name %s", err, segments[0].SID)
			}
		})
	}
	table, err := NewLocalTable(nil, everySource)
	if err != nil || table != nil {
		t.Errorf("an empty configuration produced %v (%v), want no table at all", table, err)
	}
}

// egressAt is an egress segment on sid allowing the prefixes written
func egressAt(sid string, allow ...string) Segment {
	segment := Segment{SID: saddr(sid), Behavior: BehaviorEndDT46, Deliver: DeliverEgress}
	for _, prefix := range allow {
		segment.Allow = append(segment.Allow, sprefix(prefix))
	}
	return segment
}

// Each refusal of an egress segment is one an operator reads at load and names
// the field to change: a list that would make the exit an open proxy, one no
// packet could pass, and a delivery or a list on a segment that never reads it
func TestEgressSegmentIsRefusedWhereItWouldCarryTheWrongSources(t *testing.T) {
	const sid = "2001:db8::3"
	with := func(segment Segment, change func(*Segment)) Segment {
		change(&segment)
		return segment
	}
	valid := egressAt(sid, "3fff:a::/32", "198.18.0.0/15")
	for name, c := range map[string]struct {
		segments []Segment
		says     string
	}{
		"deliver egress on End":      {[]Segment{with(valid, func(s *Segment) { s.Behavior = BehaviorEnd })}, "deliver egress belongs to End.DT46, and End hands the packet to its next segment"},
		"allow on a mesh End.DT46":   {[]Segment{with(valid, func(s *Segment) { s.Deliver = DeliverMesh })}, `allow is read only with deliver = "egress"`},
		"allow on End":               {[]Segment{with(valid, func(s *Segment) { s.Deliver, s.Behavior = DeliverMesh, BehaviorEnd })}, `allow is read only with deliver = "egress"`},
		"a delivery with no name":    {[]Segment{with(valid, func(s *Segment) { s.Deliver = 7 })}, "delivery(7) is not mesh or egress"},
		"no allow list":              {[]Segment{egressAt(sid)}, "delivers to egress with no allow list"},
		"an empty allow list":        {[]Segment{with(valid, func(s *Segment) { s.Allow = []schema.Prefix{} })}, "delivers to egress with no allow list"},
		"an entry that is no prefix": {[]Segment{with(valid, func(s *Segment) { s.Allow = append(s.Allow, schema.Prefix{}) })}, "allow entry 3 is not a prefix"},
		"bits below the length":      {[]Segment{egressAt(sid, "3fff:a::1/32")}, "allow 3fff:a::1/32 has bits set below its prefix length"},
		"an IPv4 prefix as IPv6":     {[]Segment{egressAt(sid, "3fff:a::/32", "::ffff:198.18.0.0/111")}, "allow ::ffff:198.18.0.0/111 is an IPv4 prefix written as IPv6, so write it as 198.18.0.0/15"},
		"every IPv4 address":         {[]Segment{egressAt(sid, "3fff:a::/32", "0.0.0.0/0")}, "allow 0.0.0.0/0 admits every address of its family, which makes the segment an open proxy"},
		"every IPv6 address":         {[]Segment{egressAt(sid, "::/0")}, "allow ::/0 admits every address of its family"},
		"an IPv4 entry under /8":     {[]Segment{egressAt(sid, "3fff:a::/32", "4.0.0.0/7")}, "allow 4.0.0.0/7 is shorter than /8 for IPv4 or /12 for IPv6"},
		"an IPv6 entry under /12":    {[]Segment{egressAt(sid, "3fe0::/11")}, "allow 3fe0::/11 is shorter than /8 for IPv4 or /12 for IPv6"},
		"an entry written twice":     {[]Segment{egressAt(sid, "3fff:a::/32", "198.18.0.0/15", "3fff:a::/32")}, "allow 3fff:a::/32 is written twice"},
		"no IPv6 entry":              {[]Segment{egressAt(sid, "198.18.0.0/15")}, "allow holds no IPv6 prefix, and the outer source of a segment routed packet is always IPv6"},
		"a SID written twice": {
			[]Segment{valid, {SID: saddr(sid), Behavior: BehaviorEnd}},
			"cap.segment local 2001:db8::3 is written twice, as 2001:db8::3 End.DT46 deliver egress allow 3fff:a::/32 198.18.0.0/15 and as 2001:db8::3 End",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLocalTable(c.segments, everySource)
			if err == nil {
				t.Fatal("the segment was accepted")
			}
			if !strings.Contains(err.Error(), c.says) || !strings.Contains(err.Error(), "cap.segment local "+sid) {
				t.Errorf("the refusal %q does not say %q of %s", err, c.says, sid)
			}
		})
	}
	// the floors themselves are accepted
	if _, err := NewLocalTable([]Segment{egressAt(sid, "3ff0::/12", "4.0.0.0/8")}, everySource); err != nil {
		t.Errorf("an allow list at the floors was refused: %v", err)
	}
}

// String is the segment as the file spells it, which the status line and the
// duplicate refusal print
func TestSegmentPrintsItsDeliveryAndAllowList(t *testing.T) {
	for want, segment := range map[string]Segment{
		"2001:db8::3 End.DT46": {SID: saddr("2001:db8::3"), Behavior: BehaviorEndDT46},
		"2001:db8::2 End":      {SID: saddr("2001:db8::2"), Behavior: BehaviorEnd},
		"2001:db8::3 End.DT46 deliver egress allow 3fff:a::/32 198.18.0.0/15": egressAt("2001:db8::3", "3fff:a::/32", "198.18.0.0/15"),
	} {
		if got := segment.String(); got != want {
			t.Errorf("the segment prints as %q, want %q", got, want)
		}
	}
}

// deliver is spelled as a word in every format, an omitted one is the mesh,
// and a word that is neither is refused by name
func TestDeliverSpellsMeshOrEgress(t *testing.T) {
	type holder struct {
		Deliver Delivery `yaml:"deliver,omitempty" json:"deliver,omitempty" toml:"deliver,omitempty"`
	}
	for name, c := range map[string]struct {
		decode func(string, *holder) error
		mesh   string
		egress string
		other  string
	}{
		"toml": {func(s string, h *holder) error { _, err := toml.Decode(s, h); return err }, `deliver = "mesh"`, `deliver = "egress"`, `deliver = "kernel"`},
		"yaml": {func(s string, h *holder) error { return yaml.Unmarshal([]byte(s), h) }, "deliver: mesh", "deliver: egress", "deliver: kernel"},
		"json": {func(s string, h *holder) error { return json.Unmarshal([]byte(s), h) }, `{"deliver": "mesh"}`, `{"deliver": "egress"}`, `{"deliver": "kernel"}`},
	} {
		t.Run(name, func(t *testing.T) {
			for written, want := range map[string]Delivery{c.mesh: DeliverMesh, c.egress: DeliverEgress} {
				got := holder{Deliver: 7}
				if err := c.decode(written, &got); err != nil || got.Deliver != want {
					t.Errorf("%s read as %v (%v), want %v", written, got.Deliver, err, want)
				}
			}
			if err := c.decode(c.other, &holder{}); err == nil || !strings.Contains(err.Error(), `deliver "kernel" is not mesh or egress`) {
				t.Errorf("%s was not refused by name: %v", c.other, err)
			}
		})
	}
	for name, render := range map[string]func(any) ([]byte, error){"yaml": yaml.Marshal, "json": json.Marshal, "toml": toml.Marshal} {
		if written, err := render(holder{Deliver: 7}); err == nil {
			t.Errorf("%s wrote a delivery with no spelling as %q", name, written)
		}
	}
}

// The spelling is RFC 8986's and `ip route ... encap seg6local action`'s, so a
// configuration converted from the fleet's own reads the same.
func TestBehaviorSpellsItselfTheWayTheFleetWritesIt(t *testing.T) {
	for name, want := range map[string]Behavior{
		"End":      BehaviorEnd,
		"end":      BehaviorEnd,
		"End.DT46": BehaviorEndDT46,
		"end.dt46": BehaviorEndDT46,
		" End ":    BehaviorEnd,
	} {
		got, err := ParseBehavior(name)
		if err != nil || got != want {
			t.Errorf("ParseBehavior(%q) = %v (%v), want %v", name, got, err, want)
		}
	}
	for _, name := range []string{"", "End.DT4", "End.X", "uN"} {
		if _, err := ParseBehavior(name); err == nil {
			t.Errorf("ParseBehavior(%q) was accepted", name)
		}
	}
	if got := BehaviorEnd.String(); got != "End" {
		t.Errorf("BehaviorEnd prints as %q", got)
	}
	if got := BehaviorEndDT46.String(); got != "End.DT46" {
		t.Errorf("BehaviorEndDT46 prints as %q", got)
	}
}

// a behavior with no spelling is refused by every marshaller, since a file naming one is a file no decoder reads back
// the type is one byte, so every value is tried, and a behavior has a spelling when the word it prints reads back as itself
func TestEveryMarshallerRefusesABehaviorWithNoSpelling(t *testing.T) {
	type holder struct {
		Behavior Behavior `yaml:"behavior" json:"behavior" toml:"behavior"`
	}
	for name, render := range map[string]func(any) ([]byte, error){
		"yaml": yaml.Marshal,
		"json": json.Marshal,
		"toml": toml.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			for value := range 256 {
				behavior := Behavior(value)
				if read, err := ParseBehavior(behavior.String()); err == nil && read == behavior {
					continue
				}
				if written, err := render(holder{behavior}); err == nil {
					t.Errorf("behavior %d has no spelling and was written as %q", value, written)
				}
			}
		})
	}
}

// A table reports itself in a stable order, because a diagnostic that shuffles
// between two reads is one an operator cannot diff.
func TestSegmentsReportInAStableOrder(t *testing.T) {
	table, err := NewLocalTable([]Segment{
		{SID: saddr("3fff:b:0:106::2"), Behavior: BehaviorEnd},
		{SID: saddr("3fff:b:0:106::1"), Behavior: BehaviorEndDT46},
	}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Segments()) != 2 {
		t.Fatalf("the table holds %d segments", len(table.Segments()))
	}
	for range 4 {
		got := table.Segments()
		if len(got) != 2 || got[0].SID.String() != "3fff:b:0:106::1" || got[1].Behavior != BehaviorEnd {
			t.Fatalf("the table reported %v", got)
		}
	}
}
