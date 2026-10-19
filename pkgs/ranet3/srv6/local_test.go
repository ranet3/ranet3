// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/schema"
)

// A packet not addressed to one of this node's segments costs a map lookup and
// goes where it was going, which is almost every packet on the mesh.
func TestPacketsForSomebodyElsePassThrough(t *testing.T) {
	table, err := NewLocalTable([]Segment{{SID: saddr("3fff:1:69c:8c6::1"), Behavior: BehaviorEndDT46}})
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

// A waypoint moves the packet to the next segment and says where it now goes.
// An exit hands back what was inside. Both are reached only by a packet whose
// current segment is this node's.
func TestWaypointAndExitActOnTheirOwnSegments(t *testing.T) {
	waypoint := addr("3fff:1:69c:8c6::2")
	exit := addr("3fff:1:69c:98d6::1")
	table, err := NewLocalTable([]Segment{
		{SID: schema.AddrFrom(waypoint), Behavior: BehaviorEnd},
		{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46},
	})
	if err != nil {
		t.Fatal(err)
	}
	inner := innerV6("payload")
	raw, err := Encapsulate(inner, addr("3fff:1:69c:8c0::1"), []netip.Addr{waypoint, exit})
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
// dropped with a reason rather than written to the tun, where it would arrive
// as an undeliverable IPv6 packet addressed to an address of ours.
func TestSegmentsOfOursThatCannotBeActedOnAreDropped(t *testing.T) {
	sid := addr("3fff:1:69c:8c6::2")
	waypoint, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(sid), Behavior: BehaviorEnd}})
	if err != nil {
		t.Fatal(err)
	}
	// Addressed to our waypoint with no routing header at all.
	plain := innerV6("payload")
	copy(plain[24:], addr16(sid))
	result := waypoint.Handle(plain)
	if result.Action != ActionDrop || !errors.Is(result.Err, ErrNotSegmentRouted) {
		t.Errorf("a plain packet to a waypoint returned %v (%v)", result.Action, result.Err)
	}

	// Addressed to our waypoint having already reached its last segment.
	arrived := segmentRouted(t)
	copy(arrived[24:], addr16(sid))
	if result := waypoint.Handle(arrived); result.Action != ActionDrop || !errors.Is(result.Err, ErrExhausted) {
		t.Errorf("a finished path at a waypoint returned %v (%v)", result.Action, result.Err)
	}

	// An exit reached with segments still to go.
	exitSID := addr("3fff:1:69c:98d6::1")
	exit, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exitSID), Behavior: BehaviorEndDT46}})
	if err != nil {
		t.Fatal(err)
	}
	midPath, err := Encapsulate(innerV6("payload"), addr("3fff:1:69c:8c0::1"),
		[]netip.Addr{exitSID, addr("3fff:1:69c:29a6::1")})
	if err != nil {
		t.Fatal(err)
	}
	if result := exit.Handle(midPath); result.Action != ActionDrop {
		t.Errorf("an exit in the middle of a path returned %v", result.Action)
	}
}

// An egress segment hands the egress device only a packet whose outer and inner
// sources both lie in its allow list, so it is never an open proxy. The inner
// source is the one the device's stack reads, by the packet's own version, and
// a sender outside the list is refused before its header is parsed, so it is
// never answered about the header.
func TestEgressSegmentCarriesOnlyTheSourcesItAllows(t *testing.T) {
	exit := addr("3fff:1:69c:98d6::3")
	table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: []schema.Prefix{
		schema.MustPrefix("3fff:1:69c:8c0::/60"),
		schema.MustPrefix("3fff:a::/64"),
		schema.MustPrefix("198.18.104.0/24"),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	listed, unlisted := addr("3fff:1:69c:8c0::1"), addr("3fff:1:69c:8d0::1")
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
	// a v6 packet whose source carries 198.18.104.117 where a v4 header keeps its source
	announced := encapsulated(listed, sourced(innerV6("payload"), addr("3fff:b:c612:6875::1")))
	announced[ipv6HeaderLen] = NextHeaderIPv4
	// segments left past the last entry, which an exit answers with a parameter problem
	broken := encapsulated(unlisted, innerV6("payload"))
	broken[ipv6HeaderLen+3] = 5
	for name, c := range map[string]struct {
		raw    []byte
		family uint8
	}{
		"a v6 packet from inside":     {encapsulated(listed, innerV6("payload")), NextHeaderIPv6},
		"a v4 packet from inside":     {encapsulated(listed, innerV4("payload")), NextHeaderIPv4},
		"an outer source outside":     {encapsulated(unlisted, innerV6("payload")), 0},
		"a v6 inner source outside":   {encapsulated(listed, sourced(innerV6("payload"), addr("3fff:b::1"))), 0},
		"a v4 inner source outside":   {encapsulated(listed, sourced(innerV4("payload"), addr("198.18.105.1"))), 0},
		"a v6 packet announced as v4": {announced, 0},
		"an unlisted broken header":   {broken, 0},
	} {
		t.Run(name, func(t *testing.T) {
			inner := slices.Clone(c.raw[Overhead(1):])
			result := table.Handle(c.raw)
			switch {
			case c.family == 0 && (result.Action != ActionDrop || !errors.Is(result.Err, ErrSourceRefused)):
				t.Errorf("Handle returned %v (%v), want a refusal of the source", result.Action, result.Err)
			case c.family != 0 && (result.Action != ActionEgress || result.Family != c.family || !bytes.Equal(result.Inner, inner)):
				t.Errorf("Handle returned %v of family %d (%v), want the inner packet of family %d for the egress device",
					result.Action, result.Family, result.Err, c.family)
			}
		})
	}
}

// The dataplane reads the table's allow list without a lock, so a caller that
// changes the slice it passed in must not change what the table lets through.
func TestEgressAllowListSurvivesTheCallerChangingItsSlice(t *testing.T) {
	exit := addr("3fff:1:69c:98d6::3")
	allow := make([]schema.Prefix, 1, 2)
	allow[0] = schema.MustPrefix("3fff:a::/64")
	table, err := NewLocalTable([]Segment{{SID: schema.AddrFrom(exit), Behavior: BehaviorEndDT46, Deliver: DeliverEgress, Allow: allow}})
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
		"a v4 segment":     {{SID: saddr("198.18.104.117"), Behavior: BehaviorEnd}},
		"a duplicate":      {{SID: saddr("2001:db8::1"), Behavior: BehaviorEnd}, {SID: saddr("2001:db8::1"), Behavior: BehaviorEndDT46}},
		"a behavior of no": {{SID: saddr("2001:db8::1"), Behavior: 0}},
		"one not written":  {{SID: saddr("2001:db8::1"), Behavior: Behavior(99)}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLocalTable(segments)
			if err == nil {
				t.Fatalf("%s was accepted", name)
			}
			if !strings.Contains(err.Error(), segments[0].SID.String()) {
				t.Errorf("the refusal %q does not name %s", err, segments[0].SID)
			}
		})
	}
	table, err := NewLocalTable(nil)
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
			_, err := NewLocalTable(c.segments)
			if err == nil {
				t.Fatal("the segment was accepted")
			}
			if !strings.Contains(err.Error(), c.says) || !strings.Contains(err.Error(), "cap.segment local "+sid) {
				t.Errorf("the refusal %q does not say %q of %s", err, c.says, sid)
			}
		})
	}
	// the floors themselves are accepted
	if _, err := NewLocalTable([]Segment{egressAt(sid, "3ff0::/12", "4.0.0.0/8")}); err != nil {
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
		{SID: saddr("3fff:1:69c:8c6::2"), Behavior: BehaviorEnd},
		{SID: saddr("3fff:1:69c:8c6::1"), Behavior: BehaviorEndDT46},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Segments()) != 2 {
		t.Fatalf("the table holds %d segments", len(table.Segments()))
	}
	for range 4 {
		got := table.Segments()
		if len(got) != 2 || got[0].SID.String() != "3fff:1:69c:8c6::1" || got[1].Behavior != BehaviorEnd {
			t.Fatalf("the table reported %v", got)
		}
	}
}
