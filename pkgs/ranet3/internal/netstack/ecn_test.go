// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/hex"
	"log/slog"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// RFC 6040 section 4.2: "In these cases, particularly the more dangerous ones, the decapsulator SHOULD log the event and MAY also raise an alarm"
// so an End.DT46 counts each packet whose inner and outer ECN fields Figure 4 marks currently unused, the one it drops among them, and no other
// and records netstack.ecn.unused at most once an interval, with the count since the record before, both fields and the inner IP header of the packet it records
func TestExitCountsAndRecordsTheUnusedECNCombinations(t *testing.T) {
	exit, steerer := segAddr("3fff:b:0:206::1"), segAddr("3fff:b:0:100::1")
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(exit), Behavior: srv6.BehaviorEndDT46}}, everySource)
	if err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), events: bus.Emit}
	m.startSegmentReports()
	m.SetSegments(table)
	steered := func(inner, outer packet.ECN) []byte {
		raw, err := srv6.Encapsulate(plainHeader(t, inner), steerer, []netip.Addr{exit})
		if err != nil {
			t.Fatal(err)
		}
		packet.SetECN(raw, outer)
		return raw
	}
	type record struct{ outer, inner, count, header string }
	recordsOf := func() []record {
		var out []record
		for _, event := range bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.ecn.unused" }, 0) {
			out = append(out, record{event.Attrs["outer"], event.Attrs["inner"], event.Attrs["count"], event.Attrs["header"]})
		}
		return out
	}
	m.applySegments(framed(steered(packet.ECT1, packet.ECT0), steered(packet.ECT1, packet.ECT0), steered(packet.NotECT, packet.CE), steered(packet.ECT0, packet.CE), steered(packet.ECT0, packet.ECT0)), DefaultMTU, nil)
	want := []record{{"ECT(0)", "ECT(1)", "1", hex.EncodeToString(plainHeader(t, packet.ECT1))}}
	if got := recordsOf(); !slices.Equal(got, want) {
		t.Fatalf("within one interval the records are %+v, want %+v", got, want)
	}
	if got := m.SegmentCounters(); got.ECNUnused != 3 || got.Delivered != 4 || got.Dropped != 1 {
		t.Errorf("two packets of an unused combination delivered and one dropped counted %+v, want 3 unused", got)
	}
	m.ecnUnused.next.Add(-int64(reportInterval))
	m.applySegments(framed(steered(packet.NotECT, packet.ECT1)), DefaultMTU, nil)
	want = append(want, record{"ECT(1)", "Not-ECT", "3", hex.EncodeToString(plainHeader(t, packet.NotECT))})
	if got := recordsOf(); !slices.Equal(got, want) {
		t.Errorf("an interval later the records are %+v, want %+v", got, want)
	}
}

// plainHeader is the packet the test above steers, an IPv6 header with its ECN field field and no payload
func plainHeader(t *testing.T, field packet.ECN) []byte {
	t.Helper()
	plain := plainV6(segAddr("3fff:a::1"), segAddr("3fff:a::2"), "")
	packet.SetECN(plain, field)
	return plain
}
