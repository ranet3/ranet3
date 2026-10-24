// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package srv6

import (
	"encoding/binary"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// edgeHeader is one extension header of a packet edgeChain lays out, of kind, with the routing type routing where it is a routing header
type edgeHeader struct{ kind, routing byte }

var (
	hopByHop = edgeHeader{kind: nextHeaderHopByHop}
	destOpts = edgeHeader{kind: nextHeaderDestOpts}
	fragHead = edgeHeader{kind: nextHeaderFragment}
)

func routingOf(kind byte) edgeHeader { return edgeHeader{kind: nextHeaderRouting, routing: kind} }

// edgeUDP is the protocol number of the UDP header edgeChain ends its chain in
const edgeUDP = 17

// edgeChain is an IPv6 packet whose extension headers are headers, 8 octets each and each naming the next, then a UDP header of 8 octets
// a hop-by-hop or destination options header is Pad1 options, a routing header has segments left 0, and a fragment header offset 0
func edgeChain(headers ...edgeHeader) []byte {
	raw := make([]byte, ipv6HeaderLen, ipv6HeaderLen+extensionUnit*(len(headers)+1))
	raw[0], raw[6], raw[7] = 0x60, edgeUDP, 64
	copy(raw[8:], addr16(addr("3fff:a::1")))
	copy(raw[24:], addr16(addr("3fff:b::2")))
	if len(headers) > 0 {
		raw[6] = headers[0].kind
	}
	for i, h := range headers {
		next := byte(edgeUDP)
		if i+1 < len(headers) {
			next = headers[i+1].kind
		}
		raw = append(raw, next, 0, h.routing, 0, 0, 0, 0, 0)
	}
	raw = append(raw, 0x0f, 0xa0, 0x13, 0x88, 0, 8, 0, 0)
	binary.BigEndian.PutUint16(raw[4:], uint16(len(raw)-ipv6HeaderLen))
	return raw
}

// checkEdge holds WalkEdge on raw to want, and on a pass to the next header at and the offset it stopped at
func checkEdge(tb testing.TB, name string, raw []byte, want EdgeVerdict, next byte, offset int) {
	tb.Helper()
	verdict, gotNext, gotOffset := WalkEdge(slices.Clip(raw))
	if verdict != want || want == EdgePass && (gotNext != next || gotOffset != offset) {
		tb.Errorf("%s walked to verdict %d at next header %d offset %d, want %d at %d offset %d", name, verdict, gotNext, gotOffset, want, next, offset)
	}
}

// a routing header behind one the walk passes is read as the first is, so a type 0 cannot hide behind a type 2, a hop-by-hop or destination options header
// and one behind a fragment header passes unexamined, the walk stopping at the fragment
func TestEdgeReadsEveryRoutingHeaderOfTheChain(t *testing.T) {
	for _, c := range []struct {
		name    string
		headers []edgeHeader
		want    EdgeVerdict
		next    byte
		offset  int
	}{
		{"a type 3 behind a type 2", []edgeHeader{routingOf(2), routingOf(3)}, EdgePass, edgeUDP, ipv6HeaderLen + 2*extensionUnit},
		{"a type 254 behind a type 253", []edgeHeader{routingOf(253), routingOf(254)}, EdgePass, edgeUDP, ipv6HeaderLen + 2*extensionUnit},
		{"a type 0 behind a type 2", []edgeHeader{routingOf(2), routingOf(0)}, EdgeRoutingHeader, 0, 0},
		{"a type 4 behind a type 3", []edgeHeader{routingOf(3), routingOf(4)}, EdgeRoutingHeader, 0, 0},
		{"a type 0 behind a hop-by-hop header", []edgeHeader{hopByHop, routingOf(0)}, EdgeRoutingHeader, 0, 0},
		{"a type 0 behind destination options", []edgeHeader{destOpts, routingOf(0)}, EdgeRoutingHeader, 0, 0},
		{"a type 4 behind both and a type 2", []edgeHeader{hopByHop, destOpts, routingOf(2), destOpts, routingOf(4)}, EdgeRoutingHeader, 0, 0},
		{"a type 0 behind a fragment header", []edgeHeader{fragHead, routingOf(0)}, EdgePass, nextHeaderFragment, ipv6HeaderLen},
		{"a type 0 behind a type 2 and a fragment header", []edgeHeader{routingOf(2), fragHead, routingOf(0)}, EdgePass, nextHeaderFragment, ipv6HeaderLen + extensionUnit},
		{"no extension header", nil, EdgePass, edgeUDP, ipv6HeaderLen},
	} {
		checkEdge(t, c.name, edgeChain(c.headers...), c.want, c.next, c.offset)
	}
}

// the walk's bound counts destination options headers as it counts the others, and a chain at the bound may end in a header the walk does not read
// the property sweeps the bound's edges over the other kinds
func TestEdgeBoundCountsEveryHeaderItReads(t *testing.T) {
	atBound := slices.Repeat([]edgeHeader{hopByHop, destOpts, routingOf(2), routingOf(253)}, maxEdgeHeaders/4)
	checkEdge(t, "17 destination options headers", edgeChain(slices.Repeat([]edgeHeader{destOpts}, maxEdgeHeaders+1)...), EdgeInvalid, 0, 0)
	checkEdge(t, "16 headers and a fragment header", edgeChain(append(atBound, fragHead)...), EdgePass, nextHeaderFragment, ipv6HeaderLen+extensionUnit*maxEdgeHeaders)
}

// a header the walk reads that claims more octets than the packet holds is invalid
func TestEdgeRefusesAHeaderLongerThanThePacket(t *testing.T) {
	long := edgeChain(destOpts)
	long[ipv6HeaderLen+1] = 2
	checkEdge(t, "a header claiming more octets than the packet holds", long, EdgeInvalid, 0, 0)
}

// a header the walk does not recognize, here the experimental 253 of RFC 4727, passes unexamined, as RFC 7045 section 2.1 asks
func TestEdgePassesAHeaderItDoesNotRecognize(t *testing.T) {
	unknown := edgeHeader{kind: 253}
	checkEdge(t, "a header of kind 253", edgeChain(unknown), EdgePass, 253, ipv6HeaderLen)
	checkEdge(t, "a header of kind 253 behind destination options", edgeChain(destOpts, unknown), EdgePass, 253, ipv6HeaderLen+extensionUnit)
}

// the walk runs on every IPv6 read off the tun, and allocates nothing however long the chain it reads
func TestEdgeWalkAllocatesNothing(t *testing.T) {
	raw := edgeChain(slices.Repeat([]edgeHeader{hopByHop, routingOf(2)}, maxEdgeHeaders/2)...)
	if allocs := testing.AllocsPerRun(100, func() { WalkEdge(raw) }); allocs != 0 {
		t.Errorf("the walk over %d headers allocated %v times", maxEdgeHeaders, allocs)
	}
}

// Holds names the SIDs of the table and nothing else, and a nil table, a node configuring no segments, names none
func TestLocalTableHoldsItsSIDsAlone(t *testing.T) {
	table, err := NewLocalTable([]Segment{
		{SID: saddr("3fff:5::1"), Behavior: BehaviorEndDT46},
		{SID: saddr("3fff:5::2"), Behavior: BehaviorEnd},
	}, []schema.Prefix{sprefix("3fff::/20")})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		address string
		want    bool
	}{{"3fff:5::1", true}, {"3fff:5::2", true}, {"3fff:5::3", false}, {"3fff::1", false}} {
		if got := table.Holds(addr(c.address)); got != c.want {
			t.Errorf("the table holds %s %t, want %t", c.address, got, c.want)
		}
	}
	var none *LocalTable
	if none.Holds(addr("3fff:5::1")) {
		t.Error("a nil table holds a SID")
	}
}

// the walk over a bare TCP packet and over a chain of the 16 headers it reads at most
func BenchmarkWalkEdge(b *testing.B) {
	// a TCP header of five words behind the fixed header
	tcp := slices.Concat(edgeChain()[:ipv6HeaderLen], make([]byte, 20))
	tcp[6], tcp[ipv6HeaderLen+12] = 6, 5<<4
	binary.BigEndian.PutUint16(tcp[4:], 20)
	for _, c := range []struct {
		name string
		raw  []byte
	}{
		{"bare TCP", tcp},
		{"16 headers", edgeChain(slices.Repeat([]edgeHeader{hopByHop, routingOf(2)}, maxEdgeHeaders/2)...)},
	} {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				WalkEdge(c.raw)
			}
		})
	}
}
