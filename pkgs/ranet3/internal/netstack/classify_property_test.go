// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// steeredTo is a destination a steering policy of a conservingLeaf claims, through a first segment the peer routes
// strandedTo one a policy claims through a first segment held unreachable
var steeredTo, strandedTo = segAddr("3fff:5::9"), segAddr("3fff:9::9")

// readOutcome is a read the conservation property draws, of the families it applies to, and the field of TransitCounters it moves, none for one classify queues or cuts for its peer
type readOutcome struct {
	name     string
	families []int
	packet   func(family int) []byte
	field    string
}

// readOutcomes are every outcome classify gives a read off the tun
var readOutcomes = []readOutcome{
	{"queued", both, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], 100, false) }, ""},
	{"cut", v4, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, false) }, ""},
	{"steered", v6, func(int) []byte { return udpPacket(transitOwn[6], steeredTo, 100, false) }, ""},
	{"unparseable", v4, func(int) []byte { return []byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17} }, "Invalid"},
	{"unwalkable", v6, func(f int) []byte {
		cut := withRouting(udpPacket(transitOwn[f], transitFar[f], 100, false), 2)
		cut[41] = 255
		return cut
	}, "Invalid"},
	{"carrying another family", v6, func(int) []byte {
		mislabeled := encapsulated(transitOwn[6], edgeOtherSID, udpPacket(transitOwn[4], transitFar[4], 100, false))
		mislabeled[6] = esp.NextHeaderIPv6
		return mislabeled
	}, "Invalid"},
	{"multicast", both, func(f int) []byte {
		return udpPacket(transitOwn[f], map[int]netip.Addr{4: segAddr("224.0.0.1"), 6: segAddr("ff02::1")}[f], 100, false)
	}, "Multicast"},
	{"forged", both, func(f int) []byte { return udpPacket(transitSender[f], transitFar[f], 100, false) }, "Forged"},
	{"routing header", v6, func(f int) []byte { return withRouting(udpPacket(transitOwn[f], transitFar[f], 100, false), 4) }, "RoutingHeader"},
	{"sid", v6, func(f int) []byte { return udpPacket(transitOwn[f], edgeOwnSID, 100, false) }, "SID"},
	{"unowned source", both, func(f int) []byte { return udpPacket(edgeLAN[f], edgeInternet[f], 100, false) }, "UnownedSource"},
	{"nested", v6, func(int) []byte {
		return encapsulated(transitOwn[6], edgeOtherSID, encapsulated(transitOwn[4], transitFar[4], udpPacket(transitOwn[6], transitFar[6], 100, false)))
	}, "Nested"},
	{"looped", both, func(f int) []byte { return udpPacket(transitOwn[f], edgeAssigned[f], 100, false) }, "Looped"},
	{"written back", both, func(f int) []byte { return udpPacket(transitOwn[f], edgeHeld[f], 100, false) }, "Delivered"},
	{"held", both, func(f int) []byte { return udpPacket(transitOwn[f], transitHeldHost[f], 100, false) }, "Held"},
	{"stranded", v6, func(int) []byte { return udpPacket(transitOwn[6], strandedTo, 100, false) }, "NoRoute"},
	{"too big", v6, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, false) }, "TooBig"},
	{"too big with DF", v4, func(f int) []byte { return udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, true) }, "TooBig"},
	{"too big unanswerable", v6, func(int) []byte { return icmpv6Error(transitOwn[6], transitFar[6], tracedMTU+100) }, "TooBig"},
	{"uncut", v4, func(f int) []byte { return badChecksum(udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, false)) }, "TooBig"},
	{"options at fault", v4, func(f int) []byte {
		return withOptions(udpPacket(transitOwn[f], transitFar[f], tracedMTU+100, false), []byte{7, 9, 4, 0})
	}, "Invalid"},
	{"unencapsulable", v6, func(int) []byte { return udpPacket(transitOwn[6], steeredTo, unencapsulable, false) }, "TooBig"},
}

// conservingLeaf is carriedLeaf with its peer carrying tracedMTU, its tun holding edgeHeld, and two cap.segment steer policies, toward steeredTo through edgeOtherSID and toward strandedTo through a hold
func conservingLeaf(tb testing.TB) *Mesh {
	tb.Helper()
	m, peer := carriedLeaf(tb)
	peer.SetMTU(tracedMTU)
	m.SetAnswerTTL(64)
	holdOwn(m)
	steering, err := srv6.NewSteerTable([]srv6.Steer{
		{To: schema.PrefixFrom(netip.PrefixFrom(steeredTo, 48).Masked()), Via: []schema.Addr{schema.AddrFrom(edgeOtherSID)}},
		{To: schema.PrefixFrom(netip.PrefixFrom(strandedTo, 48).Masked()), Via: []schema.Addr{schema.MustAddr("3fff:8::1")}},
	}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		tb.Fatal(err)
	}
	m.SetSteering(steering)
	m.Routes.Set(netip.Prefix{}, segPrefix("3fff:8::/48"), Unreachable)
	return m
}

// over drawn reads off the tun of every outcome classify gives, one read moves exactly one of the counters a read can move
// the reads in are the transit drops, by the reason each kind meets, the reads written back to an address the tun holds, counted delivered
// and the reads classify queued or cut for their peer, which the peer's own counters take from there
// a read cut into fragments counting once, by its first fragment
func TestClassifyCountsEveryReadOnce(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := conservingLeaf(ht)
		var packets [][]byte
		want := map[string]uint64{}
		giant := false
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			kind := readOutcomes[hegel.Draw(ht, pbt.Spanning(0, len(readOutcomes)-1))]
			// the slab of a read holds one read too large to encapsulate beside the others
			if kind.name == "unencapsulable" {
				if giant {
					continue
				}
				giant = true
			}
			family := kind.families[hegel.Draw(ht, pbt.Spanning(0, len(kind.families)-1))]
			packets = append(packets, kind.packet(family))
			want[kind.field]++
		}
		b := newOutboundBatch(len(packets))
		fill(b, packets...)
		m.classify(b)
		queuedReads, cutReads := 0, 0
		for _, peer := range b.peers[:len(packets)] {
			if peer != nil {
				queuedReads++
			}
		}
		for _, fragment := range b.cut.fragments {
			if binary.BigEndian.Uint16(fragment.raw[6:])&0x1fff == 0 {
				cutReads++
			}
		}
		counters := m.TransitCounters()
		var dropped uint64
		for _, drop := range control.TransitCounters(counters).Drops() {
			dropped += drop.Packets
		}
		if moved := dropped + counters.Delivered + uint64(queuedReads+cutReads); moved != uint64(len(packets)) {
			ht.Fatalf("%d reads moved %d drops, %d delivered, %d queued and %d cut, %+v", len(packets), dropped, counters.Delivered, queuedReads, cutReads, counters)
		}
		if uint64(queuedReads+cutReads) != want[""] {
			ht.Fatalf("%d reads to be queued or cut, %d queued and %d cut", want[""], queuedReads, cutReads)
		}
		fields := reflect.ValueOf(counters)
		for field, n := range want {
			if field == "" {
				continue
			}
			if got := fields.FieldByName(field).Uint(); got != n {
				ht.Fatalf("%d reads to be counted %s counted %d, %+v", n, field, got, counters)
			}
		}
	})
}
