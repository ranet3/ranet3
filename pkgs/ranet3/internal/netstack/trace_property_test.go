// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// modelContains is prefix holding address bit by bit, an address of the other family or an IPv4-mapped one under an IPv4 prefix held by none
func modelContains(prefix netip.Prefix, address netip.Addr) bool {
	if !address.IsValid() || prefix.Addr().Is4() != address.Is4() {
		return false
	}
	want, got := prefix.Addr().AsSlice(), address.AsSlice()
	for bit := range prefix.Bits() {
		if want[bit/8]>>(7-bit%8)&1 != got[bit/8]>>(7-bit%8)&1 {
			return false
		}
	}
	return true
}

func modelWithin(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if modelContains(prefix, address) {
			return true
		}
	}
	return len(prefixes) == 0
}

// modelSelects is the filter as TraceFilter's fields describe it, for a packet of protocol from src to dst decided as site says
func modelSelects(filter TraceFilter, src, dst netip.Addr, protocol uint8, site traceSite) bool {
	peered := filter.Peer == ""
	for _, peer := range []*Peer{site.from, site.next} {
		peered = peered || slices.Contains(tracePeerNames[peer], filter.Peer)
	}
	return modelWithin(filter.Sources, src) && modelWithin(filter.Destinations, dst) &&
		(filter.Protocol == 0 || filter.Protocol == protocol) &&
		(filter.Decision == TraceAny || filter.Decision == site.decision) && peered
}

// the addresses a drawn packet and a drawn prefix start from, of each family and an IPv4-mapped one
var traceAnchors = []netip.Addr{transitSender[4], transitFar[4], transitNowhere[4], transitSender[6], transitFar[6], transitNowhere[6], mapped(transitSender[4]), mapped(transitFar[4])}

func drawPrefixes(tc hegel.TestCase) []netip.Prefix {
	var prefixes []netip.Prefix
	for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
		anchor := hegel.Draw(tc, hegel.SampledFrom(traceAnchors))
		prefixes = append(prefixes, netip.PrefixFrom(anchor, hegel.Draw(tc, pbt.Spanning(0, anchor.BitLen()))).Masked())
	}
	return prefixes
}

var tracePeers = []*Peer{nil, traceGateway, traceLaptop, traceSession}

// tracePeerNames is every name a filter selects each peer by, written out by hand
var tracePeerNames = map[*Peer][]string{
	traceGateway: {"example/gateway", "gateway"},
	traceLaptop:  {"example/my-laptop", "my-laptop"},
	traceSession: {"example/relay:2@1", "example/relay:2", "example/relay", "relay"},
}

// over drawn clients and drawn packets of either family, each decided as a drawn site says, each client's feed takes exactly the packets its filter selects, in order, while its rate allows
// a rate of a few a second allows the first that many, since a case runs well inside the interval one record takes to come back
func TestTraceRecordsExactlyThePacketsTheFilterSelects(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
		defer m.Close()
		type client struct {
			filter TraceFilter
			rate   int
			feed   *TraceFeed
		}
		var clients []client
		for range hegel.Draw(ht, pbt.Spanning(1, 3)) {
			c := client{
				filter: TraceFilter{
					Sources:      drawPrefixes(ht),
					Destinations: drawPrefixes(ht),
					Protocol:     hegel.Draw(ht, hegel.SampledFrom([]uint8{0, 6, 17, 58})),
					Decision:     TraceDecision(hegel.Draw(ht, pbt.Spanning(0, int(traceDecisionCount)-1))),
					Peer:         hegel.Draw(ht, hegel.SampledFrom([]string{"", "example/gateway", "gateway", "my-laptop", "example/relay:2@1", "example/relay:2", "example/relay", "relay", "example/relay:3", "1", "example/other"})),
				},
				rate: hegel.Draw(ht, hegel.SampledFrom([]int{control.TraceRateMin, 2, 8, control.TraceRateMax})),
			}
			feed, err := m.Trace(c.filter, 0, c.rate)
			if err != nil {
				ht.Fatal(err)
			}
			c.feed = feed
			clients = append(clients, c)
		}
		type sent struct {
			src, dst netip.Addr
			site     traceSite
		}
		want := make([][]sent, len(clients))
		for range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			src := hegel.Draw(ht, hegel.SampledFrom(traceAnchors))
			dst := hegel.Draw(ht, hegel.SampledFrom(traceAnchors))
			if src.Is4() != dst.Is4() {
				continue
			}
			protocol := hegel.Draw(ht, hegel.SampledFrom([]uint8{6, 17, 58}))
			site := traceSite{
				arrival:  TraceArrivedSession,
				from:     hegel.Draw(ht, hegel.SampledFrom(tracePeers)),
				decision: TraceDecision(hegel.Draw(ht, pbt.Spanning(1, int(traceDecisionCount)-1))),
				next:     hegel.Draw(ht, hegel.SampledFrom(tracePeers)),
				reason:   transitNoRoute,
			}
			emit(m, site, withProtocol(udpPacket(src, dst, 100, false), protocol))
			for i, c := range clients {
				if modelSelects(c.filter, src, dst, protocol, site) && len(want[i]) < c.rate {
					want[i] = append(want[i], sent{src, dst, site})
				}
			}
		}
		for i, c := range clients {
			got := queued(c.feed)
			if len(got) != len(want[i]) {
				ht.Fatalf("client %d of filter %+v at rate %d took %d records, want %d", i, c.filter, c.rate, len(got), len(want[i]))
			}
			for j, r := range got {
				w := want[i][j]
				if r.Source != w.src || r.Destination != w.dst || r.Decision != w.site.decision {
					ht.Fatalf("client %d record %d is %v to %v %v, want %v to %v %v", i, j, r.Source, r.Destination, r.Decision, w.src, w.dst, w.site.decision)
				}
			}
		}
	})
}
