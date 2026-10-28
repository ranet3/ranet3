// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
)

// the clients a traced arm runs under at the default rate, one whose filter selects no packet of the arms by its prefixes, one selecting every packet
// and one asking for payload whose peer is neither end of any packet
var traceClientArms = []struct {
	name    string
	filter  TraceFilter
	payload int
}{
	{"filter matching nothing", TraceFilter{Destinations: []netip.Prefix{segPrefix("198.51.100.0/24"), segPrefix("2001:db8:ffff::/48")}}, 0},
	{"filter matching all", TraceFilter{}, 0},
	{"peer matching nothing asking payload", TraceFilter{Peer: "example/nobody"}, 64},
}

// traced opens a feed of filter on m at the default rate, each record carrying up to payload bytes, which a reader drains until the benchmark ends
func traced(b *testing.B, m *Mesh, filter TraceFilter, payload int) {
	b.Helper()
	feed, err := m.Trace(filter, payload, control.TraceRateDefault)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(feed.Close)
	go func() {
		for {
			select {
			case <-feed.Records():
			case <-feed.Done():
				return
			}
		}
	}()
}

// the decision's forwarded and delivered arms of BenchmarkDecide with a client listening, the cost of the trace while on
func BenchmarkDecideTraced(b *testing.B) {
	for _, c := range []struct {
		name   string
		packet []byte
	}{
		{"forwarded IPv4", udpPacket(transitSender[4], transitFar[4], 100, false)},
		{"forwarded IPv6", udpPacket(transitSender[6], transitFar[6], 100, false)},
		{"delivered IPv4", udpPacket(transitSender[4], transitOwn[4], 100, false)},
		{"delivered IPv6", udpPacket(transitSender[6], transitOwn[6], 100, false)},
	} {
		for _, client := range traceClientArms {
			b.Run(fmt.Sprintf("%s %s", c.name, client.name), func(b *testing.B) {
				m := benchTransitMesh(b)
				traced(b, m, client.filter, client.payload)
				benchmarkDecide(b, m, [][]byte{c.packet})
			})
		}
	}
}

// the plain arms of BenchmarkClassify with a client listening, the cost of the trace while on
func BenchmarkClassifyTraced(b *testing.B) {
	for _, arm := range classifyArms {
		if arm.shape != classifyPlain {
			continue
		}
		for _, client := range traceClientArms {
			b.Run(fmt.Sprintf("%s %s", arm.name, client.name), func(b *testing.B) {
				m, read := classifyRead(b, arm.family, arm.count, arm.sources, arm.shape)
				traced(b, m, client.filter, client.payload)
				inTurn := arm.count < arm.sources
				b.ReportAllocs()
				for b.Loop() {
					read.n = arm.count
					m.classify(read)
					read.reset()
					if inTurn {
						read.reads[0], read.reads[1] = read.reads[1], read.reads[0]
					}
				}
			})
		}
	}
}

// forwardedAllocs counts what decide allocates a run over BenchmarkDecide's forwarded batch of family, listen opening any feed first
// the peer is closed so its budget refuses every share and the sender allocates nothing, and leastAllocs leaves out what the runtime's own goroutines allocate
func forwardedAllocs(t *testing.T, family int, listen func(*Mesh)) float64 {
	t.Helper()
	m, _ := startTransitMesh(nil)
	t.Cleanup(m.Close)
	peer := NewPeer("bench", func(int) (BatchSealer, error) { return benchSealer, nil }, func([][]byte) error { return nil }, nil)
	peer.Close()
	for _, f := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[f]), peer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[f]), Local)
	}
	listen(m)
	raw := udpPacket(transitSender[family], transitFar[family], 100, false)
	batch := make([][]byte, decideBatch)
	for i := range batch {
		batch[i] = raw
	}
	frames := framed(batch...)
	return leastAllocs(func() {
		for _, frame := range frames {
			copy(frame[TUNHeadroom:], raw[:headerLen(raw)])
		}
		m.decide(frames, nil, nil)
	})
}

// with no client, decide over BenchmarkDecide's forwarded batch and classify over the plain reads of classifyArms allocate nothing a run
func TestUntracedDecisionAllocatesNothing(t *testing.T) {
	for _, family := range []int{4, 6} {
		if allocs := forwardedAllocs(t, family, func(*Mesh) {}); allocs != 0 {
			t.Errorf("IPv%d decide over a forwarded batch of %d allocated %v a run", family, decideBatch, allocs)
		}
	}
	for _, arm := range classifyArms {
		if arm.shape != classifyPlain {
			continue
		}
		m, read := classifyRead(t, arm.family, arm.count, arm.sources, arm.shape)
		if allocs := leastAllocs(func() {
			read.n = arm.count
			m.classify(read)
			read.reset()
		}); allocs != 0 {
			t.Errorf("classify over the read %s allocated %v a run", arm.name, allocs)
		}
	}
}

// endForwardedAllocs counts what a batch of decideBatch packets End forwards allocates a run, listen opening any feed first
// the next segment's peer is closed, so its budget refuses every share and the sender allocates nothing
func endForwardedAllocs(t *testing.T, listen func(*Mesh)) float64 {
	t.Helper()
	m, _ := egressMesh(t)
	routeClosed(m, segPrefix("3fff:b:0:206::/64"))
	listen(m)
	raw := headendSteered(udpPacket(tooBigSource[6], transitNowhere[6], 1000, false), egressWaypoint, egressNext)
	batch := make([][]byte, decideBatch)
	for i := range batch {
		batch[i] = raw
	}
	frames := framed(batch...)
	return leastAllocs(func() {
		for _, frame := range frames {
			copy(frame[TUNHeadroom:], raw)
		}
		m.DeliverInboundBatch(frames, DefaultMTU, nil)
	})
}

// a client asking for payload whose filter leaves out every forward at the hold, by a peer at neither end or a decision a forward never meets, allocates nothing over a forwarded batch
// over a batch End forwards, a client of another protocol, or one past its rate, allocates nothing more than no client does
// and a client of forwards alone reads nothing of a steered read's share its budget refused
func TestTracedDecisionCopiesNothingForAClientItLeavesOut(t *testing.T) {
	for _, filter := range []TraceFilter{{Peer: "example/nobody"}, {Decision: TraceDeliver}, {Decision: TraceEgress}} {
		for _, family := range []int{4, 6} {
			var feed *TraceFeed
			allocs := forwardedAllocs(t, family, func(m *Mesh) { feed = openTrace(t, m, filter, 64, control.TraceRateDefault) })
			if allocs != 0 || feed.Counts() != (TraceCounts{}) {
				t.Errorf("IPv%d decide under a client of %+v allocated %v a run and the feed counted %+v", family, filter, allocs, feed.Counts())
			}
		}
	}
	untraced := endForwardedAllocs(t, func(*Mesh) {})
	for _, c := range []struct {
		name    string
		filter  TraceFilter
		rate    int
		records bool
	}{
		{"of another protocol", TraceFilter{Protocol: 6}, control.TraceRateDefault, false},
		{"past its rate", TraceFilter{}, control.TraceRateMin, true},
	} {
		var feed *TraceFeed
		allocs := endForwardedAllocs(t, func(m *Mesh) { feed = openTrace(t, m, c.filter, 64, c.rate) })
		if allocs > untraced {
			t.Errorf("a batch End forwards under a client %s allocated %v a run, against %v under none", c.name, allocs, untraced)
		}
		if recorded := feed.Counts().Recorded; (recorded != 0) != c.records {
			t.Errorf("the client %s recorded %d of the batches End forwarded", c.name, recorded)
		}
	}
	m, read := classifyRead(t, 6, 1, 1, classifySteered)
	closed := routeClosed(m, segPrefix("3fff:1::/64"))
	openTrace(t, m, TraceFilter{Decision: TraceForward}, 64, control.TraceRateDefault)
	m.classify(read)
	trace := m.tracer.Load()
	if allocs := leastAllocs(func() { trace.refused(read, closed) }); allocs != 0 {
		t.Errorf("the budget drops of a steered read under a client of forwards alone allocated %v a run", allocs)
	}
}
