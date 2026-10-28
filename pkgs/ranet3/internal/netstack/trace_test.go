// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"testing"
)

// the peers a traced packet arrives from or goes to
var (
	traceGateway = &Peer{ID: "example/gateway"}
	traceLaptop  = &Peer{ID: "example/my-laptop"}
)

// traceMesh is a mesh with no tun, for its feeds alone
func traceMesh(t *testing.T) *Mesh {
	t.Helper()
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	t.Cleanup(m.Close)
	return m
}

func openTrace(t testing.TB, m *Mesh, filter TraceFilter, payload, rate int) *TraceFeed {
	t.Helper()
	feed, err := m.Trace(filter, payload, rate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(feed.Close)
	return feed
}

// emit records raw, decided as site says, through the tracer m holds now
func emit(m *Mesh, site traceSite, raw []byte) {
	if t := m.tracer.Load(); t != nil {
		t.record(site, raw)
	}
}

// queued is every record feed's queue holds
func queued(feed *TraceFeed) []TraceRecord {
	var records []TraceRecord
	for {
		select {
		case r := <-feed.Records():
			records = append(records, r)
		default:
			return records
		}
	}
}

func forwardedBy(from, next *Peer) traceSite {
	return traceSite{arrival: TraceArrivedSession, from: from, decision: TraceForward, next: next}
}

// withProtocol is raw, a UDP packet of either family, naming protocol instead
func withProtocol(raw []byte, protocol byte) []byte {
	out := bytes.Clone(raw)
	if out[0]>>4 == 6 {
		out[6] = protocol
	} else {
		out[9] = protocol
	}
	return out
}

// mapped is the IPv4-mapped IPv6 form of address
func mapped(address netip.Addr) netip.Addr { return netip.AddrFrom16(address.As16()) }

func TestTraceFilterSelectsByEachKind(t *testing.T) {
	for _, family := range []int{4, 6} {
		sender, far := transitSender[family], transitFar[family]
		senderNet, senderHost, farHost := netip.PrefixFrom(sender, sender.BitLen()-8).Masked(), hostPrefix(sender), hostPrefix(far)
		elsewhere := netip.PrefixFrom(transitNowhere[family], transitNowhere[family].BitLen()-8).Masked()
		udp := udpPacket(sender, far, 100, false)
		for _, c := range []struct {
			name   string
			filter TraceFilter
			raw    []byte
			site   traceSite
			want   bool
		}{
			{"no filter", TraceFilter{}, udp, forwardedBy(traceGateway, traceLaptop), true},
			{"the source's network", TraceFilter{Sources: []netip.Prefix{senderNet}}, udp, forwardedBy(nil, nil), true},
			{"another network as source", TraceFilter{Sources: []netip.Prefix{elsewhere}}, udp, forwardedBy(nil, nil), false},
			{"any one source prefix", TraceFilter{Sources: []netip.Prefix{elsewhere, senderNet}}, udp, forwardedBy(nil, nil), true},
			{"the destination", TraceFilter{Destinations: []netip.Prefix{farHost}}, udp, forwardedBy(nil, nil), true},
			{"the source as destination", TraceFilter{Destinations: []netip.Prefix{senderHost}}, udp, forwardedBy(nil, nil), false},
			{"the destination as source", TraceFilter{Sources: []netip.Prefix{farHost}}, udp, forwardedBy(nil, nil), false},
			{"source and destination both", TraceFilter{Sources: []netip.Prefix{senderHost}, Destinations: []netip.Prefix{farHost}}, udp, forwardedBy(nil, nil), true},
			{"the protocol", TraceFilter{Protocol: 17}, udp, forwardedBy(nil, nil), true},
			{"another protocol", TraceFilter{Protocol: 6}, udp, forwardedBy(nil, nil), false},
			{"the protocol of a TCP packet", TraceFilter{Protocol: 6}, withProtocol(udp, 6), forwardedBy(nil, nil), true},
			{"the decision", TraceFilter{Decision: TraceForward}, udp, forwardedBy(nil, nil), true},
			{"another decision", TraceFilter{Decision: TraceDrop}, udp, forwardedBy(nil, nil), false},
			{"the peer it arrived from", TraceFilter{Peer: traceGateway.ID}, udp, forwardedBy(traceGateway, traceLaptop), true},
			{"the peer it goes to", TraceFilter{Peer: traceLaptop.ID}, udp, forwardedBy(traceGateway, traceLaptop), true},
			{"another peer", TraceFilter{Peer: "example/other"}, udp, forwardedBy(traceGateway, traceLaptop), false},
			{"a peer for a packet of the tun", TraceFilter{Peer: traceGateway.ID}, udp, traceSite{arrival: TraceArrivedTUN, decision: TraceDrop, reason: transitForged}, false},
		} {
			t.Run(fmt.Sprintf("IPv%d %s", family, c.name), func(t *testing.T) {
				m := traceMesh(t)
				feed := openTrace(t, m, c.filter, 0, TraceRateMax)
				emit(m, c.site, c.raw)
				if got := len(queued(feed)); got != map[bool]int{true: 1, false: 0}[c.want] {
					t.Errorf("the feed took %d records, want selected %v", got, c.want)
				}
			})
		}
	}
	t.Run("an IPv4-mapped source under an IPv4 prefix", func(t *testing.T) {
		m := traceMesh(t)
		feed := openTrace(t, m, TraceFilter{Sources: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}, 0, TraceRateMax)
		emit(m, forwardedBy(nil, nil), udpPacket(mapped(transitSender[4]), transitFar[6], 100, false))
		emit(m, forwardedBy(nil, nil), udpPacket(transitSender[4], transitFar[4], 100, false))
		records := queued(feed)
		if len(records) != 1 || !records[0].Source.Is4() {
			t.Errorf("the feed took %+v, want the IPv4 packet alone", records)
		}
	})
}

// two clients share one tracer, each holding its own filter
func TestTraceClientsKeepTheirOwnFilters(t *testing.T) {
	m := traceMesh(t)
	toFar := openTrace(t, m, TraceFilter{Destinations: []netip.Prefix{hostPrefix(transitFar[4])}}, 0, TraceRateMax)
	toOwn := openTrace(t, m, TraceFilter{Destinations: []netip.Prefix{hostPrefix(transitOwn[4])}}, 0, TraceRateMax)
	emit(m, forwardedBy(nil, nil), udpPacket(transitSender[4], transitFar[4], 100, false))
	emit(m, traceSite{decision: TraceDeliver}, udpPacket(transitSender[4], transitOwn[4], 100, false))
	emit(m, traceSite{decision: TraceDeliver}, udpPacket(transitSender[4], transitOwn[4], 100, false))
	far, own := queued(toFar), queued(toOwn)
	if len(far) != 1 || far[0].Destination != transitFar[4] {
		t.Errorf("the client tracing far took %+v", far)
	}
	if len(own) != 2 || own[0].Destination != transitOwn[4] || own[1].Destination != transitOwn[4] {
		t.Errorf("the client tracing own took %+v", own)
	}
}

// the rate refuses past one second's worth, counts what it refused, and builds nothing for a refused packet
func TestTraceRateRefusesPastItsBurstAndBuildsNothing(t *testing.T) {
	m := traceMesh(t)
	feed := openTrace(t, m, TraceFilter{}, 64, TraceRateMin)
	raw := udpPacket(transitSender[4], transitFar[4], 100, false)
	site := forwardedBy(traceGateway, traceLaptop)
	for range 5 {
		emit(m, site, raw)
	}
	if got := len(queued(feed)); got != 1 {
		t.Errorf("a rate of %d a second took %d records at once, want 1", TraceRateMin, got)
	}
	if got := feed.Counts(); got != (TraceCounts{Recorded: 1, RefusedRate: 4}) {
		t.Errorf("the feed counted %+v", got)
	}
	if allocs := testing.AllocsPerRun(100, func() { emit(m, site, raw) }); allocs != 0 {
		t.Errorf("a packet past the rate allocated %v times", allocs)
	}
	if got := feed.Counts().RefusedRate; got < 4+100 {
		t.Errorf("the feed counted %d refused, want every packet past the first", got)
	}
}

// the queue refuses what it has no room for, and counts it apart from the rate's refusals
func TestTraceQueueRefusesPastItsLength(t *testing.T) {
	m := traceMesh(t)
	feed := openTrace(t, m, TraceFilter{}, 0, TraceRateMax)
	raw := udpPacket(transitSender[6], transitFar[6], 100, false)
	for range traceQueueLength + 10 {
		emit(m, forwardedBy(nil, nil), raw)
	}
	got := feed.Counts()
	if got.Recorded != traceQueueLength || got.RefusedQueue != 10 || got.RefusedRate != 0 {
		t.Errorf("the feed counted %+v, want %d recorded and 10 refused by the queue", got, traceQueueLength)
	}
}

// a record carries no payload unless asked, and one that asked carries the packet's first bytes, as many as asked and the packet holds
func TestTracePayloadOnlyWhenAsked(t *testing.T) {
	raw := udpPacket(transitSender[4], transitFar[4], 100, false)
	for _, payload := range []int{0, 1, 64, len(raw), TracePayloadMax} {
		m := traceMesh(t)
		feed := openTrace(t, m, TraceFilter{}, payload, TraceRateMax)
		packet := bytes.Clone(raw)
		emit(m, forwardedBy(nil, nil), packet)
		packet[30] ^= 0xff
		records := queued(feed)
		if len(records) != 1 {
			t.Fatalf("payload %d: the feed took %d records", payload, len(records))
		}
		want := raw[:min(payload, len(raw))]
		if payload == 0 {
			want = nil
		}
		if got := records[0].Payload; !bytes.Equal(got, want) || (got == nil) != (want == nil) {
			t.Errorf("payload %d: the record carries %x, want %x", payload, got, want)
		}
	}
}

// two clients asking for different payloads each get their own length
func TestTracePayloadIsEachClientsOwn(t *testing.T) {
	m := traceMesh(t)
	none := openTrace(t, m, TraceFilter{}, 0, TraceRateMax)
	some := openTrace(t, m, TraceFilter{}, 24, TraceRateMax)
	raw := udpPacket(transitSender[6], transitFar[6], 100, false)
	emit(m, forwardedBy(nil, nil), raw)
	if records := queued(none); len(records) != 1 || records[0].Payload != nil {
		t.Errorf("the client asking for none took %+v", records)
	}
	if records := queued(some); len(records) != 1 || !bytes.Equal(records[0].Payload, raw[:24]) {
		t.Errorf("the client asking for 24 bytes took %+v", records)
	}
}

// ipv6With is raw, an IPv6 UDP packet, behind the extension headers headers names, each 8 bytes and a fragment header at offset
func ipv6With(raw []byte, headers []byte, offset uint16) []byte {
	out := slices.Clone(raw[:40])
	next := raw[6]
	out[6] = next
	if len(headers) != 0 {
		out[6] = headers[0]
	}
	for i, header := range headers {
		following := next
		if i+1 < len(headers) {
			following = headers[i+1]
		}
		extension := make([]byte, 8)
		extension[0] = following
		if header == 44 {
			binary.BigEndian.PutUint16(extension[2:], offset<<3)
		}
		out = append(out, extension...)
	}
	out = append(out, raw[40:]...)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return out
}

func TestTraceRecordReadsThePacketsFields(t *testing.T) {
	udp4 := udpPacket(transitSender[4], transitFar[4], 100, false)
	udp6 := udpPacket(transitSender[6], transitFar[6], 120, false)
	tcp4 := tcpPacket(4, 0, false, synFlag|0x10, nil, 0, 10)
	icmp6 := withProtocol(udp6, 58)
	icmp6[40], icmp6[41] = 128, 0
	later4 := bytes.Clone(udp4)
	binary.BigEndian.PutUint16(later4[6:], 0x2000|3)
	for _, c := range []struct {
		name string
		raw  []byte
		want TraceRecord
	}{
		{"IPv4 UDP", udp4, TraceRecord{Protocol: 17, Transport: true, SourcePort: 4000, DestinationPort: 5000, HopLimit: 64, Length: 100}},
		{"IPv6 UDP", udp6, TraceRecord{Protocol: 17, Transport: true, SourcePort: 4000, DestinationPort: 5000, HopLimit: 64, Length: 120}},
		{"IPv4 TCP", tcp4, TraceRecord{Protocol: 6, Transport: true, SourcePort: binary.BigEndian.Uint16(tcp4[20:]), DestinationPort: binary.BigEndian.Uint16(tcp4[22:]), TCPFlags: synFlag | 0x10, HopLimit: tcp4[8], Length: len(tcp4)}},
		{"ICMPv6 echo", icmp6, TraceRecord{Protocol: 58, Transport: true, ICMPType: 128, HopLimit: 64, Length: 120}},
		{"IPv4 fragment past the first", later4, TraceRecord{Protocol: 17, HopLimit: 64, Length: 100}},
		{"IPv4 Record Route and Router Alert", withOptions(udp4, []byte{7, 7, 4, 0, 0, 0, 0, 1, 148, 4, 0, 0}), TraceRecord{Protocol: 17, Headers: []string{"record-route", "router-alert"}, Transport: true, SourcePort: 4000, DestinationPort: 5000, HopLimit: 64, Length: 112}},
		{"IPv6 behind hop-by-hop and a first fragment", ipv6With(udp6, []byte{0, 44}, 0), TraceRecord{Protocol: 17, Headers: []string{"hop-by-hop", "fragment"}, Transport: true, SourcePort: 4000, DestinationPort: 5000, HopLimit: 64, Length: 136}},
		{"IPv6 behind a later fragment", ipv6With(udp6, []byte{44}, 10), TraceRecord{Protocol: 17, Headers: []string{"fragment"}, HopLimit: 64, Length: 128}},
		{"IPv6 behind destination options cut short", ipv6With(udp6, []byte{60}, 0)[:44], TraceRecord{Protocol: 60, HopLimit: 64, Length: 44}},
		{"IPv6 behind destination options cut before their length", ipv6With(udp6, []byte{60}, 0)[:41], TraceRecord{Protocol: 60, HopLimit: 64, Length: 41}},
		{"IPv6 behind a fragment header cut short", ipv6With(udp6, []byte{44}, 0)[:44], TraceRecord{Protocol: 44, HopLimit: 64, Length: 44}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := traceMesh(t)
			feed := openTrace(t, m, TraceFilter{}, 0, TraceRateMax)
			emit(m, traceSite{arrival: TraceArrivedTUN, decision: TraceDeliver}, c.raw)
			records := queued(feed)
			if len(records) != 1 {
				t.Fatalf("the feed took %d records", len(records))
			}
			got := records[0]
			want := c.want
			want.Arrival, want.Decision = TraceArrivedTUN, TraceDeliver
			want.Source, want.Destination = tracedAddresses(c.raw)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("the record is %+v, want %+v", got, want)
			}
		})
	}
}

// emitters on 8 goroutines while clients open and close feeds in turn panic nothing, every feed's reader ends, and the mesh holds no tracer once the last closes
func TestTraceFeedsOpenAndCloseUnderEmitters(t *testing.T) {
	m := traceMesh(t)
	stop := make(chan struct{})
	var emitters, readers sync.WaitGroup
	for i := range 8 {
		emitters.Go(func() {
			raw := udpPacket(transitSender[4], transitFar[4], 100+i, false)
			for {
				select {
				case <-stop:
					return
				default:
				}
				emit(m, forwardedBy(traceGateway, traceLaptop), raw)
			}
		})
	}
	read := func(feed *TraceFeed) {
		readers.Go(func() {
			for {
				select {
				case <-feed.Records():
				case <-feed.Done():
					return
				}
			}
		})
	}
	for i := range 200 {
		feed, err := m.Trace(TraceFilter{}, i%3*16, TraceRateMax)
		if err != nil {
			t.Fatal(err)
		}
		read(feed)
		other, err := m.Trace(TraceFilter{Decision: TraceForward}, 0, TraceRateMin)
		if err != nil {
			t.Fatal(err)
		}
		read(other)
		feed.Close()
		other.Close()
		other.Close()
	}
	close(stop)
	emitters.Wait()
	readers.Wait()
	if tracer := m.tracer.Load(); tracer != nil {
		t.Errorf("the mesh holds a tracer of %d clients once every feed closed", len(tracer.clients))
	}
}

// closing the mesh ends every feed and leaves it holding no tracer
func TestMeshCloseEndsEveryFeed(t *testing.T) {
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{})}
	feed, err := m.Trace(TraceFilter{}, 0, TraceRateDefault)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()
	select {
	case <-feed.Done():
	default:
		t.Error("the feed is open once its mesh closed")
	}
	if m.TraceClients() != 0 {
		t.Errorf("the closed mesh holds %d feeds", m.TraceClients())
	}
	if _, err := m.Trace(TraceFilter{}, 0, TraceRateDefault); err == nil {
		t.Error("a closed mesh opened a feed")
	}
	feed.Close()
}

func TestTraceRefusesWhatItsBoundsLeaveOut(t *testing.T) {
	m := traceMesh(t)
	for _, c := range []struct {
		name          string
		filter        TraceFilter
		payload, rate int
	}{
		{"rate under the least", TraceFilter{}, 0, TraceRateMin - 1},
		{"rate over the most", TraceFilter{}, 0, TraceRateMax + 1},
		{"payload under none", TraceFilter{}, -1, TraceRateDefault},
		{"payload past the largest packet", TraceFilter{}, TracePayloadMax + 1, TraceRateDefault},
		{"a decision of none", TraceFilter{Decision: traceDecisionCount}, 0, TraceRateDefault},
		{"a prefix of none", TraceFilter{Sources: []netip.Prefix{{}}}, 0, TraceRateDefault},
	} {
		if feed, err := m.Trace(c.filter, c.payload, c.rate); err == nil {
			feed.Close()
			t.Errorf("%s: the feed opened", c.name)
		}
	}
	if m.TraceClients() != 0 {
		t.Errorf("the refusals left %d feeds", m.TraceClients())
	}
}

func TestTraceDecisionNamesParseBack(t *testing.T) {
	for decision := TraceDeliver; decision < traceDecisionCount; decision++ {
		if got, ok := ParseTraceDecision(decision.String()); !ok || got != decision {
			t.Errorf("ParseTraceDecision(%q) = %v %v", decision.String(), got, ok)
		}
	}
	for _, name := range []string{"", "any", "forwarded", "Drop"} {
		if got, ok := ParseTraceDecision(name); ok {
			t.Errorf("ParseTraceDecision(%q) = %v", name, got)
		}
	}
}
