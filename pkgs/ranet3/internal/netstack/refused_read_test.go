// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// readResult holds what one read off the tun did on a fresh mesh: the name of the recording peer that took packets and the packets it took, every packet the tun took, the counters
// the trace's records where traced, ExplainRead's account, and the peer sessionToward names
type readResult struct {
	to        string
	sent      [][]byte
	written   [][]byte
	counted   TransitCounters
	records   []TraceRecord
	explained Explanation
	toward    string
}

// namedPeers are the recording peers a mesh's table routes to, by name
type namedPeers map[string]*recordingPeer

// peer is a recording peer named name, kept in p
func (p namedPeers) peer(t testing.TB, name string) *Peer {
	r := &recordingPeer{}
	p[name] = r
	return r.peer(t, name)
}

// readOn classifies raw as the one read of a mesh build makes, traced where traced is set, and sends the batch as the tun reader does
func readOn(t testing.TB, build func(testing.TB, namedPeers) (*Mesh, *recordingDevice), raw []byte, traced bool) readResult {
	t.Helper()
	peers := namedPeers{}
	m, dev := build(t, peers)
	var out readResult
	out.explained = m.ExplainRead(raw)
	src, dst, _, _ := addrsOf(raw)
	if peer := m.sessionToward(m.Steering(), src, dst); peer != nil {
		out.toward = peer.ID
	}
	var feed *TraceFeed
	if traced {
		feed = openTrace(t, m, TraceFilter{}, 0, control.TraceRateMax)
	}
	b := newOutboundBatch(1)
	fill(b, raw)
	m.classify(b)
	// one worker drains the batch before the peers are read, as the mesh's own workers do
	m.outboundJobs, m.outboundFree = make(chan *outboundBatch, 1), make(chan *outboundBatch, 1)
	m.dispatchOutbound(b)
	close(m.outboundJobs)
	m.outboundWorkerWG.Add(1)
	m.outboundWorker()
	for _, name := range slices.Sorted(maps.Keys(peers)) {
		if sent := peers[name].packets(t); len(sent) != 0 {
			out.to = strings.TrimPrefix(out.to+","+name, ",")
			out.sent = append(out.sent, sent...)
		}
	}
	for done := false; !done; {
		select {
		case write := <-dev.writes:
			out.written = append(out.written, write.packets...)
		default:
			done = true
		}
	}
	out.counted = m.TransitCounters()
	if feed != nil {
		out.records = queued(feed)
	}
	return out
}

// readMesh is unroutedMesh with route on the peer named peer, the tun holding ownSource, ownedOnly as given, and room in the tun for a write-back and an answer
func readMesh(route string, ownedOnly bool) func(testing.TB, namedPeers) (*Mesh, *recordingDevice) {
	return func(t testing.TB, peers namedPeers) (*Mesh, *recordingDevice) {
		m, dev := unroutedMesh(t, func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix(route), peers.peer(t, "peer"))
		})
		dev.writes = make(chan recordedWrite, 2)
		m.SetTunAddresses([]netip.Addr{ownSource[4], ownSource[6]})
		m.ownedOnly = ownedOnly
		return m, dev
	}
}

// carrying is inner behind a bare IPv6 header from src to dst, next header 41, RFC 2473
func carrying(src, dst netip.Addr, inner []byte) []byte {
	raw := make([]byte, 40+len(inner))
	raw[0] = 0x60
	binary.BigEndian.PutUint16(raw[4:6], uint16(len(inner)))
	raw[6], raw[7] = 41, 64
	copy(raw[8:24], src.AsSlice())
	copy(raw[24:40], dst.AsSlice())
	copy(raw[40:], inner)
	return raw
}

// what a read of the table below is to meet
type readWant int

const (
	// readDropped is a read no router forwards, dropped with no answer and counted martian alone
	readDropped readWant = iota
	// readForwarded is a read the peer takes as it came, counting nothing
	readForwarded
	// readBeyondScope is a read from an IPv6 link-local source to a destination a router forwards, answered code 2 into the tun
	readBeyondScope
	// readGroup is a read to a group or the limited broadcast, counted multicast
	readGroup
	// readUnowned is a read the edge drops for a source this node does not own, counted unowned_source
	readUnowned
)

// a read off the tun from a source or to a destination no router forwards reaches no peer, gets no answer and counts martian alone
// under a route counting as no default and under a default, ownedOnly or not, traced or not, its record and ExplainRead naming a drop for martian
// whether its source is this node's own or one it does not own, so the unowned-source check leaves it to the rule
// the sources are ::1, ::, the IPv4-mapped form, a multicast address, 169.254/16, network 0, class E, an IPv4 group and the limited broadcast
// the destinations ::, ::1 and 127.0.0.1 the tun does not hold, an IPv4-mapped one, the mapped limited broadcast and loopback, 169.254/16, class E and network 0
// and a read from fe80::9 to :: or a mapped address draws no answer, the code 2 answer being for a destination a router forwards
// beside them, outside the rule: one between two addresses a router forwards leaves, one from fe80::9 to such an address is answered code 2
// one to a group is multicast, a native or mapped one and the limited broadcast
// and an IPv6 read carrying a packet to or from ::1 or of link scope leaves, the rule being the outer header's
// but under ownedOnly where the carried packet's source is not this node's, which the edge drops unowned_source
func TestTunReadNoRouterForwardsReachesNoPeerAndIsCountedMartian(t *testing.T) {
	own4, own6 := ownSource[4], ownSource[6]
	ll := segAddr("fe80::9")
	// what a read meets under ownedOnly where it differs
	underOwnedOnly := map[string]readWant{"carrying a packet from ::1": readUnowned, "carrying a packet of link scope": readUnowned}
	for _, c := range []struct {
		name               string
		raw                []byte
		specific, fallback string
		want               readWant
	}{
		{"from ::1", udpPacket(segAddr("::1"), segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readDropped},
		{"from 127.0.0.1", udpPacket(segAddr("127.0.0.1"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"from ::", udpPacket(segAddr("::"), segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readDropped},
		{"from an IPv4-mapped address", udpPacket(segAddr("::ffff:192.0.2.1"), segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readDropped},
		{"from ff0e::1", udpPacket(segAddr("ff0e::1"), segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readDropped},
		{"from 169.254.1.1", udpPacket(segAddr("169.254.1.1"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"from 0.0.0.1", udpPacket(segAddr("0.0.0.1"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"from 240.0.0.1", udpPacket(segAddr("240.0.0.1"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"from 224.0.0.1", udpPacket(segAddr("224.0.0.1"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"from 255.255.255.255", udpPacket(segAddr("255.255.255.255"), segAddr("198.51.100.9"), 200, false), "198.51.100.0/24", "0.0.0.0/0", readDropped},
		{"to ::", udpPacket(own6, segAddr("::"), 200, false), "::/128", "::/0", readDropped},
		{"to an IPv4-mapped address", udpPacket(own6, segAddr("::ffff:198.51.100.9"), 200, false), "::ffff:0:0/96", "::/0", readDropped},
		{"to the mapped limited broadcast", udpPacket(own6, segAddr("::ffff:255.255.255.255"), 200, false), "::ffff:0:0/96", "::/0", readDropped},
		{"to the mapped loopback", udpPacket(own6, segAddr("::ffff:127.0.0.1"), 200, false), "::ffff:0:0/96", "::/0", readDropped},
		{"to 169.254.1.1", udpPacket(own4, segAddr("169.254.1.1"), 200, false), "169.254.0.0/16", "0.0.0.0/0", readDropped},
		{"to 240.0.0.1", udpPacket(own4, segAddr("240.0.0.1"), 200, false), "240.0.0.0/4", "0.0.0.0/0", readDropped},
		{"to 0.0.0.1", udpPacket(own4, segAddr("0.0.0.1"), 200, false), "0.0.0.0/8", "0.0.0.0/0", readDropped},
		{"from fe80::9 to ::", udpPacket(ll, segAddr("::"), 200, false), "::/128", "::/0", readDropped},
		{"from fe80::9 to an IPv4-mapped address", udpPacket(ll, segAddr("::ffff:198.51.100.9"), 200, false), "::ffff:0:0/96", "::/0", readDropped},
		{"to ::1 the tun does not hold", udpPacket(own6, segAddr("::1"), 200, false), "::1/128", "::/0", readDropped},
		{"to 127.0.0.1 the tun does not hold", udpPacket(own4, segAddr("127.0.0.1"), 200, false), "127.0.0.0/8", "0.0.0.0/0", readDropped},
		{"between two addresses a router forwards", udpPacket(own6, segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readForwarded},
		{"from fe80::9 to an address a router forwards", udpPacket(ll, segAddr("3fff::2"), 200, false), "3fff::/16", "::/0", readBeyondScope},
		{"to a mapped group", udpPacket(own6, segAddr("::ffff:224.0.0.1"), 200, false), "::ffff:0:0/96", "::/0", readGroup},
		{"to ff0e::1", udpPacket(own6, segAddr("ff0e::1"), 200, false), "ff00::/8", "::/0", readGroup},
		{"to the limited broadcast", udpPacket(own4, segAddr("255.255.255.255"), 200, false), "255.255.255.255/32", "0.0.0.0/0", readGroup},
		{"carrying a packet to ::1", carrying(own6, segAddr("3fff::2"), udpPacket(own6, segAddr("::1"), 200, false)), "3fff::/16", "3fff::/16", readForwarded},
		{"carrying a packet from ::1", carrying(own6, segAddr("3fff::2"), udpPacket(segAddr("::1"), segAddr("3fff::9"), 200, false)), "3fff::/16", "3fff::/16", readForwarded},
		{"carrying a packet of link scope", carrying(own6, segAddr("3fff::2"), udpPacket(ll, segAddr("ff02::5"), 200, false)), "3fff::/16", "3fff::/16", readForwarded},
	} {
		for _, route := range []string{c.specific, c.fallback} {
			for _, ownedOnly := range []bool{false, true} {
				for _, traced := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s under %s, ownedOnly %t, traced %t", c.name, route, ownedOnly, traced), func(t *testing.T) {
						got := readOn(t, readMesh(route, ownedOnly), c.raw, traced)
						want := c.want
						if unowned, ok := underOwnedOnly[c.name]; ok && ownedOnly {
							want = unowned
						}
						checkRead(t, c.raw, want, got, traced)
					})
				}
			}
		}
	}
}

// checkRead holds got, what raw did, to want
func checkRead(t *testing.T, raw []byte, want readWant, got readResult, traced bool) {
	t.Helper()
	var decision TraceDecision
	var reason, answer string
	switch want {
	case readDropped:
		decision, reason = TraceDrop, "martian"
		if got.to != "" || len(got.written) != 0 || got.counted != (TransitCounters{Martian: 1}) {
			t.Errorf("the read went to %q, put %d packets into the tun and counted %+v, want no peer, nothing and martian alone", got.to, len(got.written), got.counted)
		}
	case readForwarded:
		decision = TraceForward
		if got.to != "peer" || len(got.sent) != 1 || !bytes.Equal(got.sent[0], raw) || len(got.written) != 0 || got.counted != (TransitCounters{}) {
			t.Errorf("the read went to %q as %d packets, put %d packets into the tun and counted %+v, want the peer to take it as it came and nothing counted", got.to, len(got.sent), len(got.written), got.counted)
		}
	case readBeyondScope:
		decision, reason, answer = TraceAnswer, "martian", "beyond_scope"
		if got.to != "" || len(got.written) != 1 || got.counted != (TransitCounters{Martian: 1, Answered: 1}) {
			t.Fatalf("the read went to %q, put %d packets into the tun and counted %+v, want its code 2 answer alone", got.to, len(got.written), got.counted)
		}
		_, dst, _, _ := addrsOf(raw)
		checkICMPv6(t, got.written[0], raw, dst, 1, 2, 0)
	case readGroup:
		decision, reason = TraceDrop, "multicast"
		if got.to != "" || len(got.written) != 0 || got.counted != (TransitCounters{Multicast: 1}) {
			t.Errorf("the read went to %q, put %d packets into the tun and counted %+v, want multicast alone", got.to, len(got.written), got.counted)
		}
	case readUnowned:
		decision, reason = TraceDrop, "unowned_source"
		if got.to != "" || len(got.written) != 0 || got.counted != (TransitCounters{UnownedSource: 1}) {
			t.Errorf("the read went to %q, put %d packets into the tun and counted %+v, want unowned_source alone", got.to, len(got.written), got.counted)
		}
	}
	if got.explained.Decision != decision || got.explained.Reason != reason || got.explained.Answer != answer {
		t.Errorf("ExplainRead names %v %q answering %q, want %v %q answering %q", got.explained.Decision, got.explained.Reason, got.explained.Answer, decision, reason, answer)
	}
	if traced && (len(got.records) != 1 || got.records[0].Decision != decision || got.records[0].Reason != reason || got.records[0].Answer != answer) {
		t.Errorf("the trace took %+v, want one record of %v %q answering %q", got.records, decision, reason, answer)
	}
}

// a read off the tun dropped for an address no router forwards records netstack.transit.dropped as the edge's drops do, through the same report
// naming martian and the read's source and destination, at most once an interval with the edge's drops, the counters keeping the count
func TestTunReadNoRouterForwardsRecordsTheDropEventOnceAnInterval(t *testing.T) {
	m, _ := readMesh("::/0", false)(t, namedPeers{})
	bus := events.New()
	m.events = bus.Emit
	classifiedTo(m,
		udpPacket(segAddr("::1"), segAddr("3fff::2"), 200, false),
		udpPacket(segAddr("ff0e::1"), segAddr("3fff::2"), 200, false),
		udpPacket(segAddr("2001:db8::77"), segAddr("3fff::2"), 200, false))
	if got := m.TransitCounters(); got != (TransitCounters{Martian: 2, UnownedSource: 1}) {
		t.Errorf("the reads counted %+v, want two martian and one unowned_source", got)
	}
	recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.transit.dropped" }, 0)
	if len(recorded) != 1 {
		t.Fatalf("three reads dropped in one interval recorded %d drop events, want one", len(recorded))
	}
	for key, value := range map[string]string{"reason": "martian", "src": "::1", "dst": "3fff::2"} {
		if got := recorded[0].Attrs[key]; got != value {
			t.Errorf("the event of a read from ::1 holds %s %v, want %s", key, got, value)
		}
	}
}

// heldRead is a read to an address the tun holds, steered where steerTo is written, through a first segment a route of its own carries to the peer named segment
func heldRead(steerTo string, ownedOnly, heldLoopback bool) func(testing.TB, namedPeers) (*Mesh, *recordingDevice) {
	return func(t testing.TB, peers namedPeers) (*Mesh, *recordingDevice) {
		m, dev := unroutedMesh(t, func(r *RouteTable) {
			r.Set(netip.Prefix{}, segPrefix("3fff:1::/64"), peers.peer(t, "segment"))
			if heldLoopback {
				r.Set(netip.Prefix{}, segPrefix("::1/128"), Local)
			}
		})
		dev.writes = make(chan recordedWrite, 2)
		held := []netip.Addr{ownSource[4], ownSource[6]}
		if heldLoopback {
			held = append(held, segAddr("::1"))
		}
		m.SetTunAddresses(held)
		m.ownedOnly = ownedOnly
		if steerTo != "" {
			steering, err := srv6.NewSteerTable([]srv6.Steer{{To: schema.PrefixFrom(segPrefix(steerTo)), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:b:0:100::1"))
			if err != nil {
				t.Fatal(err)
			}
			m.SetSteering(steering)
		}
		return m, dev
	}
}

// a read to an address the tun holds whose source or destination no router forwards goes back into the tun even where a steer claims it
// so neither ::1 nor fe80::9 as its source, nor a held ::1 as its destination, crosses a session inside the steer's outer packet
// it is counted delivered, its record and ExplainRead name a delivery and no policy, and sessionToward names no peer, as classify sends it to none
// beside it, outside the rule: one between addresses a router forwards leaves inside its steer, the steer's first segment's peer taking it
// under ownedOnly one from a source this node does not own is dropped unowned_source, steered or not
// and one with no steer is written back, from ::1, 127.0.0.1 or fe80::9, or to a held ::1 with ownedOnly off and on
func TestTunReadToAHeldAddressNoRouterForwardsIsWrittenBackUnsteered(t *testing.T) {
	own4, own6, lo6, ll := ownSource[4], ownSource[6], segAddr("::1"), segAddr("fe80::9")
	type outcome int
	const (
		writtenBack outcome = iota
		steered
		unowned
	)
	for _, c := range []struct {
		name string
		raw  []byte
		mesh func(testing.TB, namedPeers) (*Mesh, *recordingDevice)
		want outcome
	}{
		{"from ::1, steered", udpPacket(lo6, own6, 200, false), heldRead("3fff::1/128", false, false), writtenBack},
		{"to a held ::1, steered", udpPacket(own6, lo6, 200, false), heldRead("::1/128", false, true), writtenBack},
		{"to a held ::1, steered, ownedOnly", udpPacket(own6, lo6, 200, false), heldRead("::1/128", true, true), writtenBack},
		{"from fe80::9, steered", udpPacket(ll, own6, 200, false), heldRead("3fff::1/128", false, false), writtenBack},
		{"between addresses a router forwards, steered", udpPacket(own6, own6, 200, false), heldRead("3fff::1/128", false, false), steered},
		{"between addresses a router forwards, steered, ownedOnly", udpPacket(own6, own6, 200, false), heldRead("3fff::1/128", true, false), steered},
		{"from ::1, ownedOnly", udpPacket(lo6, own6, 200, false), heldRead("", true, false), unowned},
		{"from ::1, steered, ownedOnly", udpPacket(lo6, own6, 200, false), heldRead("3fff::1/128", true, false), unowned},
		{"from fe80::9, steered, ownedOnly", udpPacket(ll, own6, 200, false), heldRead("3fff::1/128", true, false), unowned},
		{"from ::1", udpPacket(lo6, own6, 200, false), heldRead("", false, false), writtenBack},
		{"from 127.0.0.1", udpPacket(segAddr("127.0.0.1"), own4, 200, false), heldRead("", false, false), writtenBack},
		{"from fe80::9", udpPacket(ll, own6, 200, false), heldRead("", false, false), writtenBack},
		{"to a held ::1", udpPacket(own6, lo6, 200, false), heldRead("", false, true), writtenBack},
		{"to a held ::1, ownedOnly", udpPacket(own6, lo6, 200, false), heldRead("", true, true), writtenBack},
	} {
		for _, traced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, traced %t", c.name, traced), func(t *testing.T) {
				// the tun completes no checksum of a write, so the IPv6 reads carry a whole one, and IPv4 UDP may carry none
				raw := c.raw
				if raw[0]>>4 == 6 {
					raw = withTransportSum(raw, false)
				}
				got := readOn(t, c.mesh, raw, traced)
				var decision TraceDecision
				var reason string
				switch c.want {
				case writtenBack:
					decision = TraceDeliver
					if got.to != "" || len(got.written) != 1 || got.counted != (TransitCounters{Delivered: 1}) || got.toward != "" {
						t.Fatalf("the read went to %q, put %d packets into the tun, counted %+v and sessionToward names %q, want it written back and no peer", got.to, len(got.written), got.counted, got.toward)
					}
					if !bytes.Equal(got.written[0], raw) {
						t.Errorf("the tun took %x, want the read unchanged", got.written[0])
					}
					if got.explained.Policy != nil {
						t.Errorf("ExplainRead names the policy %v for a read written back", got.explained.Policy)
					}
				case steered:
					decision = TraceForward
					if got.to != "segment" || len(got.sent) != 1 || len(got.written) != 0 || got.toward != "segment" || got.explained.Policy == nil {
						t.Fatalf("the read went to %q as %d packets, put %d packets into the tun, sessionToward names %q and ExplainRead the policy %v, want the steer's first segment", got.to, len(got.sent), len(got.written), got.toward, got.explained.Policy)
					}
					if outer, first := addressesOf(got.sent[0], 6); first != segAddr("3fff:1::1") || !bytes.HasSuffix(got.sent[0], raw) {
						t.Errorf("the steer's peer took a packet from %s to %s, want the read inside an outer packet to 3fff:1::1", outer, first)
					}
				case unowned:
					decision, reason = TraceDrop, "unowned_source"
					if got.to != "" || len(got.written) != 0 || got.counted != (TransitCounters{UnownedSource: 1}) {
						t.Errorf("the read went to %q, put %d packets into the tun and counted %+v, want unowned_source alone", got.to, len(got.written), got.counted)
					}
				}
				if got.explained.Decision != decision || got.explained.Reason != reason {
					t.Errorf("ExplainRead names %v %q, want %v %q", got.explained.Decision, got.explained.Reason, decision, reason)
				}
				if traced && (len(got.records) != 1 || got.records[0].Decision != decision || got.records[0].Reason != reason) {
					t.Errorf("the trace took %+v, want one record of %v %q", got.records, decision, reason)
				}
			})
		}
	}
}
