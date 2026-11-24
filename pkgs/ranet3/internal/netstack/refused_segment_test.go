// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// the headend that steered the segments below and the hosts behind the packets they carry, each behind a host route on a peer of its own
var (
	endHeadend  = segAddr("3fff::6")
	endSender6  = segAddr("3fff::7")
	endSender4  = segAddr("192.0.2.7")
	endReceiver = segAddr("2001:db8::9")
)

// endNode is newTransitNode with an End at transitSID, answering from sources, and the headend behind a host route on the peer named headend
func endNode(t testing.TB, mtu int, sources AnswerSources) (*transitNode, *recordingPeer) {
	t.Helper()
	n := newTransitNode(t, mtu)
	table, err := srv6.NewLocalTable([]srv6.Segment{{SID: schema.AddrFrom(transitSID), Behavior: srv6.BehaviorEnd}}, transitOverlay)
	if err != nil {
		t.Fatal(err)
	}
	n.m.SetSegments(table)
	n.m.SetAnswerSources(sources)
	headend := &recordingPeer{}
	n.m.Routes.Set(netip.Prefix{}, hostPrefix(endHeadend), headend.peer(t, "headend"))
	return n, headend
}

// endRecords are the records a trace opened on n took while deliver ran, nil where traced is not set
func endRecords(t testing.TB, n *transitNode, traced bool, deliver func()) []TraceRecord {
	t.Helper()
	if !traced {
		deliver()
		return nil
	}
	feed := openTrace(t, n.m, TraceFilter{}, 0, control.TraceRateMax)
	deliver()
	return queued(feed)
}

// End drops a next segment that is a group or that no router forwards before its route is looked up, ::1, an IPv4-mapped address, ff0e::1, ff02::1 and ::
// whatever route covers it, a default or one counting as no default, and answers none of them, the code 0 for :: under a default among them
// counting the segment dropped and the drop martian, its record a drop for martian naming the next segment, traced or not
// beside them a link-local next segment, dropped the same way
// a routed next segment goes on, and so does one whose list holds ff0e::1, :: or ::1 past the active entry, the list left as it came, RFC 8754 section 4.3.1.1
func TestEndDropsANextSegmentNoRouterForwardsUnanswered(t *testing.T) {
	far := transitFar[6]
	for _, c := range []struct {
		name  string
		next  netip.Addr
		route string
		// behind is an entry past the active one, the zero Addr for a list of two
		behind  netip.Addr
		forward bool
	}{
		{"::1 under a route of its own", segAddr("::1"), "::1/128", netip.Addr{}, false},
		{"an IPv4-mapped address under the mapped block", segAddr("::ffff:198.51.100.9"), "::ffff:0:0/96", netip.Addr{}, false},
		{"ff0e::1 under ff0e::/16", segAddr("ff0e::1"), "ff0e::/16", netip.Addr{}, false},
		{"ff02::1 under ff02::/16", segAddr("ff02::1"), "ff02::/16", netip.Addr{}, false},
		{":: under a default", segAddr("::"), "::/0", netip.Addr{}, false},
		{"fe80::9 under a route of its own", segAddr("fe80::9"), "fe80::9/128", netip.Addr{}, false},
		{"a routed next segment", far, "", netip.Addr{}, true},
		{"a routed next segment with ff0e::1 behind it", far, "", segAddr("ff0e::1"), true},
		{"a routed next segment with :: behind it", far, "", segAddr("::"), true},
		{"a routed next segment with ::1 behind it", far, "", segAddr("::1"), true},
	} {
		for _, traced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, traced %t", c.name, traced), func(t *testing.T) {
				n, headend := endNode(t, DefaultMTU+200, AnswerSources{Router4: transitOwn[4], Router6: transitOwn[6]})
				if c.route != "" {
					n.m.Routes.Set(netip.Prefix{}, segPrefix(c.route), n.outPeer)
				}
				inner := udpPacket(endSender6, endReceiver, 200, false)
				var segment []byte
				if c.behind.IsValid() {
					segment = steered(t, inner, endHeadend, transitSID, c.next, segAddr("3fff:b:0:206::1"))
					copy(segment[48:64], c.behind.AsSlice())
				} else {
					segment = steered(t, inner, endHeadend, transitSID, segAddr("3fff:b:0:206::1"))
					copy(segment[48:64], c.next.AsSlice())
				}
				rewritten := bytes.Clone(segment)
				if _, err := srv6.End(rewritten); err != nil {
					t.Fatal(err)
				}
				var tun, out, back [][]byte
				records := endRecords(t, n, traced, func() { tun, out, back = n.deliver(t, segment) })
				answered := headend.packets(t)
				counters, martian := n.m.SegmentCounters(), n.m.TransitCounters().Martian
				decision, reason := TraceDrop, "martian"
				if c.forward {
					decision, reason = TraceForward, ""
					if len(out) != 1 || !bytes.Equal(out[0], rewritten) || len(answered)+len(back)+len(tun) != 0 || counters != (SegmentCounters{Forwarded: 1}) || martian != 0 {
						t.Errorf("the segment went on as %d packets with %d answers, counted %+v and %d martian, want it on as End left it", len(out), len(answered)+len(back)+len(tun), counters, martian)
					}
				} else if len(out)+len(answered)+len(back)+len(tun) != 0 || counters != (SegmentCounters{Dropped: 1}) || martian != 1 {
					t.Errorf("the segment to %s sent %d packets on, %d to the headend, %d back and %d into the tun, counted %+v and %d martian, want nothing sent, dropped and martian", c.next, len(out), len(answered), len(back), len(tun), counters, martian)
				}
				if traced && (len(records) != 1 || records[0].Decision != decision || records[0].Reason != reason || records[0].Segment != c.next) {
					t.Errorf("the trace took %+v, want one record of %v %q naming %s", records, decision, reason, c.next)
				}
			})
		}
	}
}

// End's answer about the IPv4 packet a segment too large for its next session carries, where the node holds no IPv4 router-id
// would come from that packet's destination, and where no router forwards that destination, 169.254.9.9 or 127.0.0.1, End answers the segment itself
// with packet too big from the SID to the headend, naming the session's MTU whole and quoting the segment as End rewrote it, and sends the packet's sender nothing
// counted dropped and answered and as an answer about size, its record an answer about size that was sent, traced or not, RFC 8200 section 4.4
// and so is one that is to be cut and whose options do not frame, whose parameter problem would come from that destination, nothing counted unanswered
// where the packet's own source is one no router forwards the segment is answered about its size whatever its options, the test of that source coming first
// a packet that would draw no answer for any reason but where the answer comes from draws none: one no route leads back to the sender of, an ICMP error, and any under an answer TTL of 0
// one whose sender no route led back to when End looked, a route to it learned before the answer would leave, draws nothing either, none being built
// and the answer goes through the peer End looked up, a route to the sender removed after End looked leaving it as it was
// and a packet to a group or the limited broadcast draws nothing, from any source, with or without the router-id, no error this node builds answering it
// the answer about the segment declined by this node's policy, which its record says
// beside them, outside the rule: with the IPv4 router-id the packet's sender is answered from it
// and a sender behind an entry of this node's own counting as no default is answered into the tun from the destination, the answer never leaving the node
func TestEndAnswersTheSegmentWhereItsIPv4AnswerWouldComeFromAnAddressNoRouterForwards(t *testing.T) {
	mtu := srv6.MinimumIPv6MTU + srv6.Overhead(2)
	only6 := AnswerSources{Router6: transitOwn[6]}
	both := AnswerSources{Router4: transitOwn[4], Router6: transitOwn[6]}
	ll4, refused := segAddr("169.254.9.9"), segAddr("169.254.9.7")
	tooBig := func(src, dst netip.Addr) []byte { return udpPacket(src, dst, DefaultMTU, true) }
	unframed := func(src, dst netip.Addr) []byte {
		return withOptions(udpPacket(src, dst, DefaultMTU-4, false), []byte{7, 9, 4, 0})
	}
	type answer int
	const (
		aboutSegment answer = iota
		toSender
		intoTun
		none
		unsent
		declined
	)
	// how the node reaches the sender of the carried packet
	const (
		senderPeer = iota
		senderLocal
		senderUnrouted
		// senderLearned is a route to the sender on a peer of its own, set once End has looked the answer's route up
		senderLearned
		// senderForgotten is that route set first and removed once End has looked it up
		senderForgotten
	)
	for _, c := range []struct {
		name    string
		sources AnswerSources
		inner   []byte
		reach   int
		noTTL   bool
		want    answer
		// from, kind, code and rest are the answer about the carried packet where want is toSender or intoTun, and kind names the answer where want is unsent
		from       netip.Addr
		kind, code byte
		rest       uint32
	}{
		{"with DF to 169.254.9.9", only6, tooBig(endSender4, ll4), senderPeer, false, aboutSegment, netip.Addr{}, 0, 0, 0},
		{"with DF to 127.0.0.1", only6, tooBig(endSender4, segAddr("127.0.0.1")), senderPeer, false, aboutSegment, netip.Addr{}, 0, 0, 0},
		{"with options that do not frame to 169.254.9.9", only6, unframed(endSender4, ll4), senderPeer, false, aboutSegment, netip.Addr{}, 0, 0, 0},
		{"with DF from 169.254.9.7 to 198.51.100.9", only6, tooBig(refused, segAddr("198.51.100.9")), senderPeer, false, aboutSegment, netip.Addr{}, 0, 0, 0},
		{"with options that do not frame from 169.254.9.7 to 169.254.9.9", only6, unframed(refused, ll4), senderPeer, false, aboutSegment, netip.Addr{}, 0, 0, 0},
		{"with DF to 169.254.9.9 and no route to the sender", only6, tooBig(endSender4, ll4), senderUnrouted, false, unsent, netip.Addr{}, 3, 0, 0},
		{"with options that do not frame to 169.254.9.9 and no route to the sender", only6, unframed(endSender4, ll4), senderUnrouted, false, unsent, netip.Addr{}, 12, 0, 0},
		{"with DF to 169.254.9.9 and a route to the sender learned after End looked", only6, tooBig(endSender4, ll4), senderLearned, false, unsent, netip.Addr{}, 3, 0, 0},
		{"with options that do not frame to 169.254.9.9 and a route to the sender learned after End looked", only6, unframed(endSender4, ll4), senderLearned, false, unsent, netip.Addr{}, 12, 0, 0},
		{"with DF to 198.51.100.9 and the route to the sender removed after End looked", only6, tooBig(endSender4, segAddr("198.51.100.9")), senderForgotten, false, toSender, segAddr("198.51.100.9"), 3, 4, uint32(mtu - srv6.Overhead(2))},
		{"with DF to 127.0.0.1 and no route to the sender", only6, tooBig(endSender4, segAddr("127.0.0.1")), senderUnrouted, false, none, netip.Addr{}, 0, 0, 0},
		{"an ICMP error with DF to 169.254.9.9", only6, icmpv4Error(endSender4, ll4, DefaultMTU), senderPeer, false, none, netip.Addr{}, 0, 0, 0},
		{"with DF to 169.254.9.9 under an answer TTL of 0", only6, tooBig(endSender4, ll4), senderPeer, true, none, netip.Addr{}, 0, 0, 0},
		{"with DF to 169.254.9.9 and the IPv4 router-id", both, tooBig(endSender4, ll4), senderPeer, false, toSender, transitOwn[4], 3, 4, uint32(mtu - srv6.Overhead(2))},
		{"with options that do not frame to 169.254.9.9 and the IPv4 router-id", both, unframed(endSender4, ll4), senderPeer, false, toSender, transitOwn[4], 12, 0, 20 << 24},
		{"with DF to 169.254.9.9 from a sender of this node's own", only6, tooBig(endSender4, ll4), senderLocal, false, intoTun, ll4, 3, 4, uint32(mtu - srv6.Overhead(2))},
		{"with options that do not frame to 169.254.9.9 from a sender of this node's own", only6, unframed(endSender4, ll4), senderLocal, false, intoTun, ll4, 12, 0, 20 << 24},
		{"with DF to 224.0.0.1", only6, tooBig(endSender4, segAddr("224.0.0.1")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with DF to 255.255.255.255", only6, tooBig(endSender4, segAddr("255.255.255.255")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with DF to 224.0.0.1 and the IPv4 router-id", both, tooBig(endSender4, segAddr("224.0.0.1")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with DF to 255.255.255.255 and the IPv4 router-id", both, tooBig(endSender4, segAddr("255.255.255.255")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with options that do not frame to 224.0.0.1", only6, unframed(endSender4, segAddr("224.0.0.1")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"an IPv6 packet from 3fff::7 to ff02::1", only6, udpPacket(endSender6, segAddr("ff02::1"), DefaultMTU, false), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"an IPv6 packet from 3fff::7 to ff0e::1", only6, udpPacket(endSender6, segAddr("ff0e::1"), DefaultMTU, false), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with DF from 169.254.9.7 to 224.0.0.1", only6, tooBig(refused, segAddr("224.0.0.1")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with DF from 169.254.9.7 to 255.255.255.255", only6, tooBig(refused, segAddr("255.255.255.255")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"with options that do not frame from 169.254.9.7 to 224.0.0.1", only6, unframed(refused, segAddr("224.0.0.1")), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
		{"an IPv6 packet from fe80::7 to ff02::1", only6, udpPacket(segAddr("fe80::7"), segAddr("ff02::1"), DefaultMTU, false), senderPeer, false, declined, netip.Addr{}, 0, 0, 0},
	} {
		for _, traced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, traced %t", c.name, traced), func(t *testing.T) {
				n, headend := endNode(t, mtu, c.sources)
				if c.noTTL {
					n.m.SetAnswerTTL(0)
				}
				sender := &recordingPeer{}
				switch c.reach {
				case senderLocal:
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), Local)
				case senderPeer:
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), sender.peer(t, "sender"))
				case senderLearned:
					learned := sender.peer(t, "sender")
					n.m.sourcesRead = func() { n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), learned) }
				case senderForgotten:
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), sender.peer(t, "sender"))
					n.m.sourcesRead = func() { n.m.Routes.Remove(netip.Prefix{}, hostPrefix(endSender4)) }
				}
				segment := steered(t, slices.Clone(c.inner), endHeadend, transitSID, transitFar[6])
				rewritten := bytes.Clone(segment)
				if _, err := srv6.End(rewritten); err != nil {
					t.Fatal(err)
				}
				var tun, out, back [][]byte
				records := endRecords(t, n, traced, func() { tun, out, back = n.deliver(t, segment) })
				atHeadend := headend.packets(t)
				var atSender [][]byte
				if c.reach != senderLocal && c.reach != senderUnrouted {
					atSender = sender.packets(t)
				}
				counters, tooBigs, unanswered := n.m.SegmentCounters(), n.m.TooBigAnswered(), n.m.TransitCounters().Unanswered
				if len(out)+len(back) != 0 {
					t.Fatalf("the segment went on as %d packets and %d went back on its session, want none", len(out), len(back))
				}
				var record TraceRecord
				if traced {
					if len(records) != 1 {
						t.Fatalf("the trace took %+v, want one record", records)
					}
					record = records[0]
				}
				switch c.want {
				case aboutSegment:
					if len(atHeadend) != 1 || len(atSender)+len(tun) != 0 {
						t.Fatalf("the headend was sent %d packets, the sender %d and the tun %d, want one answer to the headend alone", len(atHeadend), len(atSender), len(tun))
					}
					checkICMPv6(t, atHeadend[0], rewritten, transitSID, 2, 0, uint32(mtu))
					if counters != (SegmentCounters{Dropped: 1, Answered: 1}) || tooBigs != 1 {
						t.Errorf("the waypoint counted %+v and %d answers about size, want it dropped and answered about its size", counters, tooBigs)
					}
					if traced && (record.Decision != TraceAnswer || record.Reason != "too_big" || record.Answer != "too_big" || record.Outcome != TraceSent) {
						t.Errorf("the trace took %+v, want an answer about size that was sent", record)
					}
				case toSender, intoTun:
					got := atSender
					if c.want == intoTun {
						got = tun
					}
					if len(got) != 1 || len(atHeadend) != 0 || len(atSender)+len(tun) != 1 {
						t.Fatalf("the headend was sent %d packets, the sender %d and the tun %d, want the one answer about the carried packet", len(atHeadend), len(atSender), len(tun))
					}
					checkICMPv4(t, got[0], c.inner, c.from, c.kind, c.code, c.rest)
					if counters != (SegmentCounters{Dropped: 1, Answered: 1}) || unanswered != 0 {
						t.Errorf("the waypoint counted %+v and %d unanswered, want it dropped and answered", counters, unanswered)
					}
				case none, unsent, declined:
					if len(atHeadend)+len(atSender)+len(tun) != 0 || counters != (SegmentCounters{Dropped: 1}) || tooBigs != 0 || unanswered != 0 {
						t.Errorf("the headend was sent %d packets, the sender %d and the tun %d, counted %+v, %d answers about size and %d unanswered, want nothing sent", len(atHeadend), len(atSender), len(tun), counters, tooBigs, unanswered)
					}
					outcome, kind := TraceNotAnswerable, "too_big"
					switch c.want {
					case unsent:
						outcome = TraceUnsent
						if c.kind == 12 {
							kind = "parameter"
						}
					case declined:
						outcome = TraceDeclined
					}
					if traced && (record.Outcome != outcome || record.Answer != kind) {
						t.Errorf("the trace took %+v, want an answer %q with the outcome %v", record, kind, outcome)
					}
				}
			})
		}
	}
}

// End takes the address its answer about a segment's IPv4 packet comes from once for the segment, so an answer that a test of that address
// found would come from no address a router forwards is not built from one that a second look found
// shown with answer sources that change at each look between holding the IPv4 router-id and holding none, starting from either
// with no router forwarding the carried packet's destination, End sends the answer due under the sources it read first and no other:
// starting with the router-id, one answer from it to the packet's sender, and starting with none, about the segment from the SID to the headend
// for a packet with DF and for one whose options do not frame alike, nothing counted unanswered, traced or not
func TestEndTakesTheSourceOfItsIPv4AnswerOnceASegment(t *testing.T) {
	mtu := srv6.MinimumIPv6MTU + srv6.Overhead(2)
	only6 := AnswerSources{Router6: transitOwn[6]}
	both := AnswerSources{Router4: transitOwn[4], Router6: transitOwn[6]}
	ll4 := segAddr("169.254.9.9")
	for name, inner := range map[string][]byte{
		"with DF":                        udpPacket(endSender4, ll4, DefaultMTU, true),
		"with options that do not frame": withOptions(udpPacket(endSender4, ll4, DefaultMTU-4, false), []byte{7, 9, 4, 0}),
	} {
		for _, first := range []AnswerSources{both, only6} {
			for _, traced := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s, starting with the IPv4 router-id %t, traced %t", name, first.Router4.IsValid(), traced), func(t *testing.T) {
					n, headend := endNode(t, mtu, first)
					sender := &recordingPeer{}
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), sender.peer(t, "sender"))
					n.m.sourcesRead = func() {
						if n.m.answers.Load().Router4.IsValid() {
							n.m.answers.Store(&only6)
						} else {
							n.m.answers.Store(&both)
						}
					}
					segment := steered(t, slices.Clone(inner), endHeadend, transitSID, transitFar[6])
					var tun, out, back [][]byte
					endRecords(t, n, traced, func() { tun, out, back = n.deliver(t, segment) })
					atHeadend, atSender := headend.packets(t), sender.packets(t)
					for _, packets := range [][][]byte{out, back, atHeadend, atSender} {
						for _, p := range packets {
							if src, dst, _, _ := addrsOf(p); unforwardedSource(src) {
								t.Errorf("End sent a packet from %s to %s on a session", src, dst)
							}
						}
					}
					wantHeadend, wantSender := 1, 0
					if first.Router4.IsValid() {
						wantHeadend, wantSender = 0, 1
					}
					if len(atHeadend) != wantHeadend || len(atSender) != wantSender || len(tun) != 0 || n.m.TransitCounters().Unanswered != 0 {
						t.Fatalf("the headend was sent %d packets, the sender %d and the tun %d, %d unanswered, want %d, %d, none and none", len(atHeadend), len(atSender), len(tun), n.m.TransitCounters().Unanswered, wantHeadend, wantSender)
					}
					for _, p := range atSender {
						if from := netip.AddrFrom4([4]byte(p[12:16])); from != transitOwn[4] {
							t.Errorf("the sender was answered from %s, want the IPv4 router-id", from)
						}
					}
					for _, p := range atHeadend {
						if from, _, _, _ := addrsOf(p); from != transitSID {
							t.Errorf("the headend was answered from %s, want the SID", from)
						}
					}
				})
			}
		}
	}
}

// End takes the TTL of its answer about a segment's IPv4 packet once for the segment, with the address the answer comes from
// so under an answer TTL of 0 when End looked, set to 64 before the answer would be built, a packet to 169.254.9.9 draws nothing
// for a packet with DF and one whose options do not frame, traced or not, its record an answer no error may make
func TestEndTakesTheTTLOfItsIPv4AnswerOnceASegment(t *testing.T) {
	mtu := srv6.MinimumIPv6MTU + srv6.Overhead(2)
	ll4 := segAddr("169.254.9.9")
	for name, c := range map[string]struct {
		inner []byte
		kind  string
	}{
		"with DF":                        {udpPacket(endSender4, ll4, DefaultMTU, true), "too_big"},
		"with options that do not frame": {withOptions(udpPacket(endSender4, ll4, DefaultMTU-4, false), []byte{7, 9, 4, 0}), "parameter"},
	} {
		for _, traced := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, traced %t", name, traced), func(t *testing.T) {
				n, headend := endNode(t, mtu, AnswerSources{Router6: transitOwn[6]})
				n.m.SetAnswerTTL(0)
				sender := &recordingPeer{}
				n.m.Routes.Set(netip.Prefix{}, hostPrefix(endSender4), sender.peer(t, "sender"))
				n.m.sourcesRead = func() { n.m.SetAnswerTTL(64) }
				segment := steered(t, slices.Clone(c.inner), endHeadend, transitSID, transitFar[6])
				var tun, out, back [][]byte
				records := endRecords(t, n, traced, func() { tun, out, back = n.deliver(t, segment) })
				atHeadend, atSender := headend.packets(t), sender.packets(t)
				if len(out)+len(back)+len(tun)+len(atHeadend)+len(atSender) != 0 || n.m.TransitCounters().Unanswered != 0 {
					t.Errorf("End sent %d packets on, %d back, %d into the tun, %d to the headend and %d to the sender, %d unanswered, want nothing", len(out), len(back), len(tun), len(atHeadend), len(atSender), n.m.TransitCounters().Unanswered)
				}
				if traced && (len(records) != 1 || records[0].Answer != c.kind || records[0].Outcome != TraceNotAnswerable) {
					t.Errorf("the trace took %+v, want one answer %q no error may make", records, c.kind)
				}
			})
		}
	}
}

// End's test of whether its answer about a carried IPv4 packet would come from an address no router forwards builds no answer, allocating nothing
// for a packet an error may answer, which it holds for, and for an ICMP error, which it does not
func TestEndTestsTheSourceOfItsIPv4AnswerWithoutAllocating(t *testing.T) {
	ll4 := segAddr("169.254.9.9")
	to := endAnswer{source: ll4, ttl: 64}
	for _, c := range []struct {
		name  string
		inner []byte
		want  bool
	}{
		{"a datagram with DF", udpPacket(endSender4, ll4, DefaultMTU, true), true},
		{"an ICMP error", icmpv4Error(endSender4, ll4, DefaultMTU), false},
	} {
		var got bool
		if allocs := leastAllocs(func() { got = answersFromUnforwarded(c.inner, to) }); allocs != 0 || got != c.want {
			t.Errorf("%s to 169.254.9.9: the test reports %t with %v allocations, want %t with none", c.name, got, allocs, c.want)
		}
	}
}
