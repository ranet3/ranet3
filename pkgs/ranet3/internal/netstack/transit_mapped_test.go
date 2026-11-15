// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

var mappedSources = []netip.Addr{
	segAddr("::ffff:192.0.2.1"), segAddr("::ffff:169.254.0.1"),
	segAddr("::ffff:0.0.0.0"), segAddr("::ffff:255.255.255.255"),
}

var mappedNeighbors = []netip.Addr{segAddr("::fffe:ffff:ffff"), segAddr("::1:0:0:0")}

// mappedAllow admits the inner range so the segment's source check, not its allow list, decides it
var mappedAllow = append([]schema.Prefix{schema.PrefixFrom(segPrefix("::/64"))}, transitOverlay...)

func mappedTransitNode(t testing.TB) (*transitNode, *TraceFeed) {
	t.Helper()
	n, feed := explainSegments(t, mappedAllow, transitOverlay)
	n.m.SetOverlay(nil)
	n.m.SetAdvertisedReady(true, true)
	// a reply route must not hide a missing source check behind an egress refusal
	n.m.Routes.Set(netip.Prefix{}, segPrefix("::fffe:0:0/95"), n.fromPeer)
	n.m.Routes.Set(netip.Prefix{}, hostPrefix(mappedNeighbors[1]), n.fromPeer)
	return n, feed
}

// requireMappedDrop holds the decision's explanation, effects, counter and trace to the same silent refusal
func requireMappedDrop(t *testing.T, n *transitNode, feed *TraceFeed, raw []byte) {
	t.Helper()
	want := Explanation{Decision: TraceDrop, Reason: "martian"}
	if got := n.m.Explain(raw); got != want {
		t.Fatalf("explanation %+v, want %+v", got, want)
	}
	tun, out, back := n.deliver(t, raw)
	if exit := n.egressed(); len(tun)+len(out)+len(back)+len(exit) != 0 {
		t.Fatalf("mapped source reached tun %x, peer %x, sender %x or exit %x", tun, out, back, exit)
	}
	if got := n.m.TransitCounters(); got != (TransitCounters{Martian: 1}) {
		t.Fatalf("counters %+v", got)
	}
	if records := queued(feed); len(records) != 1 || records[0].Decision != TraceDrop || records[0].Reason != "martian" || records[0].Answer != "" {
		t.Fatalf("trace %+v", records)
	}
}

func TestMappedSourcesReachNoDestination(t *testing.T) {
	for _, destination := range []netip.Addr{
		transitOwn[6], transitFar[6], transitNowhere[6], segAddr("fe80::1"),
		segAddr("ff02::1"), segAddr("::"), segAddr("::ffff:192.0.2.3"),
	} {
		t.Run(destination.String(), func(t *testing.T) {
			n, feed := mappedTransitNode(t)
			requireMappedDrop(t, n, feed, udpPacket(mappedSources[0], destination, 100, false))
		})
	}
	t.Run("embedded link-local", func(t *testing.T) {
		n, feed := mappedTransitNode(t)
		requireMappedDrop(t, n, feed, udpPacket(mappedSources[1], transitFar[6], 100, false))
	})
}

// the range's ends are refused and their immediate native neighbors still forward
// the byte check sees an IPv6 header, while the address check must distinguish a genuine IPv4 source
func TestMappedSourceRangeKeepsItsEdges(t *testing.T) {
	for _, c := range []struct {
		source  netip.Addr
		refused bool
	}{
		{mappedSources[2], true}, {mappedSources[3], true},
		{mappedNeighbors[0], false}, {mappedNeighbors[1], false},
		{segAddr("2001:db8::ffff:192.0.2.1"), false},
		{transitSender[4], false},
	} {
		t.Run(c.source.String(), func(t *testing.T) {
			if got := mappedAddress(c.source); got != c.refused {
				t.Fatalf("address %s: mapped %v, want %v", c.source, got, c.refused)
			}
			if c.source.Is6() {
				raw := c.source.As16()
				if got := mappedAddressBytes(raw[:]); got != c.refused {
					t.Fatalf("octets %x: mapped %v, want %v", raw, got, c.refused)
				}
			}
			n, feed := mappedTransitNode(t)
			raw := udpPacket(c.source, transitFar[familyOf(c.source)], 100, false)
			if c.refused {
				requireMappedDrop(t, n, feed, raw)
				return
			}
			if got := n.m.Explain(raw); got.Decision != TraceForward {
				t.Fatalf("native source explanation %+v", got)
			}
			tun, out, back := n.deliver(t, raw)
			if len(out) != 1 || !bytes.Equal(out[0], forwardedAs(raw)) || len(tun)+len(back)+len(n.egressed()) != 0 {
				t.Fatalf("native source reached tun %x, peer %x or sender %x", tun, out, back)
			}
		})
	}
}

func TestMappedSourceControlsKeepTheirDestinations(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, place := range []string{"local", "peer", "exit", "link"} {
			t.Run(fmt.Sprintf("IPv%d/%s", family, place), func(t *testing.T) {
				n, feed := mappedTransitNode(t)
				source, destination := transitSender[family], transitOwn[family]
				want := TraceDeliver
				switch place {
				case "peer":
					destination, want = transitFar[family], TraceForward
				case "exit":
					destination, want = transitNowhere[family], TraceEgress
				case "link":
					if family == 4 {
						destination, want = segAddr("169.254.0.1"), TraceDrop
					} else {
						source, destination = segAddr("fe80::2"), segAddr("fe80::1")
					}
				}
				raw := udpPacket(source, destination, 100, false)
				if got := n.m.Explain(raw); got.Decision != want {
					t.Fatalf("explanation %+v, want %s", got, want)
				}
				tun, out, back := n.deliver(t, raw)
				exit := n.egressed()
				var reached [][]byte
				switch want {
				case TraceDeliver:
					reached, tun = tun, nil
				case TraceForward:
					reached, out = out, nil
					raw = forwardedAs(raw)
				case TraceEgress:
					reached, exit = exit, nil
				}
				if want != TraceDrop && (len(reached) != 1 || !bytes.Equal(reached[0], raw)) {
					t.Fatalf("destination received %x, want %x", reached, raw)
				}
				if len(tun)+len(out)+len(back)+len(exit) != 0 {
					t.Fatal("packet reached another destination")
				}
				if records := queued(feed); len(records) != 1 || records[0].Decision != want {
					t.Fatalf("trace %+v, want %s", records, want)
				}
			})
		}
	}
}

func TestMappedInnerSourcesNeverLeaveSegments(t *testing.T) {
	sources := append(append(append([]netip.Addr{}, mappedSources...), mappedNeighbors...), transitSender[4], transitSender[6])
	for _, sid := range []netip.Addr{explainDT46, explainEgress} {
		for _, source := range sources {
			destinations := []netip.Addr{transitNowhere[familyOf(source)]}
			if source.Is4In6() {
				destinations = append(destinations, segAddr("ff02::1"), segAddr("fe80::1"))
			}
			for _, destination := range destinations {
				t.Run(sid.String()+"/"+source.String()+"/"+destination.String(), func(t *testing.T) {
					n, feed := mappedTransitNode(t)
					inner := udpPacket(source, destination, 100, false)
					explained := n.m.Explain(inner)
					tun, out, back := n.deliver(t, steered(t, inner, transitSender[6], sid))
					exit := n.egressed()
					if len(tun)+len(out)+len(back) != 0 {
						t.Fatalf("segment wrote tun %x, peer %x or answer %x", tun, out, back)
					}
					records := queued(feed)
					if len(records) != 1 || records[0].Decision != explained.Decision || records[0].Reason != explained.Reason || records[0].Answer != explained.Answer {
						t.Fatalf("segment %+v disagrees with decision %+v", records, explained)
					}
					if source.Is4In6() {
						if len(exit) != 0 || explained.Decision != TraceDrop || explained.Reason != "martian" {
							t.Fatalf("mapped inner source reached exit %x, explanation %+v", exit, explained)
						}
						dropped := uint64(0)
						if sid == explainEgress {
							dropped = 1
						}
						segments := n.m.SegmentCounters()
						if got := n.m.TransitCounters(); got != (TransitCounters{Martian: 1}) || segments.Refused != 0 || segments.Dropped != dropped {
							t.Fatalf("transit %+v, segments %+v, want %d segment drops", got, segments, dropped)
						}
					} else if len(exit) != 1 || !bytes.Equal(exit[0], inner) {
						t.Fatalf("control reached exit %x, want %x", exit, inner)
					}
				})
			}
		}
	}
}

func TestMappedOuterSourcesReachTheDecisionBeforeSegments(t *testing.T) {
	for _, overlay := range [][]schema.Prefix{nil, transitOverlay} {
		for _, sid := range []netip.Addr{explainEnd, explainDT46, explainEgress} {
			for _, source := range mappedSources[2:] {
				t.Run(fmt.Sprintf("overlay=%v/%s/%s", overlay, sid, source), func(t *testing.T) {
					n, feed := explainSegments(t, mappedAllow, overlay)
					n.m.Routes.Set(netip.Prefix{}, hostPrefix(sid), Local)
					path := []netip.Addr{sid}
					if sid == explainEnd {
						path = append(path, transitFar[6])
					}
					inner := udpPacket(transitSender[6], transitNowhere[6], 100, false)
					outer := steered(t, inner, transitSender[6], path...)
					address := source.As16()
					copy(outer[8:24], address[:])
					if _, _, ok := n.m.ExplainSegment(source, sid); ok {
						t.Fatal("mapped outer source was assigned to a segment rather than the decision")
					}
					requireMappedDrop(t, n, feed, outer)
					if got := n.m.SegmentCounters(); got != (SegmentCounters{}) {
						t.Fatalf("a segment acted on a mapped outer source: %+v", got)
					}
				})
			}
		}
	}
}

func TestMappedSourceNeighborsStillReachSegments(t *testing.T) {
	for _, source := range mappedNeighbors {
		for _, sid := range []netip.Addr{explainEnd, explainDT46, explainEgress} {
			t.Run(source.String()+"/"+sid.String(), func(t *testing.T) {
				overlay := append([]schema.Prefix{schema.PrefixFrom(hostPrefix(source))}, transitOverlay...)
				allow := append([]schema.Prefix{schema.PrefixFrom(hostPrefix(source))}, mappedAllow...)
				n, feed := explainSegments(t, allow, overlay)
				n.m.SetOverlay(nil)
				n.m.SetAdvertisedReady(true, true)
				n.m.Routes.Set(netip.Prefix{}, hostPrefix(sid), Local)
				if admission, _, ok := n.m.ExplainSegment(source, sid); !ok || admission.Err != nil {
					t.Fatalf("native outer source admission %+v, present %v", admission, ok)
				}
				path := []netip.Addr{sid}
				if sid == explainEnd {
					path = append(path, transitFar[6])
				}
				raw := steered(t, udpPacket(transitSender[6], transitNowhere[6], 100, false), source, path...)
				tun, out, back := n.deliver(t, raw)
				exit := n.egressed()
				want := TraceEgress
				if sid == explainEnd {
					want = TraceForward
					if len(out) != 1 || len(exit) != 0 {
						t.Fatalf("waypoint wrote peer %x, exit %x", out, exit)
					}
				} else if len(exit) != 1 || len(out) != 0 {
					t.Fatalf("decapsulation wrote peer %x, exit %x", out, exit)
				}
				if len(tun)+len(back) != 0 {
					t.Fatalf("native source reached tun %x or sender %x", tun, back)
				}
				if records := queued(feed); len(records) != 1 || records[0].Decision != want {
					t.Fatalf("trace %+v, want %s", records, want)
				}
			})
		}
	}
}

func TestMappedSourceDropReportsItsReason(t *testing.T) {
	for _, segment := range []bool{false, true} {
		t.Run(fmt.Sprintf("segment=%v", segment), func(t *testing.T) {
			bus := events.New()
			n := newRecordingTransitNode(t, DefaultMTU, bus.Emit)
			source, destination := mappedSources[0], transitNowhere[6]
			raw := udpPacket(source, destination, 100, false)
			if segment {
				table, err := srv6.NewLocalTable([]srv6.Segment{{
					SID: schema.AddrFrom(explainEgress), Behavior: srv6.BehaviorEndDT46,
					Deliver: srv6.DeliverEgress, Allow: mappedAllow,
				}}, transitOverlay)
				if err != nil {
					t.Fatal(err)
				}
				n.m.SetSegments(table)
				raw = steered(t, raw, transitSender[6], explainEgress)
			}
			n.deliver(t, raw)
			recorded := bus.Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "netstack.transit.dropped" }, 0)
			if len(recorded) != 1 {
				t.Fatalf("drop events %+v", recorded)
			}
			attrs := recorded[0].Attrs
			if attrs["reason"] != "martian" || attrs["src"] != source.String() || attrs["dst"] != destination.String() {
				t.Fatalf("drop event %+v, want martian from %s to %s", recorded[0], source, destination)
			}
		})
	}
}

func TestMappedMalformedSourcesDrawNoAnswer(t *testing.T) {
	n, feed := mappedTransitNode(t)
	raw := lengthOf(mappedSources[0], transitFar[6], 300)
	if got := n.m.Explain(raw); got != (Explanation{Decision: TraceDrop, Reason: "invalid"}) {
		t.Fatalf("explanation %+v", got)
	}
	tun, out, back := n.deliver(t, raw)
	if len(tun)+len(out)+len(back) != 0 {
		t.Fatalf("malformed mapped packet reached tun %x, peer %x or sender %x", tun, out, back)
	}
	if records := queued(feed); len(records) != 1 || records[0].Decision != TraceDrop || records[0].Reason != "invalid" {
		t.Fatalf("trace %+v", records)
	}
}
