// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/wireguard/tun"
)

// the session the route view's packets arrive through, a second session of the same node, and the peer of far hosts
const routeGateway, routeGatewayAgain, routeFar = "example/gateway:1@0", "example/gateway:2@0", "example/far:1@0"

// routeFarMTU is the most the session to routeFar carries
const routeFarMTU = 1280

// the segments of the route view's node: an End, an End.DT46 delivering to the mesh, and one delivering to egress what 3fff::1 alone sends
var routeEnd, routeDT46, routeEgress = netip.MustParseAddr("3fff:5::10"), netip.MustParseAddr("3fff:5::1"), netip.MustParseAddr("3fff:5::20")

// meshRouteClient is routeClient's node, the kernel answering answer and err and reading settings, holding sessions from example/gateway
// its mesh routes 192.0.2.1 and 3fff::1 back to example/gateway, 192.0.2.3, 3fff::3 and 3fff:1::/64 to example/far and holds 192.0.2.2 and 3fff::2
// with an IPv4 default cap.egress advertises and translates, cap.transit on, the overlay 192.0.2.0/24 and 3fff::/20
// the three segments above, IPv4 ready through the egress one, and what 3fff::2 sends steered through 3fff:1::1
// its mesh writes to a tun and egresses to an exit that count the batches handed to them
// it returns the arrival links the kernel was asked about and that tun and exit
func meshRouteClient(t *testing.T, answer kernel.MatchedRoute, lookup error, settings map[string]string) (*Client, *[]string, *routeTun) {
	t.Helper()
	c, _ := routeClient(t, answer, lookup, settings)
	written := &routeTun{}
	c.Mesh = netstack.NewOnDevice(written)
	c.Mesh.Name = "ranet0"
	c.Mesh.SetExit(written)
	t.Cleanup(c.Mesh.Close)
	var asked []string
	c.routeGet = func(_, _ netip.Addr, iif string) (kernel.MatchedRoute, error) {
		asked = append(asked, iif)
		return answer, lookup
	}
	c.sessions = newSessionSet()
	c.sessions.live[routeGateway] = &liveSession{}
	c.sessions.live[routeGatewayAgain] = &liveSession{}
	m := c.Mesh
	m.SetTransit(true)
	m.SetOverlay([]schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")})
	gateway, far := &netstack.Peer{ID: routeGateway}, &netstack.Peer{ID: routeFar}
	far.SetMTU(routeFarMTU)
	for prefix, peer := range map[string]*netstack.Peer{
		"192.0.2.1/32": gateway, "3fff::1/128": gateway,
		"192.0.2.3/32": far, "3fff::3/128": far, "3fff:1::/64": far,
		"192.0.2.2/32": netstack.Local, "3fff::2/128": netstack.Local, "0.0.0.0/0": netstack.Local,
	} {
		m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix(prefix), peer)
	}
	m.SetEgressPrefixes([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	m.SetAdvertisedReady(true, false)
	segments, err := srv6.NewLocalTable([]srv6.Segment{
		{SID: schema.AddrFrom(routeEnd), Behavior: srv6.BehaviorEnd},
		{SID: schema.AddrFrom(routeDT46), Behavior: srv6.BehaviorEndDT46},
		{SID: schema.AddrFrom(routeEgress), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: []schema.Prefix{schema.MustPrefix("3fff::1/128")}},
	}, []schema.Prefix{schema.MustPrefix("3fff::/20")})
	if err != nil {
		t.Fatal(err)
	}
	m.SetSegments(segments)
	m.SetEgressReady(true, false)
	steering, err := srv6.NewSteerTable([]srv6.Steer{{From: schema.MustPrefix("3fff::2/128"), Via: []schema.Addr{schema.MustAddr("3fff:1::1")}}}, schema.MustAddr("3fff:b:0:100::1"))
	if err != nil {
		t.Fatal(err)
	}
	m.SetSteering(steering)
	return c, &asked, written
}

// routeTun is a tun that reads nothing and counts the batches written to it, and the exit, counting the batches handed to it
type routeTun struct{ writes, egressed atomic.Int64 }

func (d *routeTun) Egress([][]byte) { d.egressed.Add(1) }

func (d *routeTun) File() *os.File                             { return nil }
func (d *routeTun) Read([]byte, []tun.ReadPacket) (int, error) { return 0, os.ErrClosed }
func (d *routeTun) Write(bufs [][]byte, _ int) (int, error) {
	d.writes.Add(1)
	return len(bufs), nil
}
func (d *routeTun) MTU() (int, error)        { return netstack.DefaultMTU, nil }
func (d *routeTun) Name() (string, error)    { return "ranet0", nil }
func (d *routeTun) Events() <-chan tun.Event { return nil }
func (d *routeTun) Close() error             { return nil }
func (d *routeTun) BatchSize() int           { return 1 }

// A session's packet meets the mesh's decision, which the view names as the mesh names it for the packet the view follows
// with the session it is held to and the table's entry, and only a packet the mesh delivers to this host goes on to the kernel, as arriving on the tun
func TestDebugRouteFollowsASessionsPacketThroughTheMesh(t *testing.T) {
	local := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("192.0.2.2/32"), Table: 255, Type: "local"}
	for name, test := range map[string]struct {
		src, dst   string
		transitOff bool
		decision   netstack.TraceDecision
		next       string
		matched    string
		counted    bool
	}{
		"a forward":          {src: "192.0.2.1", dst: "192.0.2.3", decision: netstack.TraceForward, next: routeFar, matched: "192.0.2.3/32"},
		"an IPv6 forward":    {src: "3fff::1", dst: "3fff::3", decision: netstack.TraceForward, next: routeFar, matched: "3fff::3/128"},
		"this host's own":    {src: "192.0.2.1", dst: "192.0.2.2", decision: netstack.TraceDeliver, matched: "192.0.2.2/32"},
		"an egress":          {src: "192.0.2.1", dst: "203.0.113.200", decision: netstack.TraceEgress, matched: "0.0.0.0/0", counted: true},
		"an unrouted source": {src: "203.0.113.66", dst: "203.0.113.200", decision: netstack.TraceDrop, matched: "0.0.0.0/0", counted: true},
		"no route":           {src: "3fff::1", dst: "2001:db8::5", decision: netstack.TraceAnswer},
		"transit off":        {src: "192.0.2.1", dst: "192.0.2.3", transitOff: true, decision: netstack.TraceAnswer, matched: "192.0.2.3/32"},
	} {
		t.Run(name, func(t *testing.T) {
			c, asked, _ := meshRouteClient(t, local, nil, nil)
			c.Mesh.SetTransit(!test.transitOff)
			src, dst := netip.MustParseAddr(test.src), netip.MustParseAddr(test.dst)
			info, err := c.DebugRoute(src, dst, "", "gateway")
			if err != nil {
				t.Fatal(err)
			}
			explained := c.Mesh.Explain(routePacket(src, dst))
			m := info.Mesh
			if info.Arrival != control.ArrivalSession || info.Peer != routeGateway || info.Segment != nil || m == nil {
				t.Fatalf("the view reads %+v", info)
			}
			if m.Decision != test.decision.String() || m.Reason != explained.Reason || m.Answer != explained.Answer || (test.decision != netstack.TraceForward) != (m.Reason != "" || m.Next == "") {
				t.Errorf("the mesh reads %+v, want %s as Explain names it %+v", m, test.decision, explained)
			}
			if m.Next != test.next || test.next != "" && m.MTU != routeFarMTU {
				t.Errorf("the packet is held to %q carrying %d B, want %q", m.Next, m.MTU, test.next)
			}
			if test.matched != "" && m.Matched != netip.MustParsePrefix(test.matched) || test.matched == "" && m.Matched.IsValid() || m.Counted != test.counted {
				t.Errorf("the table matched %s, counted %v, want %q and %v", m.Matched, m.Counted, test.matched, test.counted)
			}
			delivered := test.decision == netstack.TraceDeliver
			if delivered != (info.Kernel != nil) || delivered && (!slices.Equal(*asked, []string{"ranet0"}) || info.IIF != "ranet0" || info.Kernel.Rule == nil) {
				t.Errorf("the kernel reads %+v on %q, asked of %q", info.Kernel, info.IIF, *asked)
			}
		})
	}
}

// A packet to a SID of this node meets the segment, which says what it asks of the source and ends the walk
// the overlay at every segment and the allow list at an egress one, a refusal named as the segment's drop
func TestDebugRouteStopsAtTheSegment(t *testing.T) {
	for name, test := range map[string]struct {
		src              string
		sid              netip.Addr
		overlay, allowed bool
		refused          bool
		deliver          string
	}{
		"End from outside the overlay":      {src: "2001:db8:66::6", sid: routeEnd, refused: true},
		"End from the overlay":              {src: "3fff::3", sid: routeEnd, overlay: true},
		"End.DT46 to the mesh":              {src: "3fff::3", sid: routeDT46, overlay: true, deliver: srv6.DeliverMesh.String()},
		"egress from its allow list":        {src: "3fff::1", sid: routeEgress, overlay: true, allowed: true, deliver: srv6.DeliverEgress.String()},
		"egress outside its allow list":     {src: "3fff::3", sid: routeEgress, overlay: true, refused: true, deliver: srv6.DeliverEgress.String()},
		"egress from outside the overlay":   {src: "2001:db8:66::6", sid: routeEgress, refused: true, deliver: srv6.DeliverEgress.String()},
		"End.DT46 from outside the overlay": {src: "2001:db8:66::6", sid: routeDT46, refused: true, deliver: srv6.DeliverMesh.String()},
	} {
		t.Run(name, func(t *testing.T) {
			c, asked, _ := meshRouteClient(t, kernel.MatchedRoute{}, nil, nil)
			src := netip.MustParseAddr(test.src)
			info, err := c.DebugRoute(src, test.sid, "", routeGateway)
			if err != nil {
				t.Fatal(err)
			}
			s := info.Segment
			if s == nil || info.Mesh != nil || info.Kernel != nil || len(*asked) != 0 {
				t.Fatalf("the view reads %+v, the kernel asked of %q", info, *asked)
			}
			if s.SID != test.sid || s.Deliver != test.deliver || s.Overlay != test.overlay || s.Allowed != test.allowed {
				t.Errorf("the segment reads %+v", s)
			}
			if egress := test.deliver == srv6.DeliverEgress.String(); egress != (s.Egress != nil) || egress && !slices.Equal(s.Egress.Ready, []string{"ipv4"}) {
				t.Errorf("the segment's part of the exit reads %+v", s.Egress)
			}
			_, refusal, _ := c.Mesh.ExplainSegment(src, test.sid)
			if test.refused != (s.Decision == netstack.TraceDrop.String()) || s.Reason != refusal.Reason || test.refused == (s.Reason == "") {
				t.Errorf("the segment decides %q for %q, want a refusal %v as %+v", s.Decision, s.Reason, test.refused, refusal)
			}
		})
	}
}

// A session's packet names a peer this node holds a session with, the first of its sessions in path order where it has several, and carries a source
func TestDebugRouteFindsTheSessionAPacketArrivesThrough(t *testing.T) {
	c, asked, _ := meshRouteClient(t, kernel.MatchedRoute{}, nil, nil)
	for _, name := range []string{"gateway", "example/gateway", routeGateway} {
		if info, err := c.DebugRoute(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.3"), "", name); err != nil || info.Peer != routeGateway {
			t.Errorf("%s names the session %q, %v", name, info.Peer, err)
		}
	}
	if info, err := c.DebugRoute(netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.3"), "", routeGatewayAgain); err != nil || info.Peer != routeGatewayAgain {
		t.Errorf("%s names the session %q, %v", routeGatewayAgain, info.Peer, err)
	}
	for name, test := range map[string]struct {
		src        netip.Addr
		iif, named string
	}{
		"a peer with no session": {netip.MustParseAddr("192.0.2.1"), "", "example/far"},
		"no source":              {netip.Addr{}, "", "gateway"},
		"a link as well":         {netip.MustParseAddr("192.0.2.1"), "lan0", "gateway"},
	} {
		if info, err := c.DebugRoute(test.src, netip.MustParseAddr("192.0.2.3"), test.iif, test.named); err == nil {
			t.Errorf("%s was followed as %+v", name, info)
		}
	}
	if len(*asked) != 0 {
		t.Errorf("the kernel was asked of %q", *asked)
	}
}

// This host's own packet with a source, or one arriving on a link that the kernel forwards, that the kernel routes into the tun
// goes on through the mesh's checks as ExplainRead names them, a steered one with its policy
// and this host's own packet of no source, whose source the kernel picks, and one the kernel drops with forwarding off end at the kernel's route
// as a session's packet the mesh delivers does, which TestDebugRouteFollowsASessionsPacketThroughTheMesh reads
func TestDebugRouteFollowsAReadIntoTheMesh(t *testing.T) {
	intoTun := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("3fff::/20"), Table: 100, Type: "unicast", NextHops: []kernel.NextHop{{Device: "ranet0"}}}
	c, _, _ := meshRouteClient(t, intoTun, nil, nil)
	src, dst := netip.MustParseAddr("3fff::2"), netip.MustParseAddr("3fff::3")
	info, err := c.DebugRoute(src, dst, "", "")
	if err != nil {
		t.Fatal(err)
	}
	explained := c.Mesh.ExplainRead(routePacket(src, dst))
	m := info.Mesh
	if m == nil || explained.Decision != netstack.TraceForward || m.Decision != explained.Decision.String() || m.Next != routeFar || m.MTU != routeFarMTU || info.Unfollowed != "" {
		t.Fatalf("the mesh reads %+v, want %+v, unfollowed %q", m, explained, info.Unfollowed)
	}
	if p := m.Policy; p == nil || p.From != netip.MustParsePrefix("3fff::2/128") || !slices.Equal(p.Path, []netip.Addr{netip.MustParseAddr("3fff:1::1")}) || p.Overhead != srv6.Overhead(1) || m.Matched != netip.MustParsePrefix("3fff::3/128") {
		t.Errorf("the read is steered by %+v, matching %s", m.Policy, m.Matched)
	}

	if info, _ := c.DebugRoute(netip.Addr{}, dst, "", ""); info.Mesh != nil || !info.Kernel.IntoTun || info.Unfollowed == "" {
		t.Errorf("a packet of no source reads %+v and %+v, unfollowed %q", info.Mesh, info.Kernel, info.Unfollowed)
	}
	c, _, _ = meshRouteClient(t, intoTun, nil, map[string]string{"net/ipv6/conf/all/forwarding": "0"})
	if info, _ := c.DebugRoute(netip.MustParseAddr("2001:db8:100::20"), dst, "lan0", ""); info.Mesh != nil || info.Kernel.Why != control.WhyForwardingOff {
		t.Errorf("a packet the kernel drops with forwarding off reads %+v and %+v", info.Mesh, info.Kernel)
	}
	c, _, _ = meshRouteClient(t, intoTun, nil, map[string]string{"net/ipv6/conf/all/forwarding": "1"})
	if info, _ := c.DebugRoute(netip.MustParseAddr("2001:db8:100::20"), dst, "lan0", ""); info.Mesh == nil || info.Mesh.Decision != c.Mesh.ExplainRead(routePacket(netip.MustParseAddr("2001:db8:100::20"), dst)).Decision.String() {
		t.Errorf("a link's packet into the tun reads %+v", info.Mesh)
	}
}

// The view's walk moves no counter, the answers sent and withheld among them, records nothing, and hands nothing to the tun or the exit
// over a session's packets, a segment's and a read's, each followed more times than one source's bucket of ICMP tokens holds
func TestDebugRouteSpendsNothing(t *testing.T) {
	local := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("192.0.2.2/32"), Table: 255, Type: "local"}
	intoTun := kernel.MatchedRoute{Prefix: netip.MustParsePrefix("3fff::/20"), Table: 100, Type: "unicast", NextHops: []kernel.NextHop{{Device: "ranet0"}}}
	for name, test := range map[string]struct {
		answer   kernel.MatchedRoute
		src, dst string
		iif, via string
	}{
		"a forward":                     {local, "192.0.2.1", "192.0.2.3", "", routeGateway},
		"this host's own":               {local, "192.0.2.1", "192.0.2.2", "", routeGateway},
		"an egress":                     {local, "192.0.2.1", "203.0.113.200", "", routeGateway},
		"no route":                      {local, "3fff::1", "2001:db8::5", "", routeGateway},
		"an unrouted source":            {local, "203.0.113.66", "203.0.113.200", "", routeGateway},
		"egress from its allow list":    {local, "3fff::1", routeEgress.String(), "", routeGateway},
		"egress outside its allow list": {local, "3fff::3", routeEgress.String(), "", routeGateway},
		"End from outside the overlay":  {local, "2001:db8:66::6", routeEnd.String(), "", routeGateway},
		"a steered read":                {intoTun, "3fff::2", "3fff::3", "", ""},
		"a link's packet into the tun":  {intoTun, "2001:db8:100::20", "2001:db8::5", "lan0", ""},
	} {
		t.Run(name, func(t *testing.T) {
			c, _, written := meshRouteClient(t, test.answer, nil, map[string]string{"net/ipv6/conf/all/forwarding": "1"})
			feed, err := c.Mesh.Trace(netstack.TraceFilter{}, 0, control.TraceRateMax)
			if err != nil {
				t.Fatal(err)
			}
			defer feed.Close()
			for range 64 {
				if _, err := c.DebugRoute(netip.MustParseAddr(test.src), netip.MustParseAddr(test.dst), test.iif, test.via); err != nil {
					t.Fatal(err)
				}
			}
			m := c.Mesh
			if got := m.TransitCounters(); got != (netstack.TransitCounters{}) {
				t.Errorf("the walk counted %+v", got)
			}
			if got := m.SegmentCounters(); got != (netstack.SegmentCounters{}) {
				t.Errorf("the walk counted %+v", got)
			}
			if bySource, byNode := m.ICMPWithheld(); bySource+byNode != 0 || m.TooBigAnswered() != 0 || m.MSSClamped() != 0 {
				t.Errorf("the walk withheld %d and %d answers, answered %d about a size and clamped %d", bySource, byNode, m.TooBigAnswered(), m.MSSClamped())
			}
			if counts := feed.Counts(); counts != (netstack.TraceCounts{}) {
				t.Errorf("the walk was traced as %+v", counts)
			}
			if n, egressed := written.writes.Load(), written.egressed.Load(); n+egressed != 0 {
				t.Errorf("the walk wrote %d batches to the tun and handed %d to the exit", n, egressed)
			}
		})
	}
}

// The packet the view follows is one IP packet of no option or extension header with a header that checks, an echo request whose checksum sums to zero
func TestRoutePacketIsWellFormed(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.1", "203.0.113.200"}, {"3fff::1", "2001:db8::5"}} {
		src, dst := netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])
		raw := routePacket(src, dst)
		gotSrc, gotDst, version := packet.Addrs(raw)
		if payload, _ := packet.Payload(raw); gotSrc != src || gotDst != dst || len(payload) != len(raw) {
			t.Fatalf("%x reads from %s to %s, version %d", raw, gotSrc, gotDst, version)
		}
		header, sum := 20, packet.Sum(0, raw[20:])
		if version == 6 {
			header = 40
			sum = packet.Sum(packet.Sum(packet.Sum(0, raw[8:40]), []byte{0, 0, 0, 8, 0, 0, 0, 58}), raw[40:])
			if raw[6] != 58 || raw[40] != 128 || raw[7] != routeHopLimit {
				t.Errorf("%x is no ICMPv6 echo request of hop limit %d", raw, routeHopLimit)
			}
		} else if !packet.HeaderValid(raw) || raw[9] != 1 || raw[20] != 8 || raw[8] != routeHopLimit {
			t.Errorf("%x is no ICMP echo request of TTL %d with a header that checks", raw, routeHopLimit)
		}
		if uint16(sum) != 0xffff || len(raw) != header+8 {
			t.Errorf("%x sums to %#x past its header of %d", raw, sum, header)
		}
	}
}
