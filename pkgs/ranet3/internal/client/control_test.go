// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// countedMesh is a mesh whose every transit and segment counter holds a count no other holds
// set in the mesh's own fields, so what reads them meets the mesh's getters with every field nonzero
func countedMesh(t *testing.T) *netstack.Mesh {
	t.Helper()
	m := netstack.NewOnDevice(&routeTun{})
	t.Cleanup(m.Close)
	mesh := reflect.ValueOf(m).Elem()
	field := func(v reflect.Value, name string) reflect.Value {
		found := v.FieldByName(name)
		if !found.IsValid() {
			t.Fatalf("the mesh holds no counter %s", name)
		}
		return found
	}
	var counters []reflect.Value
	transit := field(mesh, "transitCounts")
	for i := range transit.Len() {
		counters = append(counters, transit.Index(i))
	}
	for _, name := range []string{"unanswered", "segmentsForwarded", "segmentsDelivered", "segmentsDropped", "segmentsSteered", "segmentsUnsteered",
		"segmentsUnrouted", "segmentsAnswered", "segmentsEgressed", "segmentsRefused", "segmentsNotReady"} {
		counters = append(counters, field(mesh, name))
	}
	counters = append(counters, field(field(mesh, "ecnUnused"), "total"))
	for i, counter := range counters {
		(*atomic.Uint64)(unsafe.Pointer(counter.UnsafeAddr())).Store(uint64(i + 1))
	}
	return m
}

// status, the segments view and the scrape carry every field of the mesh's transit and segment counters as the mesh's getters read it
func TestStatusCarriesEveryCounterOfTheMesh(t *testing.T) {
	c := writable(t)
	c.Mesh = countedMesh(t)
	transit, segments := control.TransitCounters(c.Mesh.TransitCounters()), control.SegmentCounters(c.Mesh.SegmentCounters())
	for _, counters := range []reflect.Value{reflect.ValueOf(transit), reflect.ValueOf(segments)} {
		for i := range counters.NumField() {
			if counters.Field(i).Uint() == 0 {
				t.Fatalf("the mesh's %s.%s holds no count", counters.Type(), counters.Type().Field(i).Name)
			}
		}
	}
	status := c.Status()
	if status.Transit != transit {
		t.Errorf("status carries the transit counters %+v, the mesh counted %+v", status.Transit, transit)
	}
	if status.SegmentCounters != segments {
		t.Errorf("status carries the segment counters %+v, the mesh counted %+v", status.SegmentCounters, segments)
	}
	if got := c.DebugSegments().Counters; got != segments {
		t.Errorf("the segments view carries %+v, the mesh counted %+v", got, segments)
	}
	var scrape strings.Builder
	c.renderTransitCounters(&scrape)
	c.renderSegmentCounters(&scrape)
	want := []string{
		fmt.Sprintf(`ranet3_transit_packets_total{decision="forwarded",reason=""} %d`, transit.Forwarded),
		fmt.Sprintf(`ranet3_transit_packets_total{decision="delivered",reason=""} %d`, transit.Delivered),
		fmt.Sprintf(`ranet3_transit_packets_total{decision="answered",reason=""} %d`, transit.Answered),
		fmt.Sprintf(`ranet3_transit_packets_total{decision="unanswered",reason=""} %d`, transit.Unanswered),
		fmt.Sprintf(`ranet3_transit_packets_total{decision="unsent",reason=""} %d`, transit.Unsent),
		fmt.Sprintf("ranet3_segments_forwarded_total %d", segments.Forwarded),
		fmt.Sprintf("ranet3_segments_delivered_total %d", segments.Delivered),
		fmt.Sprintf("ranet3_segments_dropped_total %d", segments.Dropped),
		fmt.Sprintf("ranet3_segments_answered_total %d", segments.Answered),
		fmt.Sprintf("ranet3_segments_egressed_total %d", segments.Egressed),
		fmt.Sprintf("ranet3_segments_refused_total %d", segments.Refused),
		fmt.Sprintf("ranet3_segments_not_ready_total %d", segments.NotReady),
		fmt.Sprintf("ranet3_segments_ecn_unused_total %d", segments.ECNUnused),
		fmt.Sprintf("ranet3_steered_total %d", segments.Steered),
		fmt.Sprintf(`ranet3_steer_dropped_total{reason="too_large"} %d`, segments.Unsteered),
		fmt.Sprintf(`ranet3_steer_dropped_total{reason="no_route"} %d`, segments.Unrouted),
	}
	for _, drop := range transit.Drops() {
		want = append(want, fmt.Sprintf(`ranet3_transit_packets_total{decision="dropped",reason="%s"} %d`, drop.Label, drop.Packets))
	}
	var got []string
	for line := range strings.Lines(scrape.String()) {
		if !strings.HasPrefix(line, "#") {
			got = append(got, strings.TrimSuffix(line, "\n"))
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("the scrape carries the series\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// loadable is a node complete enough to load carrying segment
// a check Validate makes once every capability has passed its own needs the rest of the file to pass as well
func loadable(segment *srv6.Segments) *config.Config {
	return &config.Config{
		Node: identity.MustParse("example/node"),
		Auth: config.Auth{Key: "key.pem", Trust: "trust.json"},
		Link: config.Link{
			Port:      13000,
			Listen:    true,
			Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}},
		},
		Cap: config.Caps{Segment: segment},
	}
}

// A SID this node also carries as an address would swallow every ordinary
// packet to that address: the inbound seam acts on the destination before the
// tun sees it, and a packet with no routing header is then refused rather than
// delivered. On linux the two coexist, because there the SID is a route.
//
// The check spans cap.segment and cap.table, so it lives where the file is
// read rather than in either capability.
func TestLocalSegmentOnOneOfThisNodesAddressesIsRefused(t *testing.T) {
	cfg := loadable(&srv6.Segments{Local: []srv6.Segment{
		{SID: schema.MustAddr("3fff:b:0:106::1"), Behavior: srv6.BehaviorEndDT46},
	}})
	cfg.Cap.Table = &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("3fff:b:0:106::1/128")}}
	cfg.Overlay = overlayOf("3fff::/20")
	if err := cfg.Validate(); err == nil {
		t.Error("a segment on one of this node's own addresses was accepted")
	}
	cfg.Cap.Table.Addresses = []schema.Prefix{schema.MustPrefix("3fff:b:0:106::9/128")}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a segment beside an unrelated address was refused: %v", err)
	}

	// assign_announced puts every announced prefix on the device too, so the
	// check covers everything the reconciler assigns rather than the addresses
	// list alone.
	cfg.Cap.Table.AssignAnnounced = true
	cfg.Cap.Route = &babel.Routes{Announce: announce("3fff:b:0:106::1/128")}
	if err := cfg.Validate(); err == nil {
		t.Error("a segment on a prefix this node assigns from cap.route was accepted")
	}
}

// A host address written with a prefix length is refused rather than masked,
// as the rule list refuses the same typo. Masking steers a whole prefix where
// one address was meant and says nothing about it.
// both go through the file's whole validation, which also holds the list to link.mtu
func TestSteerSelectorWithHostBitsIsRefused(t *testing.T) {
	cfg := loadable(&srv6.Segments{
		Source: schema.MustAddr("3fff:b:0:100::1"),
		Steer: []srv6.Steer{{
			From: schema.MustPrefix("3fff:a::203:0:113:10/64"),
			Via:  []schema.Addr{schema.MustAddr("3fff:b:0:206::1")},
		}},
	})
	if err := cfg.Validate(); err == nil {
		t.Error("a selector with bits below its prefix length was accepted")
	}
	cfg.Cap.Segment.Steer[0].From = schema.MustPrefix("3fff:a::203:0:113:10/128")
	if err := cfg.Validate(); err != nil {
		t.Errorf("a host selector was refused: %v", err)
	}
}

// An exit withholds a prefix whose translation rule is not installed, so that
// this node stops attracting traffic it would have to drop. A second,
// unconditional announcement of the same prefix takes that back and leaves the
// withholding reporting as working while changing nothing on the wire.
func TestEgressPrefixAnnouncedUnconditionallyIsRefused(t *testing.T) {
	exit := schema.MustPrefix("198.51.100.0/24")
	cfg := &config.Config{Cap: config.Caps{
		Route:  &babel.Routes{Announce: []schema.Announce{{Prefix: exit}}},
		Egress: &egress.Egress{Advertise: []schema.Prefix{exit}},
	}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced both by the capability and unconditionally was accepted")
	}
	cfg.Cap.Route.Announce = []schema.Announce{{Prefix: schema.MustPrefix("10.88.0.2/32")}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err != nil {
		t.Errorf("an unrelated announcement was refused: %v", err)
	}

	// The source-specific spelling is the same list, so it is covered too: an
	// exit's own default from its transit prefix is written that way.
	cfg.Cap.Route.Announce = []schema.Announce{{Prefix: exit, From: schema.MustPrefix("2001:db8::/48")}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced with a source as well was accepted")
	}
}

// The capability announces nothing until the exit says it may, so a node
// whose command never built one announces exactly what cap.route names.
func TestAnnouncementTakesTheEgressPrefixesFromTheTranslator(t *testing.T) {
	cfg := &config.Config{Cap: config.Caps{
		Route: &babel.Routes{Announce: []schema.Announce{{Prefix: schema.MustPrefix("10.88.0.2/32")}}},
	}}
	c := &Client{Mesh: &netstack.Mesh{}}
	if routes := c.announced(cfg, c.egressAdvertised()); len(routes) != 1 {
		t.Fatalf("announced %v with no exit, want cap.route alone", routes)
	}
	exit := netip.MustParsePrefix("0.0.0.0/0")
	c.SetExit(&fakeExit{announce: func() []netip.Prefix { return []netip.Prefix{exit} }})
	routes := c.announced(cfg, c.egressAdvertised())
	if len(routes) != 2 || routes[1].Destination != exit {
		t.Errorf("announced %v, want cap.route's list and the exit's own prefix", routes)
	}
}

// assignedRows is the destinations the route table view marks as addresses cap.table assigns
func assignedRows(c *Client) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range c.Routes() {
		if route.Assigned {
			out = append(out, route.Destination)
		}
	}
	return out
}

// The addresses cap.table assigns are this node's own from the start, each at
// its host route whatever prefix length it is written with, and the route
// table view marks them.
func TestAssignedAddressesAreThisNodesOwnFromTheStart(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Cap.Table = &kernel.Table{
		Addresses:       []schema.Prefix{schema.MustPrefix("10.66.0.5/24")},
		AssignAnnounced: true,
	}
	cfg.Cap.Route = &babel.Routes{Announce: announce("fd00:1::1/64")}
	c, err := newClient(cfg, privateKey, trust(t, reg), netstack.NewRoutesOnly(), nil, events.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	address := netip.MustParseAddr("10.66.0.5")
	if _, verdict, _ := c.Mesh.Routes.Resolve(address, address); verdict != netstack.RouteLocal {
		t.Errorf("%s resolves as %v, want this node's own", address, verdict)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.66.0.5/32"), netip.MustParsePrefix("fd00:1::1/128")}
	if got := assignedRows(c); !slices.Equal(got, want) {
		t.Errorf("the route table view marks %v assigned, want %v", got, want)
	}
}

// status reports the addresses the egress translates into the mesh under, each once, an address cap.table assigns unannounced among them,
// and neither a range cap.route announces nor the egress SID the node originates while it serves it
// a node with none reports none rather than leaving the field out
func TestStatusReportsTheMeshAddressesTheEgressTakes(t *testing.T) {
	const sid = "3fff:b:0:106::3"
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) {
		egressNode(cfg, egressSegment(sid, "3fff:a::/32"))
		cfg.Cap.Route = &babel.Routes{Announce: announce("203.0.113.0/24", "3fff:a::1/128")}
		cfg.Cap.Table = &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("203.0.113.10/32"), schema.MustPrefix("3fff:a::1/128")}}
	})
	c.sessions = newSessionSet()
	segmentsOf(t, c)
	speakerRecording(t, c, bus)
	c.SetEgressReady(true, true, true)
	status := c.Status()
	if !slices.Contains(status.Originate, control.Originated{Prefix: netip.MustParsePrefix(sid + "/128")}) {
		t.Fatalf("the status originates %v, without the egress SID", status.Originate)
	}
	if want := []netip.Addr{netip.MustParseAddr("3fff:a::1"), netip.MustParseAddr("203.0.113.10")}; !slices.Equal(status.MeshAddresses, want) {
		t.Errorf("the status reports the mesh addresses %v, want %v", status.MeshAddresses, want)
	}
	body, err := json.Marshal(writable(t).Status())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"mesh_addresses":[]`) {
		t.Errorf("a node with no mesh address reports %s", body)
	}
}

// status says a node is an initiator exactly where it has a peer to dial, one that dial.to names or dial.all takes from the trust
// document and that its dialer sends an IKE_SA_INIT to, so no peer to dial is a peer the trust document lacks, one whose endpoints
// carry an address only in a family this node has no endpoint of, pinned or not, or one with no endpoint carrying an address, while a
// dual-stack node dials a peer reachable over its second family alone
func TestStatusSaysInitiatorOfANodeWithAPeerToDial(t *testing.T) {
	address, v6 := "192.0.2.7", "2001:db8::7"
	beside := func(endpoint registry.Endpoint) registry.Registry {
		return registry.Registry{{Organization: "example", Nodes: []registry.Node{{CommonName: "node"}, {CommonName: "gateway", Endpoints: []registry.Endpoint{endpoint}}}}}
	}
	alone := registry.Registry{{Organization: "example", Nodes: []registry.Node{{CommonName: "node"}}}}
	dialable := beside(registry.Endpoint{SerialNumber: "1", AddressFamily: "ip4", Address: &address, Port: 13000})
	otherFamily := beside(registry.Endpoint{SerialNumber: "1", AddressFamily: "ip6", Address: &v6, Port: 13000})
	unaddressed := beside(registry.Endpoint{SerialNumber: "1", AddressFamily: "ip4", Port: 13000})
	pinned := config.Dial{To: []identity.Identity{identity.MustParse("example/gateway:1")}}
	node := config.Dial{To: []identity.Identity{identity.MustParse("example/gateway")}}
	v4, dualStack := []config.Endpoint{{Serial: "0", Family: "ip4"}}, []config.Endpoint{{Serial: "0", Family: "ip4"}, {Serial: "1", Family: "ip6"}}
	for name, test := range map[string]struct {
		local []config.Endpoint
		dial  config.Dial
		trust registry.Registry
		want  bool
	}{
		"listening alone":                                                       {local: v4, trust: dialable},
		"dialing a peer the trust document lacks":                               {local: v4, dial: pinned, trust: alone},
		"dialing a pinned endpoint of another family":                           {local: v4, dial: pinned, trust: otherFamily},
		"dialing a node with an address in another family":                      {local: v4, dial: node, trust: otherFamily},
		"dialing a node with no address":                                        {local: v4, dial: node, trust: unaddressed},
		"dialing a pinned endpoint with an address":                             {local: v4, dial: pinned, trust: dialable, want: true},
		"dialing a node with an address":                                        {local: v4, dial: node, trust: dialable, want: true},
		"dual-stack, dialing a node with an address in ip6 alone":               {local: dualStack, dial: node, trust: otherFamily, want: true},
		"under dial.all with no other node":                                     {local: v4, dial: config.Dial{All: true}, trust: alone},
		"under dial.all beside a node with an address in another family":        {local: v4, dial: config.Dial{All: true}, trust: otherFamily},
		"under dial.all beside a node with no address":                          {local: v4, dial: config.Dial{All: true}, trust: unaddressed},
		"under dial.all beside a node with an address":                          {local: v4, dial: config.Dial{All: true}, trust: dialable, want: true},
		"dual-stack, under dial.all beside a node with an address in ip6 alone": {local: dualStack, dial: config.Dial{All: true}, trust: otherFamily, want: true},
	} {
		t.Run(name, func(t *testing.T) {
			c := writable(t)
			c.cfg.Store(&config.Config{Node: identity.MustParse("example/node"), Link: config.Link{Listen: true, Endpoints: test.local}, Dial: test.dial})
			c.storeIndex(trust(t, test.trust))
			if got := c.Status().Initiator; got != test.want {
				t.Errorf("the status reports initiator %v, want %v", got, test.want)
			}
		})
	}
}

// each end of one session reports the role it took in the session's IKE_SA_INIT, initiator where it dialed and responder where it answered,
// and both report the one preference of the session, which holds where alpha, whose name sorts first, dialed
func TestSessionsReportTheRoleOfEachEndAndThePreferenceOfBoth(t *testing.T) {
	for name, alphaDials := range map[string]bool{"alpha dials": true, "bravo dials": false} {
		t.Run(name, func(t *testing.T) {
			alpha, bravo := newLoopbackMesh(t)
			dialer, answerer := alpha, bravo
			if !alphaDials {
				dialer, answerer = bravo, alpha
			}
			quiet := *answerer.cfg
			quiet.Dial.To = nil
			answerer.client.cfg.Store(&quiet)
			run(t, alpha, bravo)
			var dialed, answered []control.Session
			waitFor(t, convergeBudget, "one session at each end", func() bool {
				dialed, answered = dialer.client.Sessions(), answerer.client.Sessions()
				return len(dialed) == 1 && len(answered) == 1
			})
			if dialed[0].LocalSPI != answered[0].RemoteSPI || dialed[0].RemoteSPI != answered[0].LocalSPI {
				t.Fatalf("the two ends hold %+v and %+v, not one SA", dialed[0], answered[0])
			}
			if dialed[0].Role != "initiator" || answered[0].Role != "responder" {
				t.Errorf("%s reports its role in the session it dialed as %q and %s its role in the one it answered as %q", dialer.name, dialed[0].Role, answerer.name, answered[0].Role)
			}
			if dialed[0].Preferred != alphaDials || answered[0].Preferred != alphaDials {
				t.Errorf("%s dialing reports the session preferred %v at %s and %v at %s, want %v at both", dialer.name, dialed[0].Preferred, dialer.name, answered[0].Preferred, answerer.name, alphaDials)
			}
		})
	}
}

// a dial.all peer is dialed at its node and held at the endpoint that answered, so its row is connected through the session's node and local endpoint
func TestPeersMatchSessionsByNodeAndLocalEndpoint(t *testing.T) {
	endpoints := func(serials ...string) []registry.Endpoint {
		var out []registry.Endpoint
		for i, serial := range serials {
			out = append(out, registry.Endpoint{SerialNumber: serial, AddressFamily: []string{"ip4", "ip6"}[i], Port: 13000})
		}
		return out
	}
	c := &Client{sessions: newSessionSet()}
	c.sessions.trust = liveTrust{c}
	c.storeIndex(trust(t, registry.Registry{{Organization: "example", Nodes: []registry.Node{
		{CommonName: "local", Endpoints: endpoints("0", "1")},
		{CommonName: "gateway", Endpoints: endpoints("1", "2")},
		{CommonName: "other", Endpoints: endpoints("0", "3")},
	}}}))
	c.cfg.Store(&config.Config{
		Node: identity.MustParse("example/local"),
		Link: config.Link{Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}, {Serial: "1", Family: "ip6"}}},
		Dial: config.Dial{To: []identity.Identity{identity.MustParse("example/gateway:1")}, All: true},
	})
	for _, held := range []struct{ remote, local string }{{"example/gateway:1", "example/local:0"}, {"example/other:3", "example/local:1"}} {
		remote, local := identity.MustParse(held.remote), identity.MustParse(held.local)
		key, err := c.index().Key(remote)
		if err != nil {
			t.Fatal(err)
		}
		if _, adopted := c.sessions.adopt(identity.Path(remote, local), &ike.Session{}, local, remote, key, true, nil, nil); !adopted {
			t.Fatalf("the session with %s was not adopted", held.remote)
		}
	}
	want := []control.Peer{
		{Path: "example/gateway:1@0", Peer: "example/gateway:1", Connected: true},
		{Path: "example/gateway:1@1", Peer: "example/gateway:1"},
		{Path: "example/other@0", Peer: "example/other", Generated: true},
		{Path: "example/other@1", Peer: "example/other", Connected: true, Generated: true},
	}
	if got := c.Peers(); !slices.Equal(got, want) {
		t.Errorf("peers %+v, want %+v", got, want)
	}
}
