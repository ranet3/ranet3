// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

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

// A field added to the dataplane's counters and not to the wire's is a number
// that silently stops being reported, as an earlier version of the mapper in
// control.go allowed. The conversion below is legal only while the two
// structs have identical underlying types, so it is the check writing the
// fields out by name cannot give.
func TestSegmentCountersDoNotDrift(t *testing.T) {
	var counters netstack.SegmentCounters
	_ = control.SegmentCounters(counters)
}

// the forwarding decision's counters and their wire form hold the same fields in the same order, so a field added to either has to be added to both
// and transitCounters carries each field onto the one of its name
func TestTransitCountersDoNotDrift(t *testing.T) {
	var counters netstack.TransitCounters
	fields := reflect.ValueOf(&counters).Elem()
	for i := range fields.NumField() {
		fields.Field(i).SetUint(uint64(i + 1))
	}
	if got, want := transitCounters(counters), control.TransitCounters(counters); got != want {
		t.Errorf("status carries %+v for the decision's %+v", got, want)
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
		{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEndDT46},
	}})
	cfg.Cap.Table = &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("3fff:1:69c:8c6::1/128")}}
	cfg.Cap.Border = borderOf("3fff::/20")
	if err := cfg.Validate(); err == nil {
		t.Error("a segment on one of this node's own addresses was accepted")
	}
	cfg.Cap.Table.Addresses = []schema.Prefix{schema.MustPrefix("3fff:1:69c:8c6::9/128")}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a segment beside an unrelated address was refused: %v", err)
	}

	// assign_announced puts every announced prefix on the device too, so the
	// check covers everything the reconciler assigns rather than the addresses
	// list alone.
	cfg.Cap.Table.AssignAnnounced = true
	cfg.Cap.Route = &babel.Routes{Announce: announce("3fff:1:69c:8c6::1/128")}
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
		Source: schema.MustAddr("3fff:1:69c:8c0::1"),
		Steer: []srv6.Steer{{
			From: schema.MustPrefix("3fff:a::198:18:104:117/64"),
			Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
		}},
	})
	if err := cfg.Validate(); err == nil {
		t.Error("a selector with bits below its prefix length was accepted")
	}
	cfg.Cap.Segment.Steer[0].From = schema.MustPrefix("3fff:a::198:18:104:117/128")
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

// The capability announces nothing until the translator says it may, so a node
// whose command never built one announces exactly what cap.route names.
func TestAnnouncementTakesTheEgressPrefixesFromTheTranslator(t *testing.T) {
	cfg := &config.Config{Cap: config.Caps{
		Route: &babel.Routes{Announce: []schema.Announce{{Prefix: schema.MustPrefix("10.88.0.2/32")}}},
	}}
	c := &Client{}
	if routes := c.announced(cfg, c.egressAdvertised()); len(routes) != 1 {
		t.Fatalf("announced %v with no translator, want cap.route alone", routes)
	}
	exit := netip.MustParsePrefix("0.0.0.0/0")
	c.SetEgressAnnounce(func() []netip.Prefix { return []netip.Prefix{exit} })
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
