// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

func tableOf(addresses ...string) *kernel.Table {
	table := &kernel.Table{}
	for _, address := range addresses {
		table.Addresses = append(table.Addresses, schema.MustPrefix(address))
	}
	return table
}

// a router-id is the first global address cap.table assigns in its family that an announced prefix covers, else the first host prefix of it cap.route announces
// and the SID is the first End SID of cap.segment local that an announced prefix covers
// a prefix covers only where it has no source and does not count as a default with cap.border's overlay
// so a default, its halves and a source-specific entry never do, nor a prefix shorter than /8 or /16 the overlay leaves uncovered, fd00::/8 among them
// an address no packet from elsewhere may come from, a network's base address, an IPv4 network's directed broadcast but a /31's and a prefix covering more than one host never is one
func TestAnswerSourcesAreTheRouterIDsAndTheFirstSID(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		cfg                   config.Config
		router4, router6, sid string
	}{
		{name: "a node holding nothing"},
		{
			name: "a table assigning both families inside what is announced",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("10.66.0.5/32", "3fff:1::5/128", "10.66.0.6/32"),
				Route: &babel.Routes{Announce: announce("10.66.0.0/24", "3fff:1::/48")},
			}},
			router4: "10.66.0.5", router6: "3fff:1::5",
		},
		{
			name: "a table whose first address no announced prefix covers",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("10.67.0.5/32", "3fff:2::5/128", "10.66.0.6/32", "3fff:1::6/128"),
				Route: &babel.Routes{Announce: announce("10.66.0.0/24", "3fff:1::/48")},
			}},
			router4: "10.66.0.6", router6: "3fff:1::6",
		},
		{
			name: "a table nothing announced covers",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("10.67.0.5/32", "3fff:2::5/128"),
				Route: &babel.Routes{Announce: announce("10.66.0.0/24", "3fff:1::/48")},
			}},
		},
		{
			name: "a table only an announced default covers",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("10.67.0.5/32", "3fff:2::5/128"),
				Route: &babel.Routes{Announce: announce("0.0.0.0/0", "::/0", "10.66.0.0/24", "3fff:1::/48")},
			}},
		},
		{
			name: "a table only announced half defaults cover",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("10.67.0.5/32", "198.51.100.5/32", "3fff:2::5/128"),
				Route: &babel.Routes{Announce: announce("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.66.0.0/24", "3fff:1::/48")},
			}},
		},
		{
			name: "a table and a segment only prefixes shorter than /8 or /16 outside the overlay cover",
			cfg: config.Config{Cap: config.Caps{
				Table:   tableOf("192.0.2.5/32", "fd00::5/128"),
				Route:   &babel.Routes{Announce: announce("192.0.0.0/7", "fd00::/8")},
				Border:  &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}},
				Segment: &srv6.Segments{Local: []srv6.Segment{{SID: schema.MustAddr("fd00::1"), Behavior: srv6.BehaviorEnd}}},
			}},
		},
		{
			name: "the same prefixes without cap.border",
			cfg: config.Config{Cap: config.Caps{
				Table:   tableOf("192.0.2.5/32", "fd00::5/128"),
				Route:   &babel.Routes{Announce: announce("192.0.0.0/7", "fd00::/8")},
				Segment: &srv6.Segments{Local: []srv6.Segment{{SID: schema.MustAddr("fd00::1"), Behavior: srv6.BehaviorEnd}}},
			}},
		},
		{
			name: "the same prefixes inside the overlay",
			cfg: config.Config{Cap: config.Caps{
				Table:   tableOf("192.0.2.5/32", "fd00::5/128"),
				Route:   &babel.Routes{Announce: announce("192.0.0.0/7", "fd00::/8")},
				Border:  &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.0.0/7"), schema.MustPrefix("fd00::/8")}},
				Segment: &srv6.Segments{Local: []srv6.Segment{{SID: schema.MustAddr("fd00::1"), Behavior: srv6.BehaviorEnd}}},
			}},
			router4: "192.0.2.5", router6: "fd00::5", sid: "fd00::1",
		},
		{
			name: "a table and a host prefix only source-specific entries cover",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("3fff:2::5/128"),
				Route: &babel.Routes{Announce: append(announce("3fff:1::/48"),
					schema.Announce{Prefix: schema.MustPrefix("3fff:2::/48"), From: schema.MustPrefix("3fff:9::/48")},
					schema.Announce{Prefix: schema.MustPrefix("3fff:b::1/128"), From: schema.MustPrefix("3fff:9::/48")},
				)},
			}},
		},
		{
			name: "a table assigning addresses in class E and network 0 first",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("240.0.0.5/32", "0.1.2.3/32", "10.66.0.6/32"),
				Route: &babel.Routes{Announce: announce("240.0.0.0/8", "0.1.2.0/24", "10.66.0.0/24")},
			}},
			router4: "10.66.0.6",
		},
		{
			name: "a table assigning a network's directed broadcast first",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("192.0.2.255/24", "192.0.2.7/24"),
				Route: &babel.Routes{Announce: announce("192.0.2.0/24")},
			}},
			router4: "192.0.2.7",
		},
		{
			name: "a table assigning the upper host of a /31",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("192.0.2.9/31"),
				Route: &babel.Routes{Announce: announce("192.0.2.8/31")},
			}},
			router4: "192.0.2.9",
		},
		{
			name: "a table assigning an IPv4 address mapped into IPv6 first",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("::ffff:10.66.0.5/128", "3fff:1::6/128"),
				Route: &babel.Routes{Announce: announce("::ffff:10.66.0.0/120", "3fff:1::/48")},
			}},
			router6: "3fff:1::6",
		},
		{
			name: "a table assigning a link-local address first",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("fe80::1/64", "169.254.0.1/16", "3fff:1::2/64"),
				Route: &babel.Routes{Announce: announce("fe80::/64", "169.254.0.0/16", "3fff:1::/64")},
			}},
			router6: "3fff:1::2",
		},
		{
			name:    "announced host prefixes and a network written by one of its hosts without a table",
			cfg:     config.Config{Cap: config.Caps{Route: &babel.Routes{Announce: announce("3fff:a::1/48", "10.66.0.7/32", "3fff:b::1/128")}}},
			router4: "10.66.0.7", router6: "3fff:b::1",
		},
		{
			name: "a table ahead of an announced host prefix",
			cfg: config.Config{Cap: config.Caps{
				Table: tableOf("3fff:1::5/64"),
				Route: &babel.Routes{Announce: announce("3fff:b::1/128", "10.66.0.7/32", "3fff:1::/64")},
			}},
			router4: "10.66.0.7", router6: "3fff:1::5",
		},
		{
			name: "a table assigning what is announced",
			cfg: config.Config{Cap: config.Caps{
				Table: &kernel.Table{AssignAnnounced: true},
				Route: &babel.Routes{Announce: announce("10.66.1.1/24")},
			}},
			router4: "10.66.1.1",
		},
		{
			name: "a table assigning networks by their base addresses",
			cfg: config.Config{Cap: config.Caps{
				Table: &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("3fff:1::/64"), schema.MustPrefix("3fff:1::7/64")}, AssignAnnounced: true},
				Route: &babel.Routes{Announce: announce("10.66.1.0/24", "3fff:1::/48", "10.66.2.9/32")},
			}},
			router4: "10.66.2.9", router6: "3fff:1::7",
		},
		{
			name: "local segments",
			cfg: config.Config{Cap: config.Caps{
				Route: &babel.Routes{Announce: announce("3fff:1:69c:8c6::/64")},
				Segment: &srv6.Segments{Local: []srv6.Segment{
					{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEnd},
					{SID: schema.MustAddr("3fff:1:69c:8c6::2"), Behavior: srv6.BehaviorEnd},
				}},
			}},
			sid: "3fff:1:69c:8c6::1",
		},
		{
			name: "a link-local End segment an announced prefix covers ahead of a global one",
			cfg: config.Config{Cap: config.Caps{
				Route: &babel.Routes{Announce: announce("fe80::/64", "3fff:d::/64")},
				Segment: &srv6.Segments{Local: []srv6.Segment{
					{SID: schema.MustAddr("fe80::1"), Behavior: srv6.BehaviorEnd},
					{SID: schema.MustAddr("3fff:d::1"), Behavior: srv6.BehaviorEnd},
				}},
			}},
			sid: "3fff:d::1",
		},
		{
			name: "an egress segment and segments only a default or a source-specific entry covers ahead of an End one",
			cfg: config.Config{Cap: config.Caps{
				Route: &babel.Routes{Announce: append(announce("3fff:1:69c:8c6::/64", "3fff:1:69c:9800::/56", "::/0"),
					schema.Announce{Prefix: schema.MustPrefix("3fff:1:69c:aa::/64"), From: schema.MustPrefix("3fff:9::/48")},
				)},
				Segment: &srv6.Segments{Local: []srv6.Segment{
					{SID: schema.MustAddr("3fff:1:69c:98d6::1"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress},
					{SID: schema.MustAddr("3fff:1:69c:aa::1"), Behavior: srv6.BehaviorEnd},
					{SID: schema.MustAddr("3fff:1:69c:bb::1"), Behavior: srv6.BehaviorEnd},
					{SID: schema.MustAddr("3fff:1:69c:8c6::2"), Behavior: srv6.BehaviorEnd},
				}},
			}},
			sid: "3fff:1:69c:8c6::2",
		},
	} {
		sources := answerSources(&tc.cfg)
		for _, got := range []struct {
			name  string
			found netip.Addr
			want  string
		}{{"IPv4 router-id", sources.Router4, tc.router4}, {"IPv6 router-id", sources.Router6, tc.router6}, {"SID", sources.SID, tc.sid}} {
			if want := addressOrNone(got.want); got.found != want {
				t.Errorf("%s answers from the %s %v, want %v", tc.name, got.name, got.found, want)
			}
		}
	}
}

// the pmtu view shows the router-id of each family and the answer SID as the mesh holds them
func TestPMTUViewShowsTheRouterIDsAndTheAnswerSID(t *testing.T) {
	c := &Client{sessions: newSessionSet(), Mesh: netstack.NewRoutesOnly()}
	c.cfg.Store(&config.Config{})
	held := netstack.AnswerSources{Router4: netip.MustParseAddr("100.64.0.1"), Router6: netip.MustParseAddr("3fff:c::1"), SID: netip.MustParseAddr("3fff:1:69c:8c6::1")}
	c.Mesh.SetAnswerSources(held)
	if info := c.DebugPMTU(""); info.RouterIDv4 != held.Router4 || info.RouterIDv6 != held.Router6 || info.AnswerSID != held.SID {
		t.Errorf("a mesh answering from %+v shows %v, %v and %v", held, info.RouterIDv4, info.RouterIDv6, info.AnswerSID)
	}
}

// a node started on a table hands the mesh the router-ids it makes before any republish or reload
func TestStartHandsTheMeshItsRouterIDs(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Link.Port = freeUDPPort(t)
	cfg.Cap.Table = tableOf("10.66.0.5/32", "3fff:1::5/128")
	cfg.Cap.Route = &babel.Routes{Announce: announce("10.66.0.0/24", "3fff:1::/48")}
	mesh := netstack.NewRoutesOnly()
	c, err := newClient(cfg, privateKey, trust(t, reg), mesh, nil, events.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if sources := mesh.AnswerSources(); sources.Router4 != netip.MustParseAddr("10.66.0.5") || sources.Router6 != netip.MustParseAddr("3fff:1::5") {
		t.Errorf("a node started assigning 10.66.0.5 and 3fff:1::5 answers from %v and %v", sources.Router4, sources.Router6)
	}
}

func addressOrNone(written string) netip.Addr {
	if written == "" {
		return netip.Addr{}
	}
	return netip.MustParseAddr(written)
}

// a reload changing the address cap.table assigns hands the mesh the router-id it now makes, as a startup on that file would
func TestReloadMovesTheRouterIDWithTheTable(t *testing.T) {
	c, path, _, _ := reloadOf(t, func(old *config.Config) {
		old.Cap.Table = tableOf("10.66.0.5/32", "3fff:1::5/128")
		old.Cap.Route = &babel.Routes{Announce: announce("10.66.0.0/24", "3fff:1::/48")}
	})
	c.Republish()
	if sources := c.Mesh.AnswerSources(); sources.Router4 != netip.MustParseAddr("10.66.0.5") || sources.Router6 != netip.MustParseAddr("3fff:1::5") {
		t.Fatalf("a node assigning 10.66.0.5 and 3fff:1::5 answers from %v and %v", sources.Router4, sources.Router6)
	}
	next := *c.config()
	next.Cap.Table = tableOf("10.66.0.6/32")
	writeConfig(t, path, &next)
	if err := c.ReloadFrom(path); err != nil {
		t.Fatalf("the reload was refused: %v", err)
	}
	if sources := c.Mesh.AnswerSources(); sources.Router4 != netip.MustParseAddr("10.66.0.6") || sources.Router6.IsValid() {
		t.Errorf("a reload to a table assigning only 10.66.0.6 left the mesh answering from %v and %v", sources.Router4, sources.Router6)
	}
}
