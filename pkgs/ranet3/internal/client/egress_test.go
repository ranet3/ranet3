// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// The userspace exit's Held reads the addresses the network watch read last,
// each family's own, so an address of either family the host holds on a link
// outside the mesh is held, and one it does not hold or holds no more is not.
// With no watch, nothing is held.
func TestHeldAddressIsWhatTheWatchReadLast(t *testing.T) {
	v4, v6 := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("2001:db8::9")
	other4, other6 := netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("2001:db8::10")
	c := &Client{}
	if c.HeldAddress(v4) || c.HeldAddress(v6) {
		t.Fatal("an address is held with no watch")
	}
	network := &fakeNetwork{changes: make(chan kernel.NetworkChange), current: kernel.NetworkState{
		IPv4: kernel.NetworkFamily{Addresses: []netip.Addr{v4}},
		IPv6: kernel.NetworkFamily{Addresses: []netip.Addr{v6}},
	}}
	c.network = network
	for address, held := range map[netip.Addr]bool{v4: true, v6: true, other4: false, other6: false} {
		if got := c.HeldAddress(address); got != held {
			t.Errorf("%s held %t, want %t", address, got, held)
		}
	}
	network.current = kernel.NetworkState{IPv6: kernel.NetworkFamily{Addresses: []netip.Addr{v6}}}
	if c.HeldAddress(v4) || !c.HeldAddress(v6) {
		t.Errorf("held %s %t and %s %t once the host gave the first up, want only the second", v4, c.HeldAddress(v4), v6, c.HeldAddress(v6))
	}
}

// The members the egress translator reads from are the prefixes the mesh routes
// by the tun to another node, with no source prefix, each inside an entry of
// overlay and overlapping none of this node's own entries. A hold, a
// prefix of this node's, one reaching past the overlay and one routed from a
// source are none, and a default this node originates for what it carries out
// of the mesh leaves every member in place
func TestEgressMembersAreOtherNodesPrefixesInsideTheOverlay(t *testing.T) {
	b := &netstack.Peer{ID: "example/b"}
	route := func(source, destination string, peer *netstack.Peer) sadr.Route[*netstack.Peer] {
		var from netip.Prefix
		if source != "" {
			from = netip.MustParsePrefix(source)
		}
		return sadr.Route[*netstack.Peer]{Source: from, Destination: netip.MustParsePrefix(destination), Value: peer}
	}
	overlay := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff:20::/32")}
	routes := []sadr.Route[*netstack.Peer]{
		route("", "0.0.0.0/0", netstack.Local),
		route("", "::/0", netstack.Local),
		route("", "192.0.2.64/26", b),
		route("", "203.0.113.0/24", b),
		route("", "192.0.2.0/23", b),
		route("198.51.100.0/24", "192.0.2.128/26", b),
		route("", "192.0.2.16/28", netstack.Unreachable),
		route("", "192.0.2.32/27", netstack.Local),
		route("", "192.0.2.40/29", b),
		route("", "3fff:20:1::/48", b),
		route("", "3fff:20:5::1/128", netstack.Assigned),
		route("", "3fff:20:5::/48", b),
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.64/26"), netip.MustParsePrefix("3fff:20:1::/48")}
	if got := memberPrefixes(routes, overlay); !slices.Equal(got, want) {
		t.Errorf("the members of %v under the overlay %v are %v, want %v", routes, overlay, got, want)
	}
	if got := memberPrefixes(routes, nil); len(got) != 0 {
		t.Errorf("with no overlay the members are %v, want none", got)
	}
}
