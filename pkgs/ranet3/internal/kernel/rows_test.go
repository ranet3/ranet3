// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

// Each row of routing.md's "Where a lookup ends on Linux" for a lookup bound to
// no device, L1 to L12, and in exit mode, E1 to E4, is a case named by its ID
// whose lookup the interpreter's walk and the rules written out both end where
// the row says. L1's host holds a local table, and L5's mirror a carve-out's
// throw, which interpret reads no network for. The written-out rules read
// ranet3's table and not that throw, so L5 asserts the walk alone. A lookup
// bound to a device, B1 to B4, is not modeled and has no case.
func TestWhereALookupEndsOnLinuxByRow(t *testing.T) {
	// a LAN of the host's inside the overlay, a carve-out, through eth1
	lan := prefix("192.0.2.128/26")
	// a host whose local table answers its uplink's address at 0, ahead of every other rule
	local := plainHost(false)
	local.tables[schema.TableLocal] = []fibRoute{{destination: netip.PrefixFrom(uplink[false], 32), device: Loopback}}
	local.rules = append([]Rule{{Family: FamilyIPv4, Priority: 0, Table: schema.TableLocal}}, local.rules...)
	// a host whose main holds a refusing IPv4 default in place of its route through eth0
	refusing := plainHost(false)
	refusing.tables[schema.TableMain] = slices.Clone(refusing.tables[schema.TableMain])
	for i, route := range refusing.tables[schema.TableMain] {
		if route.destination == prefix("0.0.0.0/0") {
			refusing.tables[schema.TableMain][i] = fibRoute{destination: route.destination, unreachable: true}
		}
	}
	// a learned default and a prefix of this node's own outside the overlay
	owned := []mirrorEntry{learnedAt("0.0.0.0/0"), at(netstack.Local, "203.0.113.0/25")}
	for _, c := range []struct {
		row     string
		host    fib
		entries []mirrorEntry
		mode    exitView
		// thrown is a carve-out whose throw the mirror holds
		thrown netip.Prefix
		p      fibPacket
		want   string
	}{
		{row: "L1", host: local, entries: []mirrorEntry{learnedAt("198.51.100.0/25")}, p: from("203.0.113.5", "198.51.100.10"), want: Loopback},
		{row: "L2", entries: []mirrorEntry{learnedAt("192.0.2.0/25")}, p: fibPacket{source: uplink[false], destination: netip.MustParseAddr("192.0.2.1"), mark: schema.UnderlayMark}, want: "eth0"},
		{row: "L3", entries: []mirrorEntry{learnedAt("192.0.2.0/25")}, p: from("198.51.100.10", "192.0.2.1"), want: tunDevice},
		{row: "L4", entries: []mirrorEntry{learnedAt("192.0.2.0/25")}, p: from("198.51.100.10", "192.0.2.200"), want: "unreachable"},
		{row: "L5", host: hostWith(map[schema.TableID][]netip.Prefix{schema.TableMain: {lan}}, func(Family) []Rule { return nil }), entries: []mirrorEntry{learnedAt("192.0.2.0/25")}, thrown: lan, p: from("198.51.100.10", "192.0.2.130"), want: "eth1"},
		{row: "L6", entries: []mirrorEntry{learnedAt("198.51.100.0/25")}, p: from("203.0.113.5", "198.51.100.20"), want: "eth0"},
		{row: "L7", host: refusing, entries: owned, p: from("203.0.113.5", "203.0.113.200"), want: "unreachable"},
		{row: "L8", entries: []mirrorEntry{learnedAt("203.0.113.0/27")}, p: from("198.51.100.10", "203.0.113.9"), want: tunDevice},
		{row: "L9", entries: []mirrorEntry{at(netstack.Unreachable, "203.0.113.0/27")}, p: from("198.51.100.10", "203.0.113.9"), want: "unreachable"},
		{row: "L10", entries: []mirrorEntry{learnedAt("0.0.0.0/0"), at(netstack.Local, "203.0.113.192/27")}, p: from("203.0.113.193", "203.0.113.200"), want: "eth0"},
		{row: "L11", entries: owned, p: from("203.0.113.5", "203.0.113.200"), want: tunDevice},
		{row: "L12", entries: owned, p: from("198.51.100.10", "203.0.113.200"), want: "eth0"},
		{row: "E1", entries: namedDefaults, mode: namedForwarding, p: from("198.51.100.10", "203.0.113.9"), want: "eth0"},
		{row: "E2", entries: namedDefaults, mode: namedForwarding, p: from("203.0.113.66", "203.0.113.40"), want: "eth0"},
		{row: "E3", entries: namedDefaults, mode: namedForwarding, p: fibPacket{source: netip.MustParseAddr("203.0.113.130"), destination: netip.MustParseAddr("203.0.113.40"), iif: "br-1a"}, want: tunDevice},
		{row: "E4", entries: namedDefaults, mode: namedForwarding, p: fibPacket{source: netip.MustParseAddr("203.0.113.66"), destination: netip.MustParseAddr("203.0.113.40"), iif: "eth1"}, want: "eth0"},
	} {
		t.Run(c.row, func(t *testing.T) {
			host := c.host
			if host.tables == nil {
				host = plainHost(false)
			}
			h := interpret(t, namedOverlay, c.entries, nil, false, true, host, c.mode, nil)
			if c.thrown.IsValid() {
				// the throw carveThrows adds for a carve-out the pass's network read gives, which interpret reads none of
				h.kernel.tables[DefaultTable] = append(h.kernel.tables[DefaultTable], fibRoute{destination: c.thrown, metric: holdMetric, throw: true})
			}
			if got := h.kernel.walk(c.p); got != c.want {
				t.Errorf("%s went to %s, want %s\nthe mirror:\n%v\nthe rules:\n%s", c.p, got, c.want, h.desired, rulesText(h.kernel.rules))
			}
			if c.thrown.IsValid() {
				return
			}
			if got := h.expected(c.p); got != c.want {
				t.Errorf("the rules written out send %s to %s, want %s", c.p, got, c.want)
			}
		})
	}
}
