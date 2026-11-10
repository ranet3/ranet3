// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// recordedRoutes is a selection that answers each address a test names with
// its route and interface, and no route for any other
type recordedRoutes map[netip.Addr]struct {
	prefix netip.Prefix
	device string
}

func (r recordedRoutes) Route(addr netip.Addr) (netip.Prefix, string, bool) {
	route, ok := r[addr]
	return route.prefix, route.device, ok
}

// each live session's path is one underlay row in address order, a second
// session on a path adds none, an endpoint no route holds reads as no route,
// a link-local endpoint is asked with its zone and reads as no route without
// one, and a session's pin names its interface whatever the selection answers
// for its address
func TestUnderlayRowsAreWhereEachSessionsDatagramsLeave(t *testing.T) {
	near, far, v6 := netip.MustParseAddr("198.51.100.77"), netip.MustParseAddr("203.0.113.70"), netip.MustParseAddr("2001:db8:400::7")
	zoned := netip.MustParseAddr("fe80::9%en2")
	routes := recordedRoutes{
		near:               {netip.MustParsePrefix("198.51.100.0/24"), "en0"},
		v6:                 {netip.MustParsePrefix("::/0"), "en1"},
		zoned:              {netip.Prefix{}, "en2"},
		zoned.WithZone(""): {netip.MustParsePrefix("fe80::/64"), "en2"},
	}
	got := underlayLookups(routes, []underlayPath{
		{address: v6}, {address: far}, {address: near}, {address: v6}, {address: zoned}, {address: near, pin: "en3"}, {address: zoned.WithZone("")},
	})
	want := []control.RuleLookup{
		{Lookup: "underlay", Family: "ipv4", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Address: near, Answer: "dev en0"},
		{Lookup: "underlay", Family: "ipv4", Address: near, Answer: "dev en3"},
		{Lookup: "underlay", Family: "ipv4", Address: far, Answer: "no route"},
		{Lookup: "underlay", Family: "ipv6", Prefix: netip.MustParsePrefix("::/0"), Address: v6, Answer: "dev en1"},
		{Lookup: "underlay", Family: "ipv6", Address: zoned.WithZone(""), Answer: "no route"},
		{Lookup: "underlay", Family: "ipv6", Address: zoned, Answer: "dev en2"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("the underlay rows are %+v, want %+v", got, want)
	}
}

// a session's path is the destination its mux sends to, with the interface of the pin its datagrams carry where they carry one,
// and a link-local destination is zoned by the interface its datagrams leave by
func TestUnderlayPathIsWhatTheMuxSends(t *testing.T) {
	name := func(index int) string { return "en" + strconv.Itoa(index) }
	near, pin := netip.MustParseAddr("198.51.100.77"), netip.MustParseAddr("192.0.2.1")
	linkLocal, linkPin := netip.MustParseAddr("fe80::9"), netip.MustParseAddr("fe80::1")
	for _, test := range []struct {
		send transport.Send
		want underlayPath
	}{
		{transport.Send{Destination: near, Interface: 1}, underlayPath{address: near}},
		{transport.Send{Destination: near, Interface: 1, Pair: true, Source: pin}, underlayPath{address: near}},
		{transport.Send{Destination: near, Source: pin, PinInterface: 3}, underlayPath{address: near, pin: "en3"}},
		{transport.Send{Destination: near, Source: pin}, underlayPath{address: near}},
		{transport.Send{Destination: linkLocal, Interface: 2}, underlayPath{address: linkLocal.WithZone("en2")}},
		{transport.Send{Destination: linkLocal, Source: linkPin, Interface: 4, PinInterface: 4}, underlayPath{address: linkLocal.WithZone("en4"), pin: "en4"}},
		{transport.Send{Destination: linkLocal}, underlayPath{address: linkLocal}},
	} {
		if got := underlayPathOf(test.send, name); got != test.want {
			t.Errorf("the path of %+v is %+v, want %+v", test.send, got, test.want)
		}
	}
}

// a node the constructor built reads the host's policy rules through the kernel's own dump, and answers as it does when asked alone
func TestDebugRulesDumpsTheHostsRules(t *testing.T) {
	c := testClient(t)
	held, err := kernel.DumpRules()
	want := ""
	switch {
	case errors.Is(err, kernel.ErrUnsupported):
		want = "this platform has no policy rules"
	case err != nil:
		want = err.Error()
	}
	if info := c.DebugRules(); info.PolicyErr != want || len(info.Policy) != len(held) {
		t.Errorf("debug rules read %d rules and %q, want %d and %q", len(info.Policy), info.PolicyErr, len(held), want)
	}
}

// a node the constructor built reads the kill switch through the kernel's own read, and answers as it does when asked alone
func TestDebugRulesReadsTheHostsKillSwitch(t *testing.T) {
	c := testClient(t)
	debug, err := kernel.ReadFallback()
	table := c.fallbackTable(control.KernelFallback{State: "holding"})
	if table.Where != debug.Where || table.Held != debug.Held || err != nil && table.Err != err.Error() || err == nil && table.Err != "" {
		t.Errorf("the switch's table read %q held %t erring %q, want %q held %t erring %v", table.Where, table.Held, table.Err, debug.Where, debug.Held, err)
	}
}
