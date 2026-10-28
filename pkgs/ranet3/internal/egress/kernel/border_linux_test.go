// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// borderChain encodes the chain the filter asks for over cfg, the mesh tun
// ranet3 and lo, and sids
func borderChain(t *testing.T, cfg egress.Border, sids ...string) ([]BorderRule, []nftables.Request) {
	t.Helper()
	rt := egress.BorderRuntime{Inside: []string{"ranet3", "lo"}}
	for _, sid := range sids {
		rt.SIDs = append(rt.SIDs, netip.MustParseAddr(sid))
	}
	desired := newBorderFilter(cfg, rt, &fakeBorder{}).desired()
	requests, err := borderBatch(desired, false)
	if err != nil {
		t.Fatal(err)
	}
	return desired, requests[3:]
}

// Each rule reaches the kernel as the expressions its comment describes, in
// the inet table of this tool's name and the border chain, and reads back as
// the spelling it was written under
func TestBorderRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	desired, rules := borderChain(t, overlay(t, "198.18.0.0/15", "3fff::7/128"), "3fff:a::1")
	want := [][]string{
		{"meta", "cmp", "immediate"},
		{"meta", "cmp", "immediate"},
		{"meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate"},
		// no bitwise: a prefix as long as the address masks nothing
		{"meta", "cmp", "payload", "cmp", "counter", "immediate"},
		{"meta", "cmp", "exthdr", "cmp", "counter", "immediate"},
		{"meta", "cmp", "payload", "cmp", "counter", "immediate"},
	}
	if len(rules) != len(want) {
		t.Fatalf("encoded %d rules, want %d", len(rules), len(want))
	}
	for i, request := range rules {
		if got := expressionNames(t, request.Body); !slices.Equal(got, want[i]) {
			t.Errorf("%s encoded %q, want %q", desired[i], got, want[i])
		}
		if request.Body[0] != unix.NFPROTO_INET {
			t.Errorf("%s went to family %d, want inet", desired[i], request.Body[0])
		}
		table, chain, spec, _, _, _ := nftables.DecodeRule(nftables.Message{Data: request.Body})
		if table != TableName || chain != BorderChain || spec != desired[i].String() {
			t.Errorf("%s was written as %q into %s/%s", desired[i], spec, table, chain)
		}
	}
}

// The chain is a filter chain at prerouting at priority raw, after
// defragmentation and before conntrack, in the inet table of this tool's
// name, and the batch empties it by naming no handle before writing it. A
// batch that remakes the table deletes it first, in the same transaction.
func TestBorderChainFiltersAtPreroutingBeforeConntrack(t *testing.T) {
	requests, err := borderBatch(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	remade, err := borderBatch(nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(remade) != len(requests)+1 || remade[0].Kind != nftables.Command(unix.NFT_MSG_DELTABLE) {
		t.Fatalf("a remaking batch of %d requests starts with kind %d, want the table's deletion ahead of the %d others", len(remade), remade[0].Kind, len(requests))
	}
	for kind, value := range (nftables.Message{Data: remade[0].Body}).Attributes() {
		if kind == unix.NFTA_TABLE_NAME && unix.ByteSliceToString(value) != TableName {
			t.Errorf("a remaking batch deletes table %s", value)
		}
	}
	if requests[0].Kind != nftables.Command(unix.NFT_MSG_NEWTABLE) {
		t.Errorf("the batch's first request is kind %d, want the table", requests[0].Kind)
	}
	for _, request := range remade {
		if request.Body[0] != unix.NFPROTO_INET {
			t.Errorf("a request of the batch went to family %d, want inet", request.Body[0])
		}
	}
	table, chain, kind, hook, priority := nftables.DecodeChain(nftables.Message{Data: requests[1].Body})
	if table != TableName || chain != BorderChain || kind != "filter" {
		t.Errorf("created a %q chain %s/%s, want a filter chain %s/%s", kind, table, chain, TableName, BorderChain)
	}
	if hook != unix.NF_INET_PRE_ROUTING || priority != -300 {
		t.Errorf("hooked at %d priority %d, want prerouting (%d) at raw (-300)", hook, priority, unix.NF_INET_PRE_ROUTING)
	}
	if requests[2].Kind != nftables.Command(unix.NFT_MSG_DELRULE) {
		t.Errorf("the batch's third request is kind %d, want the flush", requests[2].Kind)
	}
	for kind, value := range (nftables.Message{Data: requests[2].Body}).Attributes() {
		switch kind {
		case unix.NFTA_RULE_HANDLE:
			t.Error("the flush names a handle, which would delete one rule rather than empty the chain")
		case unix.NFTA_RULE_CHAIN:
			if unix.ByteSliceToString(value) != BorderChain {
				t.Errorf("the flush empties chain %s", value)
			}
		}
	}
}

// The border chain reads back as written only as the filter chain at
// prerouting, priority raw, accepting by default, that the batch creates, and
// the translator's only as the chains it creates. Another type, hook,
// priority or policy, or a regular chain of its name, is a fault, all but the
// policy one nf_tables will not change in place, and a chain of another name
// or in another table is none of the filter's business.
func TestBorderChainReadsBackOnlyAsWritten(t *testing.T) {
	requests, err := borderBatch(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if fault, remake := prerouting.Fault(nftables.Message{Data: requests[1].Body}); fault != "" || remake {
		t.Errorf("the chain the batch writes reads back with the fault %q, remade %v", fault, remake)
	}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, written := range translatorChains {
			if fault, remake := written.Fault(nftables.Message{Data: written.Create(nftFamily(family)).Body}); fault != "" || remake {
				t.Errorf("the translator's %s chain %s reads back with the fault %q, remade %v", egress.FamilyName(family), written.Name, fault, remake)
			}
		}
	}
	chain := func(table, name, kind string, hook uint32, priority int32, policy uint32) nftables.Message {
		hooked := nftables.PutAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, hook)
		hooked = nftables.PutAttrBE32(hooked, unix.NFTA_HOOK_PRIORITY, uint32(priority))
		body := nftables.PutNfgenmsg(nil, unix.NFPROTO_INET)
		body = nftables.PutAttrString(body, unix.NFTA_CHAIN_TABLE, table)
		body = nftables.PutAttrString(body, unix.NFTA_CHAIN_NAME, name)
		body = nftables.PutAttr(body, unix.NFTA_CHAIN_HOOK|unix.NLA_F_NESTED, hooked)
		body = nftables.PutAttrBE32(body, unix.NFTA_CHAIN_POLICY, policy)
		body = nftables.PutAttrString(body, unix.NFTA_CHAIN_TYPE, kind)
		return nftables.Message{Data: body}
	}
	regular := nftables.PutNfgenmsg(nil, unix.NFPROTO_INET)
	regular = nftables.PutAttrString(regular, unix.NFTA_CHAIN_TABLE, TableName)
	regular = nftables.PutAttrString(regular, unix.NFTA_CHAIN_NAME, BorderChain)
	for name, c := range map[string]struct {
		message       nftables.Message
		fault, remake bool
	}{
		"as written":          {chain(TableName, BorderChain, "filter", unix.NF_INET_PRE_ROUTING, rawPriority, nftables.Accept), false, false},
		"of another type":     {chain(TableName, BorderChain, "route", unix.NF_INET_PRE_ROUTING, rawPriority, nftables.Accept), true, true},
		"at another hook":     {chain(TableName, BorderChain, "filter", unix.NF_INET_FORWARD, rawPriority, nftables.Accept), true, true},
		"at another priority": {chain(TableName, BorderChain, "filter", unix.NF_INET_PRE_ROUTING, 0, nftables.Accept), true, true},
		"dropping by default": {chain(TableName, BorderChain, "filter", unix.NF_INET_PRE_ROUTING, rawPriority, nftables.Drop), true, false},
		"a regular chain":     {nftables.Message{Data: regular}, true, true},
		"of another name":     {chain(TableName, "extra", "route", unix.NF_INET_FORWARD, 0, nftables.Drop), false, false},
		"in another table":    {chain("other", BorderChain, "route", unix.NF_INET_FORWARD, 0, nftables.Drop), false, false},
	} {
		fault, remake := prerouting.Fault(c.message)
		if (fault != "") != c.fault || remake != c.remake {
			t.Errorf("a chain %s reads back faulted %v and remade %v, want %v and %v", name, fault != "", remake, c.fault, c.remake)
		}
	}
}

// An inet chain sees both families, so a source rule tests the family before
// it reads an address: an IPv6 packet whose source bytes 4 to 7 spell an
// address in an IPv4 overlay prefix passes, while the IPv4 packet carrying
// that address is dropped
func TestIPv6PacketIsNotReadAsAnIPv4Source(t *testing.T) {
	desired, rules := borderChain(t, overlay(t, "198.18.0.0/15"))
	// 198.18.0.1 is c6 12 00 01
	ipv6 := drawnPacket{iif: "eth0", source: netip.MustParseAddr("2001:db8:c612:1::1"), destination: netip.MustParseAddr("2001:db8::2")}
	if run := runChain(t, rules, ipv6.wire()); !run.accept {
		t.Errorf("an IPv6 packet from %s was dropped by %s", ipv6.source, desired[run.rule])
	}
	ipv4 := drawnPacket{iif: "eth0", source: netip.MustParseAddr("198.18.0.1"), destination: netip.MustParseAddr("192.0.2.1")}
	if run := runChain(t, rules, ipv4.wire()); run.accept {
		t.Errorf("an IPv4 packet from %s passed", ipv4.source)
	}
}

// A device is accepted under its whole name: xfrm devices named ranet%05x sit
// beside a mesh tun named ranet3 on a router, and ranet3 compared as a prefix
// would let ranet3a1b2 carry a forged mesh source in
func TestBorderComparesTheWholeInterfaceName(t *testing.T) {
	_, rules := borderChain(t, overlay(t, "198.18.0.0/15"))
	for _, one := range []struct {
		iif    string
		accept bool
	}{{"ranet3", true}, {"ranet3a1b2", false}, {"ranet", false}, {"lo", true}} {
		packet := drawnPacket{iif: one.iif, source: netip.MustParseAddr("198.18.0.1"), destination: netip.MustParseAddr("192.0.2.1")}
		if run := runChain(t, rules, packet.wire()); run.accept != one.accept {
			t.Errorf("a forged mesh source arriving on %s: accepted %v, want %v", one.iif, run.accept, one.accept)
		}
	}
}

// The routing header rule drops a routing header of any type wherever it sits
// among a packet's first 12 extension headers, a type 4 header behind one of
// type 0 or 2 among them, while a packet with none passes, as does one whose
// routing header sits behind 12 others, where the kernel's search gives up
// from Linux 7.1
func TestBorderDropsARoutingHeaderOfAnyTypeWhereverItSits(t *testing.T) {
	desired, rules := borderChain(t, overlay(t, "198.18.0.0/15"))
	behind := func(options int, last string) []string { return append(slices.Repeat([]string{"dest"}, options), last) }
	for _, one := range []struct {
		headers []string
		drop    bool
	}{
		{[]string{"routing4"}, true},
		{[]string{"hop", "routing4"}, true},
		{[]string{"fragment", "routing4"}, true},
		{[]string{"routing4", "fragment"}, true},
		{[]string{"routing0"}, true},
		{[]string{"hop", "routing2"}, true},
		{[]string{"routing0", "routing4"}, true},
		{[]string{"routing2", "routing4"}, true},
		{behind(kernelHeaderSearch-1, "routing4"), true},
		{behind(kernelHeaderSearch, "routing4"), false},
		{nil, false},
		{[]string{"hop", "dest", "fragment"}, false},
	} {
		packet := drawnPacket{iif: "eth0", source: netip.MustParseAddr("2001:db8::1"), destination: netip.MustParseAddr("2001:db8::2"), headers: one.headers}
		run := runChain(t, rules, packet.wire())
		if run.accept == one.drop {
			t.Errorf("headers %q: accepted %v, want dropped %v", one.headers, run.accept, one.drop)
		} else if one.drop && desired[run.rule].Class != BorderRoutingHeader {
			t.Errorf("headers %q dropped by %s", one.headers, desired[run.rule])
		}
	}
}

// A packet to one of this node's own SIDs from outside the mesh is dropped,
// and one to an address a bit away from it passes
func TestBorderDropsThisNodesSIDsAsDestinations(t *testing.T) {
	desired, rules := borderChain(t, overlay(t, "198.18.0.0/15"), "3fff:a::1")
	for destination, drop := range map[string]bool{"3fff:a::1": true, "3fff:a::3": false} {
		packet := drawnPacket{iif: "eth0", source: netip.MustParseAddr("2001:db8::1"), destination: netip.MustParseAddr(destination)}
		run := runChain(t, rules, packet.wire())
		if run.accept == drop {
			t.Errorf("a packet to %s: accepted %v, want dropped %v", destination, run.accept, drop)
		} else if drop && desired[run.rule].Class != BorderDestination {
			t.Errorf("a packet to %s dropped by %s", destination, desired[run.rule])
		}
	}
}

// Another writer deleting or adding the filter's inet table, a chain, a rule
// or a set in it wakes the filter, a table update setting it dormant among
// them, and its own writes do not
func TestAnotherWritersChangeToTheBorderWakesIt(t *testing.T) {
	const own, other = 7, 9
	for name, c := range map[string]struct {
		command int
		naming  uint16
		pid     uint32
		wakes   bool
	}{
		"its table deleted":        {unix.NFT_MSG_DELTABLE, unix.NFTA_TABLE_NAME, other, true},
		"its chain deleted":        {unix.NFT_MSG_DELCHAIN, unix.NFTA_CHAIN_TABLE, other, true},
		"a rule of it deleted":     {unix.NFT_MSG_DELRULE, unix.NFTA_RULE_TABLE, other, true},
		"its table set dormant":    {unix.NFT_MSG_NEWTABLE, unix.NFTA_TABLE_NAME, other, true},
		"a chain added or changed": {unix.NFT_MSG_NEWCHAIN, unix.NFTA_CHAIN_TABLE, other, true},
		"a rule added":             {unix.NFT_MSG_NEWRULE, unix.NFTA_RULE_TABLE, other, true},
		"its own flush":            {unix.NFT_MSG_DELRULE, unix.NFTA_RULE_TABLE, own, false},
		"its own withdrawal":       {unix.NFT_MSG_DELTABLE, unix.NFTA_TABLE_NAME, own, false},
		"its own table":            {unix.NFT_MSG_NEWTABLE, unix.NFTA_TABLE_NAME, own, false},
		"its own chain":            {unix.NFT_MSG_NEWCHAIN, unix.NFTA_CHAIN_TABLE, own, false},
		"its own rule":             {unix.NFT_MSG_NEWRULE, unix.NFTA_RULE_TABLE, own, false},
		"another writer's set":     {unix.NFT_MSG_NEWSET, unix.NFTA_SET_TABLE, other, true},
	} {
		message := nftables.Message{Kind: nftables.Command(c.command), Pid: c.pid, Data: nftables.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), c.naming, TableName)}
		if got := borderTables.ChangedByAnother(message, own); got != c.wakes {
			t.Errorf("%s: woke %v, want %v", name, got, c.wakes)
		}
	}
}

// The translator's ip and ip6 tables share the filter's name, and their
// churn, the translator's own startup and withdrawal among it, never wakes
// the filter, nor does a table of the name in any other family
func TestBorderIgnoresTheTranslatorsTables(t *testing.T) {
	const own, other = 7, 9
	for _, family := range []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6, unix.NFPROTO_BRIDGE, unix.NFPROTO_NETDEV, unix.NFPROTO_ARP} {
		for _, command := range []int{unix.NFT_MSG_DELTABLE, unix.NFT_MSG_NEWTABLE} {
			message := nftables.Message{Kind: nftables.Command(command), Pid: other, Data: nftables.PutAttrString(nftables.PutNfgenmsg(nil, family), unix.NFTA_TABLE_NAME, TableName)}
			if borderTables.ChangedByAnother(message, own) {
				t.Errorf("a table %s written by command %d in family %d woke the border filter", TableName, command, family)
			}
		}
	}
}

// Another writer's change to the translator's ip or ip6 table wakes the
// translator, and its change to the border filter's inet table of the same
// name does not
func TestTranslatorIgnoresTheBordersTable(t *testing.T) {
	const own, other = 7, 9
	for family, wakes := range map[uint8]bool{unix.NFPROTO_IPV4: true, unix.NFPROTO_IPV6: true, unix.NFPROTO_INET: false} {
		for _, command := range []int{unix.NFT_MSG_DELTABLE, unix.NFT_MSG_NEWTABLE} {
			message := nftables.Message{Kind: nftables.Command(command), Pid: other, Data: nftables.PutAttrString(nftables.PutNfgenmsg(nil, family), unix.NFTA_TABLE_NAME, TableName)}
			if got := translatorTables.ChangedByAnother(message, own); got != wakes {
				t.Errorf("a table %s written by command %d in family %d: woke the translator %v, want %v", TableName, command, family, got, wakes)
			}
		}
	}
}

// A device name the kernel cannot hold is refused rather than truncated, so
// the inside rule never installs comparing against no device
func TestBorderRefusesAnInsideNameNoDeviceCarries(t *testing.T) {
	_, err := newBorderRule(BorderRule{Class: BorderInside, Device: strings.Repeat("r", unix.IFNAMSIZ)})
	if err == nil || !strings.Contains(err.Error(), "device name is at most") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
}
