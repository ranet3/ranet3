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

// encodedTable encodes the table the filter asks for over cfg and sets, the
// mesh tun ranet3 and lo: its rules in order and the batch writing it
func encodedTable(t testing.TB, cfg *egress.Border, sets egress.BorderSets) ([]BorderRule, []nftables.Request) {
	t.Helper()
	rt := egress.BorderRuntime{Tun: "ranet3", Inside: []string{"ranet3", "lo"}, Sets: func(*egress.Border) egress.BorderSets { return sets }}
	rules, written, _ := newBorderFilter(cfg, rt, &fakeBorder{}).desired()
	requests, err := borderBatch(rules, written, false)
	if err != nil {
		t.Fatal(err)
	}
	return rules, requests
}

// chainRules is the rules desired holds of one chain and the requests writing
// them, in order
func chainRules(desired []BorderRule, requests []nftables.Request, chain string) ([]BorderRule, []nftables.Request) {
	var written []nftables.Request
	for _, request := range requests {
		if request.Kind == nftables.Command(unix.NFT_MSG_NEWRULE) {
			written = append(written, request)
		}
	}
	var rules []BorderRule
	var out []nftables.Request
	for i, rule := range desired {
		if rule.Chain() == chain {
			rules, out = append(rules, rule), append(out, written[i])
		}
	}
	return rules, out
}

// borderChain encodes the antispoof chain the filter asks for over cfg, the
// mesh tun ranet3 and lo, and runs a packet through it
func borderChain(t *testing.T, cfg *egress.Border) ([]BorderRule, func(drawnPacket) chainRun) {
	t.Helper()
	desired, requests := encodedTable(t, cfg, egress.BorderSets{})
	rules, written := chainRules(desired, requests, BorderChain)
	sets := encodedSets(t, requests)
	return rules, func(p drawnPacket) chainRun {
		wire := p.wire()
		wire.sets = sets
		return runChain(t, written, wire)
	}
}

// chainRequest is the request of requests creating the chain name
func chainRequest(t *testing.T, requests []nftables.Request, name string) nftables.Request {
	t.Helper()
	for _, request := range requests {
		if _, chain, _, _, _ := nftables.DecodeChain(nftables.Message{Data: request.Body}); request.Kind == nftables.Command(unix.NFT_MSG_NEWCHAIN) && chain == name {
			return request
		}
	}
	t.Fatalf("the batch creates no chain %s", name)
	return nftables.Request{}
}

// Each rule reaches the kernel as the expressions its comment describes, in
// the inet table of this tool's name and the chain it sits in, and reads back
// as the spelling it was written under
func TestBorderRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	carveOut := egress.CarveOut{Link: "eth0", Prefix: netip.MustParsePrefix("198.18.0.0/24")}
	desired, requests := encodedTable(t, overlay(t, "198.18.0.0/15", "3fff::7/128"), egress.BorderSets{CarveOuts: []egress.CarveOut{carveOut}})
	_, rules := chainRules(desired, requests, BorderChain)
	_, entries := chainRules(desired, requests, EntryChain)
	rules = append(rules, entries...)
	lookup := []string{"meta", "cmp", "payload", "lookup"}
	want := [][]string{
		{"meta", "cmp", "immediate"},
		{"meta", "cmp", "immediate"},
		// the carved drop of IPv4 alone, the family with a carve-out
		append(slices.Clone(lookup), "counter", "immediate"),
		{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "immediate"},
		{"meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate"},
		// no bitwise: a prefix as long as the address masks nothing
		{"meta", "cmp", "payload", "cmp", "counter", "immediate"},
		{"meta", "cmp", "immediate"},
		{"ct", "cmp", "immediate"},
		{"meta", "cmp", "payload", "bitwise", "cmp", "immediate"},
		{"meta", "cmp", "payload", "bitwise", "cmp", "immediate"},
		append(slices.Clone(lookup), "immediate"),
		append(slices.Clone(lookup), "immediate"),
		append(slices.Clone(lookup), "immediate"),
		append(slices.Clone(lookup), "immediate"),
		{"meta", "cmp", "counter", "immediate"},
		{"meta", "cmp", "counter", "immediate"},
	}
	if len(rules) != len(want) || len(desired) != len(want) {
		t.Fatalf("encoded %d rules of %d, want %d", len(rules), len(desired), len(want))
	}
	for i, request := range rules {
		if got := expressionNames(t, request.Body); !slices.Equal(got, want[i]) {
			t.Errorf("%s encoded %q, want %q", desired[i], got, want[i])
		}
		if request.Body[0] != unix.NFPROTO_INET {
			t.Errorf("%s went to family %d, want inet", desired[i], request.Body[0])
		}
		table, chain, spec, _, _, _ := nftables.DecodeRule(nftables.Message{Data: request.Body})
		if table != TableName || chain != desired[i].Chain() || spec != desired[i].String() {
			t.Errorf("%s was written as %q into %s/%s", desired[i], spec, table, chain)
		}
	}
}

// The antispoof chain is a filter chain at prerouting at priority raw, after
// defragmentation and before conntrack, and the entry chain one at
// postrouting at srcnat + 10, after every source translation, both in the
// inet table of this tool's name with its six interval sets, and the batch
// empties each chain by naming no handle before writing it. A batch that
// remakes the table deletes it first, in the same transaction.
func TestBorderChainFiltersAtPreroutingBeforeConntrack(t *testing.T) {
	rules, sets, _ := newBorderFilter(overlay(t), borderRuntime(nil), &fakeBorder{}).desired()
	requests, err := borderBatch(rules, sets, false)
	if err != nil {
		t.Fatal(err)
	}
	remade, err := borderBatch(rules, sets, true)
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
	var made []string
	for _, request := range requests {
		if request.Kind == nftables.Command(unix.NFT_MSG_NEWSET) {
			set := nftables.DecodeSet(nftables.Message{Data: request.Body})
			if set.Flags&unix.NFT_SET_INTERVAL == 0 || set.Table != TableName {
				t.Errorf("set %s is made in %s with flags %#x", set.Name, set.Table, set.Flags)
			}
			made = append(made, set.Name)
		}
	}
	if want := []string{"carved4", "carved6", "owned4", "owned6", "none4", "none6"}; !slices.Equal(made, want) {
		t.Errorf("the batch makes the sets %q, want %q", made, want)
	}
	for _, want := range []struct {
		name     string
		hook     uint32
		priority int32
	}{{BorderChain, unix.NF_INET_PRE_ROUTING, -300}, {EntryChain, unix.NF_INET_POST_ROUTING, 110}} {
		request := chainRequest(t, requests, want.name)
		table, chain, kind, hook, priority := nftables.DecodeChain(nftables.Message{Data: request.Body})
		if table != TableName || kind != "filter" || hook != want.hook || priority != want.priority {
			t.Errorf("created a %q chain %s/%s at hook %d priority %d, want a filter chain %s/%s at %d priority %d", kind, table, chain, hook, priority, TableName, want.name, want.hook, want.priority)
		}
		next := requests[slices.IndexFunc(requests, func(r nftables.Request) bool { return slices.Equal(r.Body, request.Body) })+1]
		if next.Kind != nftables.Command(unix.NFT_MSG_DELRULE) {
			t.Errorf("chain %s is followed by a request of kind %d, want the flush", want.name, next.Kind)
		}
		for kind, value := range (nftables.Message{Data: next.Body}).Attributes() {
			switch kind {
			case unix.NFTA_RULE_HANDLE:
				t.Error("the flush names a handle, which would delete one rule rather than empty the chain")
			case unix.NFTA_RULE_CHAIN:
				if unix.ByteSliceToString(value) != want.name {
					t.Errorf("the flush after chain %s empties chain %s", want.name, value)
				}
			}
		}
	}
}

// The antispoof chain reads back as written only as the filter chain at
// prerouting, priority raw, accepting by default, that the batch creates, and
// the translator's only as the chains it creates. Another type, hook,
// priority or policy, or a regular chain of its name, is a fault, all but the
// policy one nf_tables will not change in place, and a chain of another name
// or in another table is none of the filter's business. A class of none's
// chain held as a base chain is a fault nf_tables will not change in place.
func TestBorderChainReadsBackOnlyAsWritten(t *testing.T) {
	rules, sets, _ := newBorderFilter(overlay(t), borderRuntime(nil), &fakeBorder{}).desired()
	requests, err := borderBatch(rules, sets, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range []nftables.Chain{prerouting, entry} {
		if fault, remake := chain.Fault(nftables.Message{Data: chainRequest(t, requests, chain.Name).Body}); fault != "" || remake {
			t.Errorf("the chain %s the batch writes reads back with the fault %q, remade %v", chain.Name, fault, remake)
		}
	}
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, written := range translatorChains(family, underNone(family)) {
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
	none := regularChain("none_192_0_2_0_24")
	if fault, remake := none.Fault(chain(TableName, none.Name, "filter", unix.NF_INET_FORWARD, 0, nftables.Accept)); fault == "" || !remake {
		t.Errorf("a class of none's chain held as a base chain reads back with the fault %q, remade %v, want a fault that remakes the table", fault, remake)
	}
}

// An inet chain sees both families, so a source rule tests the family before
// it reads an address: an IPv6 packet whose source bytes 4 to 7 spell an
// address in an IPv4 overlay prefix passes, while the IPv4 packet carrying
// that address is dropped
func TestIPv6PacketIsNotReadAsAnIPv4Source(t *testing.T) {
	desired, run := borderChain(t, overlay(t, "198.18.0.0/15"))
	// 198.18.0.1 is c6 12 00 01
	ipv6 := drawnPacket{iif: "eth0", source: netip.MustParseAddr("2001:db8:c612:1::1"), destination: netip.MustParseAddr("2001:db8::2")}
	if run := run(ipv6); !run.accept {
		t.Errorf("an IPv6 packet from %s was dropped by %s", ipv6.source, desired[run.rule])
	}
	ipv4 := drawnPacket{iif: "eth0", source: netip.MustParseAddr("198.18.0.1"), destination: netip.MustParseAddr("192.0.2.1")}
	if run := run(ipv4); run.accept {
		t.Errorf("an IPv4 packet from %s passed", ipv4.source)
	}
}

// A device is accepted under its whole name: xfrm devices named ranet%05x sit
// beside a mesh tun named ranet3 on a router, and ranet3 compared as a prefix
// would let ranet3a1b2 carry a forged mesh source in
func TestBorderComparesTheWholeInterfaceName(t *testing.T) {
	_, run := borderChain(t, overlay(t, "198.18.0.0/15"))
	for _, one := range []struct {
		iif    string
		accept bool
	}{{"ranet3", true}, {"ranet3a1b2", false}, {"ranet", false}, {"lo", true}} {
		packet := drawnPacket{iif: one.iif, source: netip.MustParseAddr("198.18.0.1"), destination: netip.MustParseAddr("192.0.2.1")}
		if run := run(packet); run.accept != one.accept {
			t.Errorf("a forged mesh source arriving on %s: accepted %v, want %v", one.iif, run.accept, one.accept)
		}
	}
}

// An exemption passes its prefix's sources from the interfaces it names: the
// shared one from every interface outside the mesh, an interface's from that
// interface alone, and one ending in * from every interface whose name starts
// with what comes before it. A source the carved set holds is dropped from
// each all the same, and the overlay's other sources stay dropped.
func TestBorderExemptionPassesFromTheInterfacesItNames(t *testing.T) {
	cfg := overlay(t, "198.18.0.0/15", "3fff::/20")
	cfg.Antispoof = egress.Antispoof{
		Exempt: prefixes(t, "198.18.1.0/24"),
		Interface: map[string]egress.AntispoofInterface{
			"eth1": {Exempt: prefixes(t, "198.18.2.0/24")},
			"wl*":  {Exempt: prefixes(t, "3fff:0:2::/48")},
		},
	}
	desired, requests := encodedTable(t, cfg, egress.BorderSets{Carved: ranges("198.18.1.9/32", "3fff:0:2::9/128")})
	_, written := chainRules(desired, requests, BorderChain)
	sets := encodedSets(t, requests)
	for _, one := range []struct {
		iif, source string
		accept      bool
	}{
		{"eth0", "198.18.1.7", true}, {"eth1", "198.18.1.7", true}, {"wlan0", "198.18.1.7", true},
		{"eth1", "198.18.2.7", true}, {"eth0", "198.18.2.7", false}, {"eth10", "198.18.2.7", false}, {"eth", "198.18.2.7", false},
		{"wlan0", "3fff:0:2::7", true}, {"wl", "3fff:0:2::7", true}, {"w", "3fff:0:2::7", false}, {"xwl0", "3fff:0:2::7", false}, {"eth1", "3fff:0:2::7", false},
		// the mesh's own prefixes inside an exemption
		{"eth0", "198.18.1.9", false}, {"wlan0", "3fff:0:2::9", false},
		// the overlay outside every exemption
		{"eth1", "198.18.3.7", false}, {"wlan0", "3fff:0:3::7", false},
	} {
		source := netip.MustParseAddr(one.source)
		destination := netip.MustParseAddr("192.0.2.1")
		if source.Is6() {
			destination = netip.MustParseAddr("2001:db8::2")
		}
		wire := drawnPacket{iif: one.iif, source: source, destination: destination}.wire()
		wire.sets = sets
		if run := runChain(t, written, wire); run.accept != one.accept {
			t.Errorf("%s arriving on %s: accepted %v, want %v", one.source, one.iif, run.accept, one.accept)
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
				t.Errorf("a table %s written by command %d in family %d woke the antispoof filter", TableName, command, family)
			}
		}
	}
}

// Another writer's change to the translator's ip or ip6 table wakes the
// translator, and its change to the antispoof filter's inet table of the same
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
