// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/schema"
)

// expressionNames is the rule's expression list in order, the sequence a
// packet is evaluated against. The encoder is checked against it rather than
// against a byte string, so a test says what the rule does rather than
// restating the encoding.
func expressionNames(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for kind, value := range (netlink.Message{Data: body}).Attributes(nftables.SizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nftables.Nested(value) {
			for _, field := range nftables.Nested(element.Value) {
				if field.Kind == unix.NFTA_EXPR_NAME {
					out = append(out, unix.ByteSliceToString(field.Value))
				}
			}
		}
	}
	return out
}

// A rule reaches the kernel as the expressions its comment describes, in the
// order a packet meets them: in the translation's chain its family's test,
// which every case's list leaves out, then both interfaces, then the
// narrowing, then the counter, the exit's label for a flow translated out of
// the mesh or from a mesh address, and the translation, or for a timeout rule
// its protocol and its object, for a stopped translator's drop of a labelled
// flow the departure, the label and the counted drop, and for the limit's rule
// the connection's state and status first and the count, the counter and the
// answer last, in its family's chain, as are the ICMP drops and the refusals,
// which take their protocol first, and a refusal then its flow's direction. A
// rule of the forward hook's tests no family first, since forward's first line
// sends IPv6's packets on to IPv6's chain, which leaves IPv4's alone past it,
// but a pass, and a stopped translator's drop of a labelled flow ahead of it,
// tests its family just before the source it looks up in its set, which nft
// lists as an address only after that test.
func TestRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	for _, one := range []struct {
		name string
		rule Rule
		want []string
	}{
		{
			"out of the mesh under the host's own address",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "immediate", "ct", "masq"},
		},
		{
			"out of the mesh under a configured address",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Source: netip.MustParseAddr("2001:db8::1")},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "immediate", "ct", "immediate", "nat"},
		},
		{
			"a stopped translator's drop of a labelled flow leaving by another link",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Stopped: Labelled},
			[]string{"meta", "cmp", "ct", "bitwise", "cmp", "counter", "immediate"},
		},
		{
			"that drop ahead of the pass of the untranslated sources",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Stopped: Labelled, Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("3fff::/20")})},
			// What the pass takes, the direction and the source looked up in
			// the family's set after the family test, then the label and the
			// counted drop.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "lookup", "ct", "bitwise", "cmp", "counter", "immediate"},
		},
		{
			"into the mesh from one prefix",
			Rule{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.0/24"), Source: netip.MustParseAddr("10.88.0.2")},
			// The leading pair is the local-origin test an inbound rule
			// carries. See TestInboundRuleExcludesThisNodesOwnTraffic.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate", "nat"},
		},
		{
			"into the mesh from one host",
			Rule{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.7/32"), Source: netip.MustParseAddr("10.88.0.2")},
			// No bitwise: a prefix as long as the address masks nothing.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "cmp", "counter", "immediate", "nat"},
		},
		{
			"out of the mesh from a class of none",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("192.0.2.0/24"), None: true},
			// The second payload loads the source the nat binds the connection to.
			[]string{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "payload", "nat"},
		},
		{
			"from this node's own mesh address",
			Rule{Family: egress.FamilyIPv6, Direction: Local, Interface: "ranet0",
				From: netip.MustParsePrefix("3fff::1/128"), Source: netip.MustParseAddr("2001:db8::7")},
			[]string{"meta", "cmp", "payload", "cmp", "counter", "immediate", "ct", "immediate", "nat"},
		},
		{
			"timeouts for UDP out of the mesh",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("198.51.100.0/24"), Timeouts: UDPTimeouts},
			// The protocol, then the destination port that is not DNS's, then
			// the object, with no counter and no verdict.
			[]string{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "meta", "cmp", "payload", "cmp", "objref"},
		},
		{
			"timeouts for ICMPv6 from this node's own mesh address",
			Rule{Family: egress.FamilyIPv6, Direction: Local, Interface: "ranet0", From: netip.MustParsePrefix("3fff::1/128"), Timeouts: ICMPv6Timeouts},
			[]string{"meta", "cmp", "payload", "cmp", "meta", "cmp", "objref"},
		},
		{
			"the limit on each source's flows out of the mesh",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Limit: egress.DefaultFlowsPerSource},
			// The family just before the source the count is keyed by.
			[]string{"ct", "bitwise", "cmp", "ct", "bitwise", "cmp", "meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "dynset", "counter", "reject"},
		},
		{
			"the drop of what no flow is tracked for out of the mesh",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("192.0.2.128/25"), Untracked: true},
			// The state first, then the direction and the class, then the counted drop.
			[]string{"ct", "bitwise", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate"},
		},
		{
			"the pass of the sources whose class is none ahead of the screens",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Passes: true, Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("3fff::/20")})},
			// The direction, then the source looked up in the family's set
			// after the one family test the line takes, then the verdict, with
			// no counter.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "lookup", "immediate"},
		},
		{
			"the drop of source quench out of the mesh",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", Drops: SourceQuench},
			// The protocol first, then the direction, the type and the counted drop.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "cmp", "counter", "immediate"},
		},
		{
			"the drop of information requests and replies into the mesh",
			Rule{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet0", Drops: Information},
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "cmp", "cmp", "counter", "immediate"},
		},
		{
			"the refusal of dccp out of the mesh from a class",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("192.0.2.128/25"), Protocol: dccp},
			// The protocol and the flow's original direction first.
			[]string{"meta", "cmp", "ct", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "reject"},
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			request, err := newRule(one.rule, unix.NFT_CT_LABELS)
			if err != nil {
				t.Fatal(err)
			}
			translation := one.rule.chain() == ChainName
			want := one.want
			if translation {
				want = append([]string{"meta", "cmp"}, want...)
			}
			if got := expressionNames(t, request.Body); !slices.Equal(got, want) {
				t.Errorf("encoded %q, want %q", got, want)
			}
			// the chain the rule names and the counter its kind says, which
			// Debug names the counter's unit by
			kind := one.rule.kind()
			table, chain, spec, _, _, counted := nftables.DecodeRule(netlink.Message{Data: request.Body})
			if table != nftables.Table || chain != one.rule.chain() || counted != kind.counted() || request.Body[0] != unix.NFPROTO_INET {
				t.Errorf("wrote into %d %s/%s counted %v, want inet %s/%s counted %v", request.Body[0], table, chain, counted, nftables.Table, one.rule.chain(), kind.counted())
			}
			for attr, value := range (netlink.Message{Data: request.Body}).Attributes(nftables.SizeofNfgenmsg) {
				if attr == unix.NFTA_RULE_EXPRESSIONS && bytes.HasPrefix(value, slices.Concat(nftables.NFProto(nftFamily(one.rule.Family))...)) != translation {
					t.Errorf("the rule in the chain %s tests for %s first: %v, want %v", one.rule.chain(), egress.FamilyName(one.rule.Family), !translation, translation)
				}
			}
			if spec != one.rule.String() {
				t.Errorf("the rule reads back as %q, want %q, so the diff would rewrite it forever", spec, one.rule.String())
			}
		})
	}
}

// Once the kernel has refused the label, a pass's rules, which hold no drop of
// a labelled flow, are written as they are, with nothing copied, and a stop's
// are written without that drop
func TestRulesWithoutTheLabelCostAPassNothing(t *testing.T) {
	cfg := egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}
	tr := newTranslator(cfg, Runtime{Interface: "ranet0"}, &fakeBackend{})
	n := &natTables{}
	desired, stopped := tr.desired(), tr.stopped()
	if allocs := testing.AllocsPerRun(100, func() { desired = n.written(desired) }); allocs != 0 {
		t.Errorf("writing a pass's rules without the label allocated %v times, want none", allocs)
	}
	written := n.written(stopped)
	if slices.ContainsFunc(written, func(rule Rule) bool { return rule.Stopped == Labelled }) || len(written) != len(stopped)-2 {
		t.Errorf("a stop's rules without the label are %v, want %v without its 2 drops of a labelled flow", written, stopped)
	}
}

// manyClasses is n classes of /48 prefixes inside 3fff::/32, every third of
// them none and the others auto
func manyClasses(n int) []egress.Class {
	classes := make([]egress.Class, n)
	for i := range classes {
		to := egress.Translation{Auto: true}
		if i%3 == 0 {
			to = egress.Translation{None: true}
		}
		from := netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 0, byte(i >> 8), byte(i)})
		classes[i] = egress.Class{From: schema.Prefix{Prefix: netip.PrefixFrom(from, 48)}, To: to}
	}
	return classes
}

// An interface name is compared over the whole IFNAMSIZ the kernel pads it to.
// A shorter comparison matches every device whose name starts the same way, so
// a rule for "ranet0" would also claim traffic on "ranet01".
func TestInterfaceComparisonCoversTheWholePaddedName(t *testing.T) {
	request, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"}, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for kind, value := range (netlink.Message{Data: request.Body}).Attributes(nftables.SizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		// past the family's test, the first meta and cmp
		for _, element := range nftables.Nested(value)[2:] {
			var name string
			var data []byte
			for _, field := range nftables.Nested(element.Value) {
				switch field.Kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.Value)
				case unix.NFTA_EXPR_DATA:
					data = field.Value
				}
			}
			if name != "cmp" {
				continue
			}
			for _, field := range nftables.Nested(data) {
				if field.Kind != unix.NFTA_CMP_DATA {
					continue
				}
				for _, inner := range nftables.Nested(field.Value) {
					if inner.Kind != unix.NFTA_DATA_VALUE {
						continue
					}
					found++
					if len(inner.Value) != unix.IFNAMSIZ {
						t.Errorf("compared %d bytes of the name, want %d", len(inner.Value), unix.IFNAMSIZ)
					}
					if unix.ByteSliceToString(inner.Value) != "ranet0" {
						t.Errorf("compared against %q", inner.Value)
					}
				}
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d interface comparisons, want one per direction", found)
	}
}

// The two interface tests carry opposite operators, which is the whole of the
// direction: a rule that compared both the same way would translate mesh
// transit, whose packets arrive on the mesh device and leave by it again.
func TestDirectionInvertsBothInterfaceTests(t *testing.T) {
	for _, one := range []struct {
		direction Direction
		want      []uint32
	}{
		// The leading EQ is the family's test.
		{Out, []uint32{unix.NFT_CMP_EQ, unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ}},
		// The NEQ after it is the local-origin test, which both directions of
		// the interface pair follow.
		{In, []uint32{unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ, unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ}},
	} {
		t.Run(one.direction.String(), func(t *testing.T) {
			request, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: one.direction, Interface: "ranet0"}, unix.NFT_CT_LABELS)
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for kind, value := range (netlink.Message{Data: request.Body}).Attributes(nftables.SizeofNfgenmsg) {
				if kind != unix.NFTA_RULE_EXPRESSIONS {
					continue
				}
				for _, element := range nftables.Nested(value) {
					var name string
					var data []byte
					for _, field := range nftables.Nested(element.Value) {
						switch field.Kind {
						case unix.NFTA_EXPR_NAME:
							name = unix.ByteSliceToString(field.Value)
						case unix.NFTA_EXPR_DATA:
							data = field.Value
						}
					}
					if name != "cmp" {
						continue
					}
					for _, field := range nftables.Nested(data) {
						if field.Kind == unix.NFTA_CMP_OP && len(field.Value) == 4 {
							got = append(got, binary.BigEndian.Uint32(field.Value))
						}
					}
				}
			}
			if !slices.Equal(got, one.want) {
				t.Errorf("compared with %v, want %v", got, one.want)
			}
		})
	}
}

// the longest spec of each direction a translator writes, from a /128 to an address under the longest device name and the longest IPv6 spelling, fits nft's comment limit
// and so do its longest timeout rule's, its limit rule's, at the largest limit a capability names, its rules' taking what no flow is tracked for, its pass's, its ICMP drops'
// and its refusals', so no configuration reaches the refusal of a longer one, which nft -f would not load back
func TestLongestRuleFitsTheCommentLimit(t *testing.T) {
	address := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
	device := strings.Repeat("r", unix.IFNAMSIZ-1)
	for _, direction := range []Direction{Out, In, Local} {
		rule := Rule{Family: egress.FamilyIPv6, Direction: direction, Interface: device, From: netip.PrefixFrom(address, 128), Source: address}
		timeouts := rule
		timeouts.Source, timeouts.Timeouts = netip.Addr{}, ICMPv6Timeouts
		for _, rule := range []Rule{rule, timeouts} {
			if _, err := newRule(rule, unix.NFT_CT_LABELS); err != nil {
				t.Errorf("the longest %s rule was refused: %v", direction, err)
			}
		}
	}
	if _, err := newRule(Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: device, Limit: egress.MaxFlowsPerSource}, unix.NFT_CT_LABELS); err != nil {
		t.Errorf("the longest limit rule was refused: %v", err)
	}
	for _, none := range []bool{false, true} {
		if _, err := newRule(Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), None: none, Untracked: true}, unix.NFT_CT_LABELS); err != nil {
			t.Errorf("the longest rule taking what no flow is tracked for was refused: %v", err)
		}
	}
	for _, rule := range []Rule{
		{Family: egress.FamilyIPv6, Direction: Out, Interface: device, Passes: true, Sources: prefixSet([]netip.Prefix{netip.PrefixFrom(address, 128)})},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: device, Drops: SourceQuench},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), Protocol: udpLite},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), None: true, Protocol: udpLite},
	} {
		if _, err := newRule(rule, unix.NFT_CT_LABELS); err != nil {
			t.Errorf("the longest pass, drop or refusal was refused: %v", err)
		}
	}
	if _, err := flowSet(egress.FamilyIPv6, egress.MaxFlowsPerSource).Create(unix.NFPROTO_INET); err != nil {
		t.Errorf("the set of the largest limit was refused: %v", err)
	}
}

// The translating chain is a nat base chain at the source translation hook,
// one below the priority the host's own source translation runs at, so it
// runs ahead of every chain there whatever order they were made in. Forward
// filters at the forward hook, where a forwarded packet meets it before the
// translation, as the host's own filters do. IPv6's chain, which forward's
// first line sends IPv6's packets on to, is a regular chain, which no packet
// enters but by a goto. The translator writes no chain of IPv4's own and none
// whose name NoneChain starts.
func TestChainsHookWhereTheirRulesAct(t *testing.T) {
	if slices.ContainsFunc(translatorChains, func(c nftables.Chain) bool { return c.Name == retiredChain || strings.HasPrefix(c.Name, NoneChain) }) {
		t.Errorf("the translator writes a chain of an earlier translator's among %v", translatorChains)
	}
	for _, want := range []struct {
		chain, kind string
		hook        uint32
		priority    int32
	}{
		{ChainName, "nat", unix.NF_INET_POST_ROUTING, 99},
		{LimitChain, "filter", unix.NF_INET_FORWARD, filterPriority},
		{"forward6", "", nftables.NoHook, 0},
	} {
		index := slices.IndexFunc(translatorChains, func(c nftables.Chain) bool { return c.Name == want.chain })
		if index < 0 {
			t.Errorf("the translator writes no chain %s", want.chain)
			continue
		}
		request := translatorChains[index].Create(unix.NFPROTO_INET)
		table, chain, kind, hook, priority := nftables.DecodeChain(netlink.Message{Data: request.Body})
		if table != nftables.Table || chain != want.chain || kind != want.kind || hook != want.hook || priority != want.priority {
			t.Errorf("created %s/%s, a %s chain at hook %d, priority %d, want %s/%s, a %s chain at hook %d, priority %d",
				table, chain, kind, hook, priority, nftables.Table, want.chain, want.kind, want.hook, want.priority)
		}
	}
}

// A chain the table holds whose name starts as an earlier translator's chain
// of a class of none did is a fault naming the chain, and another writer's
// chain of another name, the start alone among them, is none. A pass deletes
// such a chain, but for one a rule of another writer's chain goes to, by a
// goto or by its vmap, or an element of a named map, which nf_tables would
// refuse to delete: the fault names that chain or map too, and the chain stays.
// A rule going to it from a chain the pass empties, or a vmap going only to
// other chains, keeps it from nothing, and one of a binding chain, which no
// listing shows, keeps it unless a chain the pass empties binds that binding
// chain, and the fault names the chain that binds it. The chain an earlier
// translator held IPv4's forward lines in reads back and goes as such a chain
// does.
func TestChainsAnEarlierTranslatorWroteGo(t *testing.T) {
	stray := "none_198_51_100_0_24"
	goes := func(chain, to string) nftables.Installed {
		return nftables.Installed{Chain: chain, Expressions: nftables.Goto(to)}
	}
	looksUp := func(chain, set string) nftables.Installed {
		return nftables.Installed{Chain: chain, Expressions: nftables.Lookup(nftables.Set{Name: set}, false)}
	}
	vmap := []nftables.VerdictMap{{Name: "__map0", Anonymous: true, Chains: []string{stray}}}
	named := []nftables.VerdictMap{{Name: "vm", Chains: []string{"other", stray}}}
	written := []string{LimitChain, forward6.Name, ChainName}
	for name, c := range map[string]struct {
		held []string
		in   holders
		want string
		// deleted is whether a pass deletes the chain named stray, or none_mine
		deleted bool
	}{
		"as written":                    {append(slices.Clone(written), "other"), holders{}, "", false},
		"beside one of a class of none": {append(slices.Clone(written), stray), holders{}, "its chain " + stray + " is not one the translator writes", true},
		"beside one whose name alone starts as a class of none's": {append(slices.Clone(written), "none_mine"), holders{}, "its chain none_mine is not one the translator writes", true},
		"beside another writer's chain named as the start alone":  {append(slices.Clone(written), NoneChain), holders{}, "", false},
		"beside one another writer's chain goes to": {append(slices.Clone(written), "other", stray), holders{rules: []nftables.Installed{goes("other", stray)}},
			"its chain " + stray + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes", false},
		"beside one a chain a pass empties goes to": {append(slices.Clone(written), stray, "none_203_0_113_0_24"),
			holders{rules: []nftables.Installed{goes(LimitChain, stray), goes("none_203_0_113_0_24", stray)}}, "its chain " + stray + " is not one the translator writes", true},
		"beside one another writer's vmap goes to": {append(slices.Clone(written), "other", stray), holders{rules: []nftables.Installed{looksUp("other", "__map0")}, maps: vmap},
			"its chain " + stray + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes", false},
		"beside one the vmap of a chain a pass empties goes to": {append(slices.Clone(written), stray), holders{rules: []nftables.Installed{looksUp(LimitChain, "__map0")}, maps: vmap},
			"its chain " + stray + " is not one the translator writes", true},
		"beside one another writer's vmap goes elsewhere than": {append(slices.Clone(written), "other", stray),
			holders{rules: []nftables.Installed{looksUp("other", "__map0")}, maps: []nftables.VerdictMap{{Name: "__map0", Anonymous: true, Chains: []string{"other2"}}}},
			"its chain " + stray + " is not one the translator writes", true},
		"beside one a named map goes to": {append(slices.Clone(written), "other", stray), holders{maps: named},
			"its chain " + stray + " is not one the translator writes, and map vm holds an element going to it, so it stays until that element goes", false},
		"beside the chain of IPv4's an earlier translator wrote": {append(slices.Clone(written), retiredChain),
			holders{rules: []nftables.Installed{goes(LimitChain, retiredChain), looksUp(LimitChain, "__map0")}, maps: []nftables.VerdictMap{{Name: "__map0", Anonymous: true, Chains: []string{retiredChain, "forward6"}}}},
			"its chain " + retiredChain + " is not one the translator writes", true},
		"beside the chain of IPv4's another writer's chain goes to": {append(slices.Clone(written), "other", retiredChain), holders{rules: []nftables.Installed{goes("other", retiredChain)}},
			"its chain " + retiredChain + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes", false},
		"beside the chain of IPv4's a binding chain another writer's chain binds goes to": {append(slices.Clone(written), "other", retiredChain, stray),
			holders{rules: []nftables.Installed{goes("other", stray), goes(stray, retiredChain)}, listed: append(slices.Clone(written), "other", retiredChain)},
			"its chain " + retiredChain + " is not one the translator writes, and chain other holds a rule going to it, so it stays until that rule goes", false},
		"beside the chain of IPv4's a binding chain a chain a pass empties binds goes to": {append(slices.Clone(written), retiredChain, stray),
			holders{rules: []nftables.Installed{goes(LimitChain, stray), goes(stray, retiredChain)}, listed: append(slices.Clone(written), retiredChain)},
			"its chain " + retiredChain + " is not one the translator writes", true},
	} {
		if c.in.listed == nil {
			c.in.listed = c.held
		}
		chain := stray
		for _, other := range []string{"none_mine", NoneChain, retiredChain} {
			if slices.Contains(c.held, other) {
				chain = other
			}
		}
		if got := noneChainsFault(c.held, c.in); got != c.want {
			t.Errorf("%s reads back with the fault %q, want %q", name, got, c.want)
		}
		requests, err := translatorBatch(translatorContents([]uint8{egress.FamilyIPv4}, egress.DefaultFlowsPerSource, nil), nil, nftables.Contents{}, strays(c.held, c.in), nil, unix.NFT_CT_LABELS)
		if err != nil {
			t.Fatal(err)
		}
		deleted := slices.ContainsFunc(requests, func(r nftables.Request) bool {
			return r.Kind == nftables.Command(unix.NFT_MSG_DELCHAIN) && slices.Equal(r.Body, regularChain(chain).Delete(unix.NFPROTO_INET).Body)
		})
		if deleted != c.deleted {
			t.Errorf("%s: a pass deletes the chain %s: %v, want %v", name, chain, deleted, c.deleted)
		}
	}
}

// A pass over a table holding the timeout objects an earlier translator made
// sends the transaction it sends over a table without them with their
// deletions last, after the flush of the chains whose lines attached them, so
// the commit that writes the objects under their names deletes them
func TestTranslatorBatchDeletesTheEarlierTimeoutObjectsInItsTransaction(t *testing.T) {
	rules := everyTranslation()
	contents := translatorContents([]uint8{egress.FamilyIPv4, egress.FamilyIPv6}, egress.DefaultFlowsPerSource, rules)
	without, err := translatorBatch(contents, rules, nftables.Contents{}, nil, nil, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	var leftovers []nftables.Retired
	want := slices.Clone(without)
	for _, name := range []string{"translated-udp4", "translated-tcp4", "translated-icmp4", "translated-udp6", "translated-tcp6", "translated-icmpv66"} {
		leftovers = append(leftovers, nftables.Retired{Kind: "ct timeout", Name: name})
		want = append(want, nftables.Timeout{Table: nftables.Table, Name: name}.Delete(unix.NFPROTO_INET))
	}
	with, err := translatorBatch(contents, rules, nftables.Contents{}, nil, leftovers, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(with, want) {
		t.Errorf("the batch over the earlier timeout objects sends %d requests, want the %d of the batch without them and the six deletions last", len(with), len(without))
	}
}

// The readback places a rule another writer put in IPv6's chain in IPv6, one
// in the forward hook's own chain in the first family, and a rule of desired's
// in its own family whichever chain holds it
func TestReadbackPlacesAnotherWritersRuleByItsChain(t *testing.T) {
	cfg := egress.Egress{Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}}}}
	desired := newTranslator(cfg, Runtime{Interface: "ranet0", Steered: true}, &fakeBackend{}).desired()
	ours := desired[slices.IndexFunc(desired, func(rule Rule) bool { return rule.Family == egress.FamilyIPv6 && rule.chain() == forward6.Name })].String()
	held := []nftables.Installed{
		{Chain: LimitChain, Spec: dispatchSpec},
		{Chain: forward6.Name, Spec: "another's in ipv6's chain"},
		{Chain: LimitChain, Spec: "another's in forward"},
		{Chain: LimitChain, Spec: ours},
	}
	placed := placeRules(held, desired, []uint8{egress.FamilyIPv4, egress.FamilyIPv6})
	for family, want := range map[uint8][]string{
		egress.FamilyIPv4: {"another's in forward"},
		egress.FamilyIPv6: {"another's in ipv6's chain", ours},
	} {
		var got []string
		for _, rule := range placed[family] {
			got = append(got, rule.Spec)
		}
		if !slices.Equal(got, want) {
			t.Errorf("the readback places %q in %s, want %q", got, egress.FamilyName(family), want)
		}
	}
}

// Emptying a chain names a table and a chain and no handle, which nf_tables
// reads as every rule in that chain. It can reach no other chain, which is the
// ownership claim this package makes.
func TestFlushNamesOnlyThisToolsOwnChain(t *testing.T) {
	for _, written := range translatorChains {
		request := written.Flush(unix.NFPROTO_INET)
		var table, chain string
		handles := 0
		for kind, value := range (netlink.Message{Data: request.Body}).Attributes(nftables.SizeofNfgenmsg) {
			switch kind {
			case unix.NFTA_RULE_TABLE:
				table = unix.ByteSliceToString(value)
			case unix.NFTA_RULE_CHAIN:
				chain = unix.ByteSliceToString(value)
			case unix.NFTA_RULE_HANDLE:
				handles++
			}
		}
		if table != nftables.Table || chain != written.Name {
			t.Errorf("would empty %s/%s, want %s/%s", table, chain, nftables.Table, written.Name)
		}
		if handles != 0 {
			t.Errorf("named %d handles, which would delete one rule rather than the chain", handles)
		}
	}
}

// A packet this host generated itself has no arrival interface, which
// nf_tables reports as the empty name rather than as a failure to read, so
// "iifname is not the mesh device" is true of it. An inbound rule left at that
// would translate this node's own mesh traffic to the return source, which on
// an exit is an address belonging to somebody else. The rule rules it out by
// interface index, which reads as zero for a locally generated packet on every
// kernel that answers the question at all.
func TestInboundRuleExcludesThisNodesOwnTraffic(t *testing.T) {
	inbound, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet0",
		Source: netip.MustParseAddr("10.88.0.2")}, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	// past the family's test, which every rule makes first
	keys := metaKeys(t, inbound.Body)
	if len(keys) < 2 || keys[0] != unix.NFT_META_NFPROTO || keys[1] != unix.NFT_META_IIF {
		t.Fatalf("an inbound rule loads %v, want the family and then the interface index first", keys)
	}

	// An outbound rule needs none of it: a locally generated packet fails
	// "iifname is the mesh device" whichever way the kernel answers.
	outbound, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"}, unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	if got := metaKeys(t, outbound.Body); slices.Contains(got, uint32(unix.NFT_META_IIF)) {
		t.Errorf("an outbound rule loads %v, which it has no test to make of the index", got)
	}
}

// metaKeys is the metadatum each meta expression loads, in order.
func metaKeys(t *testing.T, body []byte) []uint32 {
	t.Helper()
	var out []uint32
	for kind, value := range (netlink.Message{Data: body}).Attributes(nftables.SizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nftables.Nested(value) {
			var name string
			var data []byte
			for _, field := range nftables.Nested(element.Value) {
				switch field.Kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.Value)
				case unix.NFTA_EXPR_DATA:
					data = field.Value
				}
			}
			if name != "meta" {
				continue
			}
			for _, field := range nftables.Nested(data) {
				if field.Kind == unix.NFTA_META_KEY && len(field.Value) == 4 {
					out = append(out, binary.BigEndian.Uint32(field.Value))
				}
			}
		}
	}
	return out
}

// A name too long to be a device's is refused rather than truncated. The
// kernel pads an interface register to IFNAMSIZ with a terminator, so a
// sixteen byte comparison without one can never equal it: the rule would
// install and then match nothing, or in the inbound direction everything.
func TestOversizedInterfaceNameIsRefused(t *testing.T) {
	_, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", unix.IFNAMSIZ)}, unix.NFT_CT_LABELS)
	if err == nil || !strings.Contains(err.Error(), "device name is at most") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
	if _, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", unix.IFNAMSIZ-1)}, unix.NFT_CT_LABELS); err != nil {
		t.Errorf("the longest name a device can have was refused: %v", err)
	}
}

// The forward chain but the limit drops ICMP types 15 and 16, the Information
// Request and Reply, out of the mesh and into it, under a class of none and
// one that translates, and carries type 14, a Timestamp Reply, and type 17
// on each way, out of the mesh under none by the pass
func TestInformationDropTakesTypes15And16Alone(t *testing.T) {
	for name, to := range map[string]egress.Translation{"none": {None: true}, "auto": {Auto: true}} {
		cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"),
			Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/24"), To: to}}}
		tr := translator(t, cfg, Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.200")}}, &fakeBackend{})
		requests, rules, sets := forwardButLimit(t, tr, egress.FamilyIPv4)
		for _, way := range []struct {
			direction           Direction
			iif, oif            string
			source, destination string
		}{
			{Out, "ranet0", "eth0", "192.0.2.5", "203.0.113.9"},
			{In, "eth1", "ranet0", "198.51.100.9", "192.0.2.5"},
		} {
			for _, kind := range []uint8{14, 15, 16, 17} {
				packet := drawnPacket{iif: way.iif, source: netip.MustParseAddr(way.source), destination: netip.MustParseAddr(way.destination)}.carrying(unix.IPPROTO_ICMP, 0)
				packet.transport[0] = kind
				packet.oif, packet.ctState = way.oif, nftables.CTStateNew
				by, run := runBy(t, requests, rules, sets, packet)
				want, wantBy := chainRun{rule: -1, accept: true}, ""
				switch {
				case kind == 15 || kind == 16:
					want = chainRun{counted: true}
					wantBy = Rule{Family: egress.FamilyIPv4, Direction: way.direction, Interface: "ranet0", Drops: Information}.String()
				case to.None && way.direction == Out:
					want = chainRun{accept: true}
					wantBy = "out via ranet0 ipv4 untranslated passed"
				}
				if by != wantBy || run != want {
					t.Errorf("under %s, ICMP type %d %s via ranet0 meets %q as %+v, want %q as %+v", name, kind, way.direction, by, run, wantBy, want)
				}
			}
		}
	}
}

// forwardButLimit is the rules of family's chain at tr's forward hook but the
// limit, whose count of each source's flows runRule does not model, their
// requests in the chain's order, and the sets their sources are looked up in
// as encodedSets reads them
func forwardButLimit(t testing.TB, tr *Translator, family uint8) ([]nftables.Request, []Rule, map[string][]nftables.Interval) {
	t.Helper()
	var requests []nftables.Request
	var rules []Rule
	desired := tr.desired()
	for _, rule := range desired {
		if rule.Family != family || rule.chain() == ChainName || rule.kind() == limiting {
			continue
		}
		request, err := newRule(rule, unix.NFT_CT_LABELS)
		if err != nil {
			t.Fatal(err)
		}
		requests, rules = append(requests, request), append(rules, rule)
	}
	set := untranslatedSources(family)
	filled, err := set.Fill(unix.NFPROTO_INET, familyContents(family, 0, desired).Elements[set.Name])
	if err != nil {
		t.Fatal(err)
	}
	return requests, rules, encodedSets(t, filled)
}

// runBy runs packet through requests, its lookups reading sets, and names the
// rule of rules it met, empty for the policy, with the run's rule set to 0
// where it met one
func runBy(t *testing.T, requests []nftables.Request, rules []Rule, sets map[string][]nftables.Interval, packet chainPacket) (string, chainRun) {
	t.Helper()
	packet.sets = sets
	run := runChain(t, requests, packet)
	if run.rule < 0 {
		return "", run
	}
	by := rules[run.rule].String()
	run.rule = 0
	return by, run
}

// An empty advertise list is an exit serving only steered traffic, which only
// a node holding an egress segment can be. Without one the capability would
// translate nothing and offer nothing, and New refuses it before it opens
// anything.
func TestEmptyAdvertiseNeedsAnEgressSegment(t *testing.T) {
	if err := (egress.Egress{}).Validate(); err != nil {
		t.Fatalf("a capability advertising nothing was refused on its own: %v", err)
	}
	if err := (egress.Egress{}).Serves(true); err != nil {
		t.Errorf("an exit with an egress segment was refused: %v", err)
	}
	if err := (egress.Egress{}).Serves(false); err == nil || !strings.Contains(err.Error(), "advertise is empty") {
		t.Errorf("an exit with nothing to carry was refused with %v", err)
	}
	_, err := New(egress.Egress{}, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
	if err == nil || !strings.Contains(err.Error(), "advertise is empty") {
		t.Fatalf("New returned %v, want the refusal of a capability carrying nothing", err)
	}
}

// New refuses before it opens anything, so a capability whose return direction
// cannot resolve a source fails with nothing to clean up. Only an address
// class from every source settles it for a node with no mesh address.
func TestNewRefusesAnUnresolvableReturnBeforeOpeningTheBackend(t *testing.T) {
	for name, translate := range map[string][]egress.Class{
		"no class":                      nil,
		"auto from every source":        {{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Auto: true}}},
		"an address from fewer of them": {{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}}},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"), Translate: translate}
			_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: func() (bool, bool) { return true, true }})
			if err == nil || !strings.Contains(err.Error(), "in cap.egress translate as the to of the class from 0.0.0.0/0") {
				t.Fatalf("New returned %v, want a refusal naming the field that settles it", err)
			}
		})
	}
}

// The forward chain but the limit, as forwardButLimit gives it, decides a
// DCCP or UDP-Lite packet by its flow. A flow's first packet out of the mesh
// is refused from a source the exit translates. A packet no flow is tracked
// for meets the rule taking it, which drops it in place of a refusal. Either
// from a source under none meets the pass, and from a class that translates
// inside it the rules from every source.
// A reply goes on to the
// translation its flow's first packet was given, into the mesh to a source
// under none and out of it from a leaf behind a subnet router.
func TestForwardChainTakesAChecksummedProtocolByItsFlow(t *testing.T) {
	const established, related = 1 << 1, 1 << 2
	returned := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"),
		Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{None: true}}}}
	routed := egress.Egress{Advertise: prefixes(t, "198.51.100.0/24")}
	inside := returned
	inside.Translate = append(slices.Clone(returned.Translate), egress.Class{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{Auto: true}})
	for _, c := range []struct {
		name                string
		cfg                 egress.Egress
		iif, oif            string
		source, destination string
		state               uint32
		reply               bool
		// by is the rule the packet meets with %s for the protocol, empty for the
		// policy
		by   string
		want chainRun
	}{
		{"a first packet from a translated source", returned, "ranet0", "eth0", "192.0.2.200", "203.0.113.9", nftables.CTStateNew, false,
			"out via ranet0 ipv4 %s refused", chainRun{counted: true, rejected: 13}},
		{"a first packet from a source under none", returned, "ranet0", "eth0", "192.0.2.5", "203.0.113.9", nftables.CTStateNew, false,
			"out via ranet0 ipv4 untranslated passed", chainRun{accept: true}},
		{"a first packet into the mesh under return", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", nftables.CTStateNew, false,
			"in via ranet0 ipv4 from 198.51.100.0/24 %s refused", chainRun{counted: true, rejected: 13}},
		{"no flow from a translated source", returned, "ranet0", "eth0", "192.0.2.200", "203.0.113.9", nftables.CTStateInvalid, false,
			"out via ranet0 ipv4 untracked dropped", chainRun{counted: true}},
		{"no flow from a source under none", returned, "ranet0", "eth0", "192.0.2.5", "203.0.113.9", nftables.CTStateUntracked, false,
			"out via ranet0 ipv4 untranslated passed", chainRun{accept: true}},
		{"a first packet from a class that translates inside one of none", inside, "ranet0", "eth0", "192.0.2.5", "203.0.113.9", nftables.CTStateNew, false,
			"out via ranet0 ipv4 %s refused", chainRun{counted: true, rejected: 13}},
		{"no flow from a class that translates inside one of none", inside, "ranet0", "eth0", "192.0.2.5", "203.0.113.9", nftables.CTStateInvalid, false,
			"out via ranet0 ipv4 untracked dropped", chainRun{counted: true}},
		{"a first packet from a source under none beside that class", inside, "ranet0", "eth0", "192.0.2.100", "203.0.113.9", nftables.CTStateNew, false,
			"out via ranet0 ipv4 untranslated passed", chainRun{accept: true}},
		{"a reply into the mesh to a source under none", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", established, true,
			"", chainRun{rule: -1, accept: true}},
		{"a related reply into the mesh to a source under none", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", related, true,
			"", chainRun{rule: -1, accept: true}},
		{"a leaf's reply out to a host behind a subnet router", routed, "ranet0", "eth1", "192.0.2.5", "198.51.100.9", established, true,
			"", chainRun{rule: -1, accept: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := translator(t, c.cfg, Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.200")}}, &fakeBackend{})
			requests, rules, sets := forwardButLimit(t, tr, egress.FamilyIPv4)
			for _, protocol := range checksummed {
				packet := drawnPacket{iif: c.iif, source: netip.MustParseAddr(c.source), destination: netip.MustParseAddr(c.destination)}.carrying(protocol.Number, 0)
				packet.oif, packet.ctState, packet.reply = c.oif, c.state, c.reply
				by, run := runBy(t, requests, rules, sets, packet)
				want := strings.ReplaceAll(c.by, "%s", protocol.Name)
				if by != want || run != c.want {
					t.Errorf("%s meets %q as %+v, want %q as %+v", protocol.Name, by, run, want, c.want)
				}
			}
		})
	}
}
