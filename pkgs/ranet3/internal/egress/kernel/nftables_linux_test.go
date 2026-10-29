// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress"
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
	for kind, value := range (nftables.Message{Data: body}).Attributes() {
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
// order a packet meets them: both interfaces, then the narrowing, then the
// counter and the translation, or for a timeout rule its protocol and its
// object, and for the limit's rule the connection's state and status first and
// the count, the counter and the answer last, in the limit's chain, as are the
// ICMP drops and the refusals, which take their protocol first, and a refusal
// then its flow's direction
func TestRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	for _, one := range []struct {
		name string
		rule Rule
		want []string
	}{
		{
			"out of the mesh under the host's own address",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "masq"},
		},
		{
			"out of the mesh under a configured address",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", Source: netip.MustParseAddr("2001:db8::1")},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "immediate", "nat"},
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
			[]string{"meta", "cmp", "payload", "cmp", "counter", "immediate", "nat"},
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
			[]string{"ct", "bitwise", "cmp", "ct", "bitwise", "cmp", "meta", "cmp", "meta", "cmp", "payload", "dynset", "counter", "reject"},
		},
		{
			"the drop of what no flow is tracked for out of the mesh",
			Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("192.0.2.128/25"), Untracked: true},
			// The state first, then the direction and the class, then the counted drop.
			[]string{"ct", "bitwise", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate"},
		},
		{
			"the pass of what no flow is tracked for from a class of none",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("3fff::/20"), None: true, Untracked: true},
			[]string{"ct", "bitwise", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "immediate"},
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
		{
			"the pass of udp-lite from a class of none",
			Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet0", From: netip.MustParsePrefix("3fff::/20"), None: true, Protocol: udpLite},
			[]string{"meta", "cmp", "ct", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "immediate"},
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			request, err := newRule(one.rule)
			if err != nil {
				t.Fatal(err)
			}
			if got := expressionNames(t, request.Body); !slices.Equal(got, one.want) {
				t.Errorf("encoded %q, want %q", got, one.want)
			}
			want := ChainName
			if inForwardChain(one.rule) {
				want = LimitChain
			}
			table, chain, spec, _, _ := nftables.DecodeRule(nftables.Message{Data: request.Body})
			if table != TableName || chain != want {
				t.Errorf("wrote into %s/%s, want %s/%s", table, chain, TableName, want)
			}
			if spec != one.rule.String() {
				t.Errorf("the rule reads back as %q, want %q, so the diff would rewrite it forever", spec, one.rule.String())
			}
		})
	}
}

// An interface name is compared over the whole IFNAMSIZ the kernel pads it to.
// A shorter comparison matches every device whose name starts the same way, so
// a rule for "ranet0" would also claim traffic on "ranet01".
func TestInterfaceComparisonCoversTheWholePaddedName(t *testing.T) {
	request, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for kind, value := range (nftables.Message{Data: request.Body}).Attributes() {
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
		{Out, []uint32{unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ}},
		// The leading NEQ is the local-origin test, which both directions of
		// the interface pair follow.
		{In, []uint32{unix.NFT_CMP_NEQ, unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ}},
	} {
		t.Run(one.direction.String(), func(t *testing.T) {
			request, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: one.direction, Interface: "ranet0"})
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for kind, value := range (nftables.Message{Data: request.Body}).Attributes() {
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
// and so do its longest timeout rule's, its limit rule's, at the largest limit a capability names, its rules' taking what no flow is tracked for, its ICMP drops' and its refusals', so no configuration reaches the refusal of a longer one, which nft -f would not load back
func TestLongestRuleFitsTheCommentLimit(t *testing.T) {
	address := netip.MustParseAddr("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff")
	device := strings.Repeat("r", unix.IFNAMSIZ-1)
	for _, direction := range []Direction{Out, In, Local} {
		rule := Rule{Family: egress.FamilyIPv6, Direction: direction, Interface: device, From: netip.PrefixFrom(address, 128), Source: address}
		timeouts := rule
		timeouts.Source, timeouts.Timeouts = netip.Addr{}, ICMPv6Timeouts
		for _, rule := range []Rule{rule, timeouts} {
			if _, err := newRule(rule); err != nil {
				t.Errorf("the longest %s rule was refused: %v", direction, err)
			}
		}
	}
	if _, err := newRule(Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: device, Limit: egress.MaxFlowsPerSource}); err != nil {
		t.Errorf("the longest limit rule was refused: %v", err)
	}
	for _, none := range []bool{false, true} {
		if _, err := newRule(Rule{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), None: none, Untracked: true}); err != nil {
			t.Errorf("the longest rule taking what no flow is tracked for was refused: %v", err)
		}
	}
	for _, rule := range []Rule{
		{Family: egress.FamilyIPv4, Direction: Out, Interface: device, Drops: SourceQuench},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), Protocol: udpLite},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: device, From: netip.PrefixFrom(address, 128), None: true, Protocol: udpLite},
	} {
		if _, err := newRule(rule); err != nil {
			t.Errorf("the longest drop or refusal was refused: %v", err)
		}
	}
	if _, err := flowSet(egress.FamilyIPv6, egress.MaxFlowsPerSource).Create(unix.NFPROTO_IPV6); err != nil {
		t.Errorf("the set of the largest limit was refused: %v", err)
	}
}

// The translating chain is a nat base chain at the source translation hook,
// one below the priority the host's own source translation runs at, so it
// runs ahead of every chain there whatever order they were made in. The
// limit's chain filters at the forward hook, where a forwarded packet meets it
// before the translation, as the host's own filters do.
func TestChainsHookWhereTheirRulesAct(t *testing.T) {
	for _, want := range []struct {
		chain, kind string
		hook        uint32
		priority    int32
	}{
		{ChainName, "nat", unix.NF_INET_POST_ROUTING, 99},
		{LimitChain, "filter", unix.NF_INET_FORWARD, filterPriority},
	} {
		index := slices.IndexFunc(translatorChains, func(c nftables.Chain) bool { return c.Name == want.chain })
		if index < 0 {
			t.Errorf("the translator writes no chain %s", want.chain)
			continue
		}
		request := translatorChains[index].Create(unix.NFPROTO_IPV4)
		table, chain, kind, hook, priority := nftables.DecodeChain(nftables.Message{Data: request.Body})
		if table != TableName || chain != want.chain || kind != want.kind || hook != want.hook || priority != want.priority {
			t.Errorf("created %s/%s, a %s chain at hook %d, priority %d, want %s/%s, a %s chain at hook %d, priority %d",
				table, chain, kind, hook, priority, TableName, want.chain, want.kind, want.hook, want.priority)
		}
	}
}

// Emptying a chain names a table and a chain and no handle, which nf_tables
// reads as every rule in that chain. It can reach no other table, which is the
// ownership claim this package makes.
func TestFlushNamesOnlyThisToolsOwnChain(t *testing.T) {
	for _, written := range translatorChains {
		request := written.Flush(unix.NFPROTO_IPV6)
		var table, chain string
		handles := 0
		for kind, value := range (nftables.Message{Data: request.Body}).Attributes() {
			switch kind {
			case unix.NFTA_RULE_TABLE:
				table = unix.ByteSliceToString(value)
			case unix.NFTA_RULE_CHAIN:
				chain = unix.ByteSliceToString(value)
			case unix.NFTA_RULE_HANDLE:
				handles++
			}
		}
		if table != TableName || chain != written.Name {
			t.Errorf("would empty %s/%s, want %s/%s", table, chain, TableName, written.Name)
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
		Source: netip.MustParseAddr("10.88.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	keys := metaKeys(t, inbound.Body)
	if len(keys) == 0 || keys[0] != unix.NFT_META_IIF {
		t.Fatalf("an inbound rule loads %v, want the interface index first", keys)
	}

	// An outbound rule needs none of it: a locally generated packet fails
	// "iifname is the mesh device" whichever way the kernel answers.
	outbound, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet0"})
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
	for kind, value := range (nftables.Message{Data: body}).Attributes() {
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
	_, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", unix.IFNAMSIZ)})
	if err == nil || !strings.Contains(err.Error(), "device name is at most") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
	if _, err := newRule(Rule{Family: egress.FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", unix.IFNAMSIZ-1)}); err != nil {
		t.Errorf("the longest name a device can have was refused: %v", err)
	}
}

// The forward chain but the limit drops ICMP types 15 and 16, the Information
// Request and Reply, out of the mesh and into it, under a class of none and
// one that translates, and carries type 14, a Timestamp Reply, and type 17
// on each way
func TestInformationDropTakesTypes15And16Alone(t *testing.T) {
	for name, to := range map[string]egress.Translation{"none": {None: true}, "auto": {Auto: true}} {
		cfg := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"),
			Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/24"), To: to}}}
		tr := translator(t, cfg, Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.200")}}, &fakeBackend{})
		requests, rules := forwardButLimit(t, tr)
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
				by, run := runBy(t, requests, rules, packet)
				want, wantBy := chainRun{rule: -1, accept: true}, ""
				if kind == 15 || kind == 16 {
					want = chainRun{counted: true}
					wantBy = Rule{Family: egress.FamilyIPv4, Direction: way.direction, Interface: "ranet0", Drops: Information}.String()
				}
				if by != wantBy || run != want {
					t.Errorf("under %s, ICMP type %d %s via ranet0 meets %q as %+v, want %q as %+v", name, kind, way.direction, by, run, wantBy, want)
				}
			}
		}
	}
}

// inForwardChain is whether newRule writes rule into the forward chain
func inForwardChain(rule Rule) bool {
	return rule.Limit != 0 || rule.Untracked || rule.byProtocol()
}

// forwardButLimit is the IPv4 rules of tr's forward chain but the limit, whose
// count of each source's flows runRule does not model, and their requests in
// the chain's order
func forwardButLimit(t *testing.T, tr *Translator) ([]nftables.Request, []Rule) {
	t.Helper()
	var requests []nftables.Request
	var rules []Rule
	for _, rule := range tr.desired() {
		if rule.Family == egress.FamilyIPv4 && inForwardChain(rule) && rule.Limit == 0 {
			request, err := newRule(rule)
			if err != nil {
				t.Fatal(err)
			}
			requests, rules = append(requests, request), append(rules, rule)
		}
	}
	return requests, rules
}

// runBy runs packet through requests and names the rule of rules it met,
// empty for the policy, with the run's rule set to 0 where it met one
func runBy(t *testing.T, requests []nftables.Request, rules []Rule, packet chainPacket) (string, chainRun) {
	t.Helper()
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
// DCCP or UDP-Lite packet by its flow. A flow's first packet out of
// the mesh is refused from a source the exit translates and passed from one
// under none. A packet no flow is tracked for meets the rules taking it, which
// drop it or pass it under none in place of a refusal. A reply goes on to the
// translation its flow's first packet was given, into the mesh to a source
// under none and out of it from a leaf behind a subnet router.
func TestForwardChainTakesAChecksummedProtocolByItsFlow(t *testing.T) {
	const established, related = 1 << 1, 1 << 2
	returned := egress.Egress{Return: true, Advertise: prefixes(t, "198.51.100.0/24"),
		Translate: []egress.Class{{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{None: true}}}}
	routed := egress.Egress{Advertise: prefixes(t, "198.51.100.0/24")}
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
			"out via ranet0 ipv4 from 192.0.2.0/25 %s passed", chainRun{accept: true}},
		{"a first packet into the mesh under return", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", nftables.CTStateNew, false,
			"in via ranet0 ipv4 from 198.51.100.0/24 %s refused", chainRun{counted: true, rejected: 13}},
		{"no flow from a translated source", returned, "ranet0", "eth0", "192.0.2.200", "203.0.113.9", nftables.CTStateInvalid, false,
			"out via ranet0 ipv4 untracked dropped", chainRun{counted: true}},
		{"no flow from a source under none", returned, "ranet0", "eth0", "192.0.2.5", "203.0.113.9", nftables.CTStateUntracked, false,
			"out via ranet0 ipv4 from 192.0.2.0/25 untracked passed", chainRun{accept: true}},
		{"a reply into the mesh to a source under none", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", established, true,
			"", chainRun{rule: -1, accept: true}},
		{"a related reply into the mesh to a source under none", returned, "eth1", "ranet0", "198.51.100.9", "192.0.2.5", related, true,
			"", chainRun{rule: -1, accept: true}},
		{"a leaf's reply out to a host behind a subnet router", routed, "ranet0", "eth1", "192.0.2.5", "198.51.100.9", established, true,
			"", chainRun{rule: -1, accept: true}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr := translator(t, c.cfg, Runtime{MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.200")}}, &fakeBackend{})
			requests, rules := forwardButLimit(t, tr)
			for _, protocol := range checksummed {
				packet := drawnPacket{iif: c.iif, source: netip.MustParseAddr(c.source), destination: netip.MustParseAddr(c.destination)}.carrying(protocol.Number, 0)
				packet.oif, packet.ctState, packet.reply = c.oif, c.state, c.reply
				by, run := runBy(t, requests, rules, packet)
				want := strings.ReplaceAll(c.by, "%s", protocol.Name)
				if by != want || run != c.want {
					t.Errorf("%s meets %q as %+v, want %q as %+v", protocol.Name, by, run, want, c.want)
				}
			}
		})
	}
}
