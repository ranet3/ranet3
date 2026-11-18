// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// treeDepth is the most levels a drawn class tree nests
const treeDepth = 6

// classTree draws family's classes as a tree under one root, every source of
// the family or a documentation prefix: each class either a leaf, the parent of
// one class of any longer prefix down to a host prefix, or the parent of its two
// halves, which touch. Its translations are drawn one by one, alternate none
// and auto from a root of none, or hold no none at all, and a family now and
// then has no class.
func classTree(tc hegel.TestCase, family uint8) []egress.Class {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)) {
		return nil
	}
	root, address := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParseAddr("198.51.100.7")
	documentation := netip.MustParsePrefix("192.0.2.0/24")
	if family == egress.FamilyIPv6 {
		root, address, documentation = netip.MustParsePrefix("::/0"), netip.MustParseAddr("2001:db8::7"), netip.MustParsePrefix("2001:db8::/32")
	}
	if hegel.Draw(tc, hegel.Booleans()) {
		root = documentation
	}
	depth := hegel.Draw(tc, pbt.Spanning(1, treeDepth))
	mode := hegel.Draw(tc, hegel.SampledFrom([]string{"drawn", "alternate", "translated"}))
	var out []egress.Class
	var grow func(from netip.Prefix, level int)
	grow = func(from netip.Prefix, level int) {
		var to egress.Translation
		switch mode {
		case "alternate":
			to = egress.Translation{None: level%2 == 0, Auto: level%2 == 1}
		case "translated":
			to = hegel.Draw(tc, hegel.SampledFrom([]egress.Translation{{Auto: true}, {Addr: address}}))
		default:
			to = hegel.Draw(tc, hegel.SampledFrom([]egress.Translation{{Auto: true}, {Addr: address}, {None: true}}))
		}
		out = append(out, egress.Class{From: schema.Prefix{Prefix: from}, To: to})
		if level+1 == depth || from.Bits() == from.Addr().BitLen() {
			return
		}
		switch hegel.Draw(tc, hegel.SampledFrom([]string{"leaf", "one", "halves"})) {
		case "one":
			bits := hegel.Draw(tc, pbt.Spanning(from.Bits()+1, from.Addr().BitLen()))
			grow(inside(from, bits, hegel.Draw(tc, hegel.Integers[uint64](0, ^uint64(0)))), level+1)
		case "halves":
			grow(netip.PrefixFrom(from.Addr(), from.Bits()+1), level+1)
			grow(inside(from, from.Bits()+1, 1<<63), level+1)
		}
	}
	grow(root, 0)
	return out
}

// inside is the prefix of bits inside parent whose bits past parent's are
// pattern's, from its highest bit, again from the highest past 64 of them
func inside(parent netip.Prefix, bits int, pattern uint64) netip.Prefix {
	raw := parent.Masked().Addr().AsSlice()
	for at := parent.Bits(); at < bits; at++ {
		if pattern>>(63-(at-parent.Bits())%64)&1 == 1 {
			raw[at/8] |= 0x80 >> (at % 8)
		}
	}
	address, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(address, bits)
}

// untranslatedByClass is whether the class with the longest prefix covering
// source is one of none, which no class covering it is where none does
func untranslatedByClass(classes []egress.Class, source netip.Addr) bool {
	bits, none := -1, false
	for _, class := range classes {
		if class.From.Addr().Is4() == source.Is4() && class.From.Contains(source) && class.From.Bits() > bits {
			bits, none = class.From.Bits(), class.To.None
		}
	}
	return none
}

// screensMet is the screens meant for a packet out of the mesh from source
// that forwardWalk meets, for one no flow is tracked for, the first of each
// checksummed protocol and the one that creates a TCP flow, which the limit
// meets
func screensMet(desired []Rule, source netip.Addr) []Rule {
	var met []Rule
	for _, packet := range []crossing{
		{"ranet0", "eth0", source, unix.IPPROTO_UDP, 9, 0, true, false},
		{"ranet0", "eth0", source, dccp.Number, 0, 0, false, false},
		{"ranet0", "eth0", source, udpLite.Number, 0, 0, false, false},
		{"ranet0", "eth0", source, unix.IPPROTO_TCP, 443, 0, false, false},
	} {
		for _, rule := range forwardWalk(desired, packet) {
			if meant(rule, packet) && rule.kind() != passing {
				met = append(met, rule)
			}
		}
	}
	return met
}

// screenedOnce is whether met is each screen once: the drop of what no flow is
// tracked for, the refusal of each checksummed protocol and the limit
func screenedOnce(met []Rule) bool {
	var untracked, limits int
	var protocols []uint8
	for _, rule := range met {
		switch {
		case rule.Untracked:
			untracked++
		case rule.Limit != 0:
			limits++
		case rule.Protocol.Number != 0:
			protocols = append(protocols, rule.Protocol.Number)
		}
	}
	slices.Sort(protocols)
	return len(met) == 4 && untracked == 1 && limits == 1 && slices.Equal(protocols, []uint8{dccp.Number, udpLite.Number})
}

// A packet out of the mesh meets no screen at the forward hook where the class
// with the longest prefix covering its source is one of none, and every screen
// once where that class translates or no class covers it, in each family, for
// trees of classes nested up to treeDepth levels, siblings that touch among
// them, at both ends of each class's prefix and on either side of each end,
// and at each family's first and last address. The lines and the sets a pass
// writes, run as nf_tables runs them, accept a packet no flow is
// tracked for and the first packet of each checksummed protocol from a source
// whose class is none, and drop or refuse each from any other. A family with
// no class of none has no pass.
func TestPacketsMeetTheScreensAsTheirLongestClassSays(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		cfg := egress.Egress{Translate: slices.Concat(classTree(ht, egress.FamilyIPv4), classTree(ht, egress.FamilyIPv6))}
		ht.Assume(cfg.Validate() == nil)
		both := []uint8{egress.FamilyIPv4, egress.FamilyIPv6}
		tr := newTranslator(cfg, Runtime{Interface: "ranet0", Steered: true}, &fakeBackend{})
		desired := tr.desired()
		lines := map[uint8][]nftables.Request{}
		sets := map[uint8]map[string][]nftables.Interval{}
		for _, family := range both {
			none := slices.ContainsFunc(cfg.Classes(family), func(class egress.Class) bool { return class.To.None })
			if passes := slices.ContainsFunc(desired, func(rule Rule) bool { return rule.Family == family && rule.Passes }); passes && !none {
				ht.Fatalf("under %v %s, with no class of none, holds a pass, in %v", cfg.Translate, egress.FamilyName(family), desired)
			}
			lines[family], _, sets[family] = forwardButLimit(ht, tr, family)
		}
		var prefixes []netip.Prefix
		for _, class := range cfg.Translate {
			prefixes = append(prefixes, class.From.Prefix)
		}
		ends := []netip.Addr{
			netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"),
			netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
		}
		for _, source := range slices.Concat(ends, edgesOf(true, prefixes...), edgesOf(false, prefixes...)) {
			none := untranslatedByClass(cfg.Translate, source)
			if met := screensMet(desired, source); none && len(met) != 0 || !none && !screenedOnce(met) {
				ht.Fatalf("under %v a packet from %s, whose longest class is none %v, meets the screens %v, in %v", cfg.Translate, source, none, met, desired)
			}
			destination := netip.MustParseAddr("203.0.113.9")
			if source.Is6() {
				destination = netip.MustParseAddr("2001:db8:ffff::9")
			}
			for _, protocol := range []uint8{unix.IPPROTO_UDP, dccp.Number, udpLite.Number} {
				packet := drawnPacket{iif: "ranet0", source: source, destination: destination}.carrying(protocol, 0)
				family := egress.AddressFamily(source)
				packet.oif, packet.ctState, packet.sets = "eth0", nftables.CTStateNew, sets[family]
				if protocol == unix.IPPROTO_UDP {
					packet.ctState = nftables.CTStateInvalid
				}
				run := runChain(ht, lines[family], packet)
				if passed := run.accept && !run.counted; passed != none {
					ht.Fatalf("under %v a packet of protocol %d in ct state %#x from %s, whose longest class is none %v, runs as %+v, in %v", cfg.Translate, protocol, packet.ctState, source, none, run, desired)
				}
			}
		}
	})
}

// Another writer's change to a set of untranslated sources, its elements or
// the set itself, or to a chain an earlier translator wrote, wakes the
// translator, and its own does not
func TestTranslatorWakesOnItsUntranslatedSetsAndTheChainsAnEarlierTranslatorWrote(t *testing.T) {
	const own, other = 7, 9
	named := func(command int, tableKind, nameKind uint16, name string, pid uint32) netlink.Message {
		body := netlink.PutAttrString(netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), tableKind, nftables.Table), nameKind, name)
		return netlink.Message{Kind: nftables.Command(command), Pid: pid, Data: body}
	}
	for name, c := range map[string]struct {
		message netlink.Message
		wakes   bool
	}{
		"a source added to untranslated4":   {named(unix.NFT_MSG_NEWSETELEM, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET, untranslatedSet+"4", other), true},
		"a source taken from untranslated6": {named(unix.NFT_MSG_DELSETELEM, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET, untranslatedSet+"6", other), true},
		"untranslated6 deleted":             {named(unix.NFT_MSG_DELSET, unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME, untranslatedSet+"6", other), true},
		"its own fill of untranslated4":     {named(unix.NFT_MSG_NEWSETELEM, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET, untranslatedSet+"4", own), false},
		"a rule added to a none_ chain":     {named(unix.NFT_MSG_NEWRULE, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, NoneChain+"192_0_2_0_24", other), true},
		"a rule added to forward4":          {named(unix.NFT_MSG_NEWRULE, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, retiredChain, other), true},
	} {
		if got := translatorScope.ChangedByAnother(c.message, own); got != c.wakes {
			t.Errorf("%s: woke the translator %v, want %v", name, got, c.wakes)
		}
	}
}

// elementsOf is the set a request of the elements of a set names
func elementsOf(request nftables.Request) string {
	for kind, value := range (netlink.Message{Data: request.Body}).Attributes(nftables.SizeofNfgenmsg) {
		if kind == unix.NFTA_SET_ELEM_LIST_SET {
			return unix.ByteSliceToString(value)
		}
	}
	return ""
}

// The batch a pass sends empties each family's set of untranslated sources and
// fills it with the pass's sources ahead of the pass's line, in the one
// transaction that writes the rules, so no lookup meets the sources of one
// configuration beside the rules of another.
func TestPassChangesTheUntranslatedSetsInTheTransactionOfItsRules(t *testing.T) {
	cfg := egress.Egress{Translate: []egress.Class{
		{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
		{From: schema.MustPrefix("192.0.2.0/25"), To: egress.Translation{Auto: true}},
		{From: schema.MustPrefix("2001:db8::/32"), To: egress.Translation{None: true}},
	}}
	both := []uint8{egress.FamilyIPv4, egress.FamilyIPv6}
	desired := newTranslator(cfg, Runtime{Interface: "ranet0", Steered: true}, &fakeBackend{}).desired()
	requests, err := translatorBatch(translatorContents(both, cfg.SourceLimit(), desired), desired, nftables.Contents{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for family, want := range map[uint8][]nftables.Interval{
		egress.FamilyIPv4: nftables.Prefixes([]netip.Prefix{netip.MustParsePrefix("192.0.2.128/25")}),
		egress.FamilyIPv6: nftables.Prefixes([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}),
	} {
		set := untranslatedSources(family).Name
		pass := desired[slices.IndexFunc(desired, func(rule Rule) bool { return rule.Family == family && rule.Passes })]
		flush := slices.IndexFunc(requests, func(request nftables.Request) bool {
			return request.Kind == nftables.Command(unix.NFT_MSG_DELSETELEM) && elementsOf(request) == set
		})
		fill := slices.IndexFunc(requests, func(request nftables.Request) bool {
			return request.Kind == nftables.Command(unix.NFT_MSG_NEWSETELEM) && elementsOf(request) == set
		})
		line := slices.IndexFunc(requests, func(request nftables.Request) bool {
			if request.Kind != nftables.Command(unix.NFT_MSG_NEWRULE) {
				return false
			}
			_, _, spec, _, _, _ := nftables.DecodeRule(netlink.Message{Data: request.Body})
			return spec == pass.String()
		})
		if flush < 0 || fill < flush || line < fill {
			t.Errorf("the batch empties %s at request %d, fills it at %d and writes %q at %d, want all three in that order", set, flush, fill, pass, line)
		}
		if got := encodedSets(t, requests)[set]; !slices.EqualFunc(got, want, func(a, b nftables.Interval) bool {
			return bytes.Equal(a.First, b.First) && bytes.Equal(a.Last, b.Last)
		}) {
			t.Errorf("the batch fills %s with %v, want %v", set, got, want)
		}
	}
}
