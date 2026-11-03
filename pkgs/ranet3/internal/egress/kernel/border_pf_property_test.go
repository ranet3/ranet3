// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/internal/pf"
	"ranet3.com/pkgs/ranet3/schema"
)

// drawPFRanges draws a set of one family as the filter holds it: up to four
// pieces, each a prefix of any length or a range between two addresses that no
// one prefix need cover, joined as egress.Union leaves them. The first byte is
// kept off zero, as internal/pf's drawPrefix keeps it, and a range may still
// end inside fe80::/10.
func drawPFRanges(tc hegel.TestCase, v6 bool) []egress.Range {
	size := 4
	if v6 {
		size = 16
	}
	address := func() netip.Addr {
		raw := hegel.Draw(tc, hegel.Binary(size, size))
		raw[0] |= 0x20
		a, _ := netip.AddrFromSlice(raw)
		return a
	}
	var pieces []egress.Range
	for range hegel.Draw(tc, pbt.Spanning(0, 4)) {
		if hegel.Draw(tc, hegel.Booleans()) {
			prefix := netip.PrefixFrom(address(), hegel.Draw(tc, pbt.Spanning(0, size*8))).Masked()
			pieces = append(pieces, meshkernel.Ranges([]netip.Prefix{prefix})...)
			continue
		}
		first, last := address(), address()
		if last.Less(first) {
			first, last = last, first
		}
		pieces = append(pieces, egress.Range{First: first, Last: last})
	}
	return egress.Union(pieces)
}

// printedAndParsed is rs rendered, printed as pfctl prints an anchor back, each
// rule as written and each table's entries one to a line in another order,
// and parsed again
func printedAndParsed(t *hegel.T, text string) pf.Ruleset {
	var rs pf.Ruleset
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if rest, ok := strings.CutPrefix(line, "table <"); ok {
			name, rest, _ := strings.Cut(rest, ">")
			inner := strings.TrimSpace(rest[strings.Index(rest, "{")+1 : strings.LastIndex(rest, "}")])
			var entries []string
			if inner != "" {
				entries = strings.Split(inner, ", ")
			}
			slices.Reverse(entries)
			var show strings.Builder
			for _, entry := range entries {
				show.WriteString("   " + entry + "\n")
			}
			prefixes, err := pf.ParseTableShow(show.String())
			if err != nil {
				t.Fatal(err)
			}
			rs.Tables = append(rs.Tables, pf.Table{Name: name, Const: strings.HasPrefix(rest, " const "), Prefixes: prefixes})
			continue
		}
		rule, err := pf.ParseRule(line)
		if err != nil {
			t.Fatal(err)
		}
		rs.Rules = append(rs.Rules, rule)
	}
	return rs
}

// decodedAnchor reads an anchor back as the filter's rules, by each rule's
// form and, where a carve-out's pass and an interface exemption's share one,
// by its label's leading words, and as the two tables' addresses, failing on
// any line the filter does not write and on a label other than its place's
func decodedAnchor(t *hegel.T, tun string, rs pf.Ruleset) (rules []BorderRule, overlay []netip.Prefix, carved []egress.Range) {
	for _, r := range rs.Rules {
		onTun := r.NotInterface && r.Interface == tun
		rule := BorderRule{Source: r.From.Prefix, IPv6: r.Family == pf.Inet6}
		switch {
		case !r.Quick:
			t.Fatalf("the anchor holds %q, which is not quick", r)
		case r.Action == pf.Pass && r.From.Table == pfOverlayTable && !r.NotInterface && r.Family == pf.AnyFamily:
			rule = BorderRule{Class: BorderInside, Device: r.Interface}
		case r.Action == pf.Block && r.From.Table == pfCarvedTable && onTun && r.Family != pf.AnyFamily:
			rule = BorderRule{Class: BorderCarved, IPv6: r.Family == pf.Inet6}
		case !r.From.Prefix.IsValid() || r.Family == pf.AnyFamily:
			t.Fatalf("the anchor holds %q, from no prefix of a family", r)
		case r.Action == pf.Block && onTun:
			rule.Class = BorderSource
		case r.Action == pf.Pass && onTun:
			rule.Class = BorderExempt
		case r.Action == pf.Pass && !r.NotInterface && strings.HasPrefix(r.Label, "accept exempt via "):
			rule.Class, rule.Device = BorderExempt, r.Interface
		case r.Action == pf.Pass && !r.NotInterface && strings.HasPrefix(r.Label, "accept via "):
			rule.Class, rule.Device = BorderCarveOut, r.Interface
		default:
			t.Fatalf("the anchor holds %q, which the filter does not write", r)
		}
		rules = append(rules, rule)
	}
	for i, label := range pfLabels(rules) {
		if rs.Rules[i].Label != label {
			t.Fatalf("the rule %q is labeled other than %q", rs.Rules[i], label)
		}
	}
	for _, table := range rs.Tables {
		if !table.Const {
			t.Fatalf("the table <%s> is not const", table.Name)
		}
		switch table.Name {
		case pfOverlayTable:
			overlay = table.Prefixes
		case pfCarvedTable:
			carved = meshkernel.Ranges(table.Prefixes)
		default:
			t.Fatalf("the anchor holds the table <%s>", table.Name)
		}
	}
	return rules, overlay, carved
}

// pfHoldsOtherwise reports whether rs holds a prefix pf's parse would change,
// in a table or as a rule's source: one in fe80::/10 with a nonzero second
// group past length 16
func pfHoldsOtherwise(rs pf.Ruleset) bool {
	linkLocal := netip.MustParsePrefix("fe80::/10")
	changed := func(p netip.Prefix) bool {
		return p.IsValid() && linkLocal.Contains(p.Addr()) && p.Addr().As16()[2]|p.Addr().As16()[3] != 0
	}
	return slices.ContainsFunc(rs.Tables, func(table pf.Table) bool { return slices.ContainsFunc(table.Prefixes, changed) }) ||
		slices.ContainsFunc(rs.Rules, func(r pf.Rule) bool { return changed(r.From.Prefix) })
}

// drawPFPrefix draws a prefix of either family at any length from 1, its
// first byte kept off zero
func drawPFPrefix(tc hegel.TestCase) netip.Prefix {
	size := 4
	if hegel.Draw(tc, hegel.Booleans()) {
		size = 16
	}
	raw := hegel.Draw(tc, hegel.Binary(size, size))
	raw[0] |= 0x20
	address, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(1, size*8))).Masked()
}

// drawPFFilter draws a configuration and its sets as a pass hands them to the
// pf backend: an overlay of 1 to 4 prefixes of both families, carved sets,
// carve-outs on links whose names are 1 to 15 bytes, and shared and per-link
// exemptions, each link's under its exact name or a wildcard over the links,
// every prefix of any length up to /128
func drawPFFilter(tc hegel.TestCase, tun string) *BorderFilter {
	links := make([]string, 0, 3)
	for range hegel.Draw(tc, pbt.Spanning(1, 3)) {
		name := hegel.Draw(tc, hegel.Text().Alphabet("abcdefghijklmnopqrstuvwxyz0123456789").MinSize(1).MaxSize(15))
		if !slices.Contains(links, name) && name != tun && name != "lo0" {
			links = append(links, name)
		}
	}
	slices.Sort(links)
	prefixes := func(least, most int) []schema.Prefix {
		var out []schema.Prefix
		for range hegel.Draw(tc, pbt.Spanning(least, most)) {
			if p := schema.PrefixFrom(drawPFPrefix(tc)); !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		return out
	}
	cfg := &egress.Border{Overlay: prefixes(1, 4), Antispoof: egress.Antispoof{Exempt: prefixes(0, 2)}}
	for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
		name := hegel.Draw(tc, hegel.SampledFrom(links))
		if hegel.Draw(tc, hegel.Booleans()) {
			name = name[:hegel.Draw(tc, pbt.Spanning(1, len(name)))] + "*"
		}
		if cfg.Antispoof.Interface == nil {
			cfg.Antispoof.Interface = map[string]egress.AntispoofInterface{}
		}
		cfg.Antispoof.Interface[name] = egress.AntispoofInterface{Exempt: prefixes(1, 2)}
	}
	var carveOuts []egress.CarveOut
	for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
		carveOut := egress.CarveOut{Link: hegel.Draw(tc, hegel.SampledFrom(links)), Prefix: drawPFPrefix(tc)}
		if !slices.Contains(carveOuts, carveOut) {
			carveOuts = append(carveOuts, carveOut)
		}
	}
	sets := egress.BorderSets{CarveOuts: carveOuts, Carved: slices.Concat(drawPFRanges(tc, false), drawPFRanges(tc, true)), Links: links}
	rt := egress.BorderRuntime{Tun: tun, Inside: []string{tun, "lo0"}, Sets: func(*egress.Border) egress.BorderSets { return sets }}
	return newBorderFilter(cfg, rt, &borderPF{tun: tun, inside: rt.Inside})
}

// The anchor the pf backend writes for a drawn configuration, its carve-outs
// and its carved sets, rendered, printed back as pfctl prints it and parsed,
// gives back the rules the pass asks for in order, a carve-out told from an
// exemption on the same link and prefix by its label, the overlay in
// <ranet3_overlay> and the carved sets of both families in <ranet3_carved>,
// whatever the drawing. An anchor holding a prefix pf would hold as another is
// refused, naming fe80::/10.
func TestPfAnchorReadsBackAsTheRulesAndSets(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		tun := fmt.Sprintf("utun%d", hegel.Draw(ht, pbt.Spanning(0, 255)))
		f := hegel.Draw(ht, hegel.Composite(func(tc hegel.TestCase) *BorderFilter { return drawPFFilter(tc, tun) }))
		rules, sets, _ := f.desired()
		rs, err := pfRuleset(tun, rules, sets)
		if err != nil {
			ht.Fatal(err)
		}
		text, err := rs.Render()
		if pfHoldsOtherwise(rs) {
			if err == nil || !strings.Contains(err.Error(), "fe80::/10") {
				ht.Fatalf("an anchor pf would hold otherwise renders: %v\n%s", err, text)
			}
			return
		}
		if err != nil {
			ht.Fatalf("the anchor for %+v is refused: %v", rules, err)
		}
		got, overlay, carved := decodedAnchor(ht, tun, printedAndParsed(ht, text))
		if !slices.Equal(got, rules) {
			ht.Fatalf("the anchor reads back as %v, not %v\n%s", got, rules, text)
		}
		var want []netip.Prefix
		for _, prefix := range f.Capability().Normalized().Overlay {
			want = append(want, prefix.Prefix)
		}
		slices.SortFunc(overlay, netip.Prefix.Compare)
		slices.SortFunc(want, netip.Prefix.Compare)
		if !slices.Equal(overlay, want) {
			ht.Fatalf("<%s> reads back as %v, not %v\n%s", pfOverlayTable, overlay, want, text)
		}
		hasCarved := slices.ContainsFunc(rules, func(rule BorderRule) bool { return rule.Class == BorderCarved })
		if want := egress.Union(slices.Concat(sets[carvedSet+"4"], sets[carvedSet+"6"])); hasCarved && !slices.Equal(carved, want) {
			ht.Fatalf("<%s> reads back as %v, not %v\n%s", pfCarvedTable, carved, want, text)
		}
	})
}

// On a backend that matches exact names alone the exemptions' rules are each
// exemption crossed with each link outside the mesh its name matches, in the
// exemptions' order and then the links', each rule once: a name ending in *
// matches each link whose name starts with the part before the *, any other
// name itself alone, and the shared list no link. A backend that matches a
// wildcard itself writes every exemption as given. The links drawn hold the
// tun and lo0 at times, which no rule names, and an exact lo0 writes no rule
// on either.
func TestWildcardExemptionsExpandOverTheLinks(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		names := []string{"en0", "en1", "en10", "bridge100", "utun3", "utun7", "lo0"}
		links := slices.Sorted(slices.Values(pbt.Subset(ht, names, 0, len(names))))
		cfg := &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("192.0.2.0/24")}}
		exempt := []schema.Prefix{schema.MustPrefix("192.0.2.0/26"), schema.MustPrefix("192.0.2.64/26")}
		cfg.Antispoof.Exempt = pbt.Subset(ht, exempt, 0, 1)
		for _, name := range pbt.Subset(ht, []string{"en*", "en1", "en1*", "utun*", "u*", "bridge*", "wl*", "lo0"}, 0, 4) {
			if cfg.Antispoof.Interface == nil {
				cfg.Antispoof.Interface = map[string]egress.AntispoofInterface{}
			}
			cfg.Antispoof.Interface[name] = egress.AntispoofInterface{Exempt: pbt.Subset(ht, exempt, 1, 2)}
		}
		rt := egress.BorderRuntime{Tun: "utun7", Inside: []string{"utun7", "lo0"}, Sets: func(*egress.Border) egress.BorderSets { return egress.BorderSets{Links: links} }}
		var want, given []string
		for _, exemption := range cfg.Exemptions() {
			if exemption.Interface == "lo0" {
				continue
			}
			given = append(given, BorderRule{Class: BorderExempt, Device: exemption.Interface, Source: exemption.Prefix}.String())
			devices := []string{exemption.Interface}
			if strings.HasSuffix(exemption.Interface, "*") {
				devices = nil
				for _, link := range links {
					if strings.HasPrefix(link, strings.TrimSuffix(exemption.Interface, "*")) && link != "utun7" && link != "lo0" {
						devices = append(devices, link)
					}
				}
			}
			for _, device := range devices {
				if rule := (BorderRule{Class: BorderExempt, Device: device, Source: exemption.Prefix}).String(); !slices.Contains(want, rule) {
					want = append(want, rule)
				}
			}
		}
		rules, _, _ := newBorderFilter(cfg, rt, &fakeBorder{exact: true}).desired()
		if got := exemptRules(rules); !slices.Equal(got, want) {
			ht.Fatalf("over the links %q the exemptions' rules are %q, want %q", links, got, want)
		}
		rules, _, _ = newBorderFilter(cfg, rt, &fakeBorder{}).desired()
		if got := exemptRules(rules); !slices.Equal(got, given) {
			ht.Fatalf("where the backend matches a wildcard the exemptions' rules are %q, want %q", got, given)
		}
	})
}
