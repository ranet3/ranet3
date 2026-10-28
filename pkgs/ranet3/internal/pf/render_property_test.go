// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package pf

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// labelText is every byte a label may hold, a space among them
const labelText = " !#%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~"

// drawPrefix draws a prefix of family at any length, its first
// byte kept off zero, which leaves the IPv4-compatible range, which pfctl
// prints dotted, to TestIPv4CompatibleAddressReadsBackAsWritten and the
// darwin oracle's fixed anchor. About one IPv6 draw in 64 lies in fe80::/10,
// where pfctlClears marks what the renderer must refuse: often enough that a
// run draws many anchors holding one, rarely enough that most anchors still
// render. The value picked is a middle one, since the generator favors bounds.
// shortest is the least length drawn, 1 for a rule's source, which pfctl
// prints as any at 0.
func drawPrefix(tc hegel.TestCase, family Family, shortest int) netip.Prefix {
	size := 16
	if family == Inet {
		size = 4
	}
	raw := hegel.Draw(tc, hegel.Binary(size, size))
	raw[0] |= 0x20
	if family == Inet6 && hegel.Draw(tc, hegel.Integers(0, 63)) == 17 {
		raw[0], raw[1] = 0xfe, 0x80|raw[1]&0x3f
	}
	address, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(shortest, size*8))).Masked()
}

// pfctlClears reports whether the anchor holds a prefix whose second group
// pfctl's parse clears, in a table or as a rule's source: one in fe80::/10
// with that group nonzero, as macbook's probes found (P10 to P12)
func pfctlClears(rs Ruleset) bool {
	linkLocal := netip.MustParsePrefix("fe80::/10")
	clears := func(p netip.Prefix) bool {
		return p.IsValid() && linkLocal.Contains(p.Addr()) && p.Addr().As16()[2]|p.Addr().As16()[3] != 0
	}
	return slices.ContainsFunc(rs.Tables, func(t Table) bool { return slices.ContainsFunc(t.Prefixes, clears) }) ||
		slices.ContainsFunc(rs.Rules, func(r Rule) bool { return clears(r.From.Prefix) })
}

// refusedForTheScope asserts that an anchor pfctl would change is refused,
// naming fe80::/10, and reports whether the anchor was one
func refusedForTheScope(t *hegel.T, rs Ruleset) bool {
	if !pfctlClears(rs) {
		return false
	}
	if text, err := rs.Render(); err == nil || !strings.Contains(err.Error(), "fe80::/10") {
		t.Fatalf("an anchor holding a prefix pfctl would change renders: %v\n%s", err, text)
	}
	return true
}

// drawRuleset draws an anchor of up to two tables of 0 to 64 prefixes of both
// families and one to six passes and drops of packets in over them, each from
// a table, a prefix of its family or any source, on an interface, every one
// but it, or every one, each rule's label unique and of up to 63 bytes
func drawRuleset(tc hegel.TestCase) Ruleset {
	var tables []Table
	for _, name := range pbt.Subset(tc, []string{"ranet3_overlay", "ranet3_carved"}, 0, 2) {
		t := Table{Name: name, Const: hegel.Draw(tc, hegel.Booleans())}
		for range hegel.Draw(tc, pbt.Spanning(0, 64)) {
			p := drawPrefix(tc, hegel.Draw(tc, hegel.SampledFrom([]Family{Inet, Inet6})), 0)
			if !slices.Contains(t.Prefixes, p) {
				t.Prefixes = append(t.Prefixes, p)
			}
		}
		tables = append(tables, t)
	}
	var rules []Rule
	for i := range hegel.Draw(tc, pbt.Spanning(1, 6)) {
		r := Rule{
			Action: hegel.Draw(tc, hegel.SampledFrom([]Action{Pass, Block})),
			Quick:  hegel.Draw(tc, hegel.Booleans()),
			Family: hegel.Draw(tc, hegel.SampledFrom([]Family{AnyFamily, Inet, Inet6})),
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			r.Interface = hegel.Draw(tc, hegel.SampledFrom([]string{"lo0", "en0", "utun9", "utun250", "bridge100"}))
			r.NotInterface = hegel.Draw(tc, hegel.Booleans())
		}
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 1:
			if len(tables) != 0 {
				r.From.Table = hegel.Draw(tc, hegel.SampledFrom(tables)).Name
			}
		case 2:
			if r.Family == AnyFamily {
				r.Family = hegel.Draw(tc, hegel.SampledFrom([]Family{Inet, Inet6}))
			}
			r.From.Prefix = drawPrefix(tc, r.Family, 1)
		}
		head := fmt.Sprintf("%d ", i)
		r.Label = head + hegel.Draw(tc, hegel.Text().Alphabet(labelText).MinSize(1).MaxSize(63-len(head)))
		rules = append(rules, r)
	}
	// pfctl loads only the tables a rule names, and the renderer refuses the rest
	named := slices.DeleteFunc(tables, func(t Table) bool {
		return !slices.ContainsFunc(rules, func(r Rule) bool { return r.From.Table == t.Name })
	})
	return Ruleset{Tables: named, Rules: rules}
}

// printedBack gives pfctl's readback of an anchor loaded with text, in the
// form the goldens show: each rule verbatim after its number, its table
// references carrying their entry counts, followed by its counter lines, and
// each table's flags and entries, the entries in an order other than the
// rendering's
func printedBack(t *hegel.T, text string, counters func(i int) uint64) (rules, tables string, shows map[string]string) {
	var r, tb strings.Builder
	shows = make(map[string]string)
	counts := make(map[string]int)
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(line, "table <") {
			continue
		}
		name, rest, _ := strings.Cut(strings.TrimPrefix(line, "table <"), ">")
		flags := "--a-r-"
		if strings.HasPrefix(rest, " const ") {
			flags = "c-a-r-"
		}
		inner := strings.TrimSpace(rest[strings.Index(rest, "{")+1 : strings.LastIndex(rest, "}")])
		var entries []string
		if inner != "" {
			entries = strings.Split(inner, ", ")
		}
		slices.Reverse(entries)
		var show strings.Builder
		for _, e := range entries {
			show.WriteString("   " + e + "\n")
		}
		shows[name], counts[name] = show.String(), len(entries)
		fmt.Fprintf(&tb, "%s\t%s\tcom.apple/ranet3\n\tAddresses:   %d\n", flags, name, len(entries))
	}
	i := 0
	for line := range strings.SplitSeq(strings.TrimSpace(text), "\n") {
		if strings.HasPrefix(line, "table <") {
			continue
		}
		for name, n := range counts {
			line = strings.ReplaceAll(line, "<"+name+">", fmt.Sprintf("<%s:%d>", name, n))
		}
		fmt.Fprintf(&r, "@%d %s\n  [ Owner : nil          Priority : 0     ]\n", i, line)
		fmt.Fprintf(&r, "  [ Evaluations: %d         Packets: %d         Bytes: %d           States: 0     ]\n", counters(3*i), counters(3*i+1), counters(3*i+2))
		r.WriteString("  [ Inserted: uid 0 pid 4242 ]\n")
		i++
	}
	if i == 0 {
		t.Fatal("the rendering holds no rule")
	}
	return r.String(), tb.String(), shows
}

// an anchor rendered, loaded and read back is the anchor drawn, with each
// rule's counters as pfctl printed them
func TestRenderingReadsBackAsTheModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rs := hegel.Draw(ht, hegel.Composite(drawRuleset))
		if refusedForTheScope(ht, rs) {
			return
		}
		text, err := rs.Render()
		if err != nil {
			ht.Fatalf("a drawn anchor is refused: %v\n%+v", err, rs)
		}
		counters := func(i int) uint64 { return uint64(i) * 1000003 }
		rulesOut, tablesOut, shows := printedBack(ht, text, counters)
		rules, err := ParseRules(rulesOut)
		if err != nil {
			ht.Fatalf("%v\n%s", err, rulesOut)
		}
		tables, err := ParseTables(tablesOut)
		if err != nil {
			ht.Fatal(err)
		}
		for i := range tables {
			if tables[i].Prefixes, err = ParseTableShow(shows[tables[i].Name]); err != nil {
				ht.Fatal(err)
			}
		}
		got := Readback{Rules: rules, Tables: tables}
		if !got.Ruleset().Equal(rs) {
			ht.Fatalf("rendered as\n%s\nit reads back as\n%+v\nnot\n%+v", text, got.Ruleset(), rs)
		}
		for i, c := range rules {
			if c.Packets != counters(3*i+1) || c.Bytes != counters(3*i+2) {
				ht.Fatalf("rule %d reads counters %+v", i, c)
			}
		}
	})
}

// no two rules of an anchor share a label, so each counter pfctl reads back
// belongs to one rule: a drawn anchor renders, and the same anchor with one
// rule's label copied onto another is refused
func TestLabelsAreUniqueWithinAnAnchor(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rs := hegel.Draw(ht, hegel.Composite(drawRuleset))
		if refusedForTheScope(ht, rs) {
			return
		}
		if _, err := rs.Render(); err != nil {
			ht.Fatalf("a drawn anchor is refused: %v", err)
		}
		if len(rs.Rules) < 2 {
			return
		}
		from := hegel.Draw(ht, hegel.Integers(0, len(rs.Rules)-1))
		to := hegel.Draw(ht, hegel.Integers(0, len(rs.Rules)-2))
		if to >= from {
			to++
		}
		rs.Rules[to].Label = rs.Rules[from].Label
		if text, err := rs.Render(); err == nil {
			ht.Fatalf("rules %d and %d share label %q and render\n%s", from, to, rs.Rules[from].Label, text)
		}
	})
}
