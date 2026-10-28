// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// golden reads pfctl's output as it printed it on a Mac running Darwin 27.2.0,
// for the anchor sample loads
func golden(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

// sample is the part of the anchor the goldens were read from that the filter
// writes, its overlay table written with an uncompressed IPv6 prefix that
// pfctl printed back compressed: the stateless pass in on lo0 and the two
// drops in from a prefix on every interface but the utun. The anchor's fourth
// rule, a drop out of the utun from outside a table, and the two tables only it
// names, are of a form the filter does not write.
var sample = Ruleset{
	Tables: []Table{
		{Name: "ranet3_overlay", Const: true, Prefixes: prefixes("3fff:0010:0000::/32", "192.0.2.0/24")},
	},
	Rules: []Rule{
		{Action: Pass, Quick: true, Interface: "lo0", From: Address{Table: "ranet3_overlay"}, Label: "accept via lo0"},
		{Action: Block, Quick: true, Interface: "utun250", NotInterface: true, Family: Inet,
			From: Address{Prefix: netip.MustParsePrefix("192.0.2.0/24")}, Label: "drop ipv4 source 192.0.2.0/24"},
		{Action: Block, Quick: true, Interface: "utun250", NotInterface: true, Family: Inet6,
			From: Address{Prefix: netip.MustParsePrefix("3fff:10::/32")}, Label: "drop ipv6 source 3fff:10::/32"},
	},
}

// sampled reports whether the sample holds the table name
func sampled(name string) bool {
	return slices.ContainsFunc(sample.Tables, func(t Table) bool { return t.Name == name })
}

// sampleRules is pfctl -sr -vv's readback of the sample's rules, the golden's
// first three
func sampleRules(t *testing.T) string {
	t.Helper()
	out := golden(t, "sr-vv.txt")
	at := strings.Index(out, "@3 ")
	if at < 0 {
		t.Fatal("sr-vv.txt holds no fourth rule")
	}
	return out[:at]
}

// the rendering is pfctl's own form: each rule line as pfctl -sr printed it,
// and each table with the flags pfctl -s Tables -vv gave it and its entries
// in the order and form pfctl -T show printed them
func TestRenderingIsWhatPfctlPrintsBack(t *testing.T) {
	text, err := sample.Render()
	if err != nil {
		t.Fatal(err)
	}
	tables, err := ParseTables(golden(t, "tables-vv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, table := range tables {
		if !sampled(table.Name) {
			continue
		}
		line := "table <" + table.Name + ">"
		if table.Const {
			line += " const"
		}
		var entries []string
		for entry := range strings.SplitSeq(strings.TrimSpace(golden(t, "show-"+strings.TrimPrefix(table.Name, "ranet3_")+".txt")), "\n") {
			entries = append(entries, strings.TrimSpace(entry))
		}
		want = append(want, line+" { "+strings.Join(entries, ", ")+" }")
	}
	for line := range strings.SplitSeq(strings.TrimSpace(golden(t, "sr.txt")), "\n") {
		if strings.HasPrefix(line, "pass in ") || strings.HasPrefix(line, "block drop in ") {
			want = append(want, line)
		}
	}
	if got := strings.Split(strings.TrimSpace(text), "\n"); !slices.Equal(got, want) {
		t.Errorf("the rendering\n%s\nis not what pfctl printed back\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// a table entry of one address renders bare, as pfctl -T show printed an
// earlier probe's table of 192.0.2.1, 198.51.100.0/24 and 3fff:10::1, since
// the carved table holds one address where a carve-out is one
func TestHostEntryRendersAsPfctlPrintsIt(t *testing.T) {
	var entries []string
	for entry := range strings.SplitSeq(strings.TrimSpace(golden(t, "show-owned.txt")), "\n") {
		entries = append(entries, strings.TrimSpace(entry))
	}
	table := Table{Name: "ranet3_carved", Const: true, Prefixes: prefixes("3fff:10::1/128", "198.51.100.0/24", "192.0.2.1/32")}
	if got, want := table.String(), "table <ranet3_carved> const { "+strings.Join(entries, ", ")+" }"; got != want {
		t.Errorf("%v renders %q, want %q", table.Prefixes, got, want)
	}
}

// what pfctl printed for the sample parses back as the sample
func TestPfctlsReadbackParsesAsTheSample(t *testing.T) {
	rules, err := ParseRules(sampleRules(t))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := ParseTables(golden(t, "tables-vv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var tables []Table
	for _, table := range listed {
		if !sampled(table.Name) {
			continue
		}
		name := strings.TrimPrefix(table.Name, "ranet3_")
		if table.Prefixes, err = ParseTableShow(golden(t, "show-"+name+".txt")); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	got := Readback{Rules: rules, Tables: tables}.Ruleset()
	if !got.Equal(sample) {
		t.Errorf("pfctl's readback parses as\n%+v\nnot the sample\n%+v", got, sample)
	}
	for _, c := range rules {
		if c.Packets != 0 || c.Bytes != 0 {
			t.Errorf("rule %q read counters %+v from a rule nothing had matched", c.Rule.Label, c)
		}
	}

	empty, err := ParseTables(golden(t, "tables-vv-empty.txt"))
	if want := []Table{{Name: "ranet3_none", Const: true}}; err != nil || !slices.EqualFunc(empty, want, func(a, b Table) bool { return a.Name == b.Name && a.Const == b.Const }) {
		t.Errorf("an empty const table parses as %+v (%v), want %+v", empty, err, want)
	}
}

// an IPv4-compatible IPv6 address, whose first 96 bits are zero, renders as
// netip writes it, and pfctl's print of it, its last 32 bits dotted as
// inet_ntop writes them, parses back as the same address, so one reads back as
// written in a table and as a rule's source
func TestIPv4CompatibleAddressReadsBackAsWritten(t *testing.T) {
	rs := Ruleset{
		Tables: []Table{{Name: "ranet3_overlay", Const: true, Prefixes: prefixes("192.0.2.1/32", "::c000:201/128")}},
		Rules: []Rule{
			{Action: Pass, Quick: true, Interface: "lo0", From: Address{Table: "ranet3_overlay"}, Label: "accept via lo0"},
			{Action: Block, Quick: true, Interface: "utun7", NotInterface: true, Family: Inet6,
				From: Address{Prefix: netip.MustParsePrefix("::c000:201/128")}, Label: "drop ipv6 source ::c000:201/128"},
		},
	}
	text, err := rs.Render()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(text, "::c000:201") != 3 {
		t.Errorf("the rendering writes the address otherwise:\n%s", text)
	}
	rules, err := ParseRules("@0 pass in quick on lo0 from <ranet3_overlay:2> to any no state label \"accept via lo0\"\n" +
		"  [ Evaluations: 0         Packets: 0         Bytes: 0           States: 0     ]\n" +
		"@1 block drop in quick on ! utun7 inet6 from ::192.0.2.1 to any label \"drop ipv6 source ::c000:201/128\"\n" +
		"  [ Owner : nil          Priority : 0     ]\n" +
		"  [ Evaluations: 0         Packets: 0         Bytes: 0           States: 0     ]\n" +
		"  [ Inserted: uid 0 pid 7 ]\n")
	if err != nil {
		t.Fatal(err)
	}
	tables, err := ParseTables("c-a-r-\tranet3_overlay\tcom.apple/ranet3\n\tAddresses:   2\n")
	if err != nil || len(tables) != 1 {
		t.Fatalf("the table listing parses as %+v (%v)", tables, err)
	}
	if tables[0].Prefixes, err = ParseTableShow("   192.0.2.1\n   ::192.0.2.1\n"); err != nil {
		t.Fatal(err)
	}
	if got := (Readback{Rules: rules, Tables: tables}).Ruleset(); !got.Equal(rs) {
		t.Errorf("pfctl's print parses as\n%+v\nnot as written\n%+v", got, rs)
	}
}

// a rule's counters come from its Evaluations line, whatever the other
// bracketed lines say
func TestCountersAreReadFromTheEvaluationsLine(t *testing.T) {
	out := "@0 block drop in quick on ! utun9 inet from 192.0.2.0/24 to any label \"drop ipv4 source 192.0.2.0/24\"\n" +
		"  [ Owner : nil          Priority : 0     ]\n" +
		"  [ Evaluations: 41        Packets: 3         Bytes: 252         States: 0     ]\n" +
		"  [ Inserted: uid 0 pid 7 ]\n"
	rules, err := ParseRules(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Packets != 3 || rules[0].Bytes != 252 {
		t.Errorf("read %+v, want 3 packets and 252 bytes", rules)
	}
}

// a rule of a form the filter does not write is refused by the parser,
// naming the rule, so an anchor holding one reads as unreadable, never as a
// rule of another meaning: the sample anchor's fourth rule as pfctl printed it,
// a drop out of the utun from outside a table, then a stateful pass, a pass
// and a drop of packets out each in the filter's forms, a drop that returns, a
// drop from a negated prefix or toward a destination, and a block or pass
// naming no source but a negated table
func TestRuleTheFilterDoesNotWriteIsRefused(t *testing.T) {
	var lines []string
	for line := range strings.SplitSeq(golden(t, "sr-vv.txt"), "\n") {
		if number, text, ok := strings.Cut(line, " "); ok && number == "@3" {
			lines = append(lines, text)
		}
	}
	if len(lines) != 1 {
		t.Fatalf("sr-vv.txt holds %d fourth rules", len(lines))
	}
	lines = append(lines,
		`pass in quick on en0 inet from 192.0.2.128/25 to any flags S/SA keep state label "kept"`,
		`pass in quick on en0 inet from 192.0.2.128/25 to any label "kept by default"`,
		`pass out quick on en0 inet from 192.0.2.128/25 to any no state label "a pass out"`,
		`block drop out quick on ! utun7 inet from 192.0.2.0/24 to any label "a drop out"`,
		`block return in quick on ! utun7 inet from 192.0.2.0/24 to any label "returned"`,
		`block drop in quick on ! utun7 inet from ! 192.0.2.0/24 to any label "negated"`,
		`block drop in quick on ! utun7 inet from 192.0.2.0/24 to 198.51.100.0/24 label "toward"`,
		`block drop in quick on ! utun7 inet from ! <ranet3_carved:1> to any label "negated table"`,
		`block drop in quick on ! utun7 inet from (en0) to any label "an interface's address"`,
		`pass in quick on lo0 from <ranet3_overlay:2> to any no state tagged mesh label "tagged"`,
	)
	for i, line := range lines {
		out := fmt.Sprintf("@%d %s\n  [ Evaluations: 0         Packets: 0         Bytes: 0           States: 0     ]\n", i, line)
		// the error quotes the line, its label's quotes escaped
		head, _, _ := strings.Cut(line, ` label "`)
		if rules, err := ParseRules(out); err == nil || !strings.Contains(err.Error(), head) {
			t.Errorf("%q parses as %+v (%v), want a refusal naming it", line, rules, err)
		}
	}
}

// the main ruleset's call into com.apple and the references, as pfctl printed
// them. The stock call reads as called, and so does it with in, while a
// scrub-anchor line, another anchor, the call with any word more, which
// limits the packets it evaluates the anchor for, and the call indented or
// inside an inline anchor's braces read as no call, while one after a closing
// brace reads as the call. The darwin root test
// TestPfMainCallReadsAsPfEvaluatesIt reads each limited form and the inline
// one as pfctl prints it.
func TestPfctlsCallsAndReferencesParse(t *testing.T) {
	if !ParseCalls(golden(t, "main-sr.txt"), "com.apple/*") {
		t.Error("the stock main ruleset reads as not calling com.apple/*")
	}
	if !ParseCalls("anchor \"com.apple/*\" in all\n", "com.apple/*") {
		t.Error("the call for every packet in reads as no call")
	}
	if !ParseCalls("anchor in all {\n  pass in all no state\n}\nanchor \"com.apple/*\" all\n", "com.apple/*") {
		t.Error("the call after an inline anchor's closing brace reads as no call")
	}
	for _, line := range []string{
		"scrub-anchor \"com.apple/*\" all fragment reassemble",
		"anchor \"com.apple/ranet3\" all",
		"anchor \"com.apple/*\" out all",
		"anchor \"com.apple/*\" on en0 all",
		"anchor \"com.apple/*\" in on en0 all",
		"anchor \"com.apple/*\" inet all",
		"anchor \"com.apple/*\" inet6 all",
		"anchor \"com.apple/*\" proto tcp all",
		"anchor \"com.apple/*\" inet from 192.0.2.0/24 to any",
		"anchor \"com.apple/*\" all tagged mesh",
		// a call inside an unnamed inline anchor, as pfctl prints one
		// indented between the anchor's { and }, resolves relative to it
		"anchor in all {\n  anchor \"com.apple/*\" all\n}",
		"anchor all {\n  anchor \"com.apple/*\" all\n}",
		"anchor all {\n  anchor in all {\n    anchor \"com.apple/*\" all\n  }\n}",
		"  anchor \"com.apple/*\" all",
	} {
		if ParseCalls(line+"\n", "com.apple/*") {
			t.Errorf("%q reads as the filter's call", line)
		}
	}
	// pfctl -s Interfaces -v prints each name and (skip) after a skipped one,
	// a name a set skip names with no unit number among them, which
	// TestPfBorderStartRefusesASkippedLink reads from pfctl
	interfaces := "lo0 (skip)\nen0\nutun7 (skip)\nutun70\nen (skip)\nen1 (skip)\nen2\n"
	if got, want := ParseSkipped(interfaces), []string{"lo0", "utun7", "en1"}; !slices.Equal(got, want) {
		t.Errorf("%q reads skipped %q, want %q", interfaces, got, want)
	}
	enablers, err := ParseReferences(golden(t, "references.txt"))
	want := []Enabler{
		{PID: 57931, Name: "pfprobe.test", Token: 10568795862022687003},
		{PID: 57912, Name: "pfprobe.test", Token: 13143444398357651665},
	}
	if err != nil || !slices.Equal(enablers, want) {
		t.Errorf("the references parse as %+v (%v), want %+v", enablers, err, want)
	}
	if enablers, err := ParseReferences(golden(t, "references-none.txt")); err != nil || len(enablers) != 0 {
		t.Errorf("no references parse as %+v (%v)", enablers, err)
	}
}

// pfctl refuses a label of 64 bytes, so the renderer does first
func TestLabelPastSixtyThreeBytesIsRefused(t *testing.T) {
	rule := func(n int) Ruleset {
		return Ruleset{Rules: []Rule{{Action: Block, Quick: true, Label: strings.Repeat("x", n)}}}
	}
	if _, err := rule(63).Render(); err != nil {
		t.Errorf("a label of 63 bytes is refused: %v", err)
	}
	if _, err := rule(64).Render(); err == nil {
		t.Error("a label of 64 bytes renders")
	}
}

// pfctl's parse cleared the second group of fea3:d44e:4848::/45 (P10, read
// back as fea3:0:4848::/45) and of fe98:77c1:1669:90aa:5060:1c30:f1ba:c000/114
// (P11), as a table entry and as a rule's address alike, and P12 found the
// same throughout fe80::/10 and nowhere else: not at fe7f: or fec0:, nor in
// any multicast group. Such a prefix is refused in either place, naming what
// pf would hold, and a prefix in the range whose length leaves the second
// group zero is not.
func TestLinkLocalPrefixWithASecondGroupIsRefused(t *testing.T) {
	inTable := func(prefix string) Ruleset {
		return Ruleset{Tables: []Table{{Name: "t", Prefixes: prefixes(prefix)}},
			Rules: []Rule{{Action: Block, From: Address{Table: "t"}, Label: "x"}}}
	}
	inRule := func(prefix string) Ruleset {
		return Ruleset{Rules: []Rule{{Action: Block, Family: Inet6, From: Address{Prefix: netip.MustParsePrefix(prefix)}, Label: "x"}}}
	}
	for prefix, held := range map[string]string{
		"fea3:d44e:4848::/45":                         "fea3:0:4848::/45",
		"fe98:77c1:1669:90aa:5060:1c30:f1ba:c000/114": "fe98:0:1669:90aa:5060:1c30:f1ba:c000/114",
		"fe80:77c1:1669:90aa:5060:1c30:f1ba:c001/128": "fe80:0:1669:90aa:5060:1c30:f1ba:c001/128",
		"febf:77c1:1669:90aa::/64":                    "febf:0:1669:90aa::/64",
	} {
		if _, err := inTable(prefix).Render(); err == nil || !strings.Contains(err.Error(), held) {
			t.Errorf("%s as a table entry: %v, want a refusal naming %s", prefix, err, held)
		}
		if _, err := inRule(prefix).Render(); err == nil || !strings.Contains(err.Error(), held) {
			t.Errorf("%s as a rule's source: %v, want a refusal naming %s", prefix, err, held)
		}
	}
	for _, prefix := range []string{
		"fe7f:77c1:1669:90aa::/64", "fec0:77c1:1669:90aa::/64",
		"fe98::/16", "febf::/16", "fe80::/10", "fe80::/64", "fe80::1/128",
		"ff02:77c1::1/128", "ff32:77c1::/32", "ff01:77c1::/32",
		"2001:db8:77c1::/48",
	} {
		if _, err := inTable(prefix).Render(); err != nil {
			t.Errorf("%s as a table entry is refused: %v", prefix, err)
		}
		if _, err := inRule(prefix).Render(); err != nil {
			t.Errorf("%s as a rule's source is refused: %v", prefix, err)
		}
	}
}

// what would not read back as itself is refused before it reaches pfctl
func TestRulesetThatWouldNotReadBackIsRefused(t *testing.T) {
	block := func(label string) Rule {
		return Rule{Action: Block, Quick: true, Label: label}
	}
	onTable := func(name string) Rule {
		r := block("named")
		r.From = Address{Table: name}
		return r
	}
	from := func(family Family, prefix string) Ruleset {
		r := block("from")
		r.Family, r.From = family, Address{Prefix: netip.MustParsePrefix(prefix)}
		return Ruleset{Rules: []Rule{r}}
	}
	for _, c := range []struct {
		name string
		rs   Ruleset
	}{
		{"a table name of 32 bytes", Ruleset{Tables: []Table{{Name: strings.Repeat("t", 32)}}, Rules: []Rule{onTable(strings.Repeat("t", 32))}}},
		{"a table no rule names", Ruleset{Tables: []Table{{Name: "spare"}}, Rules: []Rule{block("a")}}},
		{"a rule naming a table not defined", Ruleset{Rules: []Rule{onTable("missing")}}},
		{"two rules under one label", Ruleset{Rules: []Rule{block("same"), block("same")}}},
		{"a rule with no label", Ruleset{Rules: []Rule{block("")}}},
		{"a label holding a quote", Ruleset{Rules: []Rule{block(`say "x"`)}}},
		{"a label holding a macro pfctl expands", Ruleset{Rules: []Rule{block("rule $nr")}}},
		{"a table entry with bits past its length", Ruleset{Tables: []Table{{Name: "t", Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}}}, Rules: []Rule{onTable("t")}}},
		{"a source with bits past its length", from(Inet, "192.0.2.1/24")},
		{"a source of length 0, which pfctl prints as any", from(Inet, "0.0.0.0/0")},
		{"a source of another family than the rule's", from(Inet, "3fff:10::/32")},
		{"a source with no family named", from(AnyFamily, "192.0.2.0/24")},
		{"a source both a table and a prefix", Ruleset{Tables: []Table{{Name: "t"}}, Rules: []Rule{{Action: Block, Family: Inet,
			From: Address{Table: "t", Prefix: netip.MustParsePrefix("192.0.2.0/24")}, Label: "x"}}}},
		{"a negated interface with no name", Ruleset{Rules: []Rule{{Action: Block, NotInterface: true, Label: "x"}}}},
		{"an interface name holding a dash", Ruleset{Rules: []Rule{{Action: Block, Interface: "br-lan", Label: "x"}}}},
		{"an interface name of 16 bytes", Ruleset{Rules: []Rule{{Action: Block, Interface: strings.Repeat("i", 16), Label: "x"}}}},
		{"no action", Ruleset{Rules: []Rule{{Label: "x"}}}},
	} {
		if _, err := c.rs.Render(); err == nil {
			t.Errorf("%s renders", c.name)
		}
	}
}
