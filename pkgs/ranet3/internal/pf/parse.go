// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Counted is a rule as pfctl -sr -vv prints it, with what it has matched
// since it was loaded
type Counted struct {
	Rule    Rule
	Packets uint64
	Bytes   uint64
}

// Readback is an anchor's rules and tables as pfctl reads them back
type Readback struct {
	Rules  []Counted
	Tables []Table
}

// Ruleset gives the readback's rules and tables without the counters
func (rb Readback) Ruleset() Ruleset {
	rs := Ruleset{Tables: rb.Tables}
	for _, c := range rb.Rules {
		rs.Rules = append(rs.Rules, c.Rule)
	}
	return rs
}

// Equal reports whether rs and other hold the same rules in the same order and
// the same tables, a table's prefixes and the tables themselves in any order
func (rs Ruleset) Equal(other Ruleset) bool {
	if !slices.Equal(rs.Rules, other.Rules) || len(rs.Tables) != len(other.Tables) {
		return false
	}
	for _, t := range rs.Tables {
		i := slices.IndexFunc(other.Tables, func(o Table) bool { return o.Name == t.Name })
		if i < 0 || other.Tables[i].Const != t.Const || !samePrefixes(t.Prefixes, other.Tables[i].Prefixes) {
			return false
		}
	}
	return true
}

func samePrefixes(a, b []netip.Prefix) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.SortFunc(a, comparePrefixes)
	slices.SortFunc(b, comparePrefixes)
	return slices.Equal(a, b)
}

// ParseRules reads pfctl -sr -vv: each rule on a line of its own after its
// number, then bracketed lines of which the one carrying Evaluations gives the
// counters
func ParseRules(out string) ([]Counted, error) {
	var rules []Counted
	for line := range strings.SplitSeq(out, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
		case strings.HasPrefix(line, "@"):
			number, text, ok := strings.Cut(line[1:], " ")
			if _, err := strconv.Atoi(number); !ok || err != nil {
				return nil, fmt.Errorf("pf: a rule line with no number: %q", line)
			}
			rule, err := ParseRule(text)
			if err != nil {
				return nil, err
			}
			rules = append(rules, Counted{Rule: rule})
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			if len(rules) == 0 {
				return nil, fmt.Errorf("pf: a counter line before any rule: %q", line)
			}
			if err := rules[len(rules)-1].count(trimmed); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pf: a line pfctl -sr -vv printed that is no rule: %q", line)
		}
	}
	return rules, nil
}

// count reads "[ Evaluations: 0 Packets: 0 Bytes: 0 States: 0 ]" and leaves
// the other bracketed lines alone
func (c *Counted) count(line string) error {
	fields := strings.Fields(strings.Trim(line, "[] "))
	if len(fields) == 0 || fields[0] != "Evaluations:" {
		return nil
	}
	targets := map[string]*uint64{"Packets:": &c.Packets, "Bytes:": &c.Bytes}
	for i := 0; i+1 < len(fields); i += 2 {
		target, ok := targets[fields[i]]
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(fields[i+1], 10, 64)
		if err != nil {
			return fmt.Errorf("pf: counter %s %q: %w", fields[i], fields[i+1], err)
		}
		*target = n
	}
	return nil
}

// ParseRule reads one rule in the form Rule.String writes, the form pfctl -sr
// prints, a table reference carrying pfctl -vv's count included
func ParseRule(line string) (Rule, error) {
	var r Rule
	text, label, labeled := strings.Cut(line, ` label "`)
	if labeled {
		if !strings.HasSuffix(label, `"`) || strings.Count(label, `"`) != 1 {
			return Rule{}, fmt.Errorf("pf: a label that does not end the rule: %q", line)
		}
		r.Label = strings.TrimSuffix(label, `"`)
	}
	words := strings.Fields(text)
	next := func() string {
		if len(words) == 0 {
			return ""
		}
		w := words[0]
		words = words[1:]
		return w
	}
	take := func(w string) bool {
		if len(words) > 0 && words[0] == w {
			words = words[1:]
			return true
		}
		return false
	}
	fail := func(what string) (Rule, error) {
		return Rule{}, fmt.Errorf("pf: %s in %q", what, line)
	}
	// the filter writes a pass and a block drop of packets in alone, never a
	// block that does not drop or a rule for packets out
	switch {
	case take("pass"):
		r.Action = Pass
	case take("block") && take("drop"):
		r.Action = Block
	default:
		return fail("an action other than pass or block drop")
	}
	if !take("in") {
		return fail("a direction other than in")
	}
	r.Quick = take("quick")
	if take("on") {
		r.NotInterface = take("!")
		if r.Interface = next(); r.Interface == "" {
			return fail("no interface")
		}
	}
	switch {
	case take("inet"):
		r.Family = Inet
	case take("inet6"):
		r.Family = Inet6
	}
	if !take("all") {
		if !take("from") {
			return fail("no from")
		}
		var err error
		if r.From, err = parseAddress(next()); err != nil {
			return fail(err.Error())
		}
		// the filter's rules match any destination
		if !take("to") || !take("any") {
			return fail("a destination other than any")
		}
	}
	// a pass keeping state would let a flow's later packets through on the
	// state alone, past every rule, so the filter writes none
	if r.Action == Pass && (!take("no") || !take("state")) {
		return fail("a pass that keeps state")
	}
	if len(words) > 0 {
		return fail(fmt.Sprintf("%q past the addresses", words))
	}
	return r, nil
}

// parseAddress reads a source the filter writes, a table or a prefix, never a
// negated one
func parseAddress(word string) (Address, error) {
	switch {
	case word == "any":
		return Address{}, nil
	case strings.HasPrefix(word, "<") && strings.HasSuffix(word, ">"):
		name, count, counted := strings.Cut(word[1:len(word)-1], ":")
		if _, err := strconv.ParseUint(count, 10, 64); counted && err != nil {
			return Address{}, fmt.Errorf("table reference %q", word)
		}
		return Address{Table: name}, nil
	}
	p, err := parsePrefix(word)
	if err != nil {
		return Address{}, fmt.Errorf("an address %q that is no table or prefix", word)
	}
	return Address{Prefix: p}, nil
}

// parsePrefix reads a prefix as pfctl prints one, a host prefix as its bare
// address
func parsePrefix(word string) (netip.Prefix, error) {
	if strings.Contains(word, "/") {
		return netip.ParsePrefix(word)
	}
	a, err := netip.ParseAddr(word)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseTables reads pfctl -s Tables -vv: each table on a line of flags, its
// name and its anchor, separated by tabs, the first flag c when the table is
// const, then counters on lines opening with a tab. The prefixes are left
// empty, since pfctl -T show gives them.
func ParseTables(out string) ([]Table, error) {
	var tables []Table
	for line := range strings.SplitSeq(out, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "\t") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 || fields[0] == "" || fields[1] == "" {
			return nil, fmt.Errorf("pf: a line pfctl -s Tables -vv printed that is no table: %q", line)
		}
		tables = append(tables, Table{Name: fields[1], Const: fields[0][0] == 'c'})
	}
	return tables, nil
}

// ParseTableShow reads pfctl -T show, one prefix to a line
func ParseTableShow(out string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for line := range strings.SplitSeq(out, "\n") {
		word := strings.TrimSpace(line)
		if word == "" {
			continue
		}
		p, err := parsePrefix(word)
		if err != nil {
			return nil, fmt.Errorf("pf: a table entry pfctl -T show printed: %w", err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// ParseCalls reports whether the main ruleset pfctl -sr prints calls anchor
// for filtering every packet in on every interface in both families: a line
// of the anchor rule with all alone, or with in and all. pf skips an anchor
// rule whose direction, interface, family, protocol or addresses a packet does
// not match before it steps in (bsd_net_pf.c:5272-5348), so a call that names
// any of them leaves packets out of the anchor, and a scrub-anchor line calls
// it for normalization alone. Only a line at the main ruleset's own depth
// counts, one with no leading space outside every inline anchor's braces:
// pfctl prints an unnamed inline anchor's rules indented between its line
// ending in { and a line of }, and pf resolves a relative call inside it
// relative to that inline anchor (bsd_net_pf_ruleset.c:494-519), so such a
// call never reaches anchor.
func ParseCalls(out, anchor string) bool {
	call := `"` + anchor + `"`
	depth := 0
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		top := depth == 0 && line == strings.TrimLeft(line, " \t")
		switch {
		case len(fields) != 0 && fields[len(fields)-1] == "{":
			depth++
		case slices.Equal(fields, []string{"}"}):
			depth = max(depth-1, 0)
		case top && (slices.Equal(fields, []string{"anchor", call, "all"}) || slices.Equal(fields, []string{"anchor", call, "in", "all"})):
			return true
		}
	}
	return false
}

// ParseSkipped reads the interfaces pfctl -s Interfaces -v prints as skipped,
// which it marks with (skip) after the name. pf passes a packet on a skipped
// interface before any rule (bsd_net_pf.c:9756, :10361). A set skip on a name
// with no trailing digit, such as en, marks every interface whose name is it
// followed by a unit number (pfi_skip_if, bsd_net_pf_if.c:714-737), and pfctl
// lists the name too, so a name with no trailing digit is left out.
func ParseSkipped(out string) []string {
	var skipped []string
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "(skip)" && strings.ContainsAny(fields[0][len(fields[0])-1:], "0123456789") {
			skipped = append(skipped, fields[0])
		}
	}
	return skipped
}

// ParseRunning reads whether pf is enabled from the Status line pfctl -s info
// prints
func ParseRunning(out string) (bool, error) {
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "Status:" {
			continue
		}
		switch fields[1] {
		case "Enabled":
			return true, nil
		case "Disabled":
			return false, nil
		}
		return false, fmt.Errorf("pf: a status pfctl -s info printed: %q", line)
	}
	return false, errors.New("pf: pfctl -s info printed no status")
}

// Enabler is one reference pfctl -s References lists, by the process that
// took it, as the filter's status and its debug read carry it
type Enabler struct {
	PID   int
	Name  string
	Token uint64
}

// ParseReferences reads pfctl -s References: a header, then per reference its
// pid, its process's name, its token and when it was taken
func ParseReferences(out string) ([]Enabler, error) {
	var enablers []Enabler
	for line := range strings.SplitSeq(out, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0, line == "TOKENS:", line == "No pf starter references held", fields[0] == "PID":
			continue
		case len(fields) < 6 || fields[len(fields)-2] != "days":
			return nil, fmt.Errorf("pf: a line pfctl -s References printed that is no reference: %q", line)
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			return nil, fmt.Errorf("pf: a reference's pid %q: %w", fields[0], err)
		}
		// the token, then the age as "<days> days <hh:mm:ss>"
		token, err := strconv.ParseUint(fields[len(fields)-4], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("pf: a reference's token %q: %w", fields[len(fields)-4], err)
		}
		enablers = append(enablers, Enabler{PID: pid, Name: strings.Join(fields[1:len(fields)-4], " "), Token: token})
	}
	return enablers, nil
}
