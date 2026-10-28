// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Render writes rs as pfctl -f reads it, each rule in the form pfctl -sr prints
// it back and each table's prefixes in the order and form pfctl -T show prints
// them. It refuses a ruleset that would not read back as itself.
func (rs Ruleset) Render() (string, error) {
	if err := rs.check(); err != nil {
		return "", err
	}
	var b strings.Builder
	for _, t := range rs.Tables {
		b.WriteString(t.String())
		b.WriteByte('\n')
	}
	for _, r := range rs.Rules {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// String is the table's definition, its prefixes sorted as pfctl prints them
func (t Table) String() string {
	var b strings.Builder
	b.WriteString("table <" + t.Name + ">")
	if t.Const {
		b.WriteString(" const")
	}
	b.WriteString(" {")
	prefixes := slices.Clone(t.Prefixes)
	slices.SortFunc(prefixes, comparePrefixes)
	for i, p := range prefixes {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(" " + formatPrefix(p))
	}
	b.WriteString(" }")
	return b.String()
}

// String is the rule as pfctl -sr prints it, a pass with no state
func (r Rule) String() string {
	words := []string{"block", "drop", "in"}
	if r.Action == Pass {
		words = []string{"pass", "in"}
	}
	if r.Quick {
		words = append(words, "quick")
	}
	if r.Interface != "" {
		words = append(words, "on")
		if r.NotInterface {
			words = append(words, "!")
		}
		words = append(words, r.Interface)
	}
	switch r.Family {
	case Inet:
		words = append(words, "inet")
	case Inet6:
		words = append(words, "inet6")
	}
	if r.From.Any() {
		words = append(words, "all")
	} else {
		words = append(words, "from", r.From.String(), "to", "any")
	}
	if r.Action == Pass {
		words = append(words, "no", "state")
	}
	return strings.Join(words, " ") + ` label "` + r.Label + `"`
}

// String is the address as a rule writes it
func (a Address) String() string {
	switch {
	case a.Table != "":
		return "<" + a.Table + ">"
	case a.Prefix.IsValid():
		return formatPrefix(a.Prefix)
	}
	return "any"
}

// comparePrefixes orders IPv4 before IPv6, then by address, which is the
// order pfctl -T show walks a table in
func comparePrefixes(a, b netip.Prefix) int {
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// formatPrefix writes a host prefix as its bare address, as pfctl prints one
func formatPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}

func (rs Ruleset) check() error {
	tables := make(map[string]bool, len(rs.Tables))
	for _, t := range rs.Tables {
		if err := t.check(); err != nil {
			return err
		}
		if tables[t.Name] {
			return fmt.Errorf("pf: table <%s> is defined twice", t.Name)
		}
		tables[t.Name] = false
	}
	labels := make(map[string]bool, len(rs.Rules))
	for _, r := range rs.Rules {
		if err := r.check(); err != nil {
			return fmt.Errorf("pf: rule %q: %w", r.Label, err)
		}
		if labels[r.Label] {
			return fmt.Errorf("pf: two rules carry the label %q, so their counters cannot be told apart", r.Label)
		}
		labels[r.Label] = true
		if r.From.Table != "" {
			if _, ok := tables[r.From.Table]; !ok {
				return fmt.Errorf("pf: rule %q names table <%s>, which the ruleset does not define", r.Label, r.From.Table)
			}
			tables[r.From.Table] = true
		}
	}
	for _, t := range rs.Tables {
		if !tables[t.Name] {
			return fmt.Errorf("pf: table <%s> is defined and no rule names it", t.Name)
		}
	}
	return nil
}

func (t Table) check() error {
	// PF_TABLE_NAME_SIZE less its terminator, bsd/net/pfvar.h
	if err := checkName(t.Name, 31); err != nil {
		return fmt.Errorf("pf: table name %q: %w", t.Name, err)
	}
	seen := make(map[netip.Prefix]bool, len(t.Prefixes))
	for _, p := range t.Prefixes {
		if err := CheckPrefix(p); err != nil {
			return fmt.Errorf("pf: table <%s>: %w", t.Name, err)
		}
		if seen[p] {
			return fmt.Errorf("pf: table <%s> holds %s twice", t.Name, p)
		}
		seen[p] = true
	}
	return nil
}

func (r Rule) check() error {
	if r.Action != Pass && r.Action != Block {
		return fmt.Errorf("action %d", r.Action)
	}
	if r.Interface != "" {
		if err := CheckInterface(r.Interface); err != nil {
			return fmt.Errorf("interface %q: %w", r.Interface, err)
		}
	} else if r.NotInterface {
		return errors.New("a negated interface with no name")
	}
	if r.Family > Inet6 {
		return fmt.Errorf("family %d", r.Family)
	}
	if err := r.From.check(r.Family); err != nil {
		return err
	}
	// PF_RULE_LABEL_SIZE less its terminator, bsd/net/pfvar.h, which pfctl
	// refuses past as "rule label too long (max 63 chars)"
	if r.Label == "" || len(r.Label) > 63 {
		return fmt.Errorf("a label of %d bytes, where pf holds 1 to 63", len(r.Label))
	}
	// pfctl expands $if, $srcaddr, $nr and the other label macros of
	// pf.conf(5) when it parses a label
	for _, c := range r.Label {
		if c < ' ' || c > '~' || c == '"' || c == '\\' || c == '$' {
			return fmt.Errorf("the label holds %q, which pfctl would not print back as written", c)
		}
	}
	return nil
}

// check refuses a source that pfctl would print back as another: a prefix of
// length 0, which it prints as any, and one whose family the rule does not
// name, since pfctl sets the rule's family from its address
func (a Address) check(family Family) error {
	if !a.Prefix.IsValid() {
		return nil
	}
	want := Inet
	if a.Prefix.Addr().Is6() {
		want = Inet6
	}
	switch {
	case a.Table != "":
		return fmt.Errorf("a source of table <%s> and prefix %s at once", a.Table, a.Prefix)
	case a.Prefix.Bits() == 0:
		return fmt.Errorf("prefix %s, which pfctl prints as any", a.Prefix)
	case family != want:
		return fmt.Errorf("prefix %s under family %d", a.Prefix, family)
	}
	return CheckPrefix(a.Prefix)
}

// CheckPrefix refuses a prefix that pf would not hold as written as a table's
// entry or a rule's address
func CheckPrefix(p netip.Prefix) error {
	if !p.IsValid() || p.Addr().Zone() != "" {
		return fmt.Errorf("prefix %s is not a prefix pf holds", p)
	}
	if p != p.Masked() {
		return fmt.Errorf("prefix %s has bits set past its length, which pfctl masks off", p)
	}
	// pfctl's parse clears the second group of an address in fe80::/10, where
	// a BSD kernel keeps a link-local address's zone, and pf then holds and
	// matches the cleared prefix. A masked prefix of length 16 or less has a
	// zero second group, and so does every real link-local prefix.
	if a := p.Addr().As16(); p.Addr().Is6() && a[0] == 0xfe && a[1]&0xc0 == 0x80 && (a[2] != 0 || a[3] != 0) {
		return fmt.Errorf("prefix %s is in fe80::/10 with a nonzero second group, which pfctl clears, so pf would hold %s", p, clearSecondGroup(p))
	}
	return nil
}

// CheckInterface refuses an interface name a rule cannot carry as written
func CheckInterface(name string) error {
	// IFNAMSIZ less its terminator, bsd/net/if.h
	return checkName(name, 15)
}

// clearSecondGroup is p as pfctl parses a prefix in fe80::/10
func clearSecondGroup(p netip.Prefix) netip.Prefix {
	a := p.Addr().As16()
	a[2], a[3] = 0, 0
	return netip.PrefixFrom(netip.AddrFrom16(a), p.Bits())
}

// checkName holds a table or interface name to what pf.conf reads as one word
func checkName(name string, most int) error {
	if name == "" || len(name) > most {
		return fmt.Errorf("%d bytes, where pf holds 1 to %d", len(name), most)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return fmt.Errorf("holds %q", c)
		}
	}
	return nil
}
