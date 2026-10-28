// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package pf writes and reads the rules ranet3 keeps in an anchor of macOS's
// packet filter. pfctl is the one writer and reader: the package renders a
// ruleset as pf.conf text in the form pfctl prints it back, loads it into an
// anchor in one transaction, and parses pfctl's readback into the same model,
// so a readback compares with what was written as values. No struct of
// pfvar.h is laid out here.
package pf

import "net/netip"

// Action names the fate of a packet a rule matches
type Action uint8

const (
	// Pass lets the packet through, keeping no state for it
	Pass Action = iota + 1
	// Block drops the packet in silence
	Block
)

// Family is the address family a rule names, AnyFamily when it names none
type Family uint8

const (
	AnyFamily Family = iota
	Inet
	Inet6
)

// Address is the source a rule matches: the table where Table is set, the
// prefix where Prefix is valid, and any address where neither is
type Address struct {
	Table  string
	Prefix netip.Prefix
}

// Any reports whether a matches every address
func (a Address) Any() bool {
	return a.Table == "" && !a.Prefix.IsValid()
}

// Rule is one filter rule. Every rule this package renders matches packets in,
// is quick when Quick holds, keeps no state, matches any destination, and
// carries a label that names it within its anchor.
type Rule struct {
	Action Action
	Quick  bool
	// Interface is the interface the rule matches, every one when empty, and
	// every one but it where NotInterface holds
	Interface    string
	NotInterface bool
	Family       Family
	From         Address
	Label        string
}

// Table is a table of prefixes an anchor defines for its rules
type Table struct {
	Name     string
	Const    bool
	Prefixes []netip.Prefix
}

// Ruleset holds the tables and rules one load writes into an anchor,
// replacing all it held
type Ruleset struct {
	Tables []Table
	Rules  []Rule
}
