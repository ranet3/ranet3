// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "net/netip"

// DumpedRule is one policy rule as the kernel holds it, whoever wrote it: the
// reconciler, networkd, the kernel's own three or an operator. Both readers
// decode through one decoder: Rules keeps only the reconciler's, to diff
// against, and DumpRules every one, to show ranet3's rules among the rest.
type DumpedRule struct {
	Family   Family
	Priority uint32
	// To and From are the selectors, the zero prefix where the rule names none
	To, From netip.Prefix
	// IIF and OIF are the device names the rule selects on, empty for none
	IIF, OIF       string
	FWMark, FWMask uint32
	// L3mdev is FRA_L3MDEV, a lookup in the table of the l3mdev master the
	// packet's device belongs to, whichever program made that master
	L3mdev bool
	// Invert is FIB_RULE_INVERT, a rule matching every packet its selectors do not
	Invert bool
	// Action names the step a matching packet meets: lookup, goto, nop, blackhole,
	// unreachable, prohibit, or "action N" for a number this names nothing for
	Action string
	// Table is the table a lookup rule reads, as the kernel holds it whatever
	// the action
	Table uint32
	// Goto is FRA_GOTO, the priority a goto jumps to, zero where the rule names none
	Goto uint32
	// Suppress is FRA_SUPPRESS_PREFIXLEN
	Suppress Suppress
	// Protocol is FRA_PROTOCOL, zero where the kernel holds none
	Protocol uint8
}
