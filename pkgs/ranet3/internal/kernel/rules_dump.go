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
	// Unread is each selector the rule carries beyond the ones above
	Unread Selectors
}

// Selectors is a set of what a rule may carry that DumpedRule holds no value
// of. Each but suppress_ifgroup is a selector fib_rule_match matches a packet
// on. Where every selector TakeRule reads holds, TakeRule assumes the rule
// carrying an unread one does not take the packet, inverted or not.
// suppress_ifgroup is a condition on a lookup's answer, the device
// group of the route it found (fib4_rule_suppress, fib6_rule_suppress), which
// TakeRule assumes suppressed the answer.
type Selectors uint8

const (
	SelectorTunID Selectors = 1 << iota
	SelectorSuppressIfgroup
	SelectorUIDRange
	SelectorIPProto
	SelectorSport
	SelectorDport
	SelectorDSCP
	SelectorFlowlabel
)

// Names is each selector of the set as `ip rule` spells it
func (s Selectors) Names() []string {
	var names []string
	for i, name := range []string{"tun_id", "suppress_ifgroup", "uidrange", "ipproto", "sport", "dport", "dscp", "flowlabel"} {
		if s&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	return names
}
