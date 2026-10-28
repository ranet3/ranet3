// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/schema"
)

// This file is the linux realization of policy routing, a linux facility with
// no equivalent on the other platforms this tree builds for, which is why it
// is an optional half of the platform rather than methods every backend has to
// stub. See ruler in kernel.go for what the other platforms do instead.
//
// Ownership is the same as routes': every rule this file writes carries
// FRA_PROTOCOL set to the reconciler's protocol, a dump keeps only those, and
// a delete carries the protocol too so the kernel refuses a mismatch as well.
// FRA_PROTOCOL has been in the kernel since 4.17 and systemd-networkd sets it
// to RTPROT_STATIC on the rules it installs, so the fleet's own rules and this
// reconciler's are already distinguishable on a running node.

// af is one rule's family as this backend writes it into the header. It lives
// with the netlink encoder rather than beside the Family type, because a
// family is a word everywhere else in this tree and a number only here.
func (f Family) af() uint8 {
	if f == FamilyIPv4 {
		return unix.AF_INET
	}
	return unix.AF_INET6
}

// sizeofFibRuleHdr is struct fib_rule_hdr, which has the same shape as rtmsg:
// family, dst_len, src_len, tos, table, res1, res2, action, then a 32-bit
// flags field. x/sys/unix exports no type for it, so the twelve bytes are
// written by hand, as routeMessage writes rtmsg.
const sizeofFibRuleHdr = 12

// frAction is the FR_ACT a rule of this action carries.
func (a ruleAction) frAction() uint8 {
	switch a {
	case actionGoto:
		return unix.FR_ACT_GOTO
	case actionNop:
		return unix.FR_ACT_NOP
	case actionUnreachable:
		return unix.FR_ACT_UNREACHABLE
	}
	return unix.FR_ACT_TO_TBL
}

// ruleMessage is the body of an RTM_NEWRULE or RTM_DELRULE for one rule. It
// carries every selector the rule holds, since a delete compares the mark and
// the suppress length only where it carries them, the mask wherever it carries
// a mark, and otherwise takes the first rule its other selectors match.
//
// The table goes in FRA_TABLE rather than in the one-byte header field, and
// the header field stays RT_TABLE_UNSPEC, which is how a table number above
// 255 reaches the kernel at all. routeMessage carries the table in RTA_TABLE
// the same way, and in the header byte as well for one up to 255. Only a
// lookup names a table.
func (p *netlinkPlatform) ruleMessage(rule Rule) []byte {
	body := make([]byte, sizeofFibRuleHdr)
	body[0] = rule.Family.af()
	if rule.To.IsValid() {
		body[1] = uint8(rule.To.Bits())
	}
	if rule.From.IsValid() {
		body[2] = uint8(rule.From.Bits())
	}
	// body[4] is the legacy table field, left at RT_TABLE_UNSPEC.
	body[7] = rule.action.frAction()
	if rule.invert {
		binary.NativeEndian.PutUint32(body[8:], unix.FIB_RULE_INVERT)
	}
	body = putAttrU32(body, unix.FRA_PRIORITY, rule.Priority)
	switch rule.action {
	case actionLookup:
		body = putAttrU32(body, unix.FRA_TABLE, uint32(rule.Table))
	case actionGoto:
		body = putAttrU32(body, unix.FRA_GOTO, rule.target)
	}
	if bits, ok := rule.suppress.Bits(); ok {
		body = putAttrU32(body, unix.FRA_SUPPRESS_PREFIXLEN, uint32(bits))
	}
	body = putAttr(body, unix.FRA_PROTOCOL, []byte{p.table.Proto})
	if rule.To.IsValid() {
		body = putAttr(body, unix.FRA_DST, addressBytes(rule.To.Addr()))
	}
	if rule.From.IsValid() {
		body = putAttr(body, unix.FRA_SRC, addressBytes(rule.From.Addr()))
	}
	if rule.FWMark != 0 {
		body = putAttrU32(body, unix.FRA_FWMARK, rule.FWMark)
		if rule.FWMask != 0 {
			body = putAttrU32(body, unix.FRA_FWMASK, rule.FWMask)
		}
	}
	if rule.IIF != "" {
		body = putAttrString(body, unix.FRA_IIFNAME, rule.IIF)
	}
	if rule.oif != "" {
		body = putAttrString(body, unix.FRA_OIFNAME, rule.oif)
	}
	if rule.l3mdev {
		body = putAttr(body, unix.FRA_L3MDEV, []byte{1})
	}
	return body
}

// Rules dumps every policy rule and keeps the ones carrying this reconciler's
// protocol. A rule with no FRA_PROTOCOL, which the kernel's own three built-in
// rules give back, is somebody else's by definition: this file never writes
// one without it.
func (p *netlinkPlatform) Rules() ([]Rule, error) {
	body := make([]byte, sizeofFibRuleHdr)
	body[0] = unix.AF_UNSPEC
	replies, err := p.conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, body)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump rules: %w", err)
	}
	var out []Rule
	for _, reply := range replies {
		if rule, ok := p.decodeRule(reply); ok {
			out = append(out, rule)
		}
	}
	return out, nil
}

// decodeRule reads one dumped rule through the dump's decoder, and reports
// false for anything this reconciler does not own or could not have written.
// Everything it accepts has to compare equal to the rule it came from, or
// each pass deletes the rule and installs it again, and a rule of ours it
// drops is never withdrawn.
func (p *netlinkPlatform) decodeRule(message nlMessage) (Rule, bool) {
	held, ok := decodeDumpedRule(message)
	if !ok || held.Protocol != p.table.Proto || held.Priority == 0 {
		return Rule{}, false
	}
	rule := Rule{
		Family: held.Family, To: schema.PrefixFrom(held.To), From: schema.PrefixFrom(held.From),
		FWMark: held.FWMark, FWMask: held.FWMask, IIF: held.IIF, Priority: held.Priority, suppress: held.Suppress,
		invert: held.Invert, oif: held.OIF, l3mdev: held.L3mdev,
	}
	// Only the actions this file writes, each in the shape it writes it. A
	// rule that blackholes or prohibits is not one of ours however it is
	// marked, and deleting it on the strength of a protocol byte alone would be
	// taking somebody's word for what it does. The kernel dumps FRA_TABLE 0 for
	// a goto, a nop and an unreachable.
	switch {
	case held.Action == actionLookup.String() && held.Table != 0 && held.Goto == 0:
		rule.action, rule.Table = actionLookup, schema.TableID(held.Table)
	case held.Action == actionGoto.String() && held.Table == 0 && held.Goto > held.Priority:
		rule.action, rule.target = actionGoto, held.Goto
	case held.Action == actionNop.String() && held.Table == 0 && held.Goto == 0:
		rule.action = actionNop
	case held.Action == actionUnreachable.String() && held.Table == 0 && held.Goto == 0:
		rule.action = actionUnreachable
	default:
		return Rule{}, false
	}
	// A mask the kernel reports as all ones on a marked rule is the exact
	// match an absent FRA_FWMASK asks for, so the two spellings compare equal
	// rather than making every pass delete and reinstall the same rule.
	if rule.FWMark != 0 && rule.FWMask == ^uint32(0) {
		rule.FWMask = 0
	}
	return rule, true
}

func (p *netlinkPlatform) AddRule(rule Rule) error {
	_, err := p.conn.execute(unix.RTM_NEWRULE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, p.ruleMessage(rule))
	// EEXIST is a rule already in place under the same selectors, which a pass
	// that raced its own notification reaches. The diff wanted it there.
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("kernel: add rule %s: %w", rule, err)
	}
	return nil
}

func (p *netlinkPlatform) DelRule(rule Rule) error {
	_, err := p.conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, p.ruleMessage(rule))
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("kernel: delete rule %s: %w", rule, err)
	}
	return nil
}
