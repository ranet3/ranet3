// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
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
// af never sees an unresolved family: expandRules names one on every rule and
// validate refuses anything else.
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

// ruleMessage is the body of an RTM_NEWRULE or RTM_DELRULE for one rule.
//
// The table goes in FRA_TABLE rather than in the one-byte header field, and
// the header field stays RT_TABLE_UNSPEC, which is how a table number above
// 255 reaches the kernel at all. routeMessage splits it the same way.
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
	body[7] = unix.FR_ACT_TO_TBL
	body = putAttrU32(body, unix.FRA_PRIORITY, rule.Priority)
	body = putAttrU32(body, unix.FRA_TABLE, uint32(rule.Table))
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
// Everything it accepts has to compare equal to the configured rule it came
// from, or the diff installs a duplicate on every pass.
func (p *netlinkPlatform) decodeRule(message nlMessage) (Rule, bool) {
	held, ok := decodeDumpedRule(message)
	// Only the action this file writes. A rule that blackholes or that reaches
	// a goto target is not one of ours however it is marked, and deleting it
	// on the strength of a protocol byte alone would be taking somebody's
	// word for what it does.
	if !ok || held.Action != actionName(unix.FR_ACT_TO_TBL) || held.Protocol != p.table.Proto || held.Table == 0 || held.Priority == 0 {
		return Rule{}, false
	}
	rule := Rule{
		Family: held.Family, To: schema.PrefixFrom(held.To), From: schema.PrefixFrom(held.From),
		FWMark: held.FWMark, FWMask: held.FWMask, IIF: held.IIF, Table: schema.TableID(held.Table), Priority: held.Priority,
	}
	// A mask the kernel reports as all ones is the exact match an absent
	// FRA_FWMASK asks for, so the two spellings compare equal rather than
	// making every pass delete and reinstall the same rule.
	if rule.FWMask == ^uint32(0) {
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
