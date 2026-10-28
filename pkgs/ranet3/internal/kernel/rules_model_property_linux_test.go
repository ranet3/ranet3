// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"maps"
	"math"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// kernelRule is the part of struct fib_rule, with fib4_rule's or fib6_rule's
// addresses, that a rule this reconciler writes reaches, as
// net/core/fib_rules.c at 940de590 fills it in
type kernelRule struct {
	family, action      uint8
	pref, table, target uint32
	userPriority        bool
	mark, markMask      uint32
	suppressPrefixlen   int32
	iifname             string
	proto               uint8
	dstLen, srcLen      uint8
	dst, src            string
}

// kernelParse is fib_nl2rule (fib_rules.c:568-736) and the backward goto check
// of fib_nl2rule_locked (:746-750) on one request body
func kernelParse(body []byte) (kernelRule, error) {
	attrs := maps.Collect(nlMessage{Data: body}.attributes(sizeofFibRuleHdr))
	u32 := func(kind uint16) (uint32, bool) {
		value, ok := attrs[kind]
		if !ok || len(value) != 4 {
			return 0, false
		}
		return binary.NativeEndian.Uint32(value), true
	}
	// frh_get_table: FRA_TABLE over the header's byte
	r := kernelRule{family: body[0], dstLen: body[1], srcLen: body[2], table: uint32(body[4]), action: body[7], suppressPrefixlen: -1}
	size := 4
	if r.family == unix.AF_INET6 {
		size = 16
	}
	for _, address := range []struct {
		length uint8
		kind   uint16
		into   *string
	}{{r.srcLen, unix.FRA_SRC, &r.src}, {r.dstLen, unix.FRA_DST, &r.dst}} {
		if address.length == 0 {
			continue
		}
		value, ok := attrs[address.kind]
		if !ok || int(address.length) > size*8 || len(value) != size {
			return kernelRule{}, errors.New("invalid address")
		}
		*address.into = string(value)
	}
	if pref, ok := u32(unix.FRA_PRIORITY); ok {
		r.pref, r.userPriority = pref, true
	}
	if proto, ok := attrs[unix.FRA_PROTOCOL]; ok && len(proto) == 1 {
		r.proto = proto[0]
	}
	if name, ok := attrs[unix.FRA_IIFNAME]; ok {
		r.iifname = unix.ByteSliceToString(name)
	}
	if mark, ok := u32(unix.FRA_FWMARK); ok {
		r.mark = mark
		if mark != 0 {
			r.markMask = ^uint32(0)
		}
	}
	if mask, ok := u32(unix.FRA_FWMASK); ok {
		r.markMask = mask
	}
	if table, ok := u32(unix.FRA_TABLE); ok {
		r.table = table
	}
	if length, ok := u32(unix.FRA_SUPPRESS_PREFIXLEN); ok {
		r.suppressPrefixlen = int32(length)
	}
	target, ok := u32(unix.FRA_GOTO)
	switch {
	case ok && r.action != unix.FR_ACT_GOTO:
		return kernelRule{}, errors.New("unexpected goto")
	case !ok && r.action == unix.FR_ACT_GOTO:
		return kernelRule{}, errors.New("missing goto target for action goto")
	case ok && target <= r.pref:
		return kernelRule{}, errors.New("backward goto not supported")
	}
	r.target = target
	return r, nil
}

// dump is fib_nl_fill_rule (fib_rules.c:1151-1234) with the address part of
// fib4_rule_fill or fib6_rule_fill
func (r kernelRule) dump() nlMessage {
	body := make([]byte, sizeofFibRuleHdr)
	body[0], body[1], body[2], body[7] = r.family, r.dstLen, r.srcLen, r.action
	body[4] = unix.RT_TABLE_COMPAT
	if r.table < 256 {
		body[4] = uint8(r.table)
	}
	body = putAttrU32(body, unix.FRA_TABLE, r.table)
	body = putAttrU32(body, unix.FRA_SUPPRESS_PREFIXLEN, uint32(r.suppressPrefixlen))
	body = putAttr(body, unix.FRA_PROTOCOL, []byte{r.proto})
	if r.iifname != "" {
		body = putAttrString(body, unix.FRA_IIFNAME, r.iifname)
	}
	if r.pref != 0 {
		body = putAttrU32(body, unix.FRA_PRIORITY, r.pref)
	}
	if r.mark != 0 {
		body = putAttrU32(body, unix.FRA_FWMARK, r.mark)
	}
	if r.markMask != 0 || r.mark != 0 {
		body = putAttrU32(body, unix.FRA_FWMASK, r.markMask)
	}
	if r.target != 0 {
		body = putAttrU32(body, unix.FRA_GOTO, r.target)
	}
	if r.dstLen != 0 {
		body = putAttr(body, unix.FRA_DST, []byte(r.dst))
	}
	if r.srcLen != 0 {
		body = putAttr(body, unix.FRA_SRC, []byte(r.src))
	}
	return nlMessage{Kind: unix.RTM_NEWRULE, Data: body}
}

// addresses is fib4_rule_compare's or fib6_rule_compare's test of the
// request's addresses, each compared only where the request names a length
func (r kernelRule) addresses(request kernelRule) bool {
	return (request.srcLen == 0 || (r.srcLen == request.srcLen && r.src == request.src)) &&
		(request.dstLen == 0 || (r.dstLen == request.dstLen && r.dst == request.dst))
}

// found is rule_find's test of one held rule against a delete (fib_rules.c:439-518)
func (r kernelRule) found(request kernelRule) bool {
	switch {
	case r.family != request.family,
		request.action != 0 && r.action != request.action,
		request.table != 0 && r.table != request.table,
		request.userPriority && r.pref != request.pref,
		request.iifname != "" && r.iifname != request.iifname,
		request.mark != 0 && r.mark != request.mark,
		request.suppressPrefixlen != -1 && r.suppressPrefixlen != request.suppressPrefixlen,
		request.markMask != 0 && r.markMask != request.markMask,
		request.proto != 0 && r.proto != request.proto:
		return false
	}
	return r.addresses(request)
}

// exists is rule_exists's test of one held rule against an add (fib_rules.c:779-847), which reads no goto target
func (r kernelRule) exists(request kernelRule) bool {
	return r.family == request.family && r.action == request.action && r.table == request.table &&
		r.pref == request.pref && r.iifname == request.iifname && r.mark == request.mark &&
		r.suppressPrefixlen == request.suppressPrefixlen && r.markMask == request.markMask &&
		r.proto == request.proto && r.addresses(request)
}

// allOnes is the mask the kernel stores for a mark written without one.
const allOnes = ^uint32(0)

// masks draws a mark's mask, the two spellings of an exact match more often
// than any other value.
func masks() hegel.Generator[uint32] {
	return hegel.OneOf(hegel.Integers[uint32](1, math.MaxUint32), hegel.Just(uint32(0)), hegel.Just(allOnes))
}

// devices draws an input device a rule selects on, the longest name a device
// can carry among them.
func devices() hegel.Generator[string] {
	return hegel.SampledFrom([]string{"eth1", "lo", "eth0", strings.Repeat("r", 15)})
}

// asHeld is rule as the readback decodes it, an all-ones mask on a marked rule
// read as the absent mask it matches the same packets as
func asHeld(rule Rule) Rule {
	if rule.FWMark != 0 && rule.FWMask == ^uint32(0) {
		rule.FWMask = 0
	}
	return rule
}

// ownedRules draws a rule of any action this reconciler writes, on any
// selectors, in either family, as the readback decodes it
func ownedRules() hegel.Generator[Rule] {
	return hegel.Composite(func(tc hegel.TestCase) Rule {
		v6 := hegel.Draw(tc, hegel.Booleans())
		rule := Rule{Family: FamilyIPv4, Priority: hegel.Draw(tc, edges[uint32](1, math.MaxUint32-1))}
		width := 32
		if v6 {
			rule.Family, width = FamilyIPv6, 128
		}
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 0:
			rule.Table = schema.TableID(hegel.Draw(tc, edges[uint32](1, math.MaxUint32)))
		case 1:
			rule.action, rule.target = actionGoto, hegel.Draw(tc, edges(rule.Priority+1, math.MaxUint32))
		default:
			rule.action = actionNop
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.suppress = SuppressUpTo(hegel.Draw(tc, edges(0, width)))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.FWMark, rule.FWMask = hegel.Draw(tc, edges[uint32](1, math.MaxUint32)), hegel.Draw(tc, masks())
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.IIF = hegel.Draw(tc, devices())
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.To = hegel.Draw(tc, selectors(v6))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			rule.From = hegel.Draw(tc, selectors(v6))
		}
		return asHeld(rule)
	})
}

// variant is base with one selector or its action moved, the rule a delete of
// base could take in its place
func variant(tc hegel.TestCase, base Rule) Rule {
	other := hegel.Draw(tc, ownedRules())
	switch hegel.Draw(tc, hegel.Integers(0, 6)) {
	case 0:
		base.FWMark, base.FWMask = other.FWMark, other.FWMask
		if base.FWMark == 0 {
			base.FWMark = hegel.Draw(tc, edges[uint32](1, math.MaxUint32))
		}
	case 1:
		base.FWMask = hegel.Draw(tc, masks())
		if base.FWMark == 0 {
			base.FWMark = hegel.Draw(tc, edges[uint32](1, math.MaxUint32))
		}
	case 2:
		base.suppress = other.suppress
	case 3:
		base.IIF = other.IIF
	case 4:
		base.action, base.Table, base.target = other.action, other.Table, max(other.target, base.Priority+1)
		if base.action != actionGoto {
			base.target = 0
		}
	case 5:
		if base.Family == other.Family {
			base.To = other.To
		}
	default:
		if base.Family == other.Family {
			base.From = other.From
		}
	}
	return asHeld(base)
}

// The kernel stores what the encoder writes for a rule of every action and
// selector, and its dump of that rule reads back as the rule. One that did not
// would be deleted and installed again on every pass, and one the readback
// drops would never be withdrawn.
func TestEveryOwnedRuleReadsBackFromTheKernelsDumpOfIt(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := hegel.Draw(ht, ownedRules())
		plat, conn := writePlatform(t)
		stored, err := kernelParse(sent(ht, conn, plat.AddRule, rule))
		if err != nil {
			ht.Fatalf("the kernel refuses %s: %v", rule, err)
		}
		if got, ok := plat.decodeRule(stored.dump()); !ok || got != rule {
			ht.Fatalf("%s read back from the kernel's dump of it as %s (kept %v)", rule, got, ok)
		}
	})
}

// A delete takes a rule that holds every selector of the rule deleted, whatever
// else the kernel holds at that priority: the first rule its selectors match,
// and none of another action, nor of another mark and mask, suppress length or
// device where the rule deleted names one
func TestDeleteTakesOnlyARuleHoldingEverySelectorOfTheDeletedOne(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		base := hegel.Draw(ht, ownedRules())
		plat, conn := writePlatform(t)
		var held []kernelRule
		var rules []Rule
		for _, rule := range append(hegel.Draw(ht, hegel.Lists(hegel.Composite(func(tc hegel.TestCase) Rule { return variant(tc, base) })).MaxSize(5)), base) {
			stored, err := kernelParse(sent(ht, conn, plat.AddRule, rule))
			if err != nil {
				ht.Fatalf("the kernel refuses %s: %v", rule, err)
			}
			duplicate := false
			for _, other := range held {
				duplicate = duplicate || other.exists(stored)
			}
			if !duplicate {
				held, rules = append(held, stored), append(rules, rule)
			}
		}
		deleted := rules[hegel.Draw(ht, hegel.Integers(0, len(rules)-1))]
		request, err := kernelParse(sent(ht, conn, plat.DelRule, deleted))
		if err != nil {
			ht.Fatalf("the kernel refuses the delete of %s: %v", deleted, err)
		}
		for i, stored := range held {
			if !stored.found(request) {
				continue
			}
			if !holdsEverySelectorOf(rules[i], deleted) {
				ht.Fatalf("a delete of %s took %s, ahead of it among %v", deleted, rules[i], rules)
			}
			return
		}
		ht.Fatalf("a delete of %s took nothing among %v", deleted, rules)
	})
}

// sent is the one message write sent for rule
func sent(ht *hegel.T, conn *fakeNetlink, write func(Rule) error, rule Rule) []byte {
	conn.sent = nil
	if err := write(rule); err != nil || len(conn.sent) != 1 {
		ht.Fatalf("writing %s sent %d messages (err %v)", rule, len(conn.sent), err)
	}
	return conn.sent[0].body
}

// holdsEverySelectorOf is whether rule holds, at deleted's priority and with
// its action, each selector deleted holds, equal, so every packet rule selects
// deleted selects too. A goto's target selects nothing.
func holdsEverySelectorOf(rule, deleted Rule) bool {
	mask := func(r Rule) uint32 {
		if r.FWMark != 0 && r.FWMask == 0 {
			return ^uint32(0)
		}
		return r.FWMask
	}
	_, suppresses := deleted.suppress.Bits()
	return rule.Family == deleted.Family && rule.Priority == deleted.Priority && rule.action == deleted.action &&
		(deleted.action != actionLookup || rule.Table == deleted.Table) &&
		(deleted.IIF == "" || rule.IIF == deleted.IIF) &&
		(deleted.FWMark == 0 || (rule.FWMark == deleted.FWMark && mask(rule) == mask(deleted))) &&
		(!suppresses || rule.suppress == deleted.suppress) &&
		(!deleted.To.IsValid() || rule.To == deleted.To) &&
		(!deleted.From.IsValid() || rule.From == deleted.From)
}

// a goto names its target and no table, a nop neither, and a suppress length
// of 0 goes out as itself
func TestRuleMessageCarriesTheGotoAndTheSuppressLength(t *testing.T) {
	plat, _ := writePlatform(t)
	hdr, attrs := ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, action: actionGoto, target: 5190, Priority: 5100}))
	if hdr[7] != unix.FR_ACT_GOTO {
		t.Errorf("a goto went out as action %d", hdr[7])
	}
	if target := attrs[unix.FRA_GOTO]; len(target) != 4 || binary.NativeEndian.Uint32(target) != 5190 {
		t.Errorf("FRA_GOTO is %v", target)
	}
	if _, ok := attrs[unix.FRA_TABLE]; ok {
		t.Error("a goto names a table")
	}
	hdr, attrs = ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv6, action: actionNop, Priority: 5190}))
	if hdr[7] != unix.FR_ACT_NOP {
		t.Errorf("a nop went out as action %d", hdr[7])
	}
	for _, kind := range []uint16{unix.FRA_TABLE, unix.FRA_GOTO, unix.FRA_SUPPRESS_PREFIXLEN} {
		if _, ok := attrs[kind]; ok {
			t.Errorf("a nop carries attribute %d", kind)
		}
	}
	_, attrs = ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, Table: 254, suppress: SuppressUpTo(0), Priority: 5410}))
	if length := attrs[unix.FRA_SUPPRESS_PREFIXLEN]; len(length) != 4 || binary.NativeEndian.Uint32(length) != 0 {
		t.Errorf("FRA_SUPPRESS_PREFIXLEN is %v, want 0", length)
	}
}

// The kernel takes every derived rule beside the others, reads each back as
// itself, both to the pass and to debug rules, and a delete of one takes that
// one, whatever the others at its priority select
func TestEveryDerivedRuleIsStoredAndDeletedAsItself(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		id := schema.TableID(hegel.Draw(ht, edges[uint32](1, math.MaxUint32)))
		derived := derivedRules(id, prefixes(hegel.Draw(ht, anyPrefixes())...), hegel.Draw(ht, anyPrefixes()), exitView{})
		plat, conn := writePlatform(t)
		held := make([]kernelRule, 0, len(derived))
		for _, rule := range derived {
			stored, err := kernelParse(sent(ht, conn, plat.AddRule, rule))
			if err != nil {
				ht.Fatalf("the kernel refuses %s: %v", rule, err)
			}
			for i, other := range held {
				if other.exists(stored) {
					ht.Fatalf("the kernel takes %s for %s, which it holds already", rule, derived[i])
				}
			}
			if got, ok := plat.decodeRule(stored.dump()); !ok || got != rule {
				ht.Fatalf("%s read back from the kernel's dump of it as %s (kept %v)", rule, got, ok)
			}
			if got, ok := decodeDumpedRule(stored.dump()); !ok || got != rule.dumped(plat.table.Proto) {
				ht.Fatalf("debug rules reads %s off the kernel as %+v and wants it as %+v", rule, got, rule.dumped(plat.table.Proto))
			}
			held = append(held, stored)
		}
		deleted := hegel.Draw(ht, hegel.Integers(0, len(derived)-1))
		request, err := kernelParse(sent(ht, conn, plat.DelRule, derived[deleted]))
		if err != nil {
			ht.Fatalf("the kernel refuses the delete of %s: %v", derived[deleted], err)
		}
		for i, stored := range held {
			if stored.found(request) {
				if i != deleted {
					ht.Fatalf("a delete of %s took %s", derived[deleted], derived[i])
				}
				return
			}
		}
		ht.Fatalf("a delete of %s took nothing", derived[deleted])
	})
}
