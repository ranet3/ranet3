// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"maps"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
	"ranet3.com/pkgs/ranet3/schema"
)

// ruleAttrs reads back the attributes of a rule message the backend wrote, so
// a test asserts on what reaches the kernel rather than on the struct it came
// from.
func ruleAttrs(t *testing.T, body []byte) (hdr []byte, attrs map[uint16][]byte) {
	t.Helper()
	if len(body) < sizeofFibRuleHdr {
		t.Fatalf("a rule message is %d bytes, shorter than its header", len(body))
	}
	message := nlMessage{Data: body}
	attrs = maps.Collect(message.attributes(sizeofFibRuleHdr))
	return body[:sizeofFibRuleHdr], attrs
}

// Every rule carries the reconciler's protocol, the table goes in FRA_TABLE
// rather than in the header's one byte, and a lookup goes out as
// FR_ACT_TO_TBL. The first is the ownership marker and the second is how a
// table above 255 reaches the kernel at all.
func TestRuleMessageCarriesTheOwnershipMarker(t *testing.T) {
	plat, _ := writePlatform(t)
	rule := Rule{Family: FamilyIPv6, From: schema.MustPrefix("3fff:a::/36"), Table: 200, Priority: 150}
	hdr, attrs := ruleAttrs(t, plat.ruleMessage(rule))

	if hdr[0] != unix.AF_INET6 {
		t.Errorf("family byte is %d", hdr[0])
	}
	if hdr[2] != 36 {
		t.Errorf("src_len is %d, want the source prefix length", hdr[2])
	}
	if hdr[4] != 0 {
		t.Errorf("the legacy table byte is %d, want RT_TABLE_UNSPEC so FRA_TABLE decides", hdr[4])
	}
	if hdr[7] != unix.FR_ACT_TO_TBL {
		t.Errorf("action is %d, want FR_ACT_TO_TBL", hdr[7])
	}
	protocol, ok := attrs[unix.FRA_PROTOCOL]
	if !ok || len(protocol) != 1 || protocol[0] != DefaultProtocol {
		t.Errorf("FRA_PROTOCOL is %v, want the reconciler's own protocol", protocol)
	}
	if table := attrs[unix.FRA_TABLE]; len(table) != 4 || binary.NativeEndian.Uint32(table) != 200 {
		t.Errorf("FRA_TABLE is %v", table)
	}
	if priority := attrs[unix.FRA_PRIORITY]; len(priority) != 4 || binary.NativeEndian.Uint32(priority) != 150 {
		t.Errorf("FRA_PRIORITY is %v", priority)
	}
	if _, ok := attrs[unix.FRA_DST]; ok {
		t.Error("a rule with no destination carried FRA_DST")
	}
}

// A mark rule names no address, so the family comes from the rule rather than
// from a prefix, and the mask is sent only when there is one.
func TestRuleMessageCarriesTheMarkAndItsMask(t *testing.T) {
	plat, _ := writePlatform(t)
	_, attrs := ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, Table: 254, Priority: 40}))
	if mark := attrs[unix.FRA_FWMARK]; len(mark) != 4 || binary.NativeEndian.Uint32(mark) != 0x72 {
		t.Errorf("FRA_FWMARK is %v", mark)
	}
	if _, ok := attrs[unix.FRA_FWMASK]; ok {
		t.Error("a rule with no mask carried FRA_FWMASK, which the kernel reads as an exact match anyway")
	}

	_, attrs = ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv4, FWMark: 0x72, FWMask: 0xffff, Table: 254, Priority: 40}))
	if mask := attrs[unix.FRA_FWMASK]; len(mask) != 4 || binary.NativeEndian.Uint32(mask) != 0xffff {
		t.Errorf("FRA_FWMASK is %v", mask)
	}
}

// An input device goes out as FRA_IIFNAME with its terminator, the string the
// kernel compares, and a rule naming none carries no such attribute.
func TestRuleMessageCarriesTheInputDevice(t *testing.T) {
	plat, _ := writePlatform(t)
	_, attrs := ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv6, IIF: "eth1", Table: 254, Priority: 60}))
	if name := attrs[unix.FRA_IIFNAME]; string(name) != "eth1\x00" {
		t.Errorf("FRA_IIFNAME is %q", name)
	}
	_, attrs = ruleAttrs(t, plat.ruleMessage(Rule{Family: FamilyIPv6, FWMark: 0x72, Table: 254, Priority: 40}))
	if _, ok := attrs[unix.FRA_IIFNAME]; ok {
		t.Error("a rule naming no device carried FRA_IIFNAME")
	}
}

// What the backend writes has to read back as the same value, or the diff
// installs a duplicate on every pass and the rule list grows without bound.
func TestRuleRoundTripsThroughItsOwnEncoding(t *testing.T) {
	plat, conn := writePlatform(t)
	for name, rule := range map[string]Rule{
		"a destination rule": {Family: FamilyIPv4, To: schema.MustPrefix("203.0.113.0/24"), Table: 200, Priority: 100},
		"a source rule":      {Family: FamilyIPv6, From: schema.MustPrefix("3fff:b::/48"), Table: 200, Priority: 150},
		"a mark rule":        {Family: FamilyIPv6, FWMark: 0x72, Table: 254, Priority: 40},
		"both selectors":     {Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), From: schema.MustPrefix("10.1.0.0/16"), Table: 7, Priority: 90},
		"a device rule":      {Family: FamilyIPv4, IIF: "eth1", Table: 254, Priority: 60},
	} {
		t.Run(name, func(t *testing.T) {
			conn.replies = []nlMessage{{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(rule)}}
			got, err := plat.Rules()
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("the dump read back %v, want the one rule that was written", got)
			}
			if got[0] != rule {
				t.Errorf("read back %s, want %s", got[0], rule)
			}
		})
	}
}

// The kernel reports an absent FRA_FWMASK as a mask of all ones, so the two
// spellings have to compare equal or every pass deletes and reinstalls the
// same rule.
func TestExactMarkReadsBackAsTheRuleThatWasWritten(t *testing.T) {
	plat, conn := writePlatform(t)
	rule := Rule{Family: FamilyIPv4, FWMark: 0x72, Table: 254, Priority: 40}
	body := plat.ruleMessage(rule)
	body = putAttrU32(body, unix.FRA_FWMASK, ^uint32(0))
	conn.replies = []nlMessage{{Kind: unix.RTM_NEWRULE, Data: body}}
	got, err := plat.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != rule {
		t.Fatalf("read back %v, want %s", got, rule)
	}
}

// A dump holds every rule on the box. Anything without this reconciler's
// protocol, and anything whose action is not one this backend writes, is
// somebody else's: a delete list that contained one would be a delete list
// that takes the machine's own routing apart.
func TestRuleDumpKeepsOnlyWhatThisReconcilerOwns(t *testing.T) {
	plat, conn := writePlatform(t)
	ours := Rule{Family: FamilyIPv6, From: schema.MustPrefix("2001:db8::/32"), Table: 200, Priority: 150}

	other := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), Table: 200, Priority: 100})
	// networkd stamps RTPROT_STATIC on the rules it installs, so this is the
	// marker the fleet's own rules carry today.
	other = replaceProtocol(t, other, unix.RTPROT_STATIC)

	blackhole := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("10.0.0.0/8"), Table: 200, Priority: 101})
	blackhole[7] = unix.FR_ACT_BLACKHOLE

	unmarked := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("192.0.2.0/24"), Table: 200, Priority: 102})
	unmarked = stripProtocol(t, unmarked)

	// marked as this reconciler's, yet looking up no table or sitting at
	// priority 0, the local table's, neither of which it could have written
	tableless := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("192.0.2.0/24"), Priority: 103})
	first := plat.ruleMessage(Rule{Family: FamilyIPv4, To: schema.MustPrefix("198.51.100.0/24"), Table: 200})

	conn.replies = []nlMessage{
		{Kind: unix.RTM_NEWRULE, Data: plat.ruleMessage(ours)},
		{Kind: unix.RTM_NEWRULE, Data: other},
		{Kind: unix.RTM_NEWRULE, Data: blackhole},
		{Kind: unix.RTM_NEWRULE, Data: unmarked},
		{Kind: unix.RTM_NEWRULE, Data: tableless},
		{Kind: unix.RTM_NEWRULE, Data: first},
	}
	got, err := plat.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Rule{ours}) {
		t.Fatalf("the dump kept %v, want only this reconciler's own rule", got)
	}
}

// A rule of this reconciler's protocol that another writer gave a selector no
// derived rule holds, an inverted match, an output device or an l3mdev lookup,
// reads back unequal to the derived rule it otherwise is, so the pass deletes
// it and adds its own, and the delete names the device and the l3mdev, which
// the kernel compares on a delete
func TestRuleReadBackKeepsWhatNoDerivedRuleHolds(t *testing.T) {
	plat, _ := writePlatform(t)
	underlay := Rule{Family: FamilyIPv4, Priority: 5100, FWMark: 0x72, action: actionGoto, target: 5190}
	inverted := plat.ruleMessage(underlay)
	binary.NativeEndian.PutUint32(inverted[8:], unix.FIB_RULE_INVERT)
	for name, c := range map[string]struct {
		body []byte
		kind uint16
	}{
		"an inverted match": {body: inverted},
		"an output device":  {body: putAttrString(plat.ruleMessage(underlay), unix.FRA_OIFNAME, "eth0"), kind: unix.FRA_OIFNAME},
		"an l3mdev lookup":  {body: putAttr(plat.ruleMessage(underlay), unix.FRA_L3MDEV, []byte{1}), kind: unix.FRA_L3MDEV},
	} {
		got, ok := plat.decodeRule(nlMessage{Kind: unix.RTM_NEWRULE, Data: c.body})
		if !ok {
			t.Errorf("%s: a rule of this reconciler's protocol is read as another writer's", name)
			continue
		}
		if got == underlay {
			t.Errorf("%s: read back as the derived %s", name, underlay)
		}
		hdr, attrs := ruleAttrs(t, plat.ruleMessage(got))
		if _, carried := attrs[c.kind]; c.kind != 0 && !carried {
			t.Errorf("%s: the delete of %s leaves out attribute %d", name, got, c.kind)
		}
		if c.kind == 0 && binary.NativeEndian.Uint32(hdr[8:])&unix.FIB_RULE_INVERT == 0 {
			t.Errorf("%s: the delete of %s leaves out the inversion", name, got)
		}
	}
}

// replaceProtocol and stripProtocol rewrite one attribute of an encoded rule,
// so a test can build the messages another writer would have produced without
// a second encoder to keep in step with the first.
func replaceProtocol(t *testing.T, body []byte, protocol uint8) []byte {
	t.Helper()
	out := rebuildRule(t, body, func(kind uint16, value []byte) ([]byte, bool) {
		if kind == unix.FRA_PROTOCOL {
			return []byte{protocol}, true
		}
		return value, true
	})
	return out
}

func stripProtocol(t *testing.T, body []byte) []byte {
	t.Helper()
	return rebuildRule(t, body, func(kind uint16, value []byte) ([]byte, bool) {
		return value, kind != unix.FRA_PROTOCOL
	})
}

func rebuildRule(t *testing.T, body []byte, edit func(uint16, []byte) ([]byte, bool)) []byte {
	t.Helper()
	out := slices.Clone(body[:sizeofFibRuleHdr])
	message := nlMessage{Data: body}
	for kind, value := range message.attributes(sizeofFibRuleHdr) {
		replacement, keep := edit(kind, value)
		if keep {
			out = putAttr(out, kind, replacement)
		}
	}
	return out
}
