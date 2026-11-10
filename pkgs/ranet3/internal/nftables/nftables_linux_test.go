// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// translatorNames is a scope of the shape the translator watches, two chains,
// those of a prefix and two sets
var translatorNames = Scope{Chains: []string{"forward", "postrouting"}, Prefix: "none_", Sets: []string{"flows4", "flows6"}}

// A prefix narrows a rule by the bits it actually covers, so a /24 masks the
// last octet away and a /0 is never encoded at all.
func TestPrefixMaskCoversExactlyThePrefixLength(t *testing.T) {
	for _, one := range []struct {
		prefix string
		want   []byte
	}{
		{"198.51.100.0/24", []byte{0xff, 0xff, 0xff, 0x00}},
		{"198.51.100.0/22", []byte{0xff, 0xff, 0xfc, 0x00}},
		{"198.51.100.7/32", []byte{0xff, 0xff, 0xff, 0xff}},
		{"0.0.0.0/0", []byte{0x00, 0x00, 0x00, 0x00}},
	} {
		t.Run(one.prefix, func(t *testing.T) {
			if got := prefixMask(netip.MustParsePrefix(one.prefix)); !slices.Equal(got, one.want) {
				t.Errorf("masked with %x, want %x", got, one.want)
			}
		})
	}
	if got := prefixMask(netip.MustParsePrefix("2001:db8::/48")); len(got) != net.IPv6len {
		t.Errorf("an IPv6 mask is %d bytes, want %d", len(got), net.IPv6len)
	}
}

// A rule's comment reads back as its owner wrote it, and a set's comment
// travels under a type of its own.
func TestCommentRoundTripsThroughUserdata(t *testing.T) {
	const spec = "ipv4 out via ranet0 masquerade"
	if got := comment(udataComment, userdata(udataComment, spec)); got != spec {
		t.Errorf("read back %q, want %q", got, spec)
	}
	// Another writer's userdata comes first in the same blob. Skipping it by
	// its length rather than assuming the comment is first is the difference
	// between a rule its owner recognizes and one it reinstalls forever.
	blob := append([]byte{7, 3, 'a', 'b', 'c'}, userdata(udataComment, spec)...)
	if got := comment(udataComment, blob); got != spec {
		t.Errorf("read back %q past another writer's entry, want %q", got, spec)
	}
	if got := comment(udataComment, []byte{0, 9, 'a'}); got != "" {
		t.Errorf("a truncated entry read as %q", got)
	}
	blob = append(userdata(udataComment, spec), userdata(udataSetComment, "limit 4096")...)
	if got := comment(udataSetComment, blob); got != "limit 4096" {
		t.Errorf("a set's comment read back as %q past a rule's, want %q", got, "limit 4096")
	}
}

// A spec a byte past nft's comment limit is refused, and one at the limit is
// written and reads back as itself
func TestRuleTakesOnlyASpecItsCommentHolds(t *testing.T) {
	c := Chain{Table: "ranet3", Name: "postrouting"}
	if _, err := c.Rule(unix.NFPROTO_IPV4, strings.Repeat("x", udataCommentMax+1), nil); err == nil {
		t.Errorf("a spec of %d bytes was written", udataCommentMax+1)
	}
	spec := strings.Repeat("x", udataCommentMax)
	request, err := c.Rule(unix.NFPROTO_IPV4, spec, nil)
	if err != nil {
		t.Fatalf("a spec of %d bytes was refused: %v", len(spec), err)
	}
	if _, _, got, _, _, _ := DecodeRule(netlink.Message{Data: request.Body}); got != spec {
		t.Errorf("a spec of %d bytes reads back as %d bytes", len(spec), len(got))
	}
}

// A set's comment a byte past nft's comment limit is refused, and one at the
// limit is written and reads back as itself
func TestSetTakesOnlyACommentNftLoadsBack(t *testing.T) {
	s := Set{Table: "ranet3", Name: "flows4", Comment: strings.Repeat("x", udataCommentMax+1)}
	if _, err := s.Create(unix.NFPROTO_IPV4); err == nil {
		t.Errorf("a comment of %d bytes was written", udataCommentMax+1)
	}
	s.Comment = strings.Repeat("x", udataCommentMax)
	request, err := s.Create(unix.NFPROTO_IPV4)
	if err != nil {
		t.Fatalf("a comment of %d bytes was refused: %v", len(s.Comment), err)
	}
	if got := DecodeSet(netlink.Message{Data: request.Body}).Comment; got != s.Comment {
		t.Errorf("a comment of %d bytes reads back as %d bytes", len(s.Comment), len(got))
	}
}

// A rule the kernel hands back carries its counter in the expression list, and
// the counter is of flows rather than of packets: a nat chain is consulted
// once per connection and never again.
func TestCountersComeOutOfTheExpressionList(t *testing.T) {
	var counter []byte
	counter = netlink.PutAttr(counter, unix.NFTA_COUNTER_BYTES, beBytes(4242))
	counter = netlink.PutAttr(counter, unix.NFTA_COUNTER_PACKETS, beBytes(17))
	expressions := slices.Concat(Expression("meta", nil), Expression("counter", counter))
	packets, bytes, counted := counters(expressions)
	if packets != 17 || bytes != 4242 || !counted {
		t.Errorf("read %d flows and %d bytes, counted %v, want 17 and 4242 counted", packets, bytes, counted)
	}
	if _, _, counted := counters(Expression("meta", nil)); counted {
		t.Error("an expression list with no counter reads as counted")
	}
}

func beBytes(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw[:]
}

// Each expression a translator's chains take encodes as the kernel dumps the
// rule nft 1.1.7 writes for the case's name: the connection state and status
// tests of the forward chain, its per-source count and answer, a ct timeout's
// reference, a transport port's load and the translation to an address a
// register holds. The dump adds what the kernel fills in itself, a dynset's
// timeout and flags at 0, and a nat's address maximum in the register of its
// minimum, with its flags at NF_NAT_RANGE_MAP_IPS.
func TestExpressionsCarryTheAttributesNftWrites(t *testing.T) {
	host := func(value uint32) string { return fmt.Sprintf("%x", binary.NativeEndian.AppendUint32(nil, value)) }
	for _, c := range []struct {
		name        string
		expressions [][]byte
		want        []string
	}{
		{"ct state new", CTMatch(unix.NFT_CT_STATE, CTStateNew, unix.NFT_CMP_NEQ), []string{
			"ct 1=00000001 2=00000000",
			"bitwise 1=00000001 2=00000001 3=00000004 4{1=" + host(8) + "} 5{1=00000000}",
			"cmp 1=00000001 2=00000001 3{1=00000000}",
		}},
		{"ct status ! confirmed", CTMatch(unix.NFT_CT_STATUS, CTStatusConfirmed, unix.NFT_CMP_EQ), []string{
			"ct 1=00000001 2=00000002",
			"bitwise 1=00000001 2=00000001 3=00000004 4{1=" + host(8) + "} 5{1=00000000}",
			"cmp 1=00000001 2=00000000 3{1=00000000}",
		}},
		{"add @flows4 { ip saddr ct count over 4096 }", [][]byte{SourceLoad(unix.NFPROTO_IPV4), ConnectionsOver("flows4", 4096)}, []string{
			"payload 1=00000001 2=00000001 3=0000000c 4=00000004",
			`dynset 1="flows4" 3=00000000 4=00000001 7{1="connlimit" 2{1=00001000 2=00000001}}`,
		}},
		{"ip6 saddr", [][]byte{SourceLoad(unix.NFPROTO_IPV6)}, []string{"payload 1=00000001 2=00000001 3=00000008 4=00000010"}},
		{"reject with icmpx admin-prohibited", [][]byte{RejectICMPX(unix.NFT_REJECT_ICMPX_ADMIN_PROHIBITED)}, []string{"reject 1=00000002 2=03"}},
		{`ct timeout set "translated-udp"`, [][]byte{ObjectReference(unix.NFT_OBJECT_CT_TIMEOUT, "translated-udp")}, []string{`objref 1=00000007 2="translated-udp"`}},
		{"udp dport", [][]byte{TransportLoad(2, 2)}, []string{"payload 1=00000001 2=00000002 3=00000002 4=00000002"}},
		{"snat to ip saddr", [][]byte{SourceNAT(unix.NFPROTO_IPV4)}, []string{"nat 1=00000000 2=00000002 3=00000001"}},
	} {
		var got []string
		for _, expression := range c.expressions {
			got = append(got, rendered(t, expression))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s encodes as\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

func rendered(t *testing.T, element []byte) string {
	t.Helper()
	outer := Nested(element)
	if len(outer) != 1 || outer[0].Kind != unix.NFTA_LIST_ELEM {
		t.Fatalf("%x is not one expression", element)
	}
	var name string
	var data []byte
	for _, field := range Nested(outer[0].Value) {
		switch field.Kind {
		case unix.NFTA_EXPR_NAME:
			name = unix.ByteSliceToString(field.Value)
		case unix.NFTA_EXPR_DATA:
			data = field.Value
		}
	}
	return name + " " + renderedAttributes(data)
}

func renderedAttributes(data []byte) string {
	var out []string
	for len(data) >= unix.SizeofRtAttr {
		length, kind := int(binary.NativeEndian.Uint16(data)), binary.NativeEndian.Uint16(data[2:])
		value := data[unix.SizeofRtAttr:length]
		switch {
		case kind&unix.NLA_F_NESTED != 0:
			out = append(out, fmt.Sprintf("%d{%s}", kind&^unix.NLA_F_NESTED, renderedAttributes(value)))
		case len(value) > 1 && value[len(value)-1] == 0 && strings.Trim(string(value[:len(value)-1]), "abcdefghijklmnopqrstuvwxyz0123456789-") == "":
			out = append(out, fmt.Sprintf("%d=%q", kind, value[:len(value)-1]))
		default:
			out = append(out, fmt.Sprintf("%d=%x", kind, value))
		}
		data = data[netlink.AttrAlign(length):]
	}
	slices.SortFunc(out, func(a, b string) int {
		return cmp.Compare(leadingNumber(a), leadingNumber(b))
	})
	return strings.Join(out, " ")
}

func leadingNumber(text string) int {
	n := 0
	for _, r := range text {
		if r < '0' || r > '9' {
			break
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// Only another writer's deletion of the table, a NEWTABLE of it that sets a
// flag or carries none, or a change to one of the owner's chains, a rule in
// one, one of its sets or a set's element wakes the owner. A NEWTABLE of flags
// 0 makes the table or clears its flags, which takes no owner's chain. Its own
// writes reach the notification group stamped with its own socket, and
// another owner's names in the same table, like another table's churn, are
// none of its business.
func TestOnlyAnotherWritersChangeToItsNamesWakes(t *testing.T) {
	const own, other = 7, 9
	tableOnly := func(command int, family uint8, table string, pid uint32) netlink.Message {
		return netlink.Message{Kind: Command(command), Pid: pid, Data: netlink.PutAttrString(PutNfgenmsg(nil, family), unix.NFTA_TABLE_NAME, table)}
	}
	flagged := func(flags uint32) netlink.Message {
		m := tableOnly(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, Table, other)
		m.Data = PutAttrBE32(m.Data, unix.NFTA_TABLE_FLAGS, flags)
		return m
	}
	named := func(command int, tableKind, nameKind uint16, table, name string, pid uint32) netlink.Message {
		return netlink.Message{Kind: Command(command), Pid: pid, Data: netlink.PutAttrString(netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), tableKind, table), nameKind, name)}
	}
	chain := func(command int, name string, pid uint32) netlink.Message {
		return named(command, unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME, Table, name, pid)
	}
	rule := func(command int, table, name string, pid uint32) netlink.Message {
		return named(command, unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, table, name, pid)
	}
	set := func(command int, name string, pid uint32) netlink.Message {
		return named(command, unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME, Table, name, pid)
	}
	element := func(command int, table, name string, pid uint32) netlink.Message {
		return named(command, unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET, table, name, pid)
	}
	for label, c := range map[string]struct {
		message netlink.Message
		wakes   bool
	}{
		"the table deleted":                     {tableOnly(unix.NFT_MSG_DELTABLE, unix.NFPROTO_INET, Table, other), true},
		"the table set dormant":                 {flagged(unix.NFT_TABLE_F_DORMANT), true},
		"the table given the owner flag":        {flagged(0x2), true},
		"the table with no flags attribute":     {tableOnly(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, Table, other), true},
		"the table made or its flags cleared":   {flagged(0), false},
		"its chain deleted":                     {chain(unix.NFT_MSG_DELCHAIN, "forward", other), true},
		"its chain added or changed":            {chain(unix.NFT_MSG_NEWCHAIN, "postrouting", other), true},
		"a chain of its prefix added":           {chain(unix.NFT_MSG_NEWCHAIN, "none_a", other), true},
		"a rule of its chain deleted":           {rule(unix.NFT_MSG_DELRULE, Table, "forward", other), true},
		"a rule added to a chain of its prefix": {rule(unix.NFT_MSG_NEWRULE, Table, "none_b", other), true},
		"its set added":                         {set(unix.NFT_MSG_NEWSET, "flows4", other), true},
		"its set deleted":                       {set(unix.NFT_MSG_DELSET, "flows6", other), true},
		"an element of its set added":           {element(unix.NFT_MSG_NEWSETELEM, Table, "flows4", other), true},
		"an element of its set deleted":         {element(unix.NFT_MSG_DELSETELEM, Table, "flows6", other), true},
		"its own flush":                         {rule(unix.NFT_MSG_DELRULE, Table, "forward", own), false},
		"its own withdrawal":                    {tableOnly(unix.NFT_MSG_DELTABLE, unix.NFPROTO_INET, Table, own), false},
		"its own table":                         {tableOnly(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, Table, own), false},
		"its own refill":                        {element(unix.NFT_MSG_NEWSETELEM, Table, "flows4", own), false},
		"another owner's chain":                 {chain(unix.NFT_MSG_NEWCHAIN, "antispoof", other), false},
		"a rule of another owner's chain":       {rule(unix.NFT_MSG_NEWRULE, Table, "fallback", other), false},
		"another owner's set":                   {set(unix.NFT_MSG_NEWSET, "lan4", other), false},
		"an element of another owner's set":     {element(unix.NFT_MSG_NEWSETELEM, Table, "carved4", other), false},
		"an anonymous set":                      {set(unix.NFT_MSG_NEWSET, "__set0", other), false},
		"a name its prefix ends":                {chain(unix.NFT_MSG_NEWCHAIN, "none", other), false},
		"an element of another table":           {element(unix.NFT_MSG_NEWSETELEM, "nat", "flows4", other), false},
		"a rule added to another table":         {rule(unix.NFT_MSG_NEWRULE, "nat", "forward", other), false},
		"another table deleted":                 {tableOnly(unix.NFT_MSG_DELTABLE, unix.NFPROTO_INET, "nat", other), false},
		"an ip table of its name":               {tableOnly(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_IPV4, Table, other), false},
		"an ip6 table of its name":              {tableOnly(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV6, Table, other), false},
		"a name it starts":                      {tableOnly(unix.NFT_MSG_DELTABLE, unix.NFPROTO_INET, Table+"x", other), false},
		"an object of its table":                {named(unix.NFT_MSG_NEWOBJ, unix.NFTA_OBJ_TABLE, unix.NFTA_OBJ_NAME, Table, "translated-udp4", other), false},
		"another subsystem": {
			netlink.Message{Kind: uint16(unix.NFNL_SUBSYS_CTNETLINK)<<8 | unix.NFT_MSG_DELTABLE, Pid: other, Data: netlink.PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_TABLE_NAME, Table)},
			false,
		},
	} {
		if got := translatorNames.ChangedByAnother(c.message, own); got != c.wakes {
			t.Errorf("%s: woke %v, want %v", label, got, c.wakes)
		}
	}
}

// Each expression of the switch's chain encodes as nft 1.1.7 writes the line
// named for it (`nft --debug=netlink -f`): a lookup by its set's name and ID,
// with flags only when inverted, ct with a direction only for a key the kernel
// requires one of, the mark and the destination's type the fib gives as host
// order words.
func TestFilterExpressionsCarryTheAttributesNftWrites(t *testing.T) {
	forwarded := Set{Name: "forwarded", ID: 1}
	lan4 := Set{Name: "lan4", ID: 2}
	for _, c := range []struct {
		name        string
		expressions [][]byte
		want        []string
	}{
		{"meta mark 0x00000072", MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, 0x72)), []string{
			"meta 1=00000001 2=00000003",
			"cmp 1=00000001 2=00000000 3{1=" + fmt.Sprintf("%x", binary.NativeEndian.AppendUint32(nil, 0x72)) + "}",
		}},
		{"meta iif != 0", MetaCompareValue(unix.NFT_META_IIF, unix.NFT_CMP_NEQ, make([]byte, 4)), []string{
			"meta 1=00000001 2=00000004",
			"cmp 1=00000001 2=00000001 3{1=00000000}",
		}},
		{"iifname != @forwarded", [][]byte{MetaLoad(unix.NFT_META_IIFNAME), Lookup(forwarded, true)}, []string{
			"meta 1=00000001 2=00000006",
			`lookup 1="forwarded" 2=00000001 4=00000001 5=00000001`,
		}},
		{"ip daddr @lan4", slices.Concat(NFProto(unix.NFPROTO_IPV4), [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false)}), []string{
			"meta 1=00000001 2=0000000f",
			"cmp 1=00000001 2=00000000 3{1=02}",
			"payload 1=00000001 2=00000001 3=00000010 4=00000004",
			`lookup 1="lan4" 2=00000001 4=00000002`,
		}},
		{"ip6 daddr", slices.Concat(NFProto(unix.NFPROTO_IPV6), [][]byte{DestinationLoad(unix.NFPROTO_IPV6)}), []string{
			"meta 1=00000001 2=0000000f",
			"cmp 1=00000001 2=00000000 3{1=0a}",
			"payload 1=00000001 2=00000001 3=00000018 4=00000010",
		}},
		{"ct direction reply", [][]byte{CTLoad(unix.NFT_CT_DIRECTION), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{CTReply}))}, []string{
			"ct 1=00000001 2=00000001",
			"cmp 1=00000001 2=00000000 3{1=01}",
		}},
		{"ct protocol tcp", [][]byte{CTLoad(unix.NFT_CT_PROTOCOL), Expression("cmp", Compare(unix.NFT_CMP_EQ, []byte{unix.IPPROTO_TCP}))}, []string{
			"ct 1=00000001 2=0000000a",
			"cmp 1=00000001 2=00000000 3{1=06}",
		}},
		{"ct original proto-dst", [][]byte{CTLoadDirection(unix.NFT_CT_PROTO_DST, CTOriginal)}, []string{"ct 1=00000001 2=0000000c 3=00"}},
		{"fib daddr type local", [][]byte{FibDestinationType(), Expression("cmp", Compare(unix.NFT_CMP_EQ, binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL)))}, []string{
			"fib 1=00000001 2=00000003 3=00000002",
			"cmp 1=00000001 2=00000000 3{1=" + fmt.Sprintf("%x", binary.NativeEndian.AppendUint32(nil, unix.RTN_LOCAL)) + "}",
		}},
		{"accept", [][]byte{Verdict(Accept)}, []string{"immediate 1=00000000 2{2{1=00000001}}"}},
		{"counter drop", CountedDrop(), []string{"counter ", "immediate 1=00000000 2{2{1=00000000}}"}},
		{"goto none", [][]byte{Goto("none")}, []string{`immediate 1=00000000 2{2{1=fffffffc 2="none"}}`}},
	} {
		var got []string
		for _, expression := range c.expressions {
			got = append(got, rendered(t, expression))
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s encodes as\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

// dumped is an expression as a rule dump lists it, its list element and data
// with no NLA_F_NESTED
func dumped(name string, data []byte) []byte {
	return netlink.PutAttr(nil, unix.NFTA_LIST_ELEM, netlink.PutAttr(netlink.PutAttrString(nil, unix.NFTA_EXPR_NAME, name), unix.NFTA_EXPR_DATA, data))
}

// dumpedLookup is a lookup of set as a dump lists it, by name alone with its flags written out
func dumpedLookup(set string, flags uint32) []byte {
	return dumped("lookup", PutAttrBE32(PutAttrBE32(netlink.PutAttrString(nil, unix.NFTA_LOOKUP_SET, set), unix.NFTA_LOOKUP_SREG, unix.NFT_REG_1), unix.NFTA_LOOKUP_FLAGS, flags))
}

// dumpedCompare is an equality test against value as a dump lists it
func dumpedCompare(value []byte) []byte {
	return dumped("cmp", netlink.PutAttr(PutAttrBE32(PutAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1), unix.NFTA_CMP_OP, unix.NFT_CMP_EQ), unix.NFTA_CMP_DATA, netlink.PutAttr(nil, unix.NFTA_DATA_VALUE, value)))
}

// dumpedVerdict is a verdict as a dump lists it
func dumpedVerdict(code uint32) []byte {
	data := netlink.PutAttr(nil, unix.NFTA_DATA_VERDICT, PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	return dumped("immediate", netlink.PutAttr(PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT), unix.NFTA_IMMEDIATE_DATA, data))
}

// dumpedGoto is a goto to chain as a dump lists it
func dumpedGoto(chain string) []byte {
	data := netlink.PutAttr(nil, unix.NFTA_DATA_VERDICT, netlink.PutAttrString(PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, gotoCode), unix.NFTA_VERDICT_CHAIN, chain))
	return dumped("immediate", netlink.PutAttr(PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT), unix.NFTA_IMMEDIATE_DATA, data))
}

// A rule's expressions as a dump lists them read as written where the dump
// names a lookup's set and not its ID, writes its flags at zero, numbers an
// anonymous set, counts in a counter and nests without NLA_F_NESTED, and as a
// fault where a lookup's inversion is dropped or added, a comparison's data or
// a verdict differs, a goto names another chain, an expression is gone, or a
// lookup names another set
func TestExpressionFaultTellsAnEditFromADumpsSpelling(t *testing.T) {
	forwarded, lan4 := Set{Name: "forwarded", ID: 1}, Set{Name: "lan4", ID: 2}
	mark := binary.NativeEndian.AppendUint32(nil, 0x72)
	notForwarded := [][]byte{MetaLoad(unix.NFT_META_IIFNAME), Lookup(forwarded, true), Verdict(Accept)}
	toTheLAN := [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false), Verdict(Accept)}
	marked := slices.Concat(MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, mark), [][]byte{Verdict(Accept)})
	counted := netlink.PutAttr(netlink.PutAttr(nil, unix.NFTA_COUNTER_BYTES, beBytes(180)), unix.NFTA_COUNTER_PACKETS, beBytes(3))
	for _, c := range []struct {
		name    string
		written [][]byte
		held    [][]byte
		differs bool
	}{
		{"the dump's spelling of an inverted lookup", notForwarded,
			[][]byte{MetaLoad(unix.NFT_META_IIFNAME), dumpedLookup("forwarded", unix.NFT_LOOKUP_F_INV), dumpedVerdict(Accept)}, false},
		{"the dump's spelling of a lookup with its flags at zero", toTheLAN,
			[][]byte{DestinationLoad(unix.NFPROTO_IPV4), dumpedLookup("lan4", 0), dumpedVerdict(Accept)}, false},
		{"an anonymous set the kernel numbered", [][]byte{MetaLoad(unix.NFT_META_OIFNAME), Lookup(Anonymous("t", 10, TypeIfname, unix.IFNAMSIZ, 0), false), Verdict(Accept)},
			[][]byte{MetaLoad(unix.NFT_META_OIFNAME), dumpedLookup("__set3", 0), dumpedVerdict(Accept)}, false},
		{"a counter that has counted", CountedDrop(), [][]byte{dumped("counter", counted), dumpedVerdict(Drop)}, false},
		{"a comparison as a dump spells it", marked, [][]byte{MetaLoad(unix.NFT_META_MARK), dumpedCompare(mark), dumpedVerdict(Accept)}, false},
		{"the inversion dropped", notForwarded, [][]byte{MetaLoad(unix.NFT_META_IIFNAME), dumpedLookup("forwarded", 0), dumpedVerdict(Accept)}, true},
		{"an inversion added", toTheLAN, [][]byte{DestinationLoad(unix.NFPROTO_IPV4), dumpedLookup("lan4", unix.NFT_LOOKUP_F_INV), dumpedVerdict(Accept)}, true},
		{"another comparison's data", marked, [][]byte{MetaLoad(unix.NFT_META_MARK), dumpedCompare(binary.NativeEndian.AppendUint32(nil, 0x73)), dumpedVerdict(Accept)}, true},
		{"another verdict", marked, [][]byte{MetaLoad(unix.NFT_META_MARK), dumpedCompare(mark), dumpedVerdict(Drop)}, true},
		{"a goto as a dump spells it", [][]byte{Goto("none_a")}, [][]byte{dumpedGoto("none_a")}, false},
		{"a goto to another chain", [][]byte{Goto("none_a")}, [][]byte{dumpedGoto("none_b")}, true},
		{"an expression gone", notForwarded, [][]byte{dumpedLookup("forwarded", unix.NFT_LOOKUP_F_INV), dumpedVerdict(Accept)}, true},
		{"another set looked up", toTheLAN, [][]byte{DestinationLoad(unix.NFPROTO_IPV4), dumpedLookup("lan6", 0), dumpedVerdict(Accept)}, true},
	} {
		fault := ExpressionFault(c.written, slices.Concat(c.held...))
		if (fault != "") != c.differs {
			t.Errorf("%s reads back with the fault %q, want one %v", c.name, fault, c.differs)
		}
	}
}

// Each interval set's elements are those nft 1.1.7 writes for the set's line,
// as `nft --debug=netlink -f` prints them: the leading end at zero, a start
// and the end after each interval, and an interval to the last key left open
// with the userdata that has nft print it whole
func TestIntervalElementsAreThoseNftWrites(t *testing.T) {
	for _, c := range []struct {
		name      string
		set       Set
		intervals []Interval
		want      []string
	}{
		{
			"ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 }",
			Anonymous("t", 1, TypeIPv4Addr, 4, unix.NFT_SET_INTERVAL),
			Prefixes([]netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32")}),
			[]string{"00000000 end", "a9fe0000", "a9ff0000 end", "e0000000", "f0000000 end", "ffffffff open"},
		},
		{
			"lan4 { 198.51.100.0/24, 203.0.113.0/25, 192.0.2.128/26 }",
			Set{Name: "lan4", KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
			Prefixes([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/25"), netip.MustParsePrefix("192.0.2.128/26")}),
			[]string{"00000000 end", "c0000280", "c00002c0 end", "c6336400", "c6336500 end", "cb007100", "cb007180 end"},
		},
		{
			"lan4 { 192.0.2.0/25, 192.0.2.128/25 }, touching halves written as one interval",
			Set{Name: "lan4", KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL},
			Prefixes([]netip.Prefix{netip.MustParsePrefix("192.0.2.128/25"), netip.MustParsePrefix("192.0.2.0/25")}),
			[]string{"00000000 end", "c0000200", "c0000300 end"},
		},
		{
			"lan6 { 2001:db8::/33, 2001:db8:8000::/33 }, touching halves written as one interval",
			Set{Name: "lan6", KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
			Prefixes([]netip.Prefix{netip.MustParsePrefix("2001:db8::/33"), netip.MustParsePrefix("2001:db8:8000::/33")}),
			[]string{"00000000000000000000000000000000 end", "20010db8000000000000000000000000", "20010db9000000000000000000000000 end"},
		},
		{
			"lan6 { ::/16, ff00::/8 }",
			Set{Name: "lan6", KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL},
			Prefixes([]netip.Prefix{netip.MustParsePrefix("::/16"), netip.MustParsePrefix("ff00::/8")}),
			[]string{"00000000000000000000000000000000", "00010000000000000000000000000000 end", "ff000000000000000000000000000000 open"},
		},
		{
			"ct original proto-dst { 22, 60000-61000 }",
			Anonymous("t", 3, TypeInetService, 2, unix.NFT_SET_INTERVAL),
			[]Interval{{First: []byte{0xea, 0x60}, Last: []byte{0xee, 0x48}}, Key([]byte{0, 22})},
			[]string{"0000 end", "0016", "0017 end", "ea60", "ee49 end"},
		},
	} {
		elements, err := c.set.elements(c.intervals)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		for _, e := range elements {
			text := fmt.Sprintf("%x", e.key)
			if e.flags == unix.NFT_SET_ELEM_INTERVAL_END {
				text += " end"
			}
			if slices.Equal(e.userdata, []byte{1, 4, 1, 0, 0, 0}) {
				text += " open"
			} else if e.userdata != nil {
				text += fmt.Sprintf(" userdata %x", e.userdata)
			}
			got = append(got, text)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s writes\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(c.want, "\n"))
		}
	}
}

// Another writer's elements read back as the keys a lookup finds, handed back
// in rbtree's descending order: two touching intervals whose end and start
// share a key read as one, an end with no start before it holds nothing, and
// a start with no end after it runs to the last key
func TestElementsReadBackAsALookupFindsThem(t *testing.T) {
	s := Set{Name: "lan4", KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	key := func(address string) []byte { return netlink.AddressBytes(netip.MustParseAddr(address)) }
	var list []byte
	for _, e := range []element{
		{key: key("203.0.113.0")},
		{key: key("198.51.101.0"), flags: unix.NFT_SET_ELEM_INTERVAL_END},
		{key: key("198.51.100.0")},
		{key: key("198.51.100.0"), flags: unix.NFT_SET_ELEM_INTERVAL_END},
		{key: key("192.0.2.0")},
		{key: key("0.0.0.0"), flags: unix.NFT_SET_ELEM_INTERVAL_END},
	} {
		list = append(list, e.encode()...)
	}
	dump := netlink.Message{Data: netlink.PutAttr(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, list)}
	got := s.decodeElements([]netlink.Message{dump})
	want := []Interval{
		{First: key("192.0.2.0"), Last: key("198.51.100.255")},
		{First: key("203.0.113.0"), Last: key("255.255.255.255")},
	}
	if s.elementFault(want, got) != "" {
		t.Errorf("read back as %s, want %s", s.describe(got), s.describe(want))
	}
}

// Fill refuses a key of another length than the set's and an interval in a
// set that holds single keys, which the kernel would take as two keys or
// refuse with an error naming neither
func TestFillRefusesWhatTheSetCannotHold(t *testing.T) {
	ranged := Set{Name: "lan4", KeyType: TypeIPv4Addr, KeyLen: 4, Flags: unix.NFT_SET_INTERVAL}
	if _, err := ranged.Fill(unix.NFPROTO_INET, Prefixes([]netip.Prefix{netip.MustParsePrefix("2001:db8::/32")})); err == nil {
		t.Error("an IPv4 set took an IPv6 interval")
	}
	names := Set{Name: "forwarded", KeyType: TypeIfname, KeyLen: unix.IFNAMSIZ}
	if _, err := names.Fill(unix.NFPROTO_INET, []Interval{{First: InterfaceName("lan1"), Last: InterfaceName("lan2")}}); err == nil {
		t.Error("a set of single names took an interval")
	}
	if requests, err := names.Fill(unix.NFPROTO_INET, nil); err != nil || len(requests) != 0 {
		t.Errorf("an empty fill sent %d messages (%v), want none, since the kernel refuses a message of no elements", len(requests), err)
	}
}

// A set too large for one message's elements attribute fills over several, each
// attribute's length within what a netlink attribute can say, and reads back
// whole
func TestFillSplitsWhatOneAttributeCannotSay(t *testing.T) {
	s := Set{Table: "t", Name: "lan6", KeyType: TypeIPv6Addr, KeyLen: 16, Flags: unix.NFT_SET_INTERVAL}
	var prefixes []netip.Prefix
	for i := range 3000 {
		raw := netip.MustParseAddr("2001:db8::").As16()
		binary.BigEndian.PutUint16(raw[4:], uint16(2*i))
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom16(raw), 48))
	}
	intervals := Prefixes(prefixes)
	if len(intervals) != 3000 {
		t.Fatalf("3000 apart /48s are %d intervals", len(intervals))
	}
	requests, err := s.Fill(unix.NFPROTO_INET, intervals)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) < 2 {
		t.Fatalf("6001 elements went in %d message", len(requests))
	}
	var dump []netlink.Message
	for _, request := range requests {
		for kind, value := range (netlink.Message{Data: request.Body}).Attributes(SizeofNfgenmsg) {
			if kind == unix.NFTA_SET_ELEM_LIST_ELEMENTS && unix.SizeofRtAttr+len(value) > math.MaxUint16 {
				t.Errorf("an elements attribute of %d bytes", unix.SizeofRtAttr+len(value))
			}
		}
		dump = append(dump, netlink.Message{Data: request.Body})
	}
	if fault := s.elementFault(intervals, s.decodeElements(dump)); fault != "" {
		t.Error(fault)
	}
}
