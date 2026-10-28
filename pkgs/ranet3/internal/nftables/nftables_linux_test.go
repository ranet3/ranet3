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
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// monitorWait bounds a wait on the monitor's goroutine
const monitorWait = 30 * time.Second

// translatorTables is a scope of the shape the translator watches, the ip and
// ip6 tables of one name
var translatorTables = Scope{Name: "ranet3", Families: []uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}}

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

// A rule's identity travels in its own comment, so the diff reads back the
// spelling it wrote rather than re-deriving it from the expressions, and a
// set's comment travels under a type of its own.
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
	if _, _, got, _, _, _ := DecodeRule(Message{Data: request.Body}); got != spec {
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
	if got := DecodeSet(Message{Data: request.Body}).Comment; got != s.Comment {
		t.Errorf("a comment of %d bytes reads back as %d bytes", len(s.Comment), len(got))
	}
}

// A rule the kernel hands back carries its counter in the expression list, and
// the counter is of flows rather than of packets: a nat chain is consulted
// once per connection and never again.
func TestCountersComeOutOfTheExpressionList(t *testing.T) {
	var counter []byte
	counter = PutAttr(counter, unix.NFTA_COUNTER_BYTES, beBytes(4242))
	counter = PutAttr(counter, unix.NFTA_COUNTER_PACKETS, beBytes(17))
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
		{"reject with icmp admin-prohibited", [][]byte{RejectUnreachable(13)}, []string{"reject 1=00000000 2=0d"}},
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
			out = append(out, fmt.Sprintf("%d{%s}", kind&nlaTypeMask, renderedAttributes(value)))
		case len(value) > 1 && value[len(value)-1] == 0 && strings.Trim(string(value[:len(value)-1]), "abcdefghijklmnopqrstuvwxyz0123456789-") == "":
			out = append(out, fmt.Sprintf("%d=%q", kind, value[:len(value)-1]))
		default:
			out = append(out, fmt.Sprintf("%d=%x", kind, value))
		}
		data = data[rtaAlign(length):]
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

// A datagram whose message claims to run past its end is an error rather than
// a short read, so a truncated dump can never look like a complete one and a
// diff built on it can never withdraw a rule that is still there.
func TestMalformedMessageLengthIsRefused(t *testing.T) {
	buf := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(buf, uint32(len(buf)+64))
	if _, err := parseMessages(buf); err == nil {
		t.Fatal("a message running past its datagram was accepted")
	}
}

// Only another writer's deletion or addition of the owner's table, of a chain,
// a rule, a set or a set's element in it wakes the owner, a table update
// setting it dormant among them. Its own writes reach the notification group stamped with its
// own socket, and another table's churn is none of its business.
func TestOnlyAnotherWritersChangeToTheTableWakes(t *testing.T) {
	const own, other = 7, 9
	const name = "ranet3"
	notification := func(command int, family uint8, naming uint16, table string, pid uint32) Message {
		return Message{
			Kind: Command(command),
			Pid:  pid,
			Data: PutAttrString(PutNfgenmsg(nil, family), naming, table),
		}
	}
	for label, c := range map[string]struct {
		message Message
		wakes   bool
	}{
		"its table deleted":              {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, name, other), true},
		"its chain deleted":              {notification(unix.NFT_MSG_DELCHAIN, unix.NFPROTO_IPV6, unix.NFTA_CHAIN_TABLE, name, other), true},
		"a rule of it deleted":           {notification(unix.NFT_MSG_DELRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, name, other), true},
		"its table added or set dormant": {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, name, other), true},
		"a chain added or changed":       {notification(unix.NFT_MSG_NEWCHAIN, unix.NFPROTO_IPV6, unix.NFTA_CHAIN_TABLE, name, other), true},
		"a rule added":                   {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, name, other), true},
		"its own flush":                  {notification(unix.NFT_MSG_DELRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, name, own), false},
		"its own withdrawal":             {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV6, unix.NFTA_TABLE_NAME, name, own), false},
		"its own table":                  {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, name, own), false},
		"its own rule":                   {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV6, unix.NFTA_RULE_TABLE, name, own), false},
		"a set added":                    {notification(unix.NFT_MSG_NEWSET, unix.NFPROTO_IPV4, unix.NFTA_SET_TABLE, name, other), true},
		"a set deleted":                  {notification(unix.NFT_MSG_DELSET, unix.NFPROTO_IPV6, unix.NFTA_SET_TABLE, name, other), true},
		"an element added":               {notification(unix.NFT_MSG_NEWSETELEM, unix.NFPROTO_IPV4, unix.NFTA_SET_ELEM_LIST_TABLE, name, other), true},
		"an element deleted":             {notification(unix.NFT_MSG_DELSETELEM, unix.NFPROTO_IPV6, unix.NFTA_SET_ELEM_LIST_TABLE, name, other), true},
		"its own refill":                 {notification(unix.NFT_MSG_NEWSETELEM, unix.NFPROTO_IPV4, unix.NFTA_SET_ELEM_LIST_TABLE, name, own), false},
		"an element of another table":    {notification(unix.NFT_MSG_NEWSETELEM, unix.NFPROTO_IPV4, unix.NFTA_SET_ELEM_LIST_TABLE, "nat", other), false},
		"another table deleted":          {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, "nat", other), false},
		"a rule added to another table":  {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, "nat", other), false},
		"an inet table of its name":      {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, unix.NFTA_TABLE_NAME, name, other), false},
		"a name it starts":               {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, name+"x", other), false},
		"another subsystem": {
			Message{Kind: uint16(unix.NFNL_SUBSYS_CTNETLINK)<<8 | unix.NFT_MSG_DELTABLE, Pid: other, Data: PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, name)},
			false,
		},
	} {
		if got := translatorTables.ChangedByAnother(c.message, own); got != c.wakes {
			t.Errorf("%s: woke %v, want %v", label, got, c.wakes)
		}
	}
}

// The monitor wakes missed and not changed for notifications it lost to an
// overflow or could not parse, since another table's large transaction
// overflows the socket as readily as a flush of the owner's, wakes changed
// for another writer's deletion of the owner's table, and stops on a closed
// socket
func TestMonitorTellsLostNotificationsFromADeletion(t *testing.T) {
	const own, other = 7, 9
	type answer struct {
		datagram []byte
		err      error
	}
	answers := make(chan answer)
	asked := make(chan struct{})
	m := &Monitor{
		read: func(buf []byte) (int, error) {
			asked <- struct{}{}
			a, ok := <-answers
			if !ok {
				return 0, os.ErrClosed
			}
			return copy(buf, a.datagram), a.err
		},
		pid:     own,
		scope:   translatorTables,
		changed: make(chan struct{}, 1),
		missed:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go m.run()
	t.Cleanup(func() {
		close(answers)
		for deadline := time.After(monitorWait); ; {
			select {
			case <-asked:
			case <-m.done:
				return
			case <-deadline:
				return
			}
		}
	})
	next := func() {
		t.Helper()
		select {
		case <-asked:
		case <-m.done:
			t.Fatal("the monitor stopped reading")
		case <-time.After(monitorWait):
			t.Fatal("the monitor never read again")
		}
	}
	woke := func(signal <-chan struct{}) bool {
		select {
		case <-signal:
			return true
		default:
			return false
		}
	}
	deletion := (&Conn{pid: other}).appendMessage(nil, Command(unix.NFT_MSG_DELTABLE), 0, 1,
		PutAttrString(PutNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, translatorTables.Name))
	next()
	for _, c := range []struct {
		name            string
		answer          answer
		changed, missed bool
	}{
		{"an overflow", answer{err: unix.ENOBUFS}, false, true},
		{"a datagram cut short", answer{datagram: deletion[:unix.SizeofNlMsghdr+SizeofNfgenmsg]}, false, true},
		{"another writer deleting its table", answer{datagram: deletion}, true, false},
	} {
		answers <- c.answer
		next()
		if changed, missed := woke(m.Changed()), woke(m.Missed()); changed != c.changed || missed != c.missed {
			t.Errorf("%s woke changed %v and missed %v, want %v and %v", c.name, changed, missed, c.changed, c.missed)
		}
	}
	answers <- answer{err: os.ErrClosed}
	select {
	case <-m.done:
	case <-asked:
		t.Fatal("the monitor read on after its socket closed")
	case <-time.After(monitorWait):
		t.Fatal("the monitor never returned after its socket closed")
	}
	if woke(m.Changed()) || woke(m.Missed()) {
		t.Error("a closed socket woke the owner")
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
	return PutAttr(nil, unix.NFTA_LIST_ELEM, PutAttr(PutAttrString(nil, unix.NFTA_EXPR_NAME, name), unix.NFTA_EXPR_DATA, data))
}

// dumpedLookup is a lookup of set as a dump lists it, by name alone with its flags written out
func dumpedLookup(set string, flags uint32) []byte {
	return dumped("lookup", PutAttrBE32(PutAttrBE32(PutAttrString(nil, unix.NFTA_LOOKUP_SET, set), unix.NFTA_LOOKUP_SREG, unix.NFT_REG_1), unix.NFTA_LOOKUP_FLAGS, flags))
}

// dumpedCompare is an equality test against value as a dump lists it
func dumpedCompare(value []byte) []byte {
	return dumped("cmp", PutAttr(PutAttrBE32(PutAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1), unix.NFTA_CMP_OP, unix.NFT_CMP_EQ), unix.NFTA_CMP_DATA, PutAttr(nil, unix.NFTA_DATA_VALUE, value)))
}

// dumpedVerdict is a verdict as a dump lists it
func dumpedVerdict(code uint32) []byte {
	data := PutAttr(nil, unix.NFTA_DATA_VERDICT, PutAttrBE32(nil, unix.NFTA_VERDICT_CODE, code))
	return dumped("immediate", PutAttr(PutAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_VERDICT), unix.NFTA_IMMEDIATE_DATA, data))
}

// A rule's expressions as a dump lists them read as written where the dump
// names a lookup's set and not its ID, writes its flags at zero, numbers an
// anonymous set, counts in a counter and nests without NLA_F_NESTED, and as a
// fault where a lookup's inversion is dropped or added, a comparison's data or
// a verdict differs, an expression is gone, or a lookup names another set
func TestExpressionFaultTellsAnEditFromADumpsSpelling(t *testing.T) {
	forwarded, lan4 := Set{Name: "forwarded", ID: 1}, Set{Name: "lan4", ID: 2}
	mark := binary.NativeEndian.AppendUint32(nil, 0x72)
	notForwarded := [][]byte{MetaLoad(unix.NFT_META_IIFNAME), Lookup(forwarded, true), Verdict(Accept)}
	toTheLAN := [][]byte{DestinationLoad(unix.NFPROTO_IPV4), Lookup(lan4, false), Verdict(Accept)}
	marked := slices.Concat(MetaCompareValue(unix.NFT_META_MARK, unix.NFT_CMP_EQ, mark), [][]byte{Verdict(Accept)})
	counted := PutAttr(PutAttr(nil, unix.NFTA_COUNTER_BYTES, beBytes(180)), unix.NFTA_COUNTER_PACKETS, beBytes(3))
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
	key := func(address string) []byte { return AddressBytes(netip.MustParseAddr(address)) }
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
	dump := Message{Data: PutAttr(PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_ELEM_LIST_ELEMENTS|unix.NLA_F_NESTED, list)}
	got := s.decodeElements([]Message{dump})
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
	var dump []Message
	for _, request := range requests {
		for kind, value := range (Message{Data: request.Body}).Attributes() {
			if kind == unix.NFTA_SET_ELEM_LIST_ELEMENTS && unix.SizeofRtAttr+len(value) > math.MaxUint16 {
				t.Errorf("an elements attribute of %d bytes", unix.SizeofRtAttr+len(value))
			}
		}
		dump = append(dump, Message{Data: request.Body})
	}
	if fault := s.elementFault(intervals, s.decodeElements(dump)); fault != "" {
		t.Error(fault)
	}
}
