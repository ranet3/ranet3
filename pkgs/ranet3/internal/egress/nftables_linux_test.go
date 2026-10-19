// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"encoding/binary"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// expressionNames is the rule's expression list in order, the sequence a
// packet is evaluated against. The encoder is checked against it rather than
// against a byte string, so a test says what the rule does rather than
// restating the encoding.
func expressionNames(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for kind, value := range (nftMessage{Data: body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			for _, field := range nested(element.value) {
				if field.kind == unix.NFTA_EXPR_NAME {
					out = append(out, unix.ByteSliceToString(field.value))
				}
			}
		}
	}
	return out
}

// A rule reaches the kernel as the expressions its comment describes, in the
// order a packet meets them: both interfaces, then the narrowing, then the
// counter, then the translation.
func TestRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	for _, one := range []struct {
		name string
		rule Rule
		want []string
	}{
		{
			"out of the mesh under the host's own address",
			Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "masq"},
		},
		{
			"out of the mesh under a configured address",
			Rule{Family: FamilyIPv6, Direction: Out, Interface: "ranet0", Source: netip.MustParseAddr("2001:db8::1")},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "immediate", "nat"},
		},
		{
			"out of the egress device",
			Rule{Family: FamilyIPv6, Direction: Out, Interface: "ranet0", Egress: "ranet0e"},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "masq"},
		},
		{
			"into the mesh from one prefix",
			Rule{Family: FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.0/24"), Source: netip.MustParseAddr("10.88.0.2")},
			// The leading pair is the local-origin test an inbound rule
			// carries. See TestInboundRuleExcludesThisNodesOwnTraffic.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate", "nat"},
		},
		{
			"into the mesh from one host",
			Rule{Family: FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.7/32"), Source: netip.MustParseAddr("10.88.0.2")},
			// No bitwise: a prefix as long as the address masks nothing.
			[]string{"meta", "cmp", "meta", "cmp", "meta", "cmp", "payload", "cmp", "counter", "immediate", "nat"},
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			request, err := newRule(one.rule)
			if err != nil {
				t.Fatal(err)
			}
			if got := expressionNames(t, request.body); !slices.Equal(got, one.want) {
				t.Errorf("encoded %q, want %q", got, one.want)
			}
			table, chain, spec, _, _ := decodeRule(nftMessage{Data: request.body})
			if table != TableName || chain != ChainName {
				t.Errorf("wrote into %s/%s, want %s/%s", table, chain, TableName, ChainName)
			}
			if spec != one.rule.String() {
				t.Errorf("the rule reads back as %q, want %q, so the diff would rewrite it forever", spec, one.rule.String())
			}
		})
	}
}

// An interface name is compared over the whole IFNAMSIZ the kernel pads it to.
// A shorter comparison matches every device whose name starts the same way, so
// a rule for "ranet0" would also claim traffic on "ranet01".
func TestInterfaceComparisonCoversTheWholePaddedName(t *testing.T) {
	request, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			var name string
			var data []byte
			for _, field := range nested(element.value) {
				switch field.kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.value)
				case unix.NFTA_EXPR_DATA:
					data = field.value
				}
			}
			if name != "cmp" {
				continue
			}
			for _, field := range nested(data) {
				if field.kind != unix.NFTA_CMP_DATA {
					continue
				}
				for _, inner := range nested(field.value) {
					if inner.kind != unix.NFTA_DATA_VALUE {
						continue
					}
					found++
					if len(inner.value) != ifNameSize {
						t.Errorf("compared %d bytes of the name, want %d", len(inner.value), ifNameSize)
					}
					if unix.ByteSliceToString(inner.value) != "ranet0" {
						t.Errorf("compared against %q", inner.value)
					}
				}
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d interface comparisons, want one per direction", found)
	}
}

// The two interface tests carry opposite operators, which is the whole of the
// direction: a rule that compared both the same way would translate mesh
// transit, whose packets arrive on the mesh device and leave by it again.
func TestDirectionInvertsBothInterfaceTests(t *testing.T) {
	for _, one := range []struct {
		direction Direction
		want      []uint32
	}{
		{Out, []uint32{unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ}},
		// The leading NEQ is the local-origin test, which both directions of
		// the interface pair follow.
		{In, []uint32{unix.NFT_CMP_NEQ, unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ}},
	} {
		t.Run(one.direction.String(), func(t *testing.T) {
			request, err := newRule(Rule{Family: FamilyIPv4, Direction: one.direction, Interface: "ranet0"})
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
				if kind != unix.NFTA_RULE_EXPRESSIONS {
					continue
				}
				for _, element := range nested(value) {
					var name string
					var data []byte
					for _, field := range nested(element.value) {
						switch field.kind {
						case unix.NFTA_EXPR_NAME:
							name = unix.ByteSliceToString(field.value)
						case unix.NFTA_EXPR_DATA:
							data = field.value
						}
					}
					if name != "cmp" {
						continue
					}
					for _, field := range nested(data) {
						if field.kind == unix.NFTA_CMP_OP && len(field.value) == 4 {
							got = append(got, binary.BigEndian.Uint32(field.value))
						}
					}
				}
			}
			if !slices.Equal(got, one.want) {
				t.Errorf("compared with %v, want %v", got, one.want)
			}
		})
	}
}

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
	if got := prefixMask(netip.MustParsePrefix("2001:db8::/48")); len(got) != ipv6AddressLen {
		t.Errorf("an IPv6 mask is %d bytes, want %d", len(got), ipv6AddressLen)
	}
}

// A rule's identity travels in its own comment, so the diff reads back the
// spelling it wrote rather than re-deriving it from the expressions.
func TestCommentRoundTripsThroughUserdata(t *testing.T) {
	spec := Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"}.String()
	if got := comment(userdata(spec)); got != spec {
		t.Errorf("read back %q, want %q", got, spec)
	}
	// Another writer's userdata comes first in the same blob. Skipping it by
	// its length rather than assuming the comment is first is the difference
	// between a rule this package recognizes and one it reinstalls forever.
	blob := append([]byte{7, 3, 'a', 'b', 'c'}, userdata(spec)...)
	if got := comment(blob); got != spec {
		t.Errorf("read back %q past another writer's entry, want %q", got, spec)
	}
	if got := comment([]byte{0, 9, 'a'}); got != "" {
		t.Errorf("a truncated entry read as %q", got)
	}
}

// A rule the kernel hands back carries its counter in the expression list, and
// the counter is of flows rather than of packets: a nat chain is consulted
// once per connection and never again.
func TestCountersComeOutOfTheExpressionList(t *testing.T) {
	var counter []byte
	counter = putAttr(counter, unix.NFTA_COUNTER_BYTES, beBytes(4242))
	counter = putAttr(counter, unix.NFTA_COUNTER_PACKETS, beBytes(17))
	expressions := slices.Concat(expression("meta", nil), expression("counter", counter))
	packets, bytes := counters(expressions)
	if packets != 17 || bytes != 4242 {
		t.Errorf("read %d flows and %d bytes, want 17 and 4242", packets, bytes)
	}
}

func beBytes(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw[:]
}

// A comment longer than the host will hold is refused rather than truncated,
// because a truncated comment is a rule this package no longer recognizes and
// would replace on every pass for the life of the node.
func TestRuleWithAnOversizedCommentIsRefused(t *testing.T) {
	long := strings.Repeat("x", udataCommentMax)
	_, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: long})
	if err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
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

// The chain is a nat base chain at the source translation hook, which is where
// every other source translation on the host runs too. A number nothing else
// uses would not avoid the overlap, only decide whether this node translates
// before or after whatever the operator arranged on purpose.
func TestChainIsNatAtTheSourceTranslationHook(t *testing.T) {
	request := newChain(FamilyIPv4)
	table, chain, kind, hook, priority := decodeChain(nftMessage{Data: request.body})
	if table != TableName || chain != ChainName {
		t.Errorf("created %s/%s, want %s/%s", table, chain, TableName, ChainName)
	}
	if kind != "nat" {
		t.Errorf("created a %q chain, want nat", kind)
	}
	if hook != unix.NF_INET_POST_ROUTING {
		t.Errorf("hooked at %d, want postrouting (%d)", hook, unix.NF_INET_POST_ROUTING)
	}
	if priority != natSrcPriority {
		t.Errorf("hooked at priority %d, want %d", priority, natSrcPriority)
	}
}

// Emptying the chain names a table and a chain and no handle, which nf_tables
// reads as every rule in that chain. It can reach no other table, which is the
// ownership claim this package makes.
func TestFlushNamesOnlyThisToolsOwnChain(t *testing.T) {
	request := flushChain(FamilyIPv6)
	var table, chain string
	handles := 0
	for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_HANDLE:
			handles++
		}
	}
	if table != TableName || chain != ChainName {
		t.Errorf("would empty %s/%s, want %s/%s", table, chain, TableName, ChainName)
	}
	if handles != 0 {
		t.Errorf("named %d handles, which would delete one rule rather than the chain", handles)
	}
}

// A packet this host generated itself has no arrival interface, which
// nf_tables reports as the empty name rather than as a failure to read, so
// "iifname is not the mesh device" is true of it. An inbound rule left at that
// would translate this node's own mesh traffic to the return source, which on
// an exit is an address belonging to somebody else. The rule rules it out by
// interface index, which reads as zero for a locally generated packet on every
// kernel that answers the question at all.
func TestInboundRuleExcludesThisNodesOwnTraffic(t *testing.T) {
	inbound, err := newRule(Rule{Family: FamilyIPv4, Direction: In, Interface: "ranet0",
		Source: netip.MustParseAddr("10.88.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	keys := metaKeys(t, inbound.body)
	if len(keys) == 0 || keys[0] != unix.NFT_META_IIF {
		t.Fatalf("an inbound rule loads %v, want the interface index first", keys)
	}

	// An outbound rule needs none of it: a locally generated packet fails
	// "iifname is the mesh device" whichever way the kernel answers.
	outbound, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"})
	if err != nil {
		t.Fatal(err)
	}
	if got := metaKeys(t, outbound.body); slices.Contains(got, uint32(unix.NFT_META_IIF)) {
		t.Errorf("an outbound rule loads %v, which it has no test to make of the index", got)
	}
}

// metaKeys is the metadatum each meta expression loads, in order.
func metaKeys(t *testing.T, body []byte) []uint32 {
	t.Helper()
	var out []uint32
	for kind, value := range (nftMessage{Data: body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			var name string
			var data []byte
			for _, field := range nested(element.value) {
				switch field.kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.value)
				case unix.NFTA_EXPR_DATA:
					data = field.value
				}
			}
			if name != "meta" {
				continue
			}
			for _, field := range nested(data) {
				if field.kind == unix.NFTA_META_KEY && len(field.value) == 4 {
					out = append(out, binary.BigEndian.Uint32(field.value))
				}
			}
		}
	}
	return out
}

// A name too long to be a device's is refused rather than truncated. The
// kernel pads an interface register to IFNAMSIZ with a terminator, so a
// sixteen byte comparison without one can never equal it: the rule would
// install and then match nothing, or in the inbound direction everything.
func TestOversizedInterfaceNameIsRefused(t *testing.T) {
	_, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", ifNameSize)})
	if err == nil || !strings.Contains(err.Error(), "device name is at most") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
	if _, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: strings.Repeat("r", ifNameSize-1)}); err != nil {
		t.Errorf("the longest name a device can have was refused: %v", err)
	}
}

// Only another writer's deletion or addition of this tool's table, of a chain
// in it or of a rule in it wakes the translator, a table update setting it
// dormant among them. Its own writes reach the notification group stamped
// with its own socket, and another table's churn is none of its business.
func TestOnlyAnotherWritersChangeToTheTableWakes(t *testing.T) {
	const own, other = 7, 9
	notification := func(command int, family uint8, naming uint16, table string, pid uint32) nftMessage {
		return nftMessage{
			Kind: nftCommand(command),
			Pid:  pid,
			Data: putAttrString(putNfgenmsg(nil, family), naming, table),
		}
	}
	for name, c := range map[string]struct {
		message nftMessage
		wakes   bool
	}{
		"its table deleted":              {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, TableName, other), true},
		"its chain deleted":              {notification(unix.NFT_MSG_DELCHAIN, unix.NFPROTO_IPV6, unix.NFTA_CHAIN_TABLE, TableName, other), true},
		"a rule of it deleted":           {notification(unix.NFT_MSG_DELRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, TableName, other), true},
		"its table added or set dormant": {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, TableName, other), true},
		"a chain added or changed":       {notification(unix.NFT_MSG_NEWCHAIN, unix.NFPROTO_IPV6, unix.NFTA_CHAIN_TABLE, TableName, other), true},
		"a rule added":                   {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, TableName, other), true},
		"its own flush":                  {notification(unix.NFT_MSG_DELRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, TableName, own), false},
		"its own withdrawal":             {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV6, unix.NFTA_TABLE_NAME, TableName, own), false},
		"its own table":                  {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, TableName, own), false},
		"its own rule":                   {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV6, unix.NFTA_RULE_TABLE, TableName, own), false},
		"another table deleted":          {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, "nat", other), false},
		"a rule added to another table":  {notification(unix.NFT_MSG_NEWRULE, unix.NFPROTO_IPV4, unix.NFTA_RULE_TABLE, "nat", other), false},
		"an inet table of its name":      {notification(unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, unix.NFTA_TABLE_NAME, TableName, other), false},
		"a name it starts":               {notification(unix.NFT_MSG_DELTABLE, unix.NFPROTO_IPV4, unix.NFTA_TABLE_NAME, TableName+"x", other), false},
		"another subsystem": {
			nftMessage{Kind: uint16(unix.NFNL_SUBSYS_CTNETLINK)<<8 | unix.NFT_MSG_DELTABLE, Pid: other, Data: putAttrString(putNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, TableName)},
			false,
		},
	} {
		if got := changedByAnother(c.message, own, translatorTables); got != c.wakes {
			t.Errorf("%s: woke %v, want %v", name, got, c.wakes)
		}
	}
}

// The monitor wakes missed and not changed for notifications it lost to an
// overflow or could not parse, since another table's large transaction
// overflows the socket as readily as a flush of this tool's, wakes changed
// for another writer's deletion of this tool's table, and stops on a closed
// socket, each wake read through the backend as the translator reads it
func TestMonitorTellsLostNotificationsFromADeletion(t *testing.T) {
	const own, other = 7, 9
	type answer struct {
		datagram []byte
		err      error
	}
	answers := make(chan answer)
	asked := make(chan struct{})
	m := &changeMonitor{
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
		for deadline := time.After(passWait); ; {
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
		case <-time.After(passWait):
			t.Fatal("the monitor never read again")
		}
	}
	var be backend = &nftables{monitor: m}
	woke := func(signal <-chan struct{}) bool {
		select {
		case <-signal:
			return true
		default:
			return false
		}
	}
	deletion := (&nftConn{pid: other}).appendMessage(nil, nftCommand(unix.NFT_MSG_DELTABLE), 0, 1,
		putAttrString(putNfgenmsg(nil, unix.NFPROTO_IPV4), unix.NFTA_TABLE_NAME, TableName))
	next()
	for _, c := range []struct {
		name            string
		answer          answer
		changed, missed bool
	}{
		{"an overflow", answer{err: unix.ENOBUFS}, false, true},
		{"a datagram cut short", answer{datagram: deletion[:unix.SizeofNlMsghdr+sizeofNfgenmsg]}, false, true},
		{"another writer deleting its table", answer{datagram: deletion}, true, false},
	} {
		answers <- c.answer
		next()
		if changed, missed := woke(be.Changed()), woke(be.Missed()); changed != c.changed || missed != c.missed {
			t.Errorf("%s woke changed %v and missed %v, want %v and %v", c.name, changed, missed, c.changed, c.missed)
		}
	}
	answers <- answer{err: os.ErrClosed}
	select {
	case <-m.done:
	case <-asked:
		t.Fatal("the monitor read on after its socket closed")
	case <-time.After(passWait):
		t.Fatal("the monitor never returned after its socket closed")
	}
	if woke(be.Changed()) || woke(be.Missed()) {
		t.Error("a closed socket woke the translator")
	}
}
