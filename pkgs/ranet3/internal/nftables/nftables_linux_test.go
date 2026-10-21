// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
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
// spelling it wrote rather than re-deriving it from the expressions.
func TestCommentRoundTripsThroughUserdata(t *testing.T) {
	const spec = "ipv4 out via ranet0 masquerade"
	if got := comment(userdata(spec)); got != spec {
		t.Errorf("read back %q, want %q", got, spec)
	}
	// Another writer's userdata comes first in the same blob. Skipping it by
	// its length rather than assuming the comment is first is the difference
	// between a rule its owner recognizes and one it reinstalls forever.
	blob := append([]byte{7, 3, 'a', 'b', 'c'}, userdata(spec)...)
	if got := comment(blob); got != spec {
		t.Errorf("read back %q past another writer's entry, want %q", got, spec)
	}
	if got := comment([]byte{0, 9, 'a'}); got != "" {
		t.Errorf("a truncated entry read as %q", got)
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
	if _, _, got, _, _ := DecodeRule(Message{Data: request.Body}); got != spec {
		t.Errorf("a spec of %d bytes reads back as %d bytes", len(spec), len(got))
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

// Only another writer's deletion or addition of the owner's table, of a chain
// in it or of a rule in it wakes the owner, a table update setting it dormant
// among them. Its own writes reach the notification group stamped with its
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
