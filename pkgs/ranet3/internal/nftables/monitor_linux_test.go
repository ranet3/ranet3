// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// monitorWait bounds a wait on the monitor's goroutine
const monitorWait = 30 * time.Second

// the ports the kernel stamps on the notifications of the owner's socket and
// of two other writers'
const ownPort, otherPort, thirdPort = 7, 9, 11

// monitorRead is one read of the monitor's socket, the datagram it returns or
// its error
type monitorRead struct {
	datagram []byte
	err      error
}

// fedMonitor is a monitor of translatorTables owned through ownPort whose
// every read waits for the test's answer
type fedMonitor struct {
	*Monitor
	answers chan monitorRead
	asked   chan struct{}
}

func feedMonitor(t *testing.T) *fedMonitor {
	t.Helper()
	f := &fedMonitor{answers: make(chan monitorRead), asked: make(chan struct{})}
	f.Monitor = &Monitor{
		read: func(buf []byte) (int, error) {
			f.asked <- struct{}{}
			a, ok := <-f.answers
			if !ok {
				return 0, os.ErrClosed
			}
			return copy(buf, a.datagram), a.err
		},
		pid:     ownPort,
		scope:   translatorTables,
		changed: make(chan struct{}, 1),
		missed:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go f.run()
	t.Cleanup(func() {
		close(f.answers)
		for deadline := time.After(monitorWait); ; {
			select {
			case <-f.asked:
			case <-f.done:
				return
			case <-deadline:
				return
			}
		}
	})
	f.next(t)
	return f
}

// next waits for the monitor's next read, which it asks for once it has acted
// on the last
func (f *fedMonitor) next(t *testing.T) {
	t.Helper()
	select {
	case <-f.asked:
	case <-f.done:
		t.Fatal("the monitor stopped reading")
	case <-time.After(monitorWait):
		t.Fatal("the monitor never read again")
	}
}

// answer hands the monitor read and reports what it woke for it, taking each
// wake as its owner does
func (f *fedMonitor) answer(t *testing.T, read monitorRead) (changed, missed bool) {
	t.Helper()
	f.answers <- read
	f.next(t)
	return woke(f.Changed()), woke(f.Missed())
}

func woke(signal <-chan struct{}) bool {
	select {
	case <-signal:
		return true
	default:
		return false
	}
}

// notifications is count notifications of kind in family, each naming table
type notifications struct {
	count  int
	kind   int
	family uint8
	table  string
}

// naming is the attribute each kind of notification names its table in
var naming = map[int]uint16{
	unix.NFT_MSG_NEWTABLE: unix.NFTA_TABLE_NAME, unix.NFT_MSG_DELTABLE: unix.NFTA_TABLE_NAME,
	unix.NFT_MSG_NEWCHAIN: unix.NFTA_CHAIN_TABLE, unix.NFT_MSG_DELCHAIN: unix.NFTA_CHAIN_TABLE,
	unix.NFT_MSG_NEWRULE: unix.NFTA_RULE_TABLE, unix.NFT_MSG_DELRULE: unix.NFTA_RULE_TABLE,
	unix.NFT_MSG_NEWSET: unix.NFTA_SET_TABLE, unix.NFT_MSG_DELSET: unix.NFTA_SET_TABLE,
	unix.NFT_MSG_NEWSETELEM: unix.NFTA_SET_ELEM_LIST_TABLE,
	unix.NFT_MSG_NEWOBJ:     unix.NFTA_OBJ_TABLE, unix.NFT_MSG_DELOBJ: unix.NFTA_OBJ_TABLE,
}

// transaction is the reads of one transaction written through port, each
// datagram's notifications stamped with generation in nfgenmsg's res_id as
// the kernel stamps them, then NFT_MSG_NEWGEN in a datagram of its own
func transaction(port uint32, generation uint16, datagrams ...[]notifications) []monitorRead {
	stamped := func(family uint8) []byte {
		return binary.BigEndian.AppendUint16([]byte{family, nfnetlinkV0}, generation)
	}
	conn := &Conn{pid: port}
	var reads []monitorRead
	for _, datagram := range datagrams {
		var buf []byte
		for _, n := range datagram {
			for range n.count {
				buf = conn.appendMessage(buf, Command(n.kind), 0, 0, PutAttrString(stamped(n.family), naming[n.kind], n.table))
			}
		}
		reads = append(reads, monitorRead{datagram: buf})
	}
	end := PutAttr(stamped(unix.NFPROTO_UNSPEC), unix.NFTA_GEN_ID, binary.BigEndian.AppendUint32(nil, uint32(generation)))
	return append(reads, monitorRead{datagram: conn.appendMessage(nil, Command(unix.NFT_MSG_NEWGEN), 0, 0, end)})
}

// The datagrams linux 7.3.1 sent for the translator's ip and ip6 tables, 23
// and 19 rules, a set, two chains and three timeouts each, and for nft 1.1.7
// writing a firewall's inet table
var (
	installed = [][]notifications{
		{ip(1, unix.NFT_MSG_NEWTABLE), ip(3, unix.NFT_MSG_NEWOBJ), ip(1, unix.NFT_MSG_NEWSET), ip(2, unix.NFT_MSG_NEWCHAIN), ip(4, unix.NFT_MSG_NEWRULE)},
		{ip(6, unix.NFT_MSG_NEWRULE)},
		{ip(7, unix.NFT_MSG_NEWRULE)},
		{ip(6, unix.NFT_MSG_NEWRULE), ip6(1, unix.NFT_MSG_NEWTABLE), ip6(3, unix.NFT_MSG_NEWOBJ), ip6(1, unix.NFT_MSG_NEWSET), ip6(2, unix.NFT_MSG_NEWCHAIN)},
		{ip6(6, unix.NFT_MSG_NEWRULE)},
		{ip6(7, unix.NFT_MSG_NEWRULE)},
		{ip6(6, unix.NFT_MSG_NEWRULE)},
	}
	deleted = [][]notifications{
		{ip(6, unix.NFT_MSG_DELRULE)},
		{ip(6, unix.NFT_MSG_DELRULE)},
		{ip(7, unix.NFT_MSG_DELRULE)},
		{ip(4, unix.NFT_MSG_DELRULE), ip(1, unix.NFT_MSG_DELSET), ip(3, unix.NFT_MSG_DELOBJ), ip(2, unix.NFT_MSG_DELCHAIN), ip(1, unix.NFT_MSG_DELTABLE), ip6(2, unix.NFT_MSG_DELRULE)},
		{ip6(6, unix.NFT_MSG_DELRULE)},
		{ip6(7, unix.NFT_MSG_DELRULE)},
		{ip6(4, unix.NFT_MSG_DELRULE), ip6(1, unix.NFT_MSG_DELSET), ip6(3, unix.NFT_MSG_DELOBJ), ip6(2, unix.NFT_MSG_DELCHAIN), ip6(1, unix.NFT_MSG_DELTABLE)},
	}
	// flushed is nft -f of flush ruleset and the firewall's table, whose last
	// datagram holds the firewall's notifications alone
	flushed = slices.Concat(deleted[:6], [][]notifications{
		append(slices.Clone(deleted[6]), firewall(1, unix.NFT_MSG_NEWTABLE), firewall(3, unix.NFT_MSG_NEWCHAIN), firewall(2, unix.NFT_MSG_NEWRULE), firewall(1, unix.NFT_MSG_NEWSET), firewall(3, unix.NFT_MSG_NEWSETELEM)),
		{firewall(2, unix.NFT_MSG_NEWRULE), firewall(1, unix.NFT_MSG_NEWSET), firewall(5, unix.NFT_MSG_NEWSETELEM), firewall(1, unix.NFT_MSG_NEWRULE)},
	})
	// the deletions of the ip table, then of the ip6 table, by two writers one
	// after the other
	deletedIP = [][]notifications{
		{ip(6, unix.NFT_MSG_DELRULE)},
		{ip(6, unix.NFT_MSG_DELRULE)},
		{ip(7, unix.NFT_MSG_DELRULE)},
		{ip(4, unix.NFT_MSG_DELRULE), ip(1, unix.NFT_MSG_DELSET), ip(3, unix.NFT_MSG_DELOBJ), ip(2, unix.NFT_MSG_DELCHAIN), ip(1, unix.NFT_MSG_DELTABLE)},
	}
	deletedIP6 = [][]notifications{
		{ip6(6, unix.NFT_MSG_DELRULE)},
		{ip6(7, unix.NFT_MSG_DELRULE)},
		{ip6(6, unix.NFT_MSG_DELRULE), ip6(1, unix.NFT_MSG_DELSET), ip6(3, unix.NFT_MSG_DELOBJ), ip6(2, unix.NFT_MSG_DELCHAIN), ip6(1, unix.NFT_MSG_DELTABLE)},
	}
)

func ip(count, kind int) notifications {
	return notifications{count, kind, unix.NFPROTO_IPV4, translatorTables.Name}
}

func ip6(count, kind int) notifications {
	return notifications{count, kind, unix.NFPROTO_IPV6, translatorTables.Name}
}

func firewall(count, kind int) notifications {
	return notifications{count, kind, unix.NFPROTO_INET, "nixos-fw"}
}

// drained is the read that finds the socket's queue empty
var drained = monitorRead{err: unix.EAGAIN}

// readAsSent is reads as a monitor that keeps up with the kernel reads them,
// each followed by a read that finds the queue empty
func readAsSent(reads []monitorRead) []monitorRead {
	var kept []monitorRead
	for _, read := range reads {
		kept = append(kept, read, drained)
	}
	return kept
}

// One transaction of another writer's that changes the owner's tables wakes
// Changed once, at the NFT_MSG_NEWGEN that ends it, however many datagrams its
// notifications fill and however often the monitor finds the queue empty
// between them, and the owner's own transactions and another table's wake
// nothing. A wake for each datagram would take the owner's readiness again
// after the pass that put its rules back.
func TestMonitorWakesOnceAtTheEndOfAnotherWritersTransaction(t *testing.T) {
	for _, c := range []struct {
		name  string
		reads []monitorRead
		// changed is each read after which Changed woke
		changed []int
	}{
		{"another writer's deletion of both tables", transaction(otherPort, 3, deleted...), []int{7}},
		{"another writer's deletion read as the kernel sends it", readAsSent(transaction(otherPort, 3, deleted...)), []int{14}},
		{"a ruleset flush that writes a firewall's table", transaction(otherPort, 3, flushed...), []int{8}},
		{"another writer's one rule", transaction(otherPort, 3, []notifications{ip(1, unix.NFT_MSG_NEWRULE)}), []int{1}},
		{"two writers' deletions back to back", slices.Concat(transaction(otherPort, 3, deletedIP...), transaction(thirdPort, 4, deletedIP6...)), []int{4, 8}},
		{"the owner's install", transaction(ownPort, 2, installed...), nil},
		{"the owner's withdrawal", transaction(ownPort, 5, deleted...), nil},
		{"another writer's firewall table alone", transaction(otherPort, 3, flushed[7]), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := feedMonitor(t)
			var changed []int
			for i, read := range c.reads {
				woke, missed := m.answer(t, read)
				if missed {
					t.Errorf("read %d of %d woke Missed", i, len(c.reads))
				}
				if woke {
					changed = append(changed, i)
				}
			}
			if !slices.Equal(changed, c.changed) {
				t.Errorf("Changed woke after reads %v of %d, want %v", changed, len(c.reads), c.changed)
			}
		})
	}
}

// The kernel reports an overflow ahead of the datagrams still queued and
// drops every later one until a read finds the queue empty, so the end of any
// transaction in that backlog may be gone. So a loss wakes Changed for the
// change read before it, clears it and wakes Missed, each change read up to
// the drain wakes Changed at once, a second loss in that span ends nothing,
// and a transaction read after the drain wakes Changed once at its own end.
func TestMonitorWakesChangedAtOnceFromALossToTheDrain(t *testing.T) {
	deletion := transaction(otherPort, 3, deleted...)
	objects, end := deletion[:len(deletion)-1], deletion[len(deletion)-1:]
	install := transaction(ownPort, 4, installed...)
	flush := transaction(otherPort, 5, flushed...)
	rule := transaction(otherPort, 5, []notifications{ip(1, unix.NFT_MSG_NEWRULE)})
	deletionIP := transaction(otherPort, 3, deletedIP...)
	deletionIP6 := transaction(thirdPort, 4, deletedIP6...)
	drain := []monitorRead{drained}
	cut := end[0].datagram
	for _, loss := range []struct {
		name string
		read monitorRead
	}{
		{"an overflow", monitorRead{err: unix.ENOBUFS}},
		{"a datagram cut short", monitorRead{datagram: cut[:len(cut)-1]}},
	} {
		lost := []monitorRead{loss.read}
		for _, c := range []struct {
			name  string
			reads []monitorRead
			// changed and missed are each read after which Changed and Missed
			// woke
			changed, missed []int
		}{
			{"ahead of a deletion's objects", slices.Concat(lost, deletion, drain, flush), []int{1, 2, 3, 4, 5, 6, 7, 18}, []int{0}},
			{"in the middle of a deletion", slices.Concat(deletion[:3], lost, deletion[3:], drain, rule), []int{3, 4, 5, 6, 7, 11}, []int{3}},
			{"ahead of a deletion's end", slices.Concat(objects, lost, end, drain, install, rule), []int{7, 19}, []int{7}},
			{"that took a deletion's end", slices.Concat(lost, objects, drain, install, flush), []int{1, 2, 3, 4, 5, 6, 7, 25}, []int{0}},
			{"that took the second of two writers' ends", slices.Concat(lost, deletionIP, deletionIP6[:len(deletionIP6)-1], drain, install, rule), []int{1, 2, 3, 4, 6, 7, 8, 19}, []int{0}},
			{"with nothing queued behind it", slices.Concat(lost, drain, flush), []int{10}, []int{0}},
			{"and a second in its span", slices.Concat(lost, deletion[:3], lost, deletion[3:], drain, flush), []int{1, 2, 3, 5, 6, 7, 8, 19}, []int{0, 4}},
		} {
			t.Run(loss.name+" "+c.name, func(t *testing.T) {
				m := feedMonitor(t)
				var changed, missed []int
				for i, read := range c.reads {
					woke, wokeMissed := m.answer(t, read)
					if woke {
						changed = append(changed, i)
					}
					if wokeMissed {
						missed = append(missed, i)
					}
				}
				if !slices.Equal(changed, c.changed) {
					t.Errorf("Changed woke after reads %v of %d, want %v", changed, len(c.reads), c.changed)
				}
				if !slices.Equal(missed, c.missed) {
					t.Errorf("Missed woke after reads %v of %d, want %v", missed, len(c.reads), c.missed)
				}
			})
		}
	}
}

// A read error other than an overflow or a closed socket stops the monitor
// and wakes Missed, and Changed only for a change read before it, so the
// owner marks its rules not ready ahead of the pass that reads such a change
// back
func TestMonitorWakesMissedAndAnyChangeReadBeforeAReadErrorAndStops(t *testing.T) {
	deletion := transaction(otherPort, 3, deleted...)
	for _, c := range []struct {
		name    string
		before  []monitorRead
		changed bool
	}{
		{"after another writer's objects", deletion[:len(deletion)-1], true},
		{"with no change read", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := feedMonitor(t)
			for i, read := range c.before {
				if changed, missed := m.answer(t, read); changed || missed {
					t.Fatalf("read %d of the transaction's objects woke Changed %v and Missed %v", i, changed, missed)
				}
			}
			m.answers <- monitorRead{err: unix.EIO}
			select {
			case <-m.done:
			case <-m.asked:
				t.Fatal("the monitor read on after a read error")
			case <-time.After(monitorWait):
				t.Fatal("the monitor never returned after a read error")
			}
			if changed, missed := woke(m.Changed()), woke(m.Missed()); changed != c.changed || !missed {
				t.Errorf("a read error %s woke Changed %v and Missed %v, want %v and true", c.name, changed, missed, c.changed)
			}
		})
	}
}

// The monitor wakes Missed, and Changed only for a change read before them,
// for notifications it lost to an overflow or could not parse, since another
// table's large transaction overflows the socket as readily as a flush of the
// owner's. After such a loss, with no read since finding the queue empty, it
// wakes Changed at once for another writer's deletion of the owner's table
// and nothing at that transaction's end, and it stops on a closed socket
func TestMonitorTellsLostNotificationsFromADeletion(t *testing.T) {
	m := feedMonitor(t)
	deletion := transaction(otherPort, 3, []notifications{ip(1, unix.NFT_MSG_DELTABLE)})
	for _, c := range []struct {
		name            string
		read            monitorRead
		changed, missed bool
	}{
		{"an overflow", monitorRead{err: unix.ENOBUFS}, false, true},
		{"a datagram cut short", monitorRead{datagram: deletion[0].datagram[:unix.SizeofNlMsghdr+SizeofNfgenmsg]}, false, true},
		{"another writer deleting its table", deletion[0], true, false},
		{"the end of that writer's transaction", deletion[1], false, false},
	} {
		if changed, missed := m.answer(t, c.read); changed != c.changed || missed != c.missed {
			t.Errorf("%s woke changed %v and missed %v, want %v and %v", c.name, changed, missed, c.changed, c.missed)
		}
	}
	m.answers <- monitorRead{err: os.ErrClosed}
	select {
	case <-m.done:
	case <-m.asked:
		t.Fatal("the monitor read on after its socket closed")
	case <-time.After(monitorWait):
		t.Fatal("the monitor never returned after its socket closed")
	}
	if woke(m.Changed()) || woke(m.Missed()) {
		t.Error("a closed socket woke the owner")
	}
}

// The monitor's read of a socket hands each queued datagram over, returns
// EAGAIN once when it finds the queue empty, then waits for the next
// datagram, and tells Close as os.ErrClosed, so run ends a loss's span at
// each drain and stops on Close
func TestMonitorReadTellsEachDrainOnceThenWaits(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := fds[1]
	t.Cleanup(func() { _ = unix.Close(peer) })
	file := os.NewFile(uintptr(fds[0]), "monitor-read")
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	send := func(datagram string) {
		t.Helper()
		if _, err := unix.Write(peer, []byte(datagram)); err != nil {
			t.Fatal(err)
		}
	}
	send("one")
	send("two")
	m := &Monitor{file: file, done: make(chan struct{})}
	type result struct {
		datagram string
		err      error
	}
	results := make(chan result, 8)
	go func() {
		defer close(m.done)
		read := m.drainingRead(raw)
		buf := make([]byte, 16)
		for {
			n, err := read(buf)
			results <- result{string(buf[:n]), err}
			if err != nil && !errors.Is(err, unix.EAGAIN) {
				return
			}
		}
	}()
	t.Cleanup(func() {
		m.closing.Store(true)
		_ = file.Close()
	})
	expect := func(want result) {
		t.Helper()
		select {
		case got := <-results:
			if got.datagram != want.datagram || !errors.Is(got.err, want.err) {
				t.Fatalf("read %q and %v, want %q and %v", got.datagram, got.err, want.datagram, want.err)
			}
		case <-time.After(monitorWait):
			t.Fatalf("no read within %s, want %q and %v", monitorWait, want.datagram, want.err)
		}
	}
	waits := func() {
		t.Helper()
		select {
		case got := <-results:
			t.Fatalf("the read after a drain returned %q and %v, want it to wait for a datagram", got.datagram, got.err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	expect(result{"one", nil})
	expect(result{"two", nil})
	expect(result{"", unix.EAGAIN})
	waits()
	send("three")
	expect(result{"three", nil})
	expect(result{"", unix.EAGAIN})
	waits()
	if err := m.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
	expect(result{"", os.ErrClosed})
}
