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

// the ports the kernel stamps on the notifications of the owner's socket, of
// two other writers' and of another owner's of the table
const ownPort, otherPort, thirdPort, siblingPort = 7, 9, 11, 13

// monitorRead is one read of the monitor's socket, the datagram it returns or
// its error
type monitorRead struct {
	datagram []byte
	err      error
}

// timeoutObjects are the kernel exit's ct timeout objects, in the order the
// kernel notifies them
var timeoutObjects = []string{"translated-udp4", "translated-tcp4", "translated-icmp4", "translated-udp6", "translated-tcp6", "translated-icmpv66"}

// kernelExitNames is the scope the kernel exit's monitor watched where the
// datagrams below were read
var kernelExitNames = Scope{Chains: []string{"forward", "forward6", "postrouting", "forward4"}, Prefix: "none_", Sets: []string{"flows4", "flows6"}, Timeouts: timeoutObjects}

// fedMonitor is a monitor of kernelExitNames owned through ownPort whose
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
		scope:   kernelExitNames,
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
// and, where its kind names one, the chain or set name, and a NEWTABLE the
// table's flags
type notifications struct {
	count  int
	kind   int
	family uint8
	table  string
	name   string
	flags  uint32
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

// named is the attribute each kind of notification names its chain, set or
// object in
var named = map[int]uint16{
	unix.NFT_MSG_NEWCHAIN: unix.NFTA_CHAIN_NAME, unix.NFT_MSG_DELCHAIN: unix.NFTA_CHAIN_NAME,
	unix.NFT_MSG_NEWRULE: unix.NFTA_RULE_CHAIN, unix.NFT_MSG_DELRULE: unix.NFTA_RULE_CHAIN,
	unix.NFT_MSG_NEWSET: unix.NFTA_SET_NAME, unix.NFT_MSG_DELSET: unix.NFTA_SET_NAME,
	unix.NFT_MSG_NEWSETELEM: unix.NFTA_SET_ELEM_LIST_SET,
	unix.NFT_MSG_NEWOBJ:     unix.NFTA_OBJ_NAME, unix.NFT_MSG_DELOBJ: unix.NFTA_OBJ_NAME,
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
			attributes := PutAttrString(stamped(n.family), naming[n.kind], n.table)
			if attribute, ok := named[n.kind]; ok && n.name != "" {
				attributes = PutAttrString(attributes, attribute, n.name)
			}
			// the kernel puts the table's flags in every NEWTABLE and in no DELTABLE (nf_tables_fill_table_info)
			if n.kind == unix.NFT_MSG_NEWTABLE {
				attributes = PutAttrBE32(attributes, unix.NFTA_TABLE_FLAGS, n.flags)
			}
			for range n.count {
				buf = conn.appendMessage(buf, Command(n.kind), 0, 0, attributes)
			}
		}
		reads = append(reads, monitorRead{datagram: buf})
	}
	end := PutAttr(stamped(unix.NFPROTO_UNSPEC), unix.NFTA_GEN_ID, binary.BigEndian.AppendUint32(nil, uint32(generation)))
	return append(reads, monitorRead{datagram: conn.appendMessage(nil, Command(unix.NFT_MSG_NEWGEN), 0, 0, end)})
}

// The datagrams linux 7.3.1 sent to the kernel exit's monitor under auto for
// its table inet Table of 42 rules in the chains forward, forward6 and
// postrouting, two sets and six timeout objects, each datagram's notifications
// in the order the kernel sent them, and for nft 1.1.7 flushing the ruleset
// and writing a firewall's inet table in one transaction
var (
	// installed is the exit's install, and deleted another writer's deletion
	// of the table, for which the exit's own withdrawal sends the same
	// datagrams
	installed = [][]notifications{
		slices.Concat([]notifications{exit(1, unix.NFT_MSG_NEWTABLE, ""), exit(1, unix.NFT_MSG_NEWCHAIN, "forward"), exit(1, unix.NFT_MSG_NEWCHAIN, "forward6"), exit(1, unix.NFT_MSG_NEWCHAIN, "postrouting")},
			objects(unix.NFT_MSG_NEWOBJ, timeoutObjects...),
			[]notifications{exit(1, unix.NFT_MSG_NEWSET, "flows4"), exit(1, unix.NFT_MSG_NEWSET, "flows6"), exit(4, unix.NFT_MSG_NEWRULE, "forward")}),
		{exit(5, unix.NFT_MSG_NEWRULE, "forward")},
		{exit(3, unix.NFT_MSG_NEWRULE, "forward"), exit(3, unix.NFT_MSG_NEWRULE, "postrouting")},
		{exit(6, unix.NFT_MSG_NEWRULE, "postrouting")},
		{exit(3, unix.NFT_MSG_NEWRULE, "postrouting"), exit(3, unix.NFT_MSG_NEWRULE, "forward6")},
		{exit(4, unix.NFT_MSG_NEWRULE, "forward6"), exit(1, unix.NFT_MSG_NEWRULE, "postrouting")},
		{exit(6, unix.NFT_MSG_NEWRULE, "postrouting")},
		{exit(5, unix.NFT_MSG_NEWRULE, "postrouting")},
	}
	deleted = [][]notifications{
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward6")},
		{exit(1, unix.NFT_MSG_DELRULE, "forward6"), exit(5, unix.NFT_MSG_DELRULE, "postrouting")},
		{exit(6, unix.NFT_MSG_DELRULE, "postrouting")},
		{exit(7, unix.NFT_MSG_DELRULE, "postrouting")},
		slices.Concat([]notifications{exit(6, unix.NFT_MSG_DELRULE, "postrouting"), exit(1, unix.NFT_MSG_DELSET, "flows4"), exit(1, unix.NFT_MSG_DELSET, "flows6")},
			objects(unix.NFT_MSG_DELOBJ, timeoutObjects[:4]...)),
		slices.Concat(objects(unix.NFT_MSG_DELOBJ, timeoutObjects[4:]...), dropped),
	}
	// flushed is nft -f of flush ruleset and the firewall's table, whose
	// notifications follow the deletion's in its last datagram
	flushed = append(slices.Clone(deleted[:7]), slices.Concat(deleted[7], []notifications{
		firewall(1, unix.NFT_MSG_NEWTABLE, ""), firewall(1, unix.NFT_MSG_NEWCHAIN, "input-allow"), firewall(1, unix.NFT_MSG_NEWCHAIN, "input"), firewall(1, unix.NFT_MSG_NEWCHAIN, "forward"),
		firewall(2, unix.NFT_MSG_NEWRULE, "input-allow"), firewall(1, unix.NFT_MSG_NEWSET, "__set0"), firewall(3, unix.NFT_MSG_NEWSETELEM, "__set0"), firewall(1, unix.NFT_MSG_NEWRULE, "input-allow"),
		firewall(1, unix.NFT_MSG_NEWRULE, "input"), firewall(1, unix.NFT_MSG_NEWSET, "__map0"), firewall(5, unix.NFT_MSG_NEWSETELEM, "__map0"), firewall(1, unix.NFT_MSG_NEWRULE, "input"),
	}))
	// ruled is nft -f of one rule added to postrouting
	ruled = [][]notifications{{exit(1, unix.NFT_MSG_NEWRULE, "postrouting")}}
	// flushedChain and deletedAfter are two writers one after the other, the
	// first flushing postrouting and the second deleting the table
	flushedChain = slices.Repeat([][]notifications{{exit(6, unix.NFT_MSG_DELRULE, "postrouting")}}, 4)
	deletedAfter = [][]notifications{
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward6")},
		slices.Concat([]notifications{exit(1, unix.NFT_MSG_DELRULE, "forward6"), exit(1, unix.NFT_MSG_DELSET, "flows4"), exit(1, unix.NFT_MSG_DELSET, "flows6")},
			objects(unix.NFT_MSG_DELOBJ, timeoutObjects...), dropped),
	}
	// keyedTable is keysTable's transaction of 1024 keys into Table as it
	// stands, which notifies no table
	keyedTable = keyed(Table, false, slices.Concat([]int{45}, slices.Repeat([]int{47}, 20), []int{39})...)
)

// The datagrams linux 7.3.1 sent to the kernel exit's monitor under auto with
// the antispoof filter in its namespace, the two owning Table, and to an
// owner's monitor of the chain forward in Table alone, for nft 1.1.7 as
// another writer
var (
	// reloaded is nft -f of flush ruleset and a firewall's inet table over
	// both owners' chains, and remade the filter's pass after it, which makes
	// the table again with a NEWTABLE of flags 0
	reloaded = [][]notifications{
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward")},
		{exit(6, unix.NFT_MSG_DELRULE, "forward6")},
		{exit(1, unix.NFT_MSG_DELRULE, "forward6"), exit(5, unix.NFT_MSG_DELRULE, "postrouting")},
		{exit(6, unix.NFT_MSG_DELRULE, "postrouting")},
		{exit(7, unix.NFT_MSG_DELRULE, "postrouting")},
		{exit(6, unix.NFT_MSG_DELRULE, "postrouting"), exit(1, unix.NFT_MSG_DELRULE, "antispoof")},
		{exit(3, unix.NFT_MSG_DELRULE, "antispoof"), exit(8, unix.NFT_MSG_DELRULE, "mesh_entry")},
		slices.Concat([]notifications{exit(2, unix.NFT_MSG_DELRULE, "mesh_entry"), exit(1, unix.NFT_MSG_DELSET, "flows4"), exit(1, unix.NFT_MSG_DELSET, "flows6")},
			objects(unix.NFT_MSG_DELSET, antispoofSets...), objects(unix.NFT_MSG_DELOBJ, timeoutObjects...),
			objects(unix.NFT_MSG_DELCHAIN, "forward", "forward6", "postrouting", "antispoof", "mesh_entry"),
			[]notifications{exit(1, unix.NFT_MSG_DELTABLE, ""), firewall(1, unix.NFT_MSG_NEWTABLE, ""), firewall(1, unix.NFT_MSG_NEWCHAIN, "input-allow"), firewall(1, unix.NFT_MSG_NEWCHAIN, "input"),
				firewall(1, unix.NFT_MSG_NEWCHAIN, "forward"), firewall(2, unix.NFT_MSG_NEWRULE, "input-allow"), firewall(1, unix.NFT_MSG_NEWSET, "__set0"), firewall(3, unix.NFT_MSG_NEWSETELEM, "__set0"),
				firewall(1, unix.NFT_MSG_NEWRULE, "input-allow")}),
		{firewall(1, unix.NFT_MSG_NEWRULE, "input"), firewall(1, unix.NFT_MSG_NEWSET, "__map0"), firewall(5, unix.NFT_MSG_NEWSETELEM, "__map0"), firewall(1, unix.NFT_MSG_NEWRULE, "input")},
	}
	remade = [][]notifications{
		slices.Concat([]notifications{flagged(0), exit(1, unix.NFT_MSG_NEWCHAIN, "antispoof"), exit(1, unix.NFT_MSG_NEWCHAIN, "mesh_entry")},
			objects(unix.NFT_MSG_NEWSET, antispoofSets...), []notifications{exit(4, unix.NFT_MSG_NEWRULE, "antispoof"), exit(3, unix.NFT_MSG_NEWRULE, "mesh_entry")}),
		{exit(7, unix.NFT_MSG_NEWRULE, "mesh_entry")},
	}
	// slept is nft add table inet Table setting the flag dormant over both
	// owners' chains, and woken the filter's pass after it, whose NewTable clears the
	// flag with a NEWTABLE of flags 0
	slept = [][]notifications{{flagged(unix.NFT_TABLE_F_DORMANT)}}
	woken = [][]notifications{
		{flagged(0), exit(1, unix.NFT_MSG_NEWCHAIN, "antispoof"), exit(4, unix.NFT_MSG_DELRULE, "antispoof"), exit(1, unix.NFT_MSG_NEWCHAIN, "mesh_entry"), exit(6, unix.NFT_MSG_DELRULE, "mesh_entry")},
		slices.Concat([]notifications{exit(4, unix.NFT_MSG_DELRULE, "mesh_entry")}, objects(unix.NFT_MSG_NEWSET, antispoofSets...),
			[]notifications{exit(4, unix.NFT_MSG_NEWRULE, "antispoof"), exit(1, unix.NFT_MSG_NEWRULE, "mesh_entry")}),
		{exit(9, unix.NFT_MSG_NEWRULE, "mesh_entry")},
	}
	// cleared is nft add table inet Table { } over the table set dormant
	cleared = [][]notifications{{flagged(0)}}
)

// antispoofSets are the antispoof filter's sets, in the order the kernel
// notifies them
var antispoofSets = []string{"carved4", "carved6", "owned4", "owned6", "none4", "none6"}

// flooded is keysTable's transaction of 256 keys into another table, which it makes
func flooded(table string) [][]notifications { return keyed(table, true, 44, 47, 47, 47, 47, 24) }

// dropped is the end of a deletion of the table: its chains, then the table
var dropped = []notifications{exit(1, unix.NFT_MSG_DELCHAIN, "forward"), exit(1, unix.NFT_MSG_DELCHAIN, "forward6"), exit(1, unix.NFT_MSG_DELCHAIN, "postrouting"), exit(1, unix.NFT_MSG_DELTABLE, "")}

// exit is notifications in Table naming name, the table alone where it is empty
func exit(count, kind int, name string) notifications {
	return notifications{count, kind, unix.NFPROTO_INET, Table, name, 0}
}

// flagged is one NEWTABLE of Table carrying flags
func flagged(flags uint32) notifications {
	n := exit(1, unix.NFT_MSG_NEWTABLE, "")
	n.flags = flags
	return n
}

// objects is one notification of kind in Table for each object of names
func objects(kind int, names ...string) []notifications {
	out := make([]notifications, 0, len(names))
	for _, name := range names {
		out = append(out, exit(1, kind, name))
	}
	return out
}

func firewall(count, kind int, name string) notifications {
	return notifications{count, kind, unix.NFPROTO_INET, "nixos-fw", name, 0}
}

// keyed is keysTable's transaction into table as the kernel sent it: the
// table where the transaction made it, the set, then the elements of each
// datagram, as many as counts gives
func keyed(table string, made bool, counts ...int) [][]notifications {
	datagrams := make([][]notifications, len(counts))
	for i, count := range counts {
		datagrams[i] = []notifications{{count, unix.NFT_MSG_NEWSETELEM, unix.NFPROTO_INET, table, keysSet, 0}}
	}
	first := []notifications{{1, unix.NFT_MSG_NEWSET, unix.NFPROTO_INET, table, keysSet, 0}}
	if made {
		first = append([]notifications{{1, unix.NFT_MSG_NEWTABLE, unix.NFPROTO_INET, table, "", 0}}, first...)
	}
	datagrams[0] = append(first, datagrams[0]...)
	return datagrams
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

// One transaction of another writer's that changes the table or the owner's
// scope wakes Changed once, at the NFT_MSG_NEWGEN that ends it, however many
// datagrams its notifications fill and however often the monitor finds the
// queue empty between them, and the owner's own transactions, another table's
// and a NEWTABLE of flags 0, which makes the table or clears its flags, wake
// nothing. A wake for each datagram, or for another owner's remake of the
// table after a reload, would take the owner's readiness again after the pass
// that put its rules back.
func TestMonitorWakesOnceAtTheEndOfAnotherWritersTransaction(t *testing.T) {
	for _, c := range []struct {
		name  string
		reads []monitorRead
		// changed is each read after which Changed woke
		changed []int
	}{
		// the NEWGEN after the deletion's 8 datagrams
		{"another writer's deletion of the table", transaction(otherPort, 3, deleted...), []int{8}},
		// the same NEWGEN behind 8 datagrams and 8 drains
		{"another writer's deletion read as the kernel sends it", readAsSent(transaction(otherPort, 3, deleted...)), []int{16}},
		// the NEWGEN after the flush's 8 datagrams
		{"a ruleset flush that writes a firewall's table", transaction(otherPort, 3, flushed...), []int{8}},
		// the NEWGEN after the rule's datagram
		{"another writer's one rule", transaction(otherPort, 3, ruled...), []int{1}},
		// the NEWGEN after the flush of the chain's 4 datagrams, then the one
		// after the deletion's 4
		{"two writers one after the other", slices.Concat(transaction(otherPort, 3, flushedChain...), transaction(thirdPort, 4, deletedAfter...)), []int{4, 9}},
		{"the owner's install", transaction(ownPort, 2, installed...), nil},
		{"the owner's withdrawal", transaction(ownPort, 5, deleted...), nil},
		{"another writer's tables of other names", slices.Concat(transaction(otherPort, 3, flooded("flood0")...), transaction(thirdPort, 4, flooded("flood1")...), transaction(otherPort, 5, flooded("flood2")...)), nil},
		{"another writer's set of another name in the table", transaction(otherPort, 3, keyedTable...), nil},
		// the NEWGEN after the reload's 10 datagrams, and nothing for the
		// filter's remake's 3 reads after it
		{"another owner making the table again after a reload", slices.Concat(transaction(otherPort, 4, reloaded...), transaction(siblingPort, 5, remade...)), []int{10}},
		// the NEWGEN after the dormant set's datagram, and nothing for the
		// filter's pass's 4 reads after it
		{"another writer setting the table dormant", slices.Concat(transaction(otherPort, 4, slept...), transaction(siblingPort, 5, woken...)), []int{1}},
		{"another writer clearing the table's flags", transaction(otherPort, 4, cleared...), nil},
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
	rule := transaction(otherPort, 5, ruled...)
	first := transaction(otherPort, 3, flushedChain...)
	second := transaction(thirdPort, 4, deletedAfter...)
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
			// each of the deletion's 8 datagrams at once, then the flush's NEWGEN
			// after the drain
			{"ahead of a deletion's objects", slices.Concat(lost, deletion, drain, flush), []int{1, 2, 3, 4, 5, 6, 7, 8, 19}, []int{0}},
			// the loss for the 3 datagrams read before it, each of the other 5 at
			// once, then the rule's NEWGEN after the drain
			{"in the middle of a deletion", slices.Concat(deletion[:3], lost, deletion[3:], drain, rule), []int{3, 4, 5, 6, 7, 8, 12}, []int{3}},
			// the loss for the deletion's 8 datagrams, then the rule's NEWGEN
			// after the drain and the owner's install
			{"ahead of a deletion's end", slices.Concat(objects, lost, end, drain, install, rule), []int{8, 21}, []int{8}},
			// each of the deletion's 8 datagrams at once, then the flush's NEWGEN
			{"that took a deletion's end", slices.Concat(lost, objects, drain, install, flush), []int{1, 2, 3, 4, 5, 6, 7, 8, 27}, []int{0}},
			// each of the first writer's 4 datagrams and the second's 4 at once,
			// then the rule's NEWGEN
			{"that took the second of two writers' ends", slices.Concat(lost, first, second[:len(second)-1], drain, install, rule), []int{1, 2, 3, 4, 6, 7, 8, 9, 21}, []int{0}},
			// the flush's NEWGEN after the drain
			{"with nothing queued behind it", slices.Concat(lost, drain, flush), []int{10}, []int{0}},
			// each datagram at once on either side of the second loss, which ends
			// nothing, then the flush's NEWGEN
			{"and a second in its span", slices.Concat(lost, deletion[:3], lost, deletion[3:], drain, flush), []int{1, 2, 3, 5, 6, 7, 8, 9, 20}, []int{0, 4}},
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
// wakes Changed at once for the last datagram of another writer's deletion of
// the owner's table, which holds the table's deletion, and nothing at that
// transaction's end, and it stops on a closed socket
func TestMonitorTellsLostNotificationsFromADeletion(t *testing.T) {
	m := feedMonitor(t)
	deletion := transaction(otherPort, 3, deleted...)
	last, end := deletion[len(deletion)-2], deletion[len(deletion)-1]
	for _, c := range []struct {
		name            string
		read            monitorRead
		changed, missed bool
	}{
		{"an overflow", monitorRead{err: unix.ENOBUFS}, false, true},
		{"a datagram cut short", monitorRead{datagram: deletion[0].datagram[:unix.SizeofNlMsghdr+SizeofNfgenmsg]}, false, true},
		{"another writer deleting its table", last, true, false},
		{"the end of that writer's transaction", end, false, false},
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
