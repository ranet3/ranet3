// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// The tests of this file read a real kernel's notifications through the
// monitor OpenMonitor opens, each in a network namespace it made itself and
// refusing any other, and run as root in the netlink VM check and under
// unshare -rn.

// floodTransactions is how many transactions of other tables a test commits
// at most before the kernel drops a notification, floodKeys the set elements
// of each and wholeKeys those of the one transaction after the drain, one
// notification per element. wakeRoom is the room a test gives Changed, past
// a wake for each notification of that transaction.
const (
	floodTransactions = 50
	floodKeys         = 256
	wholeKeys         = 1024
	wakeRoom          = 4 * wholeKeys
)

// parkPoll is how often a test looks for the monitor waiting in the poller
const parkPoll = 10 * time.Millisecond

// Once the monitor has read an overflow's backlog, another writer's whole
// transaction to its scope wakes Changed once, at its end, however many
// datagrams it fills. A read that never tells run of the empty queue would
// leave the monitor in the span after its first loss for good, waking Changed
// for each change message it reads. Changed holds every wake here, so the
// count does not depend on when the scheduler runs the test.
func TestMonitorWakesOnceForATransactionAfterAnOverflowDrains(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	owner, another := dial(t), dial(t)
	monitor, err := openMonitor(owner, Scope{Sets: []string{keysSet}})
	if err != nil {
		t.Fatal(err)
	}
	// no read has started, so Changed can still be swapped for one with room for every wake
	monitor.changed = make(chan struct{}, wakeRoom)
	go monitor.run()
	t.Cleanup(func() { _ = monitor.Close() })
	raw, err := monitor.file.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	socket := func(what string, f func(fd int) error) {
		t.Helper()
		var err error
		if controlErr := raw.Control(func(fd uintptr) { err = f(int(fd)) }); controlErr != nil || err != nil {
			t.Fatalf("%s: %v %v", what, controlErr, err)
		}
	}
	socket("shrink the monitor's receive buffer", func(fd int) error {
		return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1)
	})
	// a reader the scheduler favors can keep up with one transaction's notifications, so transactions go on until the kernel has dropped one
	transactions := 0
	for socketDropped(t, raw) == 0 {
		if transactions == floodTransactions {
			t.Fatalf("after %d transactions of %d keys the kernel had dropped no notification", transactions, floodKeys)
		}
		if err := another.Batch(keysTable(t, fmt.Sprintf("flood%d", transactions), floodKeys)); err != nil {
			t.Fatalf("commit another table's transaction: %v", err)
		}
		transactions++
	}
	select {
	case <-monitor.Missed():
	case <-time.After(monitorWait):
		t.Fatalf("the kernel dropped a notification after %d transactions and Missed never woke", transactions)
	}
	for deadline := time.Now().Add(monitorWait); !monitorParked(); time.Sleep(parkPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the monitor never waited for a datagram within %s of the overflow", monitorWait)
		}
	}
	if n := len(monitor.changed); n != 0 {
		t.Fatalf("another table's transactions woke Changed %d times", n)
	}
	woke(monitor.Missed())
	socket("grow the monitor's receive buffer back", func(fd int) error {
		growReceiveBuffer(fd)
		return nil
	})

	if err := another.Batch(keysTable(t, Table, wholeKeys)); err != nil {
		t.Fatalf("commit another writer's transaction to the scope: %v", err)
	}
	wakes := 0
	quiet := time.After(monitorWait)
count:
	for {
		select {
		case <-monitor.Changed():
			wakes++
			quiet = time.After(rootWait)
		case <-quiet:
			break count
		}
	}
	if woke(monitor.Missed()) {
		t.Fatalf("another writer's transaction of %d keys overflowed the monitor's socket again, so its wakes cannot be counted", wholeKeys)
	}
	if wakes != 1 {
		t.Errorf("another writer's one transaction of %d keys after the overflow drained woke Changed %d times, want once", wholeKeys, wakes)
	}
	t.Logf("the kernel dropped a notification after %d transactions of %d keys", transactions, floodKeys)
}

// keysSet is the set keysTable makes, the one set of the monitor's scope
const keysSet = "addresses"

// keysTable is one transaction that makes table in the inet family with the
// set keysSet of count IPv6 addresses
func keysTable(t *testing.T, table string, count int) []Request {
	t.Helper()
	set := Set{Table: table, Name: keysSet, ID: 1, KeyType: TypeIPv6Addr, KeyLen: 16}
	made, err := set.Create(unix.NFPROTO_INET)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]Interval, 0, count)
	for i := range count {
		keys = append(keys, Key([]byte{0x20, 0x01, 0x0d, 0xb8, 14: byte(i >> 8), 15: byte(i)}))
	}
	filled, err := set.Fill(unix.NFPROTO_INET, keys)
	if err != nil {
		t.Fatal(err)
	}
	return append([]Request{NewTable(unix.NFPROTO_INET, table), made}, filled...)
}

// socketDropped is how many datagrams the kernel has dropped for the socket
// raw controls
func socketDropped(t *testing.T, raw syscall.RawConn) uint32 {
	t.Helper()
	var meminfo [unix.SK_MEMINFO_VARS]uint32
	size := uint32(unsafe.Sizeof(meminfo))
	var errno syscall.Errno
	err := raw.Control(func(fd uintptr) {
		// x/sys wraps no getsockopt that reads SO_MEMINFO's array
		_, _, errno = unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_MEMINFO,
			uintptr(unsafe.Pointer(&meminfo)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil || errno != 0 {
		t.Fatalf("read the monitor's socket memory: %v %v", err, errno)
	}
	return meminfo[unix.SK_MEMINFO_DROPS]
}

// monitorParked is whether the goroutine running a monitor's reads waits in
// the poller, which the read OpenMonitor installs does only after it has told
// run of an empty queue
func monitorParked() bool {
	buf := make([]byte, 1<<22)
	for stack := range strings.SplitSeq(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
		if strings.Contains(stack, ".(*Monitor).run(") {
			header, _, _ := strings.Cut(stack, "\n")
			return strings.Contains(header, "[IO wait")
		}
	}
	return false
}
