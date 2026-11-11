// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

// holders is, in each network namespace, the Holds of this process that hold
// Table there, by the key namespace gives it. A share one of them was released
// from while it held is marked kept until its last Hold goes. An owner in
// another process is not counted, and its chains keep the table only where a
// withdrawal's listing shows them. The lock is held across a whole withdrawal,
// across a first write's batch and while a count changes, and nothing else is
// taken while it is held, so a pass may take it under a lock of its own
// owner's.
var holders = struct {
	sync.Mutex
	held map[namespace]*share
}{held: map[namespace]*share{}}

// share is the count of one namespace's Holds, whether one was released while
// it held, and pin the namespace's descriptor, open while any holds it, so its
// inode names no other namespace meanwhile, nil for soleNamespace
type share struct {
	count int
	kept  bool
	pin   *os.File
}

// namespace is a network namespace by its nsfs device and inode, the zero
// value none
type namespace struct {
	dev, ino uint64
}

// soleNamespace is the key namespace gives where it names no namespace, on a
// device no nsfs has
var soleNamespace = namespace{dev: math.MaxUint64}

// namespace names the network namespace c's socket was opened in, and opens it.
// The socket is asked only where the process's /proc showed a network
// namespace of its own at the process's first ask, whose answer stands for the
// process. Where it showed none, which is a kernel built without network
// namespaces and a process that cannot read it, the key is soleNamespace with
// nothing to open: before Linux 5.13 such a kernel answers the ask with a
// descriptor whose use oopses. A socket that answers the ask EINVAL, which on
// a kernel with network namespaces only a filter on the ioctl does, is keyed
// soleNamespace too, so its owner writes on. A key that joins namespaces only
// keeps a table: its count is the sum of theirs, so a withdrawal under it is
// the last only where it is the last in its own namespace as well. Where a
// filter answers some of one namespace's asks EINVAL and not others, that
// namespace's Holds sit under two keys, a withdrawal can be the last under its
// own while a Hold under the other holds, and the table then goes only where
// that withdrawal's listing shows nothing but its owner's.
func (c *Conn) namespace() (namespace, *os.File, error) {
	if !procShowsNetNamespace() {
		return soleNamespace, nil, nil
	}
	fd, err := unix.IoctlRetInt(c.link.Fd(), unix.SIOCGSKNS)
	if errors.Is(err, unix.EINVAL) {
		return soleNamespace, nil, nil
	}
	if err != nil {
		return namespace{}, nil, fmt.Errorf("nftables: open the socket's network namespace: %w", err)
	}
	pin := os.NewFile(uintptr(fd), "netns")
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = pin.Close()
		return namespace{}, nil, fmt.Errorf("nftables: read the socket's network namespace: %w", err)
	}
	return namespace{dev: uint64(st.Dev), ino: uint64(st.Ino)}, pin, nil
}

// netNamespaceShown is whether the process's /proc shows a network namespace of
// its own, as a stat of /proc/self/ns/net answered err: /proc/self/ns lists net
// only on a kernel built with network namespaces, and a stat that fails for
// any other reason tells nothing of the kernel and shows none
func netNamespaceShown(err error) bool {
	return err == nil
}

// procShowsNetNamespace is whether the process's /proc showed a network
// namespace of its own, read at the process's first ask and not at init, and
// kept for the process
var procShowsNetNamespace = sync.OnceValue(func() bool {
	_, err := os.Stat("/proc/self/ns/net")
	return netNamespaceShown(err)
})

// Hold is one owner's place among those holding Table, the zero value holding
// nothing. It holds from the commit of its first write, or from a read of its
// owner's that finds the owner's objects in the table, until a withdrawal of
// its own commits, finds no table, or finds nothing of its owner's in it, or
// until its owner ends and releases it. A write or a withdrawal that fails
// leaves it as it was, a first write whose transaction committed but whose
// answer was lost among them, which counts from the next read that finds what
// it wrote. The last holder in a namespace to withdraw deletes the table, no
// other withdrawal does, and once a holder there was released none is the
// last until every Hold of the namespace has gone. Its owner writes and
// withdraws one Scope through it, from one goroutine at a time, which alone
// reads and changes what it holds.
type Hold struct {
	// ns is the namespace of the table held, the zero value where it holds
	// none. Its owner's goroutine alone reads it, and holders' lock is held
	// wherever it changes.
	ns namespace
}

// Write sends requests, a transaction that writes the owner's objects in
// Table, through conn
func (h *Hold) Write(conn *Conn, requests []Request) error {
	if h.ns != (namespace{}) {
		return conn.Batch(requests)
	}
	holders.Lock()
	defer holders.Unlock()
	// the first write commits under the lock, so no withdrawal finds itself the last between this commit and the count
	ns, pin, err := conn.namespace()
	if err != nil {
		return err
	}
	if err := conn.Batch(requests); err != nil {
		_ = pin.Close()
		return err
	}
	h.hold(ns, pin)
	return nil
}

// Found makes h hold the table, as a write does, where its owner's read
// through conn found any of the owner's objects in it, which a start that
// takes an earlier instance's objects over keeps without a write
func (h *Hold) Found(conn *Conn) error {
	if h.ns != (namespace{}) {
		return nil
	}
	holders.Lock()
	defer holders.Unlock()
	ns, pin, err := conn.namespace()
	if err != nil {
		return err
	}
	h.hold(ns, pin)
	return nil
}

// hold counts h among ns's holders, pin being ns's descriptor, under holders'
// lock
func (h *Hold) hold(ns namespace, pin *os.File) {
	h.ns = ns
	if s, ok := holders.held[ns]; ok {
		s.count++
		_ = pin.Close()
		return
	}
	holders.held[ns] = &share{count: 1, pin: pin}
}

// Withdraw removes what s names from Table in one transaction and reports
// whether the table held any of it, a table that is not there being success.
// It flushes each chain of s's, deletes each but one another writer's rule or
// map element goes to, which nf_tables refuses to delete and which stays
// flushed, then deletes s's sets and timeout objects, which a rule of another
// writer's still using one fails. The table's last holder, as this process's
// count gives it, deletes the table at the end of that transaction, where its
// listing shows no flag but dormant and nothing but s's. The count decides for
// this process's owners and the listing for anything else in the table, so a
// chain of another process's that the listing misses goes with the table. A
// table carrying the owner or persist flag belongs to the socket that set the
// flag or to a start that adopts it.
func (h *Hold) Withdraw(conn *Conn, s Scope) (removed bool, err error) {
	holders.Lock()
	defer holders.Unlock()
	tables, err := Tables(conn, Table)
	if err != nil {
		return false, err
	}
	flags, held := tables[unix.NFPROTO_INET]
	if !held {
		h.release()
		return false, nil
	}
	l, err := list(conn, flags)
	if err != nil {
		return false, err
	}
	requests := h.withdrawal(l, s)
	if err := conn.Batch(requests); err != nil {
		return false, err
	}
	h.release()
	return len(requests) > 0, nil
}

// Release ends h's hold as its owner ends without withdrawing, and leaves what
// the owner wrote in the table: no withdrawal in its namespace deletes the
// table while any other Hold there holds it.
func (h *Hold) Release() {
	holders.Lock()
	defer holders.Unlock()
	if s, ok := holders.held[h.ns]; ok {
		s.kept = true
	}
	h.release()
}

// withdrawal is the transaction Withdraw sends over l, under holders' lock
func (h *Hold) withdrawal(l listing, s Scope) []Request {
	share, ok := holders.held[h.ns]
	return s.withdrawal(l, ok && share.count == 1 && !share.kept)
}

// release ends h's hold, under holders' lock
func (h *Hold) release() {
	if h.ns == (namespace{}) {
		return
	}
	s := holders.held[h.ns]
	if s.count--; s.count == 0 {
		_ = s.pin.Close()
		delete(holders.held, h.ns)
	}
	h.ns = namespace{}
}
