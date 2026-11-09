// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// Scope names the objects one owner writes in Table: its chains, those whose
// name runs past Prefix among them, its named sets and its ct timeout
// objects. Its monitor watches the chains and the sets, never a timeout
// object, whose change the owner's next read finds, and Withdraw removes all
// of them.
type Scope struct {
	Chains   []string
	Prefix   string
	Sets     []string
	Timeouts []string
}

func (s Scope) chain(name string) bool {
	return slices.Contains(s.Chains, name) || s.Prefix != "" && len(name) > len(s.Prefix) && strings.HasPrefix(name, s.Prefix)
}

func (s Scope) set(name string) bool { return slices.Contains(s.Sets, name) }

// Monitor wakes its owner for another writer's change to Table or to its
// scope. A NixOS firewall reload flushes the whole ruleset, which takes every
// chain an owner wrote with it until its next pass, and a rule another writer
// adds, or a table it sets dormant, bypasses the chain as surely. A table
// message reaches every owner unless it is a NEWTABLE whose flags are 0: a
// table so made holds no owner's chain, and one so cleared bypasses no chain,
// so the owner that makes the table again first after a flush wakes no other,
// and a reload wakes each owner once.
//
// nf_tables sends a transaction's notifications as one run of datagrams that
// no other transaction's interleaves and ends the run with NFT_MSG_NEWGEN.
// Changed wakes at that message, once the change is whole, so once for each
// transaction whose change to the scope it reads. Missed wakes at each loss,
// an overflow, a datagram it cannot parse or a read error, and a read error
// stops the monitor. A loss may take a transaction's end, so it wakes Changed
// as well for a change read before it. An overflow congests the socket: the
// kernel reports it ahead of the datagrams still queued and drops every
// datagram it sends until a read leaves the queue empty. So the end of any
// transaction in that backlog may be gone, and from a loss to the next
// read that finds the queue already empty and returns EAGAIN, each change
// read wakes Changed at once. A transaction read in that span can wake
// Changed more than once. A transaction the kernel sends while the socket is
// congested is lost in whole or in part, and a change lost so wakes nothing,
// so only the owner's next pass reads it back. One it sends after the read
// that leaves the queue empty and before the EAGAIN read is queued whole and
// wakes Changed at once.
type Monitor struct {
	file *os.File
	// read returns one datagram, or unix.EAGAIN once each time it finds the
	// queue empty
	read    func([]byte) (int, error)
	pid     uint32
	scope   Scope
	changed chan struct{}
	missed  chan struct{}
	done    chan struct{}
	closing atomic.Bool
}

// OpenMonitor joins the nf_tables notification group. owner is the socket
// the scope's owner writes through, whose own changes the kernel stamps with
// its port and which are not another writer's.
func OpenMonitor(owner *Conn, scope Scope) (*Monitor, error) {
	m, err := openMonitor(owner, scope)
	if err != nil {
		return nil, err
	}
	go m.run()
	return m, nil
}

// openMonitor is OpenMonitor's monitor with its socket open and its read
// installed, before its reads start
func openMonitor(owner *Conn, scope Scope) (*Monitor, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nftables: open netfilter notification socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: 1 << (unix.NFNLGRP_NFTABLES - 1)}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("nftables: join the nf_tables notification group: %w", err)
	}
	growReceiveBuffer(fd)
	// nonblocking, so os.NewFile registers it with the runtime poller and Close unblocks the reader
	file := os.NewFile(uintptr(fd), "nftables-monitor")
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("nftables: read netfilter notification socket: %w", err)
	}
	m := &Monitor{
		file:    file,
		pid:     owner.pid,
		scope:   scope,
		changed: make(chan struct{}, 1),
		missed:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	m.read = m.drainingRead(raw)
	return m, nil
}

// drainingRead reads one datagram from raw at each call. The first time it
// finds the queue empty after a datagram or an error it returns unix.EAGAIN,
// and the call after that waits for the next datagram.
func (m *Monitor) drainingRead(raw syscall.RawConn) func([]byte) (int, error) {
	told := false
	return func(buf []byte) (n int, err error) {
		waited := raw.Read(func(fd uintptr) bool {
			// a nonblocking read never sleeps, so no signal interrupts it
			n, err = unix.Read(int(fd), buf)
			return !errors.Is(err, unix.EAGAIN) || !told
		})
		switch {
		case waited != nil && m.closing.Load():
			return 0, os.ErrClosed
		case waited != nil:
			return 0, waited
		case err != nil:
			n = 0
		}
		told = errors.Is(err, unix.EAGAIN)
		return n, err
	}
}

func (m *Monitor) Changed() <-chan struct{} { return m.changed }

func (m *Monitor) Missed() <-chan struct{} { return m.missed }

func (m *Monitor) run() {
	defer close(m.done)
	buf := make([]byte, notificationReadSize)
	pending, lost := false, false
	end := func() {
		if pending {
			notify(m.changed)
		}
		pending = false
	}
	loss := func() {
		end()
		lost = true
		notify(m.missed)
	}
	for {
		n, err := m.read(buf)
		switch {
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, unix.EAGAIN):
			lost = false
			continue
		case errors.Is(err, unix.ENOBUFS):
			loss()
			continue
		case err != nil:
			loss()
			slog.Warn("stopped reading nf_tables notifications", "table", Table, "chains", m.scope.Chains, "err", err)
			return
		}
		messages, err := parseMessages(buf[:n])
		if err != nil {
			loss()
			continue
		}
		for _, message := range messages {
			switch {
			case message.Kind == Command(unix.NFT_MSG_NEWGEN):
				end()
			case m.scope.ChangedByAnother(message, m.pid):
				pending = true
				if lost {
					end()
				}
			}
		}
	}
}

// growReceiveBuffer asks for receiveBuffer bytes of receive buffer on fd, past
// rmem_max where it can. Best effort: the forced form needs the capability
// this process already holds to write a rule at all, and a kernel that refuses
// both leaves the smaller buffer rather than a failure to start.
func growReceiveBuffer(fd int) {
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, receiveBuffer) != nil {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, receiveBuffer)
	}
}

func notify(signal chan<- struct{}) {
	select {
	case signal <- struct{}{}:
	default:
	}
}

func (m *Monitor) Close() error {
	// the poller fails a raw read on a closed file with an error os does not
	// export, so the read knows a close by this
	m.closing.Store(true)
	err := m.file.Close()
	<-m.done
	return err
}

// ChangedByAnother is whether message is a change to Table, or to one of s's
// chains, a rule in one, one of its sets or a set's elements, written through
// a socket other than pid. The table's deletion reaches every owner, and so
// does a NEWTABLE that sets a flag or carries no NFTA_TABLE_FLAGS. A NEWTABLE
// whose flags are 0 reaches none: it makes the table, which holds no chain
// until another message names one, or clears its flags, which takes no
// owner's chain and leaves nothing Contents.Read faults. The kernel puts the
// flags in every NEWTABLE (nf_tables_fill_table_info), notifies an element
// only from a transaction, never from a set's garbage collection or a
// packet's dynset, and notifies nothing for an owner's NewTable over the
// table as it stands (nf_tables_updtable).
func (s Scope) ChangedByAnother(message Message, pid uint32) bool {
	if message.Pid == pid || message.Kind>>8 != unix.NFNL_SUBSYS_NFTABLES || len(message.Data) < SizeofNfgenmsg || message.Data[0] != unix.NFPROTO_INET {
		return false
	}
	var table, name uint16
	var own func(string) bool
	switch message.Kind & 0xff {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		table = unix.NFTA_TABLE_NAME
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		table, name, own = unix.NFTA_CHAIN_TABLE, unix.NFTA_CHAIN_NAME, s.chain
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		table, name, own = unix.NFTA_RULE_TABLE, unix.NFTA_RULE_CHAIN, s.chain
	case unix.NFT_MSG_NEWSET, unix.NFT_MSG_DELSET:
		table, name, own = unix.NFTA_SET_TABLE, unix.NFTA_SET_NAME, s.set
	case unix.NFT_MSG_NEWSETELEM, unix.NFT_MSG_DELSETELEM:
		table, name, own = unix.NFTA_SET_ELEM_LIST_TABLE, unix.NFTA_SET_ELEM_LIST_SET, s.set
	default:
		return false
	}
	inTable, named, unflagged := false, own == nil, false
	for kind, value := range message.Attributes() {
		switch {
		case kind == table:
			inTable = unix.ByteSliceToString(value) == Table
		case kind == name && own != nil:
			named = own(unix.ByteSliceToString(value))
		case message.Kind&0xff == unix.NFT_MSG_NEWTABLE && kind == unix.NFTA_TABLE_FLAGS:
			unflagged = len(value) == 4 && binary.BigEndian.Uint32(value) == 0
		}
	}
	return inTable && named && !unflagged
}
