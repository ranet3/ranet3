// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"golang.org/x/sys/unix"
)

// Scope is one table name in a set of nf_tables families, the tables one
// owner holds and its monitor watches
type Scope struct {
	Name     string
	Families []uint8
}

// Monitor wakes Changed once per datagram of nf_tables notifications that
// holds another writer's change to its scope's tables, and Missed once per
// overflow or datagram it cannot parse. A NixOS firewall reload flushes the
// whole ruleset, which takes every chain an owner wrote with it until its next
// pass. A rule another writer adds, or a table it sets dormant, bypasses the
// chain as surely.
type Monitor struct {
	file    *os.File
	read    func([]byte) (int, error)
	pid     uint32
	scope   Scope
	changed chan struct{}
	missed  chan struct{}
	done    chan struct{}
}

// OpenMonitor joins the nf_tables notification group. owner is the socket
// the scope's owner writes through, whose own changes the kernel stamps with
// its port and which are not another writer's.
func OpenMonitor(owner *Conn, scope Scope) (*Monitor, error) {
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
	m := &Monitor{
		file:    file,
		read:    file.Read,
		pid:     owner.pid,
		scope:   scope,
		changed: make(chan struct{}, 1),
		missed:  make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	go m.run()
	return m, nil
}

func (m *Monitor) Changed() <-chan struct{} { return m.changed }

func (m *Monitor) Missed() <-chan struct{} { return m.missed }

func (m *Monitor) run() {
	defer close(m.done)
	buf := make([]byte, notificationReadSize)
	for {
		n, err := m.read(buf)
		switch {
		case errors.Is(err, os.ErrClosed):
			return
		case errors.Is(err, unix.ENOBUFS):
			notify(m.missed)
			continue
		case err != nil:
			notify(m.missed)
			slog.Warn("egress stopped reading nf_tables notifications", "err", err)
			return
		}
		messages, err := parseMessages(buf[:n])
		switch {
		case err != nil:
			notify(m.missed)
		case slices.ContainsFunc(messages, func(message Message) bool { return m.scope.ChangedByAnother(message, m.pid) }):
			notify(m.changed)
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
	err := m.file.Close()
	<-m.done
	return err
}

// ChangedByAnother is whether message is a change to a table of s, a chain in
// one or a rule in one, written through a socket other than pid
func (s Scope) ChangedByAnother(message Message, pid uint32) bool {
	if message.Pid == pid || message.Kind>>8 != unix.NFNL_SUBSYS_NFTABLES || len(message.Data) < SizeofNfgenmsg {
		return false
	}
	if !slices.Contains(s.Families, message.Data[0]) {
		return false
	}
	var naming uint16
	switch message.Kind & 0xff {
	case unix.NFT_MSG_NEWTABLE, unix.NFT_MSG_DELTABLE:
		naming = unix.NFTA_TABLE_NAME
	case unix.NFT_MSG_NEWCHAIN, unix.NFT_MSG_DELCHAIN:
		naming = unix.NFTA_CHAIN_TABLE
	case unix.NFT_MSG_NEWRULE, unix.NFT_MSG_DELRULE:
		naming = unix.NFTA_RULE_TABLE
	default:
		return false
	}
	for kind, value := range message.Attributes() {
		if kind == naming && unix.ByteSliceToString(value) == s.Name {
			return true
		}
	}
	return false
}
