// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux && !darwin

package userspace

import (
	"errors"
	"net/netip"
)

// echoSocket is no socket where the exit has no echo relay, so every echo
// request is refused and answered as one whose socket the platform refused
type echoSocket struct{}

// errEchoClosed is a read of an echo socket that closed
var errEchoClosed = errors.New("userspace: echo socket closed")

// icmpSockets opens no ICMP socket where no build carries the exit
type icmpSockets struct{}

func openICMP(*Exit) *icmpSockets { return &icmpSockets{} }

func (*icmpSockets) openEcho(bool, netip.Addr, uint16, netip.Addr) (*echoSocket, error) {
	return nil, errors.ErrUnsupported
}

func (*icmpSockets) close() {}

func (*echoSocket) send([]byte, netip.Addr) error { return errors.ErrUnsupported }

func (*echoSocket) receive(*replyBuffer) (int, netip.Addr, error) {
	return 0, netip.Addr{}, errEchoClosed
}

func (*echoSocket) identifier() (uint16, error) { return 0, errors.ErrUnsupported }

func (*echoSocket) close() error { return nil }
