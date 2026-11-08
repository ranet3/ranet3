// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package userspace

import (
	"errors"
	"net/netip"
	"syscall"
)

// echoSocket is no socket where the exit has no echo relay, so every echo
// request is refused and answered as one whose socket the platform refused
type echoSocket struct{}

// errEchoClosed is a read of an echo socket that closed
var errEchoClosed = errors.New("userspace: echo socket closed")

func openEcho(bool, netip.Addr, uint16, func(string, syscall.RawConn) error) (*echoSocket, error) {
	return nil, errors.ErrUnsupported
}

func (*echoSocket) send([]byte, netip.Addr) error { return errors.ErrUnsupported }

func (*echoSocket) receive(*replyBuffer) (int, netip.Addr, error) {
	return 0, netip.Addr{}, errEchoClosed
}

func (*echoSocket) identifier() (uint16, error) { return 0, errors.ErrUnsupported }

func (*echoSocket) close() error { return nil }
