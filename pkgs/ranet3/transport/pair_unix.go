// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package transport

import (
	"errors"
	"slices"

	"golang.org/x/sys/unix"
)

// retryICMP reads on past the error a connected socket reports for an ICMP error an earlier datagram drew
// a peer that restarted or a hop that refused one datagram leaves the socket working
func retryICMP(fn receiveFunc) receiveFunc {
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		for {
			n, refused, err := fn(bufs, sizes, endpoints)
			if err == nil || !icmpReported(err) {
				return n, refused, err
			}
		}
	}
}

// pastICMP sends packets with write, once more past an error the kernel handed the socket for an ICMP error an earlier datagram drew
// the send that returns such an error consumes it, so a write that fails again fails for a cause of its own
// the socket still carries the pair past a refusal for size, whose datagrams the shared socket reports in a PathMTUError
func pastICMP(write func([][]byte) (int, error), packets [][]byte) (int, bool, error) {
	sent, err := write(packets)
	if err == nil {
		return sent, true, nil
	}
	if !icmpReported(err) {
		return sent, false, err
	}
	more, err := write(packets[sent:])
	return sent + more, err == nil || errors.Is(err, unix.EMSGSIZE), err
}

// icmpReported reports whether err is one the kernel hands a connected socket for an ICMP error
func icmpReported(err error) bool {
	errno, ok := errors.AsType[unix.Errno](err)
	return ok && slices.Contains(icmpErrnos, errno)
}
