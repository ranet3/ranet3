// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

// errorQueue reads the ICMP errors the kernel queues on one of the exit's
// sockets with IP_RECVERR or IPV6_RECVERR, through a descriptor of its own
// that outlives the socket's, since a failed dial closes the socket before
// its error is read
type errorQueue struct {
	fd         int
	held, ipv6 bool
}

// queue is a dial's error queue, which the dial's socket keeps on Linux
func (*icmpSockets) queue() errorQueue { return errorQueue{} }

// open turns the queue on for fd, a socket toward server, and holds a
// descriptor of it
func (q *errorQueue) open(fd int, server netip.AddrPort) error {
	ipv6 := server.Addr().Is6()
	if err := watchErrors(fd, ipv6); err != nil {
		return err
	}
	held, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	q.fd, q.held, q.ipv6 = held, true, ipv6
	return nil
}

// read is the first ICMP error the queue holds, false where it holds none.
// Linux queues an error before the dial it ended returns, whatever failed it.
func (q *errorQueue) read(error) (icmpError, bool) {
	if !q.held {
		return icmpError{}, false
	}
	oob := make([]byte, errorSpace())
	_, oobn, _, _, err := unix.Recvmsg(q.fd, nil, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
	if err != nil {
		return icmpError{}, false
	}
	return queuedError(oob[:oobn])
}

// close turns the queue off and gives its descriptor back. A connection the
// dial opened then takes an ICMP error about it as Linux's soft error, which
// ends nothing (RFC 1122 4.2.3.9, RFC 5382 REQ-10), where a socket still
// watching its errors would read one as the connection's errno.
func (q *errorQueue) close() {
	if q.held {
		level, option := unix.IPPROTO_IP, unix.IP_RECVERR
		if q.ipv6 {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
		}
		_ = unix.SetsockoptInt(q.fd, level, option, 0)
		_ = unix.Close(q.fd)
		q.held = false
	}
}

// watchErrors has the kernel queue each ICMP error about fd's datagrams, fd
// a socket of family ipv6 or IPv4, and hand it to a read as its errno
func watchErrors(fd int, ipv6 bool) error {
	level, option := unix.IPPROTO_IP, unix.IP_RECVERR
	if ipv6 {
		level, option = unix.IPPROTO_IPV6, unix.IPV6_RECVERR
	}
	return unix.SetsockoptInt(fd, level, option, 1)
}

// drainErrors empties fd's error queue, handing each an ICMP error with the
// part of the offending datagram's payload the error quoted, read into buf.
// It skips the errors the kernel raised itself, such as a datagram refused
// for its size. Emptying the queue gives back the receive buffer its errors
// held and clears the socket's pending errno.
func drainErrors(fd int, buf []byte, each func(e icmpError, prefix []byte)) {
	oob := make([]byte, errorSpace())
	for {
		n, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE|unix.MSG_DONTWAIT)
		if err != nil {
			return
		}
		if e, ok := queuedError(oob[:oobn]); ok {
			each(e, buf[:n])
		}
	}
}

// errorSpace is the control buffer one queued error takes
func errorSpace() int {
	return unix.CmsgSpace(sockExtendedErr + unix.SizeofSockaddrInet6)
}

// queuedError is the ICMP error the control messages of one read of an error
// queue name, false where they name none
func queuedError(oob []byte) (icmpError, bool) {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return icmpError{}, false
	}
	for _, m := range messages {
		if (m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR) || (m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR) {
			return extendedError(m.Data)
		}
	}
	return icmpError{}, false
}

// extendedError is the ICMP error a sock_extended_err and the offender's
// address after it name, false for one the kernel raised itself rather than
// read from an ICMP message. ee_info is in the host's byte order.
func extendedError(data []byte) (icmpError, bool) {
	if len(data) < sockExtendedErr {
		return icmpError{}, false
	}
	origin := data[4]
	if origin != unix.SO_EE_ORIGIN_ICMP && origin != unix.SO_EE_ORIGIN_ICMP6 {
		return icmpError{}, false
	}
	e := icmpError{kind: data[5], code: data[6], info: binary.NativeEndian.Uint32(data[8:12])}
	offender := data[sockExtendedErr:]
	switch {
	case origin == unix.SO_EE_ORIGIN_ICMP && len(offender) >= unix.SizeofSockaddrInet4:
		e.offender = netip.AddrFrom4([4]byte(offender[4:8]))
	case origin == unix.SO_EE_ORIGIN_ICMP6 && len(offender) >= unix.SizeofSockaddrInet6:
		e.offender = netip.AddrFrom16([16]byte(offender[8:24]))
	default:
		return icmpError{}, false
	}
	return e, true
}
