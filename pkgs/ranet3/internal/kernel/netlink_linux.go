// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
)

// nlConn is one rtnetlink socket used for synchronous request and reply, with
// the requests that are rtnetlink's own. One goroutine at a time uses each, so
// it needs no locking. The reconciler's serves its constructor and then its
// reconcile loop alone, the network watch's serves WatchNetwork and then the
// watch's own goroutine alone, and RouteGet, RouteGetBatch and DumpRules each
// dial one for the call.
type nlConn struct {
	socket *netlink.Conn
}

// dialNetlink opens a strict socket, since the kernel honors the filters a
// dump carries only on one, and without them a dump of one table reads every
// route on the host
func dialNetlink() (*nlConn, error) {
	socket, err := netlink.Dial(unix.NETLINK_ROUTE, netlink.Options{Strict: true})
	if err != nil {
		return nil, err
	}
	return &nlConn{socket: socket}, nil
}

func (c *nlConn) Close() error { return c.socket.Close() }

func (c *nlConn) execute(kind, flags uint16, body []byte) ([]netlink.Message, error) {
	return c.socket.Execute(kind, flags, body)
}

// linkInfo holds the fields of one RTM_NEWLINK this package reads
type linkInfo struct {
	index uint32
	name  string
}

// link asks about one device by index, or by name when index is 0, with a keyed RTM_GETLINK rather than a dump
// a name nothing holds answers ENODEV
func (c *nlConn) link(index uint32, name string) (linkInfo, error) {
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	if index == 0 {
		body = netlink.PutAttrString(body, unix.IFLA_IFNAME, name)
	}
	replies, err := c.execute(unix.RTM_GETLINK, 0, body)
	if err != nil {
		return linkInfo{}, err
	}
	for _, reply := range replies {
		if reply.Kind == unix.RTM_NEWLINK && len(reply.Data) >= unix.SizeofIfInfomsg {
			return decodeLink(reply), nil
		}
	}
	return linkInfo{}, unix.ENODEV
}

// decodeLink reads one RTM_NEWLINK, a lookup's reply or a dump's entry alike
// the caller has checked that it holds a whole ifinfomsg
func decodeLink(reply netlink.Message) linkInfo {
	link := linkInfo{index: binary.NativeEndian.Uint32(reply.Data[4:])}
	for kind, value := range reply.Attributes(unix.SizeofIfInfomsg) {
		if kind == unix.IFLA_IFNAME {
			link.name = unix.ByteSliceToString(value)
		}
	}
	return link
}

// addressFromBytes decides the family from the attribute length, exactly as
// the kernel wrote it, so a mapped IPv6 address is not mistaken for IPv4.
func addressFromBytes(raw []byte) (netip.Addr, bool) {
	address, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, false
	}
	return address.WithZone(""), true
}

func unspecified(family uint8) netip.Addr {
	if family == unix.AF_INET {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.AddrFrom16([16]byte{})
}

// gone reports the errnos meaning the object is already in the state the
// request asked for, or that the device has been removed under us. Neither is
// a failure: the next reconcile pass would do nothing about them either.
func gone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL)
}
