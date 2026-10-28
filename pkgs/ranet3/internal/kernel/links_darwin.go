// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// lookupDefault is the host's own default route of one family on host, the
// interface it leaves by and the next hop it points at, invalid where it
// leaves through a link instead, and ErrNoDefaultRoute where only mesh, this
// node's own tun, holds the key.
//
// It is an exact lookup of the one entry keyed on the unspecified address
// rather than a longest-prefix match, because the mesh installs routes that
// cover the whole address space and a match answers with those. Measured on
// Darwin 27.2.0: with 0.0.0.0/1 and 128.0.0.0/1 out of the tun, the match
// answers utun and the exact lookup answers the physical interface. Where
// there is no entry at all the exact lookup falls back to a match, which is
// why the mesh interface is rejected here too and not only there.
func lookupDefault(host Host, mesh int, family netip.Addr) (index int, gateway netip.Addr, err error) {
	answer, err := host.Lookup(family.Unmap(), zeroMaskOf(family))
	if err != nil {
		return 0, netip.Addr{}, err
	}
	if answer.Index == mesh {
		// The only entry covering the unspecified address of this family is
		// one of ours, so the host has no default of its own to fall back to.
		return 0, netip.Addr{}, ErrNoDefaultRoute
	}
	return answer.Index, answer.Gateway, nil
}

// zeroMaskOf is the all-zeros netmask of one family, which turns a lookup from
// a longest-prefix match into a request for that exact key.
func zeroMaskOf(family netip.Addr) netip.Addr {
	if family.Is6() {
		return netip.AddrFrom16([16]byte{})
	}
	return netip.AddrFrom4([4]byte{})
}

// lookupSeq numbers the RTM_GET requests this process makes, so a reply can be
// matched to the request that asked for it. A routing socket carries every
// other program's traffic too, and a reply read off the wrong message would
// name whichever interface somebody else was asking about.
var lookupSeq atomic.Int32

// lookupSocket opens the routing socket one lookup writes its request to and reads its answer from
// it is apart from routeRequest so that a test can read back the receive queue the kernel granted it
func lookupSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return 0, fmt.Errorf("kernel: open a routing socket to ask for a route: %w", err)
	}
	unix.CloseOnExec(fd)
	// SO_USELOOPBACK stays on, unlike the reconciler's write socket: the reply
	// to an RTM_GET comes back the same way an echo does, and silencing the
	// echo would silence the answer.

	// the replies other lookups make queue here ahead of this one's own
	// and a routing socket that overflows drops the excess without telling its reader
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, routeReceiveBuffer); err != nil {
		_ = unix.Close(fd)
		return 0, fmt.Errorf("kernel: size the receive queue of the route lookup: %w", err)
	}
	return fd, nil
}

// routeRequest is the request itself, separated from what is read off the
// answer so that a test can look at the gateway the kernel named rather than
// guess which address it was. An invalid mask sends no RTAX_NETMASK, which is
// the longest-prefix question, while a valid one asks for that exact key, because
// XNU turns an RTM_GET carrying a netmask into a lookup of that key alone.
// lookupDefault asks that way, since the mesh's own routes cover the key it
// is after and a match would answer with those.
//
// The request is the one `route -n get` makes. The technique is tailscale's,
// read from net/netns/netns_darwin.go, which is BSD-3-Clause. Nothing here is
// copied from it.
func routeRequest(destination, mask netip.Addr) (*route.RouteMessage, error) {
	fd, err := lookupSocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	seq := int(lookupSeq.Add(1))
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(destination)
	if mask.IsValid() {
		addrs[unix.RTAX_NETMASK] = routeAddr(mask)
	}
	request := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		Flags:   unix.RTF_UP,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
	raw, err := request.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kernel: encode a route lookup for %s: %w", destination, err)
	}
	if _, err := unix.Write(fd, raw); err != nil {
		// ESRCH is the kernel saying it has no route at all, which is the
		// answer rather than a failure of the mechanism.
		if gone(err) {
			return nil, ErrNoDefaultRoute
		}
		return nil, fmt.Errorf("kernel: ask for the route to %s: %w", destination, err)
	}
	return readAnswer(fd, seq, destination)
}

// readAnswer reads a routing socket until the reply to request seq arrives or lookupTimeout is over
// the deadline runs from the call, which routeRequest makes as soon as its write returns
// it is apart from routeRequest so that a test can give it a socket whose traffic the test chooses
func readAnswer(fd, seq int, destination netip.Addr) (*route.RouteMessage, error) {
	// A routing socket reports one message per read and the reply shares the
	// socket with whatever else the kernel is announcing, so the reads go on
	// until the reply or the deadline and each one is matched against the request.
	//
	// SO_RCVTIMEO bounds one read only, so each read is given what is left of the deadline
	deadline := time.Now().Add(lookupTimeout)
	buf := make([]byte, lookupReadSize)
	for left := lookupTimeout; left > 0; left = time.Until(deadline) {
		timeout := unix.NsecToTimeval(int64(left))
		if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
			return nil, fmt.Errorf("kernel: bound the route lookup: %w", err)
		}
		n, err := unix.Read(fd, buf)
		if errors.Is(err, unix.EAGAIN) {
			// the receive timeout, and the loop asks the deadline whether it is over
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("kernel: read the route to %s: %w", destination, err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
		if err != nil {
			continue
		}
		for _, message := range messages {
			rm, ok := message.(*route.RouteMessage)
			if !ok || rm.Type != unix.RTM_GET || rm.Seq != seq || rm.ID != uintptr(os.Getpid()) {
				continue
			}
			return rm, nil
		}
	}
	return nil, fmt.Errorf("kernel: the route to %s was not answered", destination)
}
