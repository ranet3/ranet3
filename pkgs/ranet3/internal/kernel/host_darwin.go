// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// runningKernel is Host over PF_ROUTE and the address ioctls, the machine the
// daemon runs on. It carries no state: every descriptor it opens is either
// handed to the caller to close or closed before the call returns, so the
// lifetime questions stay with the objects that already own descriptors.
type runningKernel struct{}

// hostOr is the Host a caller named, or the running kernel where it named
// none. Every constructor in this package goes through it, so nil means the
// same thing everywhere rather than in each of them separately.
func hostOr(h Host) Host {
	if h == nil {
		return runningKernel{}
	}
	return h
}

func (runningKernel) RouteSocket() (RouteWriter, error) { return dialRouteSocket() }

func (runningKernel) Dump() ([]byte, error) {
	return refetched(func() ([]byte, error) { return route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0) })
}

// refetched is fetch's dump, fetched again on ENOMEM up to dumpAttempts times in all
// a table that grows between FetchRIB's sizing sysctl and its read fails with ENOMEM once FetchRIB's own tries run out
func refetched(fetch func() ([]byte, error)) ([]byte, error) {
	var (
		rib []byte
		err error
	)
	for range dumpAttempts {
		if rib, err = fetch(); !errors.Is(err, unix.ENOMEM) {
			break
		}
	}
	return rib, err
}

func (runningKernel) Addresses(index int) ([]netip.Prefix, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, index)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the addresses of interface %d: %w", index, err)
	}
	return interfaceAddrs(index, rib)
}

// Links reads the interface list and one address dump of every interface
// an IPv6 address gone between the dump and the read of its flags is left out, as the read its delete wakes leaves it
func (runningKernel) Links() ([]HostInterface, error) {
	devices, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("kernel: list the interfaces: %w", err)
	}
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeInterface, 0)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump the interfaces' addresses: %w", err)
	}
	held := make(map[int][]HostAddress)
	for len(rib) > 0 {
		size := 0
		if len(rib) >= 2 {
			size = int(binary.NativeEndian.Uint16(rib))
		}
		if size < 4 || size > len(rib) {
			return nil, errors.New("kernel: the address dump holds a message cut short")
		}
		if index, address, ok := decodeAddrMessage(rib[:size]); ok {
			held[index] = append(held[index], address)
		}
		rib = rib[size:]
	}
	out := make([]HostInterface, 0, len(devices))
	for _, device := range devices {
		link := HostInterface{
			Index: device.Index, Name: device.Name,
			Up: device.Flags&net.FlagUp != 0, PointToPoint: device.Flags&net.FlagPointToPoint != 0, Loopback: device.Flags&net.FlagLoopback != 0,
		}
		for _, address := range held[device.Index] {
			if address.Prefix.Addr().Is6() && address.Prefix.Addr().IsGlobalUnicast() {
				flags, err := addressFlags6(device.Name, address.Prefix.Addr())
				if gone(err) {
					continue
				}
				if err != nil {
					return nil, err
				}
				address.Flags = flags
			}
			link.Addresses = append(link.Addresses, address)
		}
		out = append(out, link)
	}
	return out, nil
}

// addressFlags6 reads ia6_flags of one IPv6 address on device, which the address dump does not carry (it carries ifa_flags)
func addressFlags6(device string, address netip.Addr) (uint32, error) {
	fd, err := controlSocket(unix.AF_INET6)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	request := make([]byte, sizeofIn6IfReq)
	copy(request[:unix.IFNAMSIZ], device)
	putSockaddrInet6(request[offIn6IfReqAddr:], address)
	if err := ioctlRequest(fd, siocGIfAFlagIn6, request); err != nil {
		return 0, fmt.Errorf("SIOCGIFAFLAG_IN6 on %s: %w", device, err)
	}
	return binary.NativeEndian.Uint32(request[offIn6IfReqAddr:]), nil
}

func (runningKernel) Lookup(destination, mask netip.Addr) (RouteAnswer, error) {
	answer, err := routeRequest(destination, mask)
	if err != nil {
		return RouteAnswer{}, err
	}
	out := RouteAnswer{Index: answer.Index, Reject: answer.Flags&unix.RTF_REJECT != 0}
	if prefix, ok := dumpedPrefix(answer); ok {
		out.Prefix = prefix
	}
	if len(answer.Addrs) > unix.RTAX_GATEWAY {
		if next, ok := addressFromRouteAddr(answer.Addrs[unix.RTAX_GATEWAY]); ok {
			out.Gateway = next.WithZone("")
		}
	}
	return out, nil
}

func (runningKernel) InterfaceIndex(name string) (int, error) {
	device, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("kernel: look up interface %s: %w", name, err)
	}
	return device.Index, nil
}

func (runningKernel) InterfaceName(index int) (string, error) {
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		return "", fmt.Errorf("kernel: name interface %d: %w", index, err)
	}
	return device.Name, nil
}

func (runningKernel) Watch(index, skip int) (Watcher, error) {
	return newRouteMonitor(index, skip)
}

// controlSocket is one socket of a family, which is all the address ioctls
// need: they are dispatched by the domain of the socket they arrive on and
// read nothing off it.
func controlSocket(family int) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, fmt.Errorf("kernel: open an address control socket: %w", err)
	}
	unix.CloseOnExec(fd)
	return fd, nil
}

// Assign sends the one ioctl of the four that names this family and this
// direction, down a control socket of that family: the request structures are
// dispatched by the domain of the socket they arrive on, so each family needs
// its own. The ioctl is named in the error, because an errno alone does not
// say which of the four answered.
//
// The request is built inside the branch that knows the family, never before
// it: deleteRequest4 reads the address as four bytes and panics on a v6
// prefix. The socket is opened per call because an assignment happens when an
// address is missing and at no other time, which on a settled node is never.
func (runningKernel) Assign(add bool, device string, prefix netip.Prefix) error {
	var (
		family  = unix.AF_INET
		name    string
		number  uintptr
		request []byte
		err     error
	)
	if !prefix.Addr().Is4() {
		family = unix.AF_INET6
	}
	switch v6 := family == unix.AF_INET6; {
	case add && v6:
		name, number = "SIOCAIFADDR_IN6", siocAIfAddrIn6
		request, err = aliasRequest6(device, prefix)
	case add:
		name, number = "SIOCAIFADDR", uintptr(unix.SIOCAIFADDR)
		request, err = aliasRequest4(device, prefix)
	case v6:
		name, number = "SIOCDIFADDR_IN6", siocDIfAddrIn6
		request = deleteRequest6(device, prefix)
	default:
		name, number = "SIOCDIFADDR", uintptr(unix.SIOCDIFADDR)
		request = deleteRequest4(device, prefix)
	}
	if err != nil {
		return err
	}
	fd, err := controlSocket(family)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := ioctlRequest(fd, number, request); err != nil {
		return fmt.Errorf("%s on %s: %w", name, device, err)
	}
	return nil
}
