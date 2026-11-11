// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"net"
	"net/netip"

	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// Darwin is the macOS daemon's platform. interfaceOf is the node's underlay
// selection, the interface the host's own routes send to an address by with
// the mesh's left out, which scopes every socket of the exit's with
// IP_BOUND_IF or IPV6_BOUND_IF and refuses the flow where it names none
// (underlay.Bound). The route to an address is that interface, by its name and
// MTU, read when asked, so a provider's sandbox never needs the ioctl. held is
// the addresses the network watch reads off the links outside the mesh, on
// link, or on any where link is empty, and raw the root daemon's raw sockets,
// nil where the process may open none. The TCP relay's closed connections are
// held against the host ports their sockets pin (xnuHostSockets).
//
// Held asks an IPv4 address of the link a socket is scoped to, and an IPv6
// address of any link: with its sockets scoped to a utun, an exit had every
// IPv4 flow from an address on lo0 refused, while its IPv6 flows from an
// address on lo0 carried.
func Darwin(interfaceOf func(netip.Addr) (index int, generation uint64), held func(address netip.Addr, link string) bool, raw Raw) Platform {
	return Platform{
		Prepare: underlay.Bound(interfaceOf),
		Route: func(address netip.Addr) (Link, bool, error) {
			index, _ := interfaceOf(address)
			if index == 0 {
				return Link{}, false, nil
			}
			ifi, err := net.InterfaceByIndex(index)
			if err != nil {
				return Link{}, false, err
			}
			return Link{Name: ifi.Name, MTU: ifi.MTU}, true, nil
		},
		Held: func(address netip.Addr, link string) bool {
			if address.Is6() {
				link = ""
			}
			return held(address, link)
		},
		Raw:         raw,
		hostSockets: xnuHostSockets(),
	}
}
