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
// the addresses the network watch reads off the links outside the mesh, and
// raw the root daemon's raw sockets, nil where the process may open none.
func Darwin(interfaceOf func(netip.Addr) (index int, generation uint64), held func(netip.Addr) bool, raw Raw) Platform {
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
		Held: held,
		Raw:  raw,
	}
}
