// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import "net/netip"

// hostRoute is one route of the host's routing table as the underlay's selection reads it
type hostRoute struct {
	destination netip.Prefix
	index       int
	// scoped is a route only a socket scoped to its interface sees, and cloned a copy the kernel made of another route
	scoped, cloned bool
	// multicast and broadcast are the kernel's own entries for a link's group and broadcast addresses
	multicast, broadcast bool
}

// candidate reports whether a socket scoped to no interface reaches r, and r leaves by an interface other than mesh
// a reject or blackhole route stays a candidate, as the host's own lookup would take it
func (r hostRoute) candidate(mesh int) bool {
	return r.index != mesh && !r.scoped && !r.cloned && !r.multicast && !r.broadcast
}

// selectRoute is the route whose interface an underlay datagram to destination names, the longest candidate holding it
// a lookup carrying linux's underlay mark ends there, past every route of ranet3's own
// a link-local destination takes the interface zone names, unless that is mesh, and a zero zone names none
func selectRoute(routes []hostRoute, mesh int, destination netip.Addr, zone int) (hostRoute, bool) {
	destination = destination.WithZone("")
	if zone != 0 && destination.IsLinkLocalUnicast() {
		return hostRoute{index: zone}, zone != mesh
	}
	var best hostRoute
	found := false
	for _, r := range routes {
		if !r.candidate(mesh) || !r.destination.Contains(destination) {
			continue
		}
		if !found || r.destination.Bits() > best.destination.Bits() {
			best, found = r, true
		}
	}
	return best, found
}
