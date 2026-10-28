// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// selectMesh is the index of ranet3's own interface in a drawn table
const selectMesh = 1

// selectIndexes are the interfaces a drawn route leaves by, ranet3's among them
var selectIndexes = []int{selectMesh, 2, 3}

// selectTarget is one destination asked about, with the interface its zone names
type selectTarget struct {
	address netip.Addr
	zone    int
}

// selectCase is one host table and the destinations asked about it
type selectCase struct {
	routes  []hostRoute
	targets []selectTarget
}

// selectAddress is base most of the time, so the routes drawn around it nest, and otherwise any address of its family
func selectAddress(tc hegel.TestCase, base netip.Addr) netip.Addr {
	if !hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		return base
	}
	if base.Is4() {
		return hegel.Draw(tc, hegel.IPAddresses().IPv4())
	}
	return hegel.Draw(tc, hegel.IPAddresses().IPv6())
}

func selectCases() hegel.Generator[selectCase] {
	return hegel.Composite(func(tc hegel.TestCase) selectCase {
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		var c selectCase
		for range hegel.Draw(tc, pbt.Spanning(0, 12)) {
			address := selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))])
			bits := hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))
			c.routes = append(c.routes, hostRoute{
				destination: netip.PrefixFrom(address, bits).Masked(),
				index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes)),
				scoped:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
				cloned:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
				multicast:   hegel.Draw(tc, hegel.WeightedBooleans(1.0/10)),
				broadcast:   hegel.Draw(tc, hegel.WeightedBooleans(1.0/10)),
			})
		}
		for _, base := range bases {
			c.targets = append(c.targets, selectTarget{address: base})
		}
		for _, r := range c.routes {
			c.targets = append(c.targets, selectTarget{address: r.destination.Addr()}, selectTarget{address: lastAddress(r.destination)})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 4)) {
			address := selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))])
			// a zone the selection cannot resolve to an interface leaves the address to the routes
			if address.Is6() && hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
				address = address.WithZone("en9")
			}
			c.targets = append(c.targets, selectTarget{address: address})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			raw := hegel.Draw(tc, hegel.IPAddresses().IPv6()).As16()
			raw[0], raw[1] = 0xfe, 0x80
			zone := hegel.Draw(tc, hegel.SampledFrom(append([]int{0}, selectIndexes...)))
			c.targets = append(c.targets, selectTarget{address: netip.AddrFrom16(raw), zone: zone})
		}
		return c
	})
}

// Over drawn tables, the selection is the longest of the routes holding the
// destination that a socket scoped to no interface reaches, out of an
// interface other than ranet3's, or no route where none holds it. A
// link-local destination with a zone leaves by the zone's interface, unless
// that is ranet3's, and a zone that names no interface leaves the address to
// the routes. No answer names ranet3's interface.
func TestSelectionIsTheLongestHostRouteOutsideTheMesh(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, selectCases())
		for _, target := range c.targets {
			got, ok := selectRoute(c.routes, selectMesh, target.address, target.zone)
			if ok && got.index == selectMesh {
				ht.Fatalf("%s %% %d selects ranet3's own interface by %+v\nroutes %+v", target.address, target.zone, got, c.routes)
			}
			if target.zone != 0 && target.address.IsLinkLocalUnicast() {
				if want := target.zone != selectMesh; ok != want || (ok && got.index != target.zone) {
					ht.Fatalf("%s %% %d selects %+v, %v", target.address, target.zone, got, ok)
				}
				continue
			}
			longest := -1
			var holders []hostRoute
			for _, r := range c.routes {
				reached := r.index != selectMesh && !r.scoped && !r.cloned && !r.multicast && !r.broadcast
				if reached && r.destination.Contains(target.address.WithZone("")) {
					holders = append(holders, r)
					longest = max(longest, r.destination.Bits())
				}
			}
			if ok != (len(holders) > 0) {
				ht.Fatalf("%s selects %+v, %v, with %d routes holding it\nroutes %+v", target.address, got, ok, len(holders), c.routes)
			}
			if !ok {
				continue
			}
			held := false
			for _, r := range holders {
				held = held || r == got
			}
			if !held || got.destination.Bits() != longest {
				ht.Fatalf("%s selects %+v, want one of %+v at /%d\nroutes %+v", target.address, got, holders, longest, c.routes)
			}
		}
	})
}
