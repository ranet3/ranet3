// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/sadr"
)

// exemptSpaces is the addresses the property draws inside, in either family
// an overlay of 64 addresses
var exemptSpaces = [...]netip.Prefix{netip.MustParsePrefix("192.0.2.0/26"), netip.MustParsePrefix("3fff::/122")}

// drawnExemptPrefix draws a prefix inside space, or once in a while the
// prefix one bit shorter around it, wider than the overlay
func drawnExemptPrefix(tc hegel.TestCase, space netip.Prefix) netip.Prefix {
	if hegel.Draw(tc, pbt.Spanning(0, 9)) == 0 {
		return netip.PrefixFrom(space.Addr(), space.Bits()-1).Masked()
	}
	bits := hegel.Draw(tc, pbt.Spanning(space.Bits(), space.Addr().BitLen()))
	offset := hegel.Draw(tc, pbt.Spanning(0, 63))
	address := space.Addr().AsSlice()
	address[len(address)-1] |= byte(offset)
	drawn, _ := netip.AddrFromSlice(address)
	return netip.PrefixFrom(drawn, bits).Masked()
}

// an address of an exemption is carved exactly where it is this node's own
// address, or where an entry of the mesh's table routed via a peer, inside
// the overlay, holds it and no range of this node's own inside that entry
// does, and each conflict is an exemption and such an entry carving some of
// it, in either family
func TestExemptCarvedDropsWhatTheModelDrops(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		exemptSpace := exemptSpaces[hegel.Draw(ht, pbt.Spanning(0, len(exemptSpaces)-1))]
		overlay := prefixes(exemptSpace)
		draw := func(most int) []netip.Prefix {
			out := make([]netip.Prefix, hegel.Draw(ht, pbt.Spanning(0, most)))
			for i := range out {
				out[i] = drawnExemptPrefix(ht, exemptSpace)
			}
			return out
		}
		var exemptions []egress.Exemption
		for _, prefix := range draw(3) {
			exemptions = append(exemptions, egress.Exemption{Interface: []string{"", "eth1"}[hegel.Draw(ht, pbt.Spanning(0, 1))], Prefix: prefix})
		}
		own := draw(3)
		var addresses []netip.Prefix
		for _, prefix := range draw(2) {
			addresses = append(addresses, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()))
		}
		routes := netstack.NewRouteTable()
		values := []*netstack.Peer{learned, netstack.Local, netstack.Assigned, netstack.Unreachable}
		for _, prefix := range draw(4) {
			routes.Set(netip.Prefix{}, prefix, values[hegel.Draw(ht, pbt.Spanning(0, len(values)-1))])
		}
		snapshot := routes.Snapshot()
		carved, conflicts := ExemptCarved(exemptions, own, addresses, snapshot, overlay)
		another := func(entry sadr.Route[*netstack.Peer]) bool {
			return entry.Value == learned && encloses(exemptSpace, entry.Destination)
		}
		takes := func(entry sadr.Route[*netstack.Peer], address netip.Addr) bool {
			return another(entry) && entry.Destination.Contains(address) &&
				!slices.ContainsFunc(own, func(r netip.Prefix) bool { return encloses(entry.Destination, r) && r.Contains(address) })
		}
		var wantConflicts []egress.ExemptConflict
		for _, exemption := range exemptions {
			for _, entry := range snapshot {
				if !another(entry) || !exemption.Prefix.Overlaps(entry.Destination) {
					continue
				}
				both := entry.Destination
				if exemption.Prefix.Bits() > both.Bits() {
					both = exemption.Prefix
				}
				for address := both.Addr(); both.Contains(address); address = address.Next() {
					if takes(entry, address) {
						wantConflicts = append(wantConflicts, egress.ExemptConflict{Exemption: exemption, Prefix: entry.Destination, Carved: both, Via: learned.ID})
						break
					}
				}
			}
		}
		slices.SortFunc(wantConflicts, compareConflicts)
		wantConflicts = slices.Compact(wantConflicts)
		if !slices.Equal(conflicts, wantConflicts) {
			ht.Fatalf("exemptions %v, own %v, table %v: conflicts\n%v\nwant\n%v", exemptions, own, snapshot, conflicts, wantConflicts)
		}
		var want []netip.Prefix
		space := netip.PrefixFrom(exemptSpace.Addr(), exemptSpace.Bits()-1).Masked()
		for address := space.Addr(); space.Contains(address); address = address.Next() {
			inside := slices.ContainsFunc(exemptions, func(e egress.Exemption) bool { return e.Prefix.Contains(address) })
			mine := slices.ContainsFunc(addresses, func(a netip.Prefix) bool { return a.Addr() == address })
			theirs := slices.ContainsFunc(exemptions, func(e egress.Exemption) bool {
				return e.Prefix.Contains(address) && slices.ContainsFunc(snapshot, func(entry sadr.Route[*netstack.Peer]) bool { return takes(entry, address) })
			})
			if inside && (mine || theirs) {
				want = append(want, netip.PrefixFrom(address, address.BitLen()))
			}
		}
		if got := RangePrefixes(carved...); !slices.Equal(Ranges(got), Ranges(want)) {
			ht.Fatalf("exemptions %v, own %v, addresses %v, table %v: carved\n%v\nwant\n%v", exemptions, own, addresses, snapshot, got, RangePrefixes(Ranges(want)...))
		}
	})
}
