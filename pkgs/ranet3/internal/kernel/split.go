// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
)

// splitAtKeys is desired with each unscoped route of the tun's at one of keys
// in its place as its two halves, which keep every other field, Cover among
// them. A platform whose own routes beside the tun's are keyed as the tun's
// are, darwin's switch rejects, holds one route a key, so a route of ours and
// one of the platform's at one key cannot both go in (bsd/net/radix.c
// rn_addroute). A scoped route is keyed apart and stays whole. A half gives
// way to a route at its own key, and one key's halves go in once.
func splitAtKeys(desired []Route, keys []netip.Prefix, scoped func(Route) bool) []Route {
	at := func(r Route) bool { return !scoped(r) && slices.Contains(keys, r.Destination) }
	if !slices.ContainsFunc(desired, at) {
		return desired
	}
	key := func(r Route) routeKey { return routeKey{destination: r.Destination, scoped: scoped(r)} }
	out := make([]Route, 0, len(desired)+len(keys))
	taken := make(map[routeKey]bool, len(desired))
	for _, r := range desired {
		if !at(r) {
			out = append(out, r)
			taken[key(r)] = true
		}
	}
	for _, r := range desired {
		if !at(r) {
			continue
		}
		for _, half := range halves(r.Destination) {
			piece := r
			piece.Destination = half
			if taken[key(piece)] {
				continue
			}
			taken[key(piece)] = true
			out = append(out, piece)
		}
	}
	return out
}

// halves is prefix's two halves, none for a full-length prefix
func halves(prefix netip.Prefix) []netip.Prefix {
	bits := prefix.Bits()
	if bits >= prefix.Addr().BitLen() {
		return nil
	}
	raw := prefix.Addr().AsSlice()
	raw[bits/8] |= 0x80 >> (bits % 8)
	upper, _ := netip.AddrFromSlice(raw)
	return []netip.Prefix{netip.PrefixFrom(prefix.Addr(), bits+1), netip.PrefixFrom(upper, bits+1)}
}

// splitKeys is the keys a route of ours out of the tun goes in as its halves
// at in this pass: the switch's rejects' on a platform writing it as routes,
// wherever the pass asks for it or one is left in from an earlier pass
func (r *Reconciler) splitKeys() []netip.Prefix {
	if !r.switchForm().routes || !r.switchAsked && r.fallbackClear {
		return nil
	}
	return rejectKeys
}
