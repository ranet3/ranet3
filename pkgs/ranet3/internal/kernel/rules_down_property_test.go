// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// downReference is the down set as routing.md states it, rule by rule: for
// each overlay entry longer than /0, masked, in its family, a refusal at 32765
// and a lookup of main at 32764 suppressing every route shorter than the entry
func downReference(overlay []schema.Prefix) map[Rule]bool {
	out := map[Rule]bool{}
	for _, entry := range overlay {
		if !entry.Prefix.IsValid() || entry.Prefix.Bits() == 0 {
			continue
		}
		to := schema.PrefixFrom(entry.Prefix.Masked())
		family := FamilyIPv6
		if to.Addr().Is4() {
			family = FamilyIPv4
		}
		out[Rule{Family: family, Priority: 32765, To: to, action: actionUnreachable}] = true
		out[Rule{Family: family, Priority: 32764, To: to, Table: 254, suppress: SuppressUpTo(to.Bits() - 1)}] = true
	}
	return out
}

// drawnOverlayEntry is an overlay entry: none, or an address of either family
// with its host bits as drawn at a length from /0 to a host prefix
func drawnOverlayEntry(tc hegel.TestCase) schema.Prefix {
	width := 4
	switch hegel.Draw(tc, pbt.Spanning(0, 2)) {
	case 0:
		return schema.Prefix{}
	case 2:
		width = 16
	}
	raw := make([]byte, width)
	for i := range raw {
		raw[i] = byte(hegel.Draw(tc, hegel.Integers(0, 255)))
	}
	address, _ := netip.AddrFromSlice(raw)
	return schema.PrefixFrom(netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, 8*width))))
}

// For every overlay the down set holds exactly the reference's rules, each
// once, and each prefix's refusal ahead of its lookup of main, so a stop that
// adds them in order never holds the lookup without the refusal behind it
func TestDownSetIsTwoRulesForEachOverlayPrefix(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []schema.Prefix
		for range hegel.Draw(ht, pbt.Spanning(0, 6)) {
			// an entry written twice is one prefix
			if len(overlay) > 0 && hegel.Draw(ht, pbt.Spanning(0, 3)) == 3 {
				overlay = append(overlay, overlay[hegel.Draw(ht, hegel.Integers(0, len(overlay)-1))])
				continue
			}
			overlay = append(overlay, drawnOverlayEntry(ht))
		}
		got, want := downRules(overlay), downReference(overlay)
		at := map[Rule]int{}
		for i, rule := range got {
			if !want[rule] {
				ht.Fatalf("the down set of %v holds %s, which the reference does not", overlay, rule)
			}
			if _, twice := at[rule]; twice {
				ht.Fatalf("the down set of %v holds %s twice", overlay, rule)
			}
			at[rule] = i
		}
		if len(at) != len(want) {
			ht.Fatalf("the down set of %v is %v, want the %d rules of %v", overlay, got, len(want), want)
		}
		for rule, i := range at {
			if rule.Priority != 32764 {
				continue
			}
			refusal := Rule{Family: rule.Family, Priority: 32765, To: rule.To, action: actionUnreachable}
			if at[refusal] > i {
				ht.Fatalf("the down set of %v holds %s ahead of %s", overlay, rule, refusal)
			}
		}
	})
}

// For any overlay and any links, the down set holds the pair of each overlay prefix that no network or point-to-point far end of a
// link but the loopback equals or covers, and of no other prefix, and these are the prefixes a running pass holds by its
// unreachable route, so a stop holds no prefix the running node sends onto a link
func TestDownSetLeavesOutEachPrefixALinkHoldsWhole(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []schema.Prefix
		for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			overlay = append(overlay, drawnOverlayEntry(ht))
		}
		var network NetworkState
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			address := drawnOverlayEntry(ht).Prefix
			// most links meet an entry, at a length on either side of it
			if entry := overlay[hegel.Draw(ht, hegel.Integers(0, len(overlay)-1))].Prefix; entry.IsValid() && hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				address = netip.PrefixFrom(entry.Addr(), hegel.Draw(ht, pbt.Spanning(0, entry.Addr().BitLen())))
			}
			if !address.IsValid() {
				continue
			}
			link := Link{Name: []string{"eth0", "eth1", Loopback}[hegel.Draw(ht, pbt.Spanning(0, 2))]}
			if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
				link.Peers = []netip.Prefix{address}
			} else {
				link.Prefixes = []netip.Prefix{address}
			}
			family := &network.IPv4
			if address.Addr().Is6() {
				family = &network.IPv6
			}
			family.Links = append(family.Links, link)
		}
		var carved []netip.Prefix
		for _, carveOut := range CarveOuts(network, overlay) {
			carved = append(carved, carveOut.Prefix)
		}
		got := map[netip.Prefix]bool{}
		for _, rule := range downRules(heldOverlay(overlay, carved)) {
			got[rule.To.Prefix] = true
		}
		want := map[netip.Prefix]bool{}
		for _, entry := range overlay {
			if !entry.Prefix.IsValid() || entry.Prefix.Bits() == 0 {
				continue
			}
			to := entry.Prefix.Masked()
			whole := false
			for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
				for _, address := range slices.Concat(link.Prefixes, link.Peers) {
					whole = whole || link.Name != Loopback && address.Bits() <= to.Bits() && address.Contains(to.Addr())
				}
			}
			if !whole {
				want[to] = true
			}
		}
		if !maps.Equal(got, want) {
			ht.Fatalf("beside the links %+v the down set of %v holds the prefixes %v, want %v", network, overlay, got, want)
		}
		holds := map[netip.Prefix]bool{}
		running := &Reconciler{rt: Runtime{Overlay: overlay}}
		for _, hold := range running.overlayHolds(nil, carved) {
			if hold.Destination.Bits() > 0 {
				holds[hold.Destination] = true
			}
		}
		if !maps.Equal(got, holds) {
			ht.Fatalf("beside the links %+v the down set of %v holds the prefixes %v, and a running pass holds %v", network, overlay, got, holds)
		}
	})
}
