// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// assignedUniverses are the blocks a drawn node's overlay entries, classes and
// assigned prefixes lie in, one a family, each small enough for the model to
// walk every address of a network
var assignedUniverses = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:5::/120")}

// drawnIn takes within no shorter than its universe, so only the last byte
// varies
func drawnIn(ht *hegel.T, within netip.Prefix) netip.Prefix {
	raw := within.Masked().Addr().AsSlice()
	raw[len(raw)-1] |= hegel.Draw(ht, hegel.Integers[byte](0, 255)) & (0xff >> (within.Bits() - (len(raw)-1)*8))
	address, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(address, hegel.Draw(ht, pbt.Spanning(within.Bits(), address.BitLen())))
}

// drawnWithin is universe, or half the time a drawn class, so classes nest and
// a network lies inside a longer class often enough to meet the longest match
func drawnWithin(ht *hegel.T, universe netip.Prefix, classes []egress.Class) netip.Prefix {
	if len(classes) == 0 || !hegel.Draw(ht, hegel.Booleans()) {
		return universe
	}
	return classes[hegel.Draw(ht, pbt.Spanning(0, len(classes)-1))].From.Prefix
}

// connectedRefusal is the model of the refusal, which walks every address of
// each network rather than its ranges
func connectedRefusal(assigned []netip.Prefix, overlay []schema.Prefix, classes []egress.Class) (netip.Prefix, egress.Class, bool) {
	for _, prefix := range assigned {
		if prefix.Bits() == prefix.Addr().BitLen() {
			continue
		}
		network := prefix.Masked()
		for address := network.Addr(); address.IsValid() && network.Contains(address); address = address.Next() {
			if slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return entry.Contains(address) }) {
				continue
			}
			longest, found := -1, egress.Class{}
			for _, class := range classes {
				if class.From.Contains(address) && class.From.Bits() > longest {
					longest, found = class.From.Bits(), class
				}
			}
			if longest >= 0 && found.To.None {
				return prefix, found, true
			}
		}
	}
	return netip.Prefix{}, egress.Class{}, false
}

// An exit whose overlay, classes of none and auto and assigned prefixes,
// addresses and an announced prefix assign_announced assigns, are drawn inside
// one of assignedUniverses is refused where the model finds an address of an
// assigned network outside the overlay whose longest covering class is none,
// naming the first such prefix and that class, and loads everywhere else.
func TestConnectedNetworkRefusalMatchesTheModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		universe := assignedUniverses[hegel.Draw(ht, pbt.Spanning(0, len(assignedUniverses)-1))]
		overlay := slices.Clone(connectedOverlay)
		for range hegel.Draw(ht, pbt.Spanning(0, 2)) {
			if entry := (schema.Prefix{Prefix: drawnIn(ht, universe).Masked()}); !slices.Contains(overlay, entry) {
				overlay = append(overlay, entry)
			}
		}
		var classes []egress.Class
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			from := schema.Prefix{Prefix: drawnIn(ht, drawnWithin(ht, universe, classes)).Masked()}
			if slices.ContainsFunc(classes, func(class egress.Class) bool { return class.From == from }) {
				continue
			}
			to := egress.Translation{Auto: true}
			if hegel.Draw(ht, hegel.Booleans()) {
				to = egress.Translation{None: true}
			}
			classes = append(classes, egress.Class{From: from, To: to})
		}
		c := assigningExit(classes)
		c.Overlay = overlay
		var assigned []netip.Prefix
		for range hegel.Draw(ht, pbt.Spanning(1, 2)) {
			prefix := drawnIn(ht, drawnWithin(ht, universe, classes))
			c.Cap.Table.Addresses = append(c.Cap.Table.Addresses, schema.Prefix{Prefix: prefix})
			assigned = append(assigned, prefix)
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			announced := drawnIn(ht, universe).Masked()
			c = withAnnounced(c, true, announced.String())
			assigned = append(assigned, announced)
		}
		prefix, class, refused := connectedRefusal(assigned, overlay, classes)
		err := c.Validate()
		switch {
		case !refused && err != nil:
			ht.Fatalf("overlay %v, classes %v and assigned %v, which the model takes, were refused: %v", overlay, classes, assigned, err)
		case refused && err == nil:
			ht.Fatalf("overlay %v, classes %v and assigned %v loaded, want %s refused under class %s", overlay, classes, assigned, prefix, class.From)
		case refused && (!strings.Contains(err.Error(), fmt.Sprintf("cap.table assigns %s,", prefix)) || !strings.Contains(err.Error(), fmt.Sprintf("class %s,", class.From))):
			ht.Fatalf("overlay %v, classes %v and assigned %v were refused with %v, want %s and class %s named", overlay, classes, assigned, err, prefix, class.From)
		}
	})
}
