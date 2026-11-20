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
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// unownedUniverses are the blocks a drawn overlay entry, class and held
// prefix lie in, one a family, each small enough for the model to walk every
// address of a network
var unownedUniverses = []netip.Prefix{prefix("198.51.100.0/24"), prefix("2001:db8:5::/120")}

// drawnUnowned takes within no shorter than its universe, so only the last
// byte varies
func drawnUnowned(ht *hegel.T, within netip.Prefix) netip.Prefix {
	raw := within.Masked().Addr().AsSlice()
	raw[len(raw)-1] |= hegel.Draw(ht, hegel.Integers[byte](0, 255)) & (0xff >> (within.Bits() - (len(raw)-1)*8))
	address, _ := netip.AddrFromSlice(raw)
	return netip.PrefixFrom(address, hegel.Draw(ht, pbt.Spanning(within.Bits(), address.BitLen())))
}

// unownedWithin is a drawn universe, or half the time a drawn class, so
// classes nest and a network lies inside a longer class often enough to meet
// the longest match
func unownedWithin(ht *hegel.T, classes []egress.Class) netip.Prefix {
	if len(classes) == 0 || !hegel.Draw(ht, hegel.Booleans()) {
		return unownedUniverses[hegel.Draw(ht, pbt.Spanning(0, len(unownedUniverses)-1))]
	}
	return classes[hegel.Draw(ht, pbt.Spanning(0, len(classes)-1))].From.Prefix
}

// connectedModel is the loader's model of its refusal for one prefix, which
// walks every address of its network rather than its ranges
func connectedModel(held netip.Prefix, overlay []schema.Prefix, classes []egress.Class) bool {
	if held.Bits() == held.Addr().BitLen() {
		return false
	}
	network := held.Masked()
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
			return true
		}
	}
	return false
}

// A pass warns of a prefix another writer holds on the tun exactly where the
// loader's model refuses the same prefix were it assigned, for overlay
// entries, nested classes of none and auto and held prefixes, each drawn
// inside either of unownedUniverses, so one case mixes the families
func TestUnownedWarningMatchesTheLoadersModel(t *testing.T) {
	logs := captureKernelLogs(t)
	pbt.Check(t, func(ht *hegel.T) {
		logs.Reset()
		var overlay []schema.Prefix
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			if entry := (schema.Prefix{Prefix: drawnUnowned(ht, unownedWithin(ht, nil)).Masked()}); !slices.Contains(overlay, entry) {
				overlay = append(overlay, entry)
			}
		}
		var classes []egress.Class
		for range hegel.Draw(ht, pbt.Spanning(0, 6)) {
			from := schema.Prefix{Prefix: drawnUnowned(ht, unownedWithin(ht, classes)).Masked()}
			if slices.ContainsFunc(classes, func(class egress.Class) bool { return class.From == from }) {
				continue
			}
			to := egress.Translation{Auto: true}
			if hegel.Draw(ht, hegel.Booleans()) {
				to = egress.Translation{None: true}
			}
			classes = append(classes, egress.Class{From: from, To: to})
		}
		// a class of the other translation inside a drawn one, so the longest match decides often
		if len(classes) > 0 && hegel.Draw(ht, hegel.Booleans()) {
			outer := classes[hegel.Draw(ht, pbt.Spanning(0, len(classes)-1))]
			from := schema.Prefix{Prefix: drawnUnowned(ht, outer.From.Prefix).Masked()}
			if !slices.ContainsFunc(classes, func(class egress.Class) bool { return class.From == from }) {
				classes = append(classes, egress.Class{From: from, To: egress.Translation{None: !outer.To.None, Auto: outer.To.None}})
			}
		}
		// a full-length address of another block, so the pass lists the tun
		r, _, kernel := harness(t, Table{Addresses: prefixes(prefix("203.0.113.1/32"))}, Runtime{Overlay: overlay, Classes: classes})
		var held []netip.Prefix
		for range hegel.Draw(ht, pbt.Spanning(1, 4)) {
			prefix := drawnUnowned(ht, unownedWithin(ht, classes))
			if slices.ContainsFunc(held, func(other netip.Prefix) bool { return other.Addr() == prefix.Addr() }) {
				continue
			}
			kernel.addrs[prefix] = true
			held = append(held, prefix)
		}
		if _, _, err := r.applyAddresses(); err != nil {
			ht.Fatalf("pass failed: %v", err)
		}
		warned := unownedWarnings(t, logs)
		for _, prefix := range held {
			if want := connectedModel(prefix, overlay, classes); (len(warned[prefix]) == 1) != want || len(warned[prefix]) > 1 {
				ht.Fatalf("overlay %v, classes %v: %s held was warned of %d times, and the model refuses it %v", overlay, classes, prefix, len(warned[prefix]), want)
			}
		}
	})
}
