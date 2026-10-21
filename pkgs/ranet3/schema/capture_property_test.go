// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package schema

import (
	"math/big"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// floorOf is the design's floor for a family, written out rather than read
// from the constants, which holds the code to it
func floorOf(is4 bool) int {
	if is4 {
		return 8
	}
	return 16
}

// span is the run of addresses a prefix holds, as the integers its first and
// last address spell
func span(p netip.Prefix) (first, last *big.Int) {
	raw := p.Masked().Addr().AsSlice()
	first = new(big.Int).SetBytes(raw)
	size := new(big.Int).Lsh(big.NewInt(1), uint(len(raw)*8-p.Bits()))
	return first, size.Add(size, first).Sub(size, big.NewInt(1))
}

// countsInModel is the predicate as host-side 1.3 states it, read over runs of
// addresses: p counts when it holds address 0 of its family, or when it is
// shorter than its family's floor and holds an address that no overlay entry
// of its family holds
func countsInModel(p netip.Prefix, overlay []Prefix) bool {
	first, last := span(p)
	if first.Sign() == 0 {
		return true
	}
	if p.Bits() >= floorOf(p.Addr().Is4()) {
		return false
	}
	var runs [][2]*big.Int
	for _, o := range overlay {
		if o.Addr().Is4() == p.Addr().Is4() {
			a, b := span(o.Prefix)
			runs = append(runs, [2]*big.Int{a, b})
		}
	}
	slices.SortFunc(runs, func(x, y [2]*big.Int) int { return x[0].Cmp(y[0]) })
	// the lowest address of p no run reaches yet
	next := first
	for _, run := range runs {
		if run[0].Cmp(next) > 0 {
			break
		}
		if run[1].Cmp(next) >= 0 {
			next = new(big.Int).Add(run[1], big.NewInt(1))
		}
	}
	return next.Cmp(last) <= 0
}

// drawAddr draws an address of one family byte by byte, each byte's ends drawn
// outright
func drawAddr(tc hegel.TestCase, is4 bool) netip.Addr {
	raw := make([]byte, 16)
	if is4 {
		raw = raw[:4]
	}
	for i := range raw {
		raw[i] = hegel.Draw(tc, pbt.Spanning[byte](0, 255))
	}
	address, _ := netip.AddrFromSlice(raw)
	return address
}

// drawLength draws a prefix length of a family: the floor outright, one of its
// neighbors outright, a length shorter than the floor outright, or any length
func drawLength(tc hegel.TestCase, is4 bool) int {
	floor, width := floorOf(is4), 128
	if is4 {
		width = 32
	}
	switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
	case 0:
		return floor
	case 1:
		return floor - 1 + 2*hegel.Draw(tc, pbt.Spanning(0, 1))
	case 2:
		return hegel.Draw(tc, pbt.Spanning(0, floor-1))
	}
	return hegel.Draw(tc, pbt.Spanning(0, width))
}

// halves is a masked prefix's two halves, lower first
func halves(p netip.Prefix) [2]netip.Prefix {
	raw := p.Addr().AsSlice()
	raw[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	upper, _ := netip.AddrFromSlice(raw)
	return [2]netip.Prefix{netip.PrefixFrom(p.Addr(), p.Bits()+1), netip.PrefixFrom(upper, p.Bits()+1)}
}

// tileLimit is how many levels below a prefix its tiling reaches at most, past
// any narrowing of the union check to entries a few bits longer
const tileLimit = 7

// tile splits a masked prefix into its halves while must is above 0, and after
// that on drawn bits while left is, each split taking one level from both
func tile(tc hegel.TestCase, p netip.Prefix, must, left int) []netip.Prefix {
	if left == 0 || must == 0 && hegel.Draw(tc, pbt.Spanning(0, 1)) == 0 {
		return []netip.Prefix{p}
	}
	var pieces []netip.Prefix
	for _, half := range halves(p) {
		pieces = append(pieces, tile(tc, half, max(must-1, 0), left-1)...)
	}
	return pieces
}

// The predicate agrees with the model over both families and every length,
// for a prefix drawn inside, around, beside or apart from a drawn overlay
// entry, over the zero address, or tiled by overlay entries each at least a
// drawn depth below it, with one piece left out or none.
func TestCapturesTheMachineAgreesWithTheModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var overlay []Prefix
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			is4 := hegel.Draw(ht, pbt.Spanning(0, 1)) == 0
			overlay = append(overlay, PrefixFrom(netip.PrefixFrom(drawAddr(ht, is4), drawLength(ht, is4)).Masked()))
		}
		is4 := hegel.Draw(ht, pbt.Spanning(0, 1)) == 0
		address, bits := drawAddr(ht, is4), drawLength(ht, is4)
		shape := hegel.Draw(ht, pbt.Spanning(0, 6))
		var near Prefix
		if len(overlay) > 0 {
			near = overlay[hegel.Draw(ht, hegel.Integers(0, len(overlay)-1))]
		}
		switch {
		case shape == 4:
			address = netip.IPv6Unspecified()
			if is4 {
				address = netip.IPv4Unspecified()
			}
		case shape >= 5:
			// shorter than the floor and tiled by entries, every piece at least
			// a drawn depth below it, each piece an entry but the one left out,
			// if any
			bits = hegel.Draw(ht, pbt.Spanning(1, floorOf(is4)-1))
			depth := hegel.Draw(ht, pbt.Spanning(1, tileLimit))
			pieces := tile(ht, netip.PrefixFrom(address, bits).Masked(), depth, tileLimit)
			out := len(pieces)
			if hegel.Draw(ht, pbt.Spanning(0, 3)) == 3 {
				out = hegel.Draw(ht, hegel.Integers(0, len(pieces)-1))
			}
			for i, piece := range pieces {
				if i != out {
					overlay = append(overlay, PrefixFrom(piece))
				}
			}
		case shape == 0 || !near.IsValid() || near.Addr().Is4() != is4:
		case shape == 1:
			// inside, keeping the entry's bits and the drawn rest
			bits = near.Bits() + hegel.Draw(ht, pbt.Spanning(0, address.BitLen()-near.Bits()))
			address = splice(near.Addr(), address, near.Bits())
		case shape == 2:
			// around, a prefix of the entry's own address no longer than it
			address, bits = near.Addr(), hegel.Draw(ht, pbt.Spanning(0, near.Bits()))
		case shape == 3 && near.Bits() > 0:
			// beside, the entry with its last bit flipped
			raw := near.Addr().AsSlice()
			last := near.Bits() - 1
			raw[last/8] ^= 1 << (7 - last%8)
			address, _ = netip.AddrFromSlice(raw)
			bits = near.Bits()
		}
		p := netip.PrefixFrom(address, bits).Masked()
		if got, want := CapturesTheMachine(p, overlay), countsInModel(p, overlay); got != want {
			ht.Fatalf("%s under the overlay %v counts %v, the model says %v", p, overlay, got, want)
		}
	})
}

// splice is head's first n bits followed by tail's remaining ones
func splice(head, tail netip.Addr, n int) netip.Addr {
	a, b := head.AsSlice(), tail.AsSlice()
	for i := n; i < len(a)*8; i++ {
		mask := byte(1) << (7 - i%8)
		a[i/8] = a[i/8]&^mask | b[i/8]&mask
	}
	address, _ := netip.AddrFromSlice(a)
	return address
}
