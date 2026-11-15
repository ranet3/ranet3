// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// benchPrefix is the prefix of length under base offset prefixes of that
// length from its first
func benchPrefix(base netip.Prefix, offset uint64, length int) netip.Prefix {
	raw := base.Masked().Addr().As16()
	hi, lo := binary.BigEndian.Uint64(raw[:8]), binary.BigEndian.Uint64(raw[8:])
	shift := uint(128 - length)
	addHi, addLo := offset<<(shift-64), uint64(0)
	if shift < 64 {
		addHi, addLo = offset>>(64-shift), offset<<shift
	}
	lo, carry := bits.Add64(lo, addLo, 0)
	hi, _ = bits.Add64(hi, addHi, carry)
	binary.BigEndian.PutUint64(raw[:8], hi)
	binary.BigEndian.PutUint64(raw[8:], lo)
	return netip.PrefixFrom(netip.AddrFrom16(raw), length)
}

// benchTiling is n prefixes of /127 or shorter tiling inner in address order,
// as many of them in its lower half as it holds /127s but one
func benchTiling(inner netip.Prefix, n int) []netip.Prefix {
	if n == 1 {
		return []netip.Prefix{inner}
	}
	if inner.Bits() >= 127 || n < 1 {
		panic("no tiling")
	}
	lower := n - 1
	if shift := 127 - inner.Bits() - 1; shift < 62 {
		lower = min(lower, 1<<shift)
	}
	return append(benchTiling(netip.PrefixFrom(inner.Addr(), inner.Bits()+1), lower), benchTiling(benchPrefix(inner, 1, inner.Bits()+1), n-lower)...)
}

// benchPass is a darwin-like reconciler on the covering fake, which scopes
// each hold, over the entries fill sets, timed over passes after a first one
// has installed them, change setting the table before each
func benchPass(b *testing.B, fill func(*netstack.RouteTable), change func(*netstack.RouteTable, int)) {
	b.Helper()
	rt := Runtime{Interface: "ranet0", Overlay: coverOverlay, Sessions: func() int { return 1 }}
	tbl := Table{}.Normalized()
	table := netstack.NewRouteTable()
	fake := newFakeKernel(nil)
	reconciler := newReconciler(tbl, rt, tbl.Assigned(rt.Announced), table, fake)
	onCovering(reconciler, fake, coverAddresses...)
	fill(table)
	if err := reconciler.reconcile(); err != nil {
		b.Fatal(err)
	}
	adds, dels := fake.counts()
	b.ResetTimer()
	for i := range b.N {
		if change != nil {
			change(table, i)
		}
		if err := reconciler.reconcile(); err != nil {
			b.Fatal(err)
		}
	}
	stats := reconciler.Stats()
	moreAdds, moreDels := fake.counts()
	b.ReportMetric(float64(adds), "routes")
	b.ReportMetric(float64(stats.HoldPieces), "pieces")
	b.ReportMetric(float64(stats.HoldsWhole), "whole")
	b.ReportMetric(float64(moreAdds-adds+moreDels-dels)/float64(b.N), "writes/op")
}

// A pass over a full table on a platform that scopes its holds: no hold, holds
// with no live route inside, which every Mac pays in every pass, one hold
// around one live route, holds of one live route each cut until their pieces
// would pass the budget and whole after, with a live route coming and going in
// the first that moves the last cut one, holds each just past what is left,
// and the deepest chain of nested holds whose pieces all fit
func BenchmarkRoutePass(b *testing.B) {
	under := prefix("2001:db8::/32")
	b.Run("no hold", func(b *testing.B) {
		benchPass(b, func(table *netstack.RouteTable) {
			for i := range uint64(meshRouteKeys) {
				table.Set(netip.Prefix{}, benchPrefix(under, i, 64), nil)
			}
		}, nil)
	})
	// the /64s under under from the from'th on, every sixteenth a hold with no
	// live route inside
	holdsApart := func(table *netstack.RouteTable, from uint64) {
		for i := from; i < meshRouteKeys; i++ {
			var peer *netstack.Peer
			if i%16 == 15 {
				peer = netstack.Unreachable
			}
			table.Set(netip.Prefix{}, benchPrefix(under, i, 64), peer)
		}
	}
	b.Run("no hold cut", func(b *testing.B) {
		benchPass(b, func(table *netstack.RouteTable) { holdsApart(table, 0) }, nil)
	})
	b.Run("one hold cut", func(b *testing.B) {
		benchPass(b, func(table *netstack.RouteTable) {
			table.Set(netip.Prefix{}, benchPrefix(under, 0, 63), netstack.Unreachable)
			table.Set(netip.Prefix{}, benchPrefix(under, 0, 64), nil)
			holdsApart(table, 2)
		}, nil)
	})
	b.Run("at the budget", func(b *testing.B) {
		first := benchPrefix(under, 0, 48)
		moving := netip.PrefixFrom(benchPrefix(first, 1, 49).Addr(), 127)
		benchPass(b, func(table *netstack.RouteTable) {
			for i := range uint64(meshRouteKeys / 2) {
				hold := benchPrefix(under, i, 48)
				table.Set(netip.Prefix{}, hold, netstack.Unreachable)
				table.Set(netip.Prefix{}, netip.PrefixFrom(hold.Addr(), 127), nil)
			}
		}, func(table *netstack.RouteTable, i int) {
			if i%2 == 0 {
				table.Set(netip.Prefix{}, moving, nil)
			} else {
				table.Remove(netip.Prefix{}, moving)
			}
		})
	})
	// holds /40 of 52 live /127s each, at the first address of a /46 of it
	// each, 4214 pieces a hold
	b.Run("past what is left", func(b *testing.B) {
		benchPass(b, func(table *netstack.RouteTable) {
			for i := range uint64(meshRouteKeys / 53) {
				hold := benchPrefix(prefix("3fff:800::/21"), i, 40)
				table.Set(netip.Prefix{}, hold, netstack.Unreachable)
				for j := range uint64(52) {
					table.Set(netip.Prefix{}, netip.PrefixFrom(benchPrefix(hold, j, 46).Addr(), 127), nil)
				}
			}
		}, nil)
	})
	// holds /21 to /111 at one address, each around the same live routes
	// tiling the /111, so hold b takes 111-b pieces, 4095 in all
	b.Run("deep chain", func(b *testing.B) {
		const outer, inner = 21, 111
		at := prefix("3fff:800::/21").Addr()
		benchPass(b, func(table *netstack.RouteTable) {
			for length := outer; length <= inner; length++ {
				table.Set(netip.Prefix{}, netip.PrefixFrom(at, length), netstack.Unreachable)
			}
			for _, p := range benchTiling(netip.PrefixFrom(at, inner), meshRouteKeys-(inner-outer+1)) {
				table.Set(netip.Prefix{}, p, nil)
			}
		}, nil)
	})
}
