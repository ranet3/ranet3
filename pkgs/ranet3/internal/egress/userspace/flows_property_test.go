// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"math"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any share, total and bound on host ports, 0 and none among them, and any
// order of TCP and UDP opens, closes that leave a TIME_WAIT, closes that do
// not and TIME_WAIT ends over a few sources of both families, a new flow is
// admitted exactly where its source's open and held flows are below the
// share and all of them below the total, and a TCP connection also where the
// open connections and the held ones are below the bound, and a refusal
// names the host ports, then the share, as share held where the source
// holds more held than open, then the total: the exit's limits on what a
// source can make it hold, a security check, against a model that counts
func TestFlowsAdmitExactlyWithinTheShareAndTheTotal(t *testing.T) {
	sources := []netip.Addr{leaf4, other4, leaf6, other6}
	pbt.Check(t, func(ht *hegel.T) {
		share := hegel.Draw(ht, pbt.Spanning(1, 6))
		total := hegel.Draw(ht, pbt.Spanning(1, 12))
		// no bound is hostHolds.limit's where nothing holds
		bound := math.MaxInt
		if hegel.Draw(ht, hegel.Booleans()) {
			bound = hegel.Draw(ht, pbt.Spanning(0, 8))
		}
		f := newFlows(share, total)
		udp, tcp, held := map[netip.Addr]int{}, map[netip.Addr]int{}, map[netip.Addr]int{}
		sum := func(by map[netip.Addr]int) int {
			n := 0
			for _, count := range by {
				n += count
			}
			return n
		}
		for range hegel.Draw(ht, hegel.Integers(0, 80)) {
			source := sources[hegel.Draw(ht, hegel.Integers(0, len(sources)-1))]
			switch hegel.Draw(ht, hegel.Integers(0, 5)) {
			case 0:
				if udp[source] > 0 {
					f.release(source)
					udp[source]--
				}
			case 1:
				if tcp[source] > 0 {
					f.release(source)
					tcp[source]--
				}
			case 2:
				if tcp[source] > 0 {
					f.hold(source)
					tcp[source]--
					held[source]++
				}
			case 3:
				if held[source] > 0 {
					f.unhold(source)
					held[source]--
				}
			default:
				isTCP := hegel.Draw(ht, hegel.Booleans())
				mine := udp[source] + tcp[source] + held[source]
				want := ""
				switch {
				case isTCP && sum(tcp)+sum(held) >= bound:
					want = reasonHostPorts
				case mine >= share && held[source] > udp[source]+tcp[source]:
					want = reasonShareHeld
				case mine >= share:
					want = reasonShare
				case sum(udp)+sum(tcp)+sum(held) >= total:
					want = reasonTotal
				}
				var refused string
				var ok bool
				if isTCP {
					refused, ok = f.admitTCP(source, sum(tcp), bound)
				} else {
					refused, ok = f.admit(source)
				}
				if ok != (want == "") || refused != want {
					ht.Fatalf("%s opening TCP %t with %d UDP, %d TCP and %d held of a share of %d, %d TCP and %d held of a bound of %d, %d of %d in all: admitted %t refused %q, want refused %q",
						source, isTCP, udp[source], tcp[source], held[source], share, sum(tcp), sum(held), bound, sum(udp)+sum(tcp)+sum(held), total, ok, refused, want)
				}
				if !ok {
					continue
				}
				if isTCP {
					tcp[source]++
				} else {
					udp[source]++
				}
			}
		}
	})
}
