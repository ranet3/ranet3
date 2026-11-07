// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any share and total and any order of opens and closes over a few
// sources of both families, a new flow is admitted exactly where its source
// holds fewer than the share and all sources fewer than the total, and a
// refusal names the share before the total: the exit's limits on what a
// source can make it hold, a security check, against a model that counts
func TestFlowsAdmitExactlyWithinTheShareAndTheTotal(t *testing.T) {
	sources := []netip.Addr{leaf4, other4, leaf6, other6}
	pbt.Check(t, func(ht *hegel.T) {
		share := hegel.Draw(ht, pbt.Spanning(1, 6))
		total := hegel.Draw(ht, pbt.Spanning(1, 12))
		f := newFlows(share, total)
		held := map[netip.Addr]int{}
		open := 0
		for range hegel.Draw(ht, hegel.Integers(0, 80)) {
			source := sources[hegel.Draw(ht, hegel.Integers(0, len(sources)-1))]
			if hegel.Draw(ht, hegel.Booleans()) {
				if held[source] == 0 {
					continue
				}
				f.release(source)
				held[source]--
				open--
				continue
			}
			want := ""
			switch {
			case held[source] >= share:
				want = reasonShare
			case open >= total:
				want = reasonTotal
			}
			refused, ok := f.admit(source)
			if ok != (want == "") || refused != want {
				ht.Fatalf("%s holding %d of a share of %d with %d of %d open: admitted %t refused %q, want refused %q",
					source, held[source], share, open, total, ok, refused, want)
			}
			if ok {
				held[source]++
				open++
			}
		}
	})
}
