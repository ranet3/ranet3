// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package netstack

import (
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// steerThrough is a steering table sending one source through segments waypoints, nil for none
func steerThrough(tb testing.TB, segments int) *srv6.SteerTable {
	tb.Helper()
	if segments == 0 {
		return nil
	}
	via := make([]schema.Addr, segments)
	for i := range via {
		via[i] = schema.AddrFrom(netip.AddrFrom16([16]byte{0x3f, 0xff, 0, 1, 15: byte(i + 1)}))
	}
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From: schema.PrefixFrom(segPrefix("3fff:a::1/128")),
		Via:  via,
	}}, schema.MustAddr("3fff:1:69c:8c0::1"))
	if err != nil {
		tb.Fatal(err)
	}
	return table
}

// mtuStep is one reload, the link MTU it carries and the longest list its steering has
type mtuStep struct{ link, segments int }

// a longer steering list goes in after the device comes down for it and a shorter one before the device goes up
// so at every moment of a run of reloads the device MTU plus the header in force fits the larger link MTU either side of the reload
// and once a reload returns the device and the table are the ones it was given
// a list one segment longer and one segment shorter under one link MTU are tried before anything is drawn
func TestSetMTUKeepsEveryReadWithinTheLinkMTU(t *testing.T) {
	check := func(tb testing.TB, steps []mtuStep) {
		tb.Helper()
		m := NewRoutesOnly()
		table := steerThrough(tb, steps[0].segments)
		m.SetSteering(table)
		device := steps[0].link - table.Overhead()
		bound := steps[0].link
		// the device as it was before the set and as it is after, each beside the header in force
		m.setMTU = func(_ string, mtu int) error {
			installed := m.Steering().Overhead()
			if device+installed > bound || mtu+installed > bound {
				tb.Fatalf("the device went from %d to %d bytes under a %d byte steering header, past the %d bytes a session carries", device, mtu, installed, bound)
			}
			device = mtu
			return nil
		}
		for i, step := range steps[1:] {
			table := steerThrough(tb, step.segments)
			bound = max(steps[i].link, step.link)
			if err := m.SetMTU(step.link-table.Overhead(), table); err != nil {
				tb.Fatal(err)
			}
			if want := step.link - table.Overhead(); device != want || m.Steering() != table {
				tb.Fatalf("reload %d left a %d byte device under a %d byte header, want %d under %d", i+1, device, m.Steering().Overhead(), want, table.Overhead())
			}
		}
	}
	check(t, []mtuStep{{DefaultMTU, 1}, {DefaultMTU, 2}})
	check(t, []mtuStep{{DefaultMTU, 2}, {DefaultMTU, 1}})
	pbt.Check(t, func(ht *hegel.T) {
		steps := make([]mtuStep, hegel.Draw(ht, pbt.Spanning(2, 6)))
		for i := range steps {
			segments := hegel.Draw(ht, pbt.Spanning(0, srv6.MaxSegments))
			least := srv6.MinimumIPv6MTU
			if segments > 0 {
				least += srv6.Overhead(segments)
			}
			steps[i] = mtuStep{hegel.Draw(ht, pbt.Spanning(least, 9000)), segments}
		}
		check(ht, steps)
	})
}
