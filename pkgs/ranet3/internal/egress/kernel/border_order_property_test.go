// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package kernel

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// orderOverlay is the overlay of the runs
var orderOverlay = []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff::/20")}

// orderClasses is an exit's none classes: a block with a class inside it that
// translates, the overlay's first half, and an IPv6 block
var orderClasses = []egress.Class{
	{From: schema.MustPrefix("198.51.100.0/24"), To: egress.Translation{None: true}},
	{From: schema.MustPrefix("198.51.100.128/26"), To: egress.Translation{Addr: netip.MustParseAddr("192.0.2.1")}},
	{From: schema.MustPrefix("203.0.113.0/25"), To: egress.Translation{None: true}},
	{From: schema.MustPrefix("2001:db8:76::/48"), To: egress.Translation{None: true}},
}

// orderDrawn is the classes of orderClasses whose bit drawn sets
func orderDrawn(drawn int) []egress.Class {
	var classes []egress.Class
	for i, class := range orderClasses {
		if drawn&(1<<i) != 0 {
			classes = append(classes, class)
		}
	}
	return classes
}

// orderNone is the addresses the classes of orderClasses whose bit drawn sets
// take as none, written out: the block less the class inside it that
// translates where that is drawn too, the overlay's first half and the IPv6
// block
func orderNone(drawn int) []egress.Range {
	addr := netip.MustParseAddr
	var none []egress.Range
	switch drawn & 0b11 {
	case 0b01:
		none = append(none, egress.Range{First: addr("198.51.100.0"), Last: addr("198.51.100.255")})
	case 0b11:
		none = append(none, egress.Range{First: addr("198.51.100.0"), Last: addr("198.51.100.127")}, egress.Range{First: addr("198.51.100.192"), Last: addr("198.51.100.255")})
	}
	if drawn&0b100 != 0 {
		none = append(none, egress.Range{First: addr("203.0.113.0"), Last: addr("203.0.113.127")})
	}
	if drawn&0b1000 != 0 {
		none = append(none, egress.Range{First: addr("2001:db8:76::"), Last: addr("2001:db8:76:ffff:ffff:ffff:ffff:ffff")})
	}
	return none
}

// orderLast is the last address of prefix
func orderLast(prefix netip.Prefix) netip.Addr {
	b := prefix.Masked().Addr().AsSlice()
	for i := prefix.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(b)
	return last
}

// orderEntry is one entry of the mesh's table a run sets and removes
type orderEntry struct{ source, destination netip.Prefix }

// orderEntries is the entries of the runs: LANs inside the block, one inside
// another, one covering the block, one inside the class that translates, one
// outside every class, a node's prefix inside the overlay and a LAN beside
// it, a LAN of the IPv6 block, one routed for a source alone, and a default
var orderEntries = []orderEntry{
	{destination: netip.MustParsePrefix("198.51.100.32/27")},
	{destination: netip.MustParsePrefix("198.51.100.40/29")},
	{destination: netip.MustParsePrefix("198.51.100.0/23")},
	{destination: netip.MustParsePrefix("198.51.100.160/27")},
	{destination: netip.MustParsePrefix("192.0.2.128/25")},
	{destination: netip.MustParsePrefix("203.0.113.16/28")},
	{destination: netip.MustParsePrefix("203.0.112.0/23")},
	{destination: netip.MustParsePrefix("2001:db8:76:5::/64")},
	{source: netip.MustParsePrefix("3fff::/20"), destination: netip.MustParsePrefix("2001:db8:76:6::/64")},
	{destination: netip.MustParsePrefix("0.0.0.0/0")},
}

// orderOutcome is how the host takes one pass's writes
type orderOutcome int

const (
	orderWrites orderOutcome = iota
	orderFailsRead
	orderFailsFill
	orderRewrites
	orderFailsRewrite
	// orderLandsFill and orderLandsRewrite take the write and still answer an error
	orderLandsFill
	orderLandsRewrite
	orderOutcomes
)

// orderFake is the fake host with a write that lands and still fails, a change
// of the mesh's table while the pass reads, and a check run once a write landed
type orderFake struct {
	*fakeBorder
	lands  bool
	during func()
	landed func(string)
}

func (b *orderFake) Rules(rules []BorderRule, sets borderSets) (chainReadback, error) {
	if during := b.during; during != nil {
		b.during = nil
		during()
	}
	return b.fakeBorder.Rules(rules, sets)
}

func (b *orderFake) Fill(rules []BorderRule, was, sets borderSets) error {
	err := b.fakeBorder.Fill(rules, was, sets)
	if err == nil {
		b.landed("a fill")
	}
	if err == nil && b.lands {
		return errors.New("the answer was lost")
	}
	return err
}

func (b *orderFake) Apply(rules []BorderRule, sets borderSets) error {
	err := b.fakeBorder.Apply(rules, sets)
	if err == nil {
		b.landed("a rewrite")
	}
	if err == nil && b.lands {
		return errors.New("the answer was lost")
	}
	return err
}

// orderOverlays is the overlays a reload of the runs draws from: the runs'
// overlay, and its second half alone, which leaves the overlay's first half,
// a none class, outside it
var orderOverlays = [][]schema.Prefix{orderOverlay, {schema.MustPrefix("203.0.113.128/25"), schema.MustPrefix("3fff::/20")}}

// orderLAN reports whether a learned entry to destination has an address
// outside overlay that ranges hold, where the entry counts as no default
func orderLAN(destination netip.Prefix, ranges []egress.Range, overlay []schema.Prefix) bool {
	destination = destination.Masked()
	if schema.CapturesTheMachine(destination, overlay) {
		return false
	}
	first, last := destination.Addr(), orderLast(destination)
	for _, r := range ranges {
		lo, hi := r.First, r.Last
		if lo.BitLen() != first.BitLen() || hi.Less(first) || last.Less(lo) {
			continue
		}
		if lo.Less(first) {
			lo = first
		}
		if last.Less(hi) {
			hi = last
		}
		// the overlay's prefixes are apart, so the meeting lies inside it only inside one of them
		if !slices.ContainsFunc(overlay, func(p schema.Prefix) bool { return p.Contains(lo) && p.Contains(hi) }) {
			return true
		}
	}
	return false
}

// orderSentinel reports whether peer is one of the mesh's own values rather than a peer
func orderSentinel(peer *netstack.Peer) bool {
	return peer == netstack.Unreachable || peer == netstack.Local || peer == netstack.Assigned
}

// orderRoute is the kernel route a reconciler writes for entry, and whether it writes one
func orderRoute(entry sadr.Route[*netstack.Peer]) (meshkernel.Route, bool) {
	if entry.Value == netstack.Local || entry.Value == netstack.Assigned {
		return meshkernel.Route{}, false
	}
	return meshkernel.Route{Destination: entry.Destination.Masked(), Source: entry.Source, Unreachable: entry.Value == netstack.Unreachable}, true
}

// orderShared is the addresses two prefixes both hold as a prefix, the
// narrower where one holds the other, and whether they share any
func orderShared(a, b netip.Prefix) (netip.Prefix, bool) {
	a, b = a.Masked(), b.Masked()
	if a.Bits() < b.Bits() {
		a, b = b, a
	}
	return a, b.Contains(a.Addr())
}

// orderPassOutcome is how the kernel takes one pass of the reconciler's route writes
type orderPassOutcome int

const (
	orderAnswersAll orderPassOutcome = iota
	orderRefusesDeletes
	orderRefusesAdds
	// orderLosesAdds takes each add and answers an error
	orderLosesAdds
	orderPassOutcomes
)

// The run is an exit with any subset of orderClasses, the empty one among
// them. Its steps are changes to the mesh's table, reloads that move the
// overlay, passes of the antispoof filter, and the two halves of a model
// reconciler's pass, which reads the route source and then writes the
// kernel's routes and tells the source what it left. A filter pass reads or
// writes with a failure, a write that lands and fails, or a clean write, and
// the table may change while it reads, an entry routed again as the pass its
// removal woke reads among those changes. One step draws outright a LAN whose
// route the kernel holds, removed and learned again from another node, and
// another a LAN inside a none class, gone with its route, held over a failed
// read with its hold written, its route's add refused, then its route written
// and its delete refused. The model
// reconciler's deletes or adds may be refused, or its adds may land with an
// error.
//
// After each step and the moment each write of the sets lands, no address
// outside the overlay the sets were written under is at once admitted by the
// host's none sets, taken into the tun by a route in the kernel and held by a
// learned entry of the mesh's table. Each family's none set holds that
// family's ranges alone. The source never hands the reconciler a learned
// entry whose own destination has an address outside the overlay that the
// host's none sets hold. It always hands an entry with no address outside the
// overlay in a none class, and every hold and entry of this node's own. It
// hands the whole table after a pass that wrote and read its sets with no
// change since, and holds nothing back once the filter is withdrawn. No real
// reconciler runs, so no settle orders anything, and the order holds at any
// settle.
func TestRoutesNeverHandAnEntryTheHostsNoneSetsLetStrangersTo(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		table := netstack.NewRouteTable()
		peer, other := &netstack.Peer{ID: "example/router"}, &netstack.Peer{ID: "example/other"}
		values := []*netstack.Peer{peer, netstack.Unreachable, netstack.Local, other}
		be := &orderFake{fakeBorder: &fakeBorder{}}
		drawn := hegel.Draw(ht, pbt.Spanning(0, 1<<len(orderClasses)-1))
		none := orderNone(drawn)
		rt := borderRuntime(nil)
		rt.Sets = orderSets(orderDrawn(drawn), table)
		f := newBorderFilter(&egress.Border{Overlay: orderOverlay}, rt, be)
		var src *routeSource
		// kernel is the routes the kernel holds, and read the snapshot a
		// reconciler's pass read and has not yet written, nil before one
		kernel := map[meshkernel.Route]bool{}
		var read []sadr.Route[*netstack.Peer]
		// overlay is the configuration's overlay, and written the overlay of
		// the pass whose write of the sets last landed
		overlay, written := orderOverlay, orderOverlay
		check := func(when string) {
			if src == nil {
				return
			}
			v4, v6, apart := noneFamilies(be.fakeBorder)
			if !apart || drawn&0b1000 != 0 && len(v6) == 0 {
				ht.Fatalf("%s: the host's IPv4 none set holds %v and its IPv6 one %v", when, v4, v6)
			}
			held := append(v4, v6...)
			for route := range kernel {
				if route.Unreachable || schema.CapturesTheMachine(route.Destination.Masked(), written) {
					continue
				}
				for _, entry := range table.Snapshot() {
					if orderSentinel(entry.Value) || schema.CapturesTheMachine(entry.Destination.Masked(), written) {
						continue
					}
					if shared, ok := orderShared(route.Destination, entry.Destination); ok && orderLAN(shared, held, written) {
						ht.Fatalf("%s: the host's none sets %v admit an address of %s, which the kernel's route %s takes into the tun toward the learned %s", when, held, shared, route, entry.Destination)
					}
				}
			}
			handed, _ := src.split()
			for _, entry := range handed {
				if !orderSentinel(entry.Value) && orderLAN(entry.Destination, held, overlay) {
					ht.Fatalf("%s: the source handed %s from %s via %s, which the host's none sets %v let strangers to", when, entry.Destination, entry.Source, entry.Value.ID, held)
				}
			}
			for _, entry := range table.Snapshot() {
				if slices.Contains(handed, entry) {
					continue
				}
				if orderSentinel(entry.Value) || !orderLAN(entry.Destination, none, overlay) {
					ht.Fatalf("%s: the source held back %s from %s via %s, which no none class takes", when, entry.Destination, entry.Source, entry.Value.ID)
				}
				hold := entry
				hold.Value = netstack.Unreachable
				if !slices.Contains(handed, hold) {
					ht.Fatalf("%s: the source held back %s from %s via %s and handed no hold in its place", when, entry.Destination, entry.Source, entry.Value.ID)
				}
			}
		}
		// snapshot is a reconciler's read of the source at the start of its pass
		snapshot := func() string {
			read = src.Snapshot()
			return fmt.Sprintf("the reconciler read %d entries", len(read))
		}
		// write is the reconciler's writes for the snapshot it read, as the
		// kernel takes them, and its report of what they left
		write := func(outcome orderPassOutcome) string {
			desired := map[meshkernel.Route]bool{}
			for _, entry := range read {
				if route, ok := orderRoute(entry); ok {
					desired[route] = true
				}
			}
			read = nil
			// the pass's listing reads the kernel
			left := maps.Clone(kernel)
			var unanswered []meshkernel.Route
			for route := range kernel {
				if desired[route] {
					continue
				}
				if outcome == orderRefusesDeletes {
					continue
				}
				delete(kernel, route)
				delete(left, route)
			}
			for route := range desired {
				if kernel[route] {
					continue
				}
				switch outcome {
				case orderRefusesAdds:
					unanswered = append(unanswered, route)
				case orderLosesAdds:
					unanswered = append(unanswered, route)
					kernel[route] = true
				default:
					kernel[route] = true
					left[route] = true
				}
			}
			src.Installed(append(slices.Collect(maps.Keys(left)), unanswered...))
			return fmt.Sprintf("the reconciler wrote %d routes, outcome %d, the kernel holds %d", len(desired), outcome, len(kernel))
		}
		be.landed = func(what string) {
			// no reload comes while a pass reads, so the pass wrote under the overlay now
			written = overlay
			check("the moment " + what + " landed")
		}
		change := func(i, value int) string {
			e := orderEntries[i]
			if value < 0 {
				table.Remove(e.source, e.destination)
				return fmt.Sprintf("remove %s", e.destination)
			}
			table.Set(e.source, e.destination, values[value])
			return fmt.Sprintf("set %s via %s", e.destination, values[value].ID)
		}
		for range hegel.Draw(ht, pbt.Spanning(0, 4)) {
			change(hegel.Draw(ht, pbt.Spanning(0, len(orderEntries)-1)), hegel.Draw(ht, pbt.Spanning(0, len(values)-1)))
		}
		if err := f.reconcile(); err != nil {
			ht.Fatalf("the first pass: %v", err)
		}
		src = f.Routes(table).(*routeSource)
		defer func() { _ = f.Close() }()
		check("after the first pass")
		// pass runs one pass of outcome, making the change i and value as it reads where i is not negative
		pass := func(step int, outcome orderOutcome, i, value int) {
			var what string
			be.mu.Lock()
			be.failRules = outcome == orderFailsRead
			be.failFill = outcome == orderFailsFill
			be.failApply = outcome == orderFailsRewrite
			be.fault = ""
			if outcome == orderRewrites || outcome == orderFailsRewrite || outcome == orderLandsRewrite {
				be.fault = "its table reads back otherwise"
			}
			be.mu.Unlock()
			be.lands = outcome == orderLandsFill || outcome == orderLandsRewrite
			if i >= 0 {
				be.during = func() { what = change(i, value) }
			}
			f.trigger = "routes"
			err := f.reconcile()
			// a pass that asks for what it read last reads nothing, and its change is not made
			during := i >= 0 && be.during == nil
			be.during = nil
			check(fmt.Sprintf("step %d, a pass of outcome %d, err %v, the table changed while it read: %q", step, outcome, err, what))
			if handed, _ := src.split(); err == nil && !during && !slices.Equal(handed, table.Snapshot()) {
				ht.Fatalf("step %d: after a pass that wrote its sets the source handed %v of the table %v", step, handed, table.Snapshot())
			}
		}
		for step := range hegel.Draw(ht, pbt.Spanning(1, 16)) {
			switch hegel.Draw(ht, pbt.Spanning(0, 8)) {
			case 8:
				// a LAN inside a none class, gone with its route and the sets
				// written again, learned while the filter's read fails, its hold
				// written, then its route's add refused once the sets leave it
				// out, and the route written and its delete refused once it goes
				var lans []int
				for i, e := range orderEntries {
					if e.destination.Bits() > 0 && orderLAN(e.destination, none, overlay) {
						lans = append(lans, i)
					}
				}
				if len(lans) == 0 {
					break
				}
				i := lans[hegel.Draw(ht, pbt.Spanning(0, len(lans)-1))]
				check(fmt.Sprintf("step %d, %s", step, change(i, -1)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderAnswersAll)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, change(i, 0)))
				pass(step, orderFailsRead, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderAnswersAll)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderRefusesAdds)))
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderAnswersAll)))
				check(fmt.Sprintf("step %d, %s", step, change(i, -1)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderRefusesDeletes)))
			case 6:
				// a LAN routed and its route written, its entry removed and the
				// removal's pass written, then the LAN learned again from another
				// node while its route is still in the kernel
				i := hegel.Draw(ht, pbt.Spanning(0, len(orderEntries)-1))
				check(fmt.Sprintf("step %d, %s", step, change(i, 0)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
				check(fmt.Sprintf("step %d, %s", step, write(orderAnswersAll)))
				check(fmt.Sprintf("step %d, %s", step, change(i, -1)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, change(i, len(values)-1)))
				pass(step, orderOutcome(hegel.Draw(ht, pbt.Spanning(0, int(orderOutcomes)-1))), -1, 0)
			case 7:
				// a reload that moves the overlay, and the pass it wakes
				overlay = orderOverlays[hegel.Draw(ht, pbt.Spanning(0, len(orderOverlays)-1))]
				if err := f.SetConfig(egress.Border{Overlay: overlay}); err != nil {
					ht.Fatalf("step %d: reload: %v", step, err)
				}
				check(fmt.Sprintf("step %d, a reload to the overlay %v", step, overlay))
				pass(step, orderOutcome(hegel.Draw(ht, pbt.Spanning(0, int(orderOutcomes)-1))), -1, 0)
			case 4:
				check(fmt.Sprintf("step %d, %s", step, snapshot()))
			case 5:
				if read != nil {
					check(fmt.Sprintf("step %d, %s", step, write(orderPassOutcome(hegel.Draw(ht, pbt.Spanning(0, int(orderPassOutcomes)-1))))))
				}
			case 0:
				outcome := orderOutcome(hegel.Draw(ht, pbt.Spanning(0, int(orderOutcomes)-1)))
				i, value := -1, 0
				if hegel.Draw(ht, pbt.Spanning(0, 2)) == 0 {
					i, value = hegel.Draw(ht, pbt.Spanning(0, len(orderEntries)-1)), hegel.Draw(ht, pbt.Spanning(-1, len(values)-1))
				}
				pass(step, outcome, i, value)
			case 1:
				// an entry routed and written, removed, and routed again as the pass the removal wakes reads
				i := hegel.Draw(ht, pbt.Spanning(0, len(orderEntries)-1))
				check(fmt.Sprintf("step %d, %s", step, change(i, 0)))
				pass(step, orderWrites, -1, 0)
				check(fmt.Sprintf("step %d, %s", step, change(i, -1)))
				pass(step, orderOutcome(hegel.Draw(ht, pbt.Spanning(0, int(orderOutcomes)-1))), i, 0)
			default:
				value := hegel.Draw(ht, pbt.Spanning(-1, len(values)-1))
				what := change(hegel.Draw(ht, pbt.Spanning(0, len(orderEntries)-1)), value)
				check(fmt.Sprintf("step %d, %s", step, what))
			}
		}
		if err := f.Close(); err != nil {
			ht.Fatalf("withdraw: %v", err)
		}
		if got, _ := src.split(); !slices.Equal(got, table.Snapshot()) {
			ht.Fatalf("once withdrawn the filter held back %v", sadrLess(table.Snapshot(), got))
		}
	})
}

// sadrLess is the entries of all that some leaves out
func sadrLess(all, some []sadr.Route[*netstack.Peer]) []sadr.Route[*netstack.Peer] {
	return slices.DeleteFunc(slices.Clone(all), func(entry sadr.Route[*netstack.Peer]) bool { return slices.Contains(some, entry) })
}
