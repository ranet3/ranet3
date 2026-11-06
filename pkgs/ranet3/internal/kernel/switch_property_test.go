// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// switchCase is one pass's input on darwin's switch: the mode (0 for off, 2
// or 3), the overlay, the mesh's routes, the destinations of its routes from
// switchSource and of its holds, which the pass scopes, the host's routes the
// selection reads, the underlay's endpoints and the tun's addresses, which
// name the covered families
type switchCase struct {
	mode        int
	overlay     []schema.Prefix
	mesh        []netip.Prefix
	sourced     []netip.Prefix
	unreachable []netip.Prefix
	hosts       []hostRoute
	endpoints   []netip.Addr
	addresses   []netip.Prefix
}

// switchVia is the SID mode 3 steers its defaults to, and switchSource the
// source of the mesh's source-specific routes
var (
	switchVia    = []schema.Addr{schema.MustAddr("3fff:0:0:e::46")}
	switchSource = prefix("2001:db8::/48")
)

// keys is the keys of the switch's rejects and of c's overlay holds
func (c switchCase) keys() []netip.Prefix {
	return slices.Concat(rejectKeys, overlayKeys(c.overlay))
}

// holdAt is the longest overlay hold holding address, invalid where none does
func (c switchCase) holdAt(address netip.Addr) netip.Prefix {
	var out netip.Prefix
	for _, key := range overlayKeys(c.overlay) {
		if key.Contains(address) && key.Bits() > out.Bits() {
			out = key
		}
	}
	return out
}

// holdsOf is the overlay holds among ours, which a crash leaves on lo0
func (c switchCase) holdsOf(ours []Route) []Route {
	return slices.DeleteFunc(slices.Clone(ours), func(r Route) bool {
		return !r.Unreachable || r.Scoped || !slices.Contains(overlayKeys(c.overlay), r.Destination)
	})
}

func switchCases() hegel.Generator[switchCase] {
	return hegel.Composite(func(tc hegel.TestCase) switchCase {
		c := switchCase{mode: hegel.Draw(tc, hegel.SampledFrom([]int{0, 2, 2, 3}))}
		switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
		case 0:
			c.addresses = coverAddresses[:1]
		case 1:
			c.addresses = coverAddresses[1:]
		default:
			c.addresses = coverAddresses
		}
		// an overlay prefix at or up to two bits inside a half of a key of the
		// switch's, or one holding a key of NAT64's and no zero address
		c.overlay = slices.Clone(coverOverlay)
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			var added netip.Prefix
			if hegel.Draw(tc, hegel.Booleans()) {
				half := halves(rejectKeys[hegel.Draw(tc, pbt.Spanning(0, len(rejectKeys)-1))])[hegel.Draw(tc, pbt.Spanning(0, 1))]
				added = netip.PrefixFrom(half.Addr(), half.Bits()+hegel.Draw(tc, pbt.Spanning(0, 2)))
			} else {
				key := nat64Prefixes[hegel.Draw(tc, pbt.Spanning(0, len(nat64Prefixes)-1))]
				added = netip.PrefixFrom(key.Addr(), hegel.Draw(tc, pbt.Spanning(16, key.Bits()-1))).Masked()
			}
			if !slices.Contains(overlayKeys(c.overlay), added) {
				c.overlay = append(c.overlay, schema.PrefixFrom(added))
			}
		}
		keys, edges := c.keys(), slices.Concat(rejectKeys, overlayKeys(coverOverlay))
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		around := func() netip.Addr { return selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))]) }
		// a key of the switch's or of a hold of coverOverlay's, or a prefix up
		// to one bit either side of one at its first address or at its upper
		// half's
		edge := func() netip.Prefix {
			key := edges[hegel.Draw(tc, pbt.Spanning(0, len(edges)-1))]
			bits := min(max(key.Bits()+hegel.Draw(tc, pbt.Spanning(-1, 1)), 0), key.Addr().BitLen())
			address := key.Addr()
			if hegel.Draw(tc, hegel.Booleans()) {
				address = halves(key)[1].Addr()
			}
			return netip.PrefixFrom(address, bits).Masked()
		}
		// a route shorter than one of keys holding it
		shorter := func(keys []netip.Prefix) netip.Prefix {
			key := keys[hegel.Draw(tc, pbt.Spanning(0, len(keys)-1))]
			return netip.PrefixFrom(key.Addr(), hegel.Draw(tc, pbt.Spanning(1, key.Bits()-1))).Masked()
		}
		zeros := []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0"), prefix("0.0.0.0/1"), prefix("::/1"), prefix("128.0.0.0/1"), prefix("8000::/1")}
		for range hegel.Draw(tc, pbt.Spanning(0, 6)) {
			switch hegel.Draw(tc, pbt.Spanning(0, 5)) {
			case 0:
				c.mesh = append(c.mesh, zeros[hegel.Draw(tc, pbt.Spanning(0, len(zeros)-1))])
			case 1:
				c.mesh = append(c.mesh, edge())
			case 4:
				// NAT64's prefixes are the keys of the switch's a shorter
				// route can hold without holding a zero address
				c.mesh = append(c.mesh, shorter(nat64Prefixes))
			case 5:
				c.mesh = append(c.mesh, shorter(overlayKeys(c.overlay)))
			default:
				address := around()
				c.mesh = append(c.mesh, netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))).Masked())
			}
		}
		// a route of the mesh's from a source, IPv6 alone, or a hold of the
		// mesh's, at or up to four bits inside an overlay prefix
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			overlay := overlayKeys(c.overlay)
			key := overlay[hegel.Draw(tc, pbt.Spanning(0, len(overlay)-1))]
			inside := netip.PrefixFrom(addressIn(tc, key), min(key.Bits()+hegel.Draw(tc, pbt.Spanning(0, 4)), key.Addr().BitLen())).Masked()
			if key.Addr().Is6() && hegel.Draw(tc, hegel.Booleans()) {
				c.sourced = append(c.sourced, inside)
			} else {
				c.unreachable = append(c.unreachable, inside)
			}
		}
		// the host's defaults, and its routes near the keys or the mesh's, none
		// at a key, where another program's route keeps the switch from reading
		// back
		if hegel.Draw(tc, hegel.Booleans()) {
			c.hosts = append(c.hosts, hostRoute{destination: prefix("0.0.0.0/0"), index: 2}, hostRoute{destination: prefix("::/0"), index: 2})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 4)) {
			var destination netip.Prefix
			switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
			case 0:
				destination = edge()
			case 1:
				address := around()
				destination = netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))).Masked()
			case 2:
				// one between a key of NAT64's and a shorter mesh route holding it,
				// as long as that route or longer, the mesh route drawn too where
				// the mesh has none
				key := nat64Prefixes[hegel.Draw(tc, pbt.Spanning(0, len(nat64Prefixes)-1))]
				least := 0
				for _, m := range c.mesh {
					if m.Bits() < key.Bits() && m.Contains(key.Addr()) {
						least = max(least, m.Bits())
					}
				}
				if least == 0 {
					holder := shorter([]netip.Prefix{key})
					c.mesh = append(c.mesh, holder)
					least = holder.Bits()
				}
				destination = netip.PrefixFrom(key.Addr(), hegel.Draw(tc, pbt.Spanning(least, key.Bits()-1))).Masked()
			default:
				// one a mesh route holding an overlay prefix can lie beneath (row L6)
				destination = shorter(overlayKeys(c.overlay))
			}
			if slices.Contains(keys, destination) || destination.Bits() == 0 {
				continue
			}
			c.hosts = append(c.hosts, hostRoute{
				destination: destination,
				index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes[1:])),
				scoped:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
			})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			if hegel.Draw(tc, hegel.Booleans()) {
				c.endpoints = append(c.endpoints, around())
			} else {
				overlay := overlayKeys(c.overlay)
				c.endpoints = append(c.endpoints, addressIn(tc, overlay[hegel.Draw(tc, pbt.Spanning(0, len(overlay)-1))]))
			}
		}
		return c
	})
}

// exitMode is c's mode with the switch asked for where switched, by
// fallback = "none" in mode 2 and by fallback unwritten in mode 3
func (c switchCase) exitMode(switched bool) *ExitMode {
	fallback := FallbackUplink
	if switched {
		fallback = FallbackNone
	}
	switch c.mode {
	case 2:
		return &ExitMode{Fallback: fallback}
	case 3:
		if switched {
			return &ExitMode{Via: switchVia}
		}
		return &ExitMode{Via: switchVia, Fallback: fallback}
	}
	return nil
}

// pass is a pass over c on rejectingKernel, the switch asked for where
// switched in modes 2 and 3
func (c switchCase) pass(t *testing.T, ht *hegel.T, switched bool) (*Reconciler, *rejectingKernel) {
	reconciler, table, k := rejectingHarness(t, c.exitMode(switched), c.addresses...)
	c.run(ht, reconciler, table)
	return reconciler, k
}

// reference is the routes of ours a pass over c with no switch asked for
// leaves on the covering fake, which writes no overlay hold and splits nothing
func (c switchCase) reference(t *testing.T, ht *hegel.T) []Route {
	reconciler, table, covering := coveredHarness(t, Table{}.WithMode(c.exitMode(false)), Runtime{Sessions: func() int { return 1 }}, c.addresses...)
	reconciler.now = func() time.Time { return start }
	c.run(ht, reconciler, table)
	return covering.snapshot()
}

// run is a pass of reconciler over c's overlay, host, endpoints and mesh
func (c switchCase) run(ht *hegel.T, reconciler *Reconciler, table *netstack.RouteTable) {
	reconciler.rt.Overlay = c.overlay
	reconciler.rt.Selection = newFakeSelection(c.hosts...)
	reconciler.rt.Underlay = func() []netip.Addr { return c.endpoints }
	for _, destination := range c.mesh {
		table.Set(netip.Prefix{}, destination, nil)
	}
	for _, destination := range c.sourced {
		table.Set(switchSource, destination, nil)
	}
	for _, destination := range c.unreachable {
		table.Set(netip.Prefix{}, destination, netstack.Unreachable)
	}
	if err := reconciler.reconcile(); err != nil {
		ht.Fatalf("the pass failed: %v", err)
	}
}

// toggle runs a pass on reconciler with the switch asked for where switched
func (c switchCase) toggle(ht *hegel.T, reconciler *Reconciler, switched bool) {
	if err := reconciler.SetTable(reconciler.table.WithMode(c.exitMode(switched)), c.overlay, nil); err != nil {
		ht.Fatal(err)
	}
	reconciler.adopt()
	if err := reconciler.reconcile(); err != nil {
		ht.Fatalf("the pass toggling the switch to %v failed: %v", switched, err)
	}
}

// probes are the addresses the property asks about, those outside the hole
// among the first and last of each key, of each of its halves, of each mesh
// and host route, and each endpoint with its neighbors
func (c switchCase) probes() []netip.Addr {
	var out []netip.Addr
	ends := func(prefix netip.Prefix) { out = append(out, prefix.Addr(), lastAddress(prefix)) }
	for _, key := range c.keys() {
		ends(key)
		for _, half := range halves(key) {
			ends(half)
		}
	}
	for _, destination := range slices.Concat(c.mesh, c.sourced, c.unreachable) {
		ends(destination)
	}
	for _, r := range c.hosts {
		ends(r.destination)
	}
	for _, endpoint := range c.endpoints {
		out = append(out, endpoint, endpoint.Prev(), endpoint.Next())
	}
	return slices.DeleteFunc(out, func(address netip.Addr) bool {
		return !address.IsValid() || inHole(address)
	})
}

// landing is where an unbound lookup ends: a route of ours, a reject, a
// route of the host's, or nothing
type landing struct {
	ours   *Route
	reject netip.Prefix
	host   netip.Prefix
}

func (l landing) String() string {
	switch {
	case l.ours != nil:
		return fmt.Sprintf("ours %+v", *l.ours)
	case l.reject.IsValid():
		return "the reject at " + l.reject.String()
	case l.host.IsValid():
		return "the host's " + l.host.String()
	}
	return "nothing"
}

// unboundAt is the longest unscoped match for address among ours, the rejects
// at rejects and the host's candidate routes, the one key a route of ours
// and a reject share going to ours, as darwin refuses the second, and one a
// route of ours and the host's share going to the host's, which darwin
// refuses ours beside
func unboundAt(ours []Route, rejects []netip.Prefix, hosts []hostRoute, address netip.Addr) landing {
	var out landing
	bits := -1
	for _, r := range ours {
		if !r.Scoped && r.Destination.Contains(address) && r.Destination.Bits() > bits {
			r := r
			out, bits = landing{ours: &r}, r.Destination.Bits()
		}
	}
	for _, key := range rejects {
		if key.Contains(address) && key.Bits() > bits {
			out, bits = landing{reject: key}, key.Bits()
		}
	}
	for _, r := range hosts {
		if r.candidate(selectMesh) && r.destination.Contains(address) && r.destination.Bits() >= bits {
			out, bits = landing{host: r.destination}, r.destination.Bits()
		}
	}
	return out
}

// keyOf is the key of the switch's holding address
func keyOf(address netip.Addr) netip.Prefix {
	for _, key := range rejectKeys {
		if key.Contains(address) {
			return key
		}
	}
	return netip.Prefix{}
}

// Over drawn overlays, routes of the mesh at and around the keys, its routes
// from a source and its holds at or inside an overlay prefix, host tables,
// endpoints, covered families and modes, with the switch asked for and not:
// no unscoped route of ours sits at a key of the switch's while it is asked
// for, nor at an overlay hold's in any mode, and every reject reads
// back. An unbound lookup of each address probes gives, outside the hole, ends
// at a route of ours with the fields of the route it ends at among the
// overlay holds and the routes a pass with no switch and no split leaves but
// those at or inside an overlay prefix that are part of no route of the mesh
// at or inside it with no source and no hold, as linux's hold answers every
// address of its prefix no such route holds for a lookup with no source,
// where it ends at one there, and otherwise at the longer of the reject and
// the host's route holding it while the switch is asked for, or at the host's
// alone, a reject longer than a hold refusing in its place. The routes of ours scoped to the tun at or inside an overlay prefix
// are those of a pass with no switch and no split, but a hold at an overlay
// key. With the routes of ours out of the tun gone, as a crash takes them,
// each address in the overlay ends at its longest hold or a longer reject,
// and each other address at the reject while the switch is asked for, but
// where a longer route of the host's holds it. A pass turning the switch on
// or off leaves the kernel as a first pass under the switch it turns to.
func TestSwitchKeepsTheTunsRoutesOffTheRejectsKeys(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, switchCases())
		switched, k := c.pass(t, ht, true)
		plainReconciler, plain := c.pass(t, ht, false)
		var holds []Route
		for _, key := range overlayKeys(c.overlay) {
			holds = append(holds, Route{Destination: key, Metric: holdMetric, Unreachable: true})
		}
		within := func(inner, outer netip.Prefix) bool {
			return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
		}
		// linux's hold answers every address of its prefix that no route of
		// the mesh at or inside the prefix holds, so its mesh table answers
		// there only from such a route. A route from a source matches no
		// lookup with no source and a hold of the mesh's refuses as the
		// overlay's does, so only a route of c.mesh holds an address there
		// for an unbound lookup
		bare := c.reference(t, ht)
		reference := append(slices.DeleteFunc(slices.Clone(bare), func(r Route) bool {
			return slices.ContainsFunc(overlayKeys(c.overlay), func(key netip.Prefix) bool {
				return within(r.Destination, key) && !slices.ContainsFunc(c.mesh, func(m netip.Prefix) bool {
					return within(m, key) && within(r.Destination, m)
				})
			})
		}), holds...)
		// a socket bound to the tun meets the routes scoped to it, which no
		// hold on lo0 answers ahead of, as linux passes a hold over for a
		// lookup bound to the tun (routing.md row B4), so at or inside an
		// overlay prefix they are the ones a pass with no switch and no split
		// leaves there but a hold at an overlay key
		scopedOf := func(routes []Route) []Route {
			out := slices.DeleteFunc(slices.Clone(routes), func(r Route) bool {
				return !r.Scoped || r.Unreachable && slices.Contains(overlayKeys(c.overlay), r.Destination) ||
					!slices.ContainsFunc(overlayKeys(c.overlay), func(key netip.Prefix) bool { return within(r.Destination, key) })
			})
			slices.SortFunc(out, compareRoutes)
			return out
		}
		asked := c.mode != 0
		held, _ := k.held()
		// the switch reads holding with no exit live and passing with one, never not holding
		if asked && (!slices.Equal(held, rejectKeys) || switchReads(switched) != string(FallbackHolding) && switchReads(switched) != string(FallbackPassing)) {
			ht.Fatalf("the switch reads %s with rejects at %v, want holding at each key\ncase %+v\nheld %v", switchReads(switched), held, c, k.snapshot())
		}
		if !asked && len(held) != 0 {
			ht.Fatalf("with no switch asked for the fake holds rejects at %v", held)
		}
		ours := k.snapshot()
		if got, want := scopedOf(ours), scopedOf(bare); !slices.Equal(got, want) {
			ht.Fatalf("the routes of ours scoped to the tun at or inside the overlay are %v, want %v\ncase %+v", got, want, c)
		}
		for _, r := range ours {
			if asked && !r.Scoped && slices.Contains(rejectKeys, r.Destination) {
				ht.Fatalf("%+v sits at a key of the switch's while it is asked for\ncase %+v\nheld %v", r, c, ours)
			}
			if !r.Scoped && !r.Unreachable && slices.Contains(overlayKeys(c.overlay), r.Destination) {
				ht.Fatalf("%+v sits at an overlay hold's key\ncase %+v\nheld %v", r, c, ours)
			}
		}
		for _, address := range c.probes() {
			got := unboundAt(ours, held, c.hosts, address)
			model := unboundAt(reference, nil, c.hosts, address)
			want := model
			// a reject longer than the hold it ends at refuses in its place
			refused := model.ours != nil && slices.Contains(holds, *model.ours) && keyOf(address).Bits() > model.ours.Destination.Bits()
			if asked && (refused || model.ours == nil && (!model.host.IsValid() || keyOf(address).Bits() > model.host.Bits())) {
				want = landing{reject: keyOf(address)}
			}
			matches := got.reject == want.reject && got.host == want.host && (got.ours == nil) == (want.ours == nil)
			if matches && got.ours != nil {
				r := *got.ours
				r.Destination = want.ours.Destination
				matches = r == *want.ours
			}
			if !matches {
				ht.Fatalf("an unbound lookup of %s ends at %s, want %s\ncase %+v\nheld %v\nwith no switch and no split %v", address, got, want, c, ours, reference)
			}
			crashed := unboundAt(c.holdsOf(ours), held, c.hosts, address)
			host := unboundAt(nil, nil, c.hosts, address).host
			switch hold := c.holdAt(address); {
			case hold.IsValid():
				if (crashed.ours == nil || crashed.ours.Destination != hold) && crashed.reject.Bits() <= hold.Bits() && (!host.IsValid() || host.Bits() <= hold.Bits()) {
					ht.Fatalf("after a crash an unbound lookup of %s ends at %s, want the hold at %s\ncase %+v\nheld %v", address, crashed, hold, c, ours)
				}
			case asked:
				if crashed.reject != keyOf(address) && (!host.IsValid() || host.Bits() <= keyOf(address).Bits()) {
					ht.Fatalf("after a crash an unbound lookup of %s ends at %s, want the reject at %s\ncase %+v", address, crashed, keyOf(address), c)
				}
			}
		}

		c.toggle(ht, switched, false)
		if after, _ := k.held(); len(after) != 0 || !slices.Equal(k.snapshot(), plain.snapshot()) {
			ht.Fatalf("turning the switch off left rejects at %v and %v, want %v\ncase %+v", after, k.snapshot(), plain.snapshot(), c)
		}
		c.toggle(ht, plainReconciler, true)
		if after, _ := plain.held(); !slices.Equal(after, held) || !slices.Equal(plain.snapshot(), ours) {
			ht.Fatalf("turning the switch on left rejects at %v and %v, want %v and %v\ncase %+v", after, plain.snapshot(), held, ours, c)
		}
	})
}
