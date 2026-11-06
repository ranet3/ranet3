// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// switchCase is one pass's input on darwin's switch: the mode (0 for off, 2
// or 3), the mesh's routes, the host's routes the selection reads, the
// underlay's endpoints and the tun's addresses, which name the covered
// families
type switchCase struct {
	mode      int
	mesh      []netip.Prefix
	hosts     []hostRoute
	endpoints []netip.Addr
	addresses []netip.Prefix
}

// switchVia is the SID mode 3 steers its defaults to
var switchVia = []schema.Addr{schema.MustAddr("3fff:0:0:e::46")}

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
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		around := func() netip.Addr { return selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))]) }
		// a key of the switch's, or a prefix up to one bit either side of one at
		// its first address or at its upper half's
		edge := func() netip.Prefix {
			key := rejectKeys[hegel.Draw(tc, pbt.Spanning(0, len(rejectKeys)-1))]
			bits := min(max(key.Bits()+hegel.Draw(tc, pbt.Spanning(-1, 1)), 0), key.Addr().BitLen())
			address := key.Addr()
			if hegel.Draw(tc, hegel.Booleans()) {
				address = halves(key)[1].Addr()
			}
			return netip.PrefixFrom(address, bits).Masked()
		}
		zeros := []netip.Prefix{prefix("0.0.0.0/0"), prefix("::/0"), prefix("0.0.0.0/1"), prefix("::/1"), prefix("128.0.0.0/1"), prefix("8000::/1")}
		for range hegel.Draw(tc, pbt.Spanning(0, 6)) {
			switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
			case 0:
				c.mesh = append(c.mesh, zeros[hegel.Draw(tc, pbt.Spanning(0, len(zeros)-1))])
			case 1:
				c.mesh = append(c.mesh, edge())
			default:
				address := around()
				c.mesh = append(c.mesh, netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))).Masked())
			}
		}
		// the host's defaults, and its routes near the keys or the mesh's, none
		// at a key, where another program's route keeps the switch from reading
		// back
		if hegel.Draw(tc, hegel.Booleans()) {
			c.hosts = append(c.hosts, hostRoute{destination: prefix("0.0.0.0/0"), index: 2}, hostRoute{destination: prefix("::/0"), index: 2})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 4)) {
			destination := edge()
			if hegel.Draw(tc, hegel.Booleans()) {
				address := around()
				destination = netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))).Masked()
			}
			if slices.Contains(rejectKeys, destination) || destination.Bits() == 0 {
				continue
			}
			c.hosts = append(c.hosts, hostRoute{
				destination: destination,
				index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes[1:])),
				scoped:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
			})
		}
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			c.endpoints = append(c.endpoints, around())
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
	reconciler.rt.Selection = newFakeSelection(c.hosts...)
	reconciler.rt.Underlay = func() []netip.Addr { return c.endpoints }
	for _, destination := range c.mesh {
		table.Set(netip.Prefix{}, destination, nil)
	}
	if err := reconciler.reconcile(); err != nil {
		ht.Fatalf("the pass failed: %v", err)
	}
	return reconciler, k
}

// toggle runs a pass on reconciler with the switch asked for where switched
func (c switchCase) toggle(ht *hegel.T, reconciler *Reconciler, switched bool) {
	if err := reconciler.SetTable(reconciler.table.WithMode(c.exitMode(switched)), coverOverlay, nil); err != nil {
		ht.Fatal(err)
	}
	reconciler.adopt()
	if err := reconciler.reconcile(); err != nil {
		ht.Fatalf("the pass toggling the switch to %v failed: %v", switched, err)
	}
}

// probes are the addresses the property asks about, none in 0.0.0.0/8 or
// ::/8: the first and last of each key, of each of its halves, of each mesh
// and host route, and each endpoint with its neighbors
func (c switchCase) probes() []netip.Addr {
	var out []netip.Addr
	ends := func(prefix netip.Prefix) { out = append(out, prefix.Addr(), lastAddress(prefix)) }
	for _, key := range rejectKeys {
		ends(key)
		for _, half := range halves(key) {
			ends(half)
		}
	}
	for _, destination := range c.mesh {
		ends(destination)
	}
	for _, r := range c.hosts {
		ends(r.destination)
	}
	for _, endpoint := range c.endpoints {
		out = append(out, endpoint, endpoint.Prev(), endpoint.Next())
	}
	return slices.DeleteFunc(out, func(address netip.Addr) bool {
		return !address.IsValid() || len(membersOf(netip.PrefixFrom(address, address.BitLen()))) == 0
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
// and a reject share going to ours, as darwin refuses the second
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
		if r.candidate(selectMesh) && r.destination.Contains(address) && r.destination.Bits() > bits {
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

// Over drawn routes of the mesh at and around the keys, host tables,
// endpoints, covered families and modes, with the switch asked for and not:
// no unscoped route of ours sits at a key of the switch's while it is asked
// for, and every reject reads back. An unbound lookup of each address outside
// 0.0.0.0/8 and ::/8 ends at a route of ours with the fields of the route of
// ours it ends at with the switch not asked for, where it ends at one there,
// and otherwise at the longer of the reject and the host's route holding it
// while the switch is asked for, or at the host's alone. With the routes of
// ours out of the tun gone, as a crash takes them, each such address ends at
// the reject while the switch is asked for, but where a longer route of the
// host's holds it. A pass turning the switch on or off leaves the kernel as a
// first pass under the switch it turns to.
func TestSwitchKeepsTheTunsRoutesOffTheRejectsKeys(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, switchCases())
		switched, k := c.pass(t, ht, true)
		plainReconciler, plain := c.pass(t, ht, false)
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
		for _, r := range ours {
			if asked && !r.Scoped && slices.Contains(rejectKeys, r.Destination) {
				ht.Fatalf("%+v sits at a key of the switch's while it is asked for\ncase %+v\nheld %v", r, c, ours)
			}
		}
		for _, address := range c.probes() {
			got := unboundAt(ours, held, c.hosts, address)
			model := unboundAt(plain.snapshot(), nil, c.hosts, address)
			want := model
			if model.ours == nil && asked && (!model.host.IsValid() || keyOf(address).Bits() > model.host.Bits()) {
				want = landing{reject: keyOf(address)}
			}
			matches := got.reject == want.reject && got.host == want.host && (got.ours == nil) == (want.ours == nil)
			if matches && got.ours != nil {
				r := *got.ours
				r.Destination = want.ours.Destination
				matches = r == *want.ours
			}
			if !matches {
				ht.Fatalf("an unbound lookup of %s ends at %s, want %s\ncase %+v\nheld %v\nwith the switch off %v", address, got, want, c, ours, plain.snapshot())
			}
			crashed := unboundAt(nil, held, c.hosts, address)
			host := unboundAt(nil, nil, c.hosts, address).host
			if asked && crashed.reject != keyOf(address) && (!host.IsValid() || host.Bits() <= keyOf(address).Bits()) {
				ht.Fatalf("after a crash an unbound lookup of %s ends at %s, want the reject at %s\ncase %+v", address, crashed, keyOf(address), c)
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
