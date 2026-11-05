// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// beneathCase is one host table, an overlay, the prefixes the mesh holds, and
// whether the pass runs cap.exit mode 2, whose zero routes go in as members
type beneathCase struct {
	table   hostTable
	overlay []schema.Prefix
	mesh    []netip.Prefix
	exit    bool
}

func beneathCases() hegel.Generator[beneathCase] {
	return hegel.Composite(func(tc hegel.TestCase) beneathCase {
		bases := []netip.Addr{hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, hegel.IPAddresses().IPv6())}
		around := func() netip.Addr { return selectAddress(tc, bases[hegel.Draw(tc, pbt.Spanning(0, 1))]) }
		c := beneathCase{table: hostTable{mesh: selectMesh}, exit: hegel.Draw(tc, hegel.Booleans())}
		for range hegel.Draw(tc, pbt.Spanning(0, 8)) {
			address := around()
			c.table.routes = append(c.table.routes, hostRoute{
				destination: netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, address.BitLen()))).Masked(),
				index:       hegel.Draw(tc, hegel.SampledFrom(selectIndexes)),
				scoped:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/5)),
				cloned:      hegel.Draw(tc, hegel.WeightedBooleans(1.0/8)),
			})
		}
		// a prefix of the overlay, half the time at the first or last address of
		// a wider prefix, which a route holding it may be
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			address := around()
			bits := hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))
			if hegel.Draw(tc, hegel.Booleans()) {
				wider := netip.PrefixFrom(address, hegel.Draw(tc, pbt.Spanning(0, bits))).Masked()
				address = wider.Addr()
				if hegel.Draw(tc, hegel.Booleans()) {
					address = lastAddress(wider)
				}
			}
			c.overlay = append(c.overlay, schema.PrefixFrom(netip.PrefixFrom(address, bits).Masked()))
		}
		// mode 2 beside another program's full tunnel, each family's halves out of another interface, which every
		// route of the mesh's but a /0 lies inside, over the covering harness's overlay as well, which the members
		// 128.0.0.0/1 and 2000::/3 hold
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)) {
			c.exit = true
			c.overlay = append(c.overlay, coverOverlay...)
			index := hegel.Draw(tc, hegel.SampledFrom(selectIndexes[1:]))
			for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
				c.table.routes = append(c.table.routes, hostRoute{destination: prefix(half), index: index})
			}
		}
		// a prefix holding a prefix of the overlay, by up to its whole length, with
		// the prefix at its first address, at its last or anywhere: the bits of the
		// prefix between the two lengths all zeros, all ones or any
		holding := func(least int) (netip.Prefix, bool) {
			if len(c.overlay) == 0 || !hegel.Draw(tc, hegel.Booleans()) {
				return netip.Prefix{}, false
			}
			held := c.overlay[hegel.Draw(tc, pbt.Spanning(0, len(c.overlay)-1))].Prefix
			shortest := min(least, held.Bits())
			if end := hegel.Draw(tc, pbt.Spanning(0, 2)); end < 2 {
				raw := held.Addr().AsSlice()
				bit := func(i int) int { return int(raw[i/8]>>(7-i%8)) & 1 }
				shortest = held.Bits()
				for shortest > least && bit(shortest-1) == end {
					shortest--
				}
			}
			return netip.PrefixFrom(held.Addr(), hegel.Draw(tc, pbt.Spanning(shortest, held.Bits()))).Masked(), true
		}
		// a host route holding the overlay, which a mesh route holding it may lie beneath
		if host, ok := holding(0); ok {
			c.table.routes = append(c.table.routes, hostRoute{destination: host, index: hegel.Draw(tc, hegel.SampledFrom(selectIndexes[1:]))})
		}
		// a length a host route or an overlay prefix has, one either side of it, or any
		var lengths []int
		for _, r := range c.table.routes {
			lengths = append(lengths, r.destination.Bits(), r.destination.Bits()+1, r.destination.Bits()-1)
		}
		for _, prefix := range c.overlay {
			lengths = append(lengths, prefix.Bits(), prefix.Bits()-1)
		}
		for range hegel.Draw(tc, pbt.Spanning(1, 6)) {
			if mesh, ok := holding(1); ok {
				c.mesh = append(c.mesh, mesh)
				continue
			}
			address := around()
			bits := hegel.Draw(tc, pbt.Spanning(1, address.BitLen()))
			if len(lengths) > 0 && hegel.Draw(tc, hegel.Booleans()) {
				bits = min(max(lengths[hegel.Draw(tc, pbt.Spanning(0, len(lengths)-1))], 1), address.BitLen())
			}
			c.mesh = append(c.mesh, netip.PrefixFrom(address, bits).Masked())
		}
		return c
	})
}

// pass is a pass over c on the covering fake, beside c's host table where
// selection is true, in mode 2 where c says so
func (c beneathCase) pass(t *testing.T, ht *hegel.T, selection bool) (*Reconciler, *coveringKernel) {
	tbl, rt := Table{}, Runtime{Overlay: c.overlay}
	if selection {
		rt.Selection = newFakeSelection(c.table.routes...)
	}
	if c.exit {
		tbl, rt.Sessions = Table{}.WithMode(&ExitMode{}), func() int { return 1 }
	}
	reconciler, table, fake := harness(t, tbl, rt)
	reconciler.now = func() time.Time { return start }
	kernel := onCovering(reconciler, fake, coverAddresses...)
	for _, destination := range c.mesh {
		table.Set(netip.Prefix{}, destination, nil)
	}
	if c.exit {
		table.Set(netip.Prefix{}, zero4.Destination, nil)
		table.Set(netip.Prefix{}, zero6.Destination, nil)
	}
	if err := reconciler.reconcile(); err != nil {
		ht.Fatalf("the pass failed: %v", err)
	}
	return reconciler, kernel
}

// probes are the addresses the property asks about: the first and last of
// each mesh route, host route and prefix of the overlay, and the addresses
// either side of each prefix of the overlay
func (c beneathCase) probes() []netip.Addr {
	var out []netip.Addr
	ends := func(prefix netip.Prefix) { out = append(out, prefix.Addr(), lastAddress(prefix)) }
	for _, prefix := range c.mesh {
		ends(prefix)
	}
	for _, r := range c.table.routes {
		ends(r.destination)
	}
	for _, prefix := range c.overlay {
		ends(prefix.Prefix)
		out = append(out, prefix.Addr().Prev(), lastAddress(prefix.Prefix).Next())
	}
	return slices.DeleteFunc(out, func(address netip.Addr) bool { return !address.IsValid() })
}

// overlaid reports address inside a prefix of c's overlay
func (c beneathCase) overlaid(address netip.Addr) bool {
	return slices.ContainsFunc(c.overlay, func(prefix schema.Prefix) bool { return prefix.Contains(address) })
}

// under is the model of row L6 on darwin, from routing.md: a route of the
// mesh's holding no address of the overlay, inside a route of the host's
// longer than /0 that an unbound lookup meets and that leaves by another
// interface than the tun, and the longest such
func (c beneathCase) under(destination netip.Prefix) (netip.Prefix, bool) {
	for _, prefix := range c.overlay {
		if prefix.Addr().Is4() == destination.Addr().Is4() && (prefix.Contains(destination.Addr()) || destination.Contains(prefix.Addr())) {
			return netip.Prefix{}, false
		}
	}
	var best netip.Prefix
	for _, r := range c.table.routes {
		h := r.destination
		if r.index == c.table.mesh || r.scoped || r.cloned || h.Bits() < 1 || h.Bits() > destination.Bits() ||
			h.Addr().Is4() != destination.Addr().Is4() || !h.Contains(destination.Addr()) {
			continue
		}
		if !best.IsValid() || h.Bits() > best.Bits() {
			best = h
		}
	}
	return best, best.IsValid()
}

// beneathExamples is a host table beside the tun at mesh, an overlay, and each
// destination of a mesh route with the host route row L6 puts it beneath, ""
// for none: one outside the overlay beneath a route longer than /0, the longest
// such, one inside the overlay or overlapping it, one beneath a /0 alone, one
// beneath a scoped route and one beneath a route of the tun's own
func beneathExamples(mesh int) (hostTable, []schema.Prefix, map[string]string) {
	other := mesh + 1
	table := hostTable{mesh: mesh, routes: []hostRoute{
		{destination: prefix("0.0.0.0/0"), index: other},
		{destination: prefix("::/0"), index: other},
		{destination: prefix("0.0.0.0/1"), index: other},
		{destination: prefix("10.0.0.0/8"), index: other},
		{destination: prefix("192.0.2.0/24"), index: other},
		{destination: prefix("2001:db8:200::/48"), index: other},
		{destination: prefix("198.51.100.0/24"), index: other, scoped: true},
		{destination: prefix("203.0.113.0/24"), index: mesh},
	}}
	overlay := prefixes(prefix("192.0.2.128/25"), prefix("2001:db8:200:80::/57"))
	return table, overlay, map[string]string{
		"10.0.0.0/8":           "10.0.0.0/8",
		"10.1.0.0/16":          "10.0.0.0/8",
		"100.64.0.0/10":        "0.0.0.0/1",
		"192.0.2.0/26":         "192.0.2.0/24",
		"2001:db8:200::/57":    "2001:db8:200::/48",
		"192.0.2.192/26":       "",
		"192.0.2.0/24":         "",
		"2001:db8:200::/56":    "",
		"2001:db8:200:80::/58": "",
		"172.16.0.0/12":        "",
		"198.51.100.0/25":      "",
		"203.0.113.0/25":       "",
	}
}

// scopedAlready is a hold and a route from a source at a destination of
// beneathExamples' that lies beneath a host route, both of which the platform
// scopes already, so neither lies beneath it as row L6 reads one
var scopedAlready = []Route{
	{Destination: prefix("192.0.2.0/26"), Unreachable: true},
	{Destination: prefix("192.0.2.0/26"), Source: prefix("198.51.100.0/24")},
}

// beneath answers each of beneathExamples as the examples name, and names no
// host route for scopedAlready
func TestBeneathAnswersTheExamples(t *testing.T) {
	table, overlay, examples := beneathExamples(selectMesh)
	for destination, host := range examples {
		got, ok := table.beneath(Route{Destination: prefix(destination)}, overlay)
		if want := host != ""; ok != want || want && got != prefix(host) {
			t.Errorf("%s lies beneath %s %v, want %q", destination, got, ok, host)
		}
	}
	for _, r := range scopedAlready {
		if got, ok := table.beneath(r, overlay); ok {
			t.Errorf("%+v lies beneath %s", r, got)
		}
	}
}

// Over drawn host tables, overlays, mesh routes and modes: beneath names a
// route of the mesh's exactly where the model of row L6 does, with the longest
// host route holding it, and a pass beside the table scopes each route it
// installs where L6 or the scope it had with no host route says so, naming in
// Stats.Beneath exactly the routes L6 scoped, so no other route's scope moves.
// An unbound lookup of an address outside the overlay that a host route
// longer than /0 holds ends at the host's routes, as Linux's rule 5410 sends
// it, a route holding the overlay cut around it where that takes L6's scope.
// The longest routes holding each address carry the fields of the longest
// route a pass with no host route installs, no key, a destination and scope,
// holds two routes, and the pass installs or skips each route it desires, so
// it desires none twice.
func TestBeneathScopesAMeshRouteUnderAHostRouteOutsideTheOverlay(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, beneathCases())
		for _, destination := range c.mesh {
			got, ok := c.table.beneath(Route{Destination: destination}, c.overlay)
			want, wanted := c.under(destination)
			if ok != wanted || got != want {
				ht.Fatalf("%s lies beneath %s %v, want %s %v\noverlay %v\ntable %+v", destination, got, ok, want, wanted, c.overlay, c.table.routes)
			}
		}

		reconciler, kernel := c.pass(t, ht, true)
		_, plain := c.pass(t, ht, false)
		if stats := reconciler.Stats(); stats.Desired != stats.Installed+stats.Skipped {
			ht.Fatalf("the pass desires %d routes, installs %d and skips %d\noverlay %v\ntable %+v\nheld %v", stats.Desired, stats.Installed, stats.Skipped, c.overlay, c.table.routes, kernel.snapshot())
		}
		keys := map[routeKey]bool{}
		for _, r := range kernel.snapshot() {
			key := routeKey{destination: r.Destination, scoped: r.Scoped}
			if keys[key] {
				ht.Fatalf("two routes take the key %s scoped %v: %v", r.Destination, r.Scoped, kernel.snapshot())
			}
			keys[key] = true
		}
		for _, address := range c.probes() {
			host, ok := c.under(netip.PrefixFrom(address, address.BitLen()))
			if route, byHost := unbound(c.table.routes, kernel, address); ok && !c.overlaid(address) && !byHost {
				ht.Fatalf("an unbound lookup of %s, outside the overlay beneath the host's %s, ends at the mesh's %s\noverlay %v\ntable %+v\nheld %v", address, host, route, c.overlay, c.table.routes, kernel.snapshot())
			}
			want, got := longestHolding(plain.snapshot(), address), longestHolding(kernel.snapshot(), address)
			for _, r := range got {
				if len(want) != 1 {
					ht.Fatalf("%s is held by %v with no host route, want one route\nheld %v", address, want, plain.snapshot())
				}
				r.Destination, r.Scoped = want[0].Destination, want[0].Scoped
				if r != want[0] {
					ht.Fatalf("%s is held by %+v, want the fields of %+v\noverlay %v\ntable %+v\nheld %v", address, got, want[0], c.overlay, c.table.routes, kernel.snapshot())
				}
			}
			if len(want) > 0 && len(got) == 0 {
				ht.Fatalf("%s, which %+v holds with no host route, is held by no route\nheld %v", address, want[0], kernel.snapshot())
			}
		}
		before := &coveringKernel{overlay: c.overlay, families: kernel.families}
		var want []Beneath
		for _, r := range kernel.snapshot() {
			host, under := c.under(r.Destination)
			under = under && !r.Unreachable && !r.Source.IsValid()
			if under {
				want = append(want, Beneath{Route: r.Destination, Host: host})
			}
			unscoped := r
			unscoped.Scoped = false
			if r.Scoped != (under || before.scopes(unscoped)) {
				ht.Fatalf("%+v went in scoped %v, want %v beneath a host route and %v with none\noverlay %v\ntable %+v", r, r.Scoped, under, before.scopes(unscoped), c.overlay, c.table.routes)
			}
		}
		slices.SortFunc(want, func(a, b Beneath) int { return comparePrefixes(a.Route, b.Route) })
		want = slices.Compact(want)
		if got := reconciler.Stats().Beneath; !slices.Equal(got, want) {
			ht.Fatalf("the pass names %+v beneath the host's routes, want %+v\noverlay %v\ntable %+v", got, want, c.overlay, c.table.routes)
		}
	})
}
