// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// coverCase is one table: the routes beside the defaults, which of them the
// platform scopes, which families carry a plain default, and the addresses
// looked up.
type coverCase struct {
	routes  []Route
	scoped  []bool
	with4   bool
	with6   bool
	lookups []netip.Addr
}

// coverPrefix draws a prefix whose first octet and length sit near the
// members' boundaries as often as anywhere else.
func coverPrefix(tc hegel.TestCase, v6 bool) netip.Prefix {
	var address netip.Addr
	if v6 {
		address = hegel.Draw(tc, hegel.IPAddresses().IPv6())
	} else {
		address = hegel.Draw(tc, hegel.IPAddresses().IPv4())
	}
	raw := address.AsSlice()
	raw[0] = hegel.Draw(tc, pbt.Spanning[uint8](0, 255))
	address, _ = netip.AddrFromSlice(raw)
	bits := hegel.Draw(tc, hegel.OneOf(pbt.Spanning(1, 9), pbt.Spanning(1, address.BitLen())))
	return netip.PrefixFrom(address, bits).Masked()
}

func coverCases() hegel.Generator[coverCase] {
	return hegel.Composite(func(tc hegel.TestCase) coverCase {
		c := coverCase{
			with4: hegel.Draw(tc, hegel.Booleans()),
			with6: hegel.Draw(tc, hegel.Booleans()),
		}
		for range hegel.Draw(tc, hegel.Integers(0, 8)) {
			destination := coverPrefix(tc, hegel.Draw(tc, hegel.Booleans()))
			c.routes = append(c.routes, Route{Destination: destination, Metric: routeMetric(0, destination, false)})
			c.scoped = append(c.scoped, hegel.Draw(tc, hegel.Booleans()))
			c.lookups = append(c.lookups, destination.Addr(), lastAddress(destination))
		}
		for range hegel.Draw(tc, hegel.Integers(0, 8)) {
			c.lookups = append(c.lookups, coverPrefix(tc, hegel.Draw(tc, hegel.Booleans())).Addr())
		}
		return c
	})
}

// inHole is an address no member holds, which stays on the host's own route.
func inHole(a netip.Addr) bool {
	if a.Is4() {
		return netip.MustParsePrefix("0.0.0.0/8").Contains(a)
	}
	return netip.MustParsePrefix("::/8").Contains(a)
}

// longest is the unscoped route an unbound lookup of a takes.
func longest(routes []Route, scopes func(Route) bool, a netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if scopes(r) || !r.Destination.Contains(a) {
			continue
		}
		if !found || r.Destination.Bits() > best.Destination.Bits() {
			best, found = r, true
		}
	}
	return best, found
}

// For every address outside the hole, the kernel's longest match with the
// cover in is the route the longest match with the plain default would take,
// or a member where that route is the default itself.
func TestCoverForwardsAsThePlainDefaultDoes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := hegel.Draw(ht, coverCases())
		scoped := map[Route]bool{}
		for i, r := range c.routes {
			if c.scoped[i] {
				scoped[r] = true
			}
		}
		scopes := func(r Route) bool { return !r.Cover && scoped[r] }
		withDefault := append([]Route(nil), c.routes...)
		if c.with4 {
			withDefault = append(withDefault, Route{Destination: netip.MustParsePrefix("0.0.0.0/0")})
		}
		if c.with6 {
			withDefault = append(withDefault, Route{Destination: netip.MustParsePrefix("::/0"), Metric: defaultIPv6Metric})
		}
		covered := coverDefaults(withDefault, scopes)
		for _, r := range covered {
			if r.Destination.Bits() == 0 && plainDefault(r) {
				ht.Fatalf("a plain default %s is still in the kernel's table", r.Destination)
			}
			if r.Cover && schema.HoldsUnspecified(r.Destination) {
				ht.Fatalf("member %s holds its family's zero address", r.Destination)
			}
		}
		for _, a := range c.lookups {
			if inHole(a) {
				continue
			}
			want, wantOK := longest(withDefault, scopes, a)
			got, gotOK := longest(covered, scopes, a)
			if wantOK != gotOK {
				ht.Fatalf("%s matches %v with the default and %v with the cover\ndefault: %v\ncover: %v", a, wantOK, gotOK, withDefault, covered)
			}
			if !wantOK {
				continue
			}
			if want.Destination.Bits() == 0 {
				if !got.Cover {
					ht.Fatalf("%s takes the default, and with the cover %s, which is not a member\ncover: %v", a, got.Destination, covered)
				}
				continue
			}
			if got.Destination != want.Destination || got.Cover {
				ht.Fatalf("%s takes %s with the default and %s (member %v) with the cover\ndefault: %v\ncover: %v",
					a, want.Destination, got.Destination, got.Cover, withDefault, covered)
			}
		}
	})
}

// unitRoutes are the routes a pass can carry beside the defaults: routes
// that withhold members at or around their keys, routes over a zero address,
// and routes that withhold nothing.
var unitRoutes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
	netip.MustParsePrefix("64.0.0.0/2"), netip.MustParsePrefix("0.0.0.0/4"),
	netip.MustParsePrefix("16.0.0.0/4"), netip.MustParsePrefix("1.0.0.0/16"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
	netip.MustParsePrefix("2000::/3"), netip.MustParsePrefix("4000::/2"),
	netip.MustParsePrefix("2001:db8::/32"),
}

// failKeys is the keys an add in a pass over routes can fail at, the
// members' and the routes' but a default's, drawn as often as each other.
func failKeys(routes []netip.Prefix) [2][]netip.Prefix {
	var keys [2][]netip.Prefix
	keys[0] = slices.Concat(zeroFreeCover[true], zeroFreeCover[false])
	for _, r := range routes {
		if r.Bits() > 0 {
			keys[1] = append(keys[1], r)
		}
	}
	return keys
}

// unitStep is one pass's table, the host's own defaults, the keys other
// programs hold, each with the error an add there meets, the keys where only
// a route that is not a member fails, and the keys where a member's delete
// fails.
type unitStep struct {
	routes              []netip.Prefix
	hosts               Covered
	taken, flaky, stuck map[netip.Prefix]error
}

func (s unitStep) equal(o unitStep) bool {
	return slices.Equal(s.routes, o.routes) && s.hosts == o.hosts &&
		maps.Equal(s.taken, o.taken) && maps.Equal(s.flaky, o.flaky) && maps.Equal(s.stuck, o.stuck)
}

// onlyRefuses reports a step whose every failure is a refusal.
func (s unitStep) onlyRefuses() bool {
	return len(s.flaky) == 0 && len(s.stuck) == 0 &&
		!slices.ContainsFunc(slices.Collect(maps.Values(s.taken)), func(err error) bool { return !errors.Is(err, errRouteSkipped) })
}

var errTransient = errors.New("no buffer space available")

func unitSteps() hegel.Generator[unitStep] {
	return hegel.Composite(func(tc hegel.TestCase) unitStep {
		step := unitStep{taken: map[netip.Prefix]error{}, flaky: map[netip.Prefix]error{}, stuck: map[netip.Prefix]error{}}
		for _, zero := range []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")} {
			if hegel.Draw(tc, pbt.Spanning(0, 4)) != 0 {
				step.routes = append(step.routes, zero)
			}
		}
		for _, r := range unitRoutes {
			if hegel.Draw(tc, pbt.Spanning(0, 3)) == 0 {
				step.routes = append(step.routes, r)
			}
		}
		step.hosts = Covered{V4: hegel.Draw(tc, pbt.Spanning(0, 4)) != 0, V6: hegel.Draw(tc, pbt.Spanning(0, 4)) != 0}
		// one kind for the step's failures, so a step that only refuses is as
		// common as either other kind
		kind := hegel.Draw(tc, pbt.Spanning(0, 2))
		keys := failKeys(step.routes)
		for range hegel.Draw(tc, pbt.Spanning(0, 3)) {
			pool := keys[hegel.Draw(tc, pbt.Spanning(0, 1))]
			if len(pool) == 0 {
				pool = keys[0]
			}
			key := pool[hegel.Draw(tc, pbt.Spanning(0, len(pool)-1))]
			switch kind {
			case 0:
				step.taken[key] = errRouteSkipped
			case 1:
				step.taken[key] = errTransient
			default:
				step.flaky[key] = errTransient
			}
		}
		// mostly a member at a route's own key, where the route meets that
		// member if its delete fails
		atRoutes := slices.DeleteFunc(slices.Clone(keys[0]), func(m netip.Prefix) bool { return !slices.Contains(keys[1], m) })
		for range hegel.Draw(tc, pbt.Spanning(0, 2)) {
			pool := keys[0]
			if len(atRoutes) > 0 && hegel.Draw(tc, pbt.Spanning(0, 3)) != 0 {
				pool = atRoutes
			}
			step.stuck[pool[hegel.Draw(tc, pbt.Spanning(0, len(pool)-1))]] = errTransient
		}
		return step
	})
}

// Over any sequence of passes that find members or the routes withholding
// them refused or failed, or a member's delete failed, each family's cover is
// every member coverDefaults gives for the routes the kernel then holds, or
// none, and none only when a member the pass tried failed, beside each member
// whose delete failed. Stats.Cover names exactly the families with members
// in, Skipped counts each refused route and each wanted member left out but
// for one whose add or delete failed, which the pass reports as its error, a
// pass over an unchanged table that only refuses adds and deletes nothing,
// the kernel refuses a route only at a key another program holds or at a
// member whose delete failed in that pass, and a pass with no error desires
// exactly what it installed and skipped.
func TestCoverGoesInWholeOrNotAtAll(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		reconciler, kernel, table := keyHarness(t)
		capture := reconciler.rt.Capture.(*recordingCapture)
		var last unitStep
		for pass := range hegel.Draw(ht, pbt.Spanning(1, 5)) {
			// the last step again, the last table with its keys free, another,
			// or the last table with a route joining at a member's key while
			// that member's delete fails
			step := last
			next := 2
			if pass > 0 {
				next = hegel.Draw(ht, pbt.Spanning(0, 3))
			}
			switch next {
			case 1, 3:
				step.taken, step.flaky, step.stuck = map[netip.Prefix]error{}, map[netip.Prefix]error{}, map[netip.Prefix]error{}
			case 2:
				step = hegel.Draw(ht, unitSteps())
			}
			if next == 3 {
				members := slices.Concat(zeroFreeCover[true], zeroFreeCover[false])
				key := members[hegel.Draw(ht, pbt.Spanning(0, len(members)-1))]
				if !slices.Contains(step.routes, key) {
					step.routes = append(slices.Clone(step.routes), key)
				}
				step.stuck[key] = errTransient
			}
			for _, r := range last.routes {
				table.Remove(netip.Prefix{}, r)
			}
			for _, r := range step.routes {
				table.Set(netip.Prefix{}, r, nil)
			}
			capture.hosts, kernel.taken, kernel.flaky, kernel.stuck = step.hosts, step.taken, step.flaky, step.stuck
			kernel.failed, kernel.kept = nil, map[netip.Prefix]bool{}
			adds, dels := kernel.counts()
			onlyRefused := step.onlyRefuses()
			err := reconciler.reconcile()
			if err != nil && onlyRefused {
				ht.Fatalf("pass %d that only refuses failed: %v", pass, err)
			}
			for _, f := range kernel.failed {
				if errors.Is(f.err, errRouteSkipped) && step.taken[f.route.Destination] == nil && !kernel.kept[f.route.Destination] {
					ht.Fatalf("pass %d tried %s at a key it holds itself, with that key's delete working\nstep %+v\nkernel %v",
						pass, f.route, step, kernel.snapshot())
				}
			}

			base := []Route{}
			for _, r := range kernel.snapshot() {
				if !r.Cover {
					base = append(base, r)
				}
			}
			for _, r := range step.routes {
				if r.Bits() == 0 && step.hosts.Has(r.Addr()) {
					base = append(base, Route{Destination: r, Metric: routeMetric(0, r, false)})
				}
			}
			expected := map[Family][]netip.Prefix{}
			for _, r := range coverDefaults(base, nil) {
				if r.Cover {
					family := familyOf(r.Destination.Addr())
					expected[family] = append(expected[family], r.Destination)
				}
			}
			broken, errored := map[Family]bool{}, map[Family]int{}
			skipped := 0
			for _, f := range kernel.failed {
				family := familyOf(f.route.Destination.Addr())
				refused := errors.Is(f.err, errRouteSkipped)
				switch {
				case f.route.Cover && !refused:
					broken[family] = true
					errored[family]++
				case f.route.Cover:
					broken[family] = true
				case refused:
					skipped++
				}
			}
			var covered []Family
			for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
				var got []netip.Prefix
				for _, r := range kernel.snapshot() {
					if r.Cover && familyOf(r.Destination.Addr()) == family {
						got = append(got, r.Destination)
					}
				}
				slices.SortFunc(got, comparePrefixes)
				want := slices.Clone(expected[family])
				if broken[family] {
					want = nil
					skipped += len(expected[family]) - errored[family]
					for _, m := range expected[family] {
						if kernel.kept[m] {
							skipped--
						}
					}
				}
				for m := range kernel.kept {
					if familyOf(m.Addr()) == family && !slices.Contains(want, m) {
						want = append(want, m)
					}
				}
				slices.SortFunc(want, comparePrefixes)
				if !slices.Equal(got, want) {
					ht.Fatalf("pass %d holds the %s members %v, want %v\nstep %+v\nkernel %v\nfailed %v",
						pass, family, got, want, step, kernel.snapshot(), kernel.failed)
				}
				if len(got) > 0 {
					covered = append(covered, family)
				}
			}
			stats := reconciler.Stats()
			if !slices.Equal(stats.Cover, covered) {
				ht.Fatalf("pass %d reports the cover %v, want %v", pass, stats.Cover, covered)
			}
			if stats.Skipped != skipped {
				ht.Fatalf("pass %d reports %d skipped, want %d\nstep %+v\nfailed %v", pass, stats.Skipped, skipped, step, kernel.failed)
			}
			if err == nil && stats.Desired != stats.Installed+stats.Skipped {
				ht.Fatalf("pass %d reports %d desired, %d installed and %d skipped, want desired to be the other two\nstep %+v",
					pass, stats.Desired, stats.Installed, stats.Skipped, step)
			}
			if nowAdds, nowDels := kernel.counts(); pass > 0 && step.equal(last) && onlyRefused && (nowAdds != adds || nowDels != dels) {
				ht.Fatalf("pass %d over an unchanged table that only refuses added %d and deleted %d routes\nstep %+v",
					pass, nowAdds-adds, nowDels-dels, step)
			}
			last = step
		}
	})
}
