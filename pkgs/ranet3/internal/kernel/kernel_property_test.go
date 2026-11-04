// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"fmt"
	"maps"
	"math"
	"net/netip"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// edges draws from lo through hi with both ends drawn on their own as well,
// since a derandomized run of a few hundred cases need not land on either.
func edges[T interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}](lo, hi T) hegel.Generator[T] {
	return hegel.OneOf(hegel.Integers(lo, hi), hegel.Just(lo), hegel.Just(hi))
}

// selectors draws a prefix a rule selects on, at a length from one through
// the family's width and with no bits set below it, the shape validate takes.
func selectors(v6 bool) hegel.Generator[schema.Prefix] {
	addresses := hegel.IPAddresses().IPv4()
	if v6 {
		addresses = hegel.IPAddresses().IPv6()
	}
	return hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address := hegel.Draw(tc, addresses)
		return schema.PrefixFrom(netip.PrefixFrom(address, hegel.Draw(tc, edges(1, address.BitLen()))).Masked())
	})
}

// capabilities draws a cap.table block with every field that Normalized fills
// in or puts in order, a field left at the zero that stands for its default
// included.
func capabilities() hegel.Generator[Table] {
	assignable := hegel.Filter(hegel.IPAddresses(), func(address netip.Addr) bool { return !address.IsUnspecified() })
	return hegel.Composite(func(tc hegel.TestCase) Table {
		table := Table{
			ID:           schema.TableID(hegel.Draw(tc, hegel.OneOf(hegel.Just(uint32(0)), edges[uint32](1, reservedTable-1), edges[uint32](lastByteTable+1, math.MaxUint32)))),
			Proto:        hegel.Draw(tc, hegel.OneOf(hegel.Just(uint8(0)), edges[uint8](protocolStatic+1, math.MaxUint8))),
			Reconcile:    schema.Duration(hegel.Draw(tc, hegel.OneOf(hegel.Just(int64(0)), edges(int64(1), int64(time.Hour))))),
			CaptureGrace: schema.Duration(hegel.Draw(tc, hegel.OneOf(hegel.Just(int64(0)), edges(int64(MinCaptureGrace), int64(time.Hour))))),
		}
		for range hegel.Draw(tc, hegel.Integers(0, 3)) {
			address := hegel.Draw(tc, assignable)
			table.Addresses = append(table.Addresses, schema.PrefixFrom(netip.PrefixFrom(address, hegel.Draw(tc, edges(1, address.BitLen())))))
		}
		// cap.exit's mode, off one time in three, its forward in any order and an entry written twice among them
		if hegel.Draw(tc, hegel.Integers(0, 2)) > 0 {
			var mode ExitMode
			for range hegel.Draw(tc, hegel.Integers(0, 4)) {
				mode.Forward = append(mode.Forward, hegel.Draw(tc, hegel.SampledFrom([]string{"docker*", "eth1", "br-?"})))
			}
			table = table.WithMode(&mode)
		}
		return table
	})
}

// A capability as the reconciler runs it changes nothing when normalized
// again. A reload normalizes whatever it is handed, so a form that moved when
// normalized again would make one capability compare unequal to itself: in its
// id or its proto, or where no reconciler runs to take the block, a reload
// refused over nothing, which is a restart that drops every SA on the node.
func TestNormalizedIsIdempotent(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		normalized := hegel.Draw(ht, capabilities()).Normalized()
		if again := normalized.Normalized(); !reflect.DeepEqual(again, normalized) {
			ht.Fatalf("a capability normalized to\n%+v\nand then to\n%+v", normalized, again)
		}
	})
}

// routes draws a route as the reconciler keys one: a canonical destination,
// and the source, metric and kind it may carry. The metrics are few on
// purpose, so a pool of them shares keys often enough for the diff to have
// something to keep.
func routes() hegel.Generator[Route] {
	return hegel.Composite(func(tc hegel.TestCase) Route {
		address := hegel.Draw(tc, hegel.IPAddresses())
		destination, _ := canonicalPrefix(netip.PrefixFrom(address, hegel.Draw(tc, edges(0, address.BitLen()))))
		route := Route{
			Destination: destination,
			Metric:      hegel.Draw(tc, hegel.SampledFrom([]uint32{0, 32, defaultIPv6Metric, holdMetric})),
			Unreachable: hegel.Draw(tc, hegel.Booleans()),
		}
		if !address.Is4() && hegel.Draw(tc, hegel.Booleans()) {
			route.Source = hegel.Draw(tc, selectors(true)).Prefix
		}
		return route
	})
}

// The diff applied to what the kernel holds leaves it holding exactly what
// the mesh wants, and no route is both installed and withdrawn. A route left
// out is a prefix the mesh has and the node does not forward, and a route
// withdrawn and installed in one pass is one that blinks on every pass.
// Applying means what the platform does: a withdrawal removes the route as it
// was read back, scope and all, and an install files the route under the
// scope the platform gives it, which on darwin can differ from what is there.
// A second pass over the result moves nothing.
func TestRouteDiffTakesTheKernelToTheDesiredSet(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		pool := hegel.Draw(ht, hegel.Lists(routes()).MaxSize(12))
		// desired stands for the output of Reconciler.desired, which never sets
		// Scoped, and actual for a dump, which on darwin may
		var desired, actual []Route
		for _, route := range pool {
			if hegel.Draw(ht, hegel.Booleans()) {
				desired = append(desired, route)
			}
			if hegel.Draw(ht, hegel.Booleans()) {
				route.Scoped = hegel.Draw(ht, hegel.Booleans())
				actual = append(actual, route)
			}
		}
		// nil is linux, which scopes nothing, and otherwise a platform scoping
		// whichever of these routes it was drawn to, by the route alone
		var scopes func(Route) bool
		if hegel.Draw(ht, hegel.Booleans()) {
			scoped := make(map[Route]bool)
			for _, route := range pool {
				scoped[route] = hegel.Draw(ht, hegel.Booleans())
			}
			scopes = func(route Route) bool {
				route.Scoped = false
				return scoped[route]
			}
		}
		installed := func(route Route) Route {
			route.Scoped = scopes != nil && scopes(route)
			return route
		}

		add, del := diffRoutes(desired, actual, scopes)
		if !slices.IsSortedFunc(add, compareRoutes) || !slices.IsSortedFunc(del, compareRoutes) {
			ht.Fatalf("the diff came out unsorted: add %v, del %v", add, del)
		}
		for _, added := range add {
			if slices.Contains(del, installed(added)) {
				ht.Fatalf("%s is both installed and withdrawn: add %v, del %v", installed(added), add, del)
			}
		}

		held := make(map[Route]bool, len(actual))
		for _, route := range actual {
			held[route] = true
		}
		for _, route := range del {
			if !held[route] {
				ht.Fatalf("%s is withdrawn and the kernel does not hold it: actual %v", route, actual)
			}
			delete(held, route)
		}
		for _, route := range add {
			if held[installed(route)] {
				ht.Fatalf("%s is installed over the same route already held: actual %v", installed(route), actual)
			}
			held[installed(route)] = true
		}
		want := make(map[Route]bool, len(desired))
		for _, route := range desired {
			want[installed(route)] = true
		}
		if !maps.Equal(held, want) {
			ht.Fatalf("the kernel ends up holding %v, want %v: actual %v, add %v, del %v",
				slices.SortedFunc(maps.Keys(held), compareRoutes), slices.SortedFunc(maps.Keys(want), compareRoutes), actual, add, del)
		}

		again, gone := diffRoutes(desired, slices.Collect(maps.Keys(held)), scopes)
		if len(again) != 0 || len(gone) != 0 {
			ht.Fatalf("a second pass over what the first left installs %v and withdraws %v", again, gone)
		}
	})
}

// reloadAddresses draws at most one length of each of a few addresses, so a sequence of capabilities renumbers, lengthens, drops and takes back the same ones
func reloadAddresses() hegel.Generator[[]schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) []schema.Prefix {
		var out []schema.Prefix
		for _, lengths := range [][]netip.Prefix{
			{prefix("203.0.113.5/32"), prefix("203.0.113.5/24")},
			{prefix("203.0.113.6/32"), prefix("203.0.113.6/24")},
			{prefix("2001:db8::5/128"), prefix("2001:db8::5/64")},
		} {
			if choice := hegel.Draw(tc, hegel.Integers(0, len(lengths))); choice < len(lengths) {
				out = append(out, schema.PrefixFrom(lengths[choice]))
			}
		}
		return out
	})
}

// reloadSID is the one SID mode 3's via names, which the mesh every case shares resolves through its own /128 from reloadSource
var reloadSID, reloadSource = addr("2001:db8:200::46"), addr("2001:db8::5")

// reloads draws a cap.table block from a few values of every field, the id and the proto among them, so that a sequence keeps some and moves others
// its mode is mode off, mode 2 with fallback unwritten or "uplink", or mode 3 along reloadSID under "uplink"
func reloads() hegel.Generator[Table] {
	return hegel.Composite(func(tc hegel.TestCase) Table {
		table := Table{
			ID:              schema.TableID(hegel.Draw(tc, hegel.SampledFrom([]uint32{0, DefaultTable, DefaultTable + 1}))),
			Proto:           hegel.Draw(tc, hegel.SampledFrom([]uint8{0, DefaultProtocol, DefaultProtocol + 1})),
			Addresses:       hegel.Draw(tc, reloadAddresses()),
			AssignAnnounced: hegel.Draw(tc, hegel.Booleans()),
			Reconcile:       schema.Duration(hegel.Draw(tc, hegel.SampledFrom([]time.Duration{0, time.Second, time.Minute}))),
			CaptureGrace:    schema.Duration(hegel.Draw(tc, hegel.SampledFrom([]time.Duration{0, MinCaptureGrace, time.Minute}))),
		}
		switch hegel.Draw(tc, pbt.Spanning(0, 3)) {
		case 1:
			table = table.WithMode(&ExitMode{})
		case 2:
			table = table.WithMode(&ExitMode{Fallback: FallbackUplink})
		case 3:
			table = table.WithMode(&ExitMode{Via: []schema.Addr{schema.AddrFrom(reloadSID)}, Fallback: FallbackUplink}).WithPathSource(reloadSource)
		}
		return table
	})
}

// reloadOverlays draws the overlay a reload hands, each of a few prefixes in or out: one holding the IPv4 addresses reloadAddresses
// and the foreign ones draw, one holding the IPv6 one, one holding an address cap.route announces, and one holding none
func reloadOverlays() hegel.Generator[[]schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) []schema.Prefix {
		var out []schema.Prefix
		for _, entry := range []string{"203.0.113.0/24", "2001:db8::/64", "198.51.100.0/24", "3fff::/20"} {
			if hegel.Draw(tc, hegel.Booleans()) {
				out = append(out, schema.MustPrefix(entry))
			}
		}
		return out
	})
}

// coveredHere is the families whose zero routes a covering platform holds as members after a pass on t over overlay, written apart from
// exitPass: in modes 2 and 3, each family an address of the tun lies inside the overlay in, the tun holding what t assigns and foreign
func coveredHere(t Table, overlay []schema.Prefix, announced, foreign []netip.Prefix) []Family {
	if t.Mode() == nil {
		return nil
	}
	var out []Family
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		inside := func(address netip.Prefix) bool {
			return familyOf(address.Addr()) == family && slices.ContainsFunc(overlay, func(entry schema.Prefix) bool { return entry.Prefix.Contains(address.Addr()) })
		}
		if slices.ContainsFunc(t.Assigned(announced), inside) || slices.ContainsFunc(foreign, inside) {
			out = append(out, family)
		}
	}
	return out
}

// announcements draws what cap.route announces, a default among it, none of it an address reloadAddresses draws
func announcements() hegel.Generator[[]netip.Prefix] {
	return hegel.Lists(hegel.SampledFrom([]netip.Prefix{prefix("2001:db8:1::1/64"), prefix("198.51.100.1/32"), prefix("::/0")})).MaxSize(2)
}

// reloadHarness is a reconciler with a live session started on table and overlay over one mesh every case shares, on a link where
// another writer already put foreign, the plain fake or, where covering, the covering fake with no policy rules, as darwin's
// byLength has the link key an IPv4 address by its length as well, as linux does
func reloadHarness(t *testing.T, table Table, overlay []schema.Prefix, announced, foreign []netip.Prefix, byLength, covering bool) (*Reconciler, *fakeKernel) {
	r, routes, fake := harness(t, table, Runtime{Announced: announced, Overlay: overlay, Sessions: func() int { return 1 }})
	fake.byLength = byLength
	routes.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	routes.Set(netip.Prefix{}, prefix("2001:db8:100::/48"), nil)
	routes.Set(prefix("2001:db8:1::/48"), prefix("::/0"), nil)
	routes.Set(netip.Prefix{}, prefix("192.0.2.0/24"), netstack.Unreachable)
	routes.Set(netip.Prefix{}, prefix("0.0.0.0/0"), nil)
	routes.Set(netip.Prefix{}, prefix("::/0"), nil)
	routes.Set(netip.Prefix{}, netip.PrefixFrom(reloadSID, 128), learned)
	for _, address := range foreign {
		fake.addrs[address] = true
	}
	if covering {
		onCovering(r, fake)
	}
	return r, fake
}

// wantCovered fails the case unless kernel holds a member of a family exactly where covered names the family and the routes r
// projects from the mesh hold a zero route of it, and no zero route of a family covered names as itself
func wantCovered(ht *hegel.T, r *Reconciler, kernel *fakeKernel, covered []Family, what string) {
	toCover := map[Family]bool{}
	for _, route := range r.desired(r.src.Snapshot(), r.readNetwork()) {
		family := familyOf(route.Destination.Addr())
		toCover[family] = toCover[family] || zeroRoute(route)
	}
	members, zeros := map[Family]bool{}, map[Family]bool{}
	for _, route := range kernel.snapshot() {
		family := familyOf(route.Destination.Addr())
		members[family] = members[family] || route.Cover
		zeros[family] = zeros[family] || zeroRoute(route)
	}
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		covers := slices.Contains(covered, family)
		if members[family] != (covers && toCover[family]) || zeros[family] && covers {
			ht.Fatalf("%s the kernel holds %s members %v and its zero route %v, want it covered %v with a zero route to cover %v: %v",
				what, family, members[family], zeros[family], covers, toCover[family], kernel.snapshot())
		}
	}
}

// inSpaceOf is next on the id and the proto of first, a default spelled either way
func inSpaceOf(tc hegel.TestCase, first, next Table) Table {
	next.ID, next.Proto = first.ID, first.Proto
	if first.Normalized().ID == DefaultTable {
		next.ID = hegel.Draw(tc, hegel.SampledFrom([]schema.TableID{0, DefaultTable}))
	}
	if first.Normalized().Proto == DefaultProtocol {
		next.Proto = hegel.Draw(tc, hegel.SampledFrom([]uint8{0, DefaultProtocol}))
	}
	return next
}

// held is everything a fake kernel holds that a reconciler writes
type held struct {
	routes    []Route
	addresses []netip.Prefix
	rules     []Rule
}

func heldBy(f *fakeKernel) held {
	routes, addresses := f.snapshot(), f.heldAddresses()
	f.mu.Lock()
	defer f.mu.Unlock()
	return held{
		routes:    routes,
		addresses: addresses,
		rules:     slices.SortedFunc(maps.Keys(f.rules), func(a, b Rule) int { return strings.Compare(a.String(), b.String()) }),
	}
}

// movedAlone is first with only its id and only its proto moved, each to a value a block may carry
func movedAlone(first Table) []Table {
	id, proto := first, first
	id.ID = DefaultTable
	if first.Normalized().ID == DefaultTable {
		id.ID = DefaultTable + 1
	}
	proto.Proto = DefaultProtocol
	if first.Normalized().Proto == DefaultProtocol {
		proto.Proto = DefaultProtocol + 1
	}
	return []Table{id, proto}
}

// meaningfulHere is whether the platform under test can carry t, written apart from the platform's code
// linux carries every setting, darwin no table or protocol of a block's own, and the rest nothing
func meaningfulHere(t Table) bool {
	n := t.Normalized()
	switch runtime.GOOS {
	case "linux":
		return true
	case "darwin":
		return n.ID == DefaultTable && n.Proto == DefaultProtocol
	}
	return false
}

// the reconciler starts on a table New accepts here, one that validates and means something on this platform
// a reload is taken when it validates, means something on this platform and keeps the id and the proto the reconciler started on
// the pass after one it took leaves the kernel holding what a reconciler started on that capability, overlay and announcements holds
// after its first pass
// that includes the addresses another writer holds
// on a covering platform it holds a family's zero routes as the cover's members exactly where coveredHere covers the family and
// the routes projected from the mesh hold a zero route of it
// on a link that keys an IPv4 address by its length, a link carrying IPv4 before and after that pass carries it throughout
// one it refused changes nothing at all
func TestReloadConvergesOnWhatAFreshReconcilerHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		first := hegel.Draw(ht, reloads())
		ht.Assume(first.Validate() == nil && meaningfulHere(first))
		foreign := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom([]netip.Prefix{
			prefix("203.0.113.9/32"), prefix("203.0.113.6/32"), prefix("2001:db8::5/96"),
		})).MaxSize(2))
		byLength, covering := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		r, kernel := reloadHarness(t, first, hegel.Draw(ht, reloadOverlays()), hegel.Draw(ht, announcements()), foreign, byLength, covering)
		if err := r.reconcile(); err != nil {
			ht.Fatalf("the first pass on %+v: %v", first, err)
		}
		// the drawn reloads keep the id and the proto in most samples, so each is moved alone first
		moves := movedAlone(first)
		for i := range len(moves) + hegel.Draw(ht, hegel.Integers(1, 4)) {
			var next Table
			var overlay []schema.Prefix
			var announced []netip.Prefix
			if i < len(moves) {
				next = moves[i]
			} else {
				next, overlay, announced = hegel.Draw(ht, reloads()), hegel.Draw(ht, reloadOverlays()), hegel.Draw(ht, announcements())
				if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
					next = inSpaceOf(ht, first, next)
				}
			}
			before, running := heldBy(kernel), r.Table()
			err := r.SetTable(next, overlay, announced)
			keeps := next.Normalized().ID == first.Normalized().ID && next.Normalized().Proto == first.Normalized().Proto
			takes := keeps && next.Validate() == nil && meaningfulHere(next)
			if (err == nil) != takes {
				ht.Fatalf("a reload from %+v to %+v answered %v", first, next, err)
			}
			if err != nil {
				if r.adopt() {
					ht.Fatalf("the refused %+v was handed to the loop", next)
				}
				if err := r.reconcile(); err != nil {
					ht.Fatalf("the pass after a refused reload: %v", err)
				}
				if after := heldBy(kernel); !reflect.DeepEqual(after, before) || !reflect.DeepEqual(r.Table(), running) {
					ht.Fatalf("the refused %+v moved the kernel from\n%+v\nto\n%+v", next, before, after)
				}
				continue
			}
			if !r.adopt() {
				ht.Fatalf("the reload to %+v handed the loop nothing", next)
			}
			kernel.emptied = false
			if err := r.reconcile(); err != nil {
				ht.Fatalf("the pass after the reload to %+v: %v", next, err)
			}
			v4 := func(address netip.Prefix) bool { return address.Addr().Is4() }
			if after := heldBy(kernel); byLength && kernel.emptied && slices.ContainsFunc(before.addresses, v4) && slices.ContainsFunc(after.addresses, v4) {
				ht.Fatalf("the reload to %+v took every IPv4 address off the link on its way from %v to %v", next, before.addresses, after.addresses)
			}
			var covered []Family
			if covering {
				covered = coveredHere(next, overlay, announced, foreign)
			}
			wantCovered(ht, r, kernel, covered, fmt.Sprintf("after the reload to %+v over %v", next, overlay))
			fresh, freshKernel := reloadHarness(t, next, overlay, announced, foreign, byLength, covering)
			if err := fresh.reconcile(); err != nil {
				ht.Fatalf("the first pass on %+v: %v", next, err)
			}
			if got, want := heldBy(kernel), heldBy(freshKernel); !reflect.DeepEqual(got, want) {
				ht.Fatalf("after the reload to %+v the kernel holds\n%+v\nand a reconciler started on it holds\n%+v", next, got, want)
			}
			if got := r.Table(); !reflect.DeepEqual(got, next.Normalized()) {
				ht.Fatalf("after the reload to %+v the reconciler runs %+v", next, got)
			}
		}
	})
}
