// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
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
			{prefix("198.18.104.5/32"), prefix("198.18.104.5/24")},
			{prefix("198.18.104.6/32"), prefix("198.18.104.6/24")},
			{prefix("2001:db8::5/128"), prefix("2001:db8::5/64")},
		} {
			if choice := hegel.Draw(tc, hegel.Integers(0, len(lengths))); choice < len(lengths) {
				out = append(out, schema.PrefixFrom(lengths[choice]))
			}
		}
		return out
	})
}

// reloads draws a cap.table block from a few values of every field, the id and the proto among them, so that a sequence keeps some and moves others
func reloads() hegel.Generator[Table] {
	return hegel.Composite(func(tc hegel.TestCase) Table {
		return Table{
			ID:              schema.TableID(hegel.Draw(tc, hegel.SampledFrom([]uint32{0, DefaultTable, DefaultTable + 1}))),
			Proto:           hegel.Draw(tc, hegel.SampledFrom([]uint8{0, DefaultProtocol, DefaultProtocol + 1})),
			Metric:          hegel.Draw(tc, hegel.SampledFrom([]uint32{0, 32, 64})),
			Addresses:       hegel.Draw(tc, reloadAddresses()),
			AssignAnnounced: hegel.Draw(tc, hegel.Booleans()),
			Reconcile:       schema.Duration(hegel.Draw(tc, hegel.SampledFrom([]time.Duration{0, time.Second, time.Minute}))),
			CaptureGrace:    schema.Duration(hegel.Draw(tc, hegel.SampledFrom([]time.Duration{0, MinCaptureGrace, time.Minute}))),
		}
	})
}

// announcements draws what cap.route announces, a default among it, none of it an address reloadAddresses draws
func announcements() hegel.Generator[[]netip.Prefix] {
	return hegel.Lists(hegel.SampledFrom([]netip.Prefix{prefix("2001:db8:1::1/64"), prefix("198.18.105.1/32"), prefix("::/0")})).MaxSize(2)
}

// reloadHarness is a reconciler started on table over one mesh every case shares, on a link where another writer already put foreign
// byLength has the link key an IPv4 address by its length as well, as linux does
func reloadHarness(t *testing.T, table Table, announced, foreign []netip.Prefix, byLength bool) (*Reconciler, *fakeKernel) {
	r, routes, fake := harness(t, table, Runtime{Announced: announced})
	fake.byLength = byLength
	routes.Set(netip.Prefix{}, prefix("10.0.0.0/8"), nil)
	routes.Set(netip.Prefix{}, prefix("2001:db8:100::/48"), nil)
	routes.Set(prefix("2001:db8:1::/48"), prefix("::/0"), nil)
	routes.Set(netip.Prefix{}, prefix("192.0.2.0/24"), netstack.Unreachable)
	for _, address := range foreign {
		fake.addrs[address] = true
	}
	return r, fake
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
// the pass after one it took leaves the kernel holding what a reconciler started on that capability holds after its first pass
// that includes the addresses another writer holds
// on a link that keys an IPv4 address by its length, a link carrying IPv4 before and after that pass carries it throughout
// one it refused changes nothing at all
func TestReloadConvergesOnWhatAFreshReconcilerHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		first := hegel.Draw(ht, reloads())
		ht.Assume(first.Validate() == nil && meaningfulHere(first))
		foreign := hegel.Draw(ht, hegel.Lists(hegel.SampledFrom([]netip.Prefix{
			prefix("198.18.104.9/32"), prefix("198.18.104.6/32"), prefix("2001:db8::5/96"),
		})).MaxSize(2))
		byLength := hegel.Draw(ht, hegel.Booleans())
		r, kernel := reloadHarness(t, first, hegel.Draw(ht, announcements()), foreign, byLength)
		if err := r.reconcile(); err != nil {
			ht.Fatalf("the first pass on %+v: %v", first, err)
		}
		// the drawn reloads keep the id and the proto in most samples, so each is moved alone first
		moves := movedAlone(first)
		for i := range len(moves) + hegel.Draw(ht, hegel.Integers(1, 4)) {
			var next Table
			var announced []netip.Prefix
			if i < len(moves) {
				next = moves[i]
			} else {
				next, announced = hegel.Draw(ht, reloads()), hegel.Draw(ht, announcements())
				if hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
					next = inSpaceOf(ht, first, next)
				}
			}
			before, running := heldBy(kernel), r.Table()
			err := r.SetTable(next, nil, announced)
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
			fresh, freshKernel := reloadHarness(t, next, announced, foreign, byLength)
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
