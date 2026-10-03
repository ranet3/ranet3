// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"maps"
	"math"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// allOnes is the mask the kernel stores for a mark written without one.
const allOnes = ^uint32(0)

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

// masks draws a mark's mask, the two spellings of an exact match more often
// than any other value.
func masks() hegel.Generator[uint32] {
	return hegel.OneOf(hegel.Integers[uint32](1, math.MaxUint32), hegel.Just(uint32(0)), hegel.Just(allOnes))
}

// writtenRules draws one rule in a shape a file writes: on addresses, which
// give the rule its family, on a mark alone, which names its family, or on
// both an address and a mark.
func writtenRules() hegel.Generator[Rule] {
	return hegel.Composite(func(tc hegel.TestCase) Rule {
		rule := Rule{
			Table:    schema.TableID(hegel.Draw(tc, edges[uint32](1, math.MaxUint32))),
			Priority: hegel.Draw(tc, edges[uint32](1, math.MaxUint32)),
		}
		marked := hegel.Draw(tc, hegel.Booleans())
		if marked {
			rule.FWMark = hegel.Draw(tc, edges[uint32](1, math.MaxUint32))
			rule.FWMask = hegel.Draw(tc, masks())
		}
		if marked && hegel.Draw(tc, hegel.Booleans()) {
			rule.Family = hegel.Draw(tc, hegel.SampledFrom([]Family{FamilyIPv4, FamilyIPv6, FamilyBoth}))
			return rule
		}
		v6 := hegel.Draw(tc, hegel.Booleans())
		switch hegel.Draw(tc, hegel.Integers(0, 2)) {
		case 0:
			rule.To = hegel.Draw(tc, selectors(v6))
		case 1:
			rule.From = hegel.Draw(tc, selectors(v6))
		default:
			rule.To = hegel.Draw(tc, selectors(v6))
			rule.From = hegel.Draw(tc, selectors(v6))
		}
		return rule
	})
}

// strayRules draws a rule with no regard for what validate takes: any prefix,
// host bits and zero lengths included, a mask with no mark, and a family that
// is no family at all. Canonicalization has to hold its shape on these too,
// since Normalized runs on a capability before anything has refused it.
func strayRules() hegel.Generator[Rule] {
	prefixes := hegel.OneOf(hegel.Just(schema.Prefix{}), hegel.Composite(func(tc hegel.TestCase) schema.Prefix {
		address := hegel.Draw(tc, hegel.IPAddresses())
		return schema.PrefixFrom(netip.PrefixFrom(address, hegel.Draw(tc, edges(0, address.BitLen()))))
	}))
	return hegel.Composite(func(tc hegel.TestCase) Rule {
		return Rule{
			To:       hegel.Draw(tc, prefixes),
			From:     hegel.Draw(tc, prefixes),
			FWMark:   hegel.Draw(tc, edges[uint32](0, math.MaxUint32)),
			FWMask:   hegel.Draw(tc, masks()),
			Table:    schema.TableID(hegel.Draw(tc, edges[uint32](0, math.MaxUint32))),
			Priority: hegel.Draw(tc, edges[uint32](0, math.MaxUint32)),
			Family:   hegel.Draw(tc, hegel.SampledFrom([]Family{FamilyUnset, FamilyIPv4, FamilyIPv6, FamilyBoth, "ipv7"})),
		}
	})
}

// capabilities draws a cap.table block carrying rules, with every other field
// that Normalized fills in or puts in order drawn as well, a field left at the
// zero that stands for its default included.
func capabilities(rules hegel.Generator[Rule]) hegel.Generator[Table] {
	assignable := hegel.Filter(hegel.IPAddresses(), func(address netip.Addr) bool { return !address.IsUnspecified() })
	return hegel.Composite(func(tc hegel.TestCase) Table {
		table := Table{
			ID:           schema.TableID(hegel.Draw(tc, hegel.OneOf(hegel.Just(uint32(0)), edges[uint32](1, reservedTable-1), edges[uint32](lastByteTable+1, math.MaxUint32)))),
			Proto:        hegel.Draw(tc, hegel.OneOf(hegel.Just(uint8(0)), edges[uint8](protocolStatic+1, math.MaxUint8))),
			Rules:        hegel.Draw(tc, hegel.Lists(rules).MaxSize(6)),
			Reconcile:    schema.Duration(hegel.Draw(tc, hegel.OneOf(hegel.Just(int64(0)), edges(int64(1), int64(time.Hour))))),
			CaptureGrace: schema.Duration(hegel.Draw(tc, hegel.OneOf(hegel.Just(int64(0)), edges(int64(MinCaptureGrace), int64(time.Hour))))),
		}
		for range hegel.Draw(tc, hegel.Integers(0, 3)) {
			address := hegel.Draw(tc, assignable)
			table.Addresses = append(table.Addresses, schema.PrefixFrom(netip.PrefixFrom(address, hegel.Draw(tc, edges(1, address.BitLen())))))
		}
		if hegel.Draw(tc, hegel.Booleans()) {
			address := hegel.Draw(tc, hegel.IPAddresses().IPv4())
			if hegel.Draw(tc, hegel.Booleans()) {
				address = netip.AddrFrom16(address.As16())
			}
			table.PrefSrc4 = schema.AddrFrom(address)
		}
		return table
	})
}

// Canonicalizing a rule that is already canonical changes nothing, and the
// same holds for a whole capability as the reconciler runs it, its rules
// expanded, canonicalized and put in order. New keeps the capability already
// normalized, while ReadsMark and a reload normalize whatever they are handed,
// so a form that moved when normalized again would make one capability compare
// unequal to itself: a reload refused over nothing, which is a restart that
// drops every SA on the node.
func TestRuleCanonicalizationIsIdempotent(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := hegel.Draw(ht, hegel.OneOf(writtenRules(), strayRules()))
		once := rule.canonical()
		if twice := once.canonical(); twice != once {
			ht.Fatalf("%s canonicalized to %s and then to %s", rule, once, twice)
		}

		table := hegel.Draw(ht, capabilities(hegel.OneOf(writtenRules(), strayRules())))
		normalized := table.Normalized()
		if again := normalized.Normalized(); !reflect.DeepEqual(again, normalized) {
			ht.Fatalf("a capability normalized to\n%+v\nand then to\n%+v", normalized, again)
		}
	})
}

// respelled writes a rule set the other way round wherever the kernel cannot
// tell the two apart: a mark's exact match written with the mask of all ones
// the kernel reports or with none at all, a rule written once for both
// families or once per family, and the entries in another order. What it
// returns is one rule set to the kernel, and so it has to be one to the
// reconciler.
func respelled(tc hegel.TestCase, rules []Rule) []Rule {
	exact := func(rule Rule) Rule {
		if rule.FWMark != 0 && (rule.FWMask == 0 || rule.FWMask == allOnes) && hegel.Draw(tc, hegel.Booleans()) {
			rule.FWMask ^= allOnes
		}
		return rule
	}
	var out []Rule
	for _, rule := range rules {
		if rule.Family == FamilyBoth && hegel.Draw(tc, hegel.Booleans()) {
			v4, v6 := rule, rule
			v4.Family, v6.Family = FamilyIPv4, FamilyIPv6
			out = append(out, exact(v4), exact(v6))
			continue
		}
		out = append(out, exact(rule))
	}
	// drawn as the distance back to swap with, so the order shrinks toward
	// the one it was written in
	for i := len(out) - 1; i > 0; i-- {
		j := i - hegel.Draw(tc, hegel.Integers(0, i))
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Two rule sets the kernel holds as one canonicalize to one, and a capability
// writing both spellings of a rule is refused as writing it twice. The
// spellings are the ones Rule.canonical and Normalized name: a mark with no
// mask and the same mark under a mask of all ones, which the kernel stores
// alike and answers EEXIST to each other, a rule for both families and its two
// halves, and the entries in any order. A reconciler holding the spelling the
// kernel does not report back deletes and reinstalls that rule on every pass,
// with a window each time in which the traffic it steers is not steered.
//
// The converse holds for the mask: two rules the kernel keeps apart by their
// mask stay apart. One mark under two different masks selects different
// packets unless both are the exact match, written as no mask or as all ones.
// So the first mask drawn is never the exact match, and the second may be
// either spelling of it. Canonicalizing the two to one rule would install a
// rule other than the one written, as an exact match on the mark, and refuse
// the two as one rule written twice.
func TestRulesTheKernelHoldsAsOneCanonicalizeEqual(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := hegel.Draw(ht, writtenRules())
		if rule.FWMark != 0 {
			bare, masked := rule, rule
			bare.FWMask, masked.FWMask = 0, allOnes
			if bare.canonical() != masked.canonical() {
				ht.Fatalf("%s and %s are one rule to the kernel and canonicalized to %s and %s", bare, masked, bare.canonical(), masked.canonical())
			}
		}

		// one mark under two masks, the second perhaps the exact match in
		// either spelling, which the kernel holds as two rules
		first := rule
		if first.FWMark == 0 {
			first.FWMark = hegel.Draw(ht, edges[uint32](1, math.MaxUint32))
		}
		second := first
		first.FWMask = hegel.Draw(ht, edges[uint32](1, math.MaxUint32-1))
		secondMasks := hegel.OneOf(edges[uint32](1, math.MaxUint32-1), hegel.Just(uint32(0)), hegel.Just(allOnes))
		second.FWMask = hegel.Draw(ht, hegel.Filter(secondMasks, func(mask uint32) bool { return mask != first.FWMask }))
		if first.canonical() == second.canonical() {
			ht.Fatalf("%s and %s are two rules to the kernel and canonicalized to one, %s", first, second, first.canonical())
		}
		if err := (Table{Rules: []Rule{first, second}}).Validate(); err != nil {
			ht.Fatalf("%s and %s are two rules to the kernel and Validate refused them: %v", first, second, err)
		}

		table := hegel.Draw(ht, capabilities(writtenRules()))
		other := table
		other.Rules = respelled(ht, table.Rules)
		refused, otherRefused := table.Validate(), other.Validate()
		if (refused == nil) != (otherRefused == nil) {
			ht.Fatalf("rules\n%v\nand\n%v\nare one rule set to the kernel, and Validate said %v and %v", table.Rules, other.Rules, refused, otherRefused)
		}
		ht.Assume(refused == nil)
		if got, want := other.Normalized(), table.Normalized(); !reflect.DeepEqual(got.Rules, want.Rules) {
			ht.Fatalf("rules\n%v\nand\n%v\nare one rule set to the kernel, and normalized to\n%v\nand\n%v", table.Rules, other.Rules, want.Rules, got.Rules)
		}

		// and both spellings written side by side are the one rule twice
		if len(table.Rules) > 0 {
			both := table
			both.Rules = append(slices.Clone(table.Rules), respelled(ht, table.Rules[:1])...)
			if err := both.Validate(); err == nil {
				ht.Fatalf("rules\n%v\nwrite %s twice, once in each spelling, and Validate took them", both.Rules, table.Rules[0])
			}
		}
	})
}

// routes draws a route as the reconciler keys one: a canonical destination,
// and the source, preferred source, metric and kind it may carry. The metrics
// are few on purpose, so a pool of them shares keys often enough for the diff
// to have something to keep.
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
		if address.Is4() && hegel.Draw(tc, hegel.Booleans()) {
			route.PrefSrc = hegel.Draw(tc, hegel.IPAddresses().IPv4())
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
