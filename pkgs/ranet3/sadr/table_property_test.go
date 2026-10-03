// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package sadr

import (
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// referenceTable is the table as a plain list of routes, searched end to end
// on every lookup. It shares nothing with the trie but the Route type, so a
// disagreement between the two is the trie's.
type referenceTable struct {
	routes []Route[int]
}

// key is how Set and Remove name an entry: both prefixes masked, and every
// invalid source the one match-all source. ok is false for what the table
// ignores, an invalid destination or a source from the other family.
func (m *referenceTable) key(src, dst netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	src, dst = src.Masked(), dst.Masked()
	if !dst.IsValid() || src.IsValid() && src.Addr().BitLen() != dst.Addr().BitLen() {
		return src, dst, false
	}
	return src, dst, true
}

func (m *referenceTable) set(src, dst netip.Prefix, value int) {
	src, dst, ok := m.key(src, dst)
	if !ok {
		return
	}
	for i, route := range m.routes {
		if route.Source == src && route.Destination == dst {
			m.routes[i].Value = value
			return
		}
	}
	m.routes = append(m.routes, Route[int]{Source: src, Destination: dst, Value: value})
}

func (m *referenceTable) remove(src, dst netip.Prefix) {
	src, dst, ok := m.key(src, dst)
	if !ok {
		return
	}
	m.routes = slices.DeleteFunc(m.routes, func(route Route[int]) bool {
		return route.Source == src && route.Destination == dst
	})
}

func (m *referenceTable) removeValue(value int) {
	m.routes = slices.DeleteFunc(m.routes, func(route Route[int]) bool { return route.Value == value })
}

// lookup takes the longest destination holding a route whose source matches,
// and within it the longest source. An invalid source matches every address
// and ranks below a source of any length, since its Bits is -1.
func (m *referenceTable) lookup(src, dst netip.Addr) (int, bool) {
	var best *Route[int]
	for i, route := range m.routes {
		if !route.Destination.Contains(dst) || route.Source.IsValid() && !route.Source.Contains(src) {
			continue
		}
		if best == nil || route.Destination.Bits() > best.Destination.Bits() ||
			route.Destination.Bits() == best.Destination.Bits() && route.Source.Bits() > best.Source.Bits() {
			best = &m.routes[i]
		}
	}
	if best == nil {
		return 0, false
	}
	return best.Value, true
}

type tableOpKind uint8

const (
	opSet tableOpKind = iota
	opRemove
	opRemoveValue
	opLookup
)

// tableOp is one call on a table, made on the trie and on the reference alike.
type tableOp struct {
	kind     tableOpKind
	src, dst netip.Prefix
	value    int
	from, to netip.Addr
}

// GoString spells each drawn operation out in a failure, as the call it stands
// for rather than as the internals of the netip values in it.
func (op tableOp) GoString() string {
	switch op.kind {
	case opSet:
		return fmt.Sprintf("Set(%v, %v, %d)", op.src, op.dst, op.value)
	case opRemove:
		return fmt.Sprintf("Remove(%v, %v)", op.src, op.dst)
	case opRemoveValue:
		return fmt.Sprintf("RemoveValue(%d)", op.value)
	}
	return fmt.Sprintf("Lookup(%v, %v)", op.from, op.to)
}

// near keeps the first keep bits of address and draws the rest.
func near(tc hegel.TestCase, address netip.Addr, keep int) netip.Addr {
	raw := address.AsSlice()
	fresh := hegel.Draw(tc, hegel.Binary(len(raw), len(raw)))
	for bit := keep; bit < len(raw)*8; bit++ {
		mask := byte(0x80) >> (bit % 8)
		raw[bit/8] = raw[bit/8]&^mask | fresh[bit/8]&mask
	}
	out, _ := netip.AddrFromSlice(raw)
	return out
}

// within is an address inside p, its host bits drawn. An invalid p is the
// match-all source, which every address is inside, so any address of either
// family will do.
func within(tc hegel.TestCase, p netip.Prefix) netip.Addr {
	if !p.IsValid() {
		return hegel.Draw(tc, hegel.IPAddresses())
	}
	return near(tc, p.Addr(), p.Bits())
}

// prefixPool is one address family's prefixes for one drawn table. The
// operations pick from it rather than drawing afresh, so they land on one
// another often enough to replace, remove and shadow. Every prefix is near one
// of a few anchors, so the destinations nest and diverge at whatever depth
// was drawn, which independent draws almost never do.
type prefixPool struct {
	dsts, srcs []netip.Prefix
}

func drawPrefixPool(tc hegel.TestCase, anchors []netip.Addr) prefixPool {
	width := anchors[0].BitLen()
	prefixes := func(lengths hegel.Generator[int]) hegel.Generator[netip.Prefix] {
		return hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
			anchor := hegel.Draw(tc, hegel.SampledFrom(anchors))
			address := near(tc, anchor, hegel.Draw(tc, pbt.Spanning(0, width)))
			// the host bits are kept, since the table masks them itself
			return netip.PrefixFrom(address, hegel.Draw(tc, lengths))
		})
	}
	// Sources take one of a few lengths, so one destination gathers enough
	// sources of a length to be indexed rather than scanned, the zero length
	// and a single host among them. A source can be the invalid prefix that
	// matches everything, spelled as the zero prefix or as one whose length
	// does not fit its address.
	lengths := hegel.Draw(tc, hegel.Lists(pbt.Spanning(0, width)).MinSize(1).MaxSize(2))
	sources := hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/3)) {
			if hegel.Draw(tc, hegel.Booleans()) {
				return netip.Prefix{}
			}
			return netip.PrefixFrom(hegel.Draw(tc, hegel.SampledFrom(anchors)), width+1)
		}
		return hegel.Draw(tc, prefixes(hegel.SampledFrom(lengths)))
	})
	return prefixPool{
		dsts: hegel.Draw(tc, hegel.Lists(prefixes(pbt.Spanning(0, width))).MinSize(1).MaxSize(3)),
		srcs: hegel.Draw(tc, hegel.Lists(sources).MinSize(4).MaxSize(16)),
	}
}

// tableMachine runs the trie and the reference side by side. Its rules are
// the table's writes and lookups, and its invariants compare what the two
// hold, now and as of every walk taken earlier.
type tableMachine struct {
	pools     [2]prefixPool
	table     Table[int]
	model     referenceTable
	snapshots []snapshot
}

// snapshot is a walk taken at some point, with the routes it has to hold
// however the table changes after it.
type snapshot struct {
	taken  int
	routes iter.Seq[Route[int]]
	want   []Route[int]
}

// opDrawer draws the arguments of one operation from the pools: mostly
// within one family, and now and then a source from the other family or an
// invalid destination, both of which the table ignores.
type opDrawer struct {
	tc          hegel.TestCase
	pool, other prefixPool
}

func (m *tableMachine) drawer(tc hegel.TestCase) opDrawer {
	family := hegel.Draw(tc, hegel.Integers(0, 1))
	return opDrawer{tc: tc, pool: m.pools[family], other: m.pools[1-family]}
}

func (d opDrawer) pick(prefixes []netip.Prefix) netip.Prefix {
	return hegel.Draw(d.tc, hegel.SampledFrom(prefixes))
}

func (d opDrawer) src() netip.Prefix {
	if hegel.Draw(d.tc, hegel.WeightedBooleans(1.0/8)) {
		return d.pick(d.other.srcs)
	}
	return d.pick(d.pool.srcs)
}

func (d opDrawer) dst() netip.Prefix {
	if hegel.Draw(d.tc, hegel.WeightedBooleans(1.0/16)) {
		return netip.Prefix{}
	}
	return d.pick(d.pool.dsts)
}

func (d opDrawer) value() int { return hegel.Draw(d.tc, hegel.Integers(0, 7)) }

// address is a lookup address inside one of prefixes, an arbitrary one of
// either family, or none at all.
func (d opDrawer) address(prefixes []netip.Prefix) netip.Addr {
	if hegel.Draw(d.tc, hegel.WeightedBooleans(1.0/4)) {
		if hegel.Draw(d.tc, hegel.Booleans()) {
			return netip.Addr{}
		}
		return hegel.Draw(d.tc, hegel.IPAddresses())
	}
	return within(d.tc, d.pick(prefixes))
}

// zoned is a drawn lookup address, now and then given a zone if it is IPv6.
// Prefix.Contains matches a zoned address against no prefix, so a zoned
// source matches only the match-all entry, which the scan of a destination's
// sources and its index both have to answer, and a zoned destination matches
// nothing.
func (d opDrawer) zoned(address netip.Addr) netip.Addr {
	if address.Is6() && hegel.Draw(d.tc, hegel.WeightedBooleans(1.0/8)) {
		return address.WithZone("eth0")
	}
	return address
}

// op draws one operation as a single value, so a failure prints it as the
// call it stands for.
func (m *tableMachine) op(tc hegel.TestCase, draw func(opDrawer) tableOp) tableOp {
	return hegel.Draw(tc, hegel.Composite(func(tc hegel.TestCase) tableOp { return draw(m.drawer(tc)) }))
}

func (m *tableMachine) set(op tableOp) {
	m.table.Set(op.src, op.dst, op.value)
	m.model.set(op.src, op.dst, op.value)
}

func (m *tableMachine) RuleSet(tc hegel.TestCase) {
	m.set(m.op(tc, func(d opDrawer) tableOp {
		return tableOp{kind: opSet, src: d.src(), dst: d.dst(), value: d.value()}
	}))
}

// RuleSetSourcesOfOneDestination is the shape babel gives the table, one
// entry per source a neighbor announces for a destination, and the one that
// gets a destination's sources indexed rather than scanned.
func (m *tableMachine) RuleSetSourcesOfOneDestination(tc hegel.TestCase) {
	ops := hegel.Draw(tc, hegel.Composite(func(tc hegel.TestCase) []tableOp {
		d := m.drawer(tc)
		dst := d.dst()
		return hegel.Draw(tc, hegel.Lists(hegel.Composite(func(tc hegel.TestCase) tableOp {
			d.tc = tc
			return tableOp{kind: opSet, src: d.src(), dst: dst, value: d.value()}
		})).MinSize(4).MaxSize(13))
	}))
	for _, op := range ops {
		m.set(op)
	}
}

// RuleSetHostRoutesSideBySide sets a host route at a pooled destination's
// address and, beside it, either the host route differing in its last bit or
// the prefix one bit shorter holding it. Either puts a node one bit short of a
// full address above a node of a full one, the last step a lookup takes, and
// prefixes drawn near an anchor land on such a pair only by luck.
func (m *tableMachine) RuleSetHostRoutesSideBySide(tc hegel.TestCase) {
	ops := hegel.Draw(tc, hegel.Composite(func(tc hegel.TestCase) []tableOp {
		d := m.drawer(tc)
		address := d.pick(d.pool.dsts).Addr()
		width := address.BitLen()
		beside := netip.PrefixFrom(address, width-1)
		if hegel.Draw(tc, hegel.Booleans()) {
			raw := address.AsSlice()
			raw[len(raw)-1] ^= 1
			sibling, _ := netip.AddrFromSlice(raw)
			beside = netip.PrefixFrom(sibling, width)
		}
		return []tableOp{
			{kind: opSet, src: d.src(), dst: netip.PrefixFrom(address, width), value: d.value()},
			{kind: opSet, src: d.src(), dst: beside, value: d.value()},
		}
	}))
	for _, op := range ops {
		m.set(op)
	}
}

func (m *tableMachine) RuleRemove(tc hegel.TestCase) {
	op := m.op(tc, func(d opDrawer) tableOp { return tableOp{kind: opRemove, src: d.src(), dst: d.dst()} })
	m.table.Remove(op.src, op.dst)
	m.model.remove(op.src, op.dst)
}

func (m *tableMachine) RuleRemoveValue(tc hegel.TestCase) {
	op := m.op(tc, func(d opDrawer) tableOp { return tableOp{kind: opRemoveValue, value: d.value()} })
	m.table.RemoveValue(op.value)
	m.model.removeValue(op.value)
}

func (m *tableMachine) RuleLookup(tc hegel.TestCase) {
	op := m.op(tc, func(d opDrawer) tableOp {
		return tableOp{kind: opLookup, from: d.zoned(d.address(d.pool.srcs)), to: d.zoned(d.address(d.pool.dsts))}
	})
	got, ok := m.table.Lookup(op.from, op.to)
	want, wantOK := m.model.lookup(op.from, op.to)
	if got != want || ok != wantOK {
		tc.Errorf("%#v answered %d, %v where the reference answers %d, %v", op, got, ok, want, wantOK)
	}
}

// RuleWalk takes a walk of the table without running it, to be held later to
// the routes the table had at this step.
func (m *tableMachine) RuleWalk(_ hegel.TestCase) {
	m.snapshots = append(m.snapshots, snapshot{
		taken: len(m.snapshots), routes: m.table.All(), want: slices.Clone(m.model.routes),
	})
}

func (m *tableMachine) InvariantWalkHoldsReferenceRoutes(tc hegel.TestCase) {
	sameRoutes(tc, "now", m.table.All(), m.model.routes)
}

// InvariantEveryRouteAnswersLikeReference looks up a packet at each end of
// every route held and just past it: from the first and the last address of
// its source, and the first of the prefix beside it, to the same three of its
// destination, and from and to the first address of an IPv6 prefix again with
// a zone. Those land where the routes nest and where a prefix test one bit
// short would still answer, which is where the order sources are tried in
// and the lengths compared decide the answer, and drawn addresses rarely do.
func (m *tableMachine) InvariantEveryRouteAnswersLikeReference(tc hegel.TestCase) {
	ends := func(p netip.Prefix) []netip.Addr {
		if !p.IsValid() {
			return []netip.Addr{{}}
		}
		last := p.Addr().AsSlice()
		for bit := p.Bits(); bit < len(last)*8; bit++ {
			last[bit/8] |= byte(0x80) >> (bit % 8)
		}
		end, _ := netip.AddrFromSlice(last)
		out := []netip.Addr{p.Addr(), end}
		if bit := p.Bits() - 1; bit >= 0 {
			beside := p.Addr().AsSlice()
			beside[bit/8] ^= byte(0x80) >> (bit % 8)
			next, _ := netip.AddrFromSlice(beside)
			out = append(out, next)
		}
		return out
	}
	for _, route := range m.model.routes {
		froms := ends(route.Source)
		if route.Source.Addr().Is6() {
			froms = append(froms, route.Source.Addr().WithZone("eth0"))
		}
		tos := ends(route.Destination)
		if route.Destination.Addr().Is6() {
			tos = append(tos, route.Destination.Addr().WithZone("eth0"))
		}
		for _, from := range froms {
			for _, to := range tos {
				got, ok := m.table.Lookup(from, to)
				want, wantOK := m.model.lookup(from, to)
				if got != want || ok != wantOK {
					tc.Errorf("Lookup(%v, %v) answered %d, %v where the reference answers %d, %v",
						from, to, got, ok, want, wantOK)
				}
			}
		}
	}
}

func (m *tableMachine) InvariantEarlierWalksHoldTheirOwnRoutes(tc hegel.TestCase) {
	for _, s := range m.snapshots {
		sameRoutes(tc, fmt.Sprintf("in walk %d", s.taken), s.routes, s.want)
	}
}

// sameRoutes reports where a walk of the table and the reference list hold
// different routes, as sets, since the order is the trie's own.
func sameRoutes(tc hegel.TestCase, when string, got iter.Seq[Route[int]], want []Route[int]) {
	type entry struct{ src, dst netip.Prefix }
	held := make(map[entry]int, len(want))
	for route := range got {
		key := entry{route.Source, route.Destination}
		if _, twice := held[key]; twice {
			tc.Errorf("%s the table walks %v from %v twice", when, route.Destination, route.Source)
		}
		held[key] = route.Value
	}
	for _, route := range want {
		value, ok := held[entry{route.Source, route.Destination}]
		if !ok || value != route.Value {
			tc.Errorf("%s the table holds %v from %v as %d, %v where the reference holds %d",
				when, route.Destination, route.Source, value, ok, route.Value)
		}
	}
	if len(held) != len(want) {
		tc.Errorf("%s the table walks %d routes where the reference holds %d: %v", when, len(held), len(want), held)
	}
}

// Any sequence of writes leaves the table answering every lookup the way the
// plain list does: the longest destination holding a route whose source
// matches, then the longest such source, with IPv4 and IPv6 apart. Every
// packet a node forwards is classified by this answer, so a trie that drifts
// from it after some order of edits sends that traffic to the wrong peer with
// nothing to show for it. The walk holds the same routes after every step,
// and a walk taken earlier still holds the routes of its own moment however
// the table has changed since, as the copy on write promises All's callers.
func TestTableAgreesWithReferenceModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// An IPv6 anchor is sometimes an IPv4 one in its mapped form, so the
		// two families hold routes for what is the same address on the wire
		// and a lookup in one must still never reach the other.
		anchors4 := hegel.Draw(ht, hegel.Lists(hegel.IPAddresses().IPv4()).MinSize(1).MaxSize(3))
		anchors6 := hegel.Draw(ht, hegel.Lists(hegel.OneOf(
			hegel.Generator[netip.Addr](hegel.IPAddresses().IPv6()),
			hegel.Map(hegel.SampledFrom(anchors4), func(anchor netip.Addr) netip.Addr {
				return netip.AddrFrom16(anchor.As16())
			}),
		)).MinSize(1).MaxSize(3))
		machine := &tableMachine{pools: [2]prefixPool{drawPrefixPool(ht, anchors4), drawPrefixPool(ht, anchors6)}}
		hegel.RunStateful(ht, machine, hegel.WithAlwaysCheckInvariants(
			"InvariantWalkHoldsReferenceRoutes", "InvariantEveryRouteAnswersLikeReference"))
	})
}
