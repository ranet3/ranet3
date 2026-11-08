// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// derivedRules is the policy rules routing.md's "Policy rules on Linux" lists,
// for the mesh's table id, the overlay and this node's own prefixes, in both
// families. Each nop comes ahead of the goto that lands on it, so a pass adding
// them in this order holds a goto with nothing to land on only where the add of
// its nop failed. The kernel passes such a goto over, as it would a missing
// one, so the underlay's marked packets meet the block's lookups until a later
// pass adds the nop.
//
// 5420 suppresses a route as long as the family's floor less one or shorter,
// the length of a route that counts as a default by its length, but never an
// unreachable, blackhole or prohibit one.
// routing.md's "Where a lookup ends on Linux" gives where each lookup ends.
//
// Mode 2 (exit.on) adds 5405, 5435 and 5440 to each family the tun holds an
// overlay address of, and a family it holds none of runs mode off's rules.
// Mode 3 sets exit.on too, so every rule this comment gives for mode 2 holds
// for it.
// Neither 5405 nor 5435 selects a source overlapping the overlay or this
// node's own prefixes: 5405 comes ahead of 5430, so an overlay address on lo,
// or an address in a LAN this node announces, would otherwise leave by main
// where mode off sends it into the mesh. A selector overlapping either is left
// out whole. One that a carve-out holds whole and no entry of the mesh's table
// inside that carve-out holds is not left out for the overlay, since the link's
// neighbors hold its addresses.
//
// Under fallback = "none" (exit.fallback) mode 2 adds two more to both
// families, so a family the tun holds no overlay address of runs mode off's
// rules and these two:
//   - 5445 looks main up to each of this node's own prefixes and each
//     carve-out the mesh's table throws, which its lookups pass on, so the host
//     reaches its own prefix beyond the gateway and a carved link's neighbors
//   - 5450 fails as unreachable every unmarked lookup of the host's own
//     traffic and of what it forwards from each link forward expands to that
//     no rule above answered, so a connect meets ENETUNREACH at once while
//     the mesh holds no default, where the filter's drop alone would leave it
//     waiting
//
// While the table ranet3_fallback does not hold (exit.unheld) it leaves 5405
// and 5435 out, so the host's own unmarked lookups from the uplink's addresses
// and networks meet 5440, 5445 and 5450 rather than main, but for a route of
// main longer than /0, which 5410 still takes.
func derivedRules(id schema.TableID, overlay []schema.Prefix, own []netip.Prefix, exit exitView) []Rule {
	var out []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		floor := schema.MinSubnetBits4
		if family == FamilyIPv6 {
			floor = schema.MinSubnetBits6
		}
		out = append(out,
			Rule{Family: family, Priority: priorityOverlayEnd, action: actionNop},
			Rule{Family: family, Priority: priorityMeshEnd, action: actionNop},
			Rule{Family: family, Priority: priorityUnderlayPastOverlay, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityOverlayEnd},
		)
		for _, prefix := range familyPrefixes(family, SchemaPrefixes(overlay)) {
			out = append(out, Rule{Family: family, Priority: priorityOverlay, To: schema.PrefixFrom(prefix), Table: id})
		}
		out = append(out, Rule{Family: family, Priority: priorityUnderlayPastMesh, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityMeshEnd})
		addresses, networks := exit.sources(family, SchemaPrefixes(overlay), own)
		for _, address := range addresses {
			out = append(out, Rule{Family: family, Priority: priorityUplinkSource, From: schema.PrefixFrom(address), IIF: linuxLoopback, Table: schema.TableMain})
		}
		out = append(out,
			Rule{Family: family, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)},
			Rule{Family: family, Priority: priorityMesh, Table: id, suppress: SuppressUpTo(floor - 1)},
		)
		for _, prefix := range outermost(familyPrefixes(family, own)) {
			out = append(out, Rule{Family: family, Priority: priorityOwn, From: schema.PrefixFrom(prefix), Table: id})
		}
		if !exit.on {
			continue
		}
		if !slices.Contains(exit.unaddressed, family) {
			for _, network := range networks {
				out = append(out, Rule{Family: family, Priority: priorityLinkSource, From: schema.PrefixFrom(network), IIF: linuxLoopback, Table: schema.TableMain})
			}
			out = append(out, Rule{Family: family, Priority: priorityCatchAll, IIF: linuxLoopback, Table: id})
			for _, link := range exit.forwarded {
				out = append(out, Rule{Family: family, Priority: priorityCatchAll, IIF: link, Table: id})
			}
		}
		if !exit.fallback {
			continue
		}
		for _, prefix := range familyPrefixes(family, exit.own) {
			out = append(out, Rule{Family: family, Priority: priorityOwnPastMesh, To: schema.PrefixFrom(prefix), Table: schema.TableMain})
		}
		out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: linuxLoopback, action: actionUnreachable})
		for _, link := range exit.forwarded {
			out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: link, action: actionUnreachable})
		}
	}
	return out
}

// exitView is mode 2 or 3 as a pass derives its rules: the host's links
// outside the mesh as the network watch reads them, the names forward expands
// to among them (see expandForward), the carve-outs of those links, the
// destinations of the mesh's table, and each family the tun holds no overlay
// address of. The zero value is mode off, whatever it holds beside. fallback
// is cap.exit fallback = "none", written or unwritten in mode 3, own is the
// prefixes the mesh's table throws (see thrown), which a pass reads only under
// it, lan is the prefixes cap.exit lan lists, and unheld is the kill switch
// not holding, which a pass reads only under fallback.
type exitView struct {
	on          bool
	network     NetworkState
	forwarded   []string
	carved      []netip.Prefix
	table       []netip.Prefix
	unaddressed []Family
	fallback    bool
	own         []netip.Prefix
	lan         []netip.Prefix
	unheld      bool
}

// thrown is the destination of each throw of the mirror's desired routes that
// holds no source, each of this node's own prefixes outside the overlay that
// counts as no default and each carve-out whose own prefix the mesh's table
// does not hold for every source. A source-specific one is left out,
// so the host's own unmarked lookup from its source the mesh's table passes on
// meets 5450.
func thrown(desired []Route) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range desired {
		if route.Throw && !route.Source.IsValid() {
			out = append(out, route.Destination)
		}
	}
	return out
}

// sources is the selectors of one family's 5405 and 5435: each address of a
// link outside the mesh as a host prefix, and each connected network shorter
// than a host prefix and each point-to-point far end outside those networks of
// a link forward leaves out, masked, each sorted and once, none refused. Mode
// off, a family the tun holds no overlay address of and fallback = "none"
// while its table does not hold have none.
func (v exitView) sources(family Family, overlay, own []netip.Prefix) (addresses, networks []netip.Prefix) {
	if !v.on || slices.Contains(v.unaddressed, family) || v.fallback && v.unheld {
		return nil, nil
	}
	links := v.network.IPv4.Links
	if family == FamilyIPv6 {
		links = v.network.IPv6.Links
	}
	for _, link := range links {
		forwarded := slices.Contains(v.forwarded, link.Name)
		for _, peer := range link.Peers {
			// a far end inside a network of its own link takes that network's rule
			inside := slices.ContainsFunc(link.Prefixes, func(prefix netip.Prefix) bool {
				return prefix.Bits() < prefix.Addr().BitLen() && encloses(prefix, peer)
			})
			if !forwarded && !inside {
				networks = append(networks, peer)
			}
		}
		for _, prefix := range link.Prefixes {
			address := prefix.Addr()
			addresses = append(addresses, netip.PrefixFrom(address, address.BitLen()))
			// a host prefix's network is its address, which 5405 already selects
			if !forwarded && prefix.Bits() < address.BitLen() {
				networks = append(networks, prefix)
			}
		}
	}
	own = familyPrefixes(family, own)
	refused := func(selector netip.Prefix) bool { return v.refused(selector, overlay, own) }
	return slices.DeleteFunc(familyPrefixes(family, addresses), refused), slices.DeleteFunc(familyPrefixes(family, networks), refused)
}

// refused reports whether 5405 and 5435 leave a selector out: one overlapping
// the overlay, unless the link holds it, or one overlapping this node's own
// prefixes, whose sources 5430 sends into the mesh in every mode
func (v exitView) refused(selector netip.Prefix, overlay, own []netip.Prefix) bool {
	return slices.ContainsFunc(overlay, selector.Overlaps) && !v.linkHolds(selector) ||
		slices.ContainsFunc(own, selector.Overlaps)
}

// linkHolds reports whether a carve-out holds a selector whole and no entry of
// the mesh's table inside that carve-out does, since the link's neighbors hold
// such a carve-out's addresses and the mesh holds the rest. An entry wider than
// the carve-out, an exit's default among them, is the route the carve-out
// takes the link's addresses back from, so linkHolds passes over it.
func (v exitView) linkHolds(selector netip.Prefix) bool {
	return slices.ContainsFunc(v.carved, func(carve netip.Prefix) bool {
		return encloses(carve, selector) && !slices.ContainsFunc(v.table, func(entry netip.Prefix) bool { return encloses(carve, entry) && encloses(entry, selector) })
	})
}

// SchemaPrefixes is prefixes as netip holds them, in order
func SchemaPrefixes(prefixes []schema.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.Prefix)
	}
	return out
}

// familyPrefixes is the prefixes of one family longer than /0, masked, each
// once and in order, as a rule's selector reads back
func familyPrefixes(family Family, prefixes []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, prefix := range prefixes {
		if prefix, ok := canonicalPrefix(prefix); ok && prefix.Bits() > 0 && familyOf(prefix.Addr()) == family {
			out = append(out, prefix)
		}
	}
	slices.SortFunc(out, comparePrefixes)
	return slices.Compact(out)
}

// outermost is distinct prefixes less each one another of them holds, in order
// 5430's rules share a priority and a table, so a held prefix's rule selects no source its holder's does not
func outermost(prefixes []netip.Prefix) []netip.Prefix {
	return slices.DeleteFunc(slices.Clone(prefixes), func(inner netip.Prefix) bool {
		return slices.ContainsFunc(prefixes, func(outer netip.Prefix) bool { return outer != inner && encloses(outer, inner) })
	})
}

// ownPrefixes is this node's own prefixes as the snapshot holds them, the
// sources OwnedSources owns less three kinds: a prefix the mesh cannot carry,
// which a class schema.Unroutable names holds whole, a LAN cap.egress
// advertises, whose hosts are no sources of this node's own, and a
// source-specific announcement D from S, which under RFC 9079 section 4's
// destination-first lookup routes D to this node only for packets from S, so a
// reply to D from outside S never comes back through the mesh.
func (r *Reconciler) ownPrefixes(snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range ownedEntries(snapshot, r.rt.Overlay) {
		prefix := entry.Destination
		if _, whole := schema.Unroutable(prefix); !entry.Source.IsValid() && !whole && !slices.Contains(r.rt.Advertised, prefix) {
			out = append(out, prefix)
		}
	}
	return out
}
