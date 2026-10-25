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
func derivedRules(id schema.TableID, overlay []schema.Prefix, own []netip.Prefix) []Rule {
	var out []Rule
	for _, family := range []Family{FamilyIPv4, FamilyIPv6} {
		floor := schema.MinSubnetBits4
		if family == FamilyIPv6 {
			floor = schema.MinSubnetBits6
		}
		out = append(out,
			Rule{Family: family, Priority: priorityOverlayEnd, action: ActionNop},
			Rule{Family: family, Priority: priorityMeshEnd, action: ActionNop},
			Rule{Family: family, Priority: priorityUnderlayPastOverlay, FWMark: schema.UnderlayMark, action: ActionGoto, target: priorityOverlayEnd},
		)
		for _, prefix := range familyPrefixes(family, schemaPrefixes(overlay)) {
			out = append(out, Rule{Family: family, Priority: priorityOverlay, To: schema.PrefixFrom(prefix), Table: id})
		}
		out = append(out,
			Rule{Family: family, Priority: priorityUnderlayPastMesh, FWMark: schema.UnderlayMark, action: ActionGoto, target: priorityMeshEnd},
			Rule{Family: family, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)},
			Rule{Family: family, Priority: priorityMesh, Table: id, suppress: SuppressUpTo(floor - 1)},
		)
		for _, prefix := range familyPrefixes(family, own) {
			out = append(out, Rule{Family: family, Priority: priorityOwn, From: schema.PrefixFrom(prefix), Table: id})
		}
	}
	return out
}

func schemaPrefixes(prefixes []schema.Prefix) []netip.Prefix {
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

// ownPrefixes is this node's own prefixes as the snapshot holds them: every
// address cap.table assigns, and every prefix this node originates that counts
// as no default, but for a prefix the mesh cannot carry, which unroutable
// names, for a LAN cap.egress advertises, whose hosts are no sources of this
// node's own, and for a source-specific announcement D from S,
// which under RFC 9079 section 4's destination-first lookup routes D to this
// node only for packets from S, so a reply to D from outside S never comes
// back through the mesh.
func (r *Reconciler) ownPrefixes(snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range snapshot {
		prefix, ok := canonicalPrefix(entry.Destination)
		switch {
		case !ok || unroutable(prefix) != "":
		case entry.Value == netstack.Assigned:
			out = append(out, prefix)
		case entry.Value == netstack.Local && !entry.Source.IsValid() && !r.captures(Route{Destination: prefix}) && !slices.Contains(r.rt.Advertised, prefix):
			out = append(out, prefix)
		}
	}
	return out
}
