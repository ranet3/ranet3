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
// Neither 5405 nor 5435 selects a source overlapping the overlay or this
// node's own prefixes: 5405 comes ahead of 5430, so an overlay address on lo,
// or an address in a LAN this node announces, would otherwise leave by main
// where mode off sends it into the mesh. A selector overlapping either is left
// out whole.
//
// Under fallback = "none" (exit.fallback) mode 2 adds two more to both
// families, so a family the tun holds no overlay address of runs mode off's
// rules and these two:
//   - 5445 looks main up to each of this node's own prefixes the mesh's table
//     throws, which its lookups pass on, so the host reaches its own prefix
//     beyond the gateway
//   - 5450 fails as unreachable every lookup of the host's own traffic and of
//     what it forwards from each link forward expands to that no rule above
//     answered, so a connect meets ENETUNREACH at once while the mesh holds no
//     default, where the filter's drop alone would leave it waiting
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
		for _, prefix := range familyPrefixes(family, schemaPrefixes(overlay)) {
			out = append(out, Rule{Family: family, Priority: priorityOverlay, To: schema.PrefixFrom(prefix), Table: id})
		}
		out = append(out, Rule{Family: family, Priority: priorityUnderlayPastMesh, FWMark: schema.UnderlayMark, action: actionGoto, target: priorityMeshEnd})
		addresses, networks := exit.sources(family, schemaPrefixes(overlay), own)
		for _, address := range addresses {
			out = append(out, Rule{Family: family, Priority: priorityUplinkSource, From: schema.PrefixFrom(address), IIF: loopback, Table: schema.TableMain})
		}
		out = append(out,
			Rule{Family: family, Priority: priorityMain, Table: schema.TableMain, suppress: SuppressUpTo(0)},
			Rule{Family: family, Priority: priorityMesh, Table: id, suppress: SuppressUpTo(floor - 1)},
		)
		for _, prefix := range familyPrefixes(family, own) {
			out = append(out, Rule{Family: family, Priority: priorityOwn, From: schema.PrefixFrom(prefix), Table: id})
		}
		if !exit.on {
			continue
		}
		if !slices.Contains(exit.unaddressed, family) {
			for _, network := range networks {
				out = append(out, Rule{Family: family, Priority: priorityLinkSource, From: schema.PrefixFrom(network), IIF: loopback, Table: schema.TableMain})
			}
			out = append(out, Rule{Family: family, Priority: priorityCatchAll, IIF: loopback, Table: id})
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
		out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: loopback, action: actionUnreachable})
		for _, link := range exit.forwarded {
			out = append(out, Rule{Family: family, Priority: priorityRefused, IIF: link, action: actionUnreachable})
		}
	}
	return out
}

// exitView is mode 2 as a pass derives its rules: the host's links outside the
// mesh as the network watch reads them, the names forward expands to among them
// (see expandForward), and each family the tun holds no overlay address of. The
// zero value is mode off, whatever it holds beside. fallback is cap.exit
// fallback = "none", and own is this node's own prefixes the mesh's table
// throws, which a pass reads only under it.
type exitView struct {
	on          bool
	network     NetworkState
	forwarded   []string
	unaddressed []Family
	fallback    bool
	own         []netip.Prefix
}

// thrown is the destination of each throw the mirror installs for this
// snapshot that holds no source, each of this node's own prefixes outside the
// overlay that counts as no default. A source-specific one is left out, so a
// lookup from its source the mesh's table passes on meets 5450.
func (r *Reconciler) thrown(snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	var out []netip.Prefix
	for _, route := range r.desired(snapshot) {
		if route.Throw && !route.Source.IsValid() {
			out = append(out, route.Destination)
		}
	}
	return out
}

// sources is the selectors of one family's 5405 and 5435: each address of a
// link outside the mesh as a host prefix, and each connected network shorter
// than a host prefix and each point-to-point far end outside those networks of
// a link forward leaves out, masked, each sorted and once. Mode off and a
// family the tun holds no overlay address of have none.
func (v exitView) sources(family Family, overlay, own []netip.Prefix) (addresses, networks []netip.Prefix) {
	if !v.on || slices.Contains(v.unaddressed, family) {
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
				return prefix.Bits() < prefix.Addr().BitLen() && prefix.Bits() <= peer.Bits() && prefix.Contains(peer.Addr())
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
	taken := func(prefix netip.Prefix) bool {
		return slices.ContainsFunc(overlay, prefix.Overlaps) ||
			// 5430 sends this node's own sources into the mesh in every mode
			slices.ContainsFunc(own, prefix.Overlaps)
	}
	return slices.DeleteFunc(familyPrefixes(family, addresses), taken), slices.DeleteFunc(familyPrefixes(family, networks), taken)
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
