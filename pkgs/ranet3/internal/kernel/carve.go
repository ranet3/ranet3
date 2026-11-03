// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// CarveOuts is each nonempty intersection of a network a link outside the mesh
// is on, or a point-to-point far end it reaches, with a prefix of the overlay:
// the network where the overlay prefix holds it, and the overlay prefix where
// the network holds it. A PPPoE uplink's gateway inside the overlay is carved
// as a lease inside it is. lo is never carved, since nothing off the host reaches
// the host through it. Sorted by link and then by prefix, each once.
func CarveOuts(network NetworkState, overlay []schema.Prefix) []egress.CarveOut {
	var out []egress.CarveOut
	for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
		if link.Name == loopback {
			continue
		}
		for _, address := range slices.Concat(link.Prefixes, link.Peers) {
			network, ok := canonicalPrefix(address)
			if !ok {
				continue
			}
			for _, entry := range overlay {
				prefix, ok := canonicalPrefix(entry.Prefix)
				if !ok || !prefix.Overlaps(network) {
					continue
				}
				// two prefixes that overlap are nested, so the longer is their intersection
				if network.Bits() > prefix.Bits() {
					prefix = network
				}
				out = append(out, egress.CarveOut{Link: link.Name, Prefix: prefix})
			}
		}
	}
	slices.SortFunc(out, compareCarveOuts)
	return slices.Compact(out)
}

func compareCarveOuts(a, b egress.CarveOut) int {
	return cmp.Or(cmp.Compare(a.Link, b.Link), comparePrefixes(a.Prefix, b.Prefix))
}

// CarvedPrefixes is the destination of each entry of the mesh's table that lies
// inside a prefix of carved, masked, sorted and each once: learned, held and
// this node's own alike, and a source-specific entry by its destination whole
func CarvedPrefixes(carved []netip.Prefix, snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	return carvedOf(carved, tableDestinations(snapshot))
}

// CarvedSets is the carved sets of one pass, with the conflicts of the
// exemptions
func CarvedSets(border *egress.Border, carveOuts []egress.CarveOut, snapshot []sadr.Route[*netstack.Peer]) ([]egress.Range, []egress.ExemptConflict) {
	exemptions := border.Exemptions()
	exempt, conflicts := ExemptCarved(exemptions, border.Own, border.Addresses, snapshot, border.Overlay)
	return egress.Union(append(carveOutCarved(carveOuts, exemptions, border.Own, snapshot), exempt...)), conflicts
}

// carveOutCarved gives the ranges the carved sets hold of the carve-outs:
// CarvedPrefixes of their prefixes, but of own only what some carve-out keeps,
// an address it holds that no exemption naming its link holds. The carved drop
// matches on every link, so an address of own leaves the sets only where each
// carve-out holding it is on a link an exemption holding it names, which then
// admits it as this node's own.
func carveOutCarved(carveOuts []egress.CarveOut, exemptions []egress.Exemption, own []netip.Prefix, snapshot []sadr.Route[*netstack.Peer]) []egress.Range {
	prefixes := make([]netip.Prefix, 0, len(carveOuts))
	var kept []egress.Range
	for _, carveOut := range carveOuts {
		prefixes = append(prefixes, carveOut.Prefix)
		var named []netip.Prefix
		for _, exemption := range exemptions {
			if exemption.Names(carveOut.Link) {
				named = append(named, exemption.Prefix)
			}
		}
		kept = append(kept, subtract(Ranges([]netip.Prefix{carveOut.Prefix}), Ranges(named))...)
	}
	carved := Ranges(CarvedPrefixes(prefixes, snapshot))
	return egress.Union(append(subtract(carved, Ranges(own)), intersect(carved, egress.Union(kept))...))
}

// carvedOf is each prefix of table inside a prefix of carved, sorted and each
// once
func carvedOf(carved, table []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, destination := range table {
		if slices.ContainsFunc(carved, func(carveOut netip.Prefix) bool { return encloses(carveOut, destination) }) {
			out = append(out, destination)
		}
	}
	slices.SortFunc(out, comparePrefixes)
	return slices.Compact(out)
}

// ExemptCarved gives the ranges the carved sets hold of the exemptions, and each
// conflict with another node's prefix. A prefix inside the overlay the mesh's
// table routes via a peer is another node's: of each exemption it overlaps,
// inside it or covering it, it carves their intersection, less each range of
// own inside the prefix, which this node's longer route takes. A range this
// node announces is its own, even where another node announces it too, and is
// carved for none. Each of addresses, this node's own, inside an exemption is
// carved. A default route, a prefix wider than the overlay and a prefix held
// unreachable carve nothing.
func ExemptCarved(exemptions []egress.Exemption, own, addresses []netip.Prefix, snapshot []sadr.Route[*netstack.Peer], overlay []schema.Prefix) ([]egress.Range, []egress.ExemptConflict) {
	var carved []egress.Range
	var conflicts []egress.ExemptConflict
	for _, entry := range snapshot {
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok || entry.Value == nil || entry.Value == netstack.Local || entry.Value == netstack.Assigned || entry.Value == netstack.Unreachable || !schema.InsideOverlay(destination, overlay) {
			continue
		}
		var longer []netip.Prefix
		for _, prefix := range own {
			if encloses(destination, prefix) {
				longer = append(longer, prefix)
			}
		}
		for _, exemption := range exemptions {
			if !exemption.Prefix.Overlaps(destination) {
				continue
			}
			// two prefixes that overlap are nested, so the longer is their intersection
			both := destination
			if exemption.Prefix.Bits() > both.Bits() {
				both = exemption.Prefix.Masked()
			}
			taken := subtract(Ranges([]netip.Prefix{both}), Ranges(longer))
			if len(taken) == 0 {
				continue
			}
			carved = append(carved, taken...)
			conflicts = append(conflicts, egress.ExemptConflict{Exemption: exemption, Prefix: destination, Carved: both, Via: entry.Value.ID})
		}
	}
	for _, address := range addresses {
		if slices.ContainsFunc(exemptions, func(exemption egress.Exemption) bool { return encloses(exemption.Prefix.Masked(), address) }) {
			carved = append(carved, Ranges([]netip.Prefix{address})...)
		}
	}
	slices.SortFunc(conflicts, compareConflicts)
	return egress.Union(carved), slices.Compact(conflicts)
}

// OwnCopies is the conflict of each exemption with a range of own, the ranges
// this node announces, that another router announces too, under the router-id
// origin reads for it. Such a conflict carves nothing, so the carved sets keep
// of the range what CarvedSets gives them.
func OwnCopies(exemptions []egress.Exemption, own []netip.Prefix, origin func(netip.Prefix) (string, bool)) []egress.ExemptConflict {
	var conflicts []egress.ExemptConflict
	for _, prefix := range own {
		routerID, ok := origin(prefix)
		if !ok {
			continue
		}
		for _, exemption := range exemptions {
			if exemption.Prefix.Overlaps(prefix) {
				conflicts = append(conflicts, egress.ExemptConflict{Exemption: exemption, Prefix: prefix, RouterID: routerID, Own: true})
			}
		}
	}
	slices.SortFunc(conflicts, compareConflicts)
	return slices.Compact(conflicts)
}

func compareConflicts(a, b egress.ExemptConflict) int {
	return cmp.Or(cmp.Compare(a.Exemption.Interface, b.Exemption.Interface), comparePrefixes(a.Exemption.Prefix, b.Exemption.Prefix),
		comparePrefixes(a.Prefix, b.Prefix), cmp.Compare(a.Via, b.Via))
}

// tableDestinations is the destination of each entry of the mesh's table,
// masked, leaving out one that is not a prefix
func tableDestinations(snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(snapshot))
	for _, entry := range snapshot {
		if destination, ok := canonicalPrefix(entry.Destination); ok {
			out = append(out, destination)
		}
	}
	return out
}

// carvedLAN is the carve-outs less the mesh's prefixes inside them, as the
// fewest prefixes: the addresses of an overlapping lease that the link's own
// neighbors hold, its gateway and resolver among them
func (v exitView) carvedLAN() []netip.Prefix {
	return rangePrefixes(subtract(Ranges(v.carved), Ranges(carvedOf(v.carved, v.table)))...)
}

// passNetwork is the host's network as one pass reads it, and the prefixes of
// the carve-outs it gives, so the routes and the rules of the pass derive
// from one reading
type passNetwork struct {
	network NetworkState
	carved  []netip.Prefix
}

// readNetwork reads the host's network for one pass
func (r *Reconciler) readNetwork() passNetwork {
	var out passNetwork
	if r.rt.Network != nil {
		out.network = r.rt.Network()
	}
	for _, carveOut := range CarveOuts(out.network, r.rt.Overlay) {
		out.carved = append(out.carved, carveOut.Prefix)
	}
	return out
}

// encloses reports each address of inner lying in outer, both masked
func encloses(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
