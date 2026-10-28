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
// inside a carve-out, masked, sorted and each once: learned, held and this
// node's own alike, since a neighbor on the carved link holds none of them, and
// a source-specific entry by its destination whole
func CarvedPrefixes(carveOuts []egress.CarveOut, snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	carved := make([]netip.Prefix, 0, len(carveOuts))
	for _, c := range carveOuts {
		carved = append(carved, c.Prefix)
	}
	return carvedOf(carved, tableDestinations(snapshot))
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
