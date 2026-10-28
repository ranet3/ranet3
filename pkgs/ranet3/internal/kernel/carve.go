// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"cmp"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// CarveOut is the part of the overlay a link outside the mesh is on, where the
// link's own neighbors hold overlay addresses no node announces
type CarveOut struct {
	Link   string
	Prefix netip.Prefix
}

// CarveOuts is each nonempty intersection of a network a link outside the mesh
// is on with a prefix of the overlay: the network where the overlay prefix holds
// it, and the overlay prefix where the network holds it. lo is never carved,
// since nothing off the host reaches the host through it. Sorted by link and
// then by prefix, each once.
func CarveOuts(network NetworkState, overlay []schema.Prefix) []CarveOut {
	var out []CarveOut
	for _, link := range slices.Concat(network.IPv4.Links, network.IPv6.Links) {
		if link.Name == loopback {
			continue
		}
		for _, address := range link.Prefixes {
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
				out = append(out, CarveOut{Link: link.Name, Prefix: prefix})
			}
		}
	}
	slices.SortFunc(out, compareCarveOuts)
	return slices.Compact(out)
}

func compareCarveOuts(a, b CarveOut) int {
	return cmp.Or(cmp.Compare(a.Link, b.Link), comparePrefixes(a.Prefix, b.Prefix))
}

// CarvedPrefixes is the destination of each entry of the mesh's table that lies
// inside a carve-out, masked, sorted and each once: learned, held and this
// node's own alike, since a neighbor on the carved link holds none of them, and
// a source-specific entry by its destination whole
func CarvedPrefixes(carveOuts []CarveOut, snapshot []sadr.Route[*netstack.Peer]) []netip.Prefix {
	var out []netip.Prefix
	for _, entry := range snapshot {
		destination, ok := canonicalPrefix(entry.Destination)
		if !ok {
			continue
		}
		if slices.ContainsFunc(carveOuts, func(c CarveOut) bool { return encloses(c.Prefix, destination) }) {
			out = append(out, destination)
		}
	}
	slices.SortFunc(out, comparePrefixes)
	return slices.Compact(out)
}

// encloses reports each address of inner lying in outer, both masked
func encloses(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}
