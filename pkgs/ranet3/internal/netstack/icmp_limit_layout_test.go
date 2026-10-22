// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import "net/netip"

// refillCap and holdsSource are the bench's reach into the limit's layout, so a tree of another layout runs the bench files beside its own versions of them

// refillCap leaves the node's cap of m full, as a new limit's is
func refillCap(m *Mesh) {
	m.icmpLimit.node.full.Store(0)
	m.icmpLimit.node.last.Store(0)
}

// holdsSource reports whether the limit of m holds a bucket for source
func holdsSource(m *Mesh, source netip.Addr) bool {
	return m.icmpLimit.shard(source).sources[source] != nil
}
