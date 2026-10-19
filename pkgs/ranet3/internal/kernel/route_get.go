// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import "net/netip"

// MatchedRoute is the route the kernel's own lookup takes for one packet.
// Source is invalid for a route that selects no source. Table is 0 on darwin,
// which has one table.
type MatchedRoute struct {
	Prefix   netip.Prefix
	Source   netip.Prefix
	Table    uint32
	Type     string
	NextHops []NextHop
}

// NextHop is one way a matched route leaves, Gateway invalid where it leaves
// through a link.
// Dead and LinkDown are the kernel's RTNH_F_DEAD and RTNH_F_LINKDOWN marks,
// which darwin's answer does not carry
type NextHop struct {
	Device   string
	Gateway  netip.Addr
	Dead     bool
	LinkDown bool
}
