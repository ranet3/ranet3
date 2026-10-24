// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"fmt"
	"net/netip"
)

// MatchedRoute is the route the kernel's own lookup takes for one packet.
// Source is invalid for a route that selects no source. Table is 0 on darwin,
// which has one table
type MatchedRoute struct {
	Prefix   netip.Prefix
	Source   netip.Prefix
	Table    uint32
	Type     string
	NextHops []NextHop
}

// NextHop is one way a matched route leaves, Gateway invalid where it leaves
// through a link. Dead and LinkDown are the kernel's RTNH_F_DEAD and
// RTNH_F_LINKDOWN marks, which darwin's answer does not carry
type NextHop struct {
	Device   string
	Gateway  netip.Addr
	Dead     bool
	LinkDown bool
}

// RouteGet asks the kernel which route it takes for a packet from src to dst.
// An empty iif is this host's own packet, and a device name is the input
// lookup a packet arriving there takes. An invalid src sends none. An invalid
// or zoned dst and a src of the other family are refused on every platform.
// Where the kernel routes no such packet its errno is the error, and a dst
// with no route answers an error matching ENETUNREACH on linux and darwin
// alike, on darwin in place of ErrNoDefaultRoute. On linux, without an
// arrival device the source must be this host's, and IPv4 answers ENETUNREACH
// for a source it does not hold. An IPv4 input lookup with forwarding off
// answers EHOSTUNREACH, where IPv6 answers its route and drops the packet
// later. Reverse path filtering answers EXDEV before Linux 6.13 and EINVAL
// from 6.13 on, the errno a martian source and a blackhole route answer too
func RouteGet(src, dst netip.Addr, iif string) (MatchedRoute, error) {
	if err := refuseRouteLookup(src, dst); err != nil {
		return MatchedRoute{}, err
	}
	return routeGet(src, dst, iif)
}

// refuseRouteLookup refuses a pair no platform looks up, before any is asked
func refuseRouteLookup(src, dst netip.Addr) error {
	switch {
	case !dst.IsValid():
		return fmt.Errorf("kernel: no route lookup to an invalid destination")
	case dst.Zone() != "":
		return fmt.Errorf("kernel: no route lookup to %s, whose zone the lookup does not take", dst)
	case src.IsValid() && src.Is4() != dst.Is4():
		return fmt.Errorf("kernel: no route lookup from %s to %s, which are not of one family", src, dst)
	}
	return nil
}
