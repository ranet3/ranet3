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
	// Exception is an IPv6 lookup answered through a route the kernel cached
	// for the destination alone under Prefix's, a path MTU's or a redirect's,
	// which it returns as a /128 (ip6_rt_cache_alloc). RouteGet reads it on
	// linux alone, by a second lookup after the one that answers the route, so
	// an exception made or expired between the two goes unseen by one or the
	// other. RouteGetBatch never reads it.
	Exception bool
	// NoEntry is a route the kernel makes for the destination itself with no
	// table entry behind it, such as for a multicast group, the limited
	// broadcast or the unspecified address, which no rule's lookup found. Its
	// Table is 0 and its Source invalid. RouteGet answers it for IPv4 on linux
	// alone, by a second lookup without RTM_F_FIB_MATCH where the first
	// answers EHOSTUNREACH (inet_rtm_getroute), and keeps that EHOSTUNREACH
	// where the second refuses the packet too, so a table changed between the
	// two goes unseen by one or the other. RouteGetBatch never asks it.
	NoEntry bool
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

// RouteGetTakesSource is whether RouteGet's lookup takes the src it is given,
// as linux's does and XNU's does not
const RouteGetTakesSource = routeGetTakesSource

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
