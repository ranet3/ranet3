// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// RouteGet asks the kernel which route it takes to dst, with the RTM_GET that
// `route -n get` sends. XNU's lookup takes neither a source nor an input
// device, so src does not enter it and a packet arriving on iif is refused
// rather than answered as this host's own.
func RouteGet(src, dst netip.Addr, iif string) (MatchedRoute, error) {
	if iif != "" {
		return MatchedRoute{}, fmt.Errorf("kernel: darwin looks up the route of this host's own packet only, not of one arriving on %s", iif)
	}
	answer, err := routeRequest(dst, netip.Addr{})
	if err != nil {
		return MatchedRoute{}, err
	}
	return decodeRouteAnswer(answer, runningKernel{}.InterfaceName)
}

func decodeRouteAnswer(answer *route.RouteMessage, name func(int) (string, error)) (MatchedRoute, error) {
	prefix, ok := dumpedPrefix(answer)
	if !ok {
		return MatchedRoute{}, errors.New("kernel: the route lookup's answer names no destination")
	}
	matched := MatchedRoute{Prefix: prefix, Type: "unicast"}
	switch {
	case answer.Flags&unix.RTF_REJECT != 0:
		matched.Type = "unreachable"
	case answer.Flags&unix.RTF_BLACKHOLE != 0:
		matched.Type = "blackhole"
	}
	if answer.Index == 0 {
		return matched, nil
	}
	device, err := name(answer.Index)
	if err != nil {
		return MatchedRoute{}, err
	}
	hop := NextHop{Device: device}
	// the gateway field names a next hop only under RTF_GATEWAY
	if answer.Flags&unix.RTF_GATEWAY != 0 {
		if gateway, ok := addressFromRouteAddr(answer.Addrs[unix.RTAX_GATEWAY]); ok {
			hop.Gateway = gateway.WithZone("")
		}
	}
	matched.NextHops = []NextHop{hop}
	return matched, nil
}
