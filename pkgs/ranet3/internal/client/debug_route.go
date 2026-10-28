// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/packet"
)

// DebugRoute follows a packet from src to dst to where this host sends it.
// One of this host's own, or arriving on the link iif, meets the kernel and,
// where its route enters the tun, the mesh's checks of a read, but for this
// host's own packet with no source and an arrival the kernel does not
// forward. One arriving through a session from the peer peer names meets the
// segment it is addressed to, or the mesh's decision and, where that delivers
// it, the kernel as a packet arriving on the tun, whose route ends the walk.
// The lookup and the rule dump go through sockets of their own, and the
// mesh's steps spend, count and write nothing.
func (c *Client) DebugRoute(src, dst netip.Addr, iif, peer string) (control.RouteInfo, error) {
	switch {
	case iif != "" && peer != "":
		return control.RouteInfo{}, fmt.Errorf("a packet arrives on the link %s or through a session from %s, not both", iif, peer)
	case peer != "":
		return c.routeFromSession(src, dst, peer)
	// dev_valid_name's refusals, since the name becomes a path under /proc/sys
	case iif == "." || iif == ".." || strings.ContainsAny(iif, "/: \t\n"):
		return control.RouteInfo{}, fmt.Errorf("%q names no link", iif)
	case iif != "" && iif == c.Mesh.Name:
		return control.RouteInfo{}, fmt.Errorf("debug route takes a link as --iif, and %s is the mesh's tun, which carries no arrival: a packet written into it is this host's own", iif)
	case iif != "" && !src.IsValid():
		return control.RouteInfo{}, fmt.Errorf("a packet arriving on %s carries a source", iif)
	}
	info := control.RouteInfo{Src: src, Dst: dst, IIF: iif, Arrival: control.ArrivalLocal}
	if iif != "" {
		info.Arrival = control.ArrivalLink
	}
	info.Kernel = c.routeKernel(src, dst, iif)
	switch k := info.Kernel; {
	case !k.IntoTun || k.Why == control.WhyForwardingOff:
	case !src.IsValid():
		info.Unfollowed = "since its checks read the source the kernel picks, which its answer does not carry"
	default:
		info.Mesh = meshOf(c.Mesh.ExplainRead(routePacket(src, dst)), dst)
	}
	return info, nil
}

// routeFromSession is DebugRoute for a packet arriving through a session
// from the peer peer names
func (c *Client) routeFromSession(src, dst netip.Addr, peer string) (control.RouteInfo, error) {
	if !src.IsValid() {
		return control.RouteInfo{}, fmt.Errorf("a packet arriving through a session from %s carries a source", peer)
	}
	path, ok := c.sessionNamed(peer)
	if !ok {
		return control.RouteInfo{}, fmt.Errorf("%s names no peer this node holds a session with", peer)
	}
	info := control.RouteInfo{Src: src, Dst: dst, Peer: path, Arrival: control.ArrivalSession}
	if admission, refused, ok := c.Mesh.ExplainSegment(src, dst); ok {
		segment := &control.RouteSegment{LocalSegment: localSegment(admission.Segment, c.segmentEgress()), Overlay: admission.Overlay, Allowed: admission.Allowed}
		if admission.Err != nil {
			segment.Decision, segment.Reason = refused.Decision.String(), refused.Reason
		}
		info.Segment = segment
		return info, nil
	}
	explained := c.Mesh.Explain(routePacket(src, dst))
	info.Mesh = meshOf(explained, dst)
	if explained.Decision == netstack.TraceDeliver {
		info.IIF = c.Mesh.Name
		info.Kernel = c.routeKernel(src, dst, c.Mesh.Name)
	}
	return info, nil
}

// sessionNamed is the path of a live session from the peer peer names, as a
// trace names one, the first in path order where it names several: the mesh
// decides alike for a packet from any session
func (c *Client) sessionNamed(peer string) (string, bool) {
	paths := c.sessions.matching(peer, false, nil)
	if len(paths) == 0 {
		return "", false
	}
	return paths[0], true
}

// routePacket is the packet debug route follows from src to dst, an ICMP
// echo request of no data with a hop limit of routeHopLimit, unmarked and
// with no IPv4 option or IPv6 extension header
func routePacket(src, dst netip.Addr) []byte {
	if dst.Is4() {
		raw := make([]byte, 28)
		raw[0], raw[8], raw[9] = 0x45, routeHopLimit, 1
		binary.BigEndian.PutUint16(raw[2:], uint16(len(raw)))
		copy(raw[12:16], src.AsSlice())
		copy(raw[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(raw[10:], ^uint16(packet.Sum(0, raw[:20])))
		// RFC 792's echo request
		raw[20] = 8
		binary.BigEndian.PutUint16(raw[22:], ^uint16(packet.Sum(0, raw[20:])))
		return raw
	}
	raw := make([]byte, 48)
	raw[0], raw[6], raw[7] = 0x60, 58, routeHopLimit
	binary.BigEndian.PutUint16(raw[4:], 8)
	copy(raw[8:24], src.AsSlice())
	copy(raw[24:40], dst.AsSlice())
	// RFC 4443 section 4.1's echo request, its checksum over RFC 8200 section 8.1's pseudo-header too
	raw[40] = 128
	pseudo := packet.Sum(packet.Sum(0, raw[8:40]), []byte{0, 0, 0, 8, 0, 0, 0, 58})
	binary.BigEndian.PutUint16(raw[42:], ^uint16(packet.Sum(pseudo, raw[40:])))
	return raw
}

// meshOf is e, the mesh's decision for a packet to dst, on the wire
func meshOf(e netstack.Explanation, dst netip.Addr) *control.RouteMesh {
	m := &control.RouteMesh{Decision: e.Decision.String(), Reason: e.Reason, Answer: e.Answer, Next: e.Next, MTU: e.MTU}
	if e.Policy != nil {
		policy := steerPolicyOf(*e.Policy)
		m.Policy = &policy
	}
	// a /0 entry always counts as a default, so a match of no bits that does not count is no entry
	if e.Match.Bits != 0 || e.Match.Counted {
		m.Matched, m.Counted = netip.PrefixFrom(dst, e.Match.Bits).Masked(), e.Match.Counted
	}
	return m
}

// routeKernel is the kernel's answer for a packet from src to dst arriving
// on iif, or this host's own where iif is empty
func (c *Client) routeKernel(src, dst netip.Addr, iif string) *control.RouteKernel {
	routeGet := c.routeGet
	if routeGet == nil {
		routeGet = kernel.RouteGet
	}
	route, err := routeGet(src, dst, iif)
	k := &control.RouteKernel{}
	if errors.Is(err, kernel.ErrUnsupported) {
		k.Err, k.Why = err.Error(), control.WhyUnsupported
		return k
	}
	k.NoSource = src.IsValid() && !kernel.RouteGetTakesSource
	if err != nil {
		k.Err = err.Error()
		var errno syscall.Errno
		if errors.As(err, &errno) {
			k.Errno = unix.ErrnoName(errno)
		}
	} else {
		k.Route, k.Source, k.Table, k.Type, k.Exception, k.NoEntry = route.Prefix, route.Source, route.Table, route.Type, route.Exception, route.NoEntry
		for _, hop := range route.NextHops {
			k.NextHops = append(k.NextHops, control.RouteNextHop{Dev: hop.Device, Gateway: hop.Gateway, Dead: hop.Dead, LinkDown: hop.LinkDown})
			k.IntoTun = k.IntoTun || hop.Device == c.Mesh.Name
		}
	}
	c.explainRoute(k, dst, iif, route, err)
	dump := c.ruleDump
	if dump == nil {
		dump = kernel.DumpRules
	}
	rules, dumpErr := dump()
	switch {
	case errors.Is(dumpErr, kernel.ErrUnsupported):
		k.RuleErr = "this platform has no policy rules"
	case dumpErr != nil:
		k.RuleErr = dumpErr.Error()
	default:
		taken := kernel.TakeRule(rules, src, dst, iif, route, err)
		k.RouteType = taken.RouteType
		proto, wanted := c.ruleOwners()
		for _, rule := range taken.Unread {
			k.Unread = append(k.Unread, policyRuleOf(rule, proto, wanted))
		}
		if taken.Found {
			rule := policyRuleOf(taken.Rule, proto, wanted)
			if taken.Candidate {
				k.Candidate = &rule
			} else {
				k.Rule = &rule
			}
		}
	}
	if errors.Is(err, syscall.ENETUNREACH) && k.Rule == nil {
		k.Why = control.WhyNoRoute
	}
	return k
}

// explainRoute sets what explains the kernel's answer, reading the settings
// that decide an arrival where an errno alone would not say which of its
// causes it is, reverse path filtering or forwarding, or where a group's
// route alone would not say whether multicast routing takes it. A setting it
// cannot read is reported unread and explains nothing, but for
// force_forwarding, which kernels before 6.17 lack.
func (c *Client) explainRoute(k *control.RouteKernel, dst netip.Addr, iif string, route kernel.MatchedRoute, err error) {
	sysctl := c.sysctl
	if sysctl == nil {
		sysctl = Sysctl
	}
	// read records the setting at path and answers its number, or why it has
	// none, empty naming an empty read
	read := func(empty string, path ...string) (int, string) {
		name := strings.Join(path, "/")
		setting := control.RouteSetting{Name: name}
		value := sysctl(name)
		number, err := strconv.Atoi(value)
		switch {
		case value == "":
			setting.Err = empty
		case err != nil:
			setting.Err = fmt.Sprintf("%q is no number", value)
		default:
			setting.Value = value
		}
		k.Settings = append(k.Settings, setting)
		return number, setting.Err
	}
	const unreadable, absent = "unreadable", "absent"
	switch {
	case iif == "":
	// ip_route_input_slow refuses a destination in 0.0.0.0/8 before it checks
	// a source against a route
	case dst.Is4() && errors.Is(err, syscall.EINVAL) && dst.As4()[0] == 0:
		k.Why = control.WhyMartianDestination
	case dst.Is4() && errors.Is(err, syscall.EINVAL):
		// the kernel filters by the larger of the two (IN_DEV_RPFILTER), a
		// group's source as any other (ip_mc_validate_source)
		all, allErr := read(unreadable, "net", "ipv4", "conf", "all", "rp_filter")
		link, linkErr := read(unreadable, "net", "ipv4", "conf", iif, "rp_filter")
		if allErr == "" && linkErr == "" && max(all, link) >= 1 && max(all, link) <= 2 {
			k.Why = control.WhyReversePath
		}
	case dst.Is4() && err == nil && route.Type == "multicast" && !localGroups.Contains(dst):
		// a group beyond the link takes the kernel's multicast routing where
		// all's and the link's mc_forwarding are on (IN_DEV_MFORWARD)
		all, allErr := read(unreadable, "net", "ipv4", "conf", "all", "mc_forwarding")
		link, linkErr := read(unreadable, "net", "ipv4", "conf", iif, "mc_forwarding")
		if allErr == "" && linkErr == "" && all != 0 && link != 0 {
			k.Why = control.WhyMulticastRouting
		}
	case dst.Is4() && errors.Is(err, syscall.EHOSTUNREACH):
		// a group beyond the link meets no forwarding check (ip_route_input_rcu)
		// and answers EHOSTUNREACH only where all's mc_forwarding sends its
		// route to multicast routing, which withholds it (rt_fill_info)
		if dst.IsMulticast() && !localGroups.Contains(dst) {
			read(unreadable, "net", "ipv4", "conf", "all", "mc_forwarding")
			k.Why = control.WhyMulticastRouting
			break
		}
		// IPv4 forwards by the arrival link's forwarding (IN_DEV_FORWARD)
		if forwarding, readErr := read(unreadable, "net", "ipv4", "conf", iif, "forwarding"); readErr == "" && forwarding == 0 {
			k.Why = control.WhyForwardingOff
		}
	case dst.Is6() && err == nil && route.Type != "local":
		// IPv6 forwards by all's forwarding or the arrival link's
		// force_forwarding, and reads no link's forwarding (ip6_forward). An
		// empty force_forwarding is taken as absent, since /proc/sys reads
		// where all's did
		all, allErr := read(unreadable, "net", "ipv6", "conf", "all", "forwarding")
		force, forceErr := read(absent, "net", "ipv6", "conf", iif, "force_forwarding")
		if allErr == "" && all == 0 && (forceErr == "" && force == 0 || forceErr == absent) {
			k.Why = control.WhyForwardingOff
		}
	}
}

// localGroups is IPv4's link-local groups, which multicast routing never
// takes (ipv4_is_local_multicast)
var localGroups = netip.MustParsePrefix("224.0.0.0/24")

// ruleOwners is the protocol the reconciler writes its rules with, the
// default one on a node with no cap.table, and the rules it derives
func (c *Client) ruleOwners() (uint8, []kernel.DumpedRule) {
	proto := uint8(kernel.DefaultProtocol)
	if table := c.config().Cap.Table; table != nil {
		proto = table.Normalized().Proto
	}
	var wanted []kernel.DumpedRule
	if read := c.reconcilerRules.Load(); read != nil {
		wanted = (*read)()
	}
	return proto, wanted
}

// policyRuleOf is rule on the wire, owned where it carries proto and wanted
// where it is owned and among the rules the reconciler derives
func policyRuleOf(rule kernel.DumpedRule, proto uint8, wanted []kernel.DumpedRule) control.PolicyRule {
	policy := policyRule(rule)
	policy.Owned = rule.Protocol == proto
	policy.Wanted = policy.Owned && slices.Contains(wanted, rule)
	return policy
}
