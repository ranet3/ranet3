// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"slices"
	"strings"
)

// PathDebugRoute is where one packet goes through this host: the kernel's
// rule and route for it, and why the kernel refuses it where it does
const PathDebugRoute = PathDebug + "route"

func init() { registerDebug(PathDebugRoute, classRead, reflect.TypeFor[RouteInfo](), serveRoute) }

// the arrivals of a packet debug route follows
const (
	// ArrivalLocal is this host's own packet
	ArrivalLocal = "local"
	// ArrivalLink is a packet arriving on a link other than the tun
	ArrivalLink = "link"
	// ArrivalSession is a packet arriving through a session from a peer
	ArrivalSession = "session"
)

// why the kernel answered a packet as it did, where a setting or the answer
// itself says
const (
	// WhyNoRoute is ENETUNREACH with no rule taken: no table the walk reached
	// holds a route, or a Candidate ended the walk, or for this host's own IPv4
	// packet, where the lookup takes its source, a source it does not hold
	// refused it first
	WhyNoRoute = "no route"
	// WhyReversePath is EINVAL for an arrival on a link whose rp_filter is 1 or 2
	WhyReversePath = "reverse path filtering"
	// WhyForwardingOff is an arrival the kernel does not forward: in IPv4 an
	// EHOSTUNREACH on a link whose forwarding reads 0, and in IPv6 a route the
	// kernel drops the packet after, all's forwarding reading 0 and the arrival
	// link's force_forwarding 0 or absent (ip6_forward), whatever the link's
	// forwarding reads
	WhyForwardingOff = "forwarding off"
	// WhyMartianDestination is EINVAL for an IPv4 arrival to 0.0.0.0/8, a
	// martian destination the kernel refuses before any rule, where the
	// source is no martian it refuses first
	WhyMartianDestination = "martian destination"
	// WhyMulticastRouting is an IPv4 arrival to a group beyond the link that
	// the kernel's multicast routing decides: a route on a link whose
	// mc_forwarding and all's are on, which multicast routing takes, or an
	// EHOSTUNREACH, an answer multicast routing withholds with all's on
	WhyMulticastRouting = "multicast routing"
	// WhyUnsupported is a platform that looks up no such packet
	WhyUnsupported = "unsupported"
)

// RouteSource is a Source that follows a packet through its routing
type RouteSource interface {
	// DebugRoute follows a packet from src to dst, arriving on the link iif,
	// through a session from the peer peer names, or this host's own where
	// both are empty, or says why it cannot. An invalid src is this host's
	// own packet sent with none.
	DebugRoute(src, dst netip.Addr, iif, peer string) (RouteInfo, error)
}

// RouteInfo is each part of the host a packet meets in order, a part absent
// where the walk did not reach it
type RouteInfo struct {
	// Src is absent for this host's own packet sent with no source
	Src netip.Addr `json:"src,omitzero"`
	Dst netip.Addr `json:"dst"`
	// IIF is the link the kernel takes the packet as arriving on, the tun
	// for one the mesh delivers to this host
	IIF string `json:"iif,omitempty"`
	// Peer is the session a packet arriving through one comes through, by
	// its path
	Peer    string        `json:"peer,omitempty"`
	Arrival string        `json:"arrival"`
	Segment *RouteSegment `json:"segment,omitempty"`
	Mesh    *RouteMesh    `json:"mesh,omitempty"`
	Kernel  *RouteKernel  `json:"kernel,omitempty"`
	// Unfollowed is why the walk did not take a packet the kernel routes into
	// the tun on through the mesh's checks of a read, where it does not
	Unfollowed string `json:"unfollowed,omitempty"`
}

// RouteSegment is the segment of this node a packet from a session is
// addressed to, which acts on it before the mesh's decision, and what it asks
// of the packet's source
type RouteSegment struct {
	LocalSegment
	// Overlay is the source lying in cap.border's overlay, which every SID
	// asks first. Allowed is it lying in an egress segment's allow list,
	// which only such a segment asks, of a source Overlay admits.
	Overlay bool `json:"overlay"`
	Allowed bool `json:"allowed,omitempty"`
	// Decision and Reason are the segment's drop of a source it refuses, as a
	// trace's record names it, and absent for one it admits
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// RouteMesh is the mesh's decision for the packet, as a trace's record of it
// names it
type RouteMesh struct {
	Decision string `json:"decision"`
	// Reason is why the packet is answered or dropped, and Answer the ICMP
	// error it is answered with
	Reason string `json:"reason,omitempty"`
	Answer string `json:"answer,omitempty"`
	// Next is the session the packet is held to, by its path, for a forward,
	// and for an answer or a drop about its size past that session, and MTU
	// the most that session carries, the bytes Policy puts in front of the
	// packet among them
	Next string `json:"next,omitempty"`
	MTU  int    `json:"mtu,omitempty"`
	// Policy is the policy that steers a read, which sends it to the first
	// segment of its path
	Policy *SteerPolicy `json:"policy,omitempty"`
	// Matched is the table's entry for the destination, absent where the walk
	// ended before the table or no entry holds the destination, and Counted
	// is that entry counting as a default
	Matched netip.Prefix `json:"matched,omitzero"`
	Counted bool         `json:"counted,omitempty"`
}

// RouteKernel is the kernel's answer: the rule its walk took and the route it
// matched, or its error and what explains it
type RouteKernel struct {
	// Rule is the rule the kernel's walk took, found by walking the rule dump
	// as the kernel walks it, since the kernel names none. RuleErr says why no
	// rule was read.
	Rule    *PolicyRule `json:"rule,omitempty"`
	RuleErr string      `json:"rule_err,omitempty"`
	// Candidate is the terminal rule the walk ends on if the walk raised the
	// kernel's errno, where a check outside the walk answers that errno for
	// the packet too, so the walk may never have reached it
	Candidate *PolicyRule `json:"candidate,omitempty"`
	// Unread is each rule the walk reached ahead of Rule, or of its end where
	// Rule is absent, whose taking the packet turns on what the walk does not
	// read: a selector, where every one it reads holds, or suppress_ifgroup on
	// a lookup it would name. The walk assumed none of them took the packet.
	Unread []PolicyRule `json:"unread,omitempty"`
	// RouteType is unreachable, prohibit or blackhole where a route of that
	// type answers the kernel's errno as well, so a table a rule ahead of
	// Rule looks up, or any where Rule is absent, may have ended the walk
	RouteType string       `json:"route_type,omitempty"`
	Route     netip.Prefix `json:"route,omitzero"`
	// Source is the source prefix of an IPv6 route keyed on one
	Source   netip.Prefix   `json:"source,omitzero"`
	Table    uint32         `json:"table,omitempty"`
	Type     string         `json:"type,omitempty"`
	NextHops []RouteNextHop `json:"nexthops,omitempty"`
	// Exception is an IPv6 answer through a route the kernel cached for Dst
	// alone under Route, a path MTU's or a redirect's, whose length a rule's
	// suppress_prefixlength reads as 128
	Exception bool `json:"exception,omitempty"`
	// NoEntry is a route the kernel made for Dst itself with no table entry
	// behind it, the kernel's own, which no rule's lookup found, so the view
	// names no rule, route type or forwarding setting for it
	NoEntry bool `json:"no_entry,omitempty"`
	// IntoTun is a route leaving by the mesh's tun
	IntoTun bool `json:"into_tun,omitempty"`
	// NoSource is a lookup made without Src, which this platform's lookup does
	// not take, as XNU's does not
	NoSource bool `json:"no_source,omitempty"`
	// Err is the kernel's error, an answer as much as a route is, and Errno
	// its name where it is an errno
	Err   string `json:"err,omitempty"`
	Errno string `json:"errno,omitempty"`
	// Why is one of the Why values where the answer or a setting explains it
	Why string `json:"why,omitempty"`
	// Settings is each setting read to explain the answer
	Settings []RouteSetting `json:"settings,omitempty"`
}

// RouteNextHop is a link a route leaves by, its gateway where it has one,
// and the kernel's marks of a hop it does not use
type RouteNextHop struct {
	Dev      string     `json:"dev"`
	Gateway  netip.Addr `json:"gateway,omitzero"`
	Dead     bool       `json:"dead,omitempty"`
	LinkDown bool       `json:"linkdown,omitempty"`
}

// RouteSetting is one sysctl as read, or why it could not be
type RouteSetting struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Err   string `json:"err,omitempty"`
}

func (s RouteSetting) unread() bool { return s.Err != "" }

// ParseRoutePacket reads the two addresses of debug route, which are of one
// family and carry no zone. An unspecified source is this host's own packet
// sent with none, answered as an invalid src.
func ParseRoutePacket(src, dst string) (netip.Addr, netip.Addr, error) {
	var out [2]netip.Addr
	for i, named := range [2]struct{ name, text string }{{"source", src}, {"destination", dst}} {
		address, err := netip.ParseAddr(named.text)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("the %s %q is not an address", named.name, named.text)
		}
		if address.Zone() != "" {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("the %s %s carries a zone, which a routed packet does not", named.name, address)
		}
		out[i] = address
	}
	if out[0].Is4() != out[1].Is4() {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("the source %s and the destination %s are of two families", out[0], out[1])
	}
	if out[0].IsUnspecified() {
		out[0] = netip.Addr{}
	}
	return out[0], out[1], nil
}

func serveRoute(d *debugServer, w http.ResponseWriter, r *http.Request) {
	if !reading(w, r) {
		return
	}
	source, ok := implements[RouteSource](d, w, "route")
	if !ok {
		return
	}
	query := r.URL.Query()
	src, dst, err := ParseRoutePacket(query.Get("src"), query.Get("dst"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, err := source.DebugRoute(src, dst, query.Get("iif"), query.Get("peer"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, info)
}

// Route follows a packet from src to dst through the host, arriving on iif,
// through a session from the peer peer names, or this host's own where both
// are empty
// ctx bounds the exchange beside the client's own timeout
func (c *Client) Route(ctx context.Context, src, dst netip.Addr, iif, peer string) (RouteInfo, error) {
	from := "::"
	if dst.Is4() {
		from = "0.0.0.0"
	}
	if src.IsValid() {
		from = src.String()
	}
	query := url.Values{"src": {from}, "dst": {dst.String()}}
	if iif != "" {
		query.Set("iif", iif)
	}
	if peer != "" {
		query.Set("peer", peer)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://control"+PathDebugRoute+"?"+query.Encode(), nil)
	if err != nil {
		return RouteInfo{}, fmt.Errorf("control: %w", err)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return RouteInfo{}, c.explain(err)
	}
	return decode[RouteInfo](PathDebugRoute, response)
}

// RenderRoute writes each part the packet meets as a name and its value, in
// the order it meets them
func RenderRoute(w io.Writer, info RouteInfo) {
	from := "no source"
	if info.Src.IsValid() {
		from = info.Src.String()
	}
	arrival := "this host's own"
	switch info.Arrival {
	case ArrivalLink:
		arrival = "arriving on " + info.IIF
	case ArrivalSession:
		arrival = "through the session " + info.Peer
	}
	packet := fmt.Sprintf("from %s to %s, %s", from, info.Dst, arrival)
	if info.Kernel != nil && info.Kernel.NoSource {
		packet += ", looked up without its source, which this platform's lookup does not take"
	}
	rows := [][]string{{"Packet", packet}}
	if s := info.Segment; s != nil {
		rows = append(rows, segmentRows(info, *s)...)
	}
	var mesh [][]string
	switch {
	case info.Mesh != nil:
		mesh = meshRows(info, *info.Mesh)
	case info.Unfollowed != "":
		mesh = [][]string{{"Mesh", "not followed, " + info.Unfollowed}}
	}
	if info.Arrival == ArrivalSession {
		rows, mesh = append(rows, mesh...), nil
	}
	if k := info.Kernel; k != nil {
		rows = append(rows, kernelRows(info, *k)...)
	}
	pairs(w, append(rows, mesh...))
}

// segmentRows says what the segment a session's packet is addressed to asks
// of its source, then the drop of a source it refuses or what it does next
func segmentRows(info RouteInfo, s RouteSegment) [][]string {
	source := "outside cap.border's overlay"
	switch {
	case s.Overlay && s.Egress != nil && s.Allowed:
		source = "inside cap.border's overlay and the allow list"
	case s.Overlay && s.Egress != nil:
		source = "inside cap.border's overlay, outside the allow list"
	case s.Overlay:
		source = "inside cap.border's overlay"
	}
	rows := [][]string{{"Segment", segmentText(s.LocalSegment)}, {"Source", info.Src.String() + " " + source}}
	if s.Decision != "" {
		return append(rows, []string{"Decision", s.Decision + ", reason " + s.Reason})
	}
	next := "End sends the packet on to the next segment of its routing header, which this view's packet carries none of"
	switch {
	case s.Egress != nil:
		next = "End.DT46 takes out the inner packet, which this view's packet carries none of, checks its source against the allow list with the exit's other checks, and hands it to the exit"
	case s.Deliver != "":
		next = "End.DT46 takes out the inner packet, which this view's packet carries none of, and hands it to the mesh's decision whatever cap.transit says"
	}
	return append(rows, []string{"Then", next})
}

// meshRows says what the mesh decides for the packet, the table's entry it
// matched, and for a packet held to a session what a larger or expiring one
// meets instead
func meshRows(info RouteInfo, m RouteMesh) [][]string {
	decision := m.Decision
	switch {
	case m.Answer != "":
		decision += " " + m.Answer + ", reason " + m.Reason
	case m.Reason != "":
		decision += ", reason " + m.Reason
	case m.Next != "":
		decision += " to " + m.Next
	}
	rows := [][]string{{"Mesh", decision}}
	if p := m.Policy; p != nil {
		rows = append(rows, []string{"Steered", fmt.Sprintf("by the policy %s, source %s, path %s", selectorText(*p), p.Source, pathText(*p))})
	}
	if m.Matched.IsValid() {
		matched := m.Matched.String()
		if m.Counted {
			matched += ", counting as a default"
		}
		rows = append(rows, []string{"Matched", matched})
	}
	if m.Next == "" {
		return rows
	}
	session := fmt.Sprintf("%s carries %d B", m.Next, m.MTU)
	if p := m.Policy; p != nil && p.Overhead != 0 {
		session += fmt.Sprintf(", %d B of them the steering's header", p.Overhead)
	}
	session += ", so a larger packet is answered too big"
	if info.Dst.Is4() {
		session += " with DF or cut into fragments without"
	}
	rows = append(rows, []string{"Session", session})
	if info.Arrival == ArrivalSession {
		rows = append(rows, []string{"Expiring", "a packet arriving with a hop limit of 1 or less is answered expired"})
	}
	return rows
}

func kernelRows(info RouteInfo, k RouteKernel) [][]string {
	if k.Why == WhyUnsupported {
		if info.Arrival != ArrivalLocal {
			return [][]string{{"Kernel", "this platform looks up this host's own packets only"}}
		}
		return [][]string{{"Kernel", "this platform looks up no route"}}
	}
	var rows [][]string
	if k.Err != "" {
		rows = append(rows, []string{"Kernel", routeRefusal(info, k)})
	}
	for _, rule := range k.Unread {
		rows = append(rows, []string{"Unread", ruleText(rule) + ", assumed not to take the packet, since this view does not read " + strings.Join(rule.Unread, " or ")})
	}
	rows = append(rows, []string{"Rule", ruleLine(info, k)})
	// a socket, which the view does not see, decides where this host's own
	// IPv6 packet to :: goes, whatever the lookup answers
	unspecified := info.Arrival == ArrivalLocal && info.Dst.Is6() && info.Dst.IsUnspecified()
	if k.Err == "" {
		rows = append(rows, []string{"Route", routeLine(k)})
		if !unspecified {
			rows = append(rows, []string{"Leaves", leaves(info, k)})
		}
	}
	if unspecified {
		rows = append(rows, []string{"Socket", ":: is the unspecified address, and a socket sends such a packet to ::1 or by the route, or refuses it, as its type and the platform decide, so the answer above may not be the packet's path"})
	}
	if len(k.Settings) > 0 {
		settings := make([]string, 0, len(k.Settings))
		for _, setting := range k.Settings {
			value := setting.Value
			if setting.Err != "" {
				value = setting.Err
			}
			settings = append(settings, setting.Name+" "+value)
		}
		rows = append(rows, []string{"Settings", strings.Join(settings, ", ")})
	}
	return rows
}

// routeRefusal says what the kernel's error means, as far as the answer and
// the settings read tell
func routeRefusal(info RouteInfo, k RouteKernel) string {
	name := k.Errno
	if name == "" {
		return "refused, " + k.Err
	}
	sourced, group := ownSourced(info, k), arrivingGroup(info)
	withheld := name + ", the route of a group arriving on " + info.IIF + ", which the kernel's multicast routing withholds from its answer"
	switch {
	case name == "EHOSTUNREACH" && group && info.Dst.Is4() && k.Why == WhyMulticastRouting && multicastRoutingUnread(k):
		return withheld + ", so multicast routing is on"
	case name == "EHOSTUNREACH" && group && info.Dst.Is4() && k.Why == WhyMulticastRouting:
		return withheld
	// the kernel builds a group's route for an IPv4 arrival only where this
	// host joined the group on the link or multicast routing takes it, then
	// checks the source
	case name == "EINVAL" && group && info.Dst.Is4() && k.Why == WhyReversePath:
		return name + ", a group this host has not joined on " + info.IIF + ", or a source the kernel's checks refuse for it, reverse path filtering among them"
	case name == "EINVAL" && group && info.Dst.Is4():
		return name + ", a group this host has not joined on " + info.IIF + ", or a source the kernel's checks refuse for it"
	case k.Why == WhyMartianDestination:
		return name + ", a martian destination or source"
	// an IPv6 arrival to a group answered with EMSGSIZE carries no route, so
	// each path the packet may take is named
	case name == "EMSGSIZE" && group && info.Dst.Is6():
		return name + ", which the kernel answers for a group arriving on a link in place of its route, and it delivers such a packet to this host where it joined the group on " + info.IIF + ", forwards it by multicast routing where that is on, and drops it otherwise"
	case k.Why == WhyNoRoute && sourced && k.Candidate != nil:
		return name + ", the rule below, or a source this host does not hold"
	case k.Why == WhyNoRoute && sourced:
		return name + ", no route, or a source this host does not hold"
	case k.Why == WhyNoRoute:
		return name + ", no route"
	case k.Why == WhyReversePath && k.Candidate != nil:
		return name + ", reverse path filtering, or a martian source, a blackhole route or the rule below, which answer the same"
	case k.Why == WhyReversePath:
		return name + ", reverse path filtering, or a martian source or a blackhole, which answer the same"
	case k.Why == WhyForwardingOff:
		return name + ", forwarding is off on " + info.IIF
	case name == "EINVAL" && info.Arrival != ArrivalLocal && info.Dst.Is4() && k.Candidate != nil:
		return name + ", a martian source, a blackhole route or the rule below"
	case name == "EINVAL" && info.Arrival != ArrivalLocal && info.Dst.Is4():
		return name + ", a martian source or a blackhole"
	case name == "EINVAL" && info.Dst.Is4() && k.Candidate != nil:
		return name + ", a source or destination the kernel refuses, a blackhole route or the rule below"
	case name == "EINVAL" && info.Dst.Is4():
		return name + ", a source or destination the kernel refuses, or a blackhole"
	case k.RouteType != "" && k.Rule != nil:
		return name + ", " + article(k.RouteType) + " route or the rule below"
	case k.RouteType != "":
		return name + ", " + article(k.RouteType) + " route"
	case k.Rule != nil:
		return name + ", the rule below"
	}
	return "refused, " + k.Err
}

// ownSourced reports this host's own IPv4 packet whose source the lookup took
func ownSourced(info RouteInfo, k RouteKernel) bool {
	return info.Arrival == ArrivalLocal && info.Src.Is4() && !k.NoSource
}

// multicastRoutingUnread reports an mc_forwarding the view could not read
func multicastRoutingUnread(k RouteKernel) bool {
	return slices.ContainsFunc(k.Settings, func(s RouteSetting) bool { return s.unread() && strings.HasSuffix(s.Name, "/mc_forwarding") })
}

// arrivingGroup reports a packet arriving on a link, or on the tun from a
// session, to a group
func arrivingGroup(info RouteInfo) bool {
	return info.Arrival != ArrivalLocal && info.Dst.IsMulticast()
}

func ruleLine(info RouteInfo, k RouteKernel) string {
	switch {
	case k.RuleErr != "":
		return k.RuleErr
	case k.NoEntry:
		return "none, the route below is the kernel's own for this destination, in no table a rule looks up"
	case k.Rule != nil:
		line := ruleText(*k.Rule)
		if k.RouteType != "" {
			line += ", unless " + article(k.RouteType) + " route in a table a rule ahead of it looks up ended the walk"
		}
		return line
	case k.Candidate != nil:
		line := ruleText(*k.Candidate) + ", if the walk reached it rather than a check outside the walk raising the same errno"
		if k.RouteType != "" {
			line += ", and unless " + article(k.RouteType) + " route in a table a rule ahead of it looks up ended the walk"
		}
		return line
	case k.Err != "" && info.Dst.Is4() && (arrivingGroup(info) || k.Why == WhyMartianDestination):
		return "none, the kernel walks no rule for this destination arriving on a link"
	case k.Errno == "EMSGSIZE" && arrivingGroup(info) && info.Dst.Is6():
		return "none named, the answer carries no route"
	case k.Err != "" && (k.Why == WhyReversePath || k.Why == WhyForwardingOff):
		return "none named, the kernel refuses the packet after its walk, whose end the answer does not carry"
	// IPv4's EINVAL has causes outside the walk, as the Candidate's errno does
	case k.RouteType != "" && k.Errno == "EINVAL" && info.Dst.Is4():
		return "none named, " + article(k.RouteType) + " route in a table some rule looks up if the walk raised this errno rather than a check outside it"
	// an IPv4 arrival's EHOSTUNREACH is also the link's forwarding off, which
	// a setting left unread does not rule out
	case k.RouteType != "" && k.Errno == "EHOSTUNREACH" && info.Arrival != ArrivalLocal && info.Dst.Is4() && slices.ContainsFunc(k.Settings, RouteSetting.unread):
		return "none named, " + article(k.RouteType) + " route in a table some rule looks up if the walk raised this errno rather than forwarding off on the link"
	case k.RouteType != "":
		return "none named, " + article(k.RouteType) + " route in a table some rule looks up ends the walk with this errno"
	case k.Errno == "ENETUNREACH" && ownSourced(info, k):
		return "none named, the walk ends past the last rule if it ran, rather than the source check answering first"
	case k.Err != "":
		return "none named, the walk ends past the last rule"
	}
	return fmt.Sprintf("none fits the kernel's answer from table %s", PolicyRule{Action: "lookup", Table: k.Table}.target())
}

// ruleText is a rule as `ip rule` lists it, with who wrote it
func ruleText(rule PolicyRule) string {
	target := rule.target()
	if rule.Action == "lookup" {
		target = "lookup " + target
	}
	return fmt.Sprintf("%d %s %s, %s", rule.Priority, rule.selects(), target, rule.owner())
}

func routeLine(k RouteKernel) string {
	route := k.Route.String()
	if k.Source.IsValid() {
		route += " from " + k.Source.String()
	}
	if k.Table != 0 {
		route += " in table " + PolicyRule{Action: "lookup", Table: k.Table}.target()
	}
	route += ", " + k.Type
	for _, hop := range k.NextHops {
		text := "dev " + hop.Dev
		if hop.Gateway.IsValid() {
			text = "via " + hop.Gateway.String() + " " + text
		}
		if hop.Dead {
			text += " dead"
		}
		if hop.LinkDown {
			text += " linkdown"
		}
		route += ", " + text
	}
	if k.Exception {
		route += ", through an exception cached for the destination alone"
	}
	if k.NoEntry {
		route += ", the kernel's own for this destination, with no table entry behind it"
	}
	return route
}

// leaves says where a packet goes by the kernel's route
func leaves(info RouteInfo, k RouteKernel) string {
	switch {
	case k.Why == WhyForwardingOff:
		// a route answered with forwarding off is IPv6's alone
		return "nowhere, the kernel drops it after the lookup with forwarding off in all and force_forwarding not on for " + info.IIF
	case k.Why == WhyMulticastRouting:
		return "by the kernel's multicast routing, which delivers it to this host as well where it joined the group on " + info.IIF
	// the kernel makes an IPv4 arrival's group route only where this host
	// joined the group on the link or multicast routing takes it
	case arrivingGroup(info) && info.Dst.Is4() && slices.ContainsFunc(k.Settings, RouteSetting.unread):
		return "nowhere, the kernel delivers it to this host where it joined the group on " + info.IIF + ", and forwards it by multicast routing where that is on for " + info.IIF
	case arrivingGroup(info) && info.Dst.Is4():
		return "nowhere, the kernel delivers it to this host, which joined the group on " + info.IIF
	case k.Type == "local", info.Arrival != ArrivalLocal && k.Type == "broadcast":
		return "nowhere, the kernel delivers it to this host"
	case k.IntoTun:
		return "into the mesh's tun"
	case len(k.NextHops) == 0:
		return "nowhere, the route is " + k.Type
	}
	var devices []string
	for _, hop := range k.NextHops {
		if !hop.Dead {
			devices = append(devices, hop.Dev)
		}
	}
	if len(devices) == 0 {
		return "nowhere, each next hop is dead"
	}
	return "by " + strings.Join(devices, " ") + ", outside the mesh"
}

// article is word after the indefinite article it takes
func article(word string) string {
	if strings.IndexByte("aeiou", word[0]) >= 0 {
		return "an " + word
	}
	return "a " + word
}
