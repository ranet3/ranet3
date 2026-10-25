// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"net/netip"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/version"
	"ranet3.com/pkgs/ranet3/srv6"
)

// This file is the runtime's side of the control socket's reads. Every method
// reads live state under whatever lock owns it and returns a value, so a slow
// reader on the socket never holds the dataplane's lock.
//
// Nothing here writes. The verbs that do are in write.go and updown.go, and none of them
// touches the configuration either: its entry points stay the file and SIGHUP,
// which is why the socket carries no authorization beyond its mode.

// SetKernelStatus hands the control surface the route reconciler's own view of
// its last pass. The reconciler is built by the command rather than here,
// because it owns the kernel and this owns the mesh, so the command supplies
// the reader once it exists. Without it the reconciler reports as off, which
// is the honest answer for a node configuring its routes externally.
func (c *Client) SetKernelStatus(read func() control.KernelStatus) {
	c.kernelStatus.Store(&read)
}

// Forwarding reports whether this host forwards, per family
// it is exported so the egress capability withholds an advertisement over the answer status and cap.border's warning read
func Forwarding() (v4, v6 bool) { return forwardingEnabled() }

func (c *Client) Status() control.Status {
	cfg := c.config()
	organizations, nodes := c.index().Size()
	stats := c.speaker.Stats()
	alive := 0
	for _, neighbor := range stats.Neighbors {
		if neighbor.Alive {
			alive++
		}
	}
	forwardsV4, forwardsV6 := forwardingEnabled()
	endpoints := make([]string, 0, len(cfg.Link.Endpoints))
	for _, endpoint := range cfg.Link.Endpoints {
		endpoints = append(endpoints, endpoint.Serial+"/"+endpoint.Family)
	}
	originate := c.speaker.Originated()
	announced := make([]control.Originated, 0, len(originate))
	for _, route := range originate {
		announced = append(announced, control.Originated{Prefix: route.Destination, From: route.Source})
	}
	return control.Status{
		Version:      version.String(),
		Node:         cfg.Node.String(),
		Port:         cfg.Link.Port,
		Endpoints:    endpoints,
		TUN:          c.Mesh.Name,
		MTU:          c.Mesh.MTU(),
		Queues:       c.Mesh.QueueCount(),
		StartedAt:    c.started,
		Uptime:       control.Duration(time.Since(c.started)),
		Responder:    cfg.Link.Listen,
		FullMesh:     cfg.Dial.All,
		NoTransit:    !cfg.Transits(),
		ForwardsIPv4: forwardsV4,
		ForwardsIPv6: forwardsV6,
		Registry: control.RegistryInfo{
			Path:          cfg.Auth.Trust,
			Organizations: organizations,
			Nodes:         nodes,
			ReadAt:        c.registryReadAt(),
		},
		Kernel: c.kernel(),
		Egress: c.egress(),
		Border: c.borderStatus(),
		Counts: control.Counts{
			Dialers:        c.dialerCount(),
			Sessions:       len(c.sessions.paths()),
			Neighbors:      len(stats.Neighbors),
			NeighborsAlive: alive,
			Prefixes:       stats.Prefixes,
			Selected:       stats.Selected,
			Originated:     stats.Originated,
		},
		ESP: control.ESPCounters{
			InboundPackets: c.inboundPackets.Load(),
			InboundDropped: c.inboundDropped.Load(),
			ReceiveDropped: c.hubDropped(),
			ReceiveRefused: c.hubRefused(),
			Keepalives:     c.hubKeepalives(),
		},
		Originate:       announced,
		Segments:        segmentText(c.Mesh.Segments()),
		Steering:        c.Mesh.Steering().Entries(),
		SegmentCounters: segmentCounters(c.Mesh.SegmentCounters()),
		Transit:         transitCounters(c.Mesh.TransitCounters()),
		Disabled:        c.disabledSubsystems(),
		Down:            c.downStatus(),
	}
}

// segmentCounters carries the dataplane's counters onto the wire, field by
// field rather than by a type conversion, so that each side names what it
// takes. Writing them out catches a renamed field and not an added one, which
// is the drift that once made a counter stop being reported here, so
// TestSegmentCountersDoNotDrift holds the two shapes identical and a field
// added to either has to be added to both.
func segmentCounters(counters netstack.SegmentCounters) control.SegmentCounters {
	return control.SegmentCounters{
		Forwarded: counters.Forwarded,
		Delivered: counters.Delivered,
		Dropped:   counters.Dropped,
		Steered:   counters.Steered,
		Unsteered: counters.Unsteered,
		Unrouted:  counters.Unrouted,
		Answered:  counters.Answered,
		Egressed:  counters.Egressed,
		Refused:   counters.Refused,
		NotReady:  counters.NotReady,
	}
}

// transitCounters carries the forwarding decision's counters onto the wire field by field, as segmentCounters does
// TestTransitCountersDoNotDrift holds the two shapes identical
func transitCounters(counters netstack.TransitCounters) control.TransitCounters {
	return control.TransitCounters{
		Forwarded:      counters.Forwarded,
		Delivered:      counters.Delivered,
		Expired:        counters.Expired,
		NoRoute:        counters.NoRoute,
		Held:           counters.Held,
		Refused:        counters.Refused,
		Invalid:        counters.Invalid,
		Martian:        counters.Martian,
		SourceRoute:    counters.SourceRoute,
		UnroutedSource: counters.UnroutedSource,
		NotReady:       counters.NotReady,
		TooBig:         counters.TooBig,
		Multicast:      counters.Multicast,
		Forged:         counters.Forged,
		RoutingHeader:  counters.RoutingHeader,
		SID:            counters.SID,
		UnownedSource:  counters.UnownedSource,
		Nested:         counters.Nested,
		Looped:         counters.Looped,
		Answered:       counters.Answered,
		Unanswered:     counters.Unanswered,
	}
}

// segmentText is the local segment table as an operator reads it, and nil on a
// node that configures none so the field is absent rather than empty.
func segmentText(table *srv6.LocalTable) []string {
	segments := table.Segments()
	if len(segments) == 0 {
		return nil
	}
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		out = append(out, segment.String())
	}
	return out
}

// kernel reports the reconciler, or that there is none. The configured half
// comes from the command through SetKernelStatus as well, because a config
// block that failed validation never became a reconciler and reporting its
// fields would describe a table nobody is writing.
func (c *Client) kernel() control.KernelStatus {
	read := c.kernelStatus.Load()
	if read == nil {
		return control.KernelStatus{}
	}
	return (*read)()
}

// egress reports the exit node capability, or that there is none. As with the
// reconciler, the configured half comes from the exit the command handed over
// through SetExit rather than from the config file, because a block that
// failed validation never became an exit and reporting its fields would
// describe rules nobody installed.
//
// The exit reports the families it holds ready, and the egress segments
// carry neither while the border's chain is not read back, so the status
// says what the mesh holds.
func (c *Client) egress() control.EgressStatus {
	status := c.exitStatus()
	if status.Enabled && c.borderHeld.Load() && len(c.config().Segments().Egress()) != 0 {
		status.Ready = nil
		reasons := slices.DeleteFunc([]string{status.Unready, "until the border filter is read back"}, func(reason string) bool { return reason == "" })
		status.Unready = strings.Join(reasons, ", and ")
	}
	return status
}

func (c *Client) exitStatus() control.EgressStatus {
	exit := c.exit.Load()
	if exit == nil {
		return control.EgressStatus{}
	}
	return egressStatus((*exit).Status())
}

// egressStatus is an exit's Status as the control surface reports it, the
// detail of a backend holding rules in the host's packet filter among it
func egressStatus(status egress.Status) control.EgressStatus {
	var ready []string
	if status.Ready4 {
		ready = append(ready, "ipv4")
	}
	if status.Ready6 {
		ready = append(ready, "ipv6")
	}
	out := control.EgressStatus{
		Enabled:   true,
		Where:     status.Where,
		Ready:     ready,
		Unready:   status.Unready,
		Skipped:   status.Skipped,
		Source4:   status.Source4.String(),
		Source6:   status.Source6.String(),
		Return:    status.Return,
		Advertise: status.Advertise,
		Announced: status.Announced,
		PassAt:    status.PassAt,
		Err:       status.Err,
	}
	if rules := status.Rules; rules != nil {
		out.Installed, out.Flows, out.Bytes, out.Conflicts = rules.Installed, rules.Flows, rules.Bytes, rules.Conflicts
	}
	return out
}

// borderStatus reports the border filter, and nil on a node with no cap.border
func (c *Client) borderStatus() *control.BorderStatus {
	f := c.border.Load()
	if f == nil {
		return nil
	}
	border := *f
	stats := border.Stats()
	overlay := border.Capability().Normalized().Overlay
	prefixes := make([]netip.Prefix, 0, len(overlay))
	for _, entry := range overlay {
		prefixes = append(prefixes, entry.Prefix)
	}
	return &control.BorderStatus{
		Where:     border.Where(),
		Inside:    border.Inside(),
		Overlay:   prefixes,
		SIDs:      slices.SortedFunc(slices.Values(border.SIDs()), netip.Addr.Compare),
		Ready:     stats.Ready,
		Unready:   stats.Unready,
		PassAt:    stats.At,
		Installed: stats.Installed,
		Dropped: control.BorderDrops{
			OverlaySourceIPv4: stats.Dropped.Source4,
			OverlaySourceIPv6: stats.Dropped.Source6,
			RoutingHeader:     stats.Dropped.RoutingHeader,
			SIDDestination:    stats.Dropped.Destination,
		},
		Err: stats.Err,
	}
}

func (c *Client) registryReadAt() time.Time {
	if at := c.regReadAt.Load(); at != 0 {
		return time.Unix(0, at)
	}
	return time.Time{}
}

func (c *Client) dialerCount() int {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return len(c.dialers)
}

func (c *Client) Neighbors() []control.Neighbor {
	stats := c.speaker.Stats()
	out := make([]control.Neighbor, 0, len(stats.Neighbors))
	for _, neighbor := range stats.Neighbors {
		entry := control.Neighbor{
			Peer:       neighbor.Peer,
			Address:    neighbor.Addr,
			Alive:      neighbor.Alive,
			Cost:       neighbor.Cost,
			Extra:      neighbor.Extra,
			Routes:     neighbor.Routes,
			Expires:    control.Duration(neighbor.Expires),
			Dropped:    neighbor.Dropped,
			SendFailed: neighbor.SendFailed,
		}
		// Both are pointers on the wire rather than a zero, because zero is a
		// cost a link can genuinely have and a round trip a loopback peer
		// genuinely measures, and "not measured yet" has to read differently
		// from "measured, and it is zero".
		if neighbor.HaveReportedCost {
			cost := neighbor.ReportedCost
			entry.ReportedCost = &cost
		}
		if neighbor.HaveRTT {
			rtt := control.Duration(neighbor.RTT)
			entry.RTT = &rtt
		}
		out = append(out, entry)
	}
	return out
}

func (c *Client) Routes() []control.Route {
	dump := c.speaker.RouteDump()
	out := make([]control.Route, 0, len(dump))
	for _, route := range dump {
		out = append(out, control.Route{
			Destination: route.Destination,
			From:        route.Source,
			Via:         route.Via,
			Metric:      route.Metric,
			RouterID:    routerID(route),
			Seqno:       route.Seqno,
			Candidates:  route.Candidates,
			Originated:  route.Originated,
			Assigned:    route.Assigned,
		})
	}
	return out
}

// routerID is the selected route's origin in hex, and empty where there is no
// selection: the zero router id is a value a peer could in principle send, so
// printing it for a prefix nobody offers would read as an origin.
func routerID(route babel.RouteStat) string {
	if route.Via == "" {
		return ""
	}
	return hex.EncodeToString(route.RouterID[:])
}

func (c *Client) Sessions() []control.Session {
	live := c.sessions.snapshot()
	out := make([]control.Session, 0, len(live))
	for _, session := range live {
		local, remote := session.session.ChildSPIs()
		started := session.session.StartedAt()
		suite := session.session.Suite()
		fragments, threshold := session.session.Fragments()
		entry := control.Session{
			Path:                 session.path,
			Peer:                 session.peer.Node().String(),
			Preferred:            session.preferred,
			Active:               session.session.Active(),
			LocalSPI:             local,
			RemoteSPI:            remote,
			IKECipher:            suite.IKECipher,
			IKEPRF:               suite.IKEPRF,
			IKEKex:               suite.IKEKex,
			IKEFragments:         fragments,
			IKEFragmentThreshold: threshold,
			ESPCipher:            suite.ESPCipher,
			ESPKex:               suite.ESPKex,
			StartedAt:            started,
			Age:                  control.Duration(time.Since(started)),
			Idle:                 control.Duration(session.session.Idle()),
		}
		if endpoint := session.session.Mux().Endpoint(); endpoint != nil {
			entry.Remote = endpoint.AddrPort().String()
		}
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b control.Session) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func (c *Client) Peers() []control.Peer {
	cfg := c.config()
	live, wanted := c.sessions.snapshot(), dials(cfg, c.index())
	out := make([]control.Peer, 0, len(wanted))
	for _, d := range wanted {
		out = append(out, control.Peer{Path: d.path, Peer: d.peer.String(), Connected: connected(live, d), Generated: d.generated})
	}
	slices.SortFunc(out, func(a, b control.Peer) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// connected matches the authenticated node and the local endpoint rather than the path, since a dial.all peer pins no serial while its session is named after the endpoint that answered
func connected(live []liveSessionView, d dial) bool {
	return slices.ContainsFunc(live, func(session liveSessionView) bool {
		return session.peer.Node() == d.peer.Node() && session.local == d.localID
	})
}
