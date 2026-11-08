// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"runtime"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/version"
	"ranet3.com/pkgs/ranet3/srv6"
)

// This file is the runtime's side of the control socket's reads. Every method
// reads live state under whatever lock owns it and returns a value, so a slow
// reader on the socket never holds the dataplane's lock.
//
// Nothing here writes. The verbs that do are in write.go and updown.go.

// Forwarding reports whether this host forwards, per family, for the egress capability, which withholds a family it reads as off
// a setting it cannot read counts as on, since the reason the exit gives a family it withholds is that the kernel does not forward it
func Forwarding() (v4, v6 bool) { return forwardsUnlessOff(forwardingEnabled()) }

func forwardsUnlessOff(v4, v6 *bool) (bool, bool) { return v4 == nil || *v4, v6 == nil || *v6 }

func (c *Client) Status() control.Status {
	cfg, x := c.config(), c.index()
	organizations, nodes := x.Size()
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
		Initiator:    slices.ContainsFunc(dials(cfg, x), func(d dial) bool { return refuseDial(x, d) == nil }),
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
		Kernel: c.kernelWithResolvers(),
		Egress: c.exitStatus(),
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
			InboundPackets:   c.inboundPackets.Load(),
			InboundDropped:   c.inboundDropped.Load(),
			InboundCE:        c.inboundCE.Load(),
			InboundECNUnused: c.inboundECNUnused.Load(),
			ReceiveDropped:   c.hubDropped(),
			ReceiveRefused:   c.hubRefused(),
			Keepalives:       c.hubKeepalives(),
		},
		Originate:       announced,
		MeshAddresses:   MeshAddresses(cfg),
		Segments:        segmentText(c.Mesh.Segments()),
		Steering:        c.Mesh.Steering().Entries(),
		SegmentCounters: control.SegmentCounters(c.Mesh.SegmentCounters()),
		Transit:         control.TransitCounters(c.Mesh.TransitCounters()),
		Disabled:        c.disabledSubsystems(),
		Down:            c.downStatus(),
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
// comes from the reconciler SetReconciler took as well, because a config
// block that failed validation never became a reconciler and reporting its
// fields would describe a table nobody is writing. Without one the reconciler
// reports as off, which is the honest answer for a node configuring its routes
// externally.
func (c *Client) kernel() control.KernelStatus {
	read := c.reconcilerNow().Status
	if read == nil {
		return control.KernelStatus{}
	}
	status := read()
	if status.ExitPath != nil {
		counts := c.Mesh.PathCounters()
		status.ExitPath.Steered, status.ExitPath.Unrouted = counts.Steered, counts.Unrouted
	}
	for _, lookup := range c.lookups() {
		switch {
		case !lookup.Taken:
		case lookup.Underlay():
			taken := control.KernelTaken{Family: string(lookup.Family), Endpoint: lookup.Address.String(), Interface: lookup.Interface, Answer: lookup.Answer}
			if lookup.Source.IsValid() {
				taken.Source = lookup.Source.String()
			}
			status.Taken = append(status.Taken, taken)
		default:
			status.Taken = append(status.Taken, control.KernelTaken{Family: string(lookup.Family), Prefix: lookup.Prefix.String(), Address: lookup.Address.String(), Answer: lookup.Answer})
		}
	}
	if status.Exit != nil && status.Exit.Fallback != nil {
		// the reconciler's status reads no endpoint name, and the dialers do
		fallback := *status.Exit.Fallback
		fallback.Unresolved = c.unresolved.list()
		exit := *status.Exit
		exit.Fallback = &fallback
		status.Exit = &exit
	}
	return status
}

// kernelWithResolvers is kernel with the DNS servers beyond the switch's LAN
// systemd-resolved names at this read, where the switch is asked for
func (c *Client) kernelWithResolvers() control.KernelStatus {
	status := c.kernel()
	ask := c.reconcilerNow().Resolvers
	if ask == nil || status.Exit == nil || status.Exit.Fallback == nil {
		return status
	}
	// kernel copied the switch's status, so this writes nothing of the reconciler's
	for _, resolver := range ask() {
		status.Exit.Fallback.Resolvers = append(status.Exit.Fallback.Resolvers, control.KernelResolver{Link: resolver.Link, Address: resolver.Address.String()})
	}
	return status
}

// exitStatus reports the exit node capability, or that there is none. As with
// the reconciler, the configured half comes from the exit the command handed
// over through SetExit rather than from the config file, because a block that
// failed validation never became an exit and reporting its fields would
// describe rules nobody installed.
func (c *Client) exitStatus() control.EgressStatus {
	exit := c.exit.Load()
	if exit == nil {
		return control.EgressStatus{}
	}
	return egressStatus((*exit).Status())
}

// readyFamilies names each family ready, ipv4 where v4 holds and ipv6 where
// v6 does
func readyFamilies(v4, v6 bool) []string {
	var ready []string
	if v4 {
		ready = append(ready, "ipv4")
	}
	if v6 {
		ready = append(ready, "ipv6")
	}
	return ready
}

// egressStatus is an exit's Status as the control surface reports it, the
// detail of a backend holding rules in the host's packet filter among it
func egressStatus(status egress.Status) control.EgressStatus {
	out := control.EgressStatus{
		Enabled:        true,
		Where:          status.Where,
		Ready:          readyFamilies(status.Ready4, status.Ready6),
		Unready:        status.Unready,
		Skipped:        status.Skipped,
		Return:         status.Return,
		Advertise:      status.Advertise,
		Announced:      status.Announced,
		FlowsPerSource: status.FlowsPerSource,
		Refused:        control.EgressPackets{IPv4: status.Refused4, IPv6: status.Refused6},
		Dropped:        control.EgressPackets{IPv4: status.Dropped4, IPv6: status.Dropped6},
		PassAt:         status.PassAt,
		Err:            status.Err,
	}
	for _, class := range status.Translate {
		out.Translate = append(out.Translate, control.EgressClass{From: class.From.Prefix, To: class.To.String()})
	}
	if rules := status.Rules; rules != nil {
		out.Installed, out.Flows, out.Bytes, out.Untranslated, out.Conflicts = rules.Installed, rules.Flows, rules.Bytes, rules.Untranslated, rules.Conflicts
		out.ConntrackCount, out.ConntrackMax = rules.ConntrackCount, rules.ConntrackMax
	}
	if flows := status.Flows; flows != nil {
		out.Userspace = userspaceStatus(*flows)
	}
	return out
}

// userspaceStatus is a userspace exit's detail as the control surface
// reports it
func userspaceStatus(f egress.Flows) *control.EgressUserspace {
	l := f.Limits
	from := control.EgressBudgetHost
	if l.From == egress.BudgetGoLimit {
		from = control.EgressBudgetGoLimit
	}
	out := &control.EgressUserspace{
		TCP:     control.EgressFlows{IPv4: f.TCP[0], IPv6: f.TCP[1]},
		UDP:     control.EgressFlows{IPv4: f.UDP[0], IPv6: f.UDP[1]},
		Echo:    control.EgressFlows{IPv4: f.Echo[0], IPv6: f.Echo[1]},
		Dialing: f.Dialing, TimeWait: f.TimeWait, Buffered: f.Buffered,
		Limits: control.EgressLimits{
			Budget: l.Budget, From: from, Flows: l.Flows, Connections: l.Connections, Dials: l.Dials,
			TimeWait: l.TimeWait, Window: l.Window, Lanes: l.Lanes, Link: l.Link,
		},
		Refused: f.Refused, Dropped: f.Dropped, Reused: f.Reused, Closed: f.Closed,
	}
	for _, source := range f.Sources {
		out.Sources = append(out.Sources, control.EgressSourceFlows{Source: source.Source, Flows: source.Flows})
	}
	return out
}

// unenforcedOn names this platform where overlay is written and no antispoof
// filter runs for it, empty wherever one runs or no overlay is written
func (c *Client) unenforcedOn() string {
	if border := c.config().Border(); border == nil || kernelexit.Filters(border) {
		return ""
	}
	return runtime.GOOS
}

// borderStatus reports the antispoof filter, that it is not enforced on a
// platform that runs none where overlay is written, and nil on any other node
// that runs none
func (c *Client) borderStatus() *control.BorderStatus {
	f := c.border.Load()
	if f == nil {
		if on := c.unenforcedOn(); on != "" {
			return &control.BorderStatus{UnenforcedOn: on, Overlay: kernel.SchemaPrefixes(c.config().Overlay)}
		}
		return nil
	}
	border := *f
	stats := border.Stats()
	prefixes := kernel.SchemaPrefixes(border.Capability().Normalized().Overlay)
	var carved []control.BorderCarveOut
	for _, carveOut := range stats.CarveOuts {
		carved = append(carved, control.BorderCarveOut{Link: carveOut.Link, Prefix: carveOut.Prefix})
	}
	dropped := make(control.BorderDrops, len(stats.Kinds))
	for i, kind := range egress.BorderDropKinds {
		if slices.Contains(stats.Kinds, kind) {
			dropped[kind.Name()] = stats.Dropped[i]
		}
	}
	return &control.BorderStatus{
		Where:     border.Where(),
		PF:        borderPF(stats.PF),
		Inside:    border.Inside(),
		Overlay:   prefixes,
		Carved:    carved,
		Ready:     stats.Ready,
		Unready:   stats.Unready,
		PassAt:    stats.At,
		Installed: stats.Installed,
		Dropped:   dropped,
		Err:       stats.Err,
	}
}

// borderPF is pf's state for the filter as the wire carries it, nil where
// the filter does not run on pf
func borderPF(pf *egress.BorderPF) *control.BorderPF {
	if pf == nil {
		return nil
	}
	return &control.BorderPF{Anchor: pf.Anchor, Token: pf.Token, PID: pf.PID, Listed: pf.Listed, Called: pf.Called}
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
		child := session.session.Child()
		started := session.session.StartedAt()
		suite := session.session.Suite()
		fragments, threshold := session.session.Fragments()
		entry := control.Session{
			Path:                 session.path,
			Peer:                 session.peer.Node().String(),
			Preferred:            session.preferred,
			Role:                 ikeRole(session.dialed),
			Active:               session.session.Active(),
			LocalSPI:             child.LocalSPI,
			RemoteSPI:            child.RemoteSPI,
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
			InvalidSPIReports:    session.session.InvalidSPIReports(),
		}
		if endpoint := session.session.Mux().Endpoint(); endpoint != nil {
			entry.Remote = endpoint.AddrPort().String()
		}
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b control.Session) int { return strings.Compare(a.Path, b.Path) })
	return out
}

func ikeRole(dialed bool) string {
	if dialed {
		return "initiator"
	}
	return "responder"
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
