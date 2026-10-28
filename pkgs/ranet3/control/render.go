// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// The renderers below are the default output of the subcommands, with --json
// giving the wire form instead. They are here rather than in the command so
// that a test can hold the columns still: the column set is the promise the
// subcommands make, and a rename of one is a change an operator's scripts see.

// table writes rows under a header, aligned. Every renderer goes through it so
// the whole command speaks in one shape.
func table(w io.Writer, header []string, rows [][]string) {
	out := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(out, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(out, strings.Join(row, "\t"))
	}
	out.Flush()
}

// pairs writes rows aligned under no header, most of them a name and its value
func pairs(w io.Writer, rows [][]string) {
	out := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintln(out, strings.Join(row, "\t"))
	}
	out.Flush()
}

// RenderStatus writes the node's own summary as aligned name and value pairs
func RenderStatus(w io.Writer, s Status) {
	rows := [][]string{
		{"Node", s.Node},
		{"Version", s.Version},
		{"Uptime", shortDuration(time.Duration(s.Uptime))},
		{"Port", fmt.Sprint(s.Port)},
		{"Endpoints", strings.Join(s.Endpoints, " ")},
		{"TUN", fmt.Sprintf("%s MTU %d queues %d", s.TUN, s.MTU, s.Queues)},
		{"Role", role(s)},
		{"Forwarding", fmt.Sprintf("IPv4 %s IPv6 %s", onOff(s.ForwardsIPv4), onOff(s.ForwardsIPv6))},
		{"Registry", fmt.Sprintf("%s, %d nodes in %d organizations", s.Registry.Path, s.Registry.Nodes, s.Registry.Organizations)},
		{"Kernel", kernelLine(s.Kernel)},
		{"Egress", egressLine(s.Egress)},
		{"Dialers", fmt.Sprintf("%d running", s.Counts.Dialers)},
		{"Sessions", fmt.Sprint(s.Counts.Sessions)},
		{"Neighbors", fmt.Sprintf("%d, %d alive", s.Counts.Neighbors, s.Counts.NeighborsAlive)},
		{"Routes", fmt.Sprintf("%d prefixes, %d selected, %d originated", s.Counts.Prefixes, s.Counts.Selected, s.Counts.Originated)},
		{"Originate", originateLine(s.Originate)},
		{"Segments", segmentLine(s)},
		{"Steering", steeringLine(s)},
		{"Transit", transitLine(s.Transit)},
		{"ESP", espLine(s.ESP)},
	}
	// under the egress line, and only on a node that writes cap.border
	if s.Border != nil {
		rows = slices.Insert(rows, slices.IndexFunc(rows, func(row []string) bool { return row[0] == "Egress" })+1, []string{"Border", borderLine(*s.Border)})
	}
	// only on a node running less than its file says, since it would read none on every other
	if len(s.Disabled) > 0 {
		rows = append(rows, []string{"Disabled", disabledLine(s.Disabled)})
	}
	// under the name, since every count below reads zero on a node off the mesh
	if s.Down != nil {
		rows = slices.Insert(rows, 1, []string{"Down", downLine(*s.Down)})
	}
	pairs(w, rows)
}

func espLine(e ESPCounters) string {
	line := fmt.Sprintf("%d in, %d dropped, %d refused", e.InboundPackets, e.InboundDropped, e.ReceiveRefused)
	if e.InboundCE > 0 {
		line += fmt.Sprintf(", %d marked CE", e.InboundCE)
	}
	if e.InboundECNUnused > 0 {
		line += fmt.Sprintf(", %d with an unused ECN combination", e.InboundECNUnused)
	}
	return line
}

func downLine(d Down) string {
	return "since " + d.Since.UTC().Format(time.DateTime) + " UTC, " + sinceText(time.Duration(d.For)) + " ago, until ranet3 up"
}

// role is the three settings that decide what this node is on a fleet, said as
// words rather than as three booleans an operator has to reassemble.
func role(s Status) string {
	parts := []string{"initiator"}
	if s.Responder {
		parts = append(parts, "responder")
	}
	if s.FullMesh {
		parts = append(parts, "full mesh")
	}
	if s.NoTransit {
		parts = append(parts, "no transit")
	} else {
		parts = append(parts, "transit")
	}
	return strings.Join(parts, ", ")
}

func kernelLine(k KernelStatus) string {
	if !k.Enabled {
		return "off, routes configured externally"
	}
	line := fmt.Sprintf("%s, %d installed", k.Where, k.Installed)
	if k.Skipped > 0 {
		line += fmt.Sprintf(", %d skipped", k.Skipped)
	}
	if len(k.Cover) > 0 {
		line += ", zero-free cover for " + strings.Join(k.Cover, " and ")
	}
	switch since := time.Since(k.PassAt); {
	case k.PassAt.IsZero():
		line += ", no pass yet"
	case since < 0:
		// The timestamp crossed the socket as JSON, which drops the monotonic
		// reading, so a daemon and a client whose clocks disagree land here.
		line += ", last pass timestamped ahead of this clock"
	default:
		line += fmt.Sprintf(", last pass %s ago", sinceText(since))
	}
	for _, taken := range k.Taken {
		if taken.Endpoint != "" {
			line += fmt.Sprintf(", the underlay's mark taken by %s toward %s", taken.Answer, taken.Endpoint)
			if taken.Source != "" {
				line += " from " + taken.Source
			}
			if taken.Interface != "" {
				line += " dev " + taken.Interface
			}
		} else {
			line += fmt.Sprintf(", overlay %s taken by %s", taken.Prefix, taken.Answer)
		}
	}
	if e := k.Exit; e != nil {
		line += ", exit mode"
		if len(e.Forwarded) > 0 {
			line += " forwarding " + strings.Join(e.Forwarded, " ")
		}
		for _, skip := range e.Skipped {
			line += fmt.Sprintf(", forward %s skips %s, %s", skip.Entry, skip.Link, skip.Reason)
		}
		for _, family := range e.Unaddressed {
			line += fmt.Sprintf(", no %s overlay address on the tun, so %s runs mode off's rules", familyLabel(family), familyLabel(family))
		}
		if f := e.Fallback; f != nil {
			line += ", fallback none " + f.State
			if f.Reason != "" {
				line += ", " + f.Reason
			}
			line += fmt.Sprintf(", %d packets, %d B dropped", f.Dropped, f.DroppedBytes)
			for _, network := range f.Captured {
				line += fmt.Sprintf(", %s left out of the LAN as it captures the machine", network)
			}
			for _, name := range f.Unresolved {
				line += fmt.Sprintf(", %s does not resolve under the switch", name)
			}
			for _, resolver := range f.Resolvers {
				line += fmt.Sprintf(", DNS server %s on %s lies beyond the LAN", resolver.Address, resolver.Link)
			}
		}
	}
	if k.Err != "" {
		line += ", " + k.Err
	}
	return line
}

// egressLine says "off" on a node that is neither an exit node nor a subnet
// router, which is most of them. On one that is, it leads with what is being
// announced rather than with what was configured, because the two differ
// exactly when the capability is not working and that difference is the whole
// reason to read the line.
func egressLine(e EgressStatus) string {
	if !e.Enabled {
		return "off, this node carries no traffic for others"
	}
	line := fmt.Sprintf("%s, %d rules, %d flows", e.Where, e.Installed, e.Flows)
	if refused := packetsText(e.Refused); refused != "" {
		line += fmt.Sprintf(", %s refused past %d a source", refused, e.FlowsPerSource)
	}
	if dropped := packetsText(e.Dropped); dropped != "" {
		line += fmt.Sprintf(", %s dropped with no tracked flow", dropped)
	}
	if e.ConntrackCount != nil {
		line += ", " + conntrackText(*e.ConntrackCount, e.ConntrackMax)
	}
	withheld := make([]string, 0, len(e.Advertise))
	for _, prefix := range e.Advertise {
		if !slices.Contains(e.Announced, prefix) {
			withheld = append(withheld, prefix.String())
		}
	}
	if len(e.Announced) > 0 {
		line += ", announcing " + prefixText(e.Announced)
	}
	if len(withheld) > 0 {
		// Named rather than counted, and said as a refusal rather than as a
		// failure: a prefix is withheld because announcing it would attract
		// traffic this node would drop, and babel gives a peer no other way
		// to learn that.
		line += ", withholding " + strings.Join(withheld, " ") + " until its family is ready"
	}
	// a node before its first pass reports no family ready and no reason
	if len(e.Ready) != 0 || e.Unready != "" {
		line += egressReadyText(e.Ready, e.Unready)
	}
	if e.Skipped != "" {
		line += ", " + e.Skipped
	}
	if len(e.Conflicts) > 0 {
		line += fmt.Sprintf(", sharing the hook with %s", strings.Join(e.Conflicts, "; "))
	}
	switch since := time.Since(e.PassAt); {
	case e.PassAt.IsZero():
		line += ", no pass yet"
	case since < 0:
		line += ", last pass timestamped ahead of this clock"
	default:
		line += fmt.Sprintf(", last pass %s ago", sinceText(since))
	}
	if e.Err != "" {
		line += ", " + e.Err
	}
	return line
}

func packetsText(r EgressPackets) string {
	var families []string
	if r.IPv4 != 0 {
		families = append(families, fmt.Sprintf("%d ipv4", r.IPv4))
	}
	if r.IPv6 != 0 {
		families = append(families, fmt.Sprintf("%d ipv6", r.IPv6))
	}
	if len(families) == 0 {
		return ""
	}
	return strings.Join(families, " and ") + " packets"
}

func conntrackText(count uint64, most *uint64) string {
	if most == nil {
		return fmt.Sprintf("conntrack holding %d entries", count)
	}
	return fmt.Sprintf("conntrack holding %d of %d entries", count, *most)
}

// borderLine leads with where the chain is and what it accepts, then the drops
// counted, so an operator who injected a packet finds its count on the line, or
// says it is not installed and why
func borderLine(b BorderStatus) string {
	if !b.Ready {
		why := b.Err
		if why == "" {
			why = b.Unready
		}
		return "not installed, " + why
	}
	overlay := fmt.Sprintf("%d overlay prefixes", len(b.Overlay))
	if len(b.Overlay) == 1 {
		overlay = "1 overlay prefix"
	}
	return fmt.Sprintf("%s, inside %s, %s, %s, dropped %d overlay sources, %d routing headers, %d SID destinations",
		b.Where, strings.Join(b.Inside, " "), overlay, countOf(len(b.SIDs), "SID"),
		b.Dropped.OverlaySourceIPv4+b.Dropped.OverlaySourceIPv6, b.Dropped.RoutingHeader, b.Dropped.SIDDestination)
}

func egressReadyText(ready []string, unready string) string {
	var notReady []string
	for _, family := range []string{"ipv4", "ipv6"} {
		if !slices.Contains(ready, family) {
			notReady = append(notReady, family)
		}
	}
	var parts []string
	if len(ready) > 0 {
		parts = append(parts, "ready for "+strings.Join(ready, " "))
	}
	// a family this node does not translate is not ready with no reason of its own
	switch {
	case len(notReady) > 0 && unready != "":
		parts = append(parts, "not ready for "+strings.Join(notReady, " ")+", "+unready)
	case len(notReady) > 0:
		parts = append(parts, "not ready for "+strings.Join(notReady, " "))
	}
	return ", egress " + strings.Join(parts, ", ")
}

// disabledLine names the stopped subsystems and says the state goes away by
// itself, because whoever reads this row is often not whoever wrote it and the
// first question is whether a restart is needed to undo it.
func disabledLine(subsystems []Subsystem) string {
	names := make([]string, 0, len(subsystems))
	for _, name := range subsystems {
		names = append(names, string(name))
	}
	return strings.Join(names, ", ") + ", stopped on the control socket and started again by an enable or a restart"
}

// RenderResult writes the answer to a write. The entries are listed under the
// sentence only where the verb reached more than one or missed any, so a redial
// that covered four paths names them and a disable does not repeat the
// subsystem it just said.
func RenderResult(w io.Writer, result Result) {
	fmt.Fprintln(w, result.Detail)
	if len(result.Acted) < 2 && len(result.Missed) == 0 {
		return
	}
	for _, entry := range result.Acted {
		fmt.Fprintf(w, "  %s\n", entry)
	}
	for _, missed := range result.Missed {
		fmt.Fprintf(w, "  %s: %s\n", missed.Entry, missed.Reason)
	}
}

func prefixText(prefixes []netip.Prefix) string {
	text := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		text = append(text, prefix.String())
	}
	return strings.Join(text, " ")
}

// segmentLine says nothing but "off" on a node that configures no segment
// routing, which is most of them, rather than three zeroes an operator has to
// read as an absence.
func segmentLine(s Status) string {
	if len(s.Segments) == 0 {
		return "off"
	}
	line := fmt.Sprintf("%s (%d forwarded, %d delivered, %d dropped",
		strings.Join(s.Segments, ", "),
		s.SegmentCounters.Forwarded, s.SegmentCounters.Delivered, s.SegmentCounters.Dropped)
	for _, count := range []struct {
		n    uint64
		name string
	}{
		{s.SegmentCounters.Answered, "answered"},
		{s.SegmentCounters.Egressed, "egressed"},
		{s.SegmentCounters.Refused, "refused"},
		{s.SegmentCounters.NotReady, "not ready"},
	} {
		if count.n > 0 {
			line += fmt.Sprintf(", %d %s", count.n, count.name)
		}
	}
	return line + ")"
}

// transitLine always names forwarded, delivered and dropped
// and each reason a packet was dropped for, answered and unanswered only while each is above 0
func transitLine(c TransitCounters) string {
	var dropped uint64
	var reasons []string
	for _, drop := range c.Drops() {
		dropped += drop.Packets
		if drop.Packets > 0 {
			reasons = append(reasons, fmt.Sprintf("%d %s", drop.Packets, drop.Words))
		}
	}
	line := fmt.Sprintf("%d forwarded, %d delivered, %d dropped", c.Forwarded, c.Delivered, dropped)
	if len(reasons) > 0 {
		line += " (" + strings.Join(reasons, ", ") + ")"
	}
	if c.Answered > 0 {
		line += fmt.Sprintf(", %d answered", c.Answered)
	}
	if c.Unanswered > 0 {
		line += fmt.Sprintf(", %d unanswered", c.Unanswered)
	}
	return line
}

// steeringLine says "off" on a node that steers nothing, which is most of
// them, rather than two zeroes a reader has to interpret as an absence.
func steeringLine(s Status) string {
	if len(s.Steering) == 0 {
		return "off"
	}
	line := strings.Join(s.Steering, "; ")
	line += fmt.Sprintf(" (%d steered", s.SegmentCounters.Steered)
	if s.SegmentCounters.Unsteered > 0 {
		line += fmt.Sprintf(", %d too large to encapsulate", s.SegmentCounters.Unsteered)
	}
	if s.SegmentCounters.Unrouted > 0 {
		line += fmt.Sprintf(", %d with no route to their first segment", s.SegmentCounters.Unrouted)
	}
	return line + ")"
}

func originateLine(routes []Originated) string {
	if len(routes) == 0 {
		return "none"
	}
	text := make([]string, 0, len(routes))
	for _, route := range routes {
		text = append(text, route.String())
	}
	return strings.Join(text, " ")
}

// RenderNeighbors writes the columns `birdc show babel neighbors` writes, plus
// the reverse cost and the two dataplane counters BIRD does not have.
func RenderNeighbors(w io.Writer, neighbors []Neighbor) {
	rows := make([][]string, 0, len(neighbors))
	for _, n := range neighbors {
		rows = append(rows, []string{
			n.Peer,
			upDown(n.Alive),
			cost(n.Cost),
			fmt.Sprint(n.Extra),
			optionalCost(n.ReportedCost),
			optionalDuration(n.RTT),
			fmt.Sprint(n.Routes),
			shortDuration(time.Duration(n.Expires)),
			fmt.Sprint(n.Dropped),
			fmt.Sprint(n.SendFailed),
		})
	}
	table(w, []string{"Peer", "State", "Cost", "Extra", "Rx cost", "RTT", "Routes", "Expires", "Dropped", "Failed"}, rows)
}

// RenderRoutes writes the mesh route table, one line per prefix.
func RenderRoutes(w io.Writer, routes []Route) {
	rows := make([][]string, 0, len(routes))
	for _, r := range routes {
		from := ""
		if r.From.IsValid() {
			from = r.From.String()
		}
		via := r.Via
		if via == "" {
			via = "unreachable"
		}
		if r.Originated || r.Assigned {
			via = "this node"
		}
		rows = append(rows, []string{
			r.Destination.String(),
			from,
			via,
			cost(r.Metric),
			r.RouterID,
			fmt.Sprint(r.Seqno),
			fmt.Sprint(r.Candidates),
		})
	}
	table(w, []string{"Destination", "From", "Via", "Metric", "Router ID", "Seqno", "Paths"}, rows)
}

// RenderWhois writes where an address goes: the sentence naming the prefix
// that covers it and the peer this node reaches it through, then every
// covering prefix so a reader sees what it would fall back to.
//
// It names the peer rather than the originating node, because Babel carries a
// router id and no name, and the id is a random one each node draws, which a
// ranet3 node keeps in its state directory. The next hop is the origin only
// where the origin is a neighbor, so the column is called via and the router
// id is printed as it arrives.
func RenderWhois(w io.Writer, address netip.Addr, covering []Route) {
	if len(covering) == 0 {
		fmt.Fprintf(w, "%s is in no prefix this mesh carries\n", address)
		return
	}
	best := covering[0]
	switch {
	case best.Originated:
		fmt.Fprintf(w, "%s is in %s originated by this node\n", address, best.Destination)
	case best.Assigned:
		fmt.Fprintf(w, "%s is in %s assigned to this node\n", address, best.Destination)
	case best.Via == "":
		fmt.Fprintf(w, "%s is in %s held unreachable\n", address, best.Destination)
	default:
		fmt.Fprintf(w, "%s is in %s via %s\n", address, best.Destination, best.Via)
	}
	fmt.Fprintln(w)
	RenderRoutes(w, covering)
}

// RenderExitNodes writes the defaults the mesh offers and which of them this
// node would use, which is `tailscale exit-node list` over the route table.
//
// One row per prefix and source, because that pair is the route table's key
// and an exit announces its default from its own transit prefix. The state
// column is the answer a reader came for: a default with a next hop is one
// this node's traffic can take, and one without is an exit that has withdrawn.
func RenderExitNodes(w io.Writer, defaults []Route) {
	if len(defaults) == 0 {
		fmt.Fprintln(w, "No node advertises a default route")
		return
	}
	rows := make([][]string, 0, len(defaults))
	for _, route := range defaults {
		from := ""
		if route.From.IsValid() {
			from = route.From.String()
		}
		rows = append(rows, []string{
			route.Destination.String(),
			from,
			exitVia(route),
			cost(route.Metric),
			route.RouterID,
			fmt.Sprint(route.Candidates),
			exitState(route),
		})
	}
	table(w, []string{"Destination", "From", "Via", "Metric", "Router ID", "Paths", "State"}, rows)
}

func exitVia(route Route) string {
	switch {
	case route.Originated:
		return "this node"
	case route.Via == "":
		return "unreachable"
	}
	return route.Via
}

// exitState says which default this node would actually take. An originated
// one is this node's own advertisement rather than a choice it made, so it is
// named as that instead of as a selection.
func exitState(route Route) string {
	switch {
	case route.Originated:
		return "advertised by this node"
	case route.Via == "":
		return "withdrawn"
	}
	return "selected"
}

// RenderAddresses writes this node's mesh addresses, one per line and nothing
// else, so the output goes into a shell variable without being cut up first.
func RenderAddresses(w io.Writer, addresses []netip.Addr) {
	for _, address := range addresses {
		fmt.Fprintln(w, address)
	}
}

// RenderSessions writes the live IKE SAs with the transforms each runs
// `swanctl --list-sas` answered the same while strongSwan carried them
func RenderSessions(w io.Writer, sessions []Session) {
	rows := make([][]string, 0, len(sessions))
	for _, s := range sessions {
		// as ike.suite.unlisted names a Child SA's suite
		esp := suite(s.ESPCipher)
		if s.ESPKex != "" {
			esp = suite(s.ESPCipher, s.ESPKex)
		}
		rows = append(rows, []string{
			s.Path,
			s.Peer,
			s.Remote,
			end(s.Preferred),
			upDown(s.Active),
			fmt.Sprintf("%08x/%08x", s.LocalSPI, s.RemoteSPI),
			suite(s.IKECipher, s.IKEPRF, s.IKEKex),
			fragments(s.IKEFragments, s.IKEFragmentThreshold),
			esp,
			shortDuration(time.Duration(s.Age)),
			shortDuration(time.Duration(s.Idle)),
			strconv.FormatUint(s.InvalidSPIReports, 10),
		})
	}
	table(w, []string{"Path", "Peer", "Remote", "End", "State", "SPI in/out", "IKE", "Fragments", "ESP", "Age", "Idle", "Invalid SPI"}, rows)
}

// fragments is the path's threshold, the largest IP datagram this end cuts a new IKE message to fit, or no where its ends did not both say they support RFC 7383 fragmentation
// it is the family's floor from a step that cuts a request down to it, taken on the path the request was readied or last cut on, which every send of it went on since, the step's own included, until a reset, and an answer cut within the datagrams of the request or repeat it answers goes below it
func fragments(supported bool, threshold int) string {
	if !supported {
		return "no"
	}
	return strconv.Itoa(threshold)
}

// suite joins an SA's transform names as cap.crypto spells them
// a daemon that reported none gets a dash
func suite(names ...string) string {
	if slices.Contains(names, "") {
		return "-"
	}
	return strings.Join(names, "/")
}

// RenderPeers writes what this node dials and whether a session holds each
func RenderPeers(w io.Writer, peers []Peer) {
	rows := make([][]string, 0, len(peers))
	for _, p := range peers {
		rows = append(rows, []string{p.Path, p.Peer, source(p.Generated), upDown(p.Connected)})
	}
	table(w, []string{"Path", "Peer", "From", "State"}, rows)
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func end(preferred bool) string {
	if preferred {
		return "initiator"
	}
	return "responder"
}

func source(generated bool) string {
	if generated {
		return "registry"
	}
	return "config"
}

// cost spells the infinite metric rather than printing 65535, which is a
// number an operator has to remember the meaning of.
func cost(metric uint16) string {
	if metric == 65535 {
		return "inf"
	}
	return fmt.Sprint(metric)
}

func optionalCost(metric *uint16) string {
	if metric == nil {
		return "-"
	}
	return cost(*metric)
}

func optionalDuration(d *Duration) string {
	if d == nil {
		return "-"
	}
	return shortDuration(time.Duration(*d))
}

// shortDuration rounds to something a person reads at a glance. Go's own
// String gives "1h3m0.5762s" for an uptime, where the seconds carry no
// information and the digits make two rows harder to compare.
// sinceText is a duration inside a sentence, where the unit is written out. A
// column keeps the compact form instead, to be scanned down rather than read,
// and to match what birdc prints.
//
// The unit is chosen after rounding rather than before, so 59.5 seconds reads
// as one minute rather than as sixty seconds.
func sinceText(d time.Duration) string {
	seconds := max(int(d.Round(time.Second).Seconds()), 0)
	if seconds < 60 {
		return countOf(seconds, "second")
	}
	minutes := (seconds + 30) / 60
	if minutes < 60 {
		return countOf(minutes, "minute")
	}
	return countOf((minutes+30)/60, "hour")
}

// Spelled writes a duration the way a sentence carries one, to the millisecond with its unit written out
// it keeps the milliseconds sinceText leaves out, which a wait is measured in
func Spelled(d time.Duration) string {
	d = d.Round(time.Millisecond)
	// the whole milliseconds over 1000 print as the decimal they are, where Seconds adds the fraction in floating point
	value, unit := strconv.FormatFloat(float64(d.Milliseconds())/1000, 'f', -1, 64), "second"
	switch {
	case d < time.Second:
		value, unit = strconv.FormatInt(d.Milliseconds(), 10), "millisecond"
	case d%time.Hour == 0:
		value, unit = strconv.FormatInt(int64(d/time.Hour), 10), "hour"
	case d%time.Minute == 0:
		value, unit = strconv.FormatInt(int64(d/time.Minute), 10), "minute"
	}
	if value != "1" {
		unit += "s"
	}
	return value + " " + unit
}

func countOf(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}

// shortDuration rounds to something a person reads at a glance. Go's own
// String gives "1h3m0.5762s" for an uptime, where the seconds carry no
// information and the digits make two rows harder to compare.
func shortDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "-"
	case d < time.Second:
		return d.Round(100 * time.Microsecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
