// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/babel"
)

// Metrics writes the Prometheus text exposition format, by hand rather than
// through a client library so the dependency list stays short.
//
// Everything here is read from live state at scrape time rather than sampled
// on a timer, so a scrape reflects the instant it happened.
func (c *Client) Metrics(w io.Writer) {
	stats := c.speaker.Stats()
	sessions := c.sessions.paths()

	fmt.Fprint(w, "# HELP ranet3_babel_neighbor_up Whether a babel neighbor is alive.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_neighbor_up gauge\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_babel_neighbor_up{peer=\"%s\"} %d\n", label(neighbor.Peer), boolValue(neighbor.Alive))
	}
	fmt.Fprint(w, "# HELP ranet3_babel_neighbor_cost Link cost to a babel neighbor, where 65535 is infinity.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_neighbor_cost gauge\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_babel_neighbor_cost{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Cost)
	}
	fmt.Fprint(w, "# HELP ranet3_babel_routes_received Routes learned from one neighbor, selected or not.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_routes_received gauge\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_babel_routes_received{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Routes)
	}
	fmt.Fprint(w, "# HELP ranet3_peer_send_dropped_total Packets a peer did not send: no room in its budget, the peer closing, its outbound SA unable to give out a sequence range, or the delay through its queue staying above the target.\n")
	fmt.Fprint(w, "# TYPE ranet3_peer_send_dropped_total counter\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_peer_send_dropped_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Dropped)
	}
	fmt.Fprint(w, "# HELP ranet3_peer_send_delay_dropped_total Packets of ranet3_peer_send_dropped_total a peer dropped from the head of its queue because the delay through it stayed above the target.\n")
	fmt.Fprint(w, "# TYPE ranet3_peer_send_delay_dropped_total counter\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_peer_send_delay_dropped_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.DelayDropped)
	}
	fmt.Fprint(w, "# HELP ranet3_peer_send_failed_total Packets a peer sealed and the transport then lost.\n")
	fmt.Fprint(w, "# TYPE ranet3_peer_send_failed_total counter\n")
	for _, neighbor := range stats.Neighbors {
		fmt.Fprintf(w, "ranet3_peer_send_failed_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.SendFailed)
	}
	renderReassembly(w, stats.Neighbors)
	fmt.Fprint(w, "# HELP ranet3_babel_routes_selected Routes currently installed in the forwarding table.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_routes_selected gauge\n")
	fmt.Fprintf(w, "ranet3_babel_routes_selected %d\n", stats.Selected)
	fmt.Fprint(w, "# HELP ranet3_babel_routes_originated Prefixes this node announces itself.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_routes_originated gauge\n")
	fmt.Fprintf(w, "ranet3_babel_routes_originated %d\n", stats.Originated)

	fmt.Fprint(w, "# HELP ranet3_session_up Whether an IKE session is established for one path.\n")
	fmt.Fprint(w, "# TYPE ranet3_session_up gauge\n")
	for _, path := range sessions {
		fmt.Fprintf(w, "ranet3_session_up{path=\"%s\"} 1\n", label(path))
	}
	fmt.Fprint(w, "# HELP ranet3_sessions Established IKE sessions.\n")
	fmt.Fprint(w, "# TYPE ranet3_sessions gauge\n")
	fmt.Fprintf(w, "ranet3_sessions %d\n", len(sessions))

	// Authenticated and validated, which is not the same as delivered: the
	// count includes babel control packets the speaker consumed, RFC 4303
	// section 2.6 dummy packets that carry nothing, and packets a closing mesh
	// discards.
	fmt.Fprint(w, "# HELP ranet3_esp_inbound_packets_total ESP packets that authenticated and passed validation, including babel control traffic and dummy packets.\n")
	fmt.Fprint(w, "# TYPE ranet3_esp_inbound_packets_total counter\n")
	fmt.Fprintf(w, "ranet3_esp_inbound_packets_total %d\n", c.inboundPackets.Load())
	fmt.Fprint(w, "# HELP ranet3_esp_inbound_dropped_total ESP packets that failed to decrypt or validate.\n")
	fmt.Fprint(w, "# TYPE ranet3_esp_inbound_dropped_total counter\n")
	fmt.Fprintf(w, "ranet3_esp_inbound_dropped_total %d\n", c.inboundDropped.Load())

	fmt.Fprint(w, "# HELP ranet3_tun_reads_truncated_total Reads off the tun that lost the tail of a GSO frame, because the frame split into more packets than one read holds.\n")
	fmt.Fprint(w, "# TYPE ranet3_tun_reads_truncated_total counter\n")
	fmt.Fprintf(w, "ranet3_tun_reads_truncated_total %d\n", c.Mesh.TUNReadsTruncated())
	fmt.Fprint(w, "# HELP ranet3_tun_frames_refused_total Frames read off the tun that the device could not decode into packets.\n")
	fmt.Fprint(w, "# TYPE ranet3_tun_frames_refused_total counter\n")
	fmt.Fprintf(w, "ranet3_tun_frames_refused_total %d\n", c.Mesh.TUNFramesRefused())

	c.renderPathMTU(w)
	c.renderReceiveCounters(w)
	c.renderPairSockets(w)
	c.renderSegmentCounters(w)
	c.renderTransitCounters(w)
	c.renderKernel(w)
	c.renderEgress(w)
	c.renderBorder(w)
}

// renderBorder writes the border filter's readiness and the packets each drop
// counted as its last pass read them, and nothing on a node with no cap.border
func (c *Client) renderBorder(w io.Writer) {
	border := c.borderStatus()
	if border == nil {
		return
	}
	fmt.Fprint(w, "# HELP ranet3_border_ready Whether the border filter's chain reads back as the configuration asks, which every family of the egress device waits for.\n")
	fmt.Fprint(w, "# TYPE ranet3_border_ready gauge\n")
	fmt.Fprintf(w, "ranet3_border_ready %d\n", boolValue(border.Ready))
	fmt.Fprint(w, "# HELP ranet3_border_dropped_packets_total Packets arriving from outside the mesh that the border filter dropped, by what they carried, as of its last pass. A rewrite of the chain starts them from zero.\n")
	fmt.Fprint(w, "# TYPE ranet3_border_dropped_packets_total counter\n")
	for _, row := range []struct {
		reason, family string
		packets        uint64
	}{
		{"overlay_source", "ipv4", border.Dropped.OverlaySourceIPv4},
		{"overlay_source", "ipv6", border.Dropped.OverlaySourceIPv6},
		{"routing_header", "ipv6", border.Dropped.RoutingHeader},
		{"sid_destination", "ipv6", border.Dropped.SIDDestination},
	} {
		fmt.Fprintf(w, "ranet3_border_dropped_packets_total{reason=\"%s\",family=\"%s\"} %d\n", row.reason, row.family, row.packets)
	}
}

// renderReassembly writes what became of the Babel packets each neighbor's session sent in fragments
// a neighbor whose session sent none has no samples, so the series name exactly the neighbors whose stacks cut their packets
func renderReassembly(w io.Writer, neighbors []babel.NeighborStat) {
	fragmenting := slices.DeleteFunc(slices.Clone(neighbors), func(neighbor babel.NeighborStat) bool {
		return neighbor.Fragments == babel.FragmentStats{}
	})
	fmt.Fprint(w, "# HELP ranet3_babel_reassembled_total Babel packets a neighbor's session sent in fragments that this node put back together and read.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_reassembled_total counter\n")
	for _, neighbor := range fragmenting {
		fmt.Fprintf(w, "ranet3_babel_reassembled_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Fragments.Read)
	}
	fmt.Fprint(w, "# HELP ranet3_babel_reassembled_largest_bytes The largest of them, a whole IPv6 packet with its headers.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_reassembled_largest_bytes gauge\n")
	for _, neighbor := range fragmenting {
		fmt.Fprintf(w, "ranet3_babel_reassembled_largest_bytes{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Fragments.Largest)
	}
	fmt.Fprint(w, "# HELP ranet3_babel_reassembly_dropped_total Babel packets a neighbor's session sent in fragments that this node dropped rather than read, by reason: a fragment overlapping another, a first fragment without the UDP header, a malformed fragment, a datagram still incomplete after its time, one that gave its place or its storage to another of the same neighbor, or one refused while the neighbor's other datagrams, all younger than 1 second, held every place or the storage it needed.\n")
	fmt.Fprint(w, "# TYPE ranet3_babel_reassembly_dropped_total counter\n")
	for _, neighbor := range fragmenting {
		for i, reason := range babel.FragmentDrops {
			fmt.Fprintf(w, "ranet3_babel_reassembly_dropped_total{peer=\"%s\",reason=\"%s\"} %d\n", label(neighbor.Peer), reason, neighbor.Fragments.Dropped[i])
		}
	}
}

// renderPathMTU writes what the node did to packets past a session's budget and how the sessions' probes of their path MTU ended
func (c *Client) renderPathMTU(w io.Writer) {
	fmt.Fprint(w, "# HELP ranet3_packet_too_big_sent_total Answers to packets past the budget of the session they were for: packet too big over IPv6 and fragmentation needed over IPv4 with DF.\n")
	fmt.Fprint(w, "# TYPE ranet3_packet_too_big_sent_total counter\n")
	fmt.Fprintf(w, "ranet3_packet_too_big_sent_total %d\n", c.Mesh.TooBigAnswered())
	source, node := c.Mesh.ICMPWithheld()
	fmt.Fprint(w, "# HELP ranet3_icmp_withheld_total ICMP errors this node did not send, by the limit that withheld them: the bucket of the source of the packet answered, or the cap over every answer.\n")
	fmt.Fprint(w, "# TYPE ranet3_icmp_withheld_total counter\n")
	fmt.Fprintf(w, "ranet3_icmp_withheld_total{limit=\"source\"} %d\n", source)
	fmt.Fprintf(w, "ranet3_icmp_withheld_total{limit=\"node\"} %d\n", node)
	fmt.Fprint(w, "# HELP ranet3_mss_clamped_total TCP SYNs whose MSS this node lowered to what their session carries.\n")
	fmt.Fprint(w, "# TYPE ranet3_mss_clamped_total counter\n")
	fmt.Fprintf(w, "ranet3_mss_clamped_total %d\n", c.Mesh.MSSClamped())
	fmt.Fprint(w, "# HELP ranet3_pmtu_probes_total Probes of the sessions' path MTU that left, by result: acked, or lost when no Ack came within the probe timeout.\n")
	fmt.Fprint(w, "# TYPE ranet3_pmtu_probes_total counter\n")
	fmt.Fprintf(w, "ranet3_pmtu_probes_total{result=\"acked\"} %d\n", c.probes.acked.Load())
	fmt.Fprintf(w, "ranet3_pmtu_probes_total{result=\"lost\"} %d\n", c.probes.lost.Load())
}

// renderEgress writes the exit node and subnet router capability. A node that
// carries nothing for anybody writes none of it, as with the reconciler.
//
// The advertised and announced counts are separate series rather than one
// gauge and a label, because their difference is the alert: a prefix is
// announced only while its chain reads back as written and the kernel
// forwards its family, so announced below advertised is this node declining
// to attract traffic it would drop, and no peer can see that from its own end.
func (c *Client) renderEgress(w io.Writer) {
	egress := c.egress()
	if !egress.Enabled {
		return
	}
	fmt.Fprint(w, "# HELP ranet3_egress_rules_installed Source translation rules the host holds for this node as of its last pass.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_rules_installed gauge\n")
	fmt.Fprintf(w, "ranet3_egress_rules_installed %d\n", egress.Installed)
	fmt.Fprint(w, "# HELP ranet3_egress_prefixes Prefixes this node offers to carry, and the ones it is announcing: announcing fewer is this node withholding a prefix whose rule is not installed or whose family the kernel will not forward.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_prefixes gauge\n")
	fmt.Fprintf(w, "ranet3_egress_prefixes{state=\"advertised\"} %d\n", len(egress.Advertise))
	fmt.Fprintf(w, "ranet3_egress_prefixes{state=\"announced\"} %d\n", len(egress.Announced))
	fmt.Fprint(w, "# HELP ranet3_egress_flows_total Connections the translation rules have rewritten. A nat chain is consulted once per connection, so this counts flows rather than packets.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_flows_total counter\n")
	fmt.Fprintf(w, "ranet3_egress_flows_total %d\n", egress.Flows)
	fmt.Fprint(w, "# HELP ranet3_egress_conflicts Other source translation at the same hook, which the first chain to claim a connection keeps.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_conflicts gauge\n")
	fmt.Fprintf(w, "ranet3_egress_conflicts %d\n", len(egress.Conflicts))
	fmt.Fprint(w, "# HELP ranet3_egress_pass_timestamp_seconds When the last pass finished, and zero before the first one has.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_pass_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "ranet3_egress_pass_timestamp_seconds %d\n", unixOrZero(egress.PassAt))
	fmt.Fprint(w, "# HELP ranet3_egress_pass_failed Whether the last pass reported an error.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_pass_failed gauge\n")
	fmt.Fprintf(w, "ranet3_egress_pass_failed %d\n", boolValue(egress.Err != ""))
	if egress.Device == "" {
		return
	}
	fmt.Fprint(w, "# HELP ranet3_egress_device_ready Whether the egress device carries a family out translated, which an egress segment's packets of that family wait for.\n")
	fmt.Fprint(w, "# TYPE ranet3_egress_device_ready gauge\n")
	fmt.Fprintf(w, "ranet3_egress_device_ready{family=\"ipv4\"} %d\n", boolValue(slices.Contains(egress.Ready, "ipv4")))
	fmt.Fprintf(w, "ranet3_egress_device_ready{family=\"ipv6\"} %d\n", boolValue(slices.Contains(egress.Ready, "ipv6")))
}

// The dataplane is this process rather than the kernel, so a scrape is the
// only place from which a steered path that stopped working can be seen.
//
// What this node did for a peer and what it did with its own traffic are
// separate series, because they fail for different reasons. A rising dropped
// means peers are sending packets this node will not act on, or the egress
// device is refusing writes, and a rising steer_dropped means this node's own
// policy is pointing somewhere the mesh cannot reach.
func (c *Client) renderSegmentCounters(w io.Writer) {
	segments := c.Mesh.SegmentCounters()
	fmt.Fprint(w, "# HELP ranet3_segments_forwarded_total Packets an End behavior sent on to their next segment.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_forwarded_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_forwarded_total %d\n", segments.Forwarded)
	fmt.Fprint(w, "# HELP ranet3_segments_delivered_total Packets an End.DT46 behavior took the outer header off and handed to the stack through the mesh tun.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_delivered_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_delivered_total %d\n", segments.Delivered)
	fmt.Fprint(w, "# HELP ranet3_segments_dropped_total Packets addressed to one of this node's segments that it would not act on, and egress packets the egress device refused while open.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_dropped_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_dropped_total %d\n", segments.Dropped)
	fmt.Fprint(w, "# HELP ranet3_segments_answered_total ICMP errors sent for dropped packets, which is the half of the dropped ones whose sender was told why.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_answered_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_answered_total %d\n", segments.Answered)
	fmt.Fprint(w, "# HELP ranet3_segments_egressed_total Packets an egress segment handed to the egress device.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_egressed_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_egressed_total %d\n", segments.Egressed)
	fmt.Fprint(w, "# HELP ranet3_segments_refused_total Packets a local SID refused for their source, an outer source outside cap.border overlay at any SID or, at an egress segment, a source outside its allow list, an inner source it cannot read, an inner packet no router forwards or one the mesh routes no reply to, which are among the dropped ones and never answered.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_refused_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_refused_total %d\n", segments.Refused)
	fmt.Fprint(w, "# HELP ranet3_segments_not_ready_total Packets an egress segment let through and no egress device took, because none was installed, it closed under the write or its family was not ready.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_not_ready_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_not_ready_total %d\n", segments.NotReady)
	fmt.Fprint(w, "# HELP ranet3_segments_drained_total Packets read off the egress device and thrown away, each one a route into the wrong device, leaving out the kernel's own to IPv6 multicast addresses of interface-local or link-local scope.\n")
	fmt.Fprint(w, "# TYPE ranet3_segments_drained_total counter\n")
	fmt.Fprintf(w, "ranet3_segments_drained_total %d\n", segments.Drained)
	fmt.Fprint(w, "# HELP ranet3_steered_total This node's own packets a steering policy encapsulated.\n")
	fmt.Fprint(w, "# TYPE ranet3_steered_total counter\n")
	fmt.Fprintf(w, "ranet3_steered_total %d\n", segments.Steered)
	fmt.Fprint(w, "# HELP ranet3_steer_dropped_total Packets a steering policy claimed and this node did not send: too large to encapsulate, or with no route to their first segment.\n")
	fmt.Fprint(w, "# TYPE ranet3_steer_dropped_total counter\n")
	fmt.Fprintf(w, "ranet3_steer_dropped_total{reason=\"too_large\"} %d\n", segments.Unsteered)
	fmt.Fprintf(w, "ranet3_steer_dropped_total{reason=\"no_route\"} %d\n", segments.Unrouted)
}

// renderTransitCounters writes the forwarding decision's counters as one series, decision saying what became of a packet and reason why one was dropped
// reason is empty for the decisions that are no drop
func (c *Client) renderTransitCounters(w io.Writer) {
	writeTransitCounters(w, transitCounters(c.Mesh.TransitCounters()))
}

func writeTransitCounters(w io.Writer, transit control.TransitCounters) {
	fmt.Fprint(w, "# HELP ranet3_transit_packets_total Packets the forwarding decision forwarded to a peer, delivered to the tun or dropped, by reason, and the ICMP errors it answered or could not answer them with.\n")
	fmt.Fprint(w, "# TYPE ranet3_transit_packets_total counter\n")
	fmt.Fprintf(w, "ranet3_transit_packets_total{decision=\"forwarded\",reason=\"\"} %d\n", transit.Forwarded)
	fmt.Fprintf(w, "ranet3_transit_packets_total{decision=\"delivered\",reason=\"\"} %d\n", transit.Delivered)
	for _, drop := range transit.Drops() {
		fmt.Fprintf(w, "ranet3_transit_packets_total{decision=\"dropped\",reason=\"%s\"} %d\n", drop.Label, drop.Packets)
	}
	fmt.Fprintf(w, "ranet3_transit_packets_total{decision=\"answered\",reason=\"\"} %d\n", transit.Answered)
	fmt.Fprintf(w, "ranet3_transit_packets_total{decision=\"unanswered\",reason=\"\"} %d\n", transit.Unanswered)
}

// renderKernel writes the route reconciler's last pass, the half of a node
// that bird_protocol_* reported for kbabel4 and kbabel6 while BIRD still ran
// here. A node whose reconciler is off writes none of it, rather than four
// zeroes that read as a reconciler doing nothing.
func (c *Client) renderKernel(w io.Writer) {
	kernel := c.kernel()
	if !kernel.Enabled {
		return
	}
	fmt.Fprint(w, "# HELP ranet3_kernel_routes_installed Routes the kernel holds for this reconciler as of its last pass.\n")
	fmt.Fprint(w, "# TYPE ranet3_kernel_routes_installed gauge\n")
	fmt.Fprintf(w, "ranet3_kernel_routes_installed %d\n", kernel.Installed)
	fmt.Fprint(w, "# HELP ranet3_kernel_routes_skipped Routes the platform refused in the last pass, and cover members left out with their family.\n")
	fmt.Fprint(w, "# TYPE ranet3_kernel_routes_skipped gauge\n")
	fmt.Fprintf(w, "ranet3_kernel_routes_skipped %d\n", kernel.Skipped)
	fmt.Fprint(w, "# HELP ranet3_kernel_pass_timestamp_seconds When the last pass finished, and zero before the first one has.\n")
	fmt.Fprint(w, "# TYPE ranet3_kernel_pass_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "ranet3_kernel_pass_timestamp_seconds %d\n", unixOrZero(kernel.PassAt))
	fmt.Fprint(w, "# HELP ranet3_kernel_pass_failed Whether the last pass reported an error.\n")
	fmt.Fprint(w, "# TYPE ranet3_kernel_pass_failed gauge\n")
	fmt.Fprintf(w, "ranet3_kernel_pass_failed %d\n", boolValue(kernel.Err != ""))
}

// unixOrZero is the unix time of a pass, and zero rather than a negative
// number before the first one, since the zero time predates the epoch by two
// millennia and an alert reading "older than five minutes" would be true of it
// either way.
func unixOrZero(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.Unix()
}

// renderReceiveCounters writes the three the hub keeps. They are separate
// series on purpose: a rising dropped means this node is behind on receive,
// which is the only signal there is for that. A rising refused means somebody
// is sending it datagrams it has nowhere to put. Keepalives are the RFC
// 3948 section 2.3 datagrams a NATed peer sends to hold its mapping open,
// which are expected rather than unwanted. Anyone who can reach the port can
// raise any of them, so none is a fault by itself, and mixing them would make
// the first two unreadable.
func (c *Client) renderReceiveCounters(w io.Writer) {
	fmt.Fprint(w, "# HELP ranet3_receive_dropped_total Inbound datagrams a full receive queue refused.\n")
	fmt.Fprint(w, "# TYPE ranet3_receive_dropped_total counter\n")
	fmt.Fprintf(w, "ranet3_receive_dropped_total %d\n", c.hubDropped())

	fmt.Fprint(w, "# HELP ranet3_receive_refused_total Inbound datagrams nothing here wanted: naming no SPI this node holds, too short or empty, for a full unclaimed queue, or with an unreadable control message or source.\n")
	fmt.Fprint(w, "# TYPE ranet3_receive_refused_total counter\n")
	fmt.Fprintf(w, "ranet3_receive_refused_total %d\n", c.hubRefused())

	fmt.Fprint(w, "# HELP ranet3_receive_keepalives_total Inbound RFC 3948 NAT keepalives, ignored on arrival.\n")
	fmt.Fprint(w, "# TYPE ranet3_receive_keepalives_total counter\n")
	fmt.Fprintf(w, "ranet3_receive_keepalives_total %d\n", c.hubKeepalives())
}

// hubDropped and hubRefused are zero before the hub exists, which is every
// call from a test that builds a Client by hand.
func (c *Client) hubDropped() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Dropped()
}

func (c *Client) hubRefused() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Refused()
}

func (c *Client) hubKeepalives() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Keepalives()
}

// renderPairSockets writes the sockets the hub holds connected to one busy peer each, under the prefix of their transport.pair events
// a fallback leaves its peer's sends on the shared socket, which carries them, until the next sweep
func (c *Client) renderPairSockets(w io.Writer) {
	sockets, fallbacks := c.hubPairs()
	fmt.Fprint(w, "# HELP ranet3_transport_pair_sockets Sockets open or opening that are connected to one busy peer each.\n")
	fmt.Fprint(w, "# TYPE ranet3_transport_pair_sockets gauge\n")
	fmt.Fprintf(w, "ranet3_transport_pair_sockets %d\n", sockets)

	fmt.Fprint(w, "# HELP ranet3_transport_pair_fallbacks_total Sockets connected to one peer that a send or a read failed on, whose pairs went back to the shared socket.\n")
	fmt.Fprint(w, "# TYPE ranet3_transport_pair_fallbacks_total counter\n")
	fmt.Fprintf(w, "ranet3_transport_pair_fallbacks_total %d\n", fallbacks)
}

// hubPairs is zero before the hub exists, as hubDropped is
func (c *Client) hubPairs() (sockets int, fallbacks uint64) {
	if c.hub == nil {
		return 0, 0
	}
	return c.hub.PairSockets(), c.hub.PairFallbacks()
}

// MetricsHandler serves Metrics, for mounting next to the pprof endpoint.
func (c *Client) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		c.Metrics(w)
	})
}

// label escapes a label value the way the Prometheus text exposition format
// defines it, which is three sequences and no others: a backslash, a double
// quote and a newline. Go's %q escapes every rune unicode.IsPrint rejects, as
// \t or \u00a0, and a scrape carrying one of those is refused whole rather
// than in part, so one tab or non-breaking space pasted into an organization
// or common name takes every series on the node out of monitoring. The values
// here are built from those names and from the identity a peer asserts.
func label(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func boolValue(b bool) int {
	if b {
		return 1
	}
	return 0
}

// paths is every path holding a live session, sorted so a scrape is stable.
func (s *sessionSet) paths() []string {
	s.mu.Lock()
	paths := make([]string, 0, len(s.live))
	for path := range s.live {
		paths = append(paths, path)
	}
	s.mu.Unlock()
	slices.Sort(paths)
	return paths
}

// countInbound is called once per decrypted batch rather than once per packet,
// so the hot path pays one atomic add per batch and nothing per packet. The
// refused half is noteInboundDropped's, which counts and reports together: two
// callers adding to one counter is how a batch gets counted twice.
func (c *Client) countInbound(delivered int) {
	if delivered > 0 {
		c.inboundPackets.Add(uint64(delivered))
	}
}

// noteInboundDropped reports ESP packets that did not survive decryption or
// validation, at most once an interval.
//
// The inbound SPI is cleartext in every datagram, so anyone who has seen one
// can send datagrams that are refused at the replay check, before any crypto,
// and a line per batch is a line per datagram. That write is synchronous, on
// the one goroutine that also hands babel its packets, and it takes the
// process-wide log mutex that babel, IKE and the kernel reconciler share:
// measured at 248,000 spoofed datagrams in one second drawing 156,000 lines
// and 24 MB of stderr for 15 MB on the wire, and withdrawing the mesh's route
// to this node in under four seconds. Hub.noteDrop and installRoute are the
// same limiter for the same reason.
func (c *Client) noteInboundDropped(peer string, count int, last error) {
	total := c.inboundDropped.Add(uint64(count))
	now := int64(time.Since(c.started))
	previous := c.dropReported.Load()
	if now-previous < int64(espDropReportInterval) || !c.dropReported.CompareAndSwap(previous, now) {
		return
	}
	slog.Warn("esp inbound packets dropped", "peer", peer, "dropped_total", total, "err", last)
}
