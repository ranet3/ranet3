---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-29
order: 90
---

`--metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on
its own listener, separate from `--pprof` so a fleet node can be scraped without
exposing a profiler. The flag is empty by default, which serves no listener.
`ranet3 metrics` prints the same scrape over the
[control socket](control-socket.md), with or without the listener.

It reports neighbor liveness and link cost, routes received per neighbor, routes
selected and originated, established sessions per path, packets each peer chose
not to send, inbound ESP packet and drop counters, and the
[sockets connected to 1 peer](platforms.md#sockets-connected-to-1-peer) with
those that failed and handed their peer back to the shared socket.

It also reports 3 subsystems that run inside the daemon. The route reconciler is
reported as routes installed and skipped, when its last pass finished, whether
that pass failed and, on Linux, the overlay prefixes and endpoints another
program's rule takes. Segment routing is reported as what this node did for
peers (forwarded, delivered, dropped, answered, and for an egress segment
egressed, refused and not ready) and what it did with its own traffic (steered,
and dropped with a reason). `cap.egress` is reported as rules installed,
connections translated and connections a class of `none` left untranslated,
packets refused past their source's share and packets dropped with no tracked
flow in each family, the host's connection table against its maximum, other
translation found at the same hook, when its last pass finished and whether that
pass failed, whether each family is [ready](exit-nodes.md#readiness), and the 2
prefix counts whose difference says this node is withholding an advertisement it
cannot stand behind. The refused and dropped counts are read from the limit
chain's rules at each pass, so they lag by up to 1 pass, and a rewrite of the
chains starts them from 0, which a scrape reads as a counter reset. A pass that
cannot read them back keeps the last pass's, unless it rewrote the chains, whose
counts start from 0 whether or not it read them back.

[The border filter](border-filter.md) is reported as whether its chain reads
back and the packets each of its drops counted, by `reason`: `overlay_source` in
both families, and `routing_header` and `sid_destination` in `ipv6`. The counts
are read from the chain at each pass, so they lag by up to 1 pass, and a rewrite
of the chain starts them from 0, which a scrape reads as a counter reset.

A node without `cap.table` writes none of the reconciler's series, a node
without `cap.egress` writes none of the egress series, and a node without
`cap.border` writes none of the border's. Zeros there would read as a subsystem
installing nothing. Segment routing writes its series on every node, zeros
included.

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. A counter cannot carry the
route table. `ranet3 routes` reads it, with each prefix's next hop, from the
control socket.

## Series

The `peer` label is the path of the peer's session, such as
`example/gateway:0@0`. A series labeled by `peer` lasts as long as that session.
`ranet3_session_up` names the same path in `path`.

| Metric                                   | Type    | Labels               | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Written                                                         |
| ---------------------------------------- | ------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `ranet3_babel_neighbor_up`               | gauge   | `peer`               | 1 while the Babel neighbor is alive, 0 otherwise                                                                                                                                                                                                                                                                                                                                                                                                                | per neighbor                                                    |
| `ranet3_babel_neighbor_cost`             | gauge   | `peer`               | Link cost to the neighbor, `cap.babel.cost.extra` included, 65535 for infinity                                                                                                                                                                                                                                                                                                                                                                                  | per neighbor                                                    |
| `ranet3_babel_routes_received`           | gauge   | `peer`               | Routes learned from the neighbor, selected or not                                                                                                                                                                                                                                                                                                                                                                                                               | per neighbor                                                    |
| `ranet3_peer_send_dropped_total`         | counter | `peer`               | Packets this node chose not to send to the peer                                                                                                                                                                                                                                                                                                                                                                                                                 | per neighbor                                                    |
| `ranet3_peer_send_delay_dropped_total`   | counter | `peer`               | The part of `ranet3_peer_send_dropped_total` dropped for the delay through the peer's queue                                                                                                                                                                                                                                                                                                                                                                     | per neighbor                                                    |
| `ranet3_peer_send_failed_total`          | counter | `peer`               | Packets sealed for the peer that the transport then lost                                                                                                                                                                                                                                                                                                                                                                                                        | per neighbor                                                    |
| `ranet3_babel_reassembled_total`         | counter | `peer`               | Babel packets the neighbor's session sent in fragments that this node read                                                                                                                                                                                                                                                                                                                                                                                      | per neighbor whose session sent a fragment                      |
| `ranet3_babel_reassembled_largest_bytes` | gauge   | `peer`               | The largest of them, a whole IPv6 packet with its headers                                                                                                                                                                                                                                                                                                                                                                                                       | per neighbor whose session sent a fragment                      |
| `ranet3_babel_reassembly_dropped_total`  | counter | `peer`, `reason`     | Fragmented Babel packets dropped instead of read                                                                                                                                                                                                                                                                                                                                                                                                                | per neighbor whose session sent a fragment, 1 series per reason |
| `ranet3_babel_routes_selected`           | gauge   | none                 | Routes selected into the mesh forwarding table                                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_babel_routes_originated`         | gauge   | none                 | Prefixes this node announces                                                                                                                                                                                                                                                                                                                                                                                                                                    | always                                                          |
| `ranet3_session_up`                      | gauge   | `path`               | 1 for an established IKE session                                                                                                                                                                                                                                                                                                                                                                                                                                | per live session                                                |
| `ranet3_sessions`                        | gauge   | none                 | Established IKE sessions                                                                                                                                                                                                                                                                                                                                                                                                                                        | always                                                          |
| `ranet3_esp_inbound_packets_total`       | counter | none                 | ESP packets that authenticated and passed validation, Babel and dummy packets included                                                                                                                                                                                                                                                                                                                                                                          | always                                                          |
| `ranet3_esp_inbound_dropped_total`       | counter | none                 | ESP packets that failed to decrypt or validate, or that reached their session on an SPI it holds with no SA installed                                                                                                                                                                                                                                                                                                                                           | always                                                          |
| `ranet3_receive_dropped_total`           | counter | none                 | Inbound datagrams a full receive queue refused                                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_receive_refused_total`           | counter | none                 | Inbound datagrams nothing on this node wanted, such as one naming no SPI it holds, which a session may also tell its peer of when it came from the peer's address and port: at most 1 SPI from each look and 1 look every 10 seconds for the whole node, none while a request of the session's is outstanding, and none within 10 seconds of the SPI's retirement, as [protocol deviations](design/protocol-deviations.md#errors-outside-an-exchange) describes | always                                                          |
| `ranet3_receive_keepalives_total`        | counter | none                 | NAT keepalives (RFC 3948) received and ignored                                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_transport_pair_sockets`          | gauge   | none                 | Sockets open or opening that are connected to 1 busy peer each                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_transport_pair_fallbacks_total`  | counter | none                 | Sockets connected to 1 peer that a send or a read failed on, whose pairs went back to the shared socket                                                                                                                                                                                                                                                                                                                                                         | always                                                          |
| `ranet3_tun_reads_truncated_total`       | counter | none                 | Reads off the tun that lost the tail of a GSO frame                                                                                                                                                                                                                                                                                                                                                                                                             | always                                                          |
| `ranet3_tun_frames_refused_total`        | counter | none                 | Frames read off the tun that could not be read as packets                                                                                                                                                                                                                                                                                                                                                                                                       | always                                                          |
| `ranet3_packet_too_big_sent_total`       | counter | none                 | Packet Too Big and fragmentation needed answers this node sent                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_icmp_withheld_total`             | counter | `limit`              | ICMP errors this node did not send, by the limit that held them back, `source` for the bucket of the source answered or `node` for the node's cap                                                                                                                                                                                                                                                                                                               | always                                                          |
| `ranet3_mss_clamped_total`               | counter | none                 | TCP SYNs whose MSS this node lowered                                                                                                                                                                                                                                                                                                                                                                                                                            | always                                                          |
| `ranet3_pmtu_probes_total`               | counter | `result`             | Path MTU probes that left, `acked` or `lost`                                                                                                                                                                                                                                                                                                                                                                                                                    | always                                                          |
| `ranet3_segments_forwarded_total`        | counter | none                 | Packets an End behavior sent on to their next segment                                                                                                                                                                                                                                                                                                                                                                                                           | always                                                          |
| `ranet3_segments_delivered_total`        | counter | none                 | Packets an End.DT46 behavior decapsulated and handed to the forwarding decision                                                                                                                                                                                                                                                                                                                                                                                 | always                                                          |
| `ranet3_segments_dropped_total`          | counter | none                 | Packets to one of this node's segments that it would not act on                                                                                                                                                                                                                                                                                                                                                                                                 | always                                                          |
| `ranet3_segments_answered_total`         | counter | none                 | ICMP errors sent for dropped packets                                                                                                                                                                                                                                                                                                                                                                                                                            | always                                                          |
| `ranet3_segments_egressed_total`         | counter | none                 | Packets an egress segment handed to the exit to leave the mesh                                                                                                                                                                                                                                                                                                                                                                                                  | always                                                          |
| `ranet3_segments_refused_total`          | counter | none                 | Packets a SID refused, from outside the overlay or an egress segment's allow list, or an egress segment's inner packet whose source it cannot read, that no router forwards, that the mesh routes no reply to or whose destination lies inside the overlay or the mesh routes itself, counted dropped, and never answered                                                                                                                                       | always                                                          |
| `ranet3_segments_not_ready_total`        | counter | none                 | Packets an egress segment let through and threw away because their family was not ready, not counted among the dropped                                                                                                                                                                                                                                                                                                                                          | always                                                          |
| `ranet3_steered_total`                   | counter | none                 | This node's own packets a steering policy encapsulated                                                                                                                                                                                                                                                                                                                                                                                                          | always                                                          |
| `ranet3_steer_dropped_total`             | counter | `reason`             | Packets a steering policy claimed and this node did not send, `too_large` or `no_route`                                                                                                                                                                                                                                                                                                                                                                         | always                                                          |
| `ranet3_transit_packets_total`           | counter | `decision`, `reason` | Packets the forwarding decision took, by what became of them, and the ICMP errors it sent or could not send about them, as [transit counters](#transit-counters) lists                                                                                                                                                                                                                                                                                          | always                                                          |
| `ranet3_kernel_routes_installed`         | gauge   | none                 | Routes the kernel holds for the reconciler as of its last pass                                                                                                                                                                                                                                                                                                                                                                                                  | with `cap.table`                                                |
| `ranet3_kernel_routes_skipped`           | gauge   | none                 | Routes the platform refused in the last pass, and cover members left out with their family                                                                                                                                                                                                                                                                                                                                                                      | with `cap.table`                                                |
| `ranet3_kernel_pass_timestamp_seconds`   | gauge   | none                 | Unix time the last pass finished, 0 before the first                                                                                                                                                                                                                                                                                                                                                                                                            | with `cap.table`                                                |
| `ranet3_kernel_pass_failed`              | gauge   | none                 | 1 when the last pass reported an error                                                                                                                                                                                                                                                                                                                                                                                                                          | with `cap.table`                                                |
| `ranet3_kernel_overlay_taken`            | gauge   | `family`             | Overlay prefixes the reconciler's last answered lookups found taken, as [sharing a host](coexistence.md#another-programs-rules) describes                                                                                                                                                                                                                                                                                                                       | on Linux, per family those lookups asked an overlay prefix in   |
| `ranet3_kernel_underlay_taken`           | gauge   | `family`             | Live peer endpoints whose lookup under the underlay's mark the reconciler's last answered lookups found answered through the tun                                                                                                                                                                                                                                                                                                                                | on Linux, per family those lookups asked an endpoint in         |
| `ranet3_egress_rules_installed`          | gauge   | none                 | Rules the host holds in this node's limit and translation chains as of its last pass                                                                                                                                                                                                                                                                                                                                                                            | with `cap.egress`                                               |
| `ranet3_egress_prefixes`                 | gauge   | `state`              | Prefixes this node offers to carry (`advertised`) and those it announces (`announced`)                                                                                                                                                                                                                                                                                                                                                                          | with `cap.egress`                                               |
| `ranet3_egress_flows_total`              | counter | none                 | Connections the translation rules rewrote                                                                                                                                                                                                                                                                                                                                                                                                                       | with `cap.egress`                                               |
| `ranet3_egress_untranslated_flows_total` | counter | none                 | Connections a class of `none` left under the source they carry                                                                                                                                                                                                                                                                                                                                                                                                  | with `cap.egress`                                               |
| `ranet3_egress_refused_total`            | counter | `family`             | Packets refused because their source held as many open flows as `cap.egress.flows_per_source` lets it, each retry of a refused flow counted, answered Host Unreachable over IPv4 and administratively prohibited over IPv6                                                                                                                                                                                                                                      | with `cap.egress`                                               |
| `ranet3_egress_dropped_total`            | counter | `family`             | Packets out of the mesh, and into it under `return`, dropped because no flow is tracked for them, which a rule that translates would otherwise send on under their own source                                                                                                                                                                                                                                                                                   | with `cap.egress`                                               |
| `ranet3_egress_conntrack_entries`        | gauge   | none                 | Entries the host's connection tracking table holds, which each source's share comes out of                                                                                                                                                                                                                                                                                                                                                                      | with `cap.egress`, once the pass reads the table                |
| `ranet3_egress_conntrack_max`            | gauge   | none                 | The most entries the host's connection tracking table takes, `net.netfilter.nf_conntrack_max`, read on each pass and never written. [What connection tracking evicts from a full table](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1663) is the kernel's                                                                                            | with `cap.egress`, once the pass reads the table                |
| `ranet3_egress_conflicts`                | gauge   | none                 | Other source translation at the same hook at this node's priority or below, which can run ahead of this node's                                                                                                                                                                                                                                                                                                                                                  | with `cap.egress`                                               |
| `ranet3_egress_pass_timestamp_seconds`   | gauge   | none                 | Unix time the last pass finished, 0 before the first                                                                                                                                                                                                                                                                                                                                                                                                            | with `cap.egress`                                               |
| `ranet3_egress_pass_failed`              | gauge   | none                 | 1 when the last pass reported an error                                                                                                                                                                                                                                                                                                                                                                                                                          | with `cap.egress`                                               |
| `ranet3_egress_ready`                    | gauge   | `family`             | 1 while this node carries the family out of the mesh translated, which egress of that family waits for in both modes, as [readiness](exit-nodes.md#readiness) says                                                                                                                                                                                                                                                                                              | with `cap.egress`                                               |
| `ranet3_border_ready`                    | gauge   | none                 | 1 while the border filter's chain reads back as the configuration asks                                                                                                                                                                                                                                                                                                                                                                                          | with `cap.border`                                               |
| `ranet3_border_dropped_packets_total`    | counter | `reason`, `family`   | Packets from outside the mesh the border filter dropped, as of its last pass                                                                                                                                                                                                                                                                                                                                                                                    | with `cap.border`                                               |

`ranet3_babel_neighbor_cost` holds the amount `cap.babel.cost.extra` charges the
neighbor, and no series reports that amount alone. It is configuration rather
than a measurement, and the neighbor view shows it apart, in the Extra column of
`ranet3 neighbors` and in the `extra` field of `/v0/neighbors`.

`ranet3_egress_ready` takes the place of `ranet3_egress_device_ready`, which is
gone together with `ranet3_segments_drained_total`: an egress segment hands its
inner packets to the exit, which writes them into the mesh tun, so no device of
its own is left to report on. A query naming the old gauge reads no series, and
one reading the new gauge sees it on every node with `cap.egress`, since
readiness holds back both modes.

## Transit counters

`ranet3_transit_packets_total` counts what the
[forwarding decision](routing.md#transit) did with each packet a session
delivered that no segment of this node took, and each read off the tun it
dropped for a multicast destination or the limited broadcast, or at the mesh's
edge, where it checks what the tun hands this node before the packet enters the
mesh. `decision` is `forwarded`, `delivered`, `dropped`, `answered` or
`unanswered`, and `reason` names why a packet was dropped and is empty for every
other decision. The dropped series sum to the packets dropped. `answered` also
counts each answer to a read off the tun that no route reaches or a hold holds,
a read counted under no other decision.

| `decision`   | `reason`          | Counts                                                                                                                                                                                                                 |
| ------------ | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `forwarded`  |                   | packets sent on to a peer, one cut into fragments counted once                                                                                                                                                         |
| `delivered`  |                   | packets written to the tun, for this node's own destinations, IPv6 link-local ones, multicast and the limited broadcast, or handed to the exit through a prefix `cap.egress` advertises that counts as a default       |
| `dropped`    | `expired`         | packets whose hop limit or TTL ran out here                                                                                                                                                                            |
| `dropped`    | `no_route`        | packets no entry of the table holds                                                                                                                                                                                    |
| `dropped`    | `held`            | packets inside a prefix held unreachable                                                                                                                                                                               |
| `dropped`    | `refused`         | packets for another node while `cap.transit` is off                                                                                                                                                                    |
| `dropped`    | `invalid`         | frames holding no whole IP packet, IPv4 headers failing their checks, IPv4 options that cannot be read, and tun reads whose header chain runs past 16 headers or ends inside one, or whose inner packet cannot be read |
| `dropped`    | `martian`         | packets from or to an address no router forwards, but those to an IPv6 link-local address, multicast or the limited broadcast                                                                                          |
| `dropped`    | `source_route`    | IPv4 packets carrying a loose or strict source route                                                                                                                                                                   |
| `dropped`    | `unrouted_source` | packets an exit would egress, through a route that counts as a default, whose source the mesh routes no reply to                                                                                                       |
| `dropped`    | `not_ready`       | packets an exit would egress through a prefix `cap.egress` advertises, while it announces no prefix of that family                                                                                                     |
| `dropped`    | `too_big`         | packets larger than the session to their next hop, answered or past cutting                                                                                                                                            |
| `dropped`    | `multicast`       | reads off the tun to a multicast destination or the limited broadcast, which the mesh forwards none of                                                                                                                 |
| `dropped`    | `forged`          | reads off the tun from a source the table routes to another node or holds unreachable, through a route that does not count as a default, or an overlay source this node does not own                                   |
| `dropped`    | `routing_header`  | reads off the tun walked to a routing header of type 0, 1 or 4, or a routing type ranet3 does not recognize                                                                                                            |
| `dropped`    | `sid`             | reads off the tun addressed to one of this node's own SIDs                                                                                                                                                             |
| `dropped`    | `unowned_source`  | reads off the tun toward an entry that counts as a default, from a source this node does not own                                                                                                                       |
| `dropped`    | `nested`          | reads off the tun whose inner packet, opened one level deep, carries another IP packet inside                                                                                                                          |
| `dropped`    | `looped`          | reads off the tun the table answers as this node's own, which the mesh could only hand back to the tun                                                                                                                 |
| `answered`   |                   | ICMP errors sent about dropped packets                                                                                                                                                                                 |
| `unanswered` |                   | dropped packets the decision would answer that find no address of their family to come from                                                                                                                            |

`unanswered` counts a drop before the rules that keep an error from answering a
packet, such as one about an ICMP error or to a group, and before the rate
limits, so it counts a drop that would have drawn no answer with an address too.
A drop from a source only this node's own default reaches counts only under its
reason, before any address is looked for, and so does a drop whose answer is
built and finds no route back. An ICMP error a rate limit held back counts in
neither `answered` nor `unanswered`, and `ranet3_icmp_withheld_total` counts it,
as [path MTU](#path-mtu) says. Every series is written from startup, at 0 on a
node that forwarded nothing. `ranet3 status` shows the same counts on its
`Transit` line.

## Tun reads

`ranet3_tun_reads_truncated_total` counts reads off the tun that lost the tail
of a GSO frame, because the frame split into more packets than 1 read holds.
Only Linux hands the tun GSO frames, so the counter stays at 0 elsewhere. There
ranet3 sets the device's `gso_max_segs` to that read batch, 128 packets,
whenever it creates the device or attaches to one, which has the kernel split a
larger frame before it reaches the tun and keeps the counter at 0. A kernel that
refuses the setting leaves a warning in the log at startup, and a sender with a
small MSS then cuts reads short. Each such read loses the rest of its frame,
which TCP sends again, and the reader goes on. A warning carries their count
since the previous warning, at most once every 30 seconds.

`ranet3_tun_frames_refused_total` counts frames the tun handed over that could
not be read as packets, and each such frame is lost alone while the reader goes
on. On Linux that is a frame whose virtio-net header does not describe its
packet, which a sender that writes the header itself, as through an `AF_PACKET`
socket, can produce, or one the kernel could not copy out. A warning and a
`netstack.tun.refused` event carry their count since the previous warning, at
most once every 30 seconds. Any other error reading the tun means the device is
gone, and the node then stops as
[the service](service.md#restarts-and-the-network) describes.

## Packets a peer did not send

`ranet3_peer_send_dropped_total` counts, per peer, every packet this node chose
not to send. A peer holds packets from the read that brought them to the
transmit that carries them within a budget of its own, which
[the design's limits](design/limits.md) give. A read that does not fit is
dropped whole rather than waited for, so a peer whose transport falls behind
never holds up another. The counter also takes the packets of a peer that was
closing, of reservations its outbound SA refused and of batches that failed to
seal, and the packets the delay control drops.
`ranet3_peer_send_delay_dropped_total` is that last part on its own. Each peer's
sender measures how long every data batch has waited since it was reserved, and
once that delay has stayed above 5 milliseconds for 100 milliseconds it drops 1
packet at the head of the queue on the schedule CoDel (RFC 8289) sets, until a
batch comes through below 5 milliseconds again or the queue empties. Babel's own
packets wait in the same queue, but the delay control neither measures nor drops
them. The sender records each start and end of that state as an event,
`netstack.codel.dropping` and `netstack.codel.drained`, which
[the debug tree](development/debug.md) shows.

Delay drops say the queue toward that peer stands. This node cannot seal and
send for that peer as fast as traffic for it arrives, because its CPU, its
socket or the path falls behind. TCP senders are told to slow down, as a
router's queue would tell them. The delay runs from the reservation, which makes
it count the seal and the wait for the encryption workers every peer shares. On
a node whose CPU is saturated, delay drops tend to show on every busy peer
together, and they mean this node cannot seal and send as fast as traffic is
offered, not that a path is slow. The rest of the counter, the total less the
delay drops, counts the reads the budget refused, together with a closing peer's
packets, reservations the outbound SA refused and batches that failed to seal.
The last 2 leave a `netstack send batch failed` warning in the log and a closing
peer ends its session, so the rest climbing on a live session without that
warning is the budget refusing reads: a burst, a CPU that cannot keep the peer's
sender running, or a transport that stopped taking packets for longer than the
budget lasts. `ranet3_peer_send_failed_total` stays apart from all of these:
those packets were sealed and the transport lost them, which is the link failing
rather than this node choosing.

## Path MTU

`ranet3_packet_too_big_sent_total` counts the answers this node sent to packets
larger than their session carries, Packet Too Big over IPv6 and fragmentation
needed over IPv4 with DF, read off the tun or carried to a waypoint, and
`ranet3_mss_clamped_total` the TCP SYNs whose MSS it lowered to what their
session carries. Both count for the node as a whole. `ranet3_pmtu_probes_total`
counts the probes of the sessions' path MTU that left, by `result`: `acked`, or
`lost` when no Ack came within the time a probe waits, and
[debugging](development/debug.md) says which probes count in neither. Lost
probes climbing on a node whose sessions have settled say a path loses its
session's largest packets now and then, and
[`ranet3 debug pmtu`](development/debug.md) names the session and shows its
search. [Path MTU](path-mtu.md) describes the search itself.

`ranet3_icmp_withheld_total` counts the ICMP errors the
[rate limits](path-mtu.md#packets-that-do-not-fit) held back, as the kernel's
`IcmpOutRateLimitHost` and `IcmpOutRateLimitGlobal` do. `limit="source"` rising
alone is a sender drawing past its own bucket, such as a flood of expired
probes, and costs no other sender anything. `limit="node"` rising is answers
past the node's cap, from many sources at once or from one sender's packets past
their session, since Packet Too Big and fragmentation needed draw from the cap
alone. Either way the cap holds back every sender's answers, Packet Too Big
included.

## Babel fragments

`ranet3_babel_reassembled_total` counts, per neighbor, the Babel packets its
session sent in fragments that this node put back together and read, and
`ranet3_babel_reassembled_largest_bytes` is the largest of them, a whole IPv6
packet with its headers. `ranet3_babel_reassembly_dropped_total` counts the
datagrams dropped instead, by `reason`:

| Reason      | Meaning                                                                                                                                                                           |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `overlap`   | A fragment overlapped another.                                                                                                                                                    |
| `header`    | A first fragment lacked the UDP header.                                                                                                                                           |
| `malformed` | A fragment was wrong in itself, or the speaker refused the whole packet.                                                                                                          |
| `timeout`   | A datagram was still incomplete 16 seconds after its first fragment.                                                                                                              |
| `evicted`   | A datagram at least 1 second old gave its place or its storage to another datagram of the same neighbor.                                                                          |
| `refused`   | A datagram found no storage, or a fragment found no place, while the neighbor's other datagrams, all younger than 1 second, held them. Each fragment refused a place counts once. |

A neighbor flooding fragments of datagrams that never complete has the node hold
under 280 KiB and allocate under 2 MiB a second. The node evicts and refuses
only that neighbor's datagrams. A neighbor that sent no fragment has none of the
3 series, so the series name exactly the neighbors whose stacks cut their
packets. [The protocol deviations](design/protocol-deviations.md) say which
fragments the speaker takes and the bounds it holds each neighbor to. The first
packet a session sent in fragments is recorded as a `babel.neighbor.fragmented`
event as well, which [the debug tree](development/debug.md) shows.
