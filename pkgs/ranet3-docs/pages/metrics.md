---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-19
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
reported as routes installed and skipped, when its last pass finished and
whether that pass failed. Segment routing is reported as what this node did for
peers (forwarded, delivered, dropped, answered) and what it did with its own
traffic (steered, and dropped with a reason). `cap.egress` is reported as rules
installed, connections translated, other translation found at the same hook,
when its last pass finished and whether that pass failed, and the 2 prefix
counts whose difference says this node is withholding an advertisement it cannot
stand behind.

A node without `cap.table` writes none of the reconciler's series, and a node
without `cap.egress` writes none of the egress series. Zeros there would read as
a subsystem installing nothing. Segment routing writes its series on every node,
zeros included.

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. A counter cannot carry the
route table. `ranet3 routes` reads it, with each prefix's next hop, from the
control socket.

## Series

The `peer` label is the path of the peer's session, such as
`example/gateway:0@0`. A series labeled by `peer` lasts as long as that session.
`ranet3_session_up` names the same path in `path`.

| Metric                                   | Type    | Labels           | Meaning                                                                                                 | Written                                                         |
| ---------------------------------------- | ------- | ---------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| `ranet3_babel_neighbor_up`               | gauge   | `peer`           | 1 while the Babel neighbor is alive, 0 otherwise                                                        | per neighbor                                                    |
| `ranet3_babel_neighbor_cost`             | gauge   | `peer`           | Link cost to the neighbor, `cap.babel.cost.extra` included, 65535 for infinity                          | per neighbor                                                    |
| `ranet3_babel_routes_received`           | gauge   | `peer`           | Routes learned from the neighbor, selected or not                                                       | per neighbor                                                    |
| `ranet3_peer_send_dropped_total`         | counter | `peer`           | Packets this node chose not to send to the peer                                                         | per neighbor                                                    |
| `ranet3_peer_send_delay_dropped_total`   | counter | `peer`           | The part of `ranet3_peer_send_dropped_total` dropped for the delay through the peer's queue             | per neighbor                                                    |
| `ranet3_peer_send_failed_total`          | counter | `peer`           | Packets sealed for the peer that the transport then lost                                                | per neighbor                                                    |
| `ranet3_babel_reassembled_total`         | counter | `peer`           | Babel packets the neighbor's session sent in fragments that this node read                              | per neighbor whose session sent a fragment                      |
| `ranet3_babel_reassembled_largest_bytes` | gauge   | `peer`           | The largest of them, a whole IPv6 packet with its headers                                               | per neighbor whose session sent a fragment                      |
| `ranet3_babel_reassembly_dropped_total`  | counter | `peer`, `reason` | Fragmented Babel packets dropped instead of read                                                        | per neighbor whose session sent a fragment, 1 series per reason |
| `ranet3_babel_routes_selected`           | gauge   | none             | Routes selected into the mesh forwarding table                                                          | always                                                          |
| `ranet3_babel_routes_originated`         | gauge   | none             | Prefixes this node announces                                                                            | always                                                          |
| `ranet3_session_up`                      | gauge   | `path`           | 1 for an established IKE session                                                                        | per live session                                                |
| `ranet3_sessions`                        | gauge   | none             | Established IKE sessions                                                                                | always                                                          |
| `ranet3_esp_inbound_packets_total`       | counter | none             | ESP packets that authenticated and passed validation, Babel and dummy packets included                  | always                                                          |
| `ranet3_esp_inbound_dropped_total`       | counter | none             | ESP packets that failed to decrypt or validate                                                          | always                                                          |
| `ranet3_receive_dropped_total`           | counter | none             | Inbound datagrams a full receive queue refused                                                          | always                                                          |
| `ranet3_receive_refused_total`           | counter | none             | Inbound datagrams nothing on this node wanted, such as one naming no SPI it holds                       | always                                                          |
| `ranet3_receive_keepalives_total`        | counter | none             | NAT keepalives (RFC 3948) received and ignored                                                          | always                                                          |
| `ranet3_transport_pair_sockets`          | gauge   | none             | Sockets open or opening that are connected to 1 busy peer each                                          | always                                                          |
| `ranet3_transport_pair_fallbacks_total`  | counter | none             | Sockets connected to 1 peer that a send or a read failed on, whose pairs went back to the shared socket | always                                                          |
| `ranet3_tun_reads_truncated_total`       | counter | none             | Reads off the tun that lost the tail of a GSO frame                                                     | always                                                          |
| `ranet3_tun_frames_refused_total`        | counter | none             | Frames read off the tun that could not be read as packets                                               | always                                                          |
| `ranet3_packet_too_big_sent_total`       | counter | none             | Packet Too Big and fragmentation needed answers this node sent                                          | always                                                          |
| `ranet3_mss_clamped_total`               | counter | none             | TCP SYNs whose MSS this node lowered                                                                    | always                                                          |
| `ranet3_pmtu_probes_total`               | counter | `result`         | Path MTU probes that left, `acked` or `lost`                                                            | always                                                          |
| `ranet3_segments_forwarded_total`        | counter | none             | Packets an End behavior sent on to their next segment                                                   | always                                                          |
| `ranet3_segments_delivered_total`        | counter | none             | Packets an End.DT46 behavior decapsulated and handed to the stack                                       | always                                                          |
| `ranet3_segments_dropped_total`          | counter | none             | Packets to one of this node's segments that it would not act on                                         | always                                                          |
| `ranet3_segments_answered_total`         | counter | none             | ICMP errors sent for those dropped packets                                                              | always                                                          |
| `ranet3_steered_total`                   | counter | none             | This node's own packets a steering policy encapsulated                                                  | always                                                          |
| `ranet3_steer_dropped_total`             | counter | `reason`         | Packets a steering policy claimed and this node did not send, `too_large` or `no_route`                 | always                                                          |
| `ranet3_kernel_routes_installed`         | gauge   | none             | Routes the kernel holds for the reconciler as of its last pass                                          | with `cap.table`                                                |
| `ranet3_kernel_routes_skipped`           | gauge   | none             | Routes the platform refused in the last pass, and cover members left out with their family              | with `cap.table`                                                |
| `ranet3_kernel_pass_timestamp_seconds`   | gauge   | none             | Unix time the last pass finished, 0 before the first                                                    | with `cap.table`                                                |
| `ranet3_kernel_pass_failed`              | gauge   | none             | 1 when the last pass reported an error                                                                  | with `cap.table`                                                |
| `ranet3_egress_rules_installed`          | gauge   | none             | Source translation rules the host holds for this node as of the last pass                               | with `cap.egress`                                               |
| `ranet3_egress_prefixes`                 | gauge   | `state`          | Prefixes this node offers to carry (`advertised`) and those it announces (`announced`)                  | with `cap.egress`                                               |
| `ranet3_egress_flows_total`              | counter | none             | Connections the translation rules rewrote                                                               | with `cap.egress`                                               |
| `ranet3_egress_conflicts`                | gauge   | none             | Other source translation at the same hook                                                               | with `cap.egress`                                               |
| `ranet3_egress_pass_timestamp_seconds`   | gauge   | none             | Unix time the last pass finished, 0 before the first                                                    | with `cap.egress`                                               |
| `ranet3_egress_pass_failed`              | gauge   | none             | 1 when the last pass reported an error                                                                  | with `cap.egress`                                               |

`ranet3_babel_neighbor_cost` holds the amount `cap.babel.cost.extra` charges the
neighbor, and no series reports that amount alone. It is configuration rather
than a measurement, and the neighbor view shows it apart, in the Extra column of
`ranet3 neighbors` and in the `extra` field of `/v0/neighbors`.

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
