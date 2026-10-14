---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-14
order: 90
---

`--metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on
its own listener, separate from `--pprof` so a fleet node can be scraped without
exposing a profiler. It reports what `prometheus-bird-exporter` reported while
Babel lived in BIRD: neighbor liveness and link cost, routes received per
neighbor, routes selected and originated, established sessions per path, packets
each peer chose not to send, and inbound ESP packet and drop counters.

It also reports the three subsystems that have no exporter anywhere, because on
a fleet node they were the kernel's. The route reconciler, which replaced BIRD's
kernel protocols, is reported as routes installed and skipped, when its last
pass finished and whether that pass failed. Segment routing, which replaced
`seg6local`, is reported as what this node did for peers (forwarded, delivered,
dropped, answered) and what it did with its own traffic (steered, and dropped
with a reason). The `cap.egress` is reported as rules installed, connections
translated, other translation found at the same hook, and the two prefix counts
whose difference says this node is withholding an advertisement it cannot stand
behind. A node with the reconciler or the capability off writes none of its
series rather than zeroes that read as a subsystem installing nothing.

`ranet3_tun_reads_truncated_total` counts reads off the TUN device that lost the
tail of a GSO frame, because the frame split into more packets than one read
holds. Only linux hands the TUN GSO frames, so the counter stays at zero
elsewhere. There ranet3 sets the device's `gso_max_segs` to that read batch, 128
packets, whenever it creates the device or attaches to one, which has the kernel
split a larger frame before it reaches the TUN and keeps the counter at zero. A
kernel that refuses the setting leaves a warning in the log at startup, and a
sender with a small MSS then cuts reads short. Each such read loses the rest of
its frame, which TCP sends again, and the reader goes on. A warning carries
their count since the previous warning, at most once every 30 seconds.

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
once that delay has stayed above 5 milliseconds for 100 milliseconds it drops
one packet at the head of the queue on the schedule CoDel (RFC 8289) sets, until
a batch comes through below 5 milliseconds again or the queue empties. Babel's
own packets wait in the same queue, but the delay control neither measures nor
drops them. The sender records each start and end of that state as an event,
`netstack.codel.dropping` and `netstack.codel.drained`, which
[the debug tree](development/debug.md) shows.

Delay drops say the queue toward that peer stands: this node cannot seal and
send for that peer as fast as traffic for it arrives, because its CPU, its
socket or the path falls behind, and TCP senders are being told to slow down, as
a router's queue would tell them. The delay runs from the reservation, which
makes it count the seal and the wait for the encryption workers every peer
shares. On a node whose CPU is saturated, delay drops tend to show on every busy
peer together, and they mean this node cannot seal and send as fast as traffic
is offered, not that a path is slow. The rest of the counter, the total less the
delay drops, counts the reads the budget refused, together with a closing peer's
packets, reservations the outbound SA refused and batches that failed to seal.
The last two leave a `netstack send batch failed` warning in the log and a
closing peer ends its session, so the rest climbing on a live session without
that warning is the budget refusing reads: a burst, a CPU that cannot keep the
peer's sender running, or a transport that stopped taking packets for longer
than the budget lasts. `ranet3_peer_send_failed_total` stays apart from all of
these: those packets were sealed and the transport lost them, which is the link
failing rather than this node choosing.

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
search, as [the configuration](configuration.md) describes it.

`ranet3_babel_reassembled_total` counts, per neighbor, the Babel packets its
session sent in fragments that this node put back together and read, and
`ranet3_babel_reassembled_largest_bytes` is the largest of them, a whole IPv6
packet with its headers. `ranet3_babel_reassembly_dropped_total` counts the
datagrams dropped instead, by `reason`: `overlap` for a fragment overlapping
another, `header` for a first fragment without the UDP header, `malformed` for a
fragment wrong in itself or a whole packet the speaker refuses, `timeout` for a
datagram still incomplete 16 seconds after its first fragment, `evicted` for one
at least 1 second old that gave its place or its storage to another datagram of
the same neighbor, and `refused` for one that found no storage, or each fragment
that found no place, while the neighbor's other datagrams, all younger than 1
second, held them. A neighbor flooding fragments of datagrams that never
complete has the node hold under 280 KiB and allocate under 2 MiB a second, and
evicts and refuses only datagrams of its own. A neighbor that sent no fragment
has none of the three, so the series name exactly the neighbors whose stacks cut
their packets. [The protocol deviations](design/protocol-deviations.md) say
which fragments the speaker takes and the bounds it holds each neighbor to. The
first packet a session sent in fragments is recorded as a
`babel.neighbor.fragmented` event as well, which
[the debug tree](development/debug.md) shows.

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. What a counter cannot carry,
the per-neighbor route lists and the route table, is on
[the control socket](control-socket.md) instead.
