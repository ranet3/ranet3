---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-06
order: 90
---

`--metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on
its own listener, separate from `--pprof` so a fleet node can be scraped without
exposing a profiler. It reports what `prometheus-bird-exporter` reported while
Babel lived in BIRD: neighbor liveness and link cost, routes received per
neighbor, routes selected and originated, established sessions per path, packets
each peer chose not to send, and inbound ESP packet and drop counters.

It also reports the three subsystems that have no exporter anywhere, because on
a fleet node they were the kernel's: the route reconciler, which replaced BIRD's
kernel protocols, as routes installed and skipped, when its last pass finished
and whether that pass failed; segment routing, which replaced `seg6local`, as
what this node did for peers (forwarded, delivered, dropped, answered) and what
it did with its own traffic (steered, and dropped with a reason); and the
`cap.egress`, as rules installed, connections translated, other translation
found at the same hook, and the two prefix counts whose difference says this
node is withholding an advertisement it cannot stand behind. A node with the
reconciler or the capability off writes none of its series rather than zeroes
that read as a subsystem installing nothing.

`ranet3_tun_reads_truncated_total` counts reads off the TUN device that lost the
tail of a GSO frame, because the frame split into more packets than one read
holds. ranet3 sets the device's `gso_max_segs` to that read batch, 128 packets,
whenever it creates the device or attaches to one, which has the kernel split a
larger frame before it reaches the TUN and keeps the counter at zero. A kernel
that refuses the setting leaves a warning in the log at startup, and a sender
with a small MSS then cuts reads short. Each such read loses the rest of its
frame, which TCP sends again, and the reader goes on. A warning carries their
count since the previous warning, at most once every 30 seconds.

`ranet3_peer_send_dropped_total` counts, per peer, every packet this node chose
not to send. A peer holds at most 4096 packets from the read that brought them
to the transmit that carries them, which lasts about 5 milliseconds at 10 Gbit/s
and 15 milliseconds at 3 Gbit/s of 1400-byte packets. A read that does not fit
is dropped whole rather than waited for, so a peer whose transport falls behind
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

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. What a counter cannot carry,
the per-neighbor route lists and the route table, is on
[the control socket](control-socket.md) instead.
