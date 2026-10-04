---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-04
order: 90
---

`--metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on
its own listener, separate from `--pprof` so a fleet node can be scraped without
exposing a profiler. It reports what `prometheus-bird-exporter` reported while
Babel lived in BIRD: neighbor liveness and link cost, routes received per
neighbor, routes selected and originated, established sessions per path, packets
each peer refused to queue, and inbound ESP packet and drop counters.

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

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. What a counter cannot carry,
the per-neighbor route lists and the route table, is on
[the control socket](control-socket.md) instead.
