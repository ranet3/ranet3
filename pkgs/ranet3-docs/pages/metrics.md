---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Metrics"
description: "The Prometheus series a node exports."
created: 2026-09-12
updated: 2026-10-03
order: 90
---

`-metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on its
own listener, separate from `-pprof` so a fleet node can be scraped without
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

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. What a counter cannot carry,
the per-neighbor route lists and the route table, is on
[the control socket](control-socket.md) instead.
