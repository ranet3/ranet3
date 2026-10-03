---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Segment routing"
description: "Segment routing and steering, done in this process rather than in the kernel."
created: 2026-09-21
updated: 2026-10-03
order: 60
---

The fleet's SRv6 is `ip route ... encap seg6local`, which is a linux facility
and only a linux facility: darwin has no segment routing, and a
`NEPacketTunnelProvider` or a `VpnService` is handed a tun and a list of routes
and never sees a forwarding table. Waiting for each platform's kernel would mean
segment routing on one of the four.

It does not have to be the kernel's, because this process is already the
dataplane. A packet leaving a node is read off the tun here, routed here and
sealed into ESP here, so pushing an outer IPv6 header and a routing header in
front of it is one more step on a path that already copies. A packet arriving is
decrypted here before anything else sees it, so a segment addressed to this node
is acted on before it reaches the tun. `srv6` implements
[RFC 8754](https://www.rfc-editor.org/rfc/rfc8754)'s header and
[RFC 8986](https://www.rfc-editor.org/rfc/rfc8986)'s H.Encaps, End and End.DT46,
and the same code runs on every platform.

`cap.segment.local` names the addresses this node answers for. `End` moves a
packet to its next segment and sends it on; `End.DT46` strips the outer header
and hands what was inside to the stack. The spelling is the one
`ip route ... encap seg6local action` takes, so a fleet's own SIDs move across
unchanged. The AS10779 fleet writes `End` at `<base>6::2` and `End.DT46` at
`<base>6::1`, with `<base>6::3` a second `End.DT46` into the egress VRF.

`cap.segment.steer` is which of this node's own packets go through a segment
list. It is keyed by source and destination prefix together, the pair the
forwarding table is keyed by, because that is the selector a steering tool on
such a fleet uses: the traffic sourced from this node's announced address,
through the waypoints and out at a chosen exit. An entry naming neither a source
nor a destination is refused, since it would claim the encapsulated packets this
node has just produced.

Every steered packet carries its segment list inside the tunnel, so the device
comes up with the longest configured list taken off its MTU, and a list long
enough to take it under the 1280 byte minimum IPv6 requires is refused rather
than installed. Steering happens before the route lookup, because a steered
packet is routed by the segment it is going to rather than by the address it was
addressed to. The outer header takes its traffic class, flow label and hop limit
from the packet it carries, as `__seg6_do_srh_encap` does, so a steered path
costs the packet one hop per waypoint and a packet that arrives with nothing
left to spend is answered with an ICMP Time Exceeded rather than dropped in
silence. A packet a policy claims and this node does not send is dropped rather
than put out by the route the policy exists to override, because a policy here
selects an exit and that route puts the packet out of another node under a
source it does not announce, which is a wrong path rather than a degraded one.
There are two ways to lose one and `status` counts them apart: too large to
encapsulate, which every other reason being refused when the configuration is
read leaves as the only one, and no route to the first segment, which is the
mesh rather than the configuration. Neither is counted against the segments this
node answers for, since neither is anything a peer did.

A header this tree writes is one the kernel acts on, which the `segments` VM
check holds: the client steers through a SID the gateway answers for with
`seg6local`, `tcpdump` parses the header as `RT6 (len=2, type=4, segleft=0)`,
and removing the SID leaves the encapsulated packet arriving with nothing coming
out of it. The other direction, a header the kernel writes and this tree acts
on, is held by the unit tests in `srv6` against a reconstruction of what
`__seg6_do_srh_encap` produces, and by no VM arm: no arm configures
`cap.segment.local`, so `End` and `End.DT46` have no end-to-end coverage.
