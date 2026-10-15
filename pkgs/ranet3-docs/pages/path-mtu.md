---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Path MTU"
description: "How each session finds the largest packet its path carries, and what happens to a packet that does not fit."
created: 2026-10-16
updated: 2026-10-16
order: 65
---

On Linux and macOS each session searches its path for the largest packet it
carries, its **budget**. A packet larger than the budget is answered or cut
before it enters the tunnel. TCP connections through the mesh have their MSS
lowered to fit.

## The link MTU

`link.mtu` is the largest inner packet a session carries inside ESP. It defaults
to 1400 bytes, which a 1500 byte path carries over IPv4 and IPv6.

The tun runs at `link.mtu` less the header of the longest `cap.segment.steer`
list: 40 bytes of outer IPv6 header, 8 bytes of routing header and 16 bytes per
segment. A steered packet carries that header inside the tunnel.

| Limit        | Value                                                                  |
| ------------ | ---------------------------------------------------------------------- |
| Default      | 1400 bytes                                                             |
| Minimum      | 1280 bytes for the tun, after the steering header (RFC 8200 section 5) |
| Maximum      | 65470 bytes, the most 1 ESP-in-UDP datagram carries over IPv4          |
| Read buffers | sized at startup for `link.mtu`, at least 2048 bytes                   |

A value outside these limits is refused when the file loads. A reload can raise
`link.mtu` only as far as the read buffers allow, as [reloading](reloading.md)
describes.

## The search

On Linux and macOS each session runs datagram path MTU discovery (RFC 8899).
Every datagram leaves with DF set, so a hop too narrow for it drops it instead
of fragmenting it. [Platforms](platforms.md) describes how each platform sets
DF.

The search works like this:

1. The **target** is the lesser of `link.mtu` and what the host's route to the
   peer's endpoint carries.
2. The session starts at the lesser of its target and 1400 bytes.
3. It probes a size with a Babel Ack Request padded to that size (RFC 8966
   section 4.6.3). The peer's speaker answers with an Ack.
4. An answered probe raises the budget to the largest size that ESP seals to the
   same datagram length, up to the target. The search then probes halfway
   between the largest size the path carried and the least it lost, until the 2
   meet.
5. A size is lost after 3 probes of it in a row go unanswered.

Once settled, the session keeps checking its path:

- Every 30 seconds while it carries data, it probes its budget again. If that
  probe is lost, the budget drops to 1280 bytes at once and the session searches
  the sizes below the one it lost.
- Every 10 minutes it reads the route again and searches up. This finds a path
  that widened.
- When the host refuses a send as too large, the route's MTU lowers the budget
  at once. A refusal never raises it.
- A session that moves to another endpoint searches the new path from the start.
- A network change, or `ranet3 debug probe`, makes sessions probe their budget
  at once.

The budget always stays between 1280 bytes and `link.mtu`.

| Timer or count               | Value      | Why                                                             |
| ---------------------------- | ---------- | --------------------------------------------------------------- |
| Probe timeout                | 6 seconds  | FRRouting (FRR) took up to 4.8 seconds to answer an Ack Request |
| Probes before a size is lost | 3          | `MAX_PROBES` of RFC 8899                                        |
| Confirmation interval        | 30 seconds | Bounds how long a new black hole drops the largest packets      |
| Raise interval               | 10 minutes | `PMTU_RAISE_TIMER` of RFC 8899                                  |

RFC 8899 recommends a probe timeout over 15 seconds. A search through 12 sizes
would then take minutes, so ranet3 waits 6 seconds.

### Paths under 1280 bytes

A path too narrow to carry 1280 bytes in 1 datagram puts its session **under the
floor**. The session then sends 1280 byte packets, and the host fragments its
datagrams. On Linux, while any session of an address family is under the floor,
that family's socket sends every datagram without DF and the family's other
searches wait. On macOS the IPv4 socket does the same, and IPv6 clears DF for
that 1 peer alone. [The design's limits](design/limits.md) describe what this
costs.

### Platforms without DF

On a platform that cannot set DF, sessions do not search. Each session carries
`link.mtu`. The tun there takes its MTU only when it opens, so a reload that
changes `link.mtu` is refused. A restart applies it.

## Packets that do not fit

A packet larger than its session's budget is never sent as it is.

- **IPv6, or IPv4 with DF set**: the packet is dropped and answered with ICMPv6
  Packet Too Big, or ICMP fragmentation needed. The answer names the budget less
  the steering header the packet would take. It comes from the address the
  packet was going to, so the sending host records the smaller path MTU for that
  destination.
- **IPv4 without DF**: the packet is cut into fragments that fit, as a router
  does (RFC 791). Its destination reassembles it.

A node that moves a steered packet on to its next segment does the same when the
session to that segment carries less, as [segment routing](segment-routing.md)
describes.

All ICMP answers share 1 rate limit per node: a burst of 8, then 1 every 250
milliseconds. Time Exceeded and Parameter Problem answers for refused segments
count against it too. A packet that would be answered past the rate limit is
dropped without an answer.

## MSS clamping

ranet3 lowers the MSS option of TCP SYN and SYN-ACK packets so that each TCP
segment fits its session:

- A SYN read off the tun gets the budget of its session, less 40 bytes under
  IPv4 or 60 bytes under IPv6, less the steering header when a policy steers it.
- A SYN arriving through a session gets the budget of that session the same way.
- A SYN that an `End.DT46` segment delivers is clamped to the session it arrived
  on.

The clamp only lowers an MSS, and updates the checksum. Hosts behind both ends
then agree on an MSS that fits the sessions of both.

These pass untouched: a SYN with no MSS option, a fragment, IPv6 with an
extension header before TCP, and an option list that does not parse.

## Watching it

| What                                                 | Where                                              |
| ---------------------------------------------------- | -------------------------------------------------- |
| Each session's search, budget and last change        | [`ranet3 debug pmtu`](development/debug.md)        |
| Probe every session now                              | `ranet3 debug probe --all`                         |
| A budget change, with its reason                     | the `pmtu.changed` event                           |
| A session going under or over the floor              | the `pmtu.floor` event                             |
| A budget too small for a steered 1280 byte packet    | the `pmtu.steering` event                          |
| Probes answered and lost                             | `ranet3_pmtu_probes_total{result="acked"\|"lost"}` |
| Packet Too Big and fragmentation needed answers sent | `ranet3_packet_too_big_sent_total`                 |
| SYNs clamped                                         | `ranet3_mss_clamped_total`                         |

A `pmtu.changed` event names its reason: `probe`, `route`, `refusal`,
`endpoint change`, `floor` or `link.mtu`.
