---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Path MTU"
description: "How each session finds the largest packet its path carries, and what happens to a packet that does not fit."
created: 2026-10-16
updated: 2026-10-26
order: 65
---

On Linux and macOS each session searches its path for the largest packet it
carries, its **budget**. A packet larger than the budget is answered, cut or
dropped before it enters the tunnel. TCP connections through the mesh have their
MSS lowered to fit.

## The link MTU

`link.mtu` is the largest inner packet a session carries inside ESP. It defaults
to 1400 bytes, which a 1500 byte path carries over IPv4 and IPv6.

The tun runs at `link.mtu` less the header of the longest `cap.segment.steer`
list: 40 bytes of outer IPv6 header, 8 bytes of routing header and 16 bytes per
segment. A steered packet carries that header inside the tunnel.

| Limit   | Value                                                                  |
| ------- | ---------------------------------------------------------------------- |
| Default | 1400 bytes                                                             |
| Minimum | 1280 bytes for the tun, after the steering header (RFC 8200 section 5) |
| Maximum | 65470 bytes, the most 1 ESP-in-UDP datagram carries over IPv4          |

A value outside these limits is refused when the file loads. A read off the tun
takes a packet of up to 65535 bytes whatever `link.mtu` the node started with,
so on Linux and macOS a reload moves the tun to a new `link.mtu` in place, as
[reloading](reloading.md) describes.

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
moves the tun is refused, and a restart applies it. A reload whose `link.mtu`
and steering leave the tun where it was is applied, and each session takes the
new `link.mtu` at once.

## Packets that do not fit

A packet larger than its session's budget is never sent as it is.

- **IPv6, or IPv4 with DF set**: the packet is dropped and answered with ICMPv6
  Packet Too Big, or ICMP fragmentation needed. The answer names the budget less
  the steering header the packet would take. The sending host matches the answer
  by the packet it quotes and records the smaller path MTU for that destination.
- **IPv4 without DF**: the packet is cut into fragments that fit, as a router
  does (RFC 791). Its destination reassembles it. Where a packet's data, from
  its fragment offset, runs past 65535 octets, it cannot be cut, and is dropped
  without an answer, counted [`too_big`](metrics.md#transit-counters) when it is
  in transit. A packet whose header fails the checks of RFC 1812 section 5.2.2,
  a bad checksum among them, is dropped without an answer. A packet whose
  options cannot be read is dropped and answered with ICMP Parameter Problem,
  which names the octet at fault.

A node that moves a steered packet on to its next segment does the same when the
session to that segment carries less, as [segment routing](segment-routing.md)
describes.

ICMP answers are held to 2 limits. Their intervals, burst and cap are the Linux
kernel's defaults, since ranet3 sends what the kernel sent before. The number of
sources a node keeps buckets for is ranet3's own:

- **Per source**: every ICMP error but Packet Too Big and fragmentation needed,
  such as the Time Exceeded and Parameter Problem a refused segment gets and
  every answer of the [forwarding decision](routing.md#transit) to transit,
  draws from a bucket for the source of the packet it answers. A bucket holds 6
  answers and earns 1 back every second for an IPv4 source and every 100
  milliseconds for an IPv6 one. A node keeps buckets for 6,144 sources, in 64
  shards of 96 that a hash of the address under a seed random to each run picks,
  so 4,096 sources at random fit with none evicted in all but about 1 run in
  200. In a full shard, the source that drew least recently gives its place to a
  new one, and a source new or returning starts full.
- **Per node**: every answer, of either family and kind, also draws from 1 cap
  for the node, 10,000 at once and 10,000 a second.

An answer draws from the limits only once its packet is one an error may answer,
and is built only once it has drawn. A packet no error may answer, such as an
ICMP error, spends nothing of either. Neither does a packet to a multicast
group, which ranet3 answers with no Packet Too Big, as
[the deviations](design/protocol-deviations.md#icmp-answers) list. A flood past
a limit costs no answer built. The cap is read first, and an answer it holds
back spends nothing of its source's bucket. A packet that would be answered past
either limit is dropped without an answer, and `ranet3_icmp_withheld_total`
counts it by the limit that held it back.

A sender's flood of expired or refused packets spends only its own bucket and
never holds back another's path MTU discovery. Packet Too Big and fragmentation
needed are limited only by the cap, so one sender's packets past their session,
at the cap's rate, hold back every answer. They draw from no source's bucket
because one address can stand for many hosts behind a NAT that routes into the
tun, and a bucket of 6 answers, then 1 a second over IPv4 or 10 over IPv6, would
hold back path MTU discovery for all of them.

Each answer draws once. A Linux router draws twice for a packet no route holds,
from the one bucket it keeps for the packet's source: `ip_error` takes 1 second
of tokens, from a bucket holding at most 5 seconds of them, before the answer is
sent, and `icmpv4_xrlim_allow` takes 1 second more as it is sent
(net/ipv4/route.c:119-120 and 1024-1037, net/ipv4/icmp.c:334-336 and
net/ipv4/inetpeer.c:277-301 at Linux `940de590`). A source new to that router
gets 2 Destination Unreachable answers to a burst, and none after while it sends
more often than once a second. ranet3 answers such a burst from an IPv4 source 6
times, and then once a second.

Every ICMPv4 answer carries the host's default TTL: `net.ipv4.ip_default_ttl` on
Linux, and `net.inet.ip.ttl` on macOS. The node reads it at start and at each
reload. A start that cannot read it stops with an error naming the setting. A
reload that cannot read it keeps the TTL the answers carried, records a
`daemon.ttl` event and applies the rest of the file. ICMPv6 answers carry a hop
limit of 64.

### Where answers come from

A packet the node read off its tun is answered into the tun from the address the
packet was going to, in both families, whatever router-id the node holds. `End`
answers a segment too large for its next session about the packet the segment
carries, through the mesh to that packet's source. The answer comes from the
node's router-id of the carried packet's family, the address
[RFC 1812 section 2.2.7](https://www.rfc-editor.org/rfc/rfc1812.html#section-2.2.7)
names a router by. Where the node holds none, an IPv6 answer comes from the SID
the segment reached and an IPv4 answer from the address the carried packet was
going to. A Parameter Problem for options that cannot be read comes from the
same address as a fragmentation needed would. The
[forwarding decision](routing.md#transit) answers a transit packet too large for
its next session from the router-id of its family as well. Where the node holds
none, an IPv6 answer comes from the answer SID below and, with no SID either,
from the address the packet was going to, and an IPv4 answer from that address.
[Protocol deviations](design/protocol-deviations.md#icmp-answers) gives the
reasons.

The router-id of a family is the first address `cap.table` assigns in it that a
prefix `cap.route` announces covers, else the first host route of it that
`cap.route` announces. A prefix covers an address only where it has no source
prefix and does not
[count as a default](routing.md#routes-that-count-as-a-default) with the overlay
`cap.border` writes, which leaves out a default, its 2 halves, a prefix shorter
than /8 or /16 that the overlay does not cover, such as `fd00::/8` outside it,
and a source-specific entry. An address no announced prefix covers is not a
router-id, since the mesh does not route it back to the node and a sender's
strict check of reverse paths would drop an answer from it. Nor is a loopback or
link-local address, or one no answer may come from: over IPv4 one in `0.0.0.0/8`
or `240.0.0.0/4`, and over IPv6 an IPv4 address mapped into it. A network's base
address is not one either. Over IPv4 it names no host
([RFC 1812 section 4.2.2.11](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.2.2.11)),
and over IPv6 it is the Subnet-Router anycast address
([RFC 4291 section 2.6.1](https://www.rfc-editor.org/rfc/rfc4291.html#section-2.6.1)).
Nor is an IPv4 network's all-ones host, its directed broadcast, which the same
RFC 1812 section says "MUST NOT be used as a source address", in a network
shorter than `/31`. A `/31` has no broadcast, its 2 addresses being its 2 hosts
([RFC 3021](https://www.rfc-editor.org/rfc/rfc3021.html)). The node takes the
router-id at start and again each time it rebuilds its announcements. The answer
SID that `ranet3 debug pmtu` shows beside the router-ids is the first `End`
segment of `cap.segment.local` that an announced prefix covers, under the same
rules.

## MSS clamping

ranet3 lowers the MSS option of TCP SYN and SYN-ACK packets so that each TCP
segment fits its session:

- A SYN read off the tun gets the budget of its session, less 40 bytes under
  IPv4 or 60 bytes under IPv6, less the steering header when a policy steers it.
- A SYN arriving through a session gets the budget of that session the same way.
- A SYN the forwarding decision sends on to another session gets the budget of
  that session too.
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
