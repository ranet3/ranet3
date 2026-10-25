---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Segment routing"
description: "Segment routing and steering, done in this process rather than in the kernel."
created: 2026-09-21
updated: 2026-10-26
order: 60
---

Kernel SRv6 is `ip route ... encap seg6` and `encap seg6local`, which only Linux
has. macOS has no segment routing. A `NEPacketTunnelProvider` on iOS or a
`VpnService` on Android is handed a tun and a list of routes and never sees a
forwarding table. Waiting for each platform's kernel would mean segment routing
on 1 of the 4.

It does not have to be the kernel's, because this process is already the
dataplane. A packet leaving a node is read off the tun here, routed here and
sealed into ESP here, so pushing an outer IPv6 header and a routing header in
front of it is one more step on a path that already copies. A packet arriving is
decrypted here before anything else sees it, so a segment addressed to this node
is acted on before it reaches the tun. `srv6` implements
[RFC 8754](https://www.rfc-editor.org/rfc/rfc8754)'s header and
[RFC 8986](https://www.rfc-editor.org/rfc/rfc8986)'s H.Encaps, End and End.DT46,
and the same code runs on every platform.

[The configuration reference](configuration-reference.md) lists every key under
`cap.segment`.

## Local segments

`cap.segment.local` names the addresses this node answers for. Past the checks
below, `End` moves a packet to its next segment and sends it on, and `End.DT46`
strips the outer header and hands the inner packet, IPv4 or IPv6, to the mesh's
[forwarding decision](routing.md#transit), which writes it to the tun where its
destination is this node's own and sends it on to the node that holds it
otherwise. The SID grants what arrives through it transit, so the inner packet
goes on with `cap.transit` off too. It takes no table. The spelling is the one
`ip route ... encap seg6local action` takes, so a fleet's own SIDs move across
unchanged.

Other nodes reach a SID through the mesh, so this node announces a prefix
covering it under `cap.route`. A SID may not be an address `cap.table` assigns
to the tun, `assign_announced` included. The daemon refuses that at load,
because every packet to that address would be taken as a segment.

Every SID acts only on a packet whose outer source lies in the IPv6 prefixes of
`cap.border.overlay`, the per-node list of RFC 8754 section 5.1, and an
[egress segment](#egress-segments) only on one whose outer source lies in its
`allow` list too. Any other counts as refused, before its header is read, and is
never answered. [The border filter](border-filter.md) drops a source inside the
overlay arriving from outside the mesh, so a host beyond the mesh reaches no SID
through a node with the filter, whatever the SID delivers to. A node that
forwards without `cap.border` is only warned at load, and passes a forged
overlay source on to every SID. A steering node's `source` has to lie inside the
overlay too, or every SID it steers through refuses its packets. The loader
refuses a local segment without `cap.border`, and one beside an overlay holding
no IPv6 prefix, which would refuse every packet. `cap.border` is Linux only, so
a node on another platform holds no local segment. A reload that changes the
overlay rebuilds the table of SIDs in place.

A node parses a packet only when its destination is one of its SIDs. It accepts
a reduced header, which leaves out the segment the destination address already
carries, and ignores TLVs after the segment list. It walks up to 7 hop-by-hop
and destination options headers, in any order and without reading their options,
to reach the first routing header. It refuses a fragment header among them, a
routing header behind more, and a list of more than 16 segments.

Past the source checks above, an `End` and an `End.DT46` answer a segment
routing header the node reaches as above, and that fits in its packet, with
Parameter Problem, code 0, pointing at its Segments Left field, where its last
entry runs past its length, at any segments left, 0 included, or where it holds
at most 16 segments and its Segments Left runs past its last entry. One that
holds more than 16 segments is dropped without an answer, whatever its Segments
Left. An `End` sends a packet on to its next segment, through the session the
mesh routes that segment to, where the node reaches a segment routing header
with segments left that describes itself and holds at most 16 segments, and acts
on that segment in turn where it is a SID of this node, as below. It answers one
at a hop limit of 1 or less with Time Exceeded, as [steering](#steering)
describes, answers, cuts or drops one larger than that session carries, and
drops one where that session has closed or has no room for it, both as
[waypoints](#waypoints-and-packet-size) describe. It drops every other packet
without an answer: among them one reached with no segments left whose segment
routing header describes itself, one with no segment routing header, whether it
carries a routing header of another type or none, one whose fragment header
comes ahead of its segment routing header, one whose segment routing header sits
behind an authentication header or behind 8 or more hop-by-hop and destination
options headers, one that ends inside its routing header or a header ahead of
it, one whose segment routing header holds more than 16 segments, with segments
left and at a hop limit of 1 too, and one whose next segment is no SID of this
node and that the mesh routes to no other node. An `End.DT46` delivers an IPv4
or IPv6 packet that follows the outer IPv6 header directly, or follows a segment
routing header at segments left 0 that the node accepts as above, and an egress
segment only one that also passes the checks of
[egress segments](#egress-segments). It drops every other packet without an
answer, whichever the SID delivers to: among them a packet reached with segments
still left, an upper-layer header other than IPv4 or IPv6 wherever it sits, a
routing header of another type with segments left, a fragment wherever its
fragment header sits, an atomic fragment included, a packet cut short before its
inner packet starts, and an IPv4 or IPv6 packet behind a hop-by-hop or
destination options header with no segment routing header, behind a routing
header of another type with segments left 0, or behind a destination options
header after the segment routing header. A SID's answer goes back only through
the session the mesh routes its destination to, and only while that session is
open and has room for it, so none reaches a source this node's own route
reaches, this host or a network behind it. Each answer draws on the ICMP rate
limits, and none answers a packet no ICMP error may answer, as
[waypoints](#waypoints-and-packet-size) describe.
[Protocol deviations](design/protocol-deviations.md#icmp-answers) list the
requirements these drops and answers depart from. When a list names several SIDs
of one node in a row, the node acts on all of them in one pass. A TCP SYN or
SYN-ACK that `End.DT46` delivers has its MSS clamped, as [path MTU](path-mtu.md)
describes.

## Egress segments

Past the checks of [local segments](#local-segments) and those below, an
`End.DT46` with `deliver = "egress"` writes its inner packet into the mesh tun
for the host to carry out of the mesh, rather than handing it to the forwarding
decision, and the host forwards it out of the uplink under the exit's translated
source. A leaf steering to the SID picks this exit by its segment list.
`deliver = "mesh"`, the default, is the forwarding decision.
[Exit nodes](exit-nodes.md#egress-segments) describes the translation and when
the exit is ready.

```toml
[[cap.segment.local]]
sid = "2001:db8:0:6::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["203.0.113.0/25", "3fff:a::/64"]
```

`allow` is required with `deliver = "egress"` and refused with anything else. A
packet passes only when its inner packet is an IPv4 or IPv6 packet at least as
long as its fixed header, of the family the header in front of it names, its
outer source and its inner source both fall inside an entry of the list, past
the overlay every SID admits, its inner source is one a router forwards, its
inner destination one a router forwards, the limited broadcast or multicast, and
the mesh routes a reply to its inner packet, as an exit's
[egress through a default](exit-nodes.md#what-an-exit-carries-out) checks. A
packet failing any of these checks counts as refused and is never answered. The
list is required since an exit carrying any source would be an open proxy.

Egress carries nothing for the mesh. Past those checks, an inner packet whose
destination lies inside `cap.border.overlay`, or that the mesh routes itself,
counts as refused too and is never answered: the overlay is the mesh's address
space, whether a node announces the address or not, a destination the mesh
routes to another node or holds is the mesh's to carry, and one of this node's
own is the forwarding decision's to deliver. No node whose `cap.border` sets an
overlay egresses an address inside it through its forwarding decision either.
Where no node announces one, an exit with `cap.border` whose table selects its
own route that counts as a default answers it as one no route holds, and a node
whose table selects that exit's route routes it there. An exit without
`cap.border` has no overlay, so its decision egresses an address no node
announces as it egresses any other destination outside the mesh. The SID looks
the destination up as the forwarding decision would, from the inner source, and
passes over every route that
[counts as a default](routing.md#routes-that-count-as-a-default), so a
destination outside the overlay that only this node's default or another exit's
covers leaves by the uplink, where its family is
[ready](exit-nodes.md#readiness). The loader refuses:

- a list with no entry, or with no IPv6 entry, since every outer source is IPv6
- an entry of length 0, which admits every address of its family
- an IPv4 entry shorter than `/8` or an IPv6 entry shorter than `/12`
- an entry with bits set past its length, an IPv4 address written as IPv6, or an
  entry written twice

The order of the list does not matter, and a reload reordering it changes
nothing. `deliver = "egress"` belongs to `End.DT46` alone, and an egress segment
needs `cap.egress` and `cap.border` with an `overlay` covering the list. It
needs no `cap.table`, though the replies still take the `to` rules
[the return path](exit-nodes.md#the-return-path) describes, and the exit is not
[ready](exit-nodes.md#readiness) while a reply would leave by another link. The
node originates the SID's `/128` itself while the exit is ready, so `cap.route`
does not announce it. The Segments line of `status` prints an egress segment as
its SID, its behavior, `deliver egress` and its list.

## At the border of the mesh

The mesh is the segment routing domain, and a node with
[the border filter](border-filter.md) is its edge, as RFC 8754 section 5.1 asks.
A packet arriving on a link outside the mesh with a routing header of any type,
or addressed to one of this node's own SIDs, is dropped there before the routing
decision. One that arrives through the mesh tun passes, since the tun is inside
the mesh. One addressed to another node's SID with no routing header passes too,
and that node refuses it where its outer source lies outside the overlay, as
[local segments](#local-segments) describe. A node that transits another segment
routing domain between 2 links outside the mesh would lose that traffic, which
[the deviations](design/protocol-deviations.md#the-border-filter) list.

## Steering

`cap.segment.steer` is which packets read off the tun go through a segment list.
That covers this node's own traffic and any traffic the host forwards into the
mesh. An entry matches on source and destination prefix together, the same pair
the forwarding table uses. A typical entry steers traffic from this node's
announced address through waypoints and out at a chosen exit.

An entry naming neither `from` nor `to` is refused, because it would steer every
packet this node sends. A `from` or `to` of length 0 is refused too. An entry
whose prefixes are IPv4 steers IPv4 traffic, which travels inside an IPv6 outer
header like any other.

`ranet3 disable steering` sends every packet by the route table, as a node with
no steer entry does. `ranet3 enable steering` turns the entries back on. Both
are refused on a node that configures no steer entry.

Every steered packet carries its segment list inside the tunnel. The tun runs at
`link.mtu` less the header of the longest list, as
[path MTU](path-mtu.md#the-link-mtu) describes. A reload moves the tun with the
steering, as [reloading](reloading.md) describes. Steering happens before the
route lookup, because a steered packet is routed by its next segment.

For an IPv6 packet, the outer header copies the traffic class, flow label and
hop limit of the packet it carries, as `__seg6_do_srh_encap` does. For an IPv4
packet, the outer hop limit is 64 and the traffic class and flow label are 0.
Each waypoint decrements the outer hop limit. The inner packet keeps its own hop
limit. A waypoint that would take the outer hop limit to 0 answers the outer
source with ICMP Time Exceeded from the SID the packet reached, an address of
the waypoint, within the ICMP rate limits below and the checks
[local segments](#local-segments) describe.

A packet a policy claims and this node cannot send is dropped. The ordinary
route would put it out of another exit under a source that exit does not
announce, which is a wrong path, not a degraded one. `status` and the scrape
count the 2 reasons apart: too large to encapsulate, and no route to the first
segment. Neither counts against the segments this node answers for, because
neither is anything a peer did.

## Waypoints and packet size

A waypoint sends a steered packet on through the session to its next segment,
past the checks [local segments](#local-segments) describe. When the steered
packet is larger than that session carries, the waypoint answers or cuts the
inner packet, or drops the segment as below. The headend (the node that steered
the packet) does the same with a packet read off its tun. An IPv6 packet gets
Packet Too Big, and an IPv4 packet with DF set gets fragmentation needed. The
answer names what the session carries less the headers in front of the packet. A
waypoint's answer goes back through the mesh to the packet's source, and the
headend writes its answer into its tun, each from the address
[path MTU](path-mtu.md#where-answers-come-from) names. An IPv4 packet without DF
is cut into fragments that fit, each sent on behind its own copy of the outer
header and the routing header. One whose options cannot be read is answered with
Parameter Problem instead, naming the octet at fault, from the same address. A
waypoint drops a segment, or the fragments it was cut into, and counts them,
where the session's budget has no room for them, as
[the dataplane](design/limits.md#dataplane) drops a tun read's packets, or where
the session has closed.

A waypoint other than a ranet3 node may answer the steered packet itself
instead, to the headend, as a tunnel's node answers under RFC 2473. A Linux
`seg6local` waypoint does. The headend writes such an answer into its tun and
does not turn it into one for the sender of the packet it carries, so path MTU
discovery through such a waypoint fails, as
[protocol deviations](design/protocol-deviations.md#icmp-answers) describes.

These are dropped without an answer:

- a segment whose routing header names something other than the packet behind it
- an IPv6 packet no ICMP error may answer: an ICMPv6 error or Redirect behind up
  to 7 hop-by-hop, routing, destination options, authentication and first
  fragment headers, an ICMPv6 header cut short before its type, or a packet from
  the unspecified address or from a multicast address
- an IPv6 packet to a multicast group, which RFC 4443 lets no error answer but
  Packet Too Big and the Parameter Problem for an unrecognized option, and which
  ranet3 answers with no Packet Too Big either, as
  [the deviations](design/protocol-deviations.md#icmp-answers) list
- an IPv4 packet whose header fails the checks of RFC 1812 section 5.2.2, a bad
  checksum among them
- an IPv4 packet with DF, or without DF and with options that do not parse, that
  no ICMP error may answer: an ICMP error, a fragment other than the first, a
  packet to a multicast group or to `255.255.255.255`, or a packet from
  `0.0.0.0/8`, a loopback address, a multicast address or `240.0.0.0/4`
- an IPv4 packet without DF that cannot be cut, because its data runs past 65535
  bytes or the session leaves no room for 8 bytes of data behind its header
- at a waypoint, a packet whose source no session leads back to, where no route
  covers it, a hold does, or a route of this node's own, and one whose session
  back has closed or has no room for its answer
- a packet that would be answered past the ICMP rate limits

The search for an ICMPv6 error reads at most 8 headers after the IPv6 header,
and a packet it finds none in is answered: one whose headers lead to another
upper-layer header, to ESP, to no next header or to a fragment past offset 0,
one that ends before an extension header's next header and length octets or a
fragment header's offset, and one with 8 extension headers or more in front of
its upper-layer header. An ICMPv6 error behind 8 extension headers or more is
answered too, a departure from RFC 4443 that
[the deviations](design/protocol-deviations.md#icmp-answers) give the reason
for.

[Path MTU](path-mtu.md#packets-that-do-not-fit) gives the ICMP rate limits. The
Time Exceeded and Parameter Problem a refused segment gets count against the
bucket of the outer source, the node that steered the packet, and against the
node's cap. A Parameter Problem for options that cannot be read answers the
packet the segment carries, and counts against the bucket of that packet's
source and against the cap. Packet Too Big and fragmentation needed count
against the cap alone. A packet no ICMP error may answer, or one to a multicast
group, counts against neither. `status` counts a segment answered or dropped
this way among the dropped, each answer among the answered, and each fragment of
a cut segment among the forwarded once its session takes it. The log reports a
dropped segment at most once every 30 seconds.

No node fragments the outer packet of a steered packet. What does not fit the
session it leaves by is answered, cut or dropped as above. The answer names what
the session carries less 48 bytes and 16 for each segment.

With 1 segment and a session that carries less than 1344 bytes, the Packet Too
Big for an IPv6 packet names less than 1280 bytes. The source never goes below
1280 bytes
([RFC 8201 section 4](https://www.rfc-editor.org/rfc/rfc8201.html#section-4)).
It keeps sending 1280 byte packets, and each one steered there is lost.

A session's budget, which `ranet3 debug pmtu` shows, falls under 1344 bytes on
an IPv4 path under 1408 bytes or an IPv6 one under 1428, the 1400 byte paths of
many overlays among them. IPv6 load steered through a headend or a waypoint
whose session to the next segment runs on such a path is carried poorly, and
steering should keep to wider paths.

A node that steers logs a warning when a session's budget falls under what a
1280 byte packet behind its longest segment list needs. It logs at info when the
budget rises back. Both log lines name the session, its budget and that need.
Each change also records a `pmtu.steering` event with `budget`, `need` and
`under`.

## Watching it

`status` prints a Segments line and a Steering line. Each says `off` on a node
that configures none. The Segments line lists the local SIDs, then the node's
forwarded, delivered and dropped counts, and each of the answered, egressed,
refused and not ready counts once it is above 0. Refused is a packet a SID
refused, counted among the dropped and never answered: an outer source outside
the overlay at any SID, or at an egress segment one of the reasons below. The
Steering line lists the entries with the steered count, and the count for each
reason a steered packet was lost once it is above 0.

An egress segment's packets are counted 3 ways. Egressed is a packet handed to
the mesh tun. Refused is a packet whose outer or inner source is outside the
segment's allow list, whose inner source it cannot read, whose inner source no
router forwards, whose inner destination no router forwards but the limited
broadcast and multicast, an IPv4 link-local one among them, whose inner packet
the mesh routes no reply to, or whose inner destination lies inside the overlay
or the mesh routes itself. Not ready is a packet the allow list and the other
checks above let through whose family was not ready, as
[exit nodes](exit-nodes.md#readiness) describes. It is this node's own state and
is not counted among the dropped.

| Metric                               | Meaning                                                                                                                                                                                                                               |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ranet3_segments_forwarded_total`    | packets an `End` sent on to their next segment                                                                                                                                                                                        |
| `ranet3_segments_delivered_total`    | packets an `End.DT46` delivered to the mesh's forwarding decision                                                                                                                                                                     |
| `ranet3_segments_dropped_total`      | packets to a local SID this node would not act on                                                                                                                                                                                     |
| `ranet3_segments_answered_total`     | ICMP errors sent for dropped packets                                                                                                                                                                                                  |
| `ranet3_segments_egressed_total`     | packets an egress segment handed to the mesh tun                                                                                                                                                                                      |
| `ranet3_segments_refused_total`      | packets a SID refused, from outside the overlay or an allow list, for an inner source it cannot read, an inner packet no router forwards, the mesh routing no reply to, or an inner destination inside the overlay or the mesh routes |
| `ranet3_segments_not_ready_total`    | packets an egress segment let through whose family was not ready                                                                                                                                                                      |
| `ranet3_steered_total`               | packets a steering entry encapsulated                                                                                                                                                                                                 |
| `ranet3_steer_dropped_total{reason}` | steered packets not sent, `reason` is `too_large` or `no_route`                                                                                                                                                                       |

## Interoperation with the Linux kernel

The `segments` VM check runs both directions against the Linux kernel. The
client steers through a SID the gateway answers for with `seg6local`. The
gateway's capture shows the packet addressed to the SID and the inner packet
after the kernel removed the header. Removing the SID leaves the encapsulated
packet arriving with nothing coming out of it.

In the other direction, the gateway's kernel encapsulates with
`encap seg6 mode encap segs` toward a SID the client answers for with
`End.DT46`. The check requires the client's delivered count to rise and its
dropped count to stay where it was. No VM arm configures `End`. Unit tests in
`srv6` check that an encapsulation copies the traffic class, flow label and hop
limit as `__seg6_do_srh_encap` does. They also check that `End` forwards the
reduced header `encap.red` writes.

The `egress-segment` VM check makes the gateway a kernel leaf of an egress
segment on the client. The gateway's `encap seg6 mode encap` route steers a ping
to an address behind the client, which sees the client's own address as the
source and answers. The check requires the client's egressed count to rise, an
inner source outside the allow list and an inner destination the client's mesh
routes to the gateway to count as refused, the latter never reaching the gateway
again, and the SID's `/128` on the gateway to follow the client's readiness. It
runs the IPv6 arm. The IPv4 path is checked by a root test with frames built in
the test.
