---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Segment routing"
description: "Segment routing and steering, done in this process rather than in the kernel."
created: 2026-09-21
updated: 2026-10-19
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

`cap.segment.local` names the addresses this node answers for. `End` moves a
packet to its next segment and sends it on. `End.DT46` strips the outer header
and writes the inner packet, IPv4 or IPv6, to the tun. It takes no table. The
spelling is the one `ip route ... encap seg6local action` takes, so a fleet's
own SIDs move across unchanged.

Other nodes reach a SID through the mesh, so this node announces a prefix
covering it under `cap.route`. A SID may not be an address `cap.table` assigns
to the tun, `assign_announced` included. The daemon refuses that at load,
because every packet to that address would be taken as a segment.

A node parses a packet only when its destination is one of its SIDs. It accepts
a reduced header, which leaves out the segment the destination address already
carries, and ignores TLVs after the segment list. It walks hop-by-hop and
destination options headers to reach the routing header. It refuses a fragment
header and a list of more than 16 segments.

An `End` reached with no segments left drops the packet without an answer. So
does an `End.DT46` reached with segments still left. When a list names several
SIDs of one node in a row, the node acts on all of them in one pass. A TCP SYN
or SYN-ACK that `End.DT46` delivers has its MSS clamped, as
[path MTU](path-mtu.md) describes.

## Egress segments

An `End.DT46` with `deliver = "egress"` writes its inner packet into the egress
device rather than the mesh tun, and the host forwards it out of the uplink
under the exit's translated source. A leaf steering to the SID picks this exit
by its segment list. `deliver = "mesh"`, the default, is the tun.
[Exit nodes](exit-nodes.md#egress-segments) describes the device, the rule it
needs in `cap.table` and when the exit is ready.

```toml
[[cap.segment.local]]
sid = "2001:db8:0:6::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["10.99.0.0/24", "fd00:99::/64"]
```

`allow` is required with `deliver = "egress"` and read with nothing else. A
packet passes only when its outer source and its inner source both fall inside
an entry of the list. Anything else counts as refused and is never answered,
since an exit carrying any source would be an open proxy. The loader refuses:

- a list with no entry, or with no IPv6 entry, since every outer source is IPv6
- an entry of length 0, which admits every address of its family
- an IPv4 entry shorter than `/8` or an IPv6 entry shorter than `/12`
- an entry with bits set past its length, an IPv4 address written as IPv6, or an
  entry written twice

The order of the list does not matter, and a reload reordering it changes
nothing. `deliver = "egress"` belongs to `End.DT46` alone, and an egress segment
needs `cap.egress`, `cap.table` and a `link.tun` that names the egress device in
14 bytes or fewer without a `%`. The node originates the SID's `/128` itself
while the exit is ready, so `cap.route` does not announce it. The Segments line
of `status` prints an egress segment as its SID, its behavior, `deliver egress`
and its list.

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
source with ICMP Time Exceeded, within the ICMP rate limit below.

A packet a policy claims and this node cannot send is dropped. The ordinary
route would put it out of another exit under a source that exit does not
announce, which is a wrong path, not a degraded one. `status` and the scrape
count the 2 reasons apart: too large to encapsulate, and no route to the first
segment. Neither counts against the segments this node answers for, because
neither is anything a peer did.

## Waypoints and packet size

A waypoint sends a steered packet on through the session to its next segment.
When the steered packet is larger than that session carries, the waypoint
answers or cuts the inner packet. The headend (the node that steered the packet)
does the same with a packet read off its tun. An IPv6 packet gets Packet Too
Big, and an IPv4 packet with DF set gets fragmentation needed. The answer names
what the session carries less the headers in front of the packet. It goes from
the packet's destination back through the mesh to its source. An IPv4 packet
without DF is cut into fragments that fit, each sent on behind its own copy of
the outer header and the routing header.

These are dropped without an answer:

- a segment whose routing header names something other than the packet behind it
- an IPv4 packet whose options do not parse
- a packet no ICMP error may answer: an ICMP error, or a packet from the
  unspecified address, from a multicast address or to a multicast group
- an IPv4 fragment other than the first, an IPv4 packet to `255.255.255.255`, or
  an IPv4 packet from `0.0.0.0/8`, a loopback address or `240.0.0.0/4`
- an IPv4 packet without DF that cannot be cut, because its data runs past 65535
  bytes or the session leaves no room for 8 bytes of data behind its header
- a packet whose answer has no route back to its source
- a packet that would be answered past the ICMP rate limit

The ICMP rate limit allows a burst of 8 answers, then 1 every 250 milliseconds.
Time Exceeded, Parameter Problem, Packet Too Big and fragmentation needed all
count against it. `status` counts a segment answered or dropped this way among
the dropped, each answer among the answered, and each fragment of a cut segment
among the forwarded. The log reports a dropped segment at most once every 30
seconds.

No node fragments the outer packet of a steered packet. What does not fit the
session it leaves by is answered or cut as above. The answer names what the
session carries less 48 bytes and 16 for each segment.

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
refused, not ready and drained counts once it is above 0. The Steering line
lists the entries with the steered count, and the count for each reason a
steered packet was lost once it is above 0.

An egress segment is an `End.DT46` whose inner packet leaves through the egress
device, a second tun, rather than through the mesh tun. Its packets are counted
4 ways. Egressed is a packet the egress device took. Refused is a packet whose
outer or inner source is outside the segment's allow list, or whose inner source
it cannot read, counted among the dropped and never answered. Not ready is a
packet the allow list let through while no egress device was installed, whose
device closed under the write, or whose family the translator had not reported
ready. It is this node's own state and is not counted among the dropped. A write
the egress device refuses for any other reason counts its packets among the
dropped. Drained is a packet read off the egress device and thrown away. Every
route into the overlay names the mesh tun, so each drained packet took a route
into the wrong device. The kernel also sends packets of its own out of the
device, its MLD reports for `ff02::2` each time the device's IPv6 comes up on a
host forwarding IPv6. These go to IPv6 multicast addresses of interface-local or
link-local scope, which no route sends to, so a packet to such an address is
read and dropped without being counted.

| Metric                               | Meaning                                                                                                                          |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `ranet3_segments_forwarded_total`    | packets an `End` sent on to their next segment                                                                                   |
| `ranet3_segments_delivered_total`    | packets an `End.DT46` delivered to the mesh tun                                                                                  |
| `ranet3_segments_dropped_total`      | packets to a local SID this node would not act on, or the open egress device refused                                             |
| `ranet3_segments_answered_total`     | ICMP errors sent for dropped packets                                                                                             |
| `ranet3_segments_egressed_total`     | packets an egress segment handed to the egress device                                                                            |
| `ranet3_segments_refused_total`      | packets an egress segment's allow list refused, or whose inner source it cannot read                                             |
| `ranet3_segments_not_ready_total`    | packets an egress segment let through and no ready device took                                                                   |
| `ranet3_segments_drained_total`      | packets read off the egress device and thrown away, leaving out the kernel's own to interface-local or link-local IPv6 multicast |
| `ranet3_steered_total`               | packets a steering entry encapsulated                                                                                            |
| `ranet3_steer_dropped_total{reason}` | steered packets not sent, `reason` is `too_large` or `no_route`                                                                  |

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
inner source outside the allow list to count as refused, and the SID's `/128` on
the gateway to follow the client's readiness. It runs the IPv6 arm. The IPv4
path is checked by a root test with frames built in the test.
