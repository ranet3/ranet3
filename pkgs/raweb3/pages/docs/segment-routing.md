---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Segment routing"
description: "Segment routing and steering, done in this process rather than in the kernel."
created: 2026-09-21
updated: 2026-11-13
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
forwarding decision, which writes it to the tun, hands it to the exit, sends it
on to another node, answers it or drops it, as [routing](routing.md#transit)
lists. The SID grants what arrives through it transit, so the inner packet goes
on with `cap.transit` off too. It takes no table. The spelling is the one
`ip route ... encap seg6local action` takes, so a fleet's own SIDs move across
unchanged.

Other nodes reach a SID through the mesh, so this node announces a prefix
covering it under `cap.route`, and an `End` SID's own `/128` where another
node's `cap.exit.via` names it, as
[the configuration reference](configuration-reference.md#capexit) gives. A SID
may not be an address `cap.table` assigns to the tun, `assign_announced`
included. The daemon refuses that at load, because every packet to that address
would be taken as a segment.

Every SID acts only on a packet whose outer source lies in the IPv6 prefixes of
`overlay`, the per-node list of RFC 8754 section 5.1, and an
[egress segment](#egress-segments) only on one whose outer source lies in an
entry of its `allow` list inside the overlay too. Any other counts as refused,
before its header is read, and is never answered. The process makes this check
itself, on every platform. [The antispoof filter](antispoof.md) drops a source
inside the overlay arriving from outside the mesh, but for the rest of a
[carve-out](antispoof.md#carve-outs) on that carve-out's own interface and an
[exemption](antispoof.md#exemptions) on the interfaces it names, less what each
carves. [The entry chain](antispoof.md#the-entry-chain) and the
[tun read](routing.md#transit) keep a source of that rest out of the mesh where
this node does not own it, so a host beyond the mesh reaches no SID through a
node with the filter from a source outside every range that node owns, whatever
the SID delivers to. An exemption inside a range the node announces admits that
range's sources as the node's own, and they reach the SIDs any source the node
owns reaches. A node that forwards without `overlay` passes on to every SID only
a forged source it owns, since on Linux the entry chain keeps every other out of
the tun and on every other platform the tun read drops it, where such a node is
also warned at load. A steering node's `source` has to lie inside the overlay
too, or every SID it steers through refuses its packets. The loader refuses a
local segment without `overlay`, and one beside an overlay holding no IPv6
prefix, which would refuse every packet. Every platform loads `overlay`, so a
node on macOS holds `End` and `End.DT46` segments, checked by the outer source
as on Linux, though no filter drops a forged overlay source there before the
check. A reload that changes the overlay rebuilds the table of SIDs in place.

A node parses a packet only when its destination is one of its SIDs. It accepts
a reduced header, which leaves out the segment the destination address already
carries, and ignores TLVs after the segment list. It walks the extension headers
in their order, stepping past at most 8 of them, without reading any header's
options. It passes a hop-by-hop header right behind the IPv6 header, destination
options and authentication headers, the Fragment header of an atomic fragment,
one whose offset and M flag are both 0, and a routing header at segments left 0,
a segment routing header or one of another type. It stops at the first segment
routing header with segments left, or at the upper-layer header.

Past the source checks above, an `End` acts on the segment routing header it
reaches with segments left. It answers one at a hop limit of 1 or less with Time
Exceeded, as [steering](#steering) describes, before it reads the rest of the
header. It answers with Parameter Problem, code 0, one whose last entry runs
past its length or whose Segments Left runs past its last entry, pointing at its
Segments Left field, and one that holds more than 16 segments with code 6,
pointing at its first octet, as RFC 8883 section 2.3 answers a header past a
processing limit. Otherwise it sends the packet on to its next segment, through
the session the mesh routes that segment to, and acts on that segment in turn
where it is a SID of this node, as below. It answers, cuts or drops one larger
than that session carries, and drops one where that session has closed or has no
room for it, both as [waypoints](#waypoints-and-packet-size) describe. It
answers a next segment that the mesh routes to no other node, or only through a
route that [counts as a default](routing.md#routes-that-count-as-a-default),
with Destination Unreachable, code 0, but drops without an answer one inside a
prefix this node originates that counts as no default. It answers a next segment
at an address `cap.table` assigns to it, which is no SID, with Parameter
Problem, code 0, pointing at the Routing Type, while segments are left, as RFC
8754 section 4.3.2 has such an address answer, and drops one at segments left 0
without an answer. An `End` that reaches the upper-layer header, at segments
left 0 or with no segment routing header, answers it with Parameter Problem,
code 4, pointing at that header, since a waypoint processes no upper-layer
header, ESP and an ICMPv6 echo request included.

An `End.DT46` delivers the IPv4 or IPv6 packet it reaches, with every header in
front of it removed, and an egress segment only one that also passes the checks
of [egress segments](#egress-segments). The packet's family is the Next Header
in front of it. Whichever the SID delivers to, it answers with Parameter Problem
a segment routing header with segments left, with code 0 pointing at its
Segments Left field, an upper-layer header other than IPv4 or IPv6, with code 4
pointing at that header, and a packet behind one of the two that is not of its
version or is shorter than that version's header, with code 0 pointing at its
first octet.

Either SID answers with Parameter Problem a header it cannot walk past:

- a routing header of another type with segments left, with code 0 pointing at
  its Routing Type
- a hop-by-hop header anywhere but right behind the IPv6 header, with code 1
  pointing at the Next Header field that names it
- an extension header of a kind it does not process, with code 1 pointing at the
  Next Header field that names it
- a header the packet ends inside, with code 0 pointing at the header's length,
  or at the IPv6 Payload Length where the packet ends before that or the header
  is a Fragment header, which has no length field
- a ninth header it would step past, with code 8 pointing at that header's first
  octet, as RFC 8883 section 2.5 answers too many extension headers

It answers code 8 only where a search that steps past at most 16 extension
headers ends within them without finding an ICMPv6 error message or a Redirect,
at any of the ends [the search for an error](#waypoints-and-packet-size) lists.
Where that search ends unfinished or finds one, it drops the packet without an
answer, since RFC 4443 section 2.4 (e.1) and (e.2) allow no error in answer to
an ICMPv6 error or a Redirect. It drops a fragment of a larger packet without an
answer. A SID's answer goes back only through the session the mesh routes its
destination to, and only while that session is open and has room for it, so none
reaches a source this node's own route reaches, this host or a network behind
it, but the answers to a segment larger than its next session that
[waypoints](#waypoints-and-packet-size) write into the tun. Each answer but
Packet Too Big and fragmentation needed, which draw on none, draws on the
[ICMP rate limits](path-mtu.md#packets-that-do-not-fit), and no answer goes to a
packet no ICMP error may answer, as [waypoints](#waypoints-and-packet-size)
describe. [Protocol deviations](design/protocol-deviations.md#icmp-answers) list
the requirements these drops and answers depart from. When a list names several
SIDs of one node in a row, the node acts on all of them in one pass. A TCP SYN
or SYN-ACK that `End.DT46` delivers has its MSS clamped, as
[path MTU](path-mtu.md) describes.

## Egress segments

Past the checks of [local segments](#local-segments) and those below, an
`End.DT46` with `deliver = "egress"` hands its inner packet to the exit rather
than to the forwarding decision, and the exit carries it out of the mesh. On
Linux the exit writes it into the mesh tun, and the host forwards it out of the
uplink under the source the exit's class for its source gives. On macOS the
userspace exit ends TCP in a stack of its own and relays UDP and echo through
the host's sockets, as [the exit on macOS](exit-nodes.md#the-exit-on-macos)
gives. A leaf steering to the SID picks this exit by its segment list.
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
outer source falls inside an entry of the list that lies inside the overlay
every SID admits, its inner source inside any entry of the list, its inner
source is one a router forwards, its inner destination one a router forwards,
and the mesh routes a reply to its inner packet, as an exit's
[egress through a default](exit-nodes.md#what-an-exit-carries-out) checks. A
packet failing any of these checks but the first is never answered. One the list
refuses counts as refused. Past the list, the drop of an inner Not-ECT packet
that arrived under an outer CE counts such a packet as dropped. Past that drop,
an inner packet to a multicast destination or the limited broadcast that the
list let through, but a Not-ECT one that arrived under an outer CE, counts as
dropped and as `session_multicast`, as the
[forwarding decision](routing.md#transit) counts it, and one failing a later
check counts as refused. The list is required since an exit carrying any source
would be an open proxy.

Egress carries nothing for the mesh. Past those checks, an inner packet whose
destination lies inside `overlay`, or that the mesh routes itself, counts as
refused too and is never answered: the overlay is the mesh's address space,
whether a node announces the address or not, a destination the mesh routes to
another node or holds is the mesh's to carry, and one of this node's own is the
forwarding decision's to deliver. No node that writes `overlay` egresses an
address inside it through its forwarding decision either. Where no node
announces one, an exit with `overlay` whose table selects its own route that
counts as a default answers it as one no route holds, and a node whose table
selects that exit's route routes it there. An exit without `overlay` has its
decision egress an address no node announces as it egresses any other
destination outside the mesh. The SID looks the destination up as the forwarding
decision would, from the inner source, and passes over every route that
[counts as a default](routing.md#routes-that-count-as-a-default), so a
destination outside the overlay that only this node's default or another exit's
covers leaves by the uplink, where its family is
[ready](exit-nodes.md#readiness), and is answered where it is not, as
[exit nodes](exit-nodes.md#egress-segments) describes. The loader refuses:

- a list with no entry, or with no IPv6 entry, since every outer source is IPv6
- an entry of length 0, which admits every address of its family
- an IPv4 entry shorter than `/8` or an IPv6 entry shorter than `/12`
- an entry with bits set past its length, an IPv4 address written as IPv6, or an
  entry written twice
- an entry outside `overlay` in a list with no IPv6 entry inside it

The domain check of RFC 8754 section 5.1 holds by the outer source alone, which
always passes through an entry inside the overlay. An entry outside it, such as
a LAN behind a subnet router, admits inner sources alone, routed back by the
mesh to the node that announces them, and the exit pairs no inner source with an
outer one, as
[the configuration reference](configuration-reference.md#capsegmentlocal) says.
The order of the list does not matter, and a reload reordering it changes
nothing. `deliver = "egress"` belongs to `End.DT46` alone, and an egress segment
needs `cap.egress` and `overlay`. It needs no `cap.table`. On Linux the replies
still take the `to` rules [the return path](exit-nodes.md#the-return-path)
describes, and the exit is not [ready](exit-nodes.md#readiness) while a reply
would leave by another link. On macOS the replies come back to the exit's own
sockets and reach the leaf through the mesh. The node originates the SID's
`/128` itself while the exit is ready, so `cap.route` does not announce it. The
Segments line of `status` prints an egress segment as its SID, its behavior,
`deliver egress` and its list.

## At the border of the mesh

The mesh is the segment routing domain, and the tun is its edge, as RFC 8754
section 5.1 asks. A packet read from the tun enters the domain there, and the
forwarding decision checks it, past every extension header a SID of the mesh
walks past: a routing header of type 0, 1 or 4, or a type the mesh does not
recognize, is dropped and counted `routing_header`, and one of this node's own
SIDs is dropped and counted `sid`. A packet arriving on a link outside the mesh
with a routing header goes by its destination, as RFC 7045 section 2.1 asks. The
node sets no `seg6_enabled` and installs no `seg6local` route, and the kernel
drops a segment routing header addressed to the host while `seg6_enabled` is off
([exthdrs.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/exthdrs.c#L381)).
A packet from outside addressed to one of this node's own SIDs never reaches the
tun, since the mirror holds or throws this node's own `/128`, and
[the antispoof filter](antispoof.md) drops it where its source lies in the
overlay outside a [carve-out](antispoof.md#carve-outs) on its interface and
outside an [exemption](antispoof.md#exemptions). A host steers with
[`cap.segment.steer`](#steering), which puts the segments on inside the mesh,
after the checks, since the checks drop the segment routing header an
`encap seg6` route on the tun writes
([seg6_iptunnel.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/seg6_iptunnel.c#L141)),
as [interoperation with the Linux kernel](#interoperation-with-the-linux-kernel)
says. A packet read from the tun addressed to another node's SID with no routing
header passes the routing header and SID checks, its source meets the same
source checks as any read, and the IPv4 or IPv6 packet it carries meets every
check one level deep as a read of its own, as [routing](routing.md#transit)
lists. What passes, that node refuses where its outer source lies outside the
overlay, as [local segments](#local-segments) describe.

## Steering

`cap.segment.steer` is which packets read off the tun go through a segment list.
That covers this node's own traffic and any traffic the host forwards into the
mesh. An entry matches on source and destination prefix together, the same pair
the forwarding table uses. A typical entry steers traffic from this node's
announced address through waypoints and out at a chosen exit.

An entry naming neither `from` nor `to` is refused, because it would steer every
packet this node sends. A `from` or `to` of length 0 is refused too, and so is a
`to` that [counts as a default](routing.md#routes-that-count-as-a-default), such
as `0.0.0.0/1` or `2000::/3`, since steering the internet is `cap.exit.via`'s.
An entry whose prefixes are IPv4 steers IPv4 traffic, which travels inside an
IPv6 outer header like any other.

[`cap.exit.via`](routing.md#mode-3-on-linux) is one more policy at this node as
headend, beside the entries: a read off the tun that no entry takes, whose
destination lies outside `overlay` and that the mesh's table answers through a
route that counts as a default or through none, goes along `via` from the path's
outer source. The headend cannot check another node's SIDs, since it keeps no
list of them. That the last SID of a list is an `End.DT46` and the others `End`
is the operator's to write, as
[RFC 8986 section 4.8](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.8)
asks. An exit refuses a packet that reaches its `End.DT46` with segments left,
an `End` last refuses one with none left, each with the Parameter Problem
[local segments](#local-segments) gives, and a last SID delivering to the mesh
sends the inner packet wherever that node's table does.

`ranet3 disable steering` stops the steer entries, so a packet one would take
goes by the route table, as on a node with no steer entry. It leaves
`cap.exit.via`'s path, which removing `via` turns off. `ranet3 enable steering`
turns the entries back on. Both are refused on a node that configures no steer
entry, `cap.exit.via` or not.

Every steered packet carries its segment list inside the tunnel. The tun runs at
`link.mtu` less the header of the longest list, as
[path MTU](path-mtu.md#the-link-mtu) describes. A reload moves the tun with the
steering, as [reloading](reloading.md) describes. Steering happens before the
route lookup, because a steered packet is routed by its next segment.

For an IPv6 packet, the outer header copies the traffic class, flow label and
hop limit of the packet it carries, as `__seg6_do_srh_encap` does. For an IPv4
packet, the outer hop limit is 64, the flow label is 0, and the traffic class
carries the packet's ECN field alone, RFC 6040's normal mode. An `End.DT46` sets
the ECN field of the packet it delivers to the cell of RFC 6040 section 4.2's
Figure 4 for its own field and the outer header's, and drops an inner Not-ECT
packet that arrived under an outer CE. It counts each packet whose two fields
the figure marks currently unused, the dropped one among them, in
`ranet3_segments_ecn_unused_total`, and records `netstack.ecn.unused` at most
once every 30 seconds with one such packet's IP header, as
[debugging](development/debug.md#events) lists. Each waypoint decrements the
outer hop limit. The inner packet keeps its own hop limit. A waypoint that would
take the outer hop limit to 0 answers the outer source with ICMP Time Exceeded
from the SID the packet reached, an address of the waypoint, within the ICMP
rate limits below and the checks [local segments](#local-segments) describe.

A packet a policy claims and this node cannot send is not sent by the ordinary
route, which would put it out of another exit under a source that exit does not
announce, a wrong path, not a degraded one. One too large to encapsulate is
dropped, and one whose first segment has no route, or, along `cap.exit.via`, has
no route of its own, is answered as one whose destination no entry holds, as
[routing](routing.md#transit) gives, from its destination into the tun, within
the ICMP rate limits. `status` and the scrape count the 2 reasons apart, and
status's Kernel line alone carries `cap.exit.via`'s own steered and unrouted
counts beside the totals, as [the command line](cli.md#reading-state) gives.
Neither counts against the segments this node answers for, because neither is
anything a peer did.

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
Parameter Problem instead, naming the octet at fault, from the same address.
Where a route of the waypoint's own that counts as no default covers the
packet's source, the waypoint writes its answer into its own tun instead, from
the packet's destination, in either family and whatever router-id it holds, as
the [forwarding decision](routing.md#transit) answers this host. A segment whose
routing header does not name a whole IP packet behind it, or that carries an
IPv4 packet without DF that cannot be cut, because its data runs past 65535
bytes or the session leaves no room for 8 bytes of data behind its header, gets
Packet Too Big about itself, to its outer source, naming what the session
carries, from the IPv6 router-id else the SID it reached, or, where such a route
covers that source, into the tun from its next segment. A waypoint drops a
segment, or the fragments it was cut into, and counts them, where the session's
budget has no room for them, as [the dataplane](design/limits.md#dataplane)
drops a tun read's packets, or where the session has closed.

A waypoint other than a ranet3 node may answer the steered packet itself
instead, to the headend, as a tunnel's node answers under RFC 2473. A Linux
`seg6local` waypoint does. The headend writes such an answer into its tun and
does not turn it into one for the sender of the packet it carries, so path MTU
discovery through such a waypoint fails, as
[protocol deviations](design/protocol-deviations.md#icmp-answers) describes.

These are dropped without an answer:

- an IPv6 packet no ICMP error may answer: an ICMPv6 error or Redirect behind up
  to 8 hop-by-hop, routing, destination options, authentication and first
  fragment headers, an ICMPv6 header cut short before its type, or a packet from
  the unspecified address or from a multicast address
- an IPv6 packet to a multicast group, which RFC 4443 lets no error answer but
  Packet Too Big and the Parameter Problem for an unrecognized option, and which
  ranet3 answers with no Packet Too Big either, as
  [the deviations](design/protocol-deviations.md#icmp-answers) list
- an IPv4 packet whose header fails the checks of RFC 1812 section 5.2.2, a bad
  checksum among them, but at a waypoint one whose version or lengths do not
  describe a whole packet, whose segment gets Packet Too Big as above
- an IPv4 packet with DF, or without DF and with options that do not parse, that
  no ICMP error may answer: an ICMP error, a fragment other than the first, a
  packet to a multicast group or to `255.255.255.255`, or a packet from
  `0.0.0.0/8`, a loopback address, a multicast address or `240.0.0.0/4`
- at the headend, an IPv4 packet without DF read off the tun that cannot be cut,
  for the reasons above, as [path MTU](path-mtu.md#packets-that-do-not-fit)
  gives
- at a waypoint, a packet whose source no session leads back to, where no route
  covers it, a hold does, or only a route of this node's own that counts as a
  default does, and one whose session back has closed or has no room for its
  answer
- a packet that would be answered past the ICMP rate limits

The search for an ICMPv6 error steps past at most 8 extension headers after the
IPv6 header and reads the header behind them, and a packet it finds none in is
answered: one whose headers lead to another upper-layer header, to ESP, to no
next header or to a fragment past offset 0, one that ends before an extension
header's next header and length octets or a fragment header's offset, one with
an extension header running past the packet's end that names no ICMPv6 header
next, and one with 9 extension headers or more in front of its upper-layer
header. An ICMPv6 error behind 9 extension headers or more is answered too, but
for the code 8 refusal [local segments](#local-segments) describe, a departure
from RFC 4443 that [the deviations](design/protocol-deviations.md#icmp-answers)
give the reason for.

[Path MTU](path-mtu.md#packets-that-do-not-fit) gives the ICMP rate limits. The
Time Exceeded, Parameter Problem and Destination Unreachable a refused segment
gets count against the bucket of the outer source, the node that steered the
packet, and against the node's cap. A Parameter Problem for options that cannot
be read answers the packet the segment carries, and counts against the bucket of
that packet's source and against the cap. Packet Too Big and fragmentation
needed count against neither. A packet no ICMP error may answer, or one to a
multicast group, counts against neither. `status` counts a segment answered or
dropped this way among the dropped, each answer among the answered, and each
fragment of a cut segment among the forwarded once its session takes it, or
among the dropped where the session's budget refuses it or the session closes.
The log reports a dropped segment at most once every 30 seconds.

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
refused, not ready and unused ECN combination counts once it is above 0. Refused
is a packet a SID refused, counted among the dropped and never answered: an
outer source outside the overlay at any SID, or at an egress segment one of the
reasons below. The Steering line lists the entries with the steered count, and
the count for each reason a steered packet was lost once it is above 0. Those
counts are the totals, `cap.exit.via`'s path among them, and a node whose one
policy is that path reads `off` there, its Kernel line carrying the path's own
counts, as [the command line](cli.md#reading-state) gives.
`ranet3 debug segments` shows each segment, each `cap.segment.steer` policy and
`cap.exit.via`'s path field by field, `ranet3 debug route --peer` whether a
segment admits the source of a packet arriving through a session, and
`ranet3 debug trace` what the packets a segment acts on meet, as
[debugging](development/debug.md) describes. A packet a segment answers shows
there as an `answer` record, with its ICMP error and what became of it.

An egress segment's packets are counted these ways besides the dropped count.
Egressed is a packet handed to the exit. Session multicast, on the `Transit`
line and among the dropped, is an inner packet to a multicast destination or the
limited broadcast that the allow list let through, but a Not-ECT one that
arrived under an outer CE. Refused is a packet whose outer source is outside
every entry of the segment's allow list inside the overlay or whose inner source
is outside the list, and an inner packet to a destination other than a multicast
destination or the limited broadcast, but a Not-ECT one that arrived under an
outer CE, whose inner source no router forwards, whose inner destination no
router forwards, an IPv4 link-local one among them, whose inner packet the mesh
routes no reply to, or whose inner destination lies inside the overlay or the
mesh routes itself. Not ready is a packet the allow list and the other checks
above let through whose family was not ready, as
[exit nodes](exit-nodes.md#readiness) describes. It is this node's own state and
is not counted among the dropped.

[Metrics](metrics.md#series) lists the series of these counts, with what each
counts and the packets another series counts as well:
`ranet3_segments_<count>_total` for each count of a segment, such as
`ranet3_segments_refused_total`, and `ranet3_steered_total` and
`ranet3_steer_dropped_total` for steering.

## Interoperation with the Linux kernel

The `segments` VM check runs both directions against the Linux kernel. The
client steers through a SID the gateway answers for with `seg6local`. The
gateway's capture shows the packet addressed to the SID and the inner packet
after the kernel removed the header. Removing the SID leaves the encapsulated
packet arriving with nothing coming out of it.

In the other direction, the gateway's kernel encapsulates with
`encap seg6 mode encap segs` toward a SID the client answers for with
`End.DT46`. The header the kernel builds leaves through the gateway's IPsec
session, and the client decrypts it and acts on it as on any packet a session
delivers, so it never crosses the client's tun. The check requires the client's
delivered count to rise and its dropped count to stay where it was. No VM arm
configures `End`. Unit tests in `srv6` check that an encapsulation copies the
traffic class, flow label and hop limit as `__seg6_do_srh_encap` does. They also
check that `End` forwards the reduced header `encap.red` writes.

A Linux host that encapsulates into ranet3's own tun, with an `encap seg6` route
on the tun device, loses those packets wherever the kernel writes a segment
routing header. That header is a type 4 routing header, which the tun read's
checks drop and count `routing_header`, as
[at the border of the mesh](#at-the-border-of-the-mesh) describes. A one-segment
`encap.red`, which writes none, reaches the SID with the packet it carries
checked as a read of its own. The loss is by design, and such a host steers with
`cap.segment.steer` instead.

The `egress-segment` VM check makes the gateway a kernel leaf of an egress
segment on the client. The gateway's `encap seg6 mode encap` route steers a ping
to an address behind the client, which sees the client's own address as the
source and answers. The check requires the client's egressed count to rise, an
inner source outside the allow list and an inner destination the client's mesh
routes to the gateway to count as refused, the latter never reaching the gateway
again, and the SID's `/128` on the gateway to follow the client's readiness. It
runs the IPv6 arm. The IPv4 path is checked by a root test with frames built in
the test.
