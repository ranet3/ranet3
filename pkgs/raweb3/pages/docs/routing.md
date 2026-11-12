---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Routing"
description: "How Babel picks a route, and how the reconciler puts it into the kernel."
created: 2026-10-16
updated: 2026-11-12
order: 45
---

Babel (RFC 8966) decides which neighbor carries each prefix. The node forwards
by those decisions in its own table, keyed by source and destination prefix. The
route reconciler copies the same decisions into a kernel routing table, out of
the tun, and each lookup the host makes ends as
[where a lookup ends on Linux](#where-a-lookup-ends-on-linux) and
[on macOS](#where-a-lookup-ends-on-macos) give. Without `cap.table`, the
reconciler does not run, and the host routes into the tun however it is
configured to. On macOS, `cap.exit` decides whether a route that counts as a
default goes in scoped to the utun, as
[where a lookup ends on macOS](#where-a-lookup-ends-on-macos) and
[the zero-free cover](#the-zero-free-cover-on-macos) give.

[The configuration reference](configuration-reference.md) lists every key under
`cap.route`, `cap.babel` and `cap.table`.

## The Babel speaker

Each node runs a Babel speaker over its ESP sessions. Each ESP session is a
point-to-point Babel link. Babel packets use UDP port 6696 and the group
`ff02::1:6`, sent from a random link-local address. They travel inside ESP and
never pass through the tun.

Every Hello interval, each neighbor gets a Hello and an IHU. The Hello carries a
timestamp (RFC 9616). The IHU carries this node's receive cost and echoes the
neighbor's timestamps. A full route update goes out every update interval. Each
Babel packet other than a path MTU probe fits in a 1280-byte inner IPv6 packet.

| Timer           | Default    | Rule                                                                                                           |
| --------------- | ---------- | -------------------------------------------------------------------------------------------------------------- |
| Hello interval  | 4 seconds  | `cap.babel.hello`                                                                                              |
| Update interval | 16 seconds | `cap.babel.update`, or 4 x the Hello one                                                                       |
| Neighbor dead   | 14 seconds | 3.5 x the neighbor's Hello interval                                                                            |
| IHU expiry      | 14 seconds | 3.5 x the interval the IHU names                                                                               |
| Route hold      | 56 seconds | 3.5 x the interval of the carrying Update                                                                      |
| Lost route hold | 60 seconds | the latest expiry of any update this node sent naming it reachable: 3.5 x that update's interval, plus 1 Hello |

The router id is random. The speaker keeps it in the state directory
(`--state-dir`) together with a limit on the seqnos it has sent. A restart
carries on with the same router id, past every seqno the last run sent.

## Link cost

A link's cost has 2 parts, and a third where `cap.babel.cost.extra` names the
neighbor. The first is the receive cost the neighbor reports in its IHU, scaled
by the share of the neighbor's last 16 Hellos this node received (ETX, RFC 8966
Appendix A.2.2). Each node computes the receive cost it reports the same way, as
`cap.babel.cost.rx` (96 by default) scaled by its own reception.

The second part is a round-trip penalty (RFC 9616). The penalty is 0 at or below
`cap.babel.cost.rtt.min` (10 milliseconds). It is `cap.babel.cost.rtt.weight`
(1024) at or above `cap.babel.cost.rtt.max` (1024 milliseconds), and linear
between them. Each new sample moves the smoothed round trip 16.4 percent of the
way toward it. This node adds the penalty to its own cost of the link and does
not advertise it.

A third part is the amount `cap.babel.cost.extra` charges the neighbor, chosen
by the identity its session authenticated: by its node, by its organization, or
for any organization other than this node's own
([configuration reference](configuration-reference.md)). This node adds it last
to its own cost of the link, and also to the receive cost in every IHU it sends
that neighbor, so the neighbor's cost of the link back rises too. Each direction
of the session pays it once, at the end that sends into it, and the neighbor
needs no setting of its own: a BIRD neighbor takes the receive cost from the IHU
as any Babel speaker does. `ranet3 neighbors` shows the amount in its Extra
column, apart from the cost that holds it.

On this node both sums stop at 65534, so the amount alone never makes a usable
link unreachable here, and a cost that is already infinite stays infinite. The
neighbor holds no such bound. One that scales by its reception, as ranet3 does
with `cap.babel.quality` at its default `etx`, multiplies the receive cost it is
sent by its own loss and takes a product past 65534 as infinite: a receive cost
of 30000 becomes infinite at a neighbor that heard 7 of this node's last 16
Hellos. At either end, a route's metric through the link is the link cost plus
the metric advertised over it, and that sum stops at infinity too. A large
amount can therefore leave a path with no finite metric, and so no fallback.

The amount suits a deployment where some paths cost more than their round trip
says. Another organization's nodes may price every hop at a fixed 96 while this
node prices a hop by its round trip, so a path across their nodes undercuts a
direct session. With `foreign = 1024`, the most the round-trip penalty can add,
a direct session to a node of this organization wins over a path through another
organization's node, which stays the fallback, since 1024 is far from either
bound above. A node name is only as strong as its organization's key, since
every holder of that key can claim any of its names.

With `cap.babel.quality` set to `"none"`, this node's own reception does not
scale the cost, and the receive cost a neighbor reports, which that neighbor may
scale by its own loss, is taken as it comes. A route's metric is the link cost,
at least 1, plus the metric the neighbor advertises. A metric of 65535 is
infinite and means unreachable.

## What a node announces

`cap.route.announce` lists the prefixes this node originates. It advertises them
with metric 0, under its own router id and seqno. An entry is a prefix, or a
prefix with the source it serves (`{ prefix, from }`). A source-specific entry
is IPv6 only (RFC 9079).

The node holds each prefix it originates as its own in its table. It holds each
address `cap.table` assigns the same way, as a host route that it announces only
if it originates that route too. A route a neighbor offers for the same
destination and source prefix as one of these never replaces it. The node keeps
it as that neighbor's offer, outside its route table, with a route's expiry
time, and drops it with no hold when that time passes, when the neighbor
retracts it, or when the neighbor goes down or its session closes. While the key
is this node's own no offer is selected, installed or advertised, and
`ranet3 routes` lists none. Each route the node holds for a key when the key
becomes its own becomes its neighbor's offer, unless it is retracted or has
expired. Once the node neither announces the key nor `cap.table` assigns it, the
offers that have not expired become its routes and selection runs on them at
once, as [retracted routes](#retracted-routes) describes. A host address of this
node's, a `/32` or `/128` it originates or `cap.table` assigns, is delivered
whatever the source, as the host's kernel delivers it, so a route a neighbor
offers for that address from another source prefix is dropped, and a key from a
source to that address that the node gives back while the address stays its own
drops its offers. For a wider prefix, a source-specific route a neighbor offers
for the same destination is another route: the node learns it and prefers it for
packets from its source, by RFC 9079 section 4's destination-first ordering. A
peer's packet for an address inside a prefix this node originates goes to the
tun, and the host decides it. A read off the tun for such an address is dropped
with no answer. Neither follows a covering route such as a default.

With transit on, the node relays every route it selects to its other neighbors
and forwards the packets they bring, as [transit](#transit) describes. With
transit off, it advertises only the prefixes it originates, and still learns and
installs every route. Transit is off unless the file writes
[`cap.transit`](configuration-reference.md), and a change to it takes a restart,
as [reloading](reloading.md) lists.

`cap.egress` adds the prefixes it is ready to carry, without a source prefix.
[Exit nodes](exit-nodes.md) describes when it does. A node with an egress
segment also originates each egress SID as a `/128` while the exit is ready, as
[exit nodes](exit-nodes.md#readiness) describes.

## Route selection

For each prefix, the speaker selects the feasible route with the lowest metric.
A tie goes to the neighbor whose peer ID sorts first. The feasibility condition
of RFC 8966 section 3.5.1 keeps the mesh free of loops, and an unfeasible route
is never selected.

Selection has hysteresis (RFC 8966 Appendix A.3) with a time constant of 3 Hello
intervals. The speaker leaves the selected route only for one with a lower
metric whose smoothed metric is lower by more than `cap.babel.margin`, 4 by
default. An equal metric keeps the current next hop, and a margin of 0 asks only
that both be lower. Where no route is selected, or the selected one is gone,
unfeasible or unreachable, the route with the lowest metric is selected at once.

An unfeasible route is kept, though never selected. An update that names an
origin the source table has no room for creates no route and retracts the one
its neighbor held, and no seqno request asks about that origin. When only
unfeasible routes remain, the speaker sends a seqno request. It repeats the
request up to 4 times, 3, 3, 6 and 12 seconds apart. An unfeasible route that
selection would take, weighed with every feasible route, if it were feasible
draws 1 seqno request to its neighbor, not repeated. The speaker holds back a
second request to a neighbor for the same prefix and origin inside 2 seconds,
but not one for a newer seqno, and a starvation request it holds back is still
repeated. A route is sent back toward its own next hop as a retraction, which is
split horizon. An update a neighbor sends under this node's own router id, which
is this node's route come back, takes out the route or offer that neighbor last
sent for the prefix, as a retraction does.

A route that appears or goes away sends a triggered update, as do a change of
origin and a metric rise of at least `rx` (RFC 8966 section 3.7.2). A new seqno
sends one only where it answers a seqno request this node forwarded in the last
10 seconds or is still repeating. A change of next hop alone, and any other
change, waits for the next full update. Triggered updates to one neighbor are
spaced by the least of 1 second, half the update interval and half the Hello
interval, and one that falls inside that time goes out at its end.

Every seqno request that asks past this node's own seqno before the next update
is built shares 1 raise, which that update carries for each prefix asked about.
The node's other prefixes carry the new seqno in the next full update, and the
full update a start sends at once carries the seqno it raised. This bounds a
burst of requests, not a steady requester: a neighbor that asks once a second
raises the seqno about once a second. A new session is sent the full update at
once, and the other neighbors are not.

| Limit                                  | Value |
| -------------------------------------- | ----- |
| Route table and own keys with an offer | 16384 |
| Origins of 1 prefix                    | 1024  |
| Origins of 1 prefix from 1 neighbor    | 256   |

## Retracted routes

A retracted or expired route is held at infinity for the hold time of the Update
it replaced, then flushed. While it is held, the forwarding entry answers
"unreachable" (RFC 8966 section 3.5.4). A packet for that prefix is dropped
instead of following a shorter covering route, such as a default another node
carries. The [forwarding decision](#transit) answers one a peer sends with
Destination Unreachable, and ranet3 answers one the tun hands it the same way,
back into the tun, unless a steering policy takes it or the checks at the mesh's
edge drop it, as [transit](#transit) says. The reconciler installs the same hold
in the kernel where [what it installs](#what-it-installs) gives, which is not
for a route that [counts as a default](#routes-that-count-as-a-default), nor on
macOS for one at an address the utun holds, except as that table gives. Once the
route is flushed, the prefix stays held until the latest time any update this
node sent naming it reachable expires at a neighbor, if that is later, as the
next paragraph says. Neither hold waits for every neighbor to acknowledge the
retraction, as
[the protocol deviations](design/protocol-deviations.md#updates-and-requests)
say.

A prefix loses its last route when that route is flushed, when the session of
the neighbor that offered it closes or is replaced, or when this node gives back
a prefix of its own, one it stops announcing while `cap.table` does not assign
it or the host route of an address `cap.table` stops assigning while this node
does not announce it, and selection takes none of the offers it kept for the
prefix. The neighbor of each unfeasible offer among them is then sent a seqno
request for the offer's origin, repeated as it is when only unfeasible routes
remain. A neighbor this node told the prefix is reachable may still send packets
for it here until that update expires there, even after a retraction, which is
sent once and never acknowledged. So the prefix is held the same way until the
latest time any update this node sent naming it reachable expires at a neighbor,
unless a neighbor's route for it is selected first. Each update's time is the
route expiry of
[RFC 8966 Appendix B](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-B),
"3.5 times the advertised update interval", counted from when that update was
sent and taken from the interval it carried, plus 1 Hello interval for it to
arrive. That covers a neighbor that expires a route at the multiple Appendix B
suggests, as ranet3 does. RFC 8966 section 3.5.3 lets a neighbor choose "a small
multiple". A shorter update interval set later does not shorten the hold, since
a neighbor that missed the update sent under it still counts toward the one
before. The prefix stays unreachable for that time even when every neighbor read
the retraction, since this node cannot know that they did. A prefix that no
update from this node named reachable in that time is not held, and a covering
route serves it at once.

A hold refuses transit for as long as it lasts. The kernel's copy of a hold
refuses the traffic this host sends or forwards into it only where the lookup
ends at it, as rows L4 and L9 of
[where a lookup ends on Linux](#where-a-lookup-ends-on-linux) and row D3 of
[where a lookup ends on macOS](#where-a-lookup-ends-on-macos) give, and any
other lookup ends where those tables give. A retracted prefix covered by a
shorter route is answered unreachable until the latest update this node sent for
it expires, 60 seconds at the defaults. While an exit originates its own default
it keeps another exit's as an offer, so once its readiness withdraws its default
its transit for the internet moves at once to the other exit's default that
selection takes. With none taken, it holds its own the same way and answers that
transit unreachable, IPv6 code 0 and IPv4 Network Unreachable, until the hold
ends.
[The protocol deviations](design/protocol-deviations.md#updates-and-requests)
list the departure. Where the hold counts as a default the kernel keeps none,
and that traffic ends as
[where a lookup ends on Linux](#where-a-lookup-ends-on-linux) and
[on macOS](#where-a-lookup-ends-on-macos) give for the routes left: by the
host's own routes, or by a shorter route of the mesh back into the tun, where
ranet3 answers it, or drops it at the mesh's edge, as a
[read off the tun](#transit). A leaf holding no other feasible default holds its
own for its own hold time, 56 seconds at the defaults.

## Transit

This node decides each packet a session delivers in its own table, after its
[segments](segment-routing.md) take the ones addressed to them. Nothing of the
host takes part: its forwarding settings, its firewall's forward chain and its
kernel tables do not. The tun carries what the mesh delivers to this host and
the networks behind it, what the host sends or its kernel forwards into it from
its other links, which the checks at the mesh's edge below meet, and, on an exit
on Linux, the egress it hands the host to carry out, as
[exit nodes](exit-nodes.md#what-an-exit-carries-out) describe. The checks run in
this order for both families, each before any answer, so a malformed packet
draws none but the first check's:

1. A frame that holds no whole IP packet is dropped with no answer, but for an
   End.DT46's inner IPv6 packet whose Payload Length runs past its octets, or is
   0 with octets after its header, which is answered with Parameter Problem,
   code 0, pointing at that field, unless its source or destination is one the
   next 2 checks drop or send to the tun. A session's own packet that holds no
   whole IP packet is dropped before its segments or this decision read it.
2. An IPv6 link-local destination goes to the tun, whatever the table holds. A
   multicast or limited broadcast destination is dropped with no answer and
   counted [`session_multicast`](metrics.md#transit-counters), whatever the
   table holds or the packet's source. An IPv4 link-local destination does not
   go to the tun, since
   [RFC 3927 section 7](https://www.rfc-editor.org/rfc/rfc3927.html#section-7)
   says "A router MUST NOT forward a packet with an IPv4 Link-Local source or
   destination address", and the next check drops it.
3. A source or destination no router forwards is dropped, an IPv4-mapped
   destination in `::ffff:0:0/96` among them, which
   [RFC 6890 section 2.2.3](https://www.rfc-editor.org/rfc/rfc6890.html#section-2.2.3)
   marks not forwardable. An IPv6 link-local source with a wider destination a
   router forwards is answered on the session it came from.
4. The table answers the packet as [route selection](#route-selection) leaves
   it. An IPv4 header failing RFC 1812 section 5.2.2's checks is then dropped
   with no answer, unless an entry of this node's own holds the destination, in
   which case the host's kernel checks the header. This node's own destination
   goes to the tun. A destination no entry holds, and one inside a held prefix,
   is answered unreachable. A destination this node holds through a route that
   [counts as a default](#routes-that-count-as-a-default) is egress, which an
   exit carries out as [exit nodes](exit-nodes.md#what-an-exit-carries-out)
   describe: one inside `overlay` is answered as one no entry holds, and any
   other goes to the exit, or to the tun through a route `cap.route` announces,
   only where the mesh routes a reply to its source, through a peer, a held
   prefix, or a network or address of this node's own.
5. With `cap.transit` off, a packet for another node is answered
   administratively prohibited, unless an End.DT46 SID of this node delivering
   to the mesh took it out of its outer header.
6. A hop limit or TTL of 1 or less is answered Time Exceeded, before the size is
   looked at.
7. An IPv4 header with options has them processed. A source route is dropped,
   Record Route and Timestamp record the IPv4 router-id, and options that cannot
   be read are answered Parameter Problem.
8. A packet larger than the next session carries is answered Packet Too Big, or
   Fragmentation Needed where it sets DF, naming that session's size. An IPv4
   packet without DF is cut into fragments, or dropped with no answer and
   counted [`too_big`](metrics.md#transit-counters) where its data, from its
   fragment offset, runs past 65535 octets. Any other packet has its hop limit
   or TTL taken down and a TCP SYN's MSS lowered to the next session's, and goes
   on.

| Packet                         | IPv6 answer                     | IPv4 answer                                                                                                                                                                                  |
| ------------------------------ | ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hop limit or TTL of 1 or less  | Time Exceeded, code 0           | Time Exceeded, code 0                                                                                                                                                                        |
| No entry holds the destination | Destination Unreachable, code 0 | Host Unreachable, code 1, inside `overlay`, Network Unreachable, code 0, elsewhere                                                                                                           |
| Inside a held prefix           | Destination Unreachable, code 0 | Host Unreachable, code 1, under a hold that does not [count as a default](#routes-that-count-as-a-default) or inside `overlay`, Network Unreachable, code 0, elsewhere under one that counts |
| `cap.transit` off              | Destination Unreachable, code 1 | Destination Unreachable, code 13                                                                                                                                                             |
| Larger than the next session   | Packet Too Big                  | Fragmentation Needed with DF, cut without                                                                                                                                                    |
| Options that cannot be read    |                                 | Parameter Problem                                                                                                                                                                            |
| A Payload Length not its own   | Parameter Problem, code 0       |                                                                                                                                                                                              |
| Link-local source              | Destination Unreachable, code 2 | none                                                                                                                                                                                         |

An answer comes from the node's router-id of the family. With no IPv4 router-id
it comes from `192.0.0.8`, and with no IPv6 one from the answer SID, the first
`End` SID an announced prefix covers as
[path MTU](path-mtu.md#where-answers-come-from) describes, or not at all. A
Packet Too Big with no IPv6 router-id and no SID, and a Fragmentation Needed
with no IPv4 router-id, come from the packet's destination. An answer to a
packet from this host or a network behind it, a source an entry of this node's
own reaches that does not count as a default, goes into the tun instead, from
the answered packet's destination, the one source every reverse path check of
the host takes. A source only this node's own default reaches gets no answer,
but for the beyond scope answer to an IPv6 link-local source, which goes back on
the session the packet came by. [Path MTU](path-mtu.md#packets-that-do-not-fit)
gives the rate limits the answers draw on, and
[the protocol deviations](design/protocol-deviations.md#icmp-answers) say where
each departs from the RFCs.

A read off the tun that is not exactly one IP packet is dropped and counted as
invalid before the checks below. A read to a multicast destination, link scope
included, or to the limited broadcast 255.255.255.255 is dropped and counted as
multicast before its route is looked up or it is steered. The mesh routes no
multicast, and
[RFC 1812 section 5.3.5.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.5.1)
says "Limited broadcasts MUST NOT be forwarded", where a covering route such as
a default would carry either to the one peer it names.

A read off the tun is also checked at the mesh's edge before it enters, since a
node that forwards for others can put a packet into the tun with a source or a
header of their choosing. The decision drops a read from a source the table
routes to another node or holds unreachable, through a route that does not count
as a default, or from an overlay source this node does not own (`forged`), one
carrying an IPv6 routing header the mesh refuses (`routing_header`), one to this
node's own SIDs (`sid`), or one from a source this node does not own
(`unowned_source`) bound toward an exit's default, or under
[mode 3](#mode-3-on-linux) toward a destination outside `overlay` that no entry
holds, and on every platform but Linux as
[the platforms](antispoof.md#platforms) say. Every IPv6 read whose walk ends at
an inner IPv4 or IPv6 packet has that packet checked one level deep, whatever
its destination, since the mesh cannot tell another node's SID from any other
address, as [the limits](design/limits.md#transit) say. An inner packet that is
itself encapsulated is dropped (`nested`). A read the table answers as this
node's own whose destination the tun holds, an address `cap.table` assigns, goes
back into the tun and is counted `delivered`, for the host's kernel to take as
arriving for that address, as macOS takes it
([IPv4](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_input.c#L1357),
[IPv6](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/ip6_input.c#L625)).
It goes back as read, but for the checksum of an IPv6 UDP or TCP read that does
not verify, which the mesh completes, since macOS leaves it to
[its loopback interface's offload](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/ip6_output.c#L4303).
Linux never routes such a packet into the tun, since its
[local table](https://man7.org/linux/man-pages/man8/ip-rule.8.html) delivers it
first. Any other read the table answers as this node's own, which the mesh could
only hand back to the host, is dropped (`looped`). None of these is answered, as
[the antispoof filter](antispoof.md) and
[segment routing](segment-routing.md#at-the-border-of-the-mesh) describe for the
mesh's edge.

A read off the tun that passes those checks and that no steering policy takes,
whose destination no entry holds or that lies inside a held prefix, is answered
as the table above gives for that destination. The answer goes back into the tun
from the packet's destination, whatever the packet's source, since the tun is
the one link the packet came by: on Linux an uplink address the mesh routes
nothing to is answered too, unless the check above drops the read as
`unowned_source`, and on every other platform that check drops it, unanswered.
It draws on the same rate limits. Under [mode 3](#mode-3-on-linux), a read that
no steering policy takes, whose destination lies outside `overlay` and that the
table answers through an entry that counts as a default or through none, is
steered along `cap.exit.via` instead. A steered packet goes by its first
segment, and one whose first segment has no route, or, along `via`, has no route
of its own as [mode 3](#mode-3-on-linux) gives, is counted and answered as one
whose destination no entry holds, from its destination into the tun.

`ranet3 status` counts each outcome on its `Transit` line, and
`ranet3_transit_packets_total` exports the same counts, as
[metrics](metrics.md#transit-counters) lists. Each drop they count also records
the event `netstack.transit.dropped` with its reason, at most once every 30
seconds, except the reads [debugging](development/debug.md#events) lists in its
paragraph on `netstack.transit.dropped`, which only the counters count. A trace,
`ranet3 debug trace`, shows the packets the decision takes as it takes them,
each with what it met and why, and `ranet3 debug route` the checks one packet
would meet, as [debugging](development/debug.md) describes.

## The route reconciler

Writing a `cap.table` block turns the reconciler on. It mirrors the mesh's
selected routes and its holds into a kernel table. Each prefix this node
originates is a hold there inside `overlay`, and outside it a throw on Linux and
nothing on macOS, but for one that
[counts as a default](#routes-that-count-as-a-default), which gets nothing. On
macOS a route at one address the utun holds, whoever put the address there, gets
no route out of the utun, from any source, a hold whether this node originates
the address or the mesh holds it back and a route the mesh learned alike, and so
does a half or a piece of a wider route the reconciler cuts at such an address,
since XNU rewrites a host route out of the utun at it, onto `lo0` over
[IPv6](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/nd6.c#L2969-L3002)
and as a local route over
[IPv4](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_rmx.c#L160-L172).
The host routes an IPv6 address on the utun as its own, out of the utun into the
mesh, which sends the packet on by its own table, by the route XNU adds for
[every IPv6 address](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6.c#L3000-L3003),
and so it does an IPv4 address the reconciler assigns, whose far end it sets to
the address itself, by the route XNU adds to the
[far end](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in.c#L1790-L1803).
An IPv4 address another program put on the utun with another far end or none has
no route of XNU's at it, and the reconciler, which leaves another writer's
address on the utun, declines a route there all the same. An overlay prefix
equal to any address the utun holds, a `/32` or a `/128`, still gets its hold on
`lo0`. A hold of the mesh's with no source at such an overlay prefix goes there
too, this node's own prefix among them, even where a carve-out equals the
overlay prefix. An address `cap.table` assigns gets no route of its own there
unless this node originates it too, since the host's kernel holds it as one of
its own already, though an overlay prefix equal to it still gets its hold,
unless a carve-out equals it, as the table below gives. On Linux a hold or a
throw names no device, though an IPv6 one reads back as `dev lo`, and every
other route leaves through the tun. On macOS every route it installs is on the
utun, but the hold of each overlay prefix and the kill switch's rejects, which
are on `lo0`. The reconciler also assigns the tun's addresses. On Linux it also
installs the [policy rules](#policy-rules-on-linux) it derives.

### What it installs

| Property    | Value                                                                                                                                                                                         |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Table       | `cap.table.id`, 200 by default                                                                                                                                                                |
| Protocol    | `cap.table.proto`, 155 by default                                                                                                                                                             |
| Metric      | the kernel's default, 0 for IPv4 and 1024 for IPv6, on Linux                                                                                                                                  |
| Hold        | an `unreachable` route at metric 4294967295, with no device, read back over IPv6 as `dev lo`, on Linux, and on macOS a reject route scoped to the utun, an overlay prefix's unscoped on `lo0` |
| Throw       | a `throw` route at metric 4294967295, with no device, read back over IPv6 as `dev lo`, on Linux only                                                                                          |
| IPv6 source | on Linux a source-specific route carries its source prefix, and on macOS it is scoped to the utun instead                                                                                     |
| IPv4 source | none written, so the kernel picks the tun's own IPv4 address, or another link's where the tun has none                                                                                        |

Each entry of the mesh's table becomes:

| Entry in the mesh's table                                                                                     | In the kernel table                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A learned route                                                                                               | a route out of the tun, but on macOS nothing at one address the utun holds                                                                                                                                                                                                                                                              |
| A learned route that [counts as a default](#routes-that-count-as-a-default)                                   | out of the tun once a session has been live, and never on an exit or in [mode 3](#mode-3-on-linux). On macOS under `cap.exit`, in a family the tun holds an overlay address of, one holding its family's zero address goes in as the members of [the zero-free cover](#the-zero-free-cover-on-macos) it contains, on the same condition |
| A hold that does not count                                                                                    | a hold, but on macOS nothing at one address the utun holds unless the hold has no source and a prefix of `overlay` equals the address, where it goes on `lo0`                                                                                                                                                                           |
| A hold that counts, or this node's own prefix that counts                                                     | nothing                                                                                                                                                                                                                                                                                                                                 |
| This node's own prefix outside `overlay`                                                                      | on Linux a throw, for one that counts as no default, that the mesh can carry and that carries no IPv4 source, and nothing on macOS                                                                                                                                                                                                      |
| This node's own prefix inside the overlay                                                                     | a hold, but on macOS nothing at one address the utun holds unless the hold has no source and a prefix of `overlay` equals the address, where it goes on `lo0`                                                                                                                                                                           |
| An address only `cap.table` assigns                                                                           | nothing                                                                                                                                                                                                                                                                                                                                 |
| Each prefix of `overlay`                                                                                      | a hold for each but one a carve-out equals, on macOS on `lo0` in every mode, as [the kill switch on macOS](#the-kill-switch-on-macos) gives                                                                                                                                                                                             |
| Each [carve-out](antispoof.md#carve-outs), where a link's network or point-to-point far end meets the overlay | in place of an overlay prefix's hold of the same prefix, on Linux a throw at metric 4294967295, and nothing where the mesh's table holds that prefix itself for every source, and on macOS nothing                                                                                                                                      |

A throw ends the table's lookup, and the rules after the one that looked it up
decide, as row L10 of [where a lookup ends](#where-a-lookup-ends-on-linux)
gives. A hold of an overlay prefix refuses an unmarked lookup bound to no device
for an overlay destination that neither a route of the mesh nor a carve-out's
throw holds, row L4, rather than letting it follow another route, such as an
exit's default, or leave by main. A route for a longer prefix inside the overlay
still wins by its length. A route of the mesh wider than an overlay prefix
carries a peer's packet for an address inside that prefix, since the forwarding
decision keeps no hold of an overlay prefix, while the host's own packet for the
same address ends as rows L2, L4 and B1 to B4 give, by its mark and the device
its lookup is bound to.

A node is an exit when its `cap.route` announces, or its `cap.egress`
advertises, a prefix that counts, or its `cap.segment` holds an egress segment.
An exit installs no route that counts, its own or learned, whatever the
sessions, since with another exit's default in its table its own traffic from
its own prefixes would end at row L11 of
[where a lookup ends](#where-a-lookup-ends-on-linux), into the tun and out
through that exit.

### Policy rules on Linux

The reconciler derives its policy rules from `overlay` and this node's own
prefixes, and installs them in two blocks at fixed priorities, each rule in both
families unless it names a prefix, and each carrying `cap.table.proto`. At
Tailscale's default base the first block sits below its rules at 5210 to 5270,
and the second above them, as [sharing a host](coexistence.md#routes-on-linux)
notes. `<table>` is `cap.table.id`.

| Priority | Rule                                                                 | What it does                                                                               |
| -------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 5100     | `fwmark 0x72 goto 5190`                                              | a marked lookup skips 5110                                                                 |
| 5110     | `to <prefix> lookup <table>`, for each prefix of `overlay`           | an overlay destination reads the mesh's table, every length counted                        |
| 5190     | `nop`                                                                | where the goto at 5100 lands                                                               |
| 5400     | `fwmark 0x72 goto 5490`                                              | a marked lookup skips 5410 to 5430                                                         |
| 5410     | `lookup main suppress_prefixlength 0`                                | main's table, its routes of /0 skipped                                                     |
| 5420     | `lookup <table> suppress_prefixlength 7` for IPv4, `15` for IPv6     | the mesh's table, its routes of /7 or shorter for IPv4 and /15 or shorter for IPv6 skipped |
| 5430     | `from <prefix> lookup <table>`, for every own prefix in no other one | the mesh's table for a lookup from this node's own prefixes, every length counted          |
| 5490     | `nop`                                                                | where the goto at 5400 lands                                                               |

A skipped length skips only a route the lookup found, never an `unreachable`,
`blackhole` or `prohibit` one.

This node's own prefixes are every address `cap.table.addresses` writes, and
every prefix this node originates, such as one `cap.route` announces, that does
not count as a default, but a prefix the mesh cannot carry, such as a link-local
one, a prefix `cap.egress` advertises for the hosts behind this node, and an
announcement with a source, D from S. Under the destination-first ordering of
[RFC 9079 section 4](https://www.rfc-editor.org/rfc/rfc9079.html#section-4) the
mesh routes D to this node only for packets from S, so a reply to D from outside
S would never come back through the mesh. With no `overlay`, no 5110 rule is
installed.

#### Exit mode on Linux

With [`cap.exit`](configuration-reference.md#capexit) the reconciler adds three
rules to each family the tun holds an overlay address of, derived on every pass
from the links outside the mesh as the network watch last read them, and from
the links `cap.exit.forward` expands to among them. A family the tun holds none
of is left out of the mode and keeps mode off's rules, as
[limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) says. On
macOS the mode is routes, as
[the zero-free cover](#the-zero-free-cover-on-macos) gives. `iif lo` matches a
lookup whose input link is `lo` (net/core/fib_rules.c:284-285 at Linux
`940de590`): the host's own, and the reverse path check of nftables' `fib`
expression, which looks up from `lo` in a prerouting chain for a forwarded
packet too (net/ipv6/netfilter/nft_fib_ipv6.c:212-213 and 33-35).

| Priority | Rule                                                                                                                                                      | What it does                                                                                                   |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| 5405     | `from <address> iif lo lookup main`, for each address of a link outside the mesh                                                                          | a socket bound to a link's address, the uplink's among them, leaves by main                                    |
| 5435     | `from <network> iif lo lookup main`, for each connected network shorter than a host prefix and each point-to-point far end of a link `forward` leaves out | a `fib` expression's reverse path check of a reply main routes to such a link finds main's route, not the mesh |
| 5440     | `iif lo lookup <table>`, and `iif <link> lookup <table>` for each link `forward` expands to                                                               | the mesh's table, every length counted, for the host's own traffic and the forwarded links'                    |

- Neither 5405 nor 5435 selects a source overlapping `overlay` or this node's
  own prefixes, which 5430 sends into the mesh. 5405 comes ahead of 5430, so an
  overlay address on `lo` or on a dummy link, as a host checking the mesh puts
  one there, or an address in a LAN this node announces, would otherwise leave
  by main where mode off sends it into the mesh. A selector overlapping either
  is left out whole, but one a [carve-out](antispoof.md#carve-outs) holds whole
  and no entry of the mesh's table holds is kept for the overlay, since the
  link's neighbors hold its addresses. A selector overlapping this node's own
  prefixes is left out even there.
- 5435 reaches a reverse path check only where 5405 to 5430 did not answer it. A
  `/32` or `/128` address is its own network, which 5405 already selects, so it
  takes no rule at 5435. 5405 comes ahead of 5410 to 5430, so a socket bound to
  a link's address reaches a mesh subnet by main, and 5405 alone covers a
  forwarded link's addresses and an address whose network 5435 leaves out.
- The tun, `lo` and the link either family's default leaves by are never
  forwarded. A pattern matching one is skipped with the reason, and the next
  pass takes the link once it no longer is one.
- 5440 counts every length, so the mesh's default, which 5420 skips, answers
  there. Where the mesh's table holds no route for the destination, the lookup
  goes on to main at 32766, the declared limit
  [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) lists with
  the states it holds in.
- A packet 5440 sends into the tun toward the mesh's default meets the
  owned-source rule
  [what forwarded traffic meets](coexistence.md#what-forwarded-traffic-meets)
  states, with what it leaves of a Docker bridge's flows and a LAN's.

#### The kill switch on Linux

macOS's switch is routes, as
[the kill switch on macOS](#the-kill-switch-on-macos) gives. With
`cap.exit.fallback = "none"` the host's traffic leaves by a link outside the
mesh only where a line of the chains below passes it while they read back as
written, whether an exit is live or not, and after each stop their lifetime
below says leaves the chains. The switch covers the host's own traffic and that
of the links `forward` names. The chain's forwarded line below passes a
forwarded packet from a link outside `forwarded`, such as a container's or a
VM's, whose destination `fib daddr type` does not read as local, a type the
kernel takes
[in IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter/nft_fib_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n58)
and
[in IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter/nft_fib_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n89).
Two more rules close the routing side, in each family:

| Priority | Rule                                                                                                                                  | What it does                                                                                                               |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| 5445     | `to <prefix> lookup main`, for each of this node's own prefixes and each [carve-out](antispoof.md#carve-outs) the mesh's table throws | the host reaches its own prefix beyond the gateway and a carved link's neighbors, which 5440's lookup passes on as a throw |
| 5450     | `iif lo unreachable`, and `iif <link> unreachable` for each link `forward` expands to                                                 | an unmarked lookup of the host's own or a forwarded link's that no rule above answered fails at once                       |

5450 fails a connect with `ENETUNREACH` at once while the mesh holds no default,
where a drop after routing would leave it waiting out its retransmissions. A
source-specific announcement's throw is left out of 5445, so the host's own
unmarked lookup from its source the mesh's table passes on meets 5450. A family
the tun holds no overlay address of runs [mode off's rules](#exit-mode-on-linux)
with 5445 and 5450 beside them, so an unmarked lookup of the host's own or of a
link `forward` names that rows L1 to L12 of
[where a lookup ends](#where-a-lookup-ends-on-linux) send to main at 32766 meets
5450 first, but one to this node's own prefixes or a carve-out, which 5445 sends
to main, and one that a route of main longer than /0 answers at 5410 meets the
chains below.

The routing side leaves open a socket bound to the uplink's address, which 5405
sends by main, one bound to the uplink's device, and a mark another program's
rule sends to main. The kill switch's two filter chains in the table
`inet ranet3`, at priority 2147483646, hold them to their lines: `fallback` at
`postrouting`, which judges the link a packet leaves by
([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n437),
[IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n248)),
and `output` at `output`, which sees the packets the host sends by the link of
their first route
([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n120),
[IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/output_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n116)).
Both hold these lines, a reply line only for a protocol `inbound` lists, and
`output` holds `fib daddr type local accept` ahead of its drop:

```text
oifname { "lo", "<tun>" } accept
meta mark 0x00000072 accept
meta iif != 0 iifname != @forwarded fib daddr type != local accept
ip daddr @lan4 accept
ip6 daddr @lan6 accept
ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
ip6 daddr { fe80::/10, ff00::/8 } accept
icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept
meta iif 0 icmpv6 type packet-too-big accept
meta iif 0 icmp type destination-unreachable icmp code 4 accept
ip daddr @own4 accept
ip6 daddr @own6 accept
ct direction reply ct protocol tcp ct original proto-dst @tcp_ports accept
ct direction reply ct protocol udp ct original proto-dst @udp_ports accept
counter drop
```

- The priority runs ahead of conntrack's
  [confirmation at 2147483647](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter_ipv4.h?id=940de590b839f71d6dc846160534bf202401b8b7#n43),
  so a refused packet confirms no entry, and
  [a drop is final](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n612)
  whatever another chain at the same hook accepts. The host's own sender meets
  `EPERM`.
- `output` is there for what a kernel tunnel or IPsec sends. At postrouting a
  packet carries as its input link the device it held before its route
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n429),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n231)),
  the tunnel for a GRE, IPIP, SIT or WireGuard outer packet, so postrouting's
  forwarded line meets it as a forwarded packet. At output a packet carries no
  input link
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n120),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/output_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n116)),
  so output's lines meet such a packet as they meet the host's own.
- Output's `fib daddr type local accept` passes a packet whose destination
  `fib daddr type` reads local
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter/nft_fib_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n58),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter/nft_fib_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n89)),
  whatever gave the packet that destination. Postrouting's lines then judge the
  link the packet leaves by, which the reroute at output looks up again with a
  bound socket's device
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter.c?id=940de590b839f71d6dc846160534bf202401b8b7#n49),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter.c?id=940de590b839f71d6dc846160534bf202401b8b7#n44)).
  Which type and which link a send gets rests on the routes and rules. In the
  labs, in both families with no rule ahead of the local table, a send that NAT
  at output redirected to 127.0.0.1 or ::1 passed output's fib line and was
  delivered by `lo`. A send bound to the uplink toward an address the host held
  on another link, which the bound lookup
  [passes over](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/fib_trie.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1413),
  passed the fib line and met postrouting's drop as it left by the uplink. One
  bound to the uplink that NAT at output sent to the uplink's own address left
  by `lo` and was delivered. A GRE tunnel bound to the uplink toward an address
  the host held on `lo` sent no outer packet out of the uplink, with the
  defaults present, retracted and after `SIGKILL`. Where a rule keyed on the
  source ahead of the local table routed the host's send to its own address on
  another link out of the uplink, IPv4 read that address as local and
  postrouting refused the send, and IPv6 read it as unicast and output's drop
  refused it.
- The lines pass the mesh and `lo`, ranet3's underlay by its mark 0x72 exactly,
  a packet forwarded from a link `forward` leaves out, which keeps its routes
  from before ranet3, toward a destination that `fib daddr type` does not read
  as local, as above, the LAN, link-local and multicast, which carry DHCP and
  most of discovery, neighbor and router discovery to any address at the hop
  limit of 255, as [RFC 4890](https://www.rfc-editor.org/rfc/rfc4890) section
  4.4.1 lists them, Packet Too Big and fragmentation needed that the host itself
  sends, with no input link, about a packet it forwards, this node's own
  prefixes, the replies of a flow the far side opened to a service
  `cap.exit.inbound` lists, keyed on the connection's protocol, so its ICMP
  error passes too, and, at output alone, a destination `fib daddr type` reads
  local, as above. The drop takes what none of them passes.
- `forwarded` holds `lo` and the links `forward` expands to. `lan4` and `lan6`
  hold the LAN: the connected networks of the links `forward` names, whole, and
  of the connected networks of every other link outside the mesh, the parts
  inside the private ranges of
  [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918), the unique local
  `fc00::/7` of [RFC 4193](https://www.rfc-editor.org/rfc/rfc4193), the
  link-local `169.254.0.0/16` and `fe80::/10`, and the prefixes `cap.exit.lan`
  lists. A network holding such a range counts for that range alone. Of a
  network that shares an address with `overlay`, its part outside the overlay
  counts by the same rules, so a lease wider than an overlay prefix keeps its
  gateway outside it, and each [carve-out](antispoof.md#carve-outs) less the
  mesh's prefixes inside it is held. A network as short as a route that
  [counts as a default](#routes-that-count-as-a-default) is left out whole.
  Status names it, and as public a network, or a prefix of its part outside the
  overlay, that the ranges and `cap.exit.lan` leave out in whole or in part.
  `own4` and `own6` hold the prefixes 5445 names but the carve-outs, and
  `tcp_ports` and `udp_ports` the ranges `inbound` lists. The rules and the sets
  come from one derivation each pass.

The table carries no owner flag, so the kernel does not delete the chains with
the process that wrote them:

- They are written by the reconciler's first pass, which the start waits up to
  10 s for before it dials a session, and again by each pass whose inputs moved,
  in one transaction with their sets. A first pass that fails, such as one that
  cannot list the tun's addresses, is logged as
  `kernel reconcile failed, retrying` and the start dials without the chains
  until a retry writes them. Chains left by an earlier instance are taken over:
  a pass that reads them back as written keeps them, with their drop's count,
  and one that does not rewrites them.
- A clean stop, `ranet3 down`, `ranet3 disable reconciler` and a reload to
  `"uplink"` or without `cap.exit` withdraw its chains and sets with the rules,
  and the table as [sharing a host](coexistence.md#the-nftables-table) gives. A
  start or a reload whose file asks for no switch deletes those an earlier
  instance left.
- A start that a refusal or `SIGINT` or `SIGTERM` ends before its build
  completes runs no pass, so it writes no chain and leaves those an earlier
  instance left, with the rules and routes of its protocol.
- The stop a failed tun causes withdraws the rules, routes and addresses, 5445
  and mode 3's steered defaults among them. The antispoof filter's chains follow
  [its lifetime](antispoof.md#where-it-runs). Where `fallback = "none"` is in
  force, as it is in mode 3 unless `"uplink"` is written, it deletes no chain of
  the kill switch: chains that are there it leaves as found, with no rule behind
  them, whatever the last pass read or wrote, and before any pass an earlier
  instance's. The chains alone then judge what leaves, by main's routes and the
  sets the last pass wrote: what 5445 sent to a carve-out or this node's own
  prefix leaves by the LAN's line or the own prefixes' line, what the mesh's
  default or the steered defaults carried meets the drop unless another line
  passes it, and a connect they refuse waits out its retransmissions rather than
  meeting 5450's `ENETUNREACH`. Where no chain is there the host's traffic
  leaves by its routes. It [logs a warning](#watching-it) that says whether a
  listing found the chains, found none, or failed, but where the chains were
  deleted or found absent since the last pass that asked for them, as after
  `ranet3 down`, `ranet3 disable reconciler` or a pass under `"uplink"`, the
  stop lists nothing and logs nothing. Where the file in force asks for no
  switch it deletes the chains as the stops above do. The daemon exits 1 for
  [the supervisor's restart](service.md#restarts-and-the-network). While ranet3
  stays down, the operator removes the chains left with
  `nft delete chain inet ranet3 fallback` and
  `nft delete chain inet ranet3 output`.
- After `SIGKILL`, or another stop that withdraws nothing, the chains and the
  rules stay and the tun goes with the process. A start followed by
  `ranet3 down` withdraws them. With ranet3 stopped, the operator removes the
  switch by deleting the chains and the rules of `cap.table.proto` in both
  families: `nft delete chain inet ranet3 fallback` and
  `nft delete chain inet ranet3 output`, `ip rule flush protocol 155` and
  `ip -6 rule flush protocol 155` at the default protocol.
- Nothing outlives a reboot, so the switch holds from ranet3's start, not from
  boot.

Each pass reads its chains back, their hooks, priorities, lines and set
elements. While they do not read back as written, or cannot be written, such as
on a kernel without `nf_tables`, the reconciler leaves 5405 and 5435 out and
keeps 5445 and 5450, so an unmarked lookup from the uplink's address meets 5440,
5445 or 5450 rather than main, but for a route of main longer than /0, which
still wins at 5410 as in mode 2, the cost
[limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) names. While
the chains hold, their drop takes that route's traffic beyond the LAN unless
another line passes it. Status names the switch `not holding` with the reason,
and the services on the uplink's address answer only where 5410 or 5445 routes
the reply, or the mark 0x72 sends it past them to main, until the chains read
back. The reconciler watches the notifications of the table and of its chains
and sets, so another writer's flush or deleted line starts a pass at once, and
the antispoof filter's and the translator's writes of their chains, rules and
sets start none. A flush of the ruleset deletes the table and another program
setting it dormant sets a flag on it, so each starts a pass in every writer
once. The first writer's pass after it makes the table again or clears the flag,
which starts none in another writer: the table it makes holds none of their
chains, and with the flag cleared it bypasses none.

#### Mode 3 on Linux

With [`cap.exit.via`](configuration-reference.md#capexit) the host's traffic
that only a default would carry leaves by the one exit the path names, and a
route the mesh holds that
[counts as no default](#routes-that-count-as-a-default) is followed as in
mode 2. Mode 3 is [exit mode's](#exit-mode-on-linux) rules, family by family,
with `via` in place of the mesh's choice of default:

- The reconciler installs no learned route that
  [counts as a default](#routes-that-count-as-a-default), so the kernel sends
  nothing of the host's by another exit's default or `/1` pair. It installs two
  steered defaults instead, `0.0.0.0/0` and `::/0` out of the tun, while every
  segment of `via` resolves to a peer through its own `/128`, the entry whose
  prefix is the segment, or for a segment after the first to this node, looked
  up from the path's outer source. The capture hold of
  [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) applies to
  them as to any route that counts.
- A pass that finds a segment of `via` unresolved, with no route, held, this
  node's own as the first, reached only through a route that counts, or by no
  route of its own, withdraws both, and the first pass that finds every segment
  resolved installs them again. Each change is logged and recorded as
  `kernel.path`.
- A packet the steered defaults send into the tun is steered along `via` by
  [the tun read](#transit), from the outer source
  [the configuration reference](configuration-reference.md#capexit) gives. A
  packet whose first segment the tun read reaches by no route of its own is
  answered as one with no route to that segment. Through a route that counts,
  the exit behind it would egress the packet where the segment lies outside the
  overlay and answer it inside, and through another node's subnet that node may
  hand it to its own host.
- An `End` drops a packet whose next segment only a route that counts reaches,
  as [local segments](segment-routing.md#local-segments) gives. A waypoint that
  loses the exit's `/128` while this node still reaches the exit's segment, and
  whose table then reaches that segment through another node's subnet, a route
  that counts as no default, sends the host's packets on to that node. This node
  reads each segment in its own table, so nothing withdraws the steered defaults
  then, and before typed SIDs no node can tell an exit's segment from a subnet's
  address.
- While the path is down, the host's traffic meets the fallback. In mode 3 an
  unwritten `fallback` is `"none"`, so
  [the kill switch](#the-kill-switch-on-linux) holds as that section gives, its
  state passing while the steered defaults are installed and holding while they
  are withdrawn. With `fallback = "uplink"` written, the host's traffic leaves
  by main while the path is down and after the daemon is killed, as in mode 2.

#### Where a lookup ends on Linux

These tables are where a lookup ends under the derived rules, and the other
pages link here for it. They hold where `cap.table` is written and the
reconciler is enabled, with every rule of the reconciler's last pass in place,
no rule of another program in the policy database, and no route of another
writer in `cap.table.id`'s table. `ranet3 debug route` names the rule and route
a lookup of one packet ends on, as [debugging](development/debug.md) describes.

Where that does not hold, the reconciler does this:

- A pass adds each `nop` before the `goto` that lands on it. Where a `nop`'s add
  fails, or another program deletes it, the kernel passes its `goto` over, as it
  would a missing one (net/core/fib_rules.c:324-330 at Linux `940de590`, where
  the walk passes a `goto` whose target is unresolved, and :936-944 and
  1078-1098, where an add and a delete leave it so), so a marked lookup meets
  that block's lookups as an unmarked one does until a later pass adds the
  `nop`.
- The reconciler never removes another writer's route from its table. It warns
  once at startup where another writer's unicast route is in its table, and once
  for each route it would install whose key another writer holds. The rows below
  leave such a route out.
- The gotos jump from 5100 to the first rule at 5190 and from 5400 to the first
  rule at 5490, so another program's rule at 5101 to 5189 or 5401 to 5489 meets
  only unmarked lookups, and one at 5190 or 5490 meets marked ones, ahead of the
  reconciler's `nop` where it was added first. Another program's `goto` that
  lands among the reconciler's rules goes on from the rule it lands on.
- Another program's rule ahead of 5100 can take any lookup it selects, a marked
  one among them, before the reconciler's rules see it. The reconciler asks the
  lookups [sharing a host](coexistence.md#another-programs-rules) describes, an
  overlay prefix's and each live session's send under the mark, and reports such
  a rule where it takes one of them, as [watching it](#watching-it) lists.

[Sharing a host](coexistence.md#another-programs-rules) gives how another
program's rule changes where a lookup ends, with the layouts measured.

- A lookup is marked when its mark is exactly 0x72, which ranet3's underlay
  sockets carry where the process may set it, as
  [sharing a host](coexistence.md#the-underlays-mark) says. Any other mark, such
  as kube-proxy's 0x4000, counts as unmarked.
- A lookup carries a source where its socket is bound to an address, or an
  earlier lookup gave it one, such as at a connect. A datagram of a socket bound
  to no address carries none, but over IPv6 the kernel looks a lookup with no
  source that the walk refuses up again from the source it then picks
  (`ip6_dst_lookup_tail`, net/ipv6/ip6_output.c:1147-1188 at Linux `940de590`),
  and that lookup ends by the rows as one from that source: at L11 where the
  source is one of this node's own prefixes and no row before L11 answers it,
  and refused again where L4, L7 or L9 refused it. A forwarded packet is an
  unmarked lookup carrying its own source.
- The mesh's longest match is the longest route of `cap.table.id` covering the
  destination, a hold or a throw among them. Over IPv6 a source-specific route
  matches only a lookup from its source.
- Within a table the first row that matches gives where the lookup ends. Each
  row holds for both families unless it names one.

A lookup bound to no device:

| Row | Destination                                                                                                                            | Lookup                                              | Where it ends                                                                            |
| --- | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| L1  | an address of the host's own                                                                                                           | any                                                 | the local table at 0, which delivers it on the host                                      |
| L2  | any other                                                                                                                              | marked                                              | main at 32766, since the gotos at 5100 and 5400 skip every rule reading the mesh's table |
| L3  | inside `overlay`, where the mesh's longest match is a route                                                                            | unmarked                                            | 5110, into the tun                                                                       |
| L4  | inside the overlay, where the mesh's longest match is a hold                                                                           | unmarked                                            | 5110, refused                                                                            |
| L5  | inside the overlay, where the mesh's longest match is a throw or the table holds nothing for it                                        | unmarked                                            | on through the rows below, as for a destination outside the overlay                      |
| L6  | outside the overlay, under a route of main longer than /0                                                                              | unmarked                                            | 5410, by main's route, whatever the mesh's table holds for it                            |
| L7  | outside the overlay, where main's best default is an `unreachable`, `blackhole` or `prohibit` route                                    | unmarked                                            | 5410, refused, whatever the mesh's table holds and whatever the source                   |
| L8  | outside the overlay, where the mesh's longest match is a route longer than /7 for IPv4 or /15 for IPv6                                 | unmarked                                            | 5420, into the tun                                                                       |
| L9  | outside the overlay, where the mesh's longest match is a hold                                                                          | unmarked                                            | 5420, refused                                                                            |
| L10 | outside the overlay, where the mesh's longest match is a throw                                                                         | unmarked                                            | past 5420 and 5430 to main at 32766                                                      |
| L11 | outside the overlay, where the mesh's longest match is a route of /7 or shorter for IPv4 or /15 or shorter for IPv6, such as a default | unmarked, from a source in this node's own prefixes | 5430, into the tun                                                                       |
| L12 | outside the overlay, any other                                                                                                         | unmarked                                            | main at 32766                                                                            |

- L3 and L5: every overlay prefix has a hold of its own, or where a carve-out
  equals it, in its place that carve-out's throw or the mesh's own route at it,
  but one whose carve-out is an address `cap.table` assigns this node gets none
  of them. So inside the overlay the mesh's longest match is never a route
  shorter than the prefix but at such an address. Without `overlay` no
  destination is inside the overlay.
- L5: a [carve-out](antispoof.md#carve-outs)'s throw is the mesh's longest match
  for an address of the carve-out no route of the mesh holds, so a lookup to the
  link's gateway or neighbor ends at L6 by main's route for the link.
- L4, L7 and L9: a skipped length never skips an `unreachable`, `blackhole` or
  `prohibit` route. That is why the reconciler installs no hold of a route that
  counts.
- L10: the throw is this node's own prefix outside the overlay. Main's route out
  of the uplink for the host's subnet, its LAN or a prefix `cap.egress`
  advertises has already answered at L6.
- L11: an exit installs no route that counts, so on an exit no lookup ends
  there.

With [exit mode](#exit-mode-on-linux), in a family the tun holds an overlay
address of, these rows hold for an unmarked lookup, the host's own and a `fib`
expression's check carrying `iif lo` and a forwarded one the link it arrived on.
In a family it holds none of, the rows above hold alone.

| Row | Lookup                                                                                                                                    | Where it ends                                                                                                   |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| E1  | the host's own, from an address of a link outside the mesh outside the overlay and this node's own prefixes, that L3 and L4 do not answer | 5405, by main's route, ahead of L6 to L11                                                                       |
| E2  | one carrying `iif lo`, from a network 5435 selects of a link `forward` leaves out, where L12 held                                         | 5435, by main's route                                                                                           |
| E3  | the host's own, or one arriving on a link `forward` expands to, where L12 held                                                            | 5440, into the tun by the mesh's route, refused by its hold, and on to main at 32766 where it holds neither one |
| E4  | any other, where L12 held                                                                                                                 | main at 32766, as L12                                                                                           |

- E1: the mesh's subnet, which L8 sends into the tun, leaves by main too, so a
  service bound to the uplink's address answers by the uplink.
- E2: the lookup is a `fib` expression's reverse path check of a reply main
  routes to that link. Without it the check would find the tun at E3 and drop
  the reply.
- E3: the mesh's default, which 5420 skips at L11, answers here, so the host's
  own traffic from any source leaves by the exit. A throw goes on to main.
- Under [the kill switch](#the-kill-switch-on-linux), E3's lookup goes on to
  5445 rather than main: to one of this node's own prefixes or a carve-out it
  ends by main's route there, and any other ends refused at 5450. E1 and E2
  still end by main, and meet the switch's chains.

A lookup bound to a device, such as by a socket bound with `SO_BINDTODEVICE`,
ends by the rows above with these changes. An address of the host's own ends at
L1 only for a lookup bound to the device that holds it.

| Row | Bound to   | Family | Where it ends                                                                                                                                                                                                                                                                                                              |
| --- | ---------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1  | the uplink | IPv4   | the walk counts only a route out of the uplink, so a route of the mesh never answers. Main's route answers at 5410 or 32766, and where the walk meets a hold first, the overlay's behind a live route of the mesh among them, or a refusal, or no route, the packet goes onto the uplink's link for the destination itself |
| B2  | the uplink | IPv6   | the walk counts only a route out of the uplink, so neither a route of the mesh nor a hold answers. Main's route answers, and with none the lookup is refused                                                                                                                                                               |
| B3  | the tun    | IPv4   | into the tun, by the mesh's route where the walk meets one, and onto the tun's link where it meets a hold, a refusal or no route                                                                                                                                                                                           |
| B4  | the tun    | IPv6   | the walk counts only a route out of the tun, so a hold is passed over for a shorter route out of the tun, the mesh's at 5110, at 5420 where it is longer than /15, or at 5430, or main's at 5410. With none the lookup is refused                                                                                          |

B1 and B2 are a declared limit, also listed in
[limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) and
[the protocol deviations](design/protocol-deviations.md#updates-and-requests).
Such a packet never enters the mesh, and an application that binds the uplink's
device asked for the uplink. Over IPv4 a packet B1 puts on the uplink's link for
a held destination went by main's route before ranet3, and a host of that link
holding the address receives it.

A pass derives the rules again from what the mesh holds, so a prefix this node
starts announcing, or a reload moving the overlay, moves them in the next pass.
Each `nop` goes in before the `goto` that lands on it. A rule another program
deletes comes back within a second, as
[sharing a host](coexistence.md#routes-on-linux) describes. `ranet3 debug rules`
lists the rules the reconciler derives beside every rule the kernel holds.

Protocol 155 differs from BIRD's 12 and babeld's 42. The reconciler asks for
each route exclusively. A key another writer already holds stays as it is, and
the reconciler warns once. Linux logs
`kernel is leaving a route that another writer holds`. macOS logs
`kernel is leaving a route that another program holds`, or for a member of the
zero-free cover the line [the cover](#the-zero-free-cover-on-macos) gives.

Some routes are never installed:

- a prefix lying wholly in a range `overlay` refuses, such as `ff02::/16`,
  `169.254.0.0/16` or `0.0.0.0/8`, with the warning
  `kernel is not installing a prefix the mesh cannot carry`. A route that only
  holds such addresses, such as `128.0.0.0/1`, is installed as any other
- source-specific IPv4 routes, with the warning
  `kernel cannot install source-specific IPv4 route`

The mesh's own table still holds both kinds and forwards a source-specific IPv4
route, while a destination of the first kind meets the checks
[transit](#transit) lists.

### When a pass runs

A pass applies, in order, the addresses, the routes and the rules. It removes
what the mesh no longer wants before it installs. A pass that applied all 3, and
the kill switch where it asks for one, without error then asks the lookups
[sharing a host](coexistence.md#another-programs-rules) describes, on macOS the
overlay's alone. A pass that failed asks none, and it and a pass whose lookups
failed keep the last answers. A failed delete of the switch is warned of and
fails no pass.

- A change in the mesh, or a kernel notification, starts a pass 250 milliseconds
  later. Changes in that window join the same pass. On Linux the notifications
  are a route of the mesh's table coming or going, a rule of the reconciler's
  protocol going, and an address of the tun coming or going, another writer's
  among them, and another writer deleting the table `inet ranet3` or setting a
  flag on it, or changing the kill switch's chains and sets in it, while the
  reconciler writes them. On macOS they are a route of the utun, or of `lo0`,
  where the holds and the kill switch's rejects are, coming, going or changing,
  another writer's among them.
- A periodic pass runs every `cap.table.reconcile` (30 seconds by default) and
  corrects drift.
- A failed pass is retried after 1 second, doubling up to the periodic interval.
- A reload that changes `cap.table`, the addresses it assigns, `overlay` or
  `cap.exit`, or whose `cap.route` announcements make this node an exit or stop
  making it one, `ranet3 enable reconciler` and `ranet3 disable reconciler`
  start a pass too.
- A change of a default or an address the network watch reads starts a pass.
  With `cap.exit` a change of links alone, a link coming, going or moving a
  prefix or a far end, starts one too, which on Linux expands `forward` again
  and derives 5405, 5435 and 5440 from the links as they are. A change of links
  alone probes no session.
- On macOS a read of the host's routes by
  [the selection](#the-underlays-interface-on-macos) that finds them changed
  starts a pass at once, and so does each change of the addresses the underlay
  sends to: a reload that changes the trust document's literal endpoints, a
  dialer's first resolution or one to another address than its last, a dialer
  that ends after resolving, and a session that starts, ends or moves to another
  endpoint.

`ranet3 disable reconciler` withdraws every route, address and rule the
reconciler installed, 5450 among them on Linux, and deletes the kill switch,
[its chains and sets](#the-kill-switch-on-linux) on Linux and
[the rejects](#the-kill-switch-on-macos) on macOS, so the host's traffic leaves
by the uplink until it is enabled again. `ranet3 enable reconciler` puts them
back. Both are refused on a node with no `cap.table`.

### Routes that count as a default

Some routes would carry the host's own traffic into the mesh, and they count as
a default. Such a route lies outside `overlay` and is shorter than `/8` for IPv4
or `/16` for IPv6, or contains its family's unspecified address however long it
is. A default and its `/1` halves count, and so do a split internet such as four
IPv4 `/2`s or `2000::/3`, and a wide prefix such as `fd00::/8`, `fc00::/7` or an
IPv4 `/7`. A route at or longer than the floor, or inside the overlay, is a
subnet, unless it contains the unspecified address. A route lies inside the
overlay when each of its addresses lies in some entry, whether one entry holds
it or several together do. Without `overlay` no route lies inside the overlay,
and macOS's interface scope judges every route as though none did.

The floors are `/8` and `/16` because a route shorter than either takes a share
of a host's traffic as a default does, a split internet above all, while the
subnets a mesh routes outside its overlay are longer. The unspecified address
counts at any length because a send on macOS that names its interface, as each
of ranet3's underlay datagrams without a pin does, falls back to it, as
[the zero-free cover](#the-zero-free-cover-on-macos) describes.

The reconciler installs a route that counts only after a session has been live.
It withdraws them all once no session has been live for
`cap.table.capture_grace` (10 seconds by default, 1 second at least), and
restores them on the first live session. On macOS under `cap.exit`, in a family
the tun holds an overlay address of, a route holding its family's zero address
goes in as the members of the zero-free cover it contains, as
[the zero-free cover](#the-zero-free-cover-on-macos) describes.

A session is live for 20 seconds after the last authenticated IKE message from
its peer, and for 20 to 30 seconds after the last authenticated ESP packet, as
[the design's limits](design/limits.md#ike) list. A pass that installs such a
route where the last held none logs
`kernel is installing the routes that carry this machine's own traffic over the mesh`,
and the withdrawal of them logs
`kernel is withdrawing the routes that would carry this machine's own traffic`.
An exit logs neither for the default it announces, which it never installs.

The reconciler never installs a hold of a route that counts, nor this node's own
prefix that counts, whatever the sessions. An `unreachable` route of that width
in the kernel would answer with an error every lookup of the host's own traffic
that ends at it, as
[where a lookup ends on Linux](#where-a-lookup-ends-on-linux) and
[on macOS](#where-a-lookup-ends-on-macos) give, while other sessions stay live,
and a retracted split internet would cut the host off there. The mesh's own
table keeps the hold, and a packet the tun hands ranet3 for an address inside it
is answered unreachable rather than following a shorter route (RFC 8966 section
3.5.4), unless a steering policy takes it or the checks at the mesh's edge drop
it, as [transit](#transit) says. A peer's packet for such an address never
reaches the host, and the [forwarding decision](#transit) answers it
unreachable. A packet the host sends or forwards for one ends as
[where a lookup ends on Linux](#where-a-lookup-ends-on-linux) and
[on macOS](#where-a-lookup-ends-on-macos) give for the routes left: by the
host's own routes, or by a shorter route of the mesh back into the tun, where
ranet3 answers or drops it the same way.
[The protocol deviations](design/protocol-deviations.md) list the departure.

A node whose `cap.route` announces, or whose `cap.egress` advertises, a prefix
that counts and is not a default makes itself an exit for that family, as if it
announced a default: every other node's reconciler treats a route to the prefix
as above. On Linux, and on macOS for a `cap.egress` advertisement, the file
still loads, and the daemon logs a warning at startup and on each reload it
applies, such as
`config: cap.route announces fd00::/8, outside the overlay and shorter than /8 for IPv4 or /16 for IPv6 or holding the unspecified address, which counts as a default and makes this node an exit for its family, as routing.md says`.
On every platform but Linux such a `cap.route` announcement, a default among
them, is refused at startup and on a reload, as
[gaps on macOS](platforms.md#gaps-on-macos) gives. A gateway to a network
numbered from `fd00::/8` that should stay a subnet router announces the prefixes
it carries, each `/16` or longer, instead.

`ranet3 exit list` lists a `/0` or the two `/1` halves one node advertises
together, and nothing else. A node whose other advertisement counts, such as
`2000::/3`, carries its family's traffic with no row there: `ranet3 routes`
shows its route, and `ranet3 whois` names the peer an address inside it takes.

### Ownership

The reconciler reads back, deletes and withdraws only what it owns. On Linux it
owns the routes in its own table that carry its protocol and leave by its tun,
and its holds and throws there. It also owns the rules that carry its protocol
and the addresses it added, and the chains `fallback` and `output` and their
sets in the nftables table `inet ranet3` by their names, whoever wrote them,
which it writes, reads back and deletes as
[the kill switch](#the-kill-switch-on-linux) gives. On macOS it is the routes of
its own shape out of its own utun, and on `lo0` the reject routes of the
switch's shape at the switch's keys and the overlay's, whoever wrote them, as
[the kill switch on macOS](#the-kill-switch-on-macos) gives.
[Sharing a host](coexistence.md) describes the rules in full.

## Linux and macOS

|                                                  | Linux                                                                                                                                 | macOS                                                                                                                                                                                                                                                                          |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Table                                            | `cap.table.id`                                                                                                                        | the single forwarding table, `id` must stay 200                                                                                                                                                                                                                                |
| Ownership                                        | the protocol `cap.table.proto`                                                                                                        | the utun and the route's shape, `proto` must stay 155                                                                                                                                                                                                                          |
| Metric                                           | installed                                                                                                                             | not stored                                                                                                                                                                                                                                                                     |
| Hold                                             | `unreachable` route                                                                                                                   | reject route scoped to the utun, and an overlay prefix's unscoped on `lo0`                                                                                                                                                                                                     |
| Source-specific IPv6 route                       | installed with its source                                                                                                             | scoped to the utun where its source prefix holds an address of the utun, and otherwise not installed                                                                                                                                                                           |
| A route holding an address the underlay sends to | installed, and the underlay's mark takes its datagrams past it                                                                        | the pieces of it around the address where it goes in unscoped, longer than the host's own route to it, which is not the one holding its family's zero address, in mode off and under `cap.exit` alike                                                                          |
| A route inside a host route longer than `/0`     | installed, and the host's route answers ahead of it at rule 5410, as row L6 of [the policy rules](#policy-rules-on-linux) gives       | outside the overlay, where the host's route is unscoped and out of another interface, scoped to the utun in mode off and under `cap.exit` alike, a member of the zero-free cover among them                                                                                    |
| A `/0` default                                   | installed                                                                                                                             | scoped to the utun. Under `cap.exit`, in a family the tun holds an overlay address of, installed as its zero-free cover, unscoped                                                                                                                                              |
| Any other route that counts as a default         | installed                                                                                                                             | scoped to the utun. Under `cap.exit`, in a family the tun holds an overlay address of, one holding its family's zero address as the zero-free cover's members it contains, and another unscoped                                                                                |
| `cap.exit`                                       | the rules of [exit mode](#exit-mode-on-linux), `forward`, [the kill switch](#the-kill-switch-on-linux) and [mode 3](#mode-3-on-linux) | the routes of [the zero-free cover](#the-zero-free-cover-on-macos), mode 3 among them, [the kill switch](#the-kill-switch-on-macos) as reject routes on `lo0`, and `forward` and `inbound` refused, as [the configuration reference](configuration-reference.md#capexit) gives |
| Policy rules                                     | derived and installed                                                                                                                 | none                                                                                                                                                                                                                                                                           |
| An underlay datagram                             | marked 0x72, so its lookup ends past the mesh's routes                                                                                | names the interface the selection answers, or the source its pin holds, as [the underlay's interface](#the-underlays-interface-on-macos) says                                                                                                                                  |
| This node's own prefix outside the overlay       | throw route, for one that counts as no default, that the mesh can carry and that carries no IPv4 source                               | nothing, so a lookup for it from a socket bound to no interface and no address of the utun ends as row D2 of [where a lookup ends on macOS](#where-a-lookup-ends-on-macos) gives                                                                                               |
| Hold of each overlay prefix                      | installed for each, but one a carve-out equals, as [carve-outs](antispoof.md#carve-outs) describe                                     | the same, on `lo0` in every mode                                                                                                                                                                                                                                               |
| `where` in the logs                              | `table 200 protocol 155`                                                                                                              | `interface utun6`, for example                                                                                                                                                                                                                                                 |

On both platforms a route that counts as a default, the `/0` default among them,
goes in only once a session has been live, and never on an exit or in mode 3,
but for mode 3's steered defaults, as [what it installs](#what-it-installs)
says. On macOS a route scoped to the utun reaches a socket bound to the utun or
to an address of it, as
[where a lookup ends on macOS](#where-a-lookup-ends-on-macos) says. An address
the underlay sends to is a literal address of a node's endpoint in the trust
document, the address a running dialer last resolved an endpoint written as a
hostname to, or the address a live session sends to.

iOS and Android have no reconciler. [Platforms](platforms.md) covers each
platform in full.

### Where a lookup ends on macOS

macOS has no policy rules, and the reconciler writes into the one forwarding
table every program shares. A socket bound to no interface and no address of the
utun takes the longest match among the table's unscoped routes, the host's and
the reconciler's alike. A route scoped to an interface answers a socket bound to
that interface, and one scoped to the utun also answers a socket bound to an
address of the utun, which the source-specific row below relies on, but for the
IPv4 TCP connect row D6 gives. A route that counts as a default goes in only
once a session has been live, and never on an exit or in mode 3, but for mode
3's steered defaults, as [what it installs](#what-it-installs) says. Under
`cap.exit` a family the tun holds an overlay address of takes the second column,
and a family it holds none of is left out of the mode and takes the first. A
family the utun holds no address of at all goes in in neither, as
[the zero-free cover](#the-zero-free-cover-on-macos) gives, but for a hold with
no source at a prefix of `overlay`, which goes on `lo0` all the same. The first
row that matches gives how an entry of the mesh's table goes in:

| Entry of the mesh's table                                                                                      | Mode off           | `cap.exit`                                          |
| -------------------------------------------------------------------------------------------------------------- | ------------------ | --------------------------------------------------- |
| This node's own prefix outside the overlay, a hold that counts, or a prefix the mesh cannot carry              | nothing            | nothing                                             |
| A hold with no source at a prefix of `overlay`                                                                 | unscoped on `lo0`  | unscoped on `lo0`                                   |
| A route at one address the utun holds                                                                          | nothing            | nothing                                             |
| A source-specific IPv4 route, or a source-specific IPv6 route whose source prefix holds no address of the utun | nothing            | nothing                                             |
| A hold                                                                                                         | scoped to the utun | scoped to the utun                                  |
| A source-specific IPv6 route                                                                                   | scoped to the utun | scoped to the utun                                  |
| A route outside the overlay inside an unscoped route of the host's longer than `/0` on another interface       | scoped to the utun | scoped to the utun                                  |
| A route holding its family's zero address                                                                      | scoped to the utun | the zero-free cover's members it contains, unscoped |
| A route at a member's destination, such as a real `128.0.0.0/1`                                                | scoped to the utun | unscoped                                            |
| A route that counts as a default                                                                               | scoped to the utun | unscoped                                            |
| Any other route                                                                                                | unscoped           | unscoped                                            |

A destination takes one scoped route. The reconciler offers the entry with the
most specific source first, and leaves another entry that would go in scoped at
the same destination uninstalled, such as `::/0` beside `::/0` from a prefix of
the utun, and logs it once. Under `cap.exit`, a route holding its family's zero
address goes in as the members of
[the zero-free cover](#the-zero-free-cover-on-macos) it contains, and each
member takes the rows above, so one inside an unscoped route of the host's
longer than `/0` out of another interface goes in scoped. That row keeps the
order row L6 of [the policy rules](#policy-rules-on-linux) gives on Linux, where
such a route of `main` answers ahead of the mesh's table for every destination
outside the overlay. A route of the mesh that holds a prefix of the overlay and
lies inside such a route of the host's goes in as the pieces of it around the
overlay's prefixes it holds, each keeping the route's other fields, a member's
among them, so the pieces outside the overlay take that row. The piece at a
prefix with a hold of its own gives way to the hold, as row D7 gives, and the
piece at any other prefix goes in unscoped in both columns, as row L3 sends an
address of the overlay into the tun. The reconciler reads the host's routes from
[the selection](#the-underlays-interface-on-macos), once each pass.

A route of the mesh that goes in unscoped and holds an address the underlay
sends to, longer than the host's own route to that address, goes in as the
pieces of it around the address, unless the host's route is the one holding its
family's zero address. Each piece keeps the route's other fields, a member's
among them, and a route cut around one address goes in as at most one piece for
each bit past its length. A datagram that names the host route's interface is
looked up scoped to it by
[rt_lookup_common](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/route.c#L3183),
which passes over an unscoped route of another interface. A route scoped for any
reason is never cut. Where a lookup ends:

| Row | Lookup                                                                                                                                                                    | Where it ends                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | a socket bound to no interface and no address of the utun                                                                                                                 | the longest unscoped match, so a route of the mesh installed unscoped takes it into the utun wherever no longer route covers the destination, the host's or a hold or reject of ranet3's on `lo0`, as rows D7 and D8 give                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| D2  | a socket bound to no interface and no address of the utun, for a destination under a scoped route of the mesh, a scoped hold among them, or inside this node's own prefix | the scoped route is passed over, or there is none, and D1 gives the end: a wider unscoped route of the mesh takes it into the utun ahead of a shorter route of the host's, but one shorter than an overlay prefix holding the destination, where row D7 gives the end                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| D3  | a socket bound to the utun                                                                                                                                                | the longest route scoped to the utun that holds the destination answers it, and a scoped hold that answers refuses it. Where the longest unscoped match leaves by the utun, that unscoped route answers instead where it is a host route and the scoped answer is not, where the scoped answer's destination address is all zeros and its own is not, or where no route scoped to the utun holds the destination. An overlay prefix's hold on `lo0` is passed over, as a socket scoped to the uplink passes the kill switch's rejects over ([the kill switch on macOS](#the-kill-switch-on-macos)). So for a destination whose unbound send that hold refuses, as row D7 gives, the longest route scoped to the utun that holds it answers, which in mode off may be the mesh's default, and with none the kernel has no route for it                                                                                                                                                                                              |
| D4  | ranet3's underlay datagram that names no source, in mode off and under `cap.exit` alike                                                                                   | names the interface [the selection](#the-underlays-interface-on-macos) answers, never the utun, and the kernel's lookup scoped to it gives where it ends                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| D5  | ranet3's underlay datagram answering from the address a peer reached, in mode off and under `cap.exit` alike                                                              | names that address as its source, and an IPv6 one also the interface holding it, or for a link-local one its arrival interface. An IPv6 one leaves by the kernel's lookup scoped to that interface ([selectroute](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6_src.c#L1021)), an IPv4 one by the interface the kernel takes ([ip_output](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_output.c#L707)), and either as D4 once the kernel refuses the address or the interface                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| D6  | a socket bound to an address of the utun and to no interface                                                                                                              | a route scoped to the utun answers it, a source-specific route whose source prefix holds that address among them, past an overlay prefix's hold on `lo0` but over IPv4 TCP, as [the kill switch on macOS](#the-kill-switch-on-macos) gives with where such a send goes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| D7  | a socket bound to no interface and no address of the utun, for an overlay destination no unscoped route of the mesh at or inside its overlay prefix covers                | the overlay prefix's hold on `lo0` refuses it with `ENETUNREACH`, while ranet3 runs and after a crash, as [the kill switch on macOS](#the-kill-switch-on-macos) gives its lifetime, or a reject of the kill switch inside the prefix does. No unscoped route of ours that comes of a route of the mesh shorter than the prefix goes in at or inside it, neither a piece of a cut around the overlay or around an address the underlay sends to, nor a half of a key of the kill switch, nor a member of the zero-free cover, as Linux's hold wins over every such route (row L4), and a route of the mesh at or inside the prefix that goes in scoped, one from a source or a hold, keeps none there, since this lookup passes it over. A route of the mesh at the prefix goes in as its two halves and wins by length, or at a `/32` or `/128` prefix as a host route beside the hold, which the kernel matches first, a route of the mesh inside the prefix wins by length, and a connected network inside it wins by length too |
| D8  | a socket bound to no interface and no address of the utun under `fallback = "none"`, for a destination no route longer than a member of the zero-free cover covers        | while no exit is live, and after a crash, the member's reject on `lo0` refuses it with `ENETUNREACH`, as [the kill switch on macOS](#the-kill-switch-on-macos) gives. While one is live the members' halves out of the utun win by length, and at a key a shorter route of the mesh's holds, that route's halves win at any time, but where a route of the host's as long as that route or longer holds the key. A member inside an overlay prefix with a hold is withheld, and a shorter route's halves at a key inside one whose hold is longer than that route give way to the hold, so there row D7 gives the end                                                                                                                                                                                                                                                                                                                                                                                                              |

### The underlay's interface on macOS

On macOS ranet3's own datagrams keep off the utun by what each names, as Linux's
mark takes its lookup past the mesh's routes
([the underlay's mark](coexistence.md#the-underlays-mark)). A datagram sent
without a pin names the interface the selection answers, in `IP_PKTINFO` or
`IPV6_PKTINFO`
([udp_check_pktinfo](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/udp_usrreq.c#L1580)).
A datagram sent from a pin, the address a peer reached, names that address as
its source, and an IPv6 one also the interface holding the address, or for a
link-local one its arrival interface, as the answers below give, and
[moving hosts](platforms.md#moving-hosts) gives which sends carry a pin. The
selection's interface is the longest match for the destination among the host's
unscoped routes, those out of ranet3's utun, the kill switch's rejects and the
holds of the overlay in force on `lo0`, cloned routes and multicast and
broadcast entries left out. Another program's reject route stays a candidate. A
link-local destination takes the interface its zone names, and a zone that names
it by name takes the index the name had at its first answer, as
[limits](design/limits.md#the-underlay-socket) gives. The daemon reads the
routing table once at its start, reads it again 250 milliseconds after a
change's first notification, and again after any that arrives later, so a
datagram sent before that read names the interface the last read found. A
notification is a route, address or link message of the routing socket or a
kernel network event of a subclass that can move a link, the utun's own left
out, the ones the network watch of [moving hosts](platforms.md#moving-hosts)
follows. A table it cannot read at the start refuses the start, and a later read
that fails keeps the last answers and logs
`kernel keeps the underlay's last selection, since it could not read the routing table`
once.

A datagram that names no source carries the selection's interface in
`IP_PKTINFO` or `IPV6_PKTINFO`
([udp_check_pktinfo](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/udp_usrreq.c#L1580)),
and the kernel's lookup scoped to that interface gives where it ends
([rt_lookup_common](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/route.c#L3183)).
A socket connected to 1 peer for a session whose sends leave the source to the
kernel is bound to the selection's interface with `IP_BOUND_IF` or
`IPV6_BOUND_IF`, and a change of interface opens a new one. One for a session
the peer opened binds the address the peer's latest fresh request or answer
reached, and an IPv6 link-local one its arrival interface. Where the selection
holds no route for a peer, the datagram is refused with `ENETUNREACH` and
nothing is written, as a marked lookup ending in an empty `main` refuses on
Linux.

The kernel keeps the route the shared socket cached for a destination whatever
interface a later send to it names
([in_pcbladdr](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L1610),
[selectroute](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6_src.c#L1278)).
The socket releases that route, by setting `IP_BOUND_IF` or `IPV6_BOUND_IF` to 0
([inp_bindif_common](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L3198)),
whenever a send names another interface than the send before it did, and
releases it again after a write where another send named another interface
meanwhile. A datagram that names its source counts as naming the interface
holding that address, or for an IPv6 link-local one its arrival interface, and
one from an address no interface holds as naming an interface of its own. The
interface holding each address is read at most once for each read of the routing
table the selection makes, which an address that moves wakes as a route does, at
the first send from a pin after it, and again at the next such send where that
read failed. Each change of interface costs 1 `setsockopt`, which waits for the
socket's sends in flight
([ip_ctloutput](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_output.c#L2343),
[ip6_ctloutput](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/ip6_output.c#L2457)),
and 1 route lookup at the next send
([ip_output](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_output.c#L785),
[selectroute](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6_src.c#L1278)),
and sends at once naming 2 interfaces cost up to 2 `setsockopt` a datagram.
[Limits](design/limits.md#the-underlay-socket) gives the datagram sent while
another send is in flight.

An answer to a peer names the address the peer reached as its source (RFC 7296
section 2.11). An IPv6 answer also names the interface holding that address, or
for a link-local one its arrival interface, so the kernel looks its route up
scoped to that interface
([selectroute](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6_src.c#L1021)).
An IPv4 answer names no interface, and the kernel takes the interface holding
the address
([ip_output](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_output.c#L707)).
Once the kernel refuses that address, or the interface an IPv6 answer names, the
datagram names the selection's interface instead. The path MTU is read from the
interface a datagram names, or for one that names its source, the interface
holding it.

The interface each endpoint's datagrams name is recorded as the
`transport.underlay.selected` event when it is first found and each time it
changes ([debugging](development/debug.md#events)). `ranet3 debug rules` lists
as `underlay` rows each address live sessions send to, with the interface of the
pin their sends carry where that pin has one
([debugging](development/debug.md#commands)). A row with a pin's interface shows
that interface in its answer, a zoned link-local row without one its zone's
interface with no matched route, and the others the interface the selection
names with the route it matched, or `no route`. Each row's `Source` and
`Interface` columns, which Linux's lookups fill, read `-`.

### The zero-free cover on macOS

Exit mode on macOS is routes in the one table. Under
[`cap.exit`](configuration-reference.md#capexit) without `via`, in each family
the tun holds an overlay address of, a route Babel selects with no source that
holds its family's zero address goes into the kernel as the members of the
zero-free cover it contains, and every other route of the family with no source
that counts as a default goes in unscoped, but for one outside the overlay
inside an unscoped route of the host's longer than `/0` out of another
interface, which goes in scoped to the utun. In [mode 3](#mode-3-on-linux) the
reconciler declines every route that counts as a default and installs its
steered defaults alone, as below. A family the tun holds no overlay address of
keeps mode off's form, and a source-specific route stays scoped to the utun in
either mode, as [where a lookup ends on macOS](#where-a-lookup-ends-on-macos)
gives. The members of each family together hold every address but the hole,
which is `0.0.0.0/8`, and `::/8` less NAT64's two prefixes, the well-known
`64:ff9b::/96` ([RFC 6052](https://www.rfc-editor.org/rfc/rfc6052#section-2.1))
and the local-use `64:ff9b:1::/48`
([RFC 8215](https://www.rfc-editor.org/rfc/rfc8215)), which are IPv6 members of
their own:

| Family | Members                                                                                                                      |
| ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| IPv4   | `1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/2`, `128.0.0.0/1`                  |
| IPv6   | `100::/8`, `200::/7`, `400::/6`, `800::/5`, `1000::/4`, `2000::/3`, `4000::/2`, `8000::/1`, `64:ff9b::/96`, `64:ff9b:1::/48` |

A plain `/0` goes in as all of its family's, and a real `0.0.0.0/1` as the 7
from `1.0.0.0/8` to `64.0.0.0/2`. While
[the kill switch](#the-kill-switch-on-macos) is asked for, each member, and any
other unscoped route of the mesh at a member's destination, goes in as its two
halves, so a plain `/0` goes in as twice its family's members, and
`ranet3 debug route` names a half as a member, as
[route rows](development/debug.md#route-rows) give. An unscoped `/0` out of the
utun would collide with the host's own default, and macOS has no route replace.
A send that names its interface, as each of ranet3's underlay datagrams without
a pin does, falls back to the host's default, which the kernel finds by a lookup
of its family's zero address
([rt_lookup_common](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/route.c#L3390)).
A route of the mesh holding that address would answer that lookup and leave the
send no route. No member holds it, so a member holding an address the underlay
sends to goes in whole wherever the host's own route to that address is the one
holding the zero address, and nothing is written outside the utun.

An IPv6 route holding `::` but neither NAT64 prefix, such as a `::/16`, contains
no member, and but for `::/128` the reconciler installs nothing of it, counts it
as desired and skipped, and logs
`kernel is not installing a route its cover holds nothing of` once while the
mesh announces it. `::/128` and a route inside `0.0.0.0/8`, such as
`0.0.0.0/24`, never reach the cover: each lies wholly in a range `overlay`
refuses, so the reconciler never installs it and logs
`kernel is not installing a prefix the mesh cannot carry` instead.

Only the kernel's table holds the cover. Babel's table, the updates it sends and
`ranet3 exit list` keep the route, so no route's prefix is replaced by a longer
one inside the protocol (RFC 8966 Appendix C).

A member is withheld while the kernel holds another route of the reconciler's at
the member's own destination, unscoped, or scoped beneath a route of the host's
as the member would be, or the pieces of one there cut around the overlay's
prefixes it holds. The kernel then forwards every address outside the hole by
the route Babel's longest match would, or by a member where that match holds the
zero address. A route the kernel refuses or fails to install withholds nothing,
and the member it would withhold is tried in its place, but for a route refused
against this node's own member, described below. A route that another program's
route refuses at a member's own key leaves that member refused too, which takes
the family's cover out as described below.

The hole stays on the host's own route. NAT64's prefixes are members, so on a
network with DNS64 the traffic to an IPv4-only destination the resolver names
inside them takes a live exit, and while none is live meets the kill switch's
rejects where `fallback = "none"`, or leaves by the uplink with
`fallback = "uplink"`, as Linux's table carries it into the exit and its kill
switch drops it.

The cover of a family goes in and out whole, with the route it stands in for.
The capture gate judges that route, so the cover waits for a live session and
leaves when no session has been live for `capture_grace`. Each family's cover a
pass puts in or takes out logs
`kernel changed the cover a zero route is installed as` and records a
`kernel.cover` event, which the withdrawal of `ranet3 down` or
`ranet3 disable reconciler` does not, as
[debugging](development/debug.md#events) says. The Kernel line of
`ranet3 status` names the covered families.

A member that another program's route at its key refuses, or that fails to
install, takes its family's cover out whole, since part of a cover would split
that family's traffic between the mesh and the other route. Each of the family's
members that no route withholds counts as skipped, but for one that failed to
install, which the pass reports as an error. The refusal logs
`kernel is leaving a default's cover out, since another program holds a route at one of its members`
once, with `held_by` naming that route. The family's traffic then takes the
routes already in the host's table.

A mesh route at a member's own destination, such as a real `128.0.0.0/1` a node
advertises, takes that member's key. The reconciler deletes the member before it
installs the route. When the delete fails, the pass reports it as an error, and
macOS refuses the route against this node's own member, which counts as skipped.
Each later pass deletes the member again and tries the route, so the error and
the skipped count last until a delete succeeds. Meanwhile the member leaves by
the utun as the route would, and traffic is forwarded as Babel selects.

A family the tun holds no overlay address of is left out of the mode. Its routes
keep mode off's form, scoped to the utun, and the family's traffic stays on the
host's own routes. The Kernel line of `ranet3 status` names it, and the change
logs
`kernel leaves a family out of the exit mode, the tun holding no overlay address of it`
and records a `kernel.exit` event, as [watching it](#watching-it) lists. Where
the utun holds no address of a family at all, in mode off as in a family the
mode leaves out, the reconciler installs none of that family's routes out of the
utun, as [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic)
gives.

Both sets of families come from the pass's listing of the tun's addresses: those
the mode leaves out, and those the utun holds no address of. A pass whose
listing fails keeps both as the last listing that answered found them, and the
first pass covers none until a listing answers. Where nothing else of the pass
needs the listing, in mode off with no address `cap.table` assigns or takes off,
that pass does not fail, and the reconciler logs
`kernel could not list the tun's addresses, so it keeps the families the last listing found without one`
once until a listing answers.

A reload that adds or removes `cap.exit`, or a family that gains or loses its
overlay address, moves the routes on the next pass with no restart: the scoped
routes out and the cover in, or the reverse. The reconciler removes before it
installs, so the Mac's traffic leaves by its uplink in between.

In [mode 3](#mode-3-on-linux) the steered defaults hold the zero address, so
they go in as the cover, and the path counts a family whose cover is in as
installed. While a segment of the path is down they are withdrawn, and the
host's traffic meets the kill switch's rejects, or with `fallback = "uplink"`
written leaves by its uplink.

Until exit selection exists, a Mac under `cap.exit` without `via` takes
whichever `/0` Babel selects, once a session has been live. Babel, its updates
and `ranet3 exit list` keep the `/0`. A source-specific default is not covered.
It is a route like any other, and a hold of a default is not installed at all.

### The kill switch on macOS

With `cap.exit.fallback = "none"`, or `via` with `fallback` unwritten, the
reconciler writes a reject route on `lo0` at each of the zero-free cover's 18
keys, both families whether or not the tun holds an address of each: unscoped,
`RTF_UP`, `RTF_STATIC`, `RTF_REJECT` and `RTF_GATEWAY` via `127.0.0.1` or `::1`,
which `netstat -rn` shows as `UGRSc`. While the switch is asked for, every route
of the mesh's at a reject's key goes in as its two halves, since the kernel
holds one unscoped route per key and mask, so the cover is twice its members and
wins by length while an exit is live. While none is, and after a crash, an
unbound send that ends at a reject is refused with `ENETUNREACH`
([rt_lookup_common](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/route.c#L3279)),
as row D8 of [where a lookup ends](#where-a-lookup-ends-on-macos) gives. A route
of the mesh's shorter than a key that holds it, such as one holding NAT64's
prefixes, goes in whole with the key's two halves beside it, which carry its
fields and win over the reject, so the route carries all it holds, unless a
route of the host's as long as it or longer holds the key. That route of the
host's answers ahead of the mesh's there, so the key gets no halves and the
reject refuses it. `RTF_GATEWAY` keeps a route on a loopback interface out of a
scoped lookup
([route.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/route.c#L3316)),
so a send scoped to an interface passes the rejects over.

This is the one list of what leaves by a link outside the mesh while no exit is
live, and after a crash:

- a connected network, the LAN with its gateway and a resolver on it, by its own
  route, longer than the rejects
- multicast, the limited broadcast and link-local, each by a route of the host's
  longer than the rejects or scoped apart from them
- a destination inside another program's route longer than a reject's key, such
  as another VPN's on its own utun, or Tailscale's
- a destination in [the zero-free cover's hole](#the-zero-free-cover-on-macos),
  which no reject holds, by the host's own route
- a socket scoped to the uplink, or bound to the uplink's address, but an IPv4
  TCP connect bound to the uplink's address, which is refused
- a TCP connection or a connected UDP socket opened over the uplink before the
  rejects went in, in either family, whose sends keep leaving by the uplink
  while it lasts, where Linux's filter drops them from the next packet on
- this node's underlay and its queries for endpoint names to a nameserver
  outside the overlay, each naming the interface
  [the selection](#the-underlays-interface-on-macos) answers
- this node's own prefixes outside the overlay, only where a route of the host's
  longer than the rejects reaches them
- a service's replies over IPv6 TCP, whether its socket is bound to the uplink's
  address or to the wildcard, and over UDP where it is bound to the uplink's
  address. Its replies over IPv4 TCP and over UDP on the wildcard are refused,
  which is why macOS refuses `cap.exit.inbound`. `cap.exit.lan` widens nothing,
  since every connected network passes already

A reject is the reconciler's by its shape alone, `lo0`, those four flags and
that gateway, unscoped, at one of the 18 keys, whoever wrote it, so one another
program wrote in exactly that shape is taken over and deleted at a stop. A route
of another shape at a key is reported and never removed, and while it stands the
switch does not read back. Each pass reads the rejects back from its one dump of
the table and writes any that is missing. While one does not read back as
written, `ranet3 status` names the switch `not holding` with the reason, such as
`another program's route 128.0.0.0/1 via 192.0.2.1 on en0 holds a key of the switch's`,
or for a route of the mesh's whose halves wait for its delete,
`this node's own route 128.0.0.0/1 on utun5 holds a key of the switch's until it goes in as its halves`.
A delete on `lo0` wakes the reconciler, so a reject another program deletes is
written again at once, and a route another program adds at a key waits for the
next periodic pass.

The hold of each prefix of `overlay` is a reject route of the same shape on
`lo0`, unscoped, in every mode, so an unbound send to an overlay address no
route covers is refused while ranet3 runs and after a crash, as Linux's
`unreachable` route outlives one. A route of the mesh's at a hold's key goes in
as its two halves, a half at a reject's key as its own two halves in turn, and
wins by length, and so does a connected network inside the prefix. At a `/32` or
`/128` prefix, which has no halves, the route of the mesh's goes in as a host
route beside the hold, which the kernel keys apart from the hold and matches
first, so the hold stays beneath it and refuses again once the route is gone,
after a crash too, as Linux's hold stays beneath the route. A link whose network
holds an overlay prefix whole is a [carve-out](antispoof.md#carve-outs), and
that prefix takes no hold. A route of that shape on `lo0` is the reconciler's at
a prefix of the overlay in force, or at one this process held a hold at, and
another program's at any other key, since `route add -reject` writes the same
shape.

A send the hold refuses unbound leaves by the uplink where it is bound to the
uplink's address, as for the rejects. Bound to an address of the utun, it passes
the hold over too, as a scoped send passes the rejects, and the longest route
scoped to the utun that holds the destination answers it, as row D6 of
[where a lookup ends](#where-a-lookup-ends-on-macos) gives. An IPv4 TCP connect
bound to the uplink's address, or to an address of the utun and to no interface,
is refused by the hold with `ENETUNREACH` instead. The utun's case was measured
where no route scoped to the utun held the destination, and is inferred where
one does from the connect bound to the uplink's address, which the hold refused
though a route scoped to the uplink held the destination. Where the longest
route scoped to the utun that holds the destination is a hold, it refuses the
send, and the kernel refuses it where no route scoped to the utun holds the
destination. Any other route takes it into the utun: the mesh's default or a
route that counts as one, in mode off or in a family the mode leaves out, or a
source-specific IPv6 route, which goes in scoped where its source prefix holds
an address of the utun. Where the route that takes it counts as a default, the
exit announcing that route answers an overlay address it reaches through that
route as unreachable where its own `overlay` holds the address, as
[transit](#transit) gives, and sends it out of its uplink as any destination
outside the mesh where it writes no `overlay` or one that does not hold the
address, as [what an exit carries out](exit-nodes.md#what-an-exit-carries-out)
gives. Where it is a source-specific route that does not count, the mesh routes
the send by the address it is bound to: to the node announcing the route where
the route's source prefix holds that address, which hands it to its host, as
[what a node announces](#what-a-node-announces) gives, and otherwise as the
mesh's table routes a send from that address, through an exit's default as above
or with the Mac's own answer of unreachable where that table holds no route for
it. The announcing node's host refuses the send where its lookup ends at a hold,
which takes that node's `cap.table` and its own `overlay` holding the address,
as [the route reconciler](#the-route-reconciler) gives. Where the lookup ends
elsewhere, at a link whose network lies inside the prefix or with no hold there
at all, the host's own routes carry the send, such as onto its LAN or out of its
uplink. On Linux the hold refuses such a send where the route that takes it on a
Mac is shorter than the overlay prefix, as row L4 of
[where a lookup ends](#where-a-lookup-ends-on-linux) gives, and a
source-specific route inside the prefix takes a send from its own source into
the tun, as row L3 gives.

The switch's lifetime:

- The reconciler's first pass writes it after the routes, which the start waits
  up to 10 s for before it dials a session, and every pass that asks for it
  writes it after the routes and every pass that no longer does deletes it
  before them, so a route of the mesh's never meets a reject at its key. A pass
  that finds the rejects an earlier instance left takes them over with no
  warning.
- A clean stop, `ranet3 down`, `ranet3 disable reconciler` and a reload to
  `"uplink"` or without `cap.exit` delete the rejects, and every stop deletes
  the holds. Where
  [the dump of the routing table they read](design/limits.md#dataplane-and-sockets)
  fails, `ranet3 down`, `ranet3 disable reconciler` and the reload try again
  later, and a stop leaves the rejects and the holds as `SIGKILL` does below.
- The stop a failed tun causes leaves the rejects, as Linux's leaves its chains,
  and the daemon exits 1 for
  [the supervisor's restart](service.md#restarts-and-the-network).
- After `SIGKILL`, or another stop that withdraws nothing, the rejects and the
  holds stay, a hold beneath a route of the mesh's at a `/32` or `/128` prefix
  among them, and the utun goes with the process and its routes with it, so the
  Mac's unbound traffic is refused until ranet3 starts again. A start followed
  by `ranet3 down` deletes them, and so does a start with no `cap.table`, the
  holds at its configuration's prefixes. A hold at a prefix the next
  configuration no longer holds stays, as
  [limits](design/limits.md#the-kill-switch-on-macos) gives.
- With ranet3 stopped, the operator deletes each with `route -n delete`, such as
  `route -n delete -net 128.0.0.0/1` and `route -n delete -inet6 -net 8000::/1`.
- Nothing outlives a reboot.

The daemon reads no count of the sends a reject refuses, so the switch reports
no drops on macOS, and `ranet3 debug rules` lists each reject with no count, as
[debugging](development/debug.md#commands) gives.

## Watching it

These commands show the routes. [Command line](cli.md) lists their flags.

- `ranet3 routes` shows Babel's table, every prefix, including the ones held
  unreachable. The prefixes this node announces and the addresses `cap.table`
  assigns show `this node` as their next hop. It is not the kernel's table.
- `ranet3 neighbors` shows each neighbor with its link cost, the amount
  `cap.babel.cost.extra` charges it, the cost it reports, its round trip and the
  routes it offers.
- `ranet3 whois <address>` shows the longest prefix covering an address first,
  then the shorter ones, each with the neighbor that is its next hop, or this
  node for one of its own.
- The Kernel line of `ranet3 status` shows where the reconciler writes, the
  routes installed and skipped, and the last pass. It then names each lookup the
  reconciler last found taken, an overlay prefix on Linux as
  `overlay 192.0.2.0/24 taken by table 51820 dev wg0`, or
  `a refusal (permission denied)` in place of the table, and on macOS by the
  route it ends at, as `overlay 192.0.2.0/24 taken by 192.0.2.0/25 on utun7`,
  and on Linux each live session's send whose lookup under the mark is taken as
  `the underlay's mark taken by table 200 dev ranet0 toward 203.0.113.70`, with
  the source and interface the send carries after it where it carries them, as
  `from 198.51.100.10 dev eth0`. With `cap.exit` it names the links the last
  pass forwarded as `exit mode forwarding br-1 docker0`, each link a `forward`
  entry matched and the pass left out as
  `forward e* skips eth0, the link the IPv4 default leaves by`, and a family the
  tun holds no overlay address of as
  `no IPv6 overlay address on the tun, so IPv6 is left out of the mode`, as
  [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) counts the
  family and says where its traffic goes. [When a pass runs](#when-a-pass-runs)
  lists what wakes the pass that reads the tun again. On macOS under `cap.exit`
  it names the families whose cover is in as `zero-free cover for ipv4`, and a
  family left out of the mode as on Linux. Under `fallback = "none"` it names
  the switch's state, `holding`, `passing` while an exit is live, or
  `not holding` with the reason the switch does not read back, and on Linux what
  the last lines of both chains have dropped, summed, as
  `fallback none holding, 12 packets, 720 B dropped`, or `drops not read yet` in
  place of the counts until a read of the chains by this process succeeds. On
  macOS it names no drops, since ranet3 reads no count of the rejects. It names
  a connected network left out of the LAN as
  `198.0.0.0/7 left out of the LAN as it captures the machine`, and one the
  private and link-local ranges and `cap.exit.lan` leave out in whole or in
  part, or of one sharing an address with the overlay each such prefix of its
  part outside the overlay, as
  `203.0.113.0/24 left out of the LAN as public, outside the private and link-local ranges and cap.exit lan`,
  an endpoint name whose last lookup failed, in any state of the switch, as
  `gateway.example.org does not resolve`, and a DNS server systemd-resolved
  queries through one link beyond the LAN, read when status is, as
  `DNS server 203.0.113.53 on eth0 lies beyond the LAN`. With `cap.exit.via` it
  names the path, its state and its counts, as
  [the command line](cli.md#reading-state) gives.
- `ranet3 debug netmon` lists each family's links outside the mesh with their
  networks and point-to-point far ends. On Linux exit mode derives its rules
  from them.
- `ranet3 debug rules` lists every lookup the reconciler last asked, taken or
  not, with the source and interface of an underlay lookup and its answer, as
  [debugging](development/debug.md#commands) gives, under `cap.exit.via` the
  steered defaults with the path's state, and under `fallback = "none"` the kill
  switch as the kernel holds it now, on Linux its chains and sets with each
  line's drop count and each set's elements, and on macOS each reject with no
  count.
- Under `fallback = "none"` a scrape carries the switch, and on Linux its drops,
  as [metrics](metrics.md#series) lists.

`SIGUSR1` writes the mesh's routes to the log, this node's own entries as
`via this node` and the holds as `via unreachable`.

| Log line                                                                                                                                                       | Level | When                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `babel neighbor up`, `babel neighbor down`                                                                                                                     | info  | a neighbor comes up or goes down                                                                                                                                                                |
| `babel route installed`                                                                                                                                        | info  | a route is selected                                                                                                                                                                             |
| `babel route retracted`                                                                                                                                        | info  | a route is held unreachable                                                                                                                                                                     |
| `kernel reconciler started`                                                                                                                                    | info  | the reconciler starts, naming where it writes                                                                                                                                                   |
| `kernel routes reconciled`                                                                                                                                     | info  | a pass added or removed a route                                                                                                                                                                 |
| `kernel changed the endpoints it cuts out of the mesh's routes or the routes it scopes beneath the host's`                                                     | info  | on macOS, a pass began or stopped cutting an address out or scoping a route beneath the host's, with `cut`, `restored`, `scoped` and `unscoped`, once for each change                           |
| `kernel reconciler withdrawn`                                                                                                                                  | info  | shutdown or `ranet3 disable reconciler` removed the routes, addresses and rules                                                                                                                 |
| `kernel finds an overlay prefix answered outside the mesh's table`                                                                                             | warn  | an overlay prefix's lookup became taken, or a taken one's answer changed                                                                                                                        |
| `kernel finds an overlay prefix answered through the tun or by a hold again`                                                                                   | info  | an overlay prefix's lookup stopped being taken                                                                                                                                                  |
| `kernel finds the underlay's mark answered through the tun`                                                                                                    | warn  | a send's lookup under the mark became taken, or a taken one's answer changed                                                                                                                    |
| `kernel finds the underlay's mark answered outside the tun again`                                                                                              | info  | a send's lookup under the mark stopped being taken                                                                                                                                              |
| `kernel no longer asks a lookup it found taken`                                                                                                                | info  | a taken lookup's prefix or send left the pass, or a withdrawal ended the lookups                                                                                                                |
| `kernel could not ask where its overlay and underlay lookups end`                                                                                              | warn  | the lookups failed, once until they answer again, and the last answers stay                                                                                                                     |
| `kernel can ask where its overlay and underlay lookups end again`                                                                                              | info  | the lookups answered after failing                                                                                                                                                              |
| `kernel leaves a link cap.exit forward matches out of the mode`                                                                                                | warn  | a `forward` entry matches the tun, `lo` or a default's link, once until it no longer                                                                                                            |
| `kernel no longer leaves a link cap.exit forward matched out of the mode`                                                                                      | info  | that link stopped being one of them, or stopped matching                                                                                                                                        |
| `kernel leaves a family out of the exit mode, the tun holding no overlay address of it`                                                                        | warn  | under `cap.exit`, the tun came to hold no overlay address of the `family`                                                                                                                       |
| `kernel no longer leaves a family out of the exit mode`                                                                                                        | info  | the tun holds one again, `cap.exit` was removed or the reconciler withdrew                                                                                                                      |
| `kernel is withdrawing the steered defaults`                                                                                                                   | warn  | under `cap.exit.via`, a pass found a segment of the path unresolved, with `segment` and `verdict`, once until that changes                                                                      |
| `kernel holds the steered defaults while every segment of cap.exit via resolves to a peer through its own /128, or for a segment after the first to this node` | info  | under `cap.exit.via`, a pass found every segment resolved, with `installed`, the families whose steered default, or on macOS its zero-free cover, it left in the table, once until that changes |
| `kernel's kill switch holds the host's traffic while no exit is live`                                                                                          | info  | the switch began holding, or holds again once it reads back, with `where`, the chains or the rejects on `lo0`                                                                                   |
| `kernel's kill switch passes the host's traffic to the exit live through the tun`                                                                              | info  | an exit became live under the switch, with `where`                                                                                                                                              |
| `kernel's kill switch is no longer asked for`                                                                                                                  | info  | a reload or a withdrawal ended the switch, with `where`                                                                                                                                         |
| `kernel is leaving its kill switch after the mesh failed`                                                                                                      | warn  | under `fallback = "none"` a failed tun's stop left the switch it found, with `where` and the last pass's `state`, empty before one                                                              |
| `kernel found no kill switch to leave after the mesh failed, so the host's traffic leaves by its routes`                                                       | warn  | under `fallback = "none"` a failed tun's stop found no switch, with `where` and the last pass's `state`, empty before one                                                                       |
| `kernel is leaving any kill switch there after the mesh failed, which it could not list`                                                                       | warn  | under `fallback = "none"` a failed tun's stop could not list the switch and deleted none, with `where`, `state` and `err`                                                                       |
| `kernel's kill switch does not read back as written`                                                                                                           | warn  | the switch stopped reading back, with `where`, `fault` and `detail`, where the host's traffic goes meanwhile, once for each fault until it does                                                 |
| `kernel could not delete a kill switch an earlier instance may have left, which keeps the host's traffic off the uplink until it is deleted`                   | warn  | a start or reload asking for no switch, or a start with no `cap.table`, failed to delete the switch, on macOS or the holds at its configuration's prefixes, with `where`, `err` and `fix`       |
| `kernel's first pass has not ended, so sessions are dialed before the kill switch is written`                                                                  | warn  | under `fallback = "none"` the start waited `waited` for the reconciler's first pass and dials without it                                                                                        |
| `kernel could not read the DNS servers systemd-resolved queries through each link`                                                                             | warn  | status could not name the resolvers beyond the LAN, once until it can                                                                                                                           |
| `stopped reading nf_tables notifications`                                                                                                                      | warn  | a read of the switch's notification socket failed, with `table`, `chains` and `err`, after which another writer's change waits for the next periodic pass                                       |

The 2 route lines share 1 limit of 1 line per second. Each carries
`changes_since_last`, the number of changes since the last line. A lookup's
lines carry `family`, `prefix` and the `address` asked inside it for an overlay
prefix or `endpoint` for the underlay, with the `source` and `interface` the
send carries where it carries them, and `answer`. The events
`babel.neighbor.up`, `babel.neighbor.down`, `babel.route.selected` and
`babel.route.retracted` record each change. `kernel.pass` records each pass that
changed the kernel, met a newly refused route, failed or followed a reload, and
a withdrawal only when it fails, `kernel.taken` each line that names a lookup,
`kernel.forward` each line about a skipped link, with its `entry`, `link`,
`reason` and `skipped`, `kernel.exit` each line about a family the tun holds no
overlay address of, with its `family` and `addressed`, `kernel.fallback` each
change of the switch's state, with `state` and `was`, each `holding`, `passing`,
`not holding` or `off`, and `kernel.path` each line about the path, with
`state`, `segment`, `verdict` and `installed`, as
[debugging](development/debug.md#events) says.

[Metrics](metrics.md#series) lists the series of Babel and of the reconciler,
`ranet3_babel_` and `ranet3_kernel_` by their prefixes, with what each counts.

The neighbor cost includes the amount `cap.babel.cost.extra` charges, which no
series reports alone. `ranet3 neighbors` shows it apart. [Metrics](metrics.md)
describes the scrape.
