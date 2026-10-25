---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Routing"
description: "How Babel picks a route, and how the reconciler puts it into the kernel."
created: 2026-10-16
updated: 2026-10-26
order: 45
---

Babel (RFC 8966) decides which neighbor carries each prefix. ranet3 forwards by
those decisions in its own table, keyed by source and destination prefix. The
route reconciler copies the same decisions into a kernel routing table, so the
host sends mesh traffic into the tun. Without `cap.table`, the reconciler does
not run, and the host routes into the tun however it is configured to. On macOS,
`link.underlay.bind` still writes a default scoped to the underlay's interface
for a family whose zero address another program's route takes.
[Sharing a host](coexistence.md) describes that route.

[The configuration reference](configuration-reference.md) lists every key under
`cap.route`, `cap.babel` and `cap.table`.

## The Babel speaker

ranet3 runs a Babel speaker over its ESP sessions. Each ESP session is a
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

With `cap.babel.quality` set to `"none"`, reception does not scale the cost. A
route's metric is the link cost, at least 1, plus the metric the neighbor
advertises. A metric of 65535 is infinite and means unreachable.

## What a node announces

`cap.route.announce` lists the prefixes this node originates. It advertises them
with metric 0, under its own router id and seqno. An entry is a prefix, or a
prefix with the source it serves (`{ prefix, from }`). A source-specific entry
is IPv6 only (RFC 9079).

The node holds each prefix it originates as its own in its table. It holds each
address `cap.table` assigns the same way, as a host route that it announces only
if it originates that route too. A route a neighbor offers for the same
destination and source prefix as one of these never replaces it. A host address
of this node's, a `/32` or `/128` it originates or `cap.table` assigns, is
delivered whatever the source, as the host's kernel delivers it, so a route a
neighbor offers for that address is dropped whatever its source prefix. For a
wider prefix, a source-specific route a neighbor offers for the same destination
is another route: the node learns it and prefers it for packets from its source,
by RFC 9079 section 4's destination-first ordering. A peer's packet for an
address inside a prefix this node originates goes to the tun, and the host
decides it. A read off the tun for such an address is dropped with no answer.
Neither follows a covering route such as a default.

With transit on, the node relays every route it selects to its other neighbors
and forwards the packets they bring, as [transit](#transit) describes. With
transit off, it advertises only the prefixes it originates, and still learns and
installs every route. Transit is off unless
[`cap.transit`](configuration-reference.md) writes `enable = true`, and a change
to it takes a restart, as [reloading](reloading.md) lists.

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
intervals. The speaker leaves the selected route only for one better on both the
current and the smoothed metric. An equal metric keeps the current next hop.

When only unfeasible routes remain, the speaker sends a seqno request. It
repeats the request up to 4 times, the first after 3 seconds. A route is sent
back toward its own next hop as a retraction, which is split horizon.

A route that appears or goes away sends an update at once. So does a change of
next hop, origin or seqno, and a metric rise of at least `rx`. Any other change
waits for the next full update.

| Limit                               | Value |
| ----------------------------------- | ----- |
| Prefixes in the route table         | 16384 |
| Origins of 1 prefix                 | 1024  |
| Origins of 1 prefix from 1 neighbor | 256   |

## Retracted routes

A retracted or expired route is held at infinity for the hold time of the Update
it replaced, then flushed. While it is held, the forwarding entry answers
"unreachable" (RFC 8966 section 3.5.4). A packet for that prefix is dropped
instead of following a shorter covering route, such as a default another node
carries. The [forwarding decision](#transit) answers one a peer sends with
Destination Unreachable, and one the tun hands ranet3 goes unanswered. The
reconciler installs the same hold in the kernel, but for a route that
[counts as a default](#routes-that-count-as-a-default). Once the route is
flushed, the prefix stays held until the latest time any update this node sent
naming it reachable expires at a neighbor, if that is later, as the next
paragraph says. Neither hold waits for every neighbor to acknowledge the
retraction, as
[the protocol deviations](design/protocol-deviations.md#updates-and-requests)
say.

A prefix loses its last route when that route is flushed, when the session of
the neighbor that offered it closes or is replaced, or when this node stops
announcing it while `cap.table` does not assign it, or, for the host route of an
address, when `cap.table` stops assigning it while this node does not announce
it. A neighbor this node told the prefix is reachable may still send packets for
it here until that update expires there, even after a retraction, which is sent
once and never acknowledged. So the prefix is held the same way until the latest
time any update this node sent naming it reachable expires at a neighbor, unless
a neighbor's route for it is selected first. Each update's time is the route
expiry of
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

A hold costs transit what it costs this host's own traffic. A retracted prefix
covered by a shorter route is answered unreachable until the latest update this
node sent for it expires, 60 seconds at the defaults. An exit whose readiness
withdraws its default holds that default the same way. While it originates its
own default it holds no other exit's, since it drops every update for a prefix
it originates. With another exit's default on offer, its transit for the
internet moves to that exit once that exit's next update arrives, within 16
seconds at the defaults. With none, it answers that transit unreachable, IPv6
code 0 and IPv4 Network Unreachable, until the hold ends. Only a peer's packet
is answered so. A hold drops this host's own traffic into it with no answer, or,
where the hold counts as a default, leaves that traffic to the host's own
routes, since the kernel keeps no such hold. A leaf holding no other feasible
default holds its own for its own hold time, 56 seconds at the defaults.

## Transit

ranet3 decides each packet a session delivers in its own table, after this
node's [segments](segment-routing.md) take the ones addressed to them. Nothing
of the host takes part: its forwarding settings, its firewall's forward chain
and its kernel tables do not, and the tun carries only this host's own traffic.
The checks run in RFC 1812's order for both families, each before any answer, so
a malformed packet draws none:

1. A frame that holds no whole IP packet is dropped with no answer.
2. A multicast, limited broadcast or IPv6 link-local destination goes to the
   tun, whatever the table holds. An IPv4 link-local destination does not, since
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
   describe: one inside `cap.border.overlay` is answered as one no entry holds,
   and any other goes to the exit, or to the tun through a route `cap.route`
   announces, only where the mesh routes a reply to its source, through a peer,
   a held prefix, or a network or address of this node's own.
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

| Packet                         | IPv6 answer                     | IPv4 answer                                                                                                                                                                                             |
| ------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hop limit or TTL of 1 or less  | Time Exceeded, code 0           | Time Exceeded, code 0                                                                                                                                                                                   |
| No entry holds the destination | Destination Unreachable, code 0 | Host Unreachable, code 1, inside `cap.border.overlay`, Network Unreachable, code 0, elsewhere                                                                                                           |
| Inside a held prefix           | Destination Unreachable, code 0 | Host Unreachable, code 1, under a hold that does not [count as a default](#routes-that-count-as-a-default) or inside `cap.border.overlay`, Network Unreachable, code 0, elsewhere under one that counts |
| `cap.transit` off              | Destination Unreachable, code 1 | Destination Unreachable, code 13                                                                                                                                                                        |
| Larger than the next session   | Packet Too Big                  | Fragmentation Needed with DF, cut without                                                                                                                                                               |
| Options that cannot be read    |                                 | Parameter Problem                                                                                                                                                                                       |
| Link-local source              | Destination Unreachable, code 2 | none                                                                                                                                                                                                    |

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

A read off the tun to a multicast destination, link scope included, or to the
limited broadcast 255.255.255.255 is dropped and counted as multicast before its
route is looked up or it is steered. The mesh routes no multicast, and
[RFC 1812 section 5.3.5.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.5.1)
says "Limited broadcasts MUST NOT be forwarded", where a covering route such as
a default would carry either to the one peer it names.

`ranet3 status` counts each outcome on its `Transit` line, and
`ranet3_transit_packets_total` exports the same counts. A dropped packet also
records the event `netstack.transit.dropped` with its reason, at most once every
30 seconds.

## The route reconciler

Writing a `cap.table` block turns the reconciler on. It mirrors the mesh's
selected routes and its holds into a kernel table, and installs each prefix this
node originates as a hold, but for one that
[counts as a default](#routes-that-count-as-a-default). An address `cap.table`
assigns gets no route there unless this node originates it too, since the host's
kernel holds it as one of its own already. Every route other than a hold leaves
through the tun. The reconciler also assigns the tun's addresses. On Linux it
also installs policy rules.

### What it installs

| Property    | Value                                                       |
| ----------- | ----------------------------------------------------------- |
| Table       | `cap.table.id`, 200 by default                              |
| Protocol    | `cap.table.proto`, 155 by default                           |
| Metric      | `cap.table.metric`, or 0 for IPv4 and 1024 for IPv6         |
| Hold        | an `unreachable` route at metric 4294967295, with no device |
| IPv4 source | `cap.table.prefsrc4` on every IPv4 route                    |
| IPv6 source | a source-specific route carries its source prefix           |

Protocol 155 differs from BIRD's 12 and babeld's 42. The reconciler asks for
each route exclusively. A key another writer already holds stays as it is, and
the reconciler warns once. Linux logs
`kernel is leaving a route that another writer holds`. macOS logs
`kernel is leaving a route that another program holds`.

Some routes are never installed:

- multicast, link-local and loopback prefixes, and `255.255.255.255/32`, with
  the warning `kernel is not installing a prefix the mesh cannot carry`
- source-specific IPv4 routes, with the warning
  `kernel cannot install source-specific IPv4 route`

The mesh's own table still forwards both kinds.

### When a pass runs

A pass applies, in order, the addresses, the routes and the rules. It removes
what the mesh no longer wants before it installs.

- A change in the mesh, or a kernel notification, starts a pass 250 milliseconds
  later. Changes in that window join the same pass.
- A periodic pass runs every `cap.table.reconcile` (30 seconds by default) and
  corrects drift.
- A failed pass is retried after 1 second, doubling up to the periodic interval.
- A reload that changes `cap.table`, the addresses it assigns or
  `cap.border.overlay`, `ranet3 enable reconciler` and
  `ranet3 disable reconciler` start a pass too.

`ranet3 disable reconciler` withdraws every route, address and rule the
reconciler installed. `ranet3 enable reconciler` puts them back. Both are
refused on a node with no `cap.table`.

### Routes that count as a default

Some routes would carry the host's own traffic into the mesh, and they count as
a default. Such a route lies outside `cap.border.overlay` and is shorter than
`/8` for IPv4 or `/16` for IPv6, or contains its family's unspecified address
however long it is. A default and its `/1` halves count, and so do a split
internet such as four IPv4 `/2`s or `2000::/3`, and a wide prefix such as
`fd00::/8`, `fc00::/7` or an IPv4 `/7`. A route at or longer than the floor, or
inside the overlay, is a subnet, unless it contains the unspecified address. A
route lies inside the overlay when each of its addresses lies in some entry,
whether one entry holds it or several together do. Without `cap.border`, which
macOS refuses at startup, no route lies inside the overlay.

The floors are `/8` and `/16` because a route shorter than either takes a share
of a host's traffic as a default does, a split internet above all, while the
subnets a mesh routes outside its overlay are longer. The unspecified address
counts at any length because macOS falls back to it for a socket bound with
`IP_BOUND_IF`, as [sharing a host](coexistence.md#the-underlay-default-on-macos)
describes.

The reconciler installs a route that counts only after a session has been live.
It withdraws them all once no session has been live for
`cap.table.capture_grace` (10 seconds by default, 1 second at least), and
restores them on the first live session.

A session is live for 20 seconds after the last authenticated IKE message from
its peer, and for 20 to 30 seconds after the last authenticated ESP packet, as
[the design's limits](design/limits.md#ike) list. No session counts as live
while the underlay socket is not ready. The withdrawal logs
`kernel is withdrawing the routes that would carry this machine's own traffic`,
and the restore logs
`kernel is carrying this machine's own traffic over the mesh again`.

The reconciler never installs a hold of a route that counts, nor this node's own
prefix that counts, whatever the sessions. An `unreachable` route of that width
in the kernel would answer the host's own traffic it covers with an error while
other sessions stay live, and a retracted split internet would cut the host off.
The mesh's own table keeps the hold, and a packet the tun hands ranet3 for an
address inside it is dropped rather than following a shorter route (RFC 8966
section 3.5.4). A peer's packet for such an address never reaches the host, and
the [forwarding decision](#transit) answers it unreachable. A packet the host
sends or forwards for one follows the host's own routes instead: out of its
uplink, or by a shorter route back into the tun, where ranet3 drops it with no
answer. [The protocol deviations](design/protocol-deviations.md) list both
departures.

A node whose `cap.route` announces, or whose `cap.egress` advertises, a prefix
that counts and is not a default makes itself an exit for that family, as if it
announced a default: every other node's reconciler treats a route to the prefix
as above. The file still loads, and the daemon logs a warning at startup and on
each reload it applies, such as
`config: cap.route announces fd00::/8, outside the overlay and shorter than /8 for IPv4 or /16 for IPv6 or holding the unspecified address, which counts as a default and makes this node an exit for its family, as routing.md says`.
A gateway to a network numbered from `fd00::/8` that should stay a subnet router
announces the prefixes it carries, each `/16` or longer, instead.

`ranet3 exit list` lists a `/0` or the two `/1` halves one node advertises
together, and nothing else. A node whose other advertisement counts, such as
`2000::/3`, carries its family's traffic with no row there: `ranet3 routes`
shows its route, and `ranet3 whois` names the peer an address inside it takes.

### Ownership

The reconciler reads back, deletes and withdraws only what it owns. On Linux it
owns the routes in its own table that carry its protocol and either leave by its
tun or are its holds. It also owns the rules that carry its protocol and the
addresses it added. On macOS it is the routes of its own shape out of its own
utun. [Sharing a host](coexistence.md) describes the rules in full.

## Linux and macOS

|                                                    | Linux                          | macOS                                                                                                              |
| -------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------ |
| Table                                              | `cap.table.id`                 | the single forwarding table, `id` must stay 200                                                                    |
| Ownership                                          | the protocol `cap.table.proto` | the utun and the route's shape, `proto` must stay 155                                                              |
| Metric                                             | installed                      | not stored                                                                                                         |
| Hold                                               | `unreachable` route            | reject route scoped to the utun                                                                                    |
| Source-specific IPv6 route                         | installed with its source      | scoped to the utun, when the source covers an address on the utun                                                  |
| A route covering a listed literal endpoint address | installed                      | scoped to the utun, with or without `link.underlay.bind`                                                           |
| A `/0` default                                     | installed                      | scoped to the utun. With `link.underlay.bind`, installed as its zero-free cover, unscoped                          |
| Any other route that counts as a default           | installed                      | scoped to the utun. With `link.underlay.bind`, scoped when it covers a listed endpoint address, otherwise unscoped |
| Rules, `prefsrc4`                                  | supported                      | refused at startup                                                                                                 |
| `where` in the logs                                | `table 200 protocol 155`       | `interface utun6`, for example                                                                                     |

On macOS a scoped route reaches only a socket bound to the utun. A listed
endpoint address is a literal address of a node's endpoint in the trust
document. An endpoint written as a hostname does not count.

iOS and Android have no reconciler. [Platforms](platforms.md) covers each
platform in full.

### The zero-free cover on macOS

With `link.underlay.bind` set, a plain `/0` that Babel selects goes into the
kernel as 8 routes per family that together hold every address but `0.0.0.0/8`
and `::/8`:

| Family | Members                                                                                                     |
| ------ | ----------------------------------------------------------------------------------------------------------- |
| IPv4   | `1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`, `32.0.0.0/3`, `64.0.0.0/2`, `128.0.0.0/1` |
| IPv6   | `100::/8`, `200::/7`, `400::/6`, `800::/5`, `1000::/4`, `2000::/3`, `4000::/2`, `8000::/1`                  |

An unscoped `/0` out of the utun would collide with the host's own default, and
macOS has no route replace. No member holds its family's zero address, so a
socket bound with `IP_BOUND_IF`, ranet3's own underlay socket among them, falls
back to the host's own default for every destination. The members are therefore
unscoped even where a listed endpoint address lies in one, and nothing is
written outside the utun. That was measured on a Mac with a bound socket
connecting inside every member. The Mac had no unscoped IPv6 default, so the
IPv6 half was measured against a stand-in default on a test utun.

Only the kernel's table holds the cover. Babel's table, the updates it sends and
`ranet3 exit list` keep the `/0`, so no route's prefix is replaced by a longer
one inside the protocol (RFC 8966 Appendix C).

A member is withheld while the kernel holds another route of the reconciler's,
unscoped and in the same family, of length 1 up to the member's own, that
contains it. The kernel then forwards every address outside the hole by the
route Babel's longest match would, or by a member where that match is the `/0`.
A route the kernel refuses or fails to install withholds nothing, and the
members it would withhold are tried in its place, but for a route refused
against this node's own member, described below. A route that another program's
route refuses at a member's own key leaves that member refused too, which takes
the family's cover out as described below.

The hole, `0.0.0.0/8` and `::/8`, stays on the host's own route. `::/8` holds
`64:ff9b::/96`, the NAT64 well-known prefix, so NAT64 traffic does not take the
exit.

The cover of a family goes in and out whole, with the `/0`. The capture gate
judges the `/0`, so the cover waits for a live session and leaves when no
session has been live for `capture_grace`. Its family also waits for the host's
own default of that family, and while it waits the reconciler logs
`kernel is holding back a route that would carry this machine's own traffic`.
Each family's cover going in or out logs
`kernel changed the cover a plain default is installed as` and records a
`kernel.cover` event. The Kernel line of `ranet3 status` names the covered
families.

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

Until exit selection exists, a Mac with `bind` set takes whichever `/0` Babel
selects. A source-specific default and a real `/1` half that a node advertises
are not covered. They are routes like any other, and a hold of a default is not
installed at all.

A route the reconciler installs unscoped that is not a member but holds a zero
address, such as a real `0.0.0.0/1` or a `0.0.0.0/24`, needs a default scoped to
the underlay's interface for that family before it is installed. The reconciler
asks for it on every pass and asks again after a pass deletes such a route, so
the scoped default is withdrawn in that same pass, once the route is out of the
table. [Sharing a host](coexistence.md#the-underlay-default-on-macos) describes
it.

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
  routes installed and skipped, and the last pass.

`SIGUSR1` writes the mesh's routes to the log, this node's own entries as
`via this node` and the holds as `via unreachable`.

| Log line                                   | Level | When                                                                            |
| ------------------------------------------ | ----- | ------------------------------------------------------------------------------- |
| `babel neighbor up`, `babel neighbor down` | info  | a neighbor comes up or goes down                                                |
| `babel route installed`                    | info  | a route is selected                                                             |
| `babel route retracted`                    | info  | a route is held unreachable                                                     |
| `kernel reconciler started`                | info  | the reconciler starts, naming where it writes                                   |
| `kernel routes reconciled`                 | info  | a pass added or removed a route                                                 |
| `kernel reconciler withdrawn`              | info  | shutdown or `ranet3 disable reconciler` removed the routes, addresses and rules |

The 2 route lines share 1 limit of 1 line per second. Each carries
`changes_since_last`, the number of changes since the last line. The events
`babel.neighbor.up`, `babel.neighbor.down`, `babel.route.selected` and
`babel.route.retracted` record each change. `kernel.pass` records each pass that
changed the kernel, met a newly refused route, failed or followed a reload.

| Metric                                 | Meaning                                                                                    |
| -------------------------------------- | ------------------------------------------------------------------------------------------ |
| `ranet3_babel_neighbor_up{peer}`       | whether a neighbor is alive                                                                |
| `ranet3_babel_neighbor_cost{peer}`     | link cost with its extra, 65535 is infinity                                                |
| `ranet3_babel_routes_received{peer}`   | routes learned from a neighbor                                                             |
| `ranet3_babel_routes_selected`         | routes in the forwarding table                                                             |
| `ranet3_babel_routes_originated`       | prefixes this node announces                                                               |
| `ranet3_kernel_routes_installed`       | routes the kernel holds for the reconciler                                                 |
| `ranet3_kernel_routes_skipped`         | routes the platform refused in the last pass, and cover members left out with their family |
| `ranet3_kernel_pass_timestamp_seconds` | when the last pass finished                                                                |
| `ranet3_kernel_pass_failed`            | whether the last pass reported an error                                                    |

The neighbor cost includes the amount `cap.babel.cost.extra` charges, which no
series reports alone. `ranet3 neighbors` shows it apart. [Metrics](metrics.md)
describes the scrape.
