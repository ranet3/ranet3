---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Routing"
description: "How Babel picks a route, and how the reconciler puts it into the kernel."
created: 2026-10-16
updated: 2026-10-18
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

| Timer           | Default    | Rule                                      |
| --------------- | ---------- | ----------------------------------------- |
| Hello interval  | 4 seconds  | `cap.babel.hello`                         |
| Update interval | 16 seconds | `cap.babel.update`, or 4 x the Hello one  |
| Neighbor dead   | 14 seconds | 3.5 x the neighbor's Hello interval       |
| IHU expiry      | 14 seconds | 3.5 x the interval the IHU names          |
| Route hold      | 56 seconds | 3.5 x the interval of the carrying Update |

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

The node holds each prefix it originates as unreachable in its own table. A
packet for an address inside the prefix that this node does not carry is
dropped. It does not follow a covering route such as a default.

With transit on, the node relays every route it selects to its other neighbors.
With transit off, it advertises only the prefixes it originates, and still
learns and installs every route. Transit is off unless
[`cap.transit`](configuration-reference.md) writes `enable = true`, and a change
to it takes a restart, as [reloading](reloading.md) lists.

`cap.egress` adds the prefixes it is ready to carry, without a source prefix.
[Exit nodes](exit-nodes.md) describes when it does.

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
carries. The reconciler installs the same hold in the kernel.

## The route reconciler

Writing a `cap.table` block turns the reconciler on. It mirrors the mesh's
selected routes and its holds into a kernel table. Every route other than a hold
leaves through the tun. The reconciler also assigns the tun's addresses. On
Linux it also installs policy rules and enslaves the tun to a VRF.

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

A pass applies, in order, the VRF, the enslaving, the addresses, the routes and
the rules. It removes what the mesh no longer wants before it installs.

- A change in the mesh, or a kernel notification, starts a pass 250 milliseconds
  later. Changes in that window join the same pass.
- A periodic pass runs every `cap.table.reconcile` (30 seconds by default) and
  corrects drift.
- A failed pass is retried after 1 second, doubling up to the periodic interval.
- A reload that changes `cap.table` or the addresses it assigns,
  `ranet3 enable reconciler` and `ranet3 disable reconciler` start a pass too.

`ranet3 disable reconciler` withdraws every route, address and rule the
reconciler installed. It also takes the tun out of a VRF the reconciler enslaved
it to, and removes a VRF the reconciler created. `ranet3 enable reconciler` puts
them back. Both are refused on a node with no `cap.table`.

### Routes that carry the host's own traffic

Some routes would carry the host's own traffic into the mesh. Such a route has a
prefix length of 0 or 1, or contains the family's unspecified address. The
reconciler installs one only after a session has been live. It withdraws them
all once no session has been live for `cap.table.capture_grace` (10 seconds by
default, 1 second at least), and restores them on the first live session.

A session is live for 20 seconds after the last authenticated IKE message from
its peer, and for 20 to 30 seconds after the last authenticated ESP packet, as
[the design's limits](design/limits.md#ike) list. No session counts as live
while the underlay socket is not ready. The withdrawal logs
`kernel is withdrawing the routes that would carry this machine's own traffic`,
and the restore logs
`kernel is carrying this machine's own traffic over the mesh again`.

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
| The `/1` halves                                    | installed                      | scoped to the utun. With `link.underlay.bind`, scoped when it covers a listed endpoint address, otherwise unscoped |
| VRF, rules, `prefsrc4`                             | supported                      | refused at startup                                                                                                 |
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
selects. A source-specific default, a hold and a real `/1` half that a node
advertises are not covered. They are routes like any other.

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
  unreachable. It is not the kernel's table.
- `ranet3 neighbors` shows each neighbor with its link cost, the amount
  `cap.babel.cost.extra` charges it, the cost it reports, its round trip and the
  routes it offers.
- `ranet3 whois <address>` shows the longest prefix covering an address first,
  then the shorter ones, each with the neighbor that is its next hop.
- The Kernel line of `ranet3 status` shows where the reconciler writes, the
  routes installed and skipped, and the last pass.

`SIGUSR1` writes the mesh's routes to the log.

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
