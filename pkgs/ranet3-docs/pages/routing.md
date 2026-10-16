---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Routing"
description: "How Babel picks a route, and how the reconciler puts it into the kernel."
created: 2026-10-16
updated: 2026-10-16
order: 45
---

Babel (RFC 8966) decides which neighbor carries each prefix. ranet3 forwards by
those decisions in its own table, keyed by source and destination prefix. The
route reconciler copies the same decisions into a kernel routing table, so the
host sends mesh traffic into the tun. Without `cap.table`, the reconciler does
not run, and the host routes into the tun however it is configured to. On macOS,
`link.underlay.bind` still writes a default for each family, scoped to the
underlay's interface. [Sharing a host](coexistence.md) describes that route.

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

A link's cost has 2 parts. The first is the receive cost the neighbor reports in
its IHU, scaled by the share of the neighbor's last 16 Hellos this node received
(ETX, RFC 8966 Appendix A.2.2). Each node computes the receive cost it reports
the same way, as `cap.babel.cost.rx` (96 by default) scaled by its own
reception.

The second part is a round-trip penalty (RFC 9616). The penalty is 0 at or below
`cap.babel.cost.rtt.min` (10 milliseconds). It is `cap.babel.cost.rtt.weight`
(1024) at or above `cap.babel.cost.rtt.max` (1024 milliseconds), and linear
between them. Each new sample moves the smoothed round trip 16.4 percent of the
way toward it. This node adds the penalty to its own cost of the link and does
not advertise it.

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

|                                                    | Linux                          | macOS                                                                                                                                |
| -------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| Table                                              | `cap.table.id`                 | the single forwarding table, `id` must stay 200                                                                                      |
| Ownership                                          | the protocol `cap.table.proto` | the utun and the route's shape, `proto` must stay 155                                                                                |
| Metric                                             | installed                      | not stored                                                                                                                           |
| Hold                                               | `unreachable` route            | reject route scoped to the utun                                                                                                      |
| Source-specific IPv6 route                         | installed with its source      | scoped to the utun, when the source covers an address on the utun                                                                    |
| A route covering a listed literal endpoint address | installed                      | scoped to the utun, with or without `link.underlay.bind`                                                                             |
| A `/0` default                                     | installed                      | scoped to the utun. With `link.underlay.bind`, scoped when it covers a listed endpoint address, otherwise tried unscoped and skipped |
| The `/1` halves                                    | installed                      | scoped to the utun. With `link.underlay.bind`, scoped when it covers a listed endpoint address, otherwise unscoped                   |
| VRF, rules, `prefsrc4`                             | supported                      | refused at startup                                                                                                                   |
| `where` in the logs                                | `table 200 protocol 155`       | `interface utun6`, for example                                                                                                       |

On macOS a scoped route reaches only a socket bound to the utun. A listed
endpoint address is a literal address of a node's endpoint in the trust
document. An endpoint written as a hostname does not count.

With `link.underlay.bind` set, the reconciler tries to install a default
unscoped when no listed endpoint address lies in it. That route collides with
the host's own default. macOS has no route replace, so the reconciler skips it
and warns once. A Mac therefore takes a mesh exit only through the halves,
`0.0.0.0/1` with `128.0.0.0/1` and `::/1` with `8000::/1`.

A half that covers a listed endpoint address still stays scoped. Every IPv4
address lies in 1 of the 2 IPv4 halves, and every global IPv6 address lies in
`::/1`. Listed IPv4 endpoints in both IPv4 halves leave the Mac without an IPv4
exit. Any listed global IPv6 endpoint leaves it without an IPv6 exit.

With `link.underlay.bind` set, a capturing route also waits until the underlay's
own interface has a default scoped to it for that family. While it waits, the
reconciler logs
`kernel is holding back a route that would carry this machine's own traffic`.

iOS and Android have no reconciler. [Platforms](platforms.md) covers each
platform in full.

## Watching it

These commands show the routes. [Command line](cli.md) lists their flags.

- `ranet3 routes` shows Babel's table, every prefix, including the ones held
  unreachable. It is not the kernel's table.
- `ranet3 neighbors` shows each neighbor with its link cost, the cost it
  reports, its round trip and the routes it offers.
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

| Metric                                 | Meaning                                       |
| -------------------------------------- | --------------------------------------------- |
| `ranet3_babel_neighbor_up{peer}`       | whether a neighbor is alive                   |
| `ranet3_babel_neighbor_cost{peer}`     | link cost to a neighbor, 65535 is infinity    |
| `ranet3_babel_routes_received{peer}`   | routes learned from a neighbor                |
| `ranet3_babel_routes_selected`         | routes in the forwarding table                |
| `ranet3_babel_routes_originated`       | prefixes this node announces                  |
| `ranet3_kernel_routes_installed`       | routes the kernel holds for the reconciler    |
| `ranet3_kernel_routes_skipped`         | selected routes the last pass did not install |
| `ranet3_kernel_pass_timestamp_seconds` | when the last pass finished                   |
| `ranet3_kernel_pass_failed`            | whether the last pass reported an error       |

[Metrics](metrics.md) describes the scrape.
