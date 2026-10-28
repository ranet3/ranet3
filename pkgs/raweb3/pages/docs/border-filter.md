---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "The border filter"
description: "Dropping what arrives from outside the mesh carrying a mesh source, a routing header or one of this node's SIDs."
created: 2026-10-19
updated: 2026-10-28
order: 55
---

The `cap.border` block makes this node drop 3 kinds of packet that arrive on a
link outside the mesh: a source in the mesh's own address space, an IPv6 routing
header of any type, and a destination that is one of this node's SIDs. A mesh
source, a segment routing header or a SID arriving from anywhere else is forged.
A routing header of another type goes too, since it could carry a segment
routing header behind it.

```toml
[cap.border]
overlay = ["203.0.113.0/24", "3fff:a::/36", "3fff:b::/48"]
```

[The configuration reference](configuration-reference.md#capborder) lists the
key and its refusals.

## What it defends

A node that forwards takes a packet from any of its links and routes it by its
destination. Where the host routes a mesh destination into the tun, as
[where a lookup ends on Linux](routing.md#where-a-lookup-ends-on-linux) gives,
every peer then takes the packet as the mesh's own. A host on the same link as
such a node can therefore put a packet into the mesh with any source the
[checks at the mesh's edge](routing.md#transit) pass, such as one no route of
the mesh covers or, on a node without `cap.border`, an overlay address no node
announces.

An [egress segment](segment-routing.md#egress-segments) carries out of the mesh
only the sources its `allow` list names. The list is authorization, and a host
beside a forwarding node without `cap.border` can forge each source it names
that those checks pass and the exit routes a reply to, such as an address the
forwarding node itself announces. An allowed address no node announces does not
leave the exit. The forwarding node drops it as `unowned_source` where its table
routes the inner destination by a route that counts as a default, and otherwise
the exit refuses it as an inner source the mesh routes no reply to. A forged
allowed source the exit routes a reply to, sent to its SID through that node,
would leave the exit under its class's translation, so the exit would relay
traffic for someone who is not on the mesh. The filter on the node in front of
the exit drops it at the first hop. The filter on the exit itself protects the
exit's own SID from its own links, the host's services from a forged mesh
source, and every other exit from a forged allowed source sent through this
node. Another node's SID that delivers to the mesh is protected by that node, as
[below](#what-it-drops) describes.

The filter guards the mesh's edge on the links outside it. A packet this host's
own kernel routes into the tun enters the mesh by the other side of that edge,
where the
[forwarding decision checks what the tun hands this
node](segment-routing.md#at-the-border-of-the-mesh): it drops a read from a
source the table routes to another node or holds unreachable, through a route
that does not count as a default, or from an overlay source this node does not
own, one carrying a routing header the mesh refuses, one to one of this node's
own SIDs, one bound through an exit from a source this node does not own, or one
whose inner packet fails the same checks. Those reads count on the `Transit`
line, not among the border's drops.

## What it drops

Each packet arriving on a device outside the mesh meets the rules in this order,
and the first that matches decides:

| Rule                                     | Drops                                                                             | Family |
| ---------------------------------------- | --------------------------------------------------------------------------------- | ------ |
| 1 per `overlay` prefix                   | a source inside the prefix                                                        | its    |
| 1                                        | a routing header of any type, among the first 12 extension headers from Linux 7.1 | IPv6   |
| 1 per SID of a `cap.segment.local` entry | that SID as the destination, whatever the segment's behavior                      | IPv6   |

A packet 2 rules match counts once, in the first, so the counters partition the
drops. A packet matching none passes. A drop sends no ICMP error, as
[the deviations](design/protocol-deviations.md#drops-with-no-answer) explain.

The overlay is the address space every node of the mesh is numbered from, the
same on every node. It has to cover every exit's `allow` list, since a source
outside it passes every filter. The loader refuses an egress segment with an
`allow` entry the overlay does not cover.

The overlay holds only addresses the mesh carries inside its tunnels. Every
address a peer's ESP comes from lies outside it, since that ESP arrives on a
link outside the mesh and the filter would drop it. So does the source of any
other packet that reaches this node outside the tunnels, such as one another
node sends from its mesh address over the internet rather than through the mesh.
The loader cannot check either, since endpoints are often names.

The routing header rule drops a routing header of every type from outside,
whatever its segments name. nf_tables finds only the first routing header of a
packet, so a rule for type 4 alone would pass a segment routing header behind
one of type 0 or 2, which a node acting on segment routing headers still
processes. A segment routing header naming another node's SID is the same
forgery one hop later, and before typed SIDs this node cannot tell which
addresses are SIDs. That departs from RFC 8754 section 4.2 and RFC 5095 section
4.2 for a node transiting another segment routing domain or Mobile IPv6 traffic
between 2 links outside the mesh, as
[the deviations](design/protocol-deviations.md#the-border-filter) describe.

From Linux 7.1 the kernel's search for a routing header gives up at the 13th
extension header, so the rule passes a routing header behind 12 others. A Linux
host from 7.1 that the packet is addressed to with `seg6_enabled` set still acts
on a segment routing header 13th in the chain, and drops a packet whose routing
header sits further back. Before 7.1 neither search has a limit: the rule finds
a routing header anywhere in the chain, and the host acts on one anywhere. This
node's own SIDs refuse a packet unless its outer source lies in the overlay,
wherever its routing header sits.

The SID rule holds this node's own segments only, since before typed SIDs this
node cannot tell which addresses are SIDs. A packet to another node's SID with
no routing header passes it, and the overlay rule drops it only for a source
inside the overlay. The SID's own node refuses the rest: every local SID acts
only on a packet whose outer source lies in the overlay's IPv6 prefixes, the
per-node list of RFC 8754 section 5.1, as
[segment routing](segment-routing.md#local-segments) describes. Between them a
host beyond the mesh reaches no SID through a node with the filter. A node that
forwards without `cap.border` is only warned, as
[below](#nodes-that-forward-without-it) describes, and passes on to every SID in
the mesh a packet with a forged overlay source, such as an overlay address no
node announces, when its host routes the packet into the tun and the
[tun read's checks](routing.md#transit) pass it. So a file with a local segment
needs `cap.border`, with an IPv6 prefix in its overlay.

## Which devices are inside

The filter accepts whatever arrives on a device inside the mesh, before any
drop. The list is derived and has no setting:

1. the mesh tun, through which an egress segment's inner packets arrive as well
2. `lo`, through which a packet this host sends to its own address arrives

A deployment that carries mesh sources on another link, a subnet router of
mesh-numbered hosts, is refused at load: a `cap.egress` `advertise` entry that
overlaps the overlay is refused, since the hosts behind such a node arrive on a
link outside the mesh with a mesh source and the filter would drop them.

## Where it runs

The filter owns its own nftables table, `inet ranet3`, holding 1 chain:

| Property | Value        |
| -------- | ------------ |
| Name     | `border`     |
| Type     | `filter`     |
| Hook     | `prerouting` |
| Priority | -300 (`raw`) |
| Policy   | `accept`     |

Prerouting comes before the routing decision, so a forged packet to one of this
node's own addresses is dropped as well as one to forward. Priority `raw` comes
after defragmentation and before conntrack, so a forged packet creates no
conntrack entry. Each rule carries its spelling as its comment, which
`nft list ruleset` shows: `accept via ranet3`,
`drop ipv4 source 203.0.113.0/24`, `drop ipv6 routing header`,
`drop ipv6 destination 3fff:b:0:306::3`. Only the drops carry counters.

The filter needs no forwarding. With forwarding off the kernel routes nothing
from the node's links into the tun, but a forged mesh source to the node's own
address still reaches the host's services, and a host firewall's reverse path
check in loose mode passes it wherever it finds a route back to that source
through the tun, as for a live node's address. The filter drops that packet too,
so it runs wherever `cap.border` is written.

A pass reads the chain back whole: every rule in order, whoever wrote it, the
table's flags, and the chain's type, hook, priority and policy. When anything
differs from what the configuration asks for, a rule another writer added, a
dormant table or a policy of drop among it, the pass rewrites the table and the
chain in 1 transaction and reads them back again. nf_tables clears no table flag
in place but dormant, and changes no chain's type, hook or priority, so when one
of those differs the same transaction first deletes the table, and any chain
another writer put in it, then makes it again. A pass runs every 30 seconds, and
a failed one is retried after 1 second, doubling up to the 30. Another writer
adding, changing or deleting the table, the chain or a rule wakes a pass at
once, and the filter reads not ready until that pass puts the chain back in 1
transaction. Between the change and that transaction forged packets may pass.
The filter's own writes wake nothing. Notifications the daemon lost, which
another table's large transaction can overflow its socket with, wake a pass too
and leave readiness as it was, since that pass reads the chain back.

`ranet3 down` leaves the filter in place: the kernel still forwards and the
host's services still trust mesh sources. At shutdown the filter goes last,
after the reconciler withdrew the routes into the tun and the mesh closed its
sessions, so nothing forwards into the mesh by the time it is gone.

## Readiness

The filter is ready while its chain reads back as the configuration asks,
holding nothing else, at its hook, priority and policy, in a table with no
flags. An [egress segment](exit-nodes.md#readiness) serves a family only while
the filter is ready, beside what the translator holds: neither family of the
egress segments is ready while the chain is not read back, and the SID's `/128`
is withdrawn. An egress segment relays other nodes' traffic out of the mesh, and
an exit whose filter is down stops doing that until the pass restores it. The
hold covers the egress segments alone. Traffic through an advertised prefix or a
steered default keeps leaving by the translator's own readiness, which
`ranet3_egress_ready` reports.

A node with no egress segment keeps forwarding while its filter is down. The
pass retries, the log warns, `ranet3_border_ready` reads 0, and `status` and
`ranet3 debug rules` say why. Only `ranet3 down` or `ranet3 disable reconciler`
stops the kernel forwarding into the tun, and only where `cap.table` installed
the routes into it.

At startup the daemon refuses to start when the first pass cannot install the
chain and read it back, which on a host means a kernel without nf_tables or a
daemon without `CAP_NET_ADMIN`. A node that asked for the filter does not run
without it.

## Nodes that forward without it

A node whose host forwards and whose file writes no `cap.border` logs, at
startup and at every reload,
`config: this node forwards IPv4 and IPv6 and holds no cap.border, so a host on any of its links can forge a mesh source through it into the mesh: add cap.border with the prefixes the mesh numbers its nodes from`,
naming the families it forwards.

## Platforms

`cap.border` works on Linux only. On any other platform the daemon refuses it at
startup with
`egress: cap.border is an nftables chain, which <platform> does not have, so this node cannot filter what enters the mesh from its other links`.
A node there that forwards gets the warning above, and holds no local segment,
since a local segment needs `cap.border`.

## Reloads

The block appearing or going is a restart, refused by a reload with
`config: cap.border added, restart to apply` or
`config: cap.border removed, restart to apply`. A changed `overlay` list, or a
local segment moving to another SID, applies in place: the reload hands both to
the filter, which rewrites its chain on the pass the reload wakes. With
`cap.table`, the reconciler's pass moves the policy rules and holds it derives
from the overlay too, as [routing](routing.md#policy-rules-on-linux) lists them.
Reordering the list is no change.

## Watching it

`status` prints 1 line for the filter, after the egress line: the table and the
chain, the devices inside, the overlay prefixes and SIDs it holds, and the
packets each kind of drop counted as of the last pass. A filter whose chain is
not read back reads `not installed`, with the reason, also where the chain is
there and holds another writer's rule or sits in a dormant table. The egress
line of an exit whose filter holds its egress segments back says
`until the border filter is read back`.

`ranet3 debug rules` reads the chain now, through a socket of its own, so an
operator who sends a test packet reads the counters of that moment rather than
of the last pass. It lists every policy rule the kernel holds beside the chain,
and the rules the reconciler derives from the overlay, as
[the debug page](development/debug.md) describes.

| Log line                                         | Level | When                                                                                                                        |
| ------------------------------------------------ | ----- | --------------------------------------------------------------------------------------------------------------------------- |
| `border filter in <where>, inside <devices>`     | info  | the daemon starts the filter                                                                                                |
| `border filter installed`                        | info  | a pass rewrote the chain, with `rules`, `replaced` and `where`                                                              |
| `border filter pass failed, retrying`            | warn  | a pass failed, with `err` and `retry_in`                                                                                    |
| `border filter not ready`                        | warn  | the chain stopped reading back, with the reason as `detail`                                                                 |
| `border filter ready`                            | info  | the chain reads back again                                                                                                  |
| `border filter dropped packets`                  | info  | a pass read a counter that moved, at most once per pass                                                                     |
| `border filter withdrawn`                        | info  | the table is removed at shutdown                                                                                            |
| `egress stopped reading nf_tables notifications` | warn  | a read of the filter's notification socket failed, with `err`, after which another writer's change waits for the next sweep |

A pass that rewrote the chain or failed records a `border.pass` event with
`trigger`, `took`, `installed` and, on failure, `err`. A change of readiness
records `border.ready` with `ready`. A pass that read a counter move records
`border.dropped` with the packets of each kind since the pass before, at most
once per pass.

| Metric                                               | Meaning                                      |
| ---------------------------------------------------- | -------------------------------------------- |
| `ranet3_border_ready`                                | whether the chain reads back, 1 or 0         |
| `ranet3_border_dropped_packets_total{reason,family}` | packets dropped by kind, as of the last pass |

The reasons are `overlay_source` in both families, and `routing_header` and
`sid_destination` in `ipv6`. A rewrite of the chain starts the counters from 0,
which a scrape reads as a counter reset.
