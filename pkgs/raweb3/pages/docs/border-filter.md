---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "The border filter"
description: "Dropping a mesh source that arrives from outside the mesh, carving a link's own network out of the overlay, and letting into the mesh only what this node owns."
created: 2026-10-19
updated: 2026-10-31
order: 55
---

The border filter owns the nftables table `inet ranet3` and its 2 chains. Chain
`border`, which the `cap.border` block turns on, drops a packet that arrives on
a link outside the mesh with a source in the mesh's own address space, but where
the link's own network lies inside that space. Chain `mesh_entry` runs on every
Linux node with no key, and lets a packet the host sends into the tun pass only
from a source this node owns, as a reply, toward a destination a `none` class
takes, or toward an IPv6 link-local or multicast destination. A mesh source
arriving from anywhere else is forged, and so is a packet entering the mesh
under a source the mesh routes to another node.

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
every peer then takes the packet as the mesh's own. Chain `mesh_entry` keeps a
host on the same link as such a node out of the mesh: what the host routes into
the tun passes only as [the entry chain](#the-entry-chain) lists, from an
address this node owns or translated to one, such as by Docker's masquerade,
among them. Such a host can still forge one of this node's own addresses. Chain
`border` drops a forged source inside the overlay and a carved one where
`cap.border` is written. A source inside a LAN this node announces or advertises
outside the overlay passes from any link, and the host's own reverse path
filtering decides it, as [the packet filter](coexistence.md#the-packet-filter)
says.

An [egress segment](segment-routing.md#egress-segments) carries out of the mesh
only the sources its `allow` list names. The list is authorization. A forged
allowed source sent through a forwarding node is dropped there by `mesh_entry`
unless that node owns it, and by `border` where its `cap.border` holds the
overlay, which the loader makes cover every `allow` list. The filter on the exit
itself keeps a forged mesh source off the host's services. Another node's SID
that delivers to the mesh is protected by that node, as [below](#what-it-drops)
describes.

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

Each packet arriving on a device outside the mesh meets chain `border`'s rules
in this order, and the first that matches decides:

| Rule                          | Does                                                                             | Family |
| ----------------------------- | -------------------------------------------------------------------------------- | ------ |
| 1 per device inside           | accepts what arrives on it                                                       | both   |
| 1 per family with a carve-out | drops a source in `carved4` or `carved6`, the mesh's prefixes inside a carve-out | its    |
| 1 per carve-out               | accepts a source inside the carve-out arriving on its own link                   | its    |
| 1 per `overlay` prefix        | drops a source inside the prefix                                                 | its    |

A packet matching none passes. A drop sends no ICMP error, as
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

The chain drops no routing header and no destination by its address. A routing
header from outside goes by its destination, and a packet to one of this node's
SIDs never reaches the tun, as
[segment routing](segment-routing.md#at-the-border-of-the-mesh) says. Every
local SID acts only on a packet whose outer source lies in the overlay's IPv6
prefixes, the per-node list of RFC 8754 section 5.1, as
[segment routing](segment-routing.md#local-segments) describes, so a file with a
local segment needs `cap.border`, with an IPv6 prefix in its overlay.

## Carve-outs

A link outside the mesh can hold a network inside the overlay, such as a lease
from a carrier-grade NAT where the overlay is numbered from the same shared
space of RFC 6598, or reach a point-to-point far end inside it, such as a PPPoE
gateway's. For each link but `lo`, each of its networks and far ends that shares
an address with an overlay prefix is a carve-out on that link: the network or
far end where the overlay prefix holds it, the overlay prefix where the network
or far end holds it. The filter follows the host's links, so a lease that comes
or goes moves the carve-outs on the next pass.

- `carved4` and `carved6` hold every prefix of the mesh's table inside a
  carve-out, learned, held or this node's own, and the chain drops such a source
  from any link, the carve-out's own among them. A neighbor on the leased link
  cannot reach the host as a mesh peer or as this node.
- The carve-out's own accept then passes the rest of the carve-out from its own
  link alone, so the gateway and the link's other neighbors reach the host. The
  same addresses from any other link meet the overlay's drop.
- With `cap.table` the reconciler throws the carve-out in the mesh's table in
  place of an equal overlay hold, so the host reaches the link's neighbors by
  main, and a route of the mesh inside the lease still wins by its length, as
  rows L5 and L6 of
  [where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give.
  [Exit mode](routing.md#exit-mode-on-linux) selects the lease's address and
  network for main at 5405 and 5435 unless an entry of the mesh's table inside
  the carve-out holds them, so an exit's default leaves them selected.
  [The kill switch](routing.md#the-kill-switch-on-linux) gives what a carve-out
  adds to its sets and to 5445, and what of its network outside the overlay its
  LAN holds.

Each carve-out that comes is logged at warning,
`border carves the overlay for a link that holds part of it`, with `link` and
`prefix`, and one that goes at info,
`border no longer carves the overlay for a link`. Both record a `border.carve`
event with `link`, `prefix` and `carved`. An address of a carve-out that no node
announces belongs to the link, as
[the limits](design/limits.md#the-border-filter) say.

A carve-out serves this host alone. On an exit whose lease overlaps the overlay,
a node egressing through it reaches no address of the overlay that no node
announces, and no node reaches the lease's hosts at an address the mesh routes,
which departs from RFC 4787 REQ-7, as
[the deviations](design/protocol-deviations.md) list.

## The entry chain

Chain `mesh_entry` judges every packet the host sends or forwards out of the
tun, after every source translation, and its first line that matches decides:

| Rule comment                  | Does                                                                      |
| ----------------------------- | ------------------------------------------------------------------------- |
| `return via other than <tun>` | passes a packet leaving by any other link                                 |
| `return a reply`              | passes a packet conntrack reads as the reply of a flow, an ICMP error too |
| `return ipv6 to fe80::/10`    | passes an IPv6 link-local destination, neighbor discovery among them      |
| `return ipv6 to ff00::/8`     | passes an IPv6 multicast destination                                      |
| `return ipv4 source @owned4`  | passes a source this node owns, and the same for `owned6`                 |
| `return ipv4 to @none4`       | passes a destination a `none` class takes, and the same for `none6`       |
| `drop ipv4 entering the mesh` | drops the rest, counted, and the same for `ipv6`                          |

- `owned4` and `owned6` hold the addresses `cap.table` writes and every prefix
  this node originates that does not
  [count as a default](routing.md#routes-that-count-as-a-default), a
  source-specific one by its destination whole, the sources the tun read owns.
- `none4` and `none6` hold, on an exit, the addresses whose `cap.egress` class
  is `none`, a longer class inside one taking its own addresses out, less every
  LAN another node advertises outside the overlay, so a stranger's packet from
  the internet reaches such a class's hosts and no other node's LAN, through its
  hold either. The overlay's prefixes stay whole. A node with no `cap.egress`
  holds them empty.
- The chain sits at postrouting at priority `srcnat` + 10, 110, so it reads the
  source after the translator's, Docker's masquerade and any other source
  translation, as [sharing a host](coexistence.md#the-packet-filter) describes.
- A UDP datagram the host's own socket sends and the chain drops fails its send
  with `EPERM`, as `nf_hook_slow` in
  [core.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/netfilter/core.c)
  returns it. A forwarded one is dropped with no answer.
- An untracked packet, one a `notrack` rule exempts, matches no reply line, as
  [the limits](design/limits.md#the-border-filter) say.

The sets follow the mesh's table on every change of it. A LAN another node
starts advertising inside a `none` class leaves `none4` or `none6` on the pass
that change wakes, before the reconciler's route into the tun lands one settle
later, so no stranger's packet reaches the LAN in between, which the root lab
checks on every learn. A LAN no node advertises any more comes back into the set
on the pass its withdrawal wakes, while its route stays up to a settle more, and
the chain then passes what the `none` class takes.

The chain's `ct` expression turns conntrack on in the network namespace, for
every Linux node, as `nft_ct_get_init` in
[nft_ct.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/netfilter/nft_ct.c)
asks it of `nf_ct_netns_get`, and with it both families' defragmentation, as
`nf_ct_netns_do_get` in
[nf_conntrack_proto.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/netfilter/nf_conntrack_proto.c)
turns it on.

## Which devices are inside

Chain `border` accepts whatever arrives on a device inside the mesh, before any
drop. The list is derived and has no setting:

1. the mesh tun, through which an egress segment's inner packets arrive as well
2. `lo`, through which a packet this host sends to its own address arrives

A deployment that carries mesh sources on another link, a subnet router of
mesh-numbered hosts, is refused at load: a `cap.egress` `advertise` entry that
overlaps the overlay is refused, since the hosts behind such a node arrive on a
link outside the mesh with a mesh source and the filter would drop them.

## Where it runs

The filter owns its own nftables table, `inet ranet3`, with these chains and the
6 interval sets `carved4`, `carved6`, `owned4`, `owned6`, `none4` and `none6`:

| Chain        | Type     | Hook          | Priority          | Policy   | When                      |
| ------------ | -------- | ------------- | ----------------- | -------- | ------------------------- |
| `border`     | `filter` | `prerouting`  | -300 (`raw`)      | `accept` | where `cap.border` is set |
| `mesh_entry` | `filter` | `postrouting` | 110 (`srcnat`+10) | `accept` | every Linux node          |

Prerouting comes before the routing decision, so a forged packet to one of this
node's own addresses is dropped as well as one to forward. Priority `raw` comes
after defragmentation and before conntrack, so a forged packet creates no
conntrack entry. Each rule carries its spelling as its comment, which
`nft list ruleset` shows: `accept via ranet3`, `drop ipv4 source @carved4`,
`accept via eth0 source 203.0.113.0/26`, `drop ipv4 source 203.0.113.0/24`,
`drop ipv6 entering the mesh`. Only the drops carry counters.

Chain `border` needs no forwarding. With forwarding off the kernel routes
nothing from the node's links into the tun, but a forged mesh source to the
node's own address still reaches the host's services, and a host firewall's
reverse path check in loose mode passes it wherever it finds a route back to
that source through the tun, as for a live node's address. The chain drops that
packet too, so it runs wherever `cap.border` is written.

A pass reads the table back whole: every rule of both chains in order, whoever
wrote it, the table's flags, each chain's type, hook, priority and policy, and
each set's elements as ranges. When anything differs from what the configuration
asks for, a rule another writer added, a flushed set, a dormant table or a
policy of drop among it, the pass rewrites the table, its chains and its sets in
1 transaction and reads them back again. A change of the mesh's table or the
host's links that moves only a set deletes each range that set no longer holds
and adds each new one, a range's start and end together, in 1 transaction, the
chains left alone, so a lookup meets the set before the change or after it. One
LAN coming or going sends every nf_tables listener a notification for each
element of the ranges that differ: 2 to 6 for a LAN enclosing no other, and more
for one that does, since the ranges of the LANs inside it go or come with it.
nf_tables clears no table flag in place but dormant, and changes no chain's
type, hook or priority, so when one of those differs the same transaction first
deletes the table, and any chain another writer put in it, then makes it again.
A pass runs every 30 seconds, and a failed one is retried after 1 second,
doubling up to the 30. Another writer adding, changing or deleting the table,
one of its chains, a rule or a set's element wakes a pass at once, and the
filter reads not ready until that pass puts the table back in 1 transaction.
Between the change and that transaction forged packets may pass. The filter's
own writes wake nothing. Notifications the daemon lost, which another table's
large transaction can overflow its socket with, wake a pass too and leave
readiness as it was, since that pass reads the table back.

`ranet3 down` leaves the filter in place: the kernel still forwards and the
host's services still trust mesh sources. At shutdown the filter goes last,
after the reconciler withdrew the routes into the tun and the mesh closed its
sessions, so nothing forwards into the mesh by the time it is gone. The table
carries no owner flag, so after `SIGKILL` it stays: the tun goes with the
process, `mesh_entry` then passes every packet at its first line, and `border`
keeps dropping forged sources until ranet3 starts again and takes the table
over.

## Readiness

The filter is ready while both its chains and every set read back as the
configuration asks, holding nothing else, at their hooks, priorities and
policies, in a table with no flags. Readiness holds nothing back: an
[egress segment](exit-nodes.md#readiness) follows the translator alone. While
the filter is not ready the pass retries, the log warns, `ranet3_border_ready`
reads 0, and `status` and `ranet3 debug rules` say why.

At startup the daemon refuses to start on Linux when the first pass cannot
install the table and read it back, which on a host means a kernel without
nf_tables or conntrack or a daemon without `CAP_NET_ADMIN`. A node does not run
without its entry chain.

## Nodes that forward without it

On a platform that runs no entry chain, a node whose host forwards and whose
file writes no `cap.border` logs, at startup and at every reload,
`config: this node forwards IPv4 and IPv6 and holds no cap.border, so a host on any of its links can reach this host's own services under a mesh source`,
naming the families it forwards. On Linux the tun read and `mesh_entry` keep a
forged source out of the mesh, and no warning is logged.

## Platforms

The table is Linux's alone. On any other platform the daemon runs no entry chain
and refuses `cap.border` at startup with
`egress: cap.border is an nftables chain, which <platform> does not have, so this node cannot filter what enters the mesh from its other links`.
A node there that forwards gets the warning above, and holds no local segment,
since a local segment needs `cap.border`. [Platforms](platforms.md) lists what
each one carries.

## Reloads

The block appearing or going is a restart, refused by a reload with
`config: cap.border added, restart to apply` or
`config: cap.border removed, restart to apply`. A changed `overlay` list applies
in place: the reload hands it to the filter, which rewrites chain `border` on
the pass the reload wakes. With `cap.table`, the reconciler's pass moves the
policy rules and holds it derives from the overlay too, as
[routing](routing.md#policy-rules-on-linux) lists them. Reordering the list is
no change.

## Watching it

`status` prints 1 line for the filter, after the egress line: the table and its
chains, the devices inside, the overlay prefixes, each carve-out as
`carving <prefix> on <link>`, and the packets each kind of drop counted as of
the last pass, the overlay's, the carved prefixes' and those entering the mesh.
A node with no `cap.border` prints the table, chain `mesh_entry` and its drops
alone. A filter whose table is not read back reads `not installed`, with the
reason, also where it is there and holds another writer's rule or sits in a
dormant table.

`ranet3 debug rules` reads the table's rules now, through a socket of its own,
so an operator who sends a test packet reads the counters of that moment rather
than of the last pass. It lists both chains with the hooks and priorities they
are written at and the rules read now, and each set with the elements the last
pass asked for, beside every policy rule the kernel holds and the rules the
reconciler derives from the overlay, as [the debug page](development/debug.md)
describes.

| Log line                                                     | Level | When                                                                                                                                    |
| ------------------------------------------------------------ | ----- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `border filter in <where>, inside <devices>`                 | info  | the daemon starts the filter                                                                                                            |
| `border filter installed`                                    | info  | a pass rewrote the table, with `rules`, `replaced` and `where`                                                                          |
| `border filter pass failed, retrying`                        | warn  | a pass failed, with `err` and `retry_in`                                                                                                |
| `border filter not ready`                                    | warn  | the table stopped reading back, with the reason as `detail`                                                                             |
| `border filter ready`                                        | info  | the table reads back again                                                                                                              |
| `border filter dropped packets`                              | info  | a pass read a counter that moved, at most once per pass                                                                                 |
| `border carves the overlay for a link that holds part of it` | warn  | a carve-out came, with `link` and `prefix`                                                                                              |
| `border no longer carves the overlay for a link`             | info  | a carve-out went, with `link` and `prefix`                                                                                              |
| `border filter withdrawn`                                    | info  | the table is removed at shutdown                                                                                                        |
| `stopped reading nf_tables notifications`                    | warn  | a read of the filter's notification socket failed, with `table` and `err`, after which another writer's change waits for the next sweep |

A pass that rewrote the table or a set, or failed, records a `border.pass` event
with `trigger`, `took`, `installed`, `wrote` and, on failure, `err`. A change of
readiness records `border.ready` with `ready`. A pass that read a counter move
records `border.dropped` with the packets of each kind since the pass before, at
most once per pass, and a carve-out coming or going records `border.carve`.

| Metric                                               | Meaning                                      |
| ---------------------------------------------------- | -------------------------------------------- |
| `ranet3_border_ready`                                | whether the table reads back, 1 or 0         |
| `ranet3_border_dropped_packets_total{reason,family}` | packets dropped by kind, as of the last pass |

The reasons are `overlay_source`, `carved_source` and `mesh_entry`, each in both
families. `mesh_entry` counts what the entry chain kept out of the mesh, though
the metric is named for the border. A rewrite of the table starts the counters
from 0, which a scrape reads as a counter reset.
