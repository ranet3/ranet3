---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "The antispoof filter"
description: "Dropping a mesh source that arrives from outside the mesh, carving an interface's own network out of the overlay, exempting what the operator names, and letting into the mesh only what this node owns."
created: 2026-10-19
updated: 2026-11-07
order: 55
---

The antispoof filter owns the nftables table `inet ranet3` and its 2 chains on
Linux, and the pf anchor `com.apple/ranet3` on macOS. Chain `antispoof` runs
wherever the top-level `overlay` is written, and drops a packet that arrives on
an interface outside the mesh with a source in the mesh's own address space, but
where the interface's own network lies inside that space or an exemption passes
it. Chain `mesh_entry` runs on every Linux node with no key, and lets a packet
the host sends into the tun pass only from a source this node owns, as a reply,
toward a destination a `none` class takes, or toward an IPv6 link-local or
multicast destination. On macOS the tun read makes that check, as
[the platforms](#platforms) say. A mesh source arriving from anywhere else is
forged, and so is a packet entering the mesh under a source the mesh routes to
another node.

A protection is on by default, and its block only exempts. `overlay` turns the
filter on, and `[cap.antispoof]` holds nothing but exemptions:

```toml
overlay = ["203.0.113.0/24", "3fff:a::/36", "3fff:b::/48"]

[cap.antispoof]
exempt = ["203.0.113.128/25"]

[cap.antispoof.interface.eth1]
exempt = ["3fff:a:1::/48"]

[cap.antispoof.interface."wl*"]
exempt = ["203.0.113.64/26"]
```

[The configuration reference](configuration-reference.md#top-level) lists
`overlay` and its refusals, and
[`cap.antispoof`](configuration-reference.md#capantispoof) the exemptions'.

## What it defends

A node that forwards takes a packet from any of its interfaces and routes it by
its destination. Where the host routes a mesh destination into the tun, as
[where a lookup ends on Linux](routing.md#where-a-lookup-ends-on-linux) gives,
every peer then takes the packet as the mesh's own. Chain `mesh_entry` keeps a
host on the same network as such a node out of the mesh: what the host routes
into the tun passes only as [the entry chain](#the-entry-chain) lists, from an
address this node owns or translated to one, such as by Docker's masquerade,
among them. Such a host can still forge one of this node's own addresses. Chain
`antispoof` drops a forged source inside the overlay and a carved one where
`overlay` is written. A source inside a LAN this node announces or advertises
outside the overlay passes from any interface, and the host's own reverse path
filtering decides it, as [the packet filter](coexistence.md#the-packet-filter)
says.

An [egress segment](segment-routing.md#egress-segments) carries out of the mesh
only the sources its `allow` list names. The list is authorization. A forged
allowed source sent through a forwarding node is dropped there by `mesh_entry`
unless that node owns it, and, for a source inside the overlay, by `antispoof`
unless an exemption of that node passes it. A source an `allow` entry outside
the overlay admits, which [egress segments](segment-routing.md#egress-segments)
describe, meets `mesh_entry` alone. The filter on the exit itself keeps a forged
mesh source off the host's services. Another node's SID that delivers to the
mesh is protected by that node, as [below](#what-it-drops) describes.

The filter guards the mesh's edge on the interfaces outside it. A packet this
host's own kernel routes into the tun enters the mesh by the other side of that
edge, where the
[forwarding decision checks what the tun hands this
node](segment-routing.md#at-the-border-of-the-mesh): it drops a read from a
source the table routes to another node or holds unreachable, through a route
that does not count as a default, or from an overlay source this node does not
own, one carrying a routing header the mesh refuses, one to one of this node's
own SIDs, one bound through an exit from a source this node does not own, or one
whose inner packet fails the same checks, and more on every platform but Linux,
as [the platforms](#platforms) say. Those reads count on the `Transit` line, not
among the filter's drops.

## What it drops

Each packet arriving on an interface outside the mesh meets chain `antispoof`'s
rules in this order, and the first that matches decides:

| Rule                                          | Does                                                                                                | Family |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------- | ------ |
| 1 per interface inside                        | accepts what arrives on it                                                                          | both   |
| 1 per family with a carve-out or an exemption | drops a source in `carved4` or `carved6`, which the carve-outs and the exemptions carve             | its    |
| 1 per carve-out                               | accepts a source inside the carve-out arriving on its own interface                                 | its    |
| 1 per exemption                               | accepts a source inside it arriving on an interface its name matches, or on any for the shared list | its    |
| 1 per `overlay` prefix                        | drops a source inside the prefix                                                                    | its    |

A packet matching none passes. A drop sends no ICMP error, as
[the deviations](design/protocol-deviations.md#drops-with-no-answer) explain.

The overlay is the address space every node of the mesh is numbered from, the
same on every node. An exit's `allow` entry admits an outer source only where
the overlay covers it, since a source outside the overlay passes every filter.
The loader refuses an egress segment whose `allow` list the overlay cannot
admit, as [egress segments](segment-routing.md#egress-segments) gives.

The overlay holds only addresses the mesh carries inside its tunnels. Every
address a peer's ESP comes from lies outside it, since that ESP arrives on an
interface outside the mesh and the filter would drop it. So does the source of
any other packet that reaches this node outside the tunnels, such as one another
node sends from its mesh address over the internet rather than through the mesh.
The loader cannot check either, since endpoints are often names.

The chain drops no routing header and no destination by its address. A routing
header from outside goes by its destination, and a packet to one of this node's
SIDs never reaches the tun, as
[segment routing](segment-routing.md#at-the-border-of-the-mesh) says. Every
local SID acts only on a packet whose outer source lies in the overlay's IPv6
prefixes, the per-node list of RFC 8754 section 5.1, as
[segment routing](segment-routing.md#local-segments) describes, so a file with a
local segment needs `overlay`, with an IPv6 prefix in it.

### On macOS

On macOS the chain is the rules of [the anchor](#the-pf-anchor-on-macos) in the
same order. pf matches an interface by its exact name and negates at most 1 in a
rule, so the mesh tun's accept folds into each drop as `on ! <tun>`, and the
loopback link's accept passes overlay sources alone. With the mesh tun `utun7`,
the overlay `192.0.2.0/24` and `3fff:10::/32`, a carve-out of `192.0.2.128/25`
on `en0` holding another node's `192.0.2.200`, the shared exemption
`192.0.2.32/27`, `en*`'s `3fff:10:1::/48` over the links `en0` and `en1`, and
`en1`'s `192.0.2.64/26`, the anchor holds:

```
table <ranet3_overlay> const { 192.0.2.0/24, 3fff:10::/32 }
table <ranet3_carved> const { 192.0.2.200 }
pass in quick on lo0 from <ranet3_overlay> to any no state label "accept via lo0"
block drop in quick on ! utun7 inet from <ranet3_carved> to any label "drop ipv4 source @carved4"
block drop in quick on ! utun7 inet6 from <ranet3_carved> to any label "drop ipv6 source @carved6"
pass in quick on en0 inet from 192.0.2.128/25 to any no state label "accept via en0 source 192.0.2.128/25"
pass in quick on ! utun7 inet from 192.0.2.32/27 to any no state label "accept exempt source 192.0.2.32/27"
pass in quick on en0 inet6 from 3fff:10:1::/48 to any no state label "accept exempt via en0 source 3fff:10:1::/48"
pass in quick on en1 inet6 from 3fff:10:1::/48 to any no state label "accept exempt via en1 source 3fff:10:1::/48"
pass in quick on en1 inet from 192.0.2.64/26 to any no state label "accept exempt via en1 source 192.0.2.64/26"
block drop in quick on ! utun7 inet from 192.0.2.0/24 to any label "drop ipv4 source 192.0.2.0/24"
block drop in quick on ! utun7 inet6 from 3fff:10::/32 to any label "drop ipv6 source 3fff:10::/32"
```

- Every rule is `quick`, and each pass names 1 family or the overlay's table, 1
  prefix or that table, and 1 interface or `! utun7`, and keeps no state.
  [The limits](design/limits.md#the-antispoof-filter) give how far a pass
  reaches and what pf decides before the anchor: a `quick` pass ahead of the
  main ruleset's call to `com.apple/*`, and a state in pf's state table. An
  operator's own block of a source the anchor passes goes in the main ruleset
  ahead of that call.
- `lo0`'s pass carries the Mac's own datagrams from an overlay address to
  `127.0.0.1` and `::1`, which arrive on `lo0` with that source, and reaches no
  source outside the overlay. The mesh tun's packets match no rule, since each
  drop names every interface but `utun7`.
- Each table holds both families, and a rule of 1 family reads its own. A family
  no carve-out and no exemption is of has no carved drop, as on Linux.
- A rule's label is its spelling, which `pfctl -a com.apple/ranet3 -s rules`
  shows, where it fits pf's 63 bytes. A carve-out's or an exemption's that does
  not is `accept via <link> carve-out <n>`, `accept exempt <n>` or
  `accept exempt via <link> <n>`, `n` its place among the rules of its kind from
  1, and `ranet3 debug rules` still shows the whole spelling.

## Carve-outs

An interface outside the mesh can hold a network inside the overlay, such as a
lease from a carrier-grade NAT where the overlay is numbered from the same
shared space of RFC 6598, or reach a point-to-point far end inside it, such as a
PPPoE gateway's. For each interface but the loopback link, `lo` on Linux and
`lo0` on macOS, each of its networks and far ends that shares an address with an
overlay prefix is a carve-out on that interface: the network or far end where
the overlay prefix holds it, the overlay prefix where the network or far end
holds it. The filter follows the host's interfaces, as
[the network watch](platforms.md#moving-hosts) reads them, so a lease that comes
or goes moves the carve-outs on the next pass. On macOS the watch reads an IPv4
address on a point-to-point link as a host, so such a link's carve-outs are its
address and its far end, each a `/32`.

- `carved4` and `carved6` hold every prefix of the mesh's table inside a
  carve-out, learned, held or this node's own, but for what the next bullet
  lifts, and what [the exemptions](#exemptions) carve. The chain drops such a
  source from any interface, the carve-out's own among them, so a neighbor on
  the leased network cannot reach the host as a mesh peer or as this node.
- An address of a range this node announces leaves `carved4` and `carved6`
  where, for each carve-out holding it, an exemption under [a name](#exemptions)
  matching the carve-out's interface holds it too. The sets are one for every
  interface, so where any carve-out holding the address is on an interface no
  such exemption names, the address stays carved and is dropped from every
  interface. This node's addresses and another node's prefix inside the range
  stay carved, as [the exemptions](#exemptions) give.
- The carve-out's own accept then passes the rest of the carve-out from its own
  interface alone, so the gateway and the network's other neighbors reach the
  host. The same addresses from any other interface meet the overlay's drop,
  unless an exemption passes them from that interface.
- On Linux, with `cap.table`, the reconciler throws the carve-out in the mesh's
  table in place of an equal overlay hold, so the host reaches the network's
  neighbors by main, and a route of the mesh inside the lease still wins by its
  length, as rows L5 and L6 of
  [where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give.
  [Exit mode](routing.md#exit-mode-on-linux) selects the lease's address and
  network for main at 5405 and 5435 unless an entry of the mesh's table inside
  the carve-out holds them, so an exit's default leaves them selected.
  [The kill switch](routing.md#the-kill-switch-on-linux) gives what a carve-out
  adds to its sets and to 5445, and what of its network outside the overlay its
  LAN holds.

Each carve-out that comes is logged at warning,
`antispoof carves the overlay for a link that holds part of it`, with `link` and
`prefix`, and one that goes at info,
`antispoof no longer carves the overlay for a link`. Both record an
`antispoof.carve` event with `link`, `prefix` and `carved`. An address of a
carve-out that no node announces belongs to the interface, as
[the limits](design/limits.md#the-antispoof-filter) say.

A carve-out serves this host alone. On an exit whose lease overlaps the overlay,
a node egressing through it reaches no address of the overlay that no node
announces, and no node reaches the lease's hosts at an address the mesh routes,
which departs from RFC 4787 REQ-7, as
[the deviations](design/protocol-deviations.md) list.

## Exemptions

An exemption passes overlay sources the operator names from the interfaces
outside the mesh, where the carve-outs pass only an interface's own network. It
serves a network inside the overlay the host does not hold as its own, such as a
range of the shared space of RFC 6598 a carrier routes to this host from further
away than its lease, or the site behind a gateway that
[announces it](#a-gateways-site).

- `cap.antispoof.exempt` passes its prefixes from every interface outside the
  mesh. `cap.antispoof.interface.<name>.exempt` passes them only from the
  interfaces the name matches: the interface of that name, or, for a name ending
  in `*`, every interface whose name starts with what comes before it, so `wl*`
  matches `wlan0` and `wlp3s0`. An interface takes the shared list and the list
  of every name that matches it.
- No exemption reaches an interface inside the mesh, where the filter drops
  nothing. An exemption under the exact name of the mesh tun or the loopback
  link writes no rule, and the filter logs
  `antispoof leaves out an exemption naming a device inside the mesh, where it drops nothing`
  at warning, with `interface` and `prefix`, once, at the start or the reload
  that brings it in.
- Each prefix lies inside `overlay`, each of its addresses in some entry. One
  outside exempts nothing, since the filter drops only an overlay source, and
  the loader refuses it, as it refuses a `*` anywhere but last, a name of `*`
  alone, which the shared list says, and a block exempting nothing.
- Each node address of this node inside an exemption, a host prefix `cap.route`
  announces or an address `cap.table` writes, joins `carved4` or `carved6`. So
  does the part of an exemption that another node's prefix inside the overlay
  holds, the exemption where the prefix covers it and the prefix where the
  exemption covers it, less every range this node announces inside that prefix.
  The carved drop comes before the exemption's accept.
- A range this node announces by `cap.route` is its own even if another node
  announces it too, and no exemption carves it, inside or covering.
  [Another router's offer](routing.md#what-a-node-announces) for such a range
  makes a conflict, as below. A held prefix, a default and a prefix wider than
  the overlay carve nothing.
- The loader refuses a `cap.antispoof.exempt` entry that overlaps a range inside
  the overlay that this node announces, since the shared list passes it from the
  uplink too, and names the `cap.antispoof.interface.<name>.exempt` form, which
  takes it.
- Exemptions covering the whole overlay pass every overlay source that no other
  node's prefix, no node address of this node and no carve-out's carved drop
  holds, from the interfaces they name. The filter has no setting that passes a
  mesh node's own address from outside the mesh.
- Each exemption but one naming an interface inside the mesh is 1 rule,
  commented `accept exempt source <prefix>` for the shared list and
  `accept exempt via <name> source <prefix>` for a name, which
  `nft list ruleset` shows as `iifname "<name>"`, or as `iifname "wl*"` for a
  name ending in `*`. An exemption of 1 family widens only that family's carved
  set.
- On macOS the shared list's rule passes on `! <tun>`, and a name's on that
  interface, as [the anchor](#on-macos) shows. An interface not attached yet is
  written as named, and pf matches it once it attaches. pf matches no name
  ending in `*`, so such a name is 1 rule per link
  [the network watch](platforms.md#moving-hosts) reports whose name it matches,
  in the links' order, but the mesh tun and `lo0`, and none while no link
  matches, rewritten as links come and go. A link whose exempt sources must pass
  from the moment it attaches is named exactly, as
  [the limits](design/limits.md#the-antispoof-filter) give. An exact name and a
  name ending in `*` that give the same link and prefix are 1 rule.

Each part of an exemption another node's prefix comes to hold is logged at
warning,
`antispoof drops part of an exemption, since another node's prefix holds it`,
with `exemption`, `interface`, `prefix`, `carved`, `routed_via` and `router_id`,
once, and records an `antispoof.conflict` event with the same and `own` false.
`routed_via` is the peer the mesh routes the prefix through and `router_id` the
router-id of the route babel selected for it. Neither names the node that
announces it. A part is the exemption, its interface, the prefix and what is
carved, so a route to the prefix that moves to another peer or router-id logs
nothing. One that goes is logged at info,
`antispoof no longer drops part of an exemption for another node's prefix`.

A range `cap.route` announces inside the overlay that babel keeps another
router's offer for, with no source prefix, is a conflict of each exemption
overlapping it, and the conflict carves nothing. Its `router_id` is the
router-id of the offer of least cost. [Watching it](#watching-it) gives its
lines and attributes.

### A gateway's site

Gateway G has the node address `203.0.113.1`, announces its site's
`203.0.113.0/25`, and reaches the internet by `eth0` and its site through a
router on `eth1`, whose own network, `198.51.100.0/24`, lies outside the
overlay:

```toml
overlay = ["203.0.113.0/24", "3fff:a::/36"]

[cap.table]
addresses = ["203.0.113.1/32"]

[cap.route]
announce = ["203.0.113.0/25"]

[cap.antispoof.interface.eth1]
exempt = ["203.0.113.0/25"]
```

- A host of the site at `203.0.113.65` reaches G from `eth1`, passed by
  `accept exempt via eth1 source 203.0.113.0/25`.
- The same source arriving on `eth0` meets `drop ipv4 source 203.0.113.0/24`,
  since the exemption names `eth1` alone.
- `203.0.113.1`, G's own address, joins `carved4`, and G drops it from `eth1`
  too.
- Another node announcing `203.0.113.96/28` inside G's range has its sources
  carved, so G drops them from `eth1`, logs the conflict and records
  `antispoof.conflict` with `prefix` `203.0.113.96/28`.
- Another node announcing exactly `203.0.113.0/25` changes nothing G passes or
  drops. G logs the conflict and records `antispoof.conflict` with `prefix`
  `203.0.113.0/25`, `own` true and that node's router-id as `router_id`.
- The same exemption under `[cap.antispoof]` is refused at load by a message
  naming `cap.antispoof.interface.<name>.exempt`, as
  [`cap.antispoof`](configuration-reference.md#capantispoof) gives it.
- A node that starts announcing a more specific prefix, such as
  `203.0.113.112/29`, is carved out on the pass its route wakes.

Where `eth1`'s own network holds the site's range instead, such as
`203.0.113.126/25`, `eth1` is a carve-out of `203.0.113.0/25`, and the exemption
under `eth1` lifts the range out of `carved4`, as [the carve-outs](#carve-outs)
give. The site's host passes from `eth1` by
`accept via eth1 source 203.0.113.0/25`, the carve-out's accept, and meets
`drop ipv4 source 203.0.113.0/24` on `eth0` as above, while G's own address and
the other node's prefix stay carved. Without the exemption on `eth1`, the carved
drop takes the range too, and the site's sources are dropped on `eth1` as well.

## The entry chain

Chain `mesh_entry` judges every packet the host sends or forwards out of the tun
on Linux, after every source translation. On every other platform the tun read
takes its place, as [the platforms](#platforms) say. The chain's first line that
matches decides:

| Rule comment                  | Does                                                                      |
| ----------------------------- | ------------------------------------------------------------------------- |
| `return via other than <tun>` | passes a packet leaving by any other interface                            |
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
  [the limits](design/limits.md#the-antispoof-filter) say.

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

## Which interfaces are inside

Chain `antispoof` accepts whatever arrives on an interface inside the mesh,
before any drop. The list is derived and has no setting:

1. the mesh tun, through which an egress segment's inner packets arrive as well
2. the loopback link, `lo` on Linux and `lo0` on macOS, through which a packet
   this host sends to its own address arrives

On macOS the tun's accept is each drop's `on ! <tun>`, and `lo0`'s pass takes
overlay sources alone, every source a drop there would take, as
[the anchor](#on-macos) shows.

A deployment that carries mesh sources on another interface, a subnet router of
mesh-numbered hosts, is refused at load: a `cap.egress` `advertise` entry that
overlaps the overlay is refused, since the hosts behind such a node arrive on an
interface outside the mesh with a mesh source and the filter would drop them.

## Where it runs

The filter owns its own nftables table, `inet ranet3`, with these chains and the
6 interval sets `carved4`, `carved6`, `owned4`, `owned6`, `none4` and `none6`:

| Chain        | Type     | Hook          | Priority          | Policy   | When                       |
| ------------ | -------- | ------------- | ----------------- | -------- | -------------------------- |
| `antispoof`  | `filter` | `prerouting`  | -300 (`raw`)      | `accept` | where `overlay` is written |
| `mesh_entry` | `filter` | `postrouting` | 110 (`srcnat`+10) | `accept` | every Linux node           |

Prerouting comes before the routing decision, so a forged packet to one of this
node's own addresses is dropped as well as one to forward. Priority `raw` comes
after defragmentation and before conntrack, so a forged packet creates no
conntrack entry. Each rule carries its spelling as its comment, which
`nft list ruleset` shows: `accept via ranet3`, `drop ipv4 source @carved4`,
`accept via eth0 source 203.0.113.0/26`,
`accept exempt via wl* source 203.0.113.64/26`,
`drop ipv4 source 203.0.113.0/24`, `drop ipv6 entering the mesh`. Only the drops
carry counters.

Chain `antispoof` needs no forwarding. With forwarding off the kernel routes
nothing from the node's interfaces into the tun, but a forged mesh source to the
node's own address still reaches the host's services, and a host firewall's
reverse path check in loose mode passes it wherever it finds a route back to
that source through the tun, as for a live node's address. The chain drops that
packet too, so it runs wherever `overlay` is written.

A pass reads the table back whole: every rule of both chains in order, whoever
wrote it, every chain the table holds, the table's flags, each chain's type,
hook, priority and policy, and each set's elements as ranges. When anything
differs from what the configuration asks for, a rule another writer added, a
chain the filter does not write, a flushed set, a dormant table or a policy of
drop among it, the pass deletes the table, with every chain in it, and makes it
again with its chains and sets in 1 transaction, then reads them back again. A
change of the mesh's table or the host's interfaces that moves only a set
deletes each range that set no longer holds and adds each new one, a range's
start and end together, in 1 transaction, the chains left alone, so a lookup
meets the set before the change or after it. One LAN coming or going sends every
nf_tables listener a notification for each element of the ranges that differ: 2
to 6 for a LAN enclosing no other, and more for one that does, since the ranges
of the LANs inside it go or come with it. A pass runs every 30 seconds, and a
failed one is retried after 1 second, doubling up to the 30. Another writer
adding, changing or deleting the table, one of its chains, a rule or a set's
element wakes a pass at once, and the filter reads not ready until that pass
puts the table back in 1 transaction. Between the change and that transaction
forged packets may pass. The filter's own writes wake nothing. Notifications the
daemon lost, which another table's large transaction can overflow its socket
with, wake a pass too and leave readiness as it was, since that pass reads the
table back.

The table's lifetime:

- The start writes it with the filter's first pass, before the reconciler routes
  anything into the tun. A table an earlier instance left is taken over: a first
  pass that reads it back as it would write it keeps it, with its counters, and
  one that does not rewrites it in 1 transaction, so `antispoof` drops forged
  sources throughout.
- `ranet3 down` leaves it: the kernel still forwards and the host's services
  still trust mesh sources.
- A stop on `SIGINT` or `SIGTERM` withdraws it last, after the reconciler
  withdrew the routes into the tun and the mesh closed its sessions, so nothing
  forwards into the mesh by the time it is gone.
- A start that a refusal or either signal ends before its build completes, after
  the filter's first pass, withdraws the table where that pass made it, and
  leaves one the pass found, taken over or rewritten, logging
  `antispoof filter is leaving the table it found`. A first pass that fails ends
  the start the same way, and one whose read of the table fails leaves whatever
  is there and logs nothing beyond the start's refusal.
- The stop a failed tun causes leaves it, as
  [the kill switch's](routing.md#the-kill-switch-on-linux) stop leaves its
  table, and logs `antispoof filter is leaving its table after the mesh failed`.
  `antispoof` keeps dropping forged sources while the supervisor starts the
  daemon again, `mesh_entry` passes every packet at its first line with the tun
  gone, and the next start takes the table over as above. While ranet3 stays
  down, the operator removes it with `nft delete table inet ranet3`.
- After `SIGKILL` it stays, since the table carries no owner flag: the tun goes
  with the process, `mesh_entry` passes every packet at its first line, and
  `antispoof` keeps dropping forged sources until ranet3 starts again and takes
  the table over.

### The pf anchor on macOS

On macOS the filter writes the anchor `com.apple/ranet3`, a child of
`com.apple`, which the stock main ruleset of `/etc/pf.conf` calls with
`anchor "com.apple/*"`, so pf evaluates it among `com.apple`'s other children in
the order of their names. The filter runs only where `overlay` is written, and a
Mac with no `overlay` leaves pf as it found it but for what an earlier run's
record names, which its start gives back, as below.
[The limits](design/limits.md#the-antispoof-filter) give what turning pf on
means for the rest of the host. pfctl is the only program the daemon runs on pf,
and every load and flush names the anchor: `pfctl -a com.apple/ranet3 -f -`
loads the anchor whole in 1 transaction, which leaves it as it was where pfctl
refuses the text, `pfctl -a com.apple/ranet3 -T load -f -` loads its tables
alone in 1 transaction, which keeps the rules and their counters, when only the
carved sets move, and `pfctl -a com.apple/ranet3 -F rules` and `-F Tables` empty
it. The one write that names no anchor gives back a reference by its token, with
`pfctl -X <token>`.

The daemon keeps pf enabled with a reference of its own, which `DIOCSTARTREF`
takes and `pfctl -s References` lists under the daemon's pid, and records its
token beside that pid in `pf.json`, in the directory
[`--state-dir`](cli.md#running-the-node) names, `/var/db/ranet3` by default,
before it writes the anchor. A reference outlives the process that took it, and
pf gives a freed token's value to later references of any process, since a token
is the hash of its allocation
([pf_ioctl.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ioctl.c#L341-L368)),
so the daemon counts a token as its own only where pf lists it under the pid the
record holds, and gives back nothing else. pf runs while any reference is held
([pf_ioctl.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ioctl.c#L1669-L1695)),
so the daemon never runs `pfctl -e` or `pfctl -d`.

The anchor's and the reference's lifetime:

- The start takes a new reference, records it, then gives back the one an
  earlier run recorded, where pf still lists it under that run's pid, so pf
  stays enabled throughout where that reference kept it so. Its first pass takes
  the anchor over as Linux's takes the table.
- A start refused after it took its reference, its first pass not ready or a
  later step of the start failing, gives that reference back and empties the
  record, and empties the anchor where its own pass wrote it, as a refused Linux
  start removes the table it made. Where the start found an anchor an earlier
  run left, that anchor stays, and so does the new reference where it took the
  place of an earlier run's that pf still listed, so pf runs as the start found
  it.
- A start without `overlay` takes no reference. Where the record names one, it
  empties the anchor, gives back each recorded reference pf lists under its pid,
  and empties the record, so pf runs as it would had that run stopped. Where pf
  listed one, it logs
  `antispoof filter gave back the pf anchor and reference an earlier run left, since overlay is not written`.
  Where pfctl refuses a release, the record keeps that token for the next start,
  and the start fails naming the refusal, with no such line.
- A stop on `SIGINT` or `SIGTERM` empties the anchor, then gives the reference
  back and empties the record, which stops pf where no other program holds a
  reference.
- The stop a failed tun causes leaves the anchor, the reference and its record,
  and logs `antispoof filter is leaving its table after the mesh failed`. pf
  keeps the anchor's rules while the supervisor starts the daemon again, and the
  next start takes both over, or gives both back where it has no `overlay`.
- After a crash the anchor and the reference stay, and keep dropping forged
  sources. Its drops spare a utun that went with the process, so an overlay
  source on a utun another program opens under that unit passes until the next
  start rewrites the anchor for its own utun, as
  [the limits](design/limits.md#the-antispoof-filter) say. While ranet3 stays
  down, the operator empties the anchor with
  `pfctl -a com.apple/ranet3 -F rules` and
  `pfctl -a com.apple/ranet3 -F Tables`, and runs `pfctl -X <token>` with the
  token `pf.json` holds only where `pfctl -s References` lists that token under
  the pid `pf.json` holds beside it, the check the daemon makes, since pf may
  have given a freed value to another program's reference, which `-X` would end.
  A token listed under no such pid is left alone, and `pf.json` as it is for the
  next start.
- A reboot ends every reference and every rule. The next start finds the record
  naming a token pf does not list under its pid, drops it unreleased and takes
  its own.

## Readiness

The filter is ready while both its chains and every set read back as the
configuration asks, holding nothing else, at their hooks, priorities and
policies, in a table with no other chain and no flags. Readiness holds nothing
back: an [egress segment](exit-nodes.md#readiness) follows the translator alone.
While the filter is not ready the pass retries, the log warns,
`ranet3_antispoof_ready` reads 0, and `status` and `ranet3 debug rules` say why.

At startup the daemon refuses to start on Linux when the first pass cannot
install the table and read it back, which on a host means a kernel without
nf_tables or conntrack or a daemon without `CAP_NET_ADMIN`. A node does not run
without its entry chain.

On macOS the pass runs every 5 seconds, since pf tells no program of another's
change, so another program's change to the anchor goes unnoticed for up to 5
seconds. The anchor reading back as written is not enough there, and the filter
is ready only while pf evaluates it too:

- pf lists the daemon's reference under the daemon's pid. `pfctl -d` ends every
  reference and stops pf, and another program's `pfctl -X` ends one, which stops
  pf where no other reference holds it
  ([pf_ioctl.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ioctl.c#L1659-L1695)).
  A pass that finds the reference gone reads whether pf runs from
  `pfctl -s info`, then takes a new one and records it, and leaves the anchor,
  which pf keeps while stopped. Where pf was off, the new reference turns it
  back on. Where another holder kept pf running, pf was not off, and the new
  reference only takes the old one's place. Where `pfctl -s info` fails, the
  pass takes the new reference all the same, and says pf's state could not be
  read. The pass logs which at warning, with why it took the reference and how
  to turn the filter off, as [the log lines](#watching-it) list, and records
  `antispoof.pf`. Removing `overlay` is the way to turn the filter off, since a
  pass turns pf back on within 5 seconds of `pfctl -d`. Where the new reference
  cannot be taken, the filter reads not ready, naming the refusal.
- The main ruleset calls `com.apple/*` for every packet in, as the stock line
  does, which pfctl prints as `anchor "com.apple/*" all`, or the same with `in`.
  pf skips an anchor rule whose direction, interface, family, protocol or
  addresses a packet does not match before it steps in
  ([pf.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf.c#L5272-L5348)),
  so a call naming `out`, an interface, `inet`, `inet6`, a protocol or an
  address reads as no call. So does one inside an inline anchor's braces, which
  pfctl prints indented and pf resolves relative to that inline anchor
  ([pf_ruleset.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf_ruleset.c#L494-L519)).
  `pfctl -F all` or another program's ruleset replaces the stock one, and the
  filter reads not ready, naming the missing line and `pfctl -f /etc/pf.conf`,
  which loads the stock ruleset again. The daemon never edits the main ruleset.
- pf skips no interface outside the mesh. A `set skip` naming one, loaded with
  the main ruleset, makes pf pass every packet on it before any rule
  ([pf.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/pf.c#L9756)),
  a forged overlay source among them, and the filter reads not ready, naming
  each skipped interface and `pfctl -f /etc/pf.conf`, as
  [pf on macOS](coexistence.md#pf-on-macos) gives. A skip of the mesh utun or
  `lo0` changes nothing the filter passes or drops, since the tun's packets meet
  no drop and `lo0`'s pass takes every overlay source there.

None of these reasons rewrites the anchor, which reads back as written
throughout. The start refuses to run where the first pass reads any of them, as
a Linux start does, and [pf on macOS](coexistence.md#pf-on-macos) gives the
refusal and the host's fix. An anchor holding a rule of a form the filter never
writes, such as a stateful pass another program loaded, is a fault like any
other the readback finds, which the next pass replaces by loading the anchor
whole.

## Nodes that forward without it

Where no antispoof filter runs, a node whose host forwards logs a warning at
startup and at every reload, naming the families it reads as forwarding and the
platform, as
`config: this node forwards IPv4 and IPv6 and freebsd runs no antispoof filter, so a host on any of its links can reach this host's own services under a mesh source`.
No filter runs on a Mac with no `overlay` or on a platform with neither nftables
nor pf, and a node with no `overlay` says `and writes no overlay,` after the
families.

A family whose setting the node cannot read is not named, and a node that can
read neither logs no warning. The warning is of the inbound side alone, since
the tun read judges what enters the mesh there, as [the platforms](#platforms)
below say, though a host on the node's links can still send under one of the
node's own addresses. On Linux the tun read and `mesh_entry` keep a forged
source out of the mesh and chain `antispoof` runs wherever `overlay` is written,
on a Mac with `overlay` the tun read and chain `antispoof` do, and neither logs
the warning.

## Platforms

The table is Linux's alone. On macOS `overlay` turns pf on and the filter writes
chain `antispoof` into [its anchor](#the-pf-anchor-on-macos), as
[the chain on macOS](#on-macos) gives, with every carve-out and exemption.
`status` reads
`pf anchor com.apple/ranet3, inside utun7 lo0, 2 overlay prefixes, carving 192.0.2.128/25 on en0, dropped 11 overlay sources and 1 carved sources`
on the antispoof line, with no drops entering the mesh, since the anchor holds
no entry chain. A Mac with no `overlay` leaves pf as it found it, once it gives
back what [an earlier run left](#the-pf-anchor-on-macos).

The start and a reload on macOS refuse an exemption under an exact interface
name the anchor cannot write, one holding a byte other than an ASCII letter, a
digit or `_`, such as `br-lan`, and the error names it.

Every other platform loads `overlay` and `cap.antispoof`, with every refusal of
theirs, and enforces neither, so a host on one of its interfaces can reach its
services under an overlay source. With `overlay` written, `status` reads
`not enforced on freebsd, 2 overlay prefixes` on the antispoof line and
`ranet3 debug rules` reads `Antispoof filter, not enforced on freebsd`, naming
the platform, and no pass logs anything. A node there, or on a Mac with no
`overlay`, that forwards gets
[the warning above](#nodes-that-forward-without-it).

The entry chain's place on every other platform, macOS among them, is the tun
read's own: it drops a read from a source this node does not own toward every
destination but an IPv6 link-local one, as `mesh_entry` passes `fe80::/10`, and
counts it `unowned_source` on the `Transit` line and in
`ranet3_transit_packets_total`, as [metrics](metrics.md#transit-counters) lists.
A multicast destination never reaches the check, since the read drops it first.
No reply passes it, since the read cannot tell one from a new flow, as
[the limits](design/limits.md#transit) say of the errors it drops. The drop
applies to the packet an IPv6 read carries as well.

There the overlay still bounds what the process does itself. Every local segment
loads and acts only on an outer source in the overlay's IPv6 prefixes, and the
[forwarding decision](segment-routing.md#at-the-border-of-the-mesh) reads the
overlay, as on Linux. macOS installs no overlay hold: a hold goes only beside
the policy rules that read the mesh's table, and macOS has none, so an overlay
destination no node announces leaves a Mac by its own routes.
[Platforms](platforms.md) lists what each one carries.

## Reloads

`overlay` appearing or going is a restart, since the filter and its pass are
built once at startup, as the translator is, and a reload refuses it with
`config: overlay added, restart to apply` or
`config: overlay removed, restart to apply`. A changed `overlay` list or
`cap.antispoof` block applies in place, named `overlay` and `cap.antispoof`
among the capabilities the reload applied: the reload hands both to the filter,
with the ranges inside the overlay that `cap.route` announces and the node
addresses of this node, among them each address `cap.table.assign_announced`
assigns where it is set, and the pass that wakes rewrites chain `antispoof` and
the carved sets from what the filter was handed, not the file the reload stores
after, with the mesh's table and the host's links as they are then. A reload
that moves only those ranges or addresses hands them on too. With `cap.table`,
the reconciler's pass moves the policy rules and holds it derives from the
overlay too, as [routing](routing.md#policy-rules-on-linux) lists them.
Reordering a list is no change.

## Watching it

`status` prints 1 line for the filter, after the egress line: the table and its
chains, the interfaces inside, the overlay prefixes, each carve-out as
`carving <prefix> on <link>`, and the packets each kind of drop counted as of
the last pass, the overlay's, the carved prefixes' and those entering the mesh.
A node with no `overlay` prints the table, chain `mesh_entry` and its drops
alone, and a Mac prints no drops entering the mesh, since its anchor holds no
entry chain. A filter whose table is not read back reads `not installed`, with
the reason, also where it is there and holds another writer's rule or chain or
sits in a dormant table.

`ranet3 debug rules` reads the table's rules now, through a socket of its own,
so an operator who sends a test packet reads the counters of that moment rather
than of the last pass. It lists both chains with the hooks and priorities they
are written at and the rules read now, the exemptions' accepts among them, and
each set with the elements the last pass asked for, beside every policy rule the
kernel holds and the rules the reconciler derives from the overlay, as
[the debug page](development/debug.md) describes.

On macOS the status's `border` object carries a `pf` block with the anchor, the
daemon's `token` and `pid`, `listed`, whether pf lists the one under the other,
and `called`, whether the main ruleset calls `com.apple/*`, as the last pass
read them. `ranet3 debug rules` heads the anchor's rules by their direction,
`in` for chain `antispoof`, with no priority and with their counters read now,
each by its whole spelling where pf holds its label shortened, lists the carved
table, and then the daemon's reference, the main ruleset's call and every
reference `pfctl -s References` lists now, by pid and process name:

```
Antispoof filter, pf anchor com.apple/ranet3, read 2 seconds ago, ready
  chain antispoof, in
    accept  via lo0
    drop    ipv4 source @carved4  1 packets, 84 B
    drop    ipv6 source @carved6  0 packets, 0 B
    accept  via en0 source 192.0.2.128/25
    accept  exempt source 192.0.2.32/27
    accept  exempt via bridge100 source 3fff:10:2222:3333:4444:5555:6666:7777/128
    accept  exempt via en0 source 3fff:10:1::/48
    accept  exempt via en1 source 3fff:10:1::/48
    accept  exempt via en1 source 192.0.2.64/26
    drop    ipv4 source 192.0.2.0/24  2 packets, 168 B
    drop    ipv6 source 3fff:10::/32  9 packets, 936 B
  table ranet3_carved  192.0.2.200, 3fff:10::/48
  pf reference         token 9223372036854775809 of pid 4242, listed
  pf main ruleset      calls com.apple/*
  pf enabler           pid 4242 ranet3
  pf enabler           pid 377 othervpn
```

The rule for `bridge100` is labelled `accept exempt via bridge100 2` in the
anchor, its spelling past 63 bytes.

| Log line                                                                                                                                                                                                                                                                      | Level | When                                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `antispoof filter in <where>, inside <interfaces>`                                                                                                                                                                                                                            | info  | the daemon starts the filter                                                                                                                                                                              |
| `antispoof filter installed`                                                                                                                                                                                                                                                  | info  | a pass rewrote the table, with `rules`, `replaced` and `where`                                                                                                                                            |
| `antispoof filter pass failed, retrying`                                                                                                                                                                                                                                      | warn  | a pass failed, with `err` and `retry_in`                                                                                                                                                                  |
| `antispoof filter not ready`                                                                                                                                                                                                                                                  | warn  | the table stopped reading back, with the reason as `detail`                                                                                                                                               |
| `antispoof filter ready`                                                                                                                                                                                                                                                      | info  | the table reads back again                                                                                                                                                                                |
| `antispoof carves the overlay for a link that holds part of it`                                                                                                                                                                                                               | warn  | a carve-out came, with `link` and `prefix`                                                                                                                                                                |
| `antispoof no longer carves the overlay for a link`                                                                                                                                                                                                                           | info  | a carve-out went, with `link` and `prefix`                                                                                                                                                                |
| `antispoof drops part of an exemption, since another node's prefix holds it`                                                                                                                                                                                                  | warn  | another node's prefix came to hold part of an exemption, with `exemption`, `interface`, `prefix`, `carved`, `routed_via` and `router_id`                                                                  |
| `antispoof no longer drops part of an exemption for another node's prefix`                                                                                                                                                                                                    | info  | that prefix went, with `exemption`, `interface` and `prefix`                                                                                                                                              |
| `antispoof admits this node's range though another router announces it too`                                                                                                                                                                                                   | warn  | another router came to announce an own range an exemption overlaps, with `exemption`, `interface`, `prefix` and `router_id`                                                                               |
| `antispoof no longer sees another router announce this node's range`                                                                                                                                                                                                          | info  | that conflict went, with `exemption`, `interface` and `prefix`                                                                                                                                            |
| `antispoof leaves out an exemption naming a device inside the mesh, where it drops nothing`                                                                                                                                                                                   | warn  | the start or a reload brought in an exemption under the exact name of the mesh tun or the loopback link, which writes no rule, with `interface` and `prefix`                                              |
| `antispoof filter withdrawn`                                                                                                                                                                                                                                                  | info  | the table is removed at shutdown, or by a start that ended in its build after making it                                                                                                                   |
| `antispoof filter is leaving its table after the mesh failed`                                                                                                                                                                                                                 | warn  | the stop a failed tun causes left the table, with `where`                                                                                                                                                 |
| `antispoof filter is leaving the table it found`                                                                                                                                                                                                                              | info  | a start that ended before its build completed left the table its first pass's read found, with `where`. A read that failed logs only the start's refusal                                                  |
| `stopped reading nf_tables notifications`                                                                                                                                                                                                                                     | warn  | a read of the filter's notification socket failed, with `table` and `err`, after which another writer's change waits for the next sweep                                                                   |
| `this daemon took its reference on pf again, since pf no longer listed it, which pfctl -d or another program's pfctl -X ends: pf was off, and this daemon turned it back on, so the host's protection was off until now, and removing overlay turns the antispoof filter off` | warn  | on macOS, a pass took a new reference where pf no longer listed the daemon's and pf was off, which the new one turned back on, with `token`, `pid` and `pf_off`                                           |
| `this daemon took its reference on pf again, since pf no longer listed it, which pfctl -d or another program's pfctl -X ends: pf was not off, as another holder kept it running, and removing overlay turns the antispoof filter off`                                         | warn  | on macOS, a pass took a new reference where pf no longer listed the daemon's and another holder kept pf running, with `token`, `pid` and `pf_off`                                                         |
| `this daemon took its reference on pf again, since pf no longer listed it, which pfctl -d or another program's pfctl -X ends: whether pf was off could not be read, and removing overlay turns the antispoof filter off`                                                      | warn  | on macOS, a pass took a new reference where pf no longer listed the daemon's and `pfctl -s info` failed, with `token`, `pid` and `err`                                                                    |
| `pf released the reference an earlier run left`                                                                                                                                                                                                                               | info  | on macOS, a start, with `overlay` or without, gave back the reference the record named, with `token` and `pid`                                                                                            |
| `pf dropped the record of a reference it no longer lists under its pid, which a reboot or another program stopping pf ends`                                                                                                                                                   | info  | on macOS, a start found the record naming a reference pf no longer lists under its pid, or a pass's renewal dropped the daemon's own ended reference beside the renewal's warning, with `token` and `pid` |
| `antispoof filter gave back the pf anchor and reference an earlier run left, since overlay is not written`                                                                                                                                                                    | info  | on macOS, a start without `overlay` found the record naming a reference pf still listed under its pid, emptied the anchor and gave it back, with `where`. One pfctl refused fails the start, naming it    |

A pass that rewrote the table or a set, or failed, records an `antispoof.pass`
event with `trigger`, `took`, `installed`, `wrote` and, on failure, `err`. A
change of readiness records `antispoof.ready` with `ready`. A pass that read a
counter move records `antispoof.dropped` with the packets since the pass before
of each drop a rule of the pass writes, at most once per pass. A carve-out
coming or going records `antispoof.carve`, and another node's prefix coming to
hold part of an exemption, or another router's offer for a range of this node's
own that an exemption overlaps, records `antispoof.conflict`. On macOS a pass
that took a new reference on pf records `antispoof.pf` with `token`, `pid` and
`pf_off`, whether pf was off, which it leaves out where pf's state could not be
read.

| Metric                                                  | Meaning                                      |
| ------------------------------------------------------- | -------------------------------------------- |
| `ranet3_antispoof_ready`                                | whether the table reads back, 1 or 0         |
| `ranet3_antispoof_dropped_packets_total{reason,family}` | packets dropped by kind, as of the last pass |

The reasons are `overlay_source`, `carved_source` and `mesh_entry`, each in the
families a rule of the last pass drops it in, and a drop no rule writes has no
series: `carved_source` in a family no carve-out and no exemption is of, as
[what it drops](#what-it-drops) gives, and `mesh_entry` on macOS, since the
anchor holds no entry chain. `mesh_entry` counts what the entry chain kept out
of the mesh. A rewrite of the table starts the counters from 0, which a scrape
reads as a counter reset. On macOS a load of the tables alone keeps the
counters.
