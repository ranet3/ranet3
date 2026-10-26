---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-10-26
order: 50
---

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. 1 action covers both features a customer asks for: an exit node advertises
`0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes behind it, and
each ends at the same operation. A packet arrives on the tun, its source is
translated to an address the far side can answer, and the host forwards it by
its ordinary routes. An [egress segment](#egress-segments) ends at the same
operation, its inner packets arriving on the same tun.

`cap.egress` works on Linux only, whose builds carry the kernel exit this page
describes. A build for any other platform, Android and iOS among them, carries
no exit, and the daemon refuses `cap.egress` at startup in words that name the
platform, as [Platforms](platforms.md#at-a-glance) quotes them. A node that
accepted the configuration and carried nothing would advertise itself and then
drop every flow that took it.

[The configuration reference](configuration-reference.md) lists every key and
its default.

```toml
[cap.egress]
advertise = ["198.51.100.0/24"] # an exit node writes ["0.0.0.0/0", "::/0"]
# source4 = "auto"                # or an address
# source6 = "auto"
# return = true                   # also translate into the mesh, for a subnet router
# sweep = "30s"
```

## What to advertise

An exit node advertises `0.0.0.0/0` and `::/0`, and only those, for Linux and
macOS clients alike. A subnet router advertises the prefixes behind it. The node
originates each prefix it announces into Babel with no source prefix.

An exit does not advertise the `/1` halves in place of a `/0`. A half is longer
than any `/0`, so wherever it is installed it wins over every `/0` exit by
longest prefix, whatever the metric, and Babel no longer chooses among exits.
The lower half, `0.0.0.0/1` or `::/1`, also contains its family's zero address,
so a Mac with `link.underlay.bind` set installs it unscoped only beside a
default the daemon writes scoped to the underlay's interface, the route the
zero-free cover does without. A node that does advertise both halves of a family
is still listed by `ranet3 exit list`, as an exit for that family. It egresses
as an exit does, and so does a node advertising a split such as four `/2`s,
since each of those prefixes
[counts as a default](routing.md#routes-that-count-as-a-default).

Until exit selection exists, a Mac with `link.underlay.bind` set takes whichever
`/0` Babel selects, once a session has been live, and installs it as its
zero-free cover, as [routing](routing.md#the-zero-free-cover-on-macos)
describes. Babel, its updates and `ranet3 exit list` keep the `/0`. A Mac
without `bind` scopes the `/0` to the tun, where no unbound socket selects it.

`cap.route` may not announce a prefix `cap.egress` advertises. The daemon
refuses that at startup and on every reload, because `cap.route` would announce
the prefix whether or not its translation rule is installed.

`cap.egress` does not depend on `cap.transit`. An exit with transit off still
advertises the prefixes it is ready to carry and translates the traffic for
them.

## Translation

Both interfaces are matched, never one. A packet that arrives on the tun and
leaves by it again is mesh transit, and rewriting its source would put this
node's address on a packet it is only relaying.

A packet this host generated itself has no arrival interface. The kernel reports
it with an empty interface name. The inbound rule therefore also requires an
arrival interface index other than 0. Without that test, this node's own traffic
into the mesh would leave under the return source.

| Direction | Installed                                                       | Matches                                                                                           |
| --------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| out       | in each advertised family, and in both beside an egress segment | arrives on the tun, leaves by another interface                                                   |
| in        | with `return`                                                   | arrives on an interface other than the tun, leaves by the tun, source inside an advertised prefix |

`source4` and `source6` say what the source becomes, per family, for every out
rule. They are a property of the node, so a packet through an advertised prefix
and one from an [egress segment](#egress-segments) leave by the same rule, under
the same address. Omitted, or written as `auto`, the out rule masquerades: the
host picks the address of the link each packet leaves by. The in rule translates
to this node's own mesh address. The translator picks that address once at
startup, among the host prefixes (`/32`, `/128`) that `cap.route` announces and
`cap.table` assigns, keeping global unicast and private addresses only.

An address written out is used unchanged in both directions. A deployment with
its own address block uses it to pin the address return traffic comes back to.
Writing out the address is the only way to make a reply land on a chosen node.

`return = true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow. An egress segment's
packet arrives on the tun, so the in rule never matches it.

With `return` set and an `auto` source, each advertised family needs exactly 1
candidate mesh address. A family with none or with several is refused at
startup, and the error asks for the address in `source4` or `source6`. A pick
among several would set the source of every flow out of the LAN. A guess could
change after an unrelated edit.

## The return path

Conntrack reverses the translation before the reply is routed. The reply is then
addressed to a mesh node, and the forwarding lookup has to find the route to it.
With the mesh's routes in the reconciler's own table, that takes a
`cap.table.rules` entry with `to` set to the mesh prefix, 1 per family. A rule
that selects on this node's own source does not match a reply.

Without the `to` rule, the outbound half works and the translation counter
moves. No reply reaches the mesh, so the exit looks like one that answers
nothing rather than like a missing rule. This example sends replies for
`203.0.113.0/25` and `3fff:a::/64` to the mesh table:

```toml
[cap.table]
id = 200

[[cap.table.rules]]
to = "203.0.113.0/25"
table = 200
priority = 100

[[cap.table.rules]]
to = "3fff:a::/64"
table = 200
priority = 100
```

An exit or subnet router set up this way can carry transit. With `cap.transit`
on, a packet another node sends through it for a prefix a third node announces,
such as the subnet behind another subnet router, goes on through the mesh by the
mesh's own table, as [routing](routing.md#transit) describes. It never reaches
the tun, so the `to` rules and the host's routes out of the uplink never see it.

## What an exit carries out

A packet a session delivers for a destination this node holds through a route
that [counts as a default](routing.md#routes-that-count-as-a-default), such as
the `0.0.0.0/0` and `::/0` it advertises, is egress. The
[forwarding decision](routing.md#transit) hands it to the exit, which writes it
into the tun, where the host translates it and forwards it out of its uplink,
only where 3 checks pass:

- A destination inside `cap.border.overlay` belongs to the mesh. One that no
  node announces is answered as a destination no route holds, IPv6 code 0 and
  IPv4 Host Unreachable, and never sent out of the uplink. An exit without
  `cap.border` has no overlay, so this check passes every packet, and it sends
  an address no node announces out of the uplink as any other destination
  outside the mesh.
- The mesh routes a reply to the packet's source. The decision looks the source
  up as a reply from the packet's destination is routed, so a route announced
  from a source prefix covers the source only where that prefix covers the
  destination, and it passes over every route that counts as a default, another
  exit's among them. The reply's route has to reach a peer, a held prefix, or a
  network or address of this node's own, such as a LAN it shares with another
  node. A packet from any other source is dropped with no answer and counted as
  `unrouted source`, since no reply to it could come back.
- For a prefix `cap.egress` advertises, the packet's family is one the exit
  holds [ready](#readiness) and the node announces some prefix of. A packet of
  any other family is dropped with no answer and counted as `not ready`. The
  node takes the families it announces before the speaker announces or retracts
  them, so a fresh announcement attracts no packet before its family is ready,
  and a packet of a family that went is dropped before the retraction reaches
  anyone. A family whose translation another writer took stays announced until
  the exit's next pass, and its packets are dropped from the moment the exit
  holds it not ready. Once the speaker retracts the prefix, the decision treats
  a packet for it as [retracted routes](routing.md#retracted-routes) describe.
  The border filter takes no part: it holds back the egress segments alone.

A packet through a prefix counting as a default that `cap.route` announces meets
the first 2 checks, and past them goes to the tun with no readiness to wait on,
since no translation of this node stands behind it. An
[egress segment](#egress-segments)'s inner packet meets the second check after
its `allow` list, and is then refused where its destination lies inside
`cap.border.overlay`, announced or not, or the mesh routes it, as
[segment routing](segment-routing.md#egress-segments) describes.

## Refusing to advertise

**An exit that cannot translate refuses to advertise.** Babel carries no
capability signal. A node that advertises a prefix promises to carry it, and the
advertisement is all a peer learns. An exit whose rule will not install would
attract traffic and drop it without telling the sender.

The capability publishes the advertisement per family on every pass. A prefix is
announced only while its family's chain reads back exactly as the node wrote it,
every rule in order and no other writer's among them, at its hook, priority and
policy in a table with no flags, the host forwards that family and, where its
lookups run, the kernel routes a translated packet of it and its reply, as
[readiness](#readiness) describes. Each pass first rewrites a chain that reads
back otherwise, such as one missing a rule, holding another writer's or in a
dormant table. nf_tables clears no table flag in place but dormant, and changes
no chain's type, hook or priority, so when one of those differs the pass deletes
the family's table, and any chain another writer put in it, then makes it again
in the same transaction. When the chain still does not read back as written, the
host stops forwarding the family or a lookup fails, that pass retracts the
prefix. A pass runs at least every `sweep` (30 seconds by default).

The node reads forwarding from `/proc/sys/net/ipv4/ip_forward` and
`/proc/sys/net/ipv6/conf/all/forwarding`. Any value other than `0` counts as on,
and so does a file the node cannot read. An exit acts on them by withholding its
advertisement, because no other node can tell whether it forwards. Transit
between sessions needs neither setting, since the mesh forwards it itself.

`status` names the prefixes it announces and the ones it withholds. The scrape
carries the advertised and the announced counts as `ranet3_egress_prefixes`.

## Readiness

A family is ready while its chain reads back as written with its table, the host
forwards it, and, where its lookups run, the kernel routes a translated packet
of the family and its reply the way the translation needs. Every node with
`cap.egress` judges each family it translates on every pass, and both modes wait
for the judgment: a packet through an advertised prefix waits for the families
ready that the node announces, and an egress segment's packet for the families
ready, as [what an exit carries out](#what-an-exit-carries-out) and
[egress segments](#egress-segments) describe. A family this node does not
translate is not ready.

The kernel's routes are read from its own route lookups, all of a pass in 1
batch through 1 netlink socket:

- **The forward lookup**, for each prefix the family advertises, or for the
  family's default (`0.0.0.0/0` or `::/0`) where it advertises none beside an
  egress segment: a packet arriving on the tun from a member's address to the
  prefix's read address has to leave by a device other than the tun.
- **The reply lookup**, 1 a family: the translated reply, arriving on the device
  the family's first forward lookup left by, from that read address back to the
  member's address, has to leave by the tun. It catches an exit whose replies
  would leave by its uplink, such as one missing the `to` rules of
  [the return path](#the-return-path). With strict reverse path filtering on the
  tun, or loose filtering on a tun with no IPv4 address, such an exit fails its
  IPv4 forward lookup first, since the kernel checks the forwarded packet's
  source against the same route.

A lookup holds its family not ready when it fails, finds a route of a type other
than `unicast`, finds no live next hop, or leaves by the wrong device, a forward
lookup with any live hop on the tun and a reply lookup with any live hop off it.
A hop the kernel marks dead or link-down is not live, and a route naming a
nexthop object that holds no hop counts as a failed lookup.

**The source** of both lookups is a member's address: the read address of a
prefix the mesh routes by the tun to another node, inside `cap.border.overlay`,
overlapping none of this node's own prefixes, taking the lowest base address
first and then the longest prefix. A correctly configured exit routes its
members' addresses into the tun, so a lookup from one reads the path a real
reply takes, where an unused overlay address would meet the overlay's hold.

**The read address** of a prefix is its own address for a host route, and
otherwise the first of these that the kernel's input path takes as a unicast
destination: its middle address, the base with the bit after the length set,
then its base plus 1, then its last address less 1. The middle alone would not
do, since `192.0.0.0/2`'s is `224.0.0.0`, a group. IPv4 refuses the limited
broadcast, `0.0.0.0`, the loopback addresses and the multicast addresses, and
IPv6 the unspecified, loopback, multicast and link-local addresses. Linux 4.20
to 5.2 also refuse `0.0.0.0/8` as a destination, where a lookup of a prefix
inside it fails and holds its family not ready.

**The skip.** The lookups of a family are skipped, and the family judged by its
chain and its forwarding alone, where the mesh routes no member of it, as before
any member is learned, in a mesh of 1, or with no `cap.border.overlay` prefix of
the family. A prefix holding no address the kernel takes, such as `127.0.0.0/8`
or `fe80::/10`, has its lookup skipped as well, since the kernel forwards
nothing to it either way. A family whose every prefix is skipped is judged as
one with no member. `status` and the `egress.ready` event say what was skipped:

- `lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay`
- `lookup skipped for fe80::/10, which holds no address the kernel takes as a unicast destination`

**The reason** a family is not ready names the lookup, the prefix, the read
address, the source and the device the packet arrived on, and what the kernel
answered, such as
`the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3 failed: no route to host, with net.ipv4.conf.ranet3.forwarding at 0`
or
`the reply lookup of 3fff:20::1 for 2001:db8::/32 from 2001:db8:8000:: arriving on eth0 leaves by eth0 rather than ranet3`.
A failed IPv4 lookup names the setting of the device it arrived on that refuses
it, the tun's for a forward lookup and the uplink's for a reply: the device's
own `forwarding` at 0, or reverse path filtering, the larger of
`net.ipv4.conf.all.rp_filter` and the device's own. The kernel answers these
with errnos it answers for other causes too, `EHOSTUNREACH` for forwarding off
and `EXDEV`, or `EINVAL` from Linux 6.13 on, for reverse path filtering, so the
reason reads the settings rather than the errno. The daemon reads them and
changes none. An IPv6 lookup with forwarding off answers its route, and the
host's forwarding check stands for it.

Another writer adding, changing or deleting part of the `ranet3` tables, such as
a `nftables.service` reload that flushes the ruleset, a rule put in a `ranet3`
chain or a table set dormant, holds both families not ready until the pass it
wakes restores them, rather than until the next sweep. The daemon's own writes
wake nothing. Notifications the daemon lost, which another table's large
transaction can overflow its socket with, wake a pass too and leave readiness as
it was, since that pass reads the rules back. A pass that reads another writer's
change back and cannot undo it holds that family not ready, with the change
named, and its prefixes withheld until a later pass does.

## The nftables tables

The translator owns 1 table named `ranet3` in each family it translates, `ip`
and `ip6`: each advertised family, and both beside an egress segment, whatever
`advertise` holds, since an egress segment carries both families. Each table
holds 1 chain:

| Property | Value          |
| -------- | -------------- |
| Name     | `postrouting`  |
| Type     | `nat`          |
| Hook     | `postrouting`  |
| Priority | 100 (`srcnat`) |
| Policy   | `accept`       |

A pass replaces the chain's rules in 1 transaction. Each rule carries its
identity as its comment, which `nft list ruleset` shows:

- `out via ranet3 ipv4 masquerade`
- `out via ranet3 ipv6 source 2001:db8::1`
- `in via ranet3 ipv4 from 198.51.100.0/24 source 203.0.113.10`

An in rule carries `from` unless its prefix covers every address. A nat chain is
consulted once per connection, so the rule counters count flows, not packets.
[Sharing a host](coexistence.md) describes how the tables live beside other
writers.

## Egress segments

An egress segment is a SID a leaf steers its traffic to, so the leaf picks this
exit by its segment list rather than by the default route Babel selects.
[Segment routing](segment-routing.md#egress-segments) describes the segment and
its `allow` list. This page covers what the exit does with the inner packet.

The mesh hands each inner packet to the exit, as it hands a packet the
forwarding decision egresses, and the exit writes it into the tun. The kernel
forwards it by its own routes, translated by the out rule keyed on the tun. A
node with an egress segment translates both families, whatever `advertise`
holds. An inner packet whose destination lies inside `cap.border.overlay`, or
that the mesh routes itself, to another node, into a hold or to this node, is
refused rather than handed to the exit, as
[segment routing](segment-routing.md#egress-segments) describes.

An exit that serves only egress segments writes `cap.egress` with an empty
`advertise`. It then attracts no default route, and only a leaf naming its SID
uses it:

```toml
[cap.egress]
advertise = []

[cap.border]
overlay = ["203.0.113.0/24", "3fff:a::/36"]

[[cap.segment.local]]
sid = "2001:db8:0:6::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["203.0.113.0/25", "3fff:a::/64"]
```

An egress segment needs [the border filter](border-filter.md), and its `allow`
list lies inside the filter's `overlay`. The daemon refuses a file with an
egress segment and no `cap.border`, or with an `allow` entry the overlay does
not cover. The list names mesh sources, which a host on a link of any forwarding
node could otherwise forge and send through that node to the SID.

An egress segment needs no `cap.table`, though its replies take the `to` rules
of [the return path](#the-return-path), which the reply lookup reads. Its
packets wait for their family's [readiness](#readiness), and the mesh counts one
of a family not ready as not ready. Both families also wait while the border
filter's chain is not read back, since the border is 1 chain for both.

The node originates each egress SID as a `/128` while at least 1 family is ready
and every family the host forwards is. A leaf reads the `/128` as the exit's
liveness. An exit forwarding a single family still serves that family, and an
exit whose translation broke in a family it forwards withdraws the SID. Each
pass reads forwarding again, so a family the host starts or stops forwarding
moves the `/128` on the next pass even where readiness stays as it was.
`cap.route` may not announce the SID's `/128`, since it would hold the route up
whatever readiness says.

## Reloads, down and up

A reload refuses a change to `cap.egress` with
`config: cap.egress changed, restart to apply`. Reordering `advertise`, writing
`"auto"` for a source and writing out the default `sweep` are not changes. A
reload is also refused when `cap.route` or `cap.table` moves the mesh address an
`auto` return source resolved to. The first egress segment and the last are a
restart, since the families the translator translates are fixed at startup. A
reload moving an egress segment to another SID or editing its `allow` list
applies in place, and the originated `/128` moves with the SID.
[Reloading](reloading.md) lists what else a reload applies.

`ranet3 down` retracts the advertisement and removes the tables. `ranet3 up`
installs them again on the next pass, and the advertisement follows.

## Watching it

`status` prints 1 line for the translator: where it writes, the rules, the
flows, what it announces, what it withholds "until its family is ready", the
families it is ready for and the reason the others are not, what the lookups
skipped, any chain it shares the hook with, the time since the last pass and the
last error. A family not ready is named with the reason the last pass found, and
a family the node does not translate with none. Before the first pass the line
names no family. While the border filter holds the egress segments back, the
line says `until the border filter is read back`.

| Log line                                                            | Level | When                                                                                                               |
| ------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------ |
| `egress translating for N prefixes in <where>`                      | info  | the daemon starts the translator                                                                                   |
| `egress translator started`                                         | info  | the translator starts, with the tun as `interface` and whether the node holds an egress segment as `steered`       |
| `egress ready`                                                      | info  | a family went ready, with `family`                                                                                 |
| `egress not ready`                                                  | warn  | a family stopped being ready, with `family` and the reason as `detail`                                             |
| `egress stopped reading nf_tables notifications`                    | warn  | a read of the notification socket failed, with `err`, after which another writer's change waits for the next sweep |
| `egress rules installed`                                            | info  | a pass wrote the chain                                                                                             |
| `egress advertisement changed`                                      | warn  | the announced prefixes changed after the first pass                                                                |
| `egress is sharing the source translation hook with another writer` | warn  | a new chain appears at the same hook, once each                                                                    |
| `egress pass failed, retrying`                                      | warn  | a pass failed, retried with backoff                                                                                |
| `egress translator withdrawn`                                       | info  | the tables are removed, at shutdown or at `ranet3 down`                                                            |
| `egress could not withdraw its tables, retrying`                    | warn  | `ranet3 down` could not remove the tables                                                                          |
| `egress translator started again`                                   | info  | the first pass after `ranet3 up`                                                                                   |

A pass that writes the chain, changes the announced prefixes or fails records an
`egress.pass` event. So does `ranet3 down`. The event carries `trigger`, `took`,
`installed`, `announced` and, on failure, `err`. A change of a family's
readiness, of whether the egress SIDs are served or of what the lookups skipped
records `egress.ready` with `ipv4`, `ipv6`, `sid`, the reason as `reason` and
the skip as `skipped`. A reason that changes while nothing else moves reaches
`status` and not the event.

| Metric                                 | Meaning                                                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `ranet3_egress_rules_installed`        | rules the host holds for this node                                                                            |
| `ranet3_egress_prefixes{state}`        | `advertised` and `announced` prefix counts                                                                    |
| `ranet3_egress_flows_total`            | connections the rules have translated                                                                         |
| `ranet3_egress_conflicts`              | other nat postrouting chains at the same hook                                                                 |
| `ranet3_egress_pass_timestamp_seconds` | when the last pass finished                                                                                   |
| `ranet3_egress_pass_failed`            | whether the last pass reported an error                                                                       |
| `ranet3_egress_ready{family}`          | whether the family is [ready](#readiness), 1 or 0, the translator's judgment without the border filter's hold |

[Metrics](metrics.md) describes the scrape.
