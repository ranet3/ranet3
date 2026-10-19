---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-10-19
order: 50
---

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. 1 action covers both features a customer asks for: an exit node advertises
`0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes behind it, and
each ends at the same operation. A packet arrives on the tun, its source is
translated to an address the far side can answer, and the host forwards it by
its ordinary routes.

`cap.egress` works on Linux only. On any other platform the daemon refuses it at
startup with `egress: source translation is unsupported on this platform`. A
node that accepted the configuration and translated nothing would advertise
itself and then drop every flow that took it.

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
is still listed by `ranet3 exit list`, as an exit for that family.

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

| Direction | Installed               | Matches                                                                                                                |
| --------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| out       | always                  | arrives on the tun, leaves by another interface                                                                        |
| out       | beside an egress device | arrives on the egress device, leaves by any interface but the tun                                                      |
| in        | with `return`           | arrives on an interface other than the tun or the egress device, leaves by the tun, source inside an advertised prefix |

`source4` and `source6` say what the source becomes, per family, for every out
rule. They are a property of the node, so a packet from the tun and one from an
[egress segment](#egress-segments) leave under the same address. Omitted, or
written as `auto`, the out rule masquerades: the host picks the address of the
link each packet leaves by. The in rule translates to this node's own mesh
address. The translator picks that address once at startup, among the host
prefixes (`/32`, `/128`) that `cap.route` announces and `cap.table` assigns,
keeping global unicast and private addresses only.

An address written out is used unchanged in both directions. A deployment with
its own address block uses it to pin the address return traffic comes back to.
Writing out the address is the only way to make a reply land on a chosen node.

`return = true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow. A packet arriving on the
egress device carries a mesh node's traffic, never traffic from behind this
node, so the in rule never matches it.

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
`10.99.0.0/24` and `fd00:99::/64` to the mesh table:

```toml
[cap.table]
id = 200

[[cap.table.rules]]
to = "10.99.0.0/24"
table = 200
priority = 100

[[cap.table.rules]]
to = "fd00:99::/64"
table = 200
priority = 100
```

## Refusing to advertise

**An exit that cannot translate refuses to advertise.** Babel carries no
capability signal. A node that advertises a prefix promises to carry it, and the
advertisement is all a peer learns. An exit whose rule will not install would
attract traffic and drop it without telling the sender.

The capability publishes the advertisement per family on every pass. A prefix is
announced only while every rule of its family is installed and the host forwards
that family. Each pass first reinstalls a missing rule. When a rule still cannot
be installed, or the host stops forwarding the family, that pass retracts the
prefix. A pass runs at least every `sweep` (30 seconds by default).

The node reads forwarding from `/proc/sys/net/ipv4/ip_forward` and
`/proc/sys/net/ipv6/conf/all/forwarding`. Any value other than `0` counts as on,
and so does a file the node cannot read.
[The transit warning](design/limits.md#transit) reads the same settings. An exit
acts on them by withholding its advertisement, because no other node can tell
whether it forwards.

`status` names the prefixes it announces and the ones it withholds. The scrape
carries the advertised and the announced counts as `ranet3_egress_prefixes`.

## The nftables tables

The translator owns 1 table named `ranet3` in each advertised family, `ip` and
`ip6`. Each table holds 1 chain:

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
- `out via ranet3e not ranet3 ipv4 masquerade`, the rule keyed on the egress
  device
- `in via ranet3 ipv4 from 192.168.1.0/24 source 10.66.0.5`
- `in via ranet3 not ranet3e ipv4 from 192.168.1.0/24 source 10.66.0.5`, the
  same rule on a node with an egress device

An in rule carries `from` unless its prefix covers every address. Beside an
egress device the translator owns both tables, whatever `advertise` holds, since
an egress segment carries both families. A nat chain is consulted once per
connection, so the rule counters count flows, not packets.
[Sharing a host](coexistence.md) describes how the tables live beside other
writers.

## Egress segments

An egress segment is a SID a leaf steers its traffic to, so the leaf picks this
exit by its segment list rather than by the default route Babel selects.
[Segment routing](segment-routing.md#egress-segments) describes the segment and
its `allow` list. This page covers what the exit does with the inner packet.

The daemon makes the egress device at startup, a tun named `link.tun` plus `e`,
`ranet3e` by default. It carries no address, takes no router advertisement, runs
with `rp_filter` 0, `disable_ipv6` 0 and multicast off, and is removed at
shutdown. The mesh writes each inner packet into it. The kernel forwards the
packet from there by its own routes, and the out rule keyed on the device
translates it. Nothing is routed into the device, and a packet the kernel sends
there anyway is read and dropped.

An exit that serves only egress segments writes `cap.egress` with an empty
`advertise`. It then attracts no default route, and only a leaf naming its SID
uses it:

```toml
[cap.egress]
advertise = []

[[cap.segment.local]]
sid = "2001:db8:0:6::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["10.99.0.0/24", "fd00:99::/64"]
```

### The egress device's rule

A steered packet keeps the leaf's mesh source, and its destination is anywhere.
A `cap.table.rules` entry has to send what arrives on the egress device to the
main table. Its place among the rules into the mesh table decides where the
packet goes:

- After every `to` rule into the mesh table, so a steered packet for a mesh
  destination still goes to the mesh rather than out of the uplink.
- Before every `from` rule into the mesh table, since such a rule takes the
  leaf's source to the mesh table's default and out of another exit.

```toml
[[cap.table.rules]]
iif = "ranet3e"
table = "main"
priority = 120
family = "both"
```

The daemon refuses a file with an egress segment and no such rule, or with the
rule on the wrong side of a `to` or `from` rule, and the error names the rule
and a priority that fits. A missing `to` or `from` rule bounds nothing. With no
`from` rule any priority after the `to` rule fits, up to 4294967295, and with no
`to` rule any priority from 1 to just before the `from` rule. Where a `from`
rule sits at or below a `to` rule, or directly above it, no priority fits, and
the error says so and names both. A lone `to` rule at 4294967295 or a lone
`from` rule at 1 leaves no priority either, and the error names that rule. It
cannot see rules another writer installs, such as networkd's, so a priority
between those is the operator's to choose. The reconciler installs the rule and
puts it back when another writer deletes it.

### Readiness

The mesh writes into the egress device only for a family the translator reports
ready, and counts an egress segment's packet of another family as not ready. A
family is ready while its rule keyed on the egress device reads back, the host
forwards the family and the kernel would take the family from the device. The
kernel takes the larger of `net.ipv4.conf.all.rp_filter` and the device's own,
and an address-less device fails even loose mode. Each pass therefore puts the
device's own `rp_filter` back to 0 when another writer set it, as systemd-sysctl
does for each new link on a host shipping its `50-default.conf`. A nonzero
`conf.all.rp_filter` is host policy the daemon leaves alone, and holds IPv4 not
ready until it is 0. The device's own IPv4 forwarding off does the same. For
IPv6, the kernel discards every packet arriving on a device whose `disable_ipv6`
is 1. The daemon makes the device with it at 0, whatever
`net.ipv6.conf.default.disable_ipv6` holds, and each pass puts it back to 0 when
another writer set it. IPv6 is not ready while it still reads 1. The device
gone, for example deleted by another writer, holds both families not ready.

Another writer deleting part of the `ranet3` tables, a `nftables.service` reload
that flushes the ruleset for one, holds both families not ready until the pass
it wakes restores them, rather than until the next sweep. Notifications the
daemon lost, which another table's large transaction can overflow its socket
with, wake a pass too and leave readiness as it was, since that pass reads the
rules back. A rule another writer adds to a `ranet3` chain wakes nothing, and
the next pass, at most `sweep` later, rewrites the chain without it.

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
restart, since the egress device is made at startup. A reload moving an egress
segment to another SID or editing its `allow` list applies in place, and the
originated `/128` moves with the SID. [Reloading](reloading.md) lists what else
a reload applies.

`ranet3 down` retracts the advertisement and removes the tables. `ranet3 up`
installs them again on the next pass, and the advertisement follows.

## Watching it

`status` prints 1 line for the translator: where it writes, the rules, the
flows, what it announces, what it withholds "until its rule is installed and the
kernel forwards it", the egress device and the families it is ready for, any
chain it shares the hook with, the time since the last pass and the last error.
A family not ready is named with the reason the last pass found, or in the
withholding clause's words before the first.

| Log line                                                             | Level | When                                                                      |
| -------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------- |
| `egress translating for N prefixes in <where>`                       | info  | the daemon starts the translator                                          |
| `egress translator started`                                          | info  | the translator starts, with the egress device as `egress`, empty for none |
| `egress device created`                                              | info  | the daemon made the egress device, with `name` and `mtu`                  |
| `egress device withdrawn`                                            | info  | the daemon removed it at shutdown                                         |
| `egress segments ready`                                              | info  | a family went ready, with `family`                                        |
| `egress segments not ready`                                          | warn  | a family stopped being ready, with `family` and the reason as `detail`    |
| `egress device rp_filter put back to 0`                              | info  | another writer set the device's own, with `was`                           |
| `egress device disable_ipv6 put back to 0`                           | info  | another writer turned IPv6 off on the device, with `was`                  |
| `egress device takes rp_filter <n> from net.ipv4.conf.all.rp_filter` | warn  | IPv4 cannot be ready, once per value                                      |
| `egress rules installed`                                             | info  | a pass wrote the chain                                                    |
| `egress advertisement changed`                                       | warn  | the announced prefixes changed after the first pass                       |
| `egress is sharing the source translation hook with another writer`  | warn  | a new chain appears at the same hook, once each                           |
| `egress pass failed, retrying`                                       | warn  | a pass failed, retried with backoff                                       |
| `egress translator withdrawn`                                        | info  | the tables are removed, at shutdown or at `ranet3 down`                   |
| `egress could not withdraw its tables, retrying`                     | warn  | `ranet3 down` could not remove the tables                                 |
| `egress translator started again`                                    | info  | the first pass after `ranet3 up`                                          |

A pass that writes the chain, changes the announced prefixes or fails records an
`egress.pass` event. So does `ranet3 down`. The event carries `trigger`, `took`,
`installed`, `announced` and, on failure, `err`. A change of the egress device's
readiness, or of whether its SIDs are served, records `egress.ready` with
`ipv4`, `ipv6` and `sid`, and the device's creation and removal record
`egress.device`.

| Metric                                 | Meaning                                                        |
| -------------------------------------- | -------------------------------------------------------------- |
| `ranet3_egress_rules_installed`        | rules the host holds for this node                             |
| `ranet3_egress_prefixes{state}`        | `advertised` and `announced` prefix counts                     |
| `ranet3_egress_flows_total`            | connections the rules have translated                          |
| `ranet3_egress_conflicts`              | other nat postrouting chains at the same hook                  |
| `ranet3_egress_pass_timestamp_seconds` | when the last pass finished                                    |
| `ranet3_egress_pass_failed`            | whether the last pass reported an error                        |
| `ranet3_egress_device_ready{family}`   | whether the egress device is ready, 1 or 0, on a node with one |

[Metrics](metrics.md) describes the scrape.
