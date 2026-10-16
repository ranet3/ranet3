---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-10-16
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

An exit node advertises `0.0.0.0/0` and `::/0`. A subnet router advertises the
prefixes behind it. The node originates each prefix it announces into Babel with
no source prefix.

An exit that serves macOS clients advertises the halves instead:

```toml
[cap.egress]
advertise = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]
```

On macOS an unscoped `/0` out of the tun collides with the host's own default.
macOS has no route replace, so the reconciler skips that route and warns once.
The reconciler never splits a `/0` into halves. A Mac takes a mesh exit only
through the halves, and only with `link.underlay.bind` set. Linux clients
install the halves as they install a `/0`, once a session has been live, as
[routing](routing.md) describes.

On the Mac, a half that covers a literal endpoint address the trust document
lists stays scoped to the tun, where an unbound socket cannot select it. An
endpoint written as a hostname does not count. Every IPv4 address lies in 1 of
the 2 IPv4 halves, and every global IPv6 address lies in `::/1`. Listed IPv4
endpoints in both IPv4 halves leave the Mac without an IPv4 exit. Any listed
global IPv6 endpoint leaves it without an IPv6 exit. [Routing](routing.md) and
[sharing a host](coexistence.md) describe the scoping.

`ranet3 exit list` shows routes of length 0 only, so it does not list an exit
that advertises the halves. `ranet3 routes` shows them.

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

| Direction | Installed     | Matches                                                                                           |
| --------- | ------------- | ------------------------------------------------------------------------------------------------- |
| out       | always        | arrives on the tun, leaves by another interface                                                   |
| in        | with `return` | arrives on an interface other than the tun, leaves by the tun, source inside an advertised prefix |

`source4` and `source6` say what the source becomes. Omitted, or written as
`auto`, the out rule masquerades: the host picks the address of the link each
packet leaves by. The in rule translates to this node's own mesh address. The
translator picks that address once at startup, among the host prefixes (`/32`,
`/128`) that `cap.route` announces and `cap.table` assigns, keeping global
unicast and private addresses only.

An address written out is used unchanged in both directions. A deployment with
its own address block uses it to pin the address return traffic comes back to.
Writing out the address is the only way to make a reply land on a chosen node.

`return = true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow.

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
- `in via ranet3 ipv4 from 192.168.1.0/24 source 10.66.0.5`

An in rule carries `from` unless its prefix covers every address. A nat chain is
consulted once per connection, so the rule counters count flows, not packets.
[Sharing a host](coexistence.md) describes how the tables live beside other
writers.

## Reloads, down and up

A reload refuses a change to `cap.egress` with
`config: cap.egress changed, restart to apply`. Reordering `advertise`, writing
`"auto"` for a source and writing out the default `sweep` are not changes. A
reload is also refused when `cap.route` or `cap.table` moves the mesh address an
`auto` return source resolved to. [Reloading](reloading.md) lists what else a
reload applies.

`ranet3 down` retracts the advertisement and removes the tables. `ranet3 up`
installs them again on the next pass, and the advertisement follows.

## Watching it

`status` prints 1 line for the translator: where it writes, the rules, the
flows, what it announces, what it withholds "until its rule is installed and the
kernel forwards it", any chain it shares the hook with, the time since the last
pass and the last error.

| Log line                                                            | Level | When                                                    |
| ------------------------------------------------------------------- | ----- | ------------------------------------------------------- |
| `egress translating for N prefixes in <where>`                      | info  | the daemon starts the translator                        |
| `egress translator started`                                         | info  | the translator starts                                   |
| `egress rules installed`                                            | info  | a pass wrote the chain                                  |
| `egress advertisement changed`                                      | warn  | the announced prefixes changed after the first pass     |
| `egress is sharing the source translation hook with another writer` | warn  | a new chain appears at the same hook, once each         |
| `egress pass failed, retrying`                                      | warn  | a pass failed, retried with backoff                     |
| `egress translator withdrawn`                                       | info  | the tables are removed, at shutdown or at `ranet3 down` |
| `egress could not withdraw its tables, retrying`                    | warn  | `ranet3 down` could not remove the tables               |
| `egress translator started again`                                   | info  | the first pass after `ranet3 up`                        |

A pass that writes the chain, changes the announced prefixes or fails records an
`egress.pass` event. So does `ranet3 down`. The event carries `trigger`, `took`,
`installed`, `announced` and, on failure, `err`.

| Metric                                 | Meaning                                       |
| -------------------------------------- | --------------------------------------------- |
| `ranet3_egress_rules_installed`        | rules the host holds for this node            |
| `ranet3_egress_prefixes{state}`        | `advertised` and `announced` prefix counts    |
| `ranet3_egress_flows_total`            | connections the rules have translated         |
| `ranet3_egress_conflicts`              | other nat postrouting chains at the same hook |
| `ranet3_egress_pass_timestamp_seconds` | when the last pass finished                   |
| `ranet3_egress_pass_failed`            | whether the last pass reported an error       |

[Metrics](metrics.md) describes the scrape.
