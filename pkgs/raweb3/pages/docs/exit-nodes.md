---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-11-22
order: 50
---

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. 1 action covers both features a customer asks for: an exit node advertises
`0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes behind it, and
each ends at the same operation. On Linux a packet arrives on the tun, its
source is translated to an address the far side can answer, or left as it is, by
the class of its source, and the host forwards it by its ordinary routes. An
[egress segment](#egress-segments) ends at the same operation: on Linux its
inner packets arrive on the same tun, and on macOS the userspace exit takes them
as it takes a packet through an advertised prefix.

`cap.egress` works on Linux and macOS. A Linux build carries the kernel exit
most of this page describes, which translates in the host's kernel. A macOS
build carries the userspace exit, which ends each TCP connection in a stack of
its own and relays UDP and echo through the host's sockets, as
[the exit on macOS](#the-exit-on-macos) gives. An Android or iOS build carries
no exit, and the daemon refuses `cap.egress` at startup in words that name the
platform, as [Platforms](platforms.md#at-a-glance) quotes them. Every build but
Linux's refuses a `cap.route` entry that
[counts as a default](routing.md#routes-that-count-as-a-default) at startup and
on a reload, since its kernel would forward that traffic with no entry chain to
pass the replies into the mesh. A node that accepted the configuration and
carried nothing would advertise itself and then drop every flow that took it.

[The configuration reference](configuration-reference.md) lists every key and
its default.

```toml
[cap.egress]
advertise = ["198.51.100.0/24"] # an exit node writes ["0.0.0.0/0", "::/0"]
# translate = [                  # left out, every source leaves under auto
#   { from = "3fff:a::/32", to = "none" },
#   { from = "0.0.0.0/0", to = "198.51.100.7" },
# ]
# return = true                   # also translate into the mesh, for a subnet router
# flows_per_source = 4096
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
so a Mac under `cap.exit` without `via`, in a family the tun holds an overlay
address of, installs it as the 7 members of the zero-free cover it contains,
which leave that address to the host's own default. In mode 3 it declines the
half, and in a family the tun holds no overlay address of it scopes the half to
the tun, as [routing](routing.md#the-zero-free-cover-on-macos) gives. A node
that does advertise both halves of a family is still listed by
`ranet3 exit list`, as an exit for that family. It egresses as an exit does, and
so does a node advertising a split such as four `/2`s, since each of those
prefixes [counts as a default](routing.md#routes-that-count-as-a-default).

[The zero-free cover](routing.md#the-zero-free-cover-on-macos) gives which `/0`
a Mac under [`cap.exit`](configuration-reference.md#capexit) takes and how it
installs it. A Mac without `cap.exit` scopes the `/0` to the tun, which only a
socket bound to the tun or to an address of it selects.

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

| Direction | Installed                                                                                 | Matches                                                                                           |
| --------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| out       | in each advertised family, and in both beside an egress segment                           | arrives on the tun, leaves by another interface                                                   |
| in        | with `return`                                                                             | arrives on an interface other than the tun, leaves by the tun, source inside an advertised prefix |
| local     | in each family the out rules cover, for each of this node's mesh addresses of that family | leaves by an interface other than the tun, from that address                                      |

### Classes

`translate` decides what the source of a packet leaving the mesh becomes, by the
packet's source. It is a list of classes, each a `from` prefix and a `to`:

- `auto` masquerades: the host picks the address of the link each packet leaves
  by.
- An address of `from`'s family is used unchanged.
- `none` leaves the source as the packet carries it, under the conditions of
  [`none`](#none).

A source takes the class of the longest `from` covering it, and `auto` where no
class covers it. The order of the list does not matter, and a `translate` left
out translates every source under `auto`. The class decides for every packet the
out rules carry, whether a route through an advertised prefix or an
[egress segment](#egress-segments) brought it, since with 1 tun the host sees
only the packet's addresses and the links it crosses.

Under a class that translates, a packet out of the mesh that the host's
connection tracking
[keeps no flow for](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n2049)
is dropped and counted, since the host's source translation
[passes such a packet as it is](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n901)
and it would leave under its mesh source. A packet another writer's rule exempts
from tracking is dropped with them. Under a class of `none` such a packet leaves
as the host forwards it. Under `return` a packet into the mesh that no flow is
tracked for is dropped and counted the same way wherever an in rule translates,
since every in rule translates.
[Protocol deviations](design/protocol-deviations.md#exit-translation) lists the
ICMP queries this leaves unanswered.

A DCCP or UDP-Lite packet the exit forwards in its flow's original direction is
refused and counted on every kernel wherever it would be translated, out of the
mesh under a class that translates and into the mesh under `return`. Each
protocol's checksum covers the addresses, and
[the host's source translation does not rewrite that checksum](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_proto.c?id=940de590b839f71d6dc846160534bf202401b8b7#n261)
on a kernel with no connection tracker for the protocol. The exit refuses on a
kernel that has one too, rather than read which kernel it runs on. A reply is
left to cross. The refusal answers Destination Unreachable, administratively
prohibited, code 13 over IPv4 and code 1 over IPv6, where the kernel's reject
answers at all, and comes ahead of
[the share](#each-sources-share-of-the-flows), so such a flow never draws the
share's answer. On a kernel before 7.1 the host's connection tracking can give a
valid UDP-Lite packet no flow, and the rule for a packet no flow is tracked for
then takes it first, as
[protocol deviations](design/protocol-deviations.md#exit-translation) describes.
Under a class of `none` such a packet leaves as the host forwards it. In IPv4,
Source Quench and Information Request and Reply are dropped and counted out of
the mesh and into it under every class, `none` among them, ahead of every other
rule. [Protocol deviations](design/protocol-deviations.md#exit-translation)
gives the reasons and the packets the refusal leaves unanswered.

The in rule translates to the address of its family's class from `0.0.0.0/0` or
`::/0` where that class names one, and to this node's own mesh address where it
is `auto`, `none` or absent. The translator picks that address once at startup,
among the host prefixes (`/32`, `/128`) that `cap.route` announces and
`cap.table` assigns, keeping global unicast and private addresses only. A
deployment with its own address block writes the address out to pin the address
return traffic comes back to. Writing out the address is the only way to make a
reply land on a chosen node.

This node's own traffic from one of those mesh addresses, leaving by another
link, takes that address's class's translation through a local rule, as a leaf's
packet from the address would. The drop of a packet no flow is tracked for and
the refusal of DCCP and UDP-Lite meet only the packets the node forwards, so its
own packet no flow is tracked for leaves under the mesh address, and its own
DCCP or UDP-Lite packet leaves translated, from Linux 6.17 for DCCP and 7.1 for
UDP-Lite with its checksum stale, as
[protocol deviations](design/protocol-deviations.md#exit-translation) lists. Its
own traffic from any other address is the host's and meets no rule of the
exit's.

`return = true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow. An egress segment's
packet arrives on the tun, so the in rule never matches it.

With `return` set and the family's class from `0.0.0.0/0` or `::/0` `auto`,
`none` or absent, each advertised family needs exactly 1 candidate mesh address.
A family with none or with several is refused at startup. Where that class is
`auto` or absent, the error asks for the address as the `to` of the class from
`0.0.0.0/0` or `::/0` in `cap.egress translate`, and where it is `none`, which
such a `to` would undo, it asks for exactly 1 mesh address through `cap.route`
and `cap.table`. A pick among several would set the source of every flow out of
the LAN. A guess could change after an unrelated edit.

### `none`

A class of `none` leaves its sources' overlay addresses on their packets. That
works only where all 3 of these hold:

1. **The upstream accepts the source.** The exit's upstream has to accept the
   overlay source, which a provider filtering at its edge as BCP 38 asks drops
   otherwise. The exit announces a prefix covering the class upstream, or holds
   a block its provider routes to it.
2. **Replies come back into the mesh.** No state is kept, so a reply may enter
   through any exit announcing the prefix. Each such exit routes the overlay
   into the mesh, and no stateful filter on it drops a reply whose outbound half
   it never saw, as a host firewall with `ct state invalid drop` in its forward
   chain would. On Linux each such exit's own
   [entry chain](antispoof.md#the-entry-chain) also drops the reply unless that
   exit's own `cap.egress` holds a class of `none` taking the reply's
   destination. This node under [`return`](#the-return-path) drops such a reply
   from inside a prefix it advertises, as it drops any packet no flow is tracked
   for, and where conntrack opens a flow for the reply instead, it translates
   the reply's source, so the reply no longer matches the leaf's flow.
3. **The exposure is accepted.** The destination sees the leaf's own overlay
   address, which stays the same across sessions and exits and identifies the
   device. Anyone can open a connection to that address through an exit
   announcing it, which leaves the leaf's own firewall as its only filter.

Classes that leave under `none` every source of a family that a router forwards
a packet from are refused at load, however they split it: an exit that
translates nothing for anyone is an open relay for the overlay's sources onto
its upstream. A class that translates only sources no router forwards a packet
from is [refused](configuration-reference.md#capegress) as well, since the mesh
drops those sources before the exit and the class translates nothing.

A flow under `none` is bound to the source it carries in this node's chain, at
priority 99, ahead of every chain at `srcnat`, so a host's own masquerade there
leaves it alone whatever order the chains were made in. A chain below 99, or one
at 99 made after it, still translates it, as
[sharing a host](coexistence.md#the-packet-filter) describes.

On Linux, a connection an internet host opens to an address of a `none` class
enters the tun through the exit's [entry chain](antispoof.md#the-entry-chain),
whose `none4` and `none6` hold the class's addresses. A longer class inside it
that translates keeps its own addresses out, and so does every LAN another node
advertises inside the class, held or not, so such an exit carries no inbound
connection to another node's LAN. An exit that advertises a LAN itself, under a
`none` class covering it, carries that LAN's inbound connections.

### An address that routes back to this exit

A translated flow's state is held by this exit alone, so the replies to the
address a class names have to reach this exit and no other, and that address
must not be announced by several nodes. Either of these does:

- an address of this exit's uplink, which `auto` picks
- an address of space the mesh announces that the mesh routes to this exit
  alone, such as its own `/32` or `/128`: a reply enters the mesh through any
  node announcing the covering prefix and reaches this exit through it, where on
  Linux conntrack reverses the translation as it arrives on the tun, and on
  macOS, for an IPv6 address alone, the exit's socket takes it

The daemon cannot check the second. A family whose classes name an address is
[ready](#readiness) only while the host holds the address: on Linux on any link
or `lo`, and on macOS as [the exit on macOS](#the-exit-on-macos) gives.

### An exit with several addresses

`auto` takes the address the kernel's masquerade picks for each flow's route,
for
[IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_masquerade.c?id=940de590b839f71d6dc846160534bf202401b8b7#n54)
and for
[IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_masquerade.c?id=940de590b839f71d6dc846160534bf202401b8b7#n237).
Where the uplink holds several addresses of a family, one source's flows can so
leave under several of them at once, the "Arbitrary" pooling of RFC 4787, whose
REQ-2 recommends "Paired", as
[protocol deviations](design/protocol-deviations.md#exit-translation) lists. A
class naming an address pins it, and pairs every flow of its sources under it.

### IPv6

An exit leaves an IPv6 source untranslated where its upstream accepts it, under
a class of `none`, and translates it otherwise with the same masquerade and
source translation as IPv4, stateful and with port translation, which covers an
overlay numbered from unique local addresses. RFC 6296's stateless prefix
translation is not offered. It maps an inside prefix to an outside one of the
same length, which needs an exit holding a routed prefix as long as the
overlay's, and such an exit can number the overlay from that prefix under
`none`. nftables has no statement for it either.

## Timeouts

A TCP, UDP, ICMP or ICMPv6 flow the exit translates, UDP to port 53 aside, keeps
timeouts of the exit's own, one a class translates out of the mesh and one an in
rule translates into it under `return` alike, which its rules attach on the
flow's first packet, where the host's would forget a quiet flow sooner than the
NAT requirements allow:

| Flow                                                                                      | Kept idle                      |
| ----------------------------------------------------------------------------------------- | ------------------------------ |
| UDP, until it has an answer and a packet more than 2 seconds after its first              | 2 minutes                      |
| UDP, from then on                                                                         | 5 minutes                      |
| UDP to port 53                                                                            | the host's                     |
| TCP opening, from its first SYN                                                           | 4 minutes                      |
| TCP established                                                                           | 5 days                         |
| TCP with 1 side closed, data unacknowledged, a window closed or its retransmissions spent | 2 hours 4 minutes              |
| TCP closing, a FIN seen each way                                                          | 4 minutes                      |
| TCP in TIME_WAIT                                                                          | 2 minutes                      |
| TCP closed by a reset after a reply                                                       | 10 seconds                     |
| TCP reset before any reply                                                                | none, the session ends at once |
| an ICMP or ICMPv6 query                                                                   | 60 seconds                     |

A connection opening is kept 4 minutes from its first SYN. A retransmitted SYN
does not renew it, so an attempt whose SYNs go unanswered is forgotten 4 minutes
after the first.

A flow under `none`, and every connection of the host's own that the class of
its mesh address does not translate, keeps the host's timeouts. The values are
fixed, and [protocol deviations](design/protocol-deviations.md#exit-translation)
gives the requirement behind each. They hold for as long as the host's
connection tracking keeps the flow, and
[what it evicts from a full table](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1663)
is the kernel's.

Each family has a connection tracking timeout object for each protocol, named
with the family's digit: `udp4`, `tcp4` and `icmp4` in IPv4, and `udp6`, `tcp6`
and `icmp6` in IPv6. They are made once and never changed in place: a pass that
rewrites a chain leaves them. Where an object reads back with other values and
no rule or map element of another writer's uses it, the pass deletes the object
and makes it again, which leaves the flows that held it on the host's timeouts.
Where such a rule or element uses it,
[sharing a host](coexistence.md#a-writers-own-that-another-writer-holds) gives
what the pass does with it. A pass, and the write of `ranet3 down`, deletes
`translated-udp4`, `translated-tcp4`, `translated-icmp4`, `translated-udp6`,
`translated-tcp6` and `translated-icmpv66`, the objects an earlier version made,
in the transaction that writes the chains, so on a host that version left by a
kill or a crash the flows that held one take the host's timeouts after the first
pass. `ranet3 down` keeps the objects with the translation's chain, as
[down and up](#reloads-down-and-up) gives, and so does a shutdown that leaves
the stopped rules there. A shutdown that withdraws takes the objects under
either name with the chains, and the flows it leaves are the host's, under the
host's timeouts. Neither deletes an object that a rule or a map element of
another writer's attaches, as
[sharing a host](coexistence.md#the-nftables-table) gives. The withdrawal takes
the kernel's nat hooks with the family's last nat chain, since
[nf_nat_core.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_core.c?id=940de590b839f71d6dc846160534bf202401b8b7)
holds them only while a nat chain of the family uses them, so such a flow keeps
its translation where another nat chain of the family stays on the host, and
where another table's flowtable has offloaded it, since
[the flowtable translates a packet from its own entry](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_flow_table_ip.c?id=940de590b839f71d6dc846160534bf202401b8b7#n507)
whatever nat chain stays.

## Each source's share of the flows

The translator also writes a filter chain at the forward hook that holds each
mesh source address under a class that translates to a share of the flows
through this node. Past `cap.egress.flows_per_source` open flows in a family,
4096 when left out, such a source's next new flow is refused. The share is per
source address and family, every protocol's flows together, so a dual-stack leaf
holds one in each family, and each address of a prefix a subnet router routes
into the mesh holds its own.

- **What it judges.** The packet that creates a connection's entry, and nothing
  after it, so a flow admitted before its source reached the share carries on
  whatever the source opens since.
- **The answer.** A refused flow is answered from this node, IPv4 with
  Destination Unreachable code 1, Host Unreachable, and IPv6 with code 1,
  administratively prohibited, and its packet goes no further. What a leaf's TCP
  does with either is its stack's, Linux's here for
  [IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n611)
  and for
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/tcp_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n511).
  [The host's rate limit on ICMP errors](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n311)
  thins the answers to one source, and the refused count counts every refused
  packet. A DCCP or UDP-Lite flow under a class that translates meets
  [its refusal](#classes) ahead of the share, so it draws code 13 over IPv4,
  never the share's code 1.
- **What it leaves out.** A source under a class of `none` holds no share: the
  line ahead of the limit that accepts the sources of `untranslated4` or
  `untranslated6` takes its packets, as [the chains](#the-nftables-chains) lay
  out, so none of its flows is counted or refused, and the operator sizes the
  host's table for them, as
  [connection tracking makes them](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1897).
  A source no class takes leaves under `auto` and holds a share.
- **What it does not count.** A TCP connection in TIME_WAIT or closed. The share
  bounds a source's open flows, and its closed ones are bounded by their
  timeouts and by how fast it closes them. The userspace exit on macOS counts
  each [held slot](#host-ports) of a TCP connection whose relay has ended.
- **A full set admits.** Each family's set, `flows4` or `flows6`, keeps a count
  for each source holding flows, up to 65535 sources. Past that a new source is
  not counted and its flows are not limited, until every flow of some source has
  ended and
  [the kernel collects its count](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_set_hash.c?id=940de590b839f71d6dc846160534bf202401b8b7#n393).
- **What its count misses.** The kernel's count of a source's flows, and a pass
  that makes a set of flows again, can leave a flow open and uncounted, past the
  share, as the row for the flows the kernel exit's count misses in
  [limits](design/limits.md#dataplane-and-sockets) gives. Behind
  [a rule that holds forwarded packets](coexistence.md#a-rule-that-holds-forwarded-packets)
  a source's flows are not bounded by the share.
- **What it bounds.** The open flows a source holds through this node. A mesh
  source's flows to this node itself, to its mesh or uplink address, take
  entries in the same table and are not counted, as
  [limits](design/limits.md#dataplane-and-sockets) lists.
- **The host's table.** The shares come out of the host's connection tracking
  table, whose size `net.netfilter.nf_conntrack_max` sets and ranet3 never
  writes,
  [its default the kernel's](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n2625).
  Size the shares against it: the shares of the sources an exit serves at once,
  with the flows of its sources under `none` and the host's own connections,
  held under the table's maximum. An exit serving a leaf that translates a LAN
  behind its one mesh address, which draws on one share for every host behind
  it, takes a larger share.

## The return path

Conntrack reverses the translation before the reply is routed. The reply is then
addressed to a mesh node, and the forwarding lookup has to find a route to it
into the tun, which with `cap.table` is in the reconciler's own table. The rules
the reconciler derives find it there: a reply to an address inside `overlay`
ends as rows L3 to L5 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give, and a reply
to another address as rows L6 to L12 give, after main's route longer than /0. An
exit therefore writes the overlay its members' addresses lie in:

```toml
overlay = ["203.0.113.0/24", "3fff:a::/36"]

[cap.table]
id = 200
```

Without it, a reply to a member whose address a route of main longer than /0
covers, a LAN holding the same addresses among them, leaves by that route, row
L6. Another program's rule ahead takes a reply either way, as
[sharing a host](coexistence.md#another-programs-rules) describes. The outbound
half works and the translation counter moves, but no reply reaches the mesh, so
the exit looks like one that answers nothing.

An exit or subnet router set up this way can carry transit. With `cap.transit`
on, a packet another node sends through it for a prefix a third node announces,
such as the subnet behind another subnet router, goes on through the mesh by the
mesh's own table, as [routing](routing.md#transit) describes. It never reaches
the tun, so the reconciler's rules and the host's routes out of the uplink never
see it.

## An exit's own traffic

An exit's reconciler installs no route that
[counts as a default](routing.md#routes-that-count-as-a-default), whatever it
learns and whether a session is live or not, so its own traffic never follows
another exit's default out of the reconciler's table. A node is an exit while
`cap.egress` advertises, or `cap.route` announces, a prefix that counts, or
while it holds an egress segment. Another exit's default in its table would
carry the exit's own traffic from an address of its own into the tun, row L11 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux), and out of that
exit. A socket bound to the tun still hands its IPv4 packets to the mesh, row
B3, which forwards them by its own table, by another exit's default where it
holds one, as an exit by an egress segment alone can. Over IPv6 such a socket
reaches the mesh only for a destination a route out of the tun covers, and is
refused otherwise, row B4. The head of that account says what another program's
rule or another writer's route in the table does. The mesh still forwards other
nodes' packets by every route it selects. On Linux a reload that starts
announcing a default makes the node an exit from the next pass. Every other
platform refuses that reload, as
[the configuration reference](configuration-reference.md#caproute) gives.

[`cap.exit`](configuration-reference.md#capexit) asks the opposite, the host's
own traffic out through another exit, so an exit refuses it by the reason it is
one, at load and on every reload, with the message
[the configuration reference](configuration-reference.md#capexit) quotes. The
loader, a reload and the reconciler read one rule for what makes a node an exit,
so a file that loads never runs the mode on one.

A host using an exit can ask with `cap.exit.fallback = "none"` for the kill
switch, which holds while no exit is live and the switch reads back as written.
[The kill switch](routing.md#the-kill-switch-on-linux) lists the lines that let
the host's traffic leave by its own uplink, and gives the rules and the chains,
the switch's reach, what each stop leaves of it, and what counts as the LAN, and
[the kill switch on macOS](routing.md#the-kill-switch-on-macos) gives the same
for a Mac's rejects. An exit installs no default for its own traffic and refuses
`cap.exit`, so no exit's egress meets the switch's chains.

Application DNS is not yet kept on the exit, on Linux or macOS, as
[limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) gives.

## What an exit carries out

A packet a session delivers for a destination this node holds through a route
that [counts as a default](routing.md#routes-that-count-as-a-default), such as
the `0.0.0.0/0` and `::/0` it advertises, is egress. The
[forwarding decision](routing.md#transit) hands it to the exit only where 3
checks pass. On Linux the exit writes it into the tun, where the host translates
it and forwards it out of its uplink, and on macOS it carries it as
[the exit on macOS](#the-exit-on-macos) gives. The checks:

- A destination inside `overlay` belongs to the mesh. One that no node announces
  is answered as a destination no route holds, IPv6 code 0 and IPv4 Host
  Unreachable, and never sent out of the uplink. An exit without `overlay`
  passes every packet through this check, and it sends an address no node
  announces out of the uplink as any other destination outside the mesh.
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

A packet through a prefix counting as a default that `cap.route` announces meets
the first 2 checks, and past them goes to the tun with no readiness to wait on,
since no translation of this node stands behind it. An
[egress segment](#egress-segments)'s inner packet to a destination other than a
multicast destination or the limited broadcast, but a Not-ECT one that arrived
under an outer CE, meets the second check after its `allow` list, and is then
refused where its destination lies inside `overlay`, announced or not, or the
mesh routes it, as [segment routing](segment-routing.md#egress-segments)
describes.

## Refusing to advertise

**An exit that cannot translate refuses to advertise.** Babel carries no
capability signal. A node that advertises a prefix promises to carry it, and the
advertisement is all a peer learns. An exit whose rule will not install would
attract traffic and drop it without telling the sender.

The capability publishes the advertisement per family on every pass. A prefix is
announced only while its family is ready, as [readiness](#readiness) gives for
each platform. A pass reads the translator's chains, the family's sets and
timeout objects, and the elements of the family's set of untranslated sources,
`untranslated4` or `untranslated6`. It also reads 3 kinds of object an earlier
translator wrote in the table `inet ranet3`: the chain `forward4`, every chain
whose name runs past `none_`, and the 6 timeout objects [timeouts](#timeouts)
names. `forward4` held IPv4's lines at the forward hook, and each `none_` chain
the lines of one class of `none`. A pass deletes each such object it finds in
the transaction that writes the chains. One that a rule or a map element of
another writer's holds stays, and keeps both families not ready, as
[sharing a host](coexistence.md#the-nftables-table) gives.
[The packet filter](coexistence.md#the-packet-filter) section of sharing a host
gives what the translator does with a chain of the table under any other name,
and a nat chain at the source translation hook at priority 99 or below is named
as a [conflict](#watching-it). Each pass first rewrites a chain that reads back
otherwise, such as one missing a rule, holding another writer's, a rule edited
under the comment it was written with or in a dormant table, and fills again a
set of untranslated sources whose elements read back otherwise. nf_tables clears
no table flag in place but dormant. When a chain, set or object of the
translator's reads back otherwise than written and the difference is one
nf_tables will not change in place, the pass deletes it and makes it again in
the same transaction, except where another writer holds it, as
[sharing a host](coexistence.md#a-writers-own-that-another-writer-holds) gives.
The pass leaves every chain, set and object of another writer's as it is beyond
[what goes of another writer's](coexistence.md#what-goes-of-another-writers).
Where nf_tables refuses that transaction with `file exists`, the pass sends it
once more as [sharing a host](coexistence.md#the-nftables-table) gives. Another
table flag holds both families not ready, with the reason
[sharing a host](coexistence.md#the-nftables-table) gives. When the chains still
do not read back as written, the host stops forwarding the family or a lookup
fails, that pass retracts the prefix. A pass runs at least every `sweep` (30
seconds by default).

On Linux the node reads forwarding from `/proc/sys/net/ipv4/ip_forward` and
`/proc/sys/net/ipv6/conf/all/forwarding`. Any value other than `0` counts as on.
The exit counts a file the node cannot read as on too, and `status` shows it as
`unknown`. The kernel exit acts on them by withholding its advertisement,
because no other node can tell whether it forwards. Transit between sessions
needs neither setting, since the mesh forwards it itself.

`status` names the prefixes it announces and the ones it withholds. The scrape
carries the advertised and the announced counts as `ranet3_egress_prefixes`.

## Readiness

On Linux a family is ready while the translator's chains read back exactly as
the node wrote them, `forward6` for IPv6 alone and every other one for both
families, since `forward` holds IPv6's goto ahead of IPv4's lines, with every
rule in order, each by its comment and by what it does, and no other writer's
among them, each at its hook, priority and policy, the family's sets, the
elements of its set of untranslated sources among them, and timeout objects read
back as written, in a table with no flags, the host forwards the family, the
host holds every address its classes name, and, where its lookups run, the
kernel routes a translated packet of the family and its reply the way the
translation needs. Every node with `cap.egress` judges each family it translates
on every pass, and both modes wait for the judgment: a packet through an
advertised prefix waits for the families ready that the node announces, and an
egress segment's packet for the families ready, as
[what an exit carries out](#what-an-exit-carries-out) and
[egress segments](#egress-segments) describe. A family this node does not
translate is not ready. On Linux `ranet3 debug egress` shows each family's
judgment condition by condition with the lookups the last pass read, and none
from a [stop](#watching-it) to the next pass, as
[debugging](development/debug.md) describes.

On macOS a family is ready while the exit's stack runs, a link outside the mesh
reaches each prefix the family advertises, or its default where it advertises
none, at the prefix's read address below, and the host holds every address its
classes name, as [the exit on macOS](#the-exit-on-macos) gives. The lookups
below are the kernel exit's.

The kernel's routes are read from its own route lookups, all of a pass in 1
batch through 1 netlink socket:

- **The address lookup**, for each address the family's classes name: a lookup
  of the address from no source and no device has to answer a route of type
  `local`, the route the kernel keeps for each address it holds, on any link or
  `lo` and whatever that link's state. A tentative IPv6 address answers another
  route until duplicate address detection has ended. These run whether or not
  the mesh routes a member of the family.
- **The forward lookup**, for each prefix the family advertises, or for the
  family's default (`0.0.0.0/0` or `::/0`) where it advertises none beside an
  egress segment: a packet arriving on the tun from a member's address to the
  prefix's read address has to leave by a device other than the tun.
- **The reply lookup**, 1 a family: the translated reply, arriving on the device
  the family's first forward lookup left by, from that read address back to the
  member's address, has to leave by the tun. It catches an exit whose replies
  would leave by its uplink, such as one where another program's rule ahead, as
  [sharing a host](coexistence.md#another-programs-rules) describes, takes the
  reply out of the uplink, where that rule selects the lookup too: the lookup
  carries no mark and the read address as its source. With strict reverse path
  filtering on the tun, or loose filtering on a tun with no IPv4 address, such
  an exit fails its IPv4 forward lookup first, since the kernel checks the
  forwarded packet's source against the same route. An exit whose `overlay`
  leaves its members out has no member to read from, so both its lookups are
  skipped, as the skip below says, and its replies leave as
  [the return path](#the-return-path) describes.

An address lookup holds its family not ready when it fails or answers a route of
any other type than `local`. A forward or reply lookup holds its family not
ready when it fails, finds a route of a type other than `unicast`, finds no live
next hop, or leaves by the wrong device, a forward lookup with any live hop on
the tun and a reply lookup with any live hop off it. A hop the kernel marks dead
or link-down is not live, and a route naming a nexthop object that holds no hop
counts as a route with no live next hop.

**The source** of the forward and reply lookups is a member's address: the read
address of a prefix the mesh routes by the tun to another node, inside
`overlay`, overlapping none of this node's own prefixes, taking the lowest base
address first and then the longest prefix. A correctly configured exit routes
its members' addresses into the tun, so a lookup from one reads the path a real
reply takes. Where `cap.table` is written, rows L4 and L5 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give the end of a
lookup to an overlay address no route of the mesh covers.

**The read address** of a prefix is its own address for a host route, and
otherwise the first of these that the mesh forwards a unicast packet to, one in
no block the [`overlay`](configuration-reference.md#top-level) entry lists: its
middle address, the base with the bit after the length set, then its base plus
1, then its last address less 1. The middle alone would not do, since
`192.0.0.0/2`'s is `224.0.0.0`, a group. An `advertise` prefix holding no such
address is [refused at load](configuration-reference.md#capegress).

**The skip.** The forward and reply lookups of a family are skipped, and the
family judged by its chains, its forwarding and its classes' addresses alone,
where the mesh routes no member of it, as before any member is learned, in a
mesh of 1, or with no `overlay` prefix of the family. `status` and the
`egress.ready` event say what was skipped, such as
`lookup skipped, the mesh routes no other node's ipv6 prefix inside overlay`.

**The reason** a family is not ready names the lookup, the prefix, the read
address, the source and the device the packet arrived on, and what the kernel
answered, such as
`the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3 failed: no route to host, with net.ipv4.conf.ranet3.forwarding at 0`
or
`the reply lookup of 3fff:20::1 for 2001:db8::/32 from 2001:db8:8000:: arriving on eth0 leaves by eth0 rather than ranet3`,
and for an address lookup the address and the answer, such as
`the lookup of 198.51.100.7, an address cap.egress translate names, found a route of type unicast, so this host does not hold it`.
A failed IPv4 lookup names the setting of the device it arrived on that refuses
it, the tun's for a forward lookup and the uplink's for a reply: the device's
own `forwarding` at 0, or reverse path filtering, the larger of
`net.ipv4.conf.all.rp_filter` and the device's own. The kernel answers these
with errnos it answers for other causes too, `EHOSTUNREACH` for forwarding off
and `EXDEV`, or `EINVAL` from Linux 6.13 on, for reverse path filtering, so the
reason reads the settings rather than the errno. The daemon reads them and
changes none. An IPv6 lookup with forwarding off answers its route, and the
host's forwarding check stands for it.

Another writer deleting the table `inet ranet3` or setting a flag on it, or
adding, changing or deleting one of the translator's chains, rules, sets or set
elements in it, such as a `nftables.service` reload that flushes the ruleset, a
rule put in one of the translator's chains or a table set dormant, holds both
families not ready until the pass it wakes restores them, rather than until the
next sweep. A chain another writer adds to the table wakes no pass unless it
carries one of the translator's names or one an earlier version wrote, as
[refusing to advertise](#refusing-to-advertise) names. A chain under any other
name holds a family not ready only where a rule of it goes to or uses a chain,
set or object of the translator's that an earlier version wrote, or that reads
back otherwise than written in a difference nf_tables will not change in place,
as [sharing a host](coexistence.md#the-packet-filter) gives. The translator's
own writes wake no pass of its own, and the antispoof filter's and the kill
switch's writes of their chains, rules and sets in the same table wake none of
the translator's either. Lost notifications wake passes as
[sharing a host](coexistence.md#the-nftables-table) gives, and those passes
leave readiness as it was, since each reads the rules back. A pass that reads
another writer's change back and cannot undo it holds the family the change is
in not ready, IPv6 alone for a change to `forward6`, and both families for a
change to another chain, `forward` among them, since it holds IPv6's goto ahead
of IPv4's lines, with a reason that names what of the translator's reads back
otherwise and what holds it where anything does, and withholds its prefixes
until a later pass does.

## The exit on macOS

A macOS build carries the userspace exit. It installs no rule and reads no
forwarding setting. What the mesh hands it, through an advertised prefix or an
egress segment, leaves the host from the host's own sockets. TCP ends in a
TCP/IP stack of the exit's own, which holds no address and answers nothing for
itself. UDP and echo reach their mappings, straight from the mesh where a packet
comes whole with no IPv6 extension header, and otherwise through the stack,
which reassembles or parses it first:

- **TCP** ends in that stack. The exit dials the server from a socket of the
  host's, from an address and port no connection from another leaf address and
  port shares, as
  [the userspace exit](design/protocol-deviations.md#the-userspace-exit) gives,
  and copies between the two. A half close passes as one and a reset as a reset.
- **UDP** takes 1 mapping per leaf address and port and address it leaves from,
  with a socket of the host's toward each destination, and filters, hairpins and
  ends it as
  [the userspace exit](design/protocol-deviations.md#the-userspace-exit) gives.
- **Echo** leaves through an ICMP socket of each family, with the leaf's
  identifier where no other mapping holds it. The exit takes a reply on an
  identifier a mapping holds from one of the 16 destinations that mapping's
  requests went toward last, a refused request's among them, and counts the
  rest: a request toward one of the 16 makes it the latest, and one toward a
  seventeenth drops the one its requests went toward longest ago. A mapping ends
  at the first sweep, every 5 seconds, that finds no send of it in flight and 60
  seconds past the last request that left on it or reply it took, so one that
  carried neither ends at the first sweep after its sends end. Replies from
  those destinations keep a mapping and its flow, with no request from the leaf,
  for as long as they come 60 seconds apart or closer. The exit's stop, at the
  times [watching it](#watching-it) gives, ends every mapping at once, and a
  request whose mapping it closed meanwhile is refused and counted as
  `withdrawn`. A request the exit or the host refuses to send once its mapping
  is open is dropped and counted as `echo unsent`: the exit refuses one toward a
  destination its underlay names no link for, and the host refuses one on the
  send. The exit's refusal, and the host's with `ENETUNREACH` or `EHOSTUNREACH`,
  which say no route or no way leads to the destination's host, are answered
  with network unreachable over IPv4 and no route over IPv6, within the node's
  ICMP limits, since macOS's errnos do not tell those causes apart. Scoped to
  lo0 toward a destination lo0 holds no route for, macOS was seen to refuse the
  IPv6 send with `EHOSTUNREACH` and to send the IPv4 one, whose leaf then hears
  nothing. Over IPv6 XNU also gives `EHOSTUNREACH` for a host route flagged
  reject or blackhole and for a socket restricted from sending on the link, and
  `ENETUNREACH` for such a network route
  ([`in6_src.c`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet6/in6_src.c)),
  each answered alike, a departure
  [protocol deviations](design/protocol-deviations.md) declares. What it gives a
  send its pf blocks, or one toward a neighbor that never answers, is not known
  here. Any other refusal is answered nothing, a departure the same page
  declares.
- **Errors.** A destination unreachable a server or a router raises about a dial
  that fails reaches the leaf from the address that raised it where the exit
  catches it: on Linux from the dial's error queue, and on macOS from the exit's
  ICMP socket of the family, where that socket is open and hands the error over
  within a short wait past the dial's failure. A dial whose error the exit does
  not catch has its leaf reset, as for a refused connection. The errors about a
  mapping's datagram that
  [the userspace exit](design/protocol-deviations.md#the-userspace-exit) relays
  reach the leaf from the address that raised them too, quoting the fields of
  the datagram the exit kept. A leaf's own error about a reply leaves from a
  mapping of the leaf's port that sent to the reply's server, the one that
  section says the exit picks. Toward a server the leaf's error goes through a
  raw socket, which only root opens, and toward a leaf whose datagram the exit
  hairpinned it goes back to that leaf with no raw socket. Where the exit finds
  no mapping, or an error toward a server finds no raw socket or fails to send,
  the error is dropped and counted. Any other error a leaf sends reaches the
  exit's stack only where the exit reads its quote down to a TCP header, or is
  dropped and counted as `leaf error quote`. An error in fragments is counted as
  `leaf error fragment`.
  - A Packet Too Big below 1280 bytes or a Fragmentation Needed below 552 is
    counted as `leaf error mtu`. One at or above that floor reaches the stack
    from any session, since one from a waypoint or a later hop comes from an
    address the mesh may reach by another first hop than the leaf. So a leaf
    behind another session can lower a connection's segment size to the floor
    with a forged one, knowing only the connection's addresses and ports, since
    gVisor at the pin checks neither the quoted sequence number (RFC 5927
    section 4.1) nor the connection's progress (section 7.2). That slows the
    connection and neither stalls nor ends it, and its smaller segments, more of
    them for the same bytes, pass through the pump and link queue every leaf
    shares.
  - Every other error reaches the stack only where the segment's destination
    sits behind the same session as the error's source, or is dropped and
    counted as `leaf error elsewhere`, so a leaf cannot end the connection of a
    leaf behind another session. Each address is judged by the session the mesh
    sends to it by, which for an address a steer entry covers is its first
    segment's, and none for an address the tun holds where either address of the
    pair is one [no router forwards](routing.md#transit). An error from a node
    the mesh reaches by another first hop than the leaf is dropped too. Over
    IPv4, the errors a router raises about an open connection, net or host
    unreachable and time exceeded, are soft errors on which TCP does not abort
    it (RFC 1122 section 4.2.3.9). The hard ones, protocol and port unreachable,
    pass from the leaf's own address or from a router behind the leaf's session.
    A filtering router's own port unreachable that the mesh reaches by another
    first hop is dropped like any error from another session.
  - Leaves behind one session are not told apart: they share that session's
    trust, as hosts on one link do, and the error's source is not held to the
    quoted destination, since a router on the leaf's side raises errors from its
    own address.

  An error about a TCP connection that is open reaches the host's TCP and never
  the leaf. Time Exceeded and Packet Too Big are the mesh's own answers, as for
  the kernel exit.

Toward a leaf the exit's stack sends only TCP. An ICMP message it would send as
the destination the leaf named, such as a Parameter Problem for IPv4 options or
a Time Exceeded for a reassembly that timed out, is dropped and counted as
`stack icmp`, and any other packet but TCP as `stack other`.

Every socket the exit sends from is scoped to the link the host's underlay names
for its destination, so none leaves inside the mesh. On macOS a socket scoped to
one link still read a datagram that arrived on `lo0`, so the exit holds no
socket that only receives to a link: a UDP mapping's on its port and each ICMP
socket before its first send. Under `auto` a TCP connection leaves from the
address the route to its server picks, as on Linux, and a UDP datagram from the
address the route to its destination picked as that destination opened. Under an
address class a flow leaves from that address, which the host has to hold: an
IPv6 address on any link or `lo0`, and an IPv4 address on the link itself. That
rests on a measurement alone: with its sockets scoped to a utun, an exit had
every IPv4 flow from an address on `lo0` refused, where the IPv6 ones carried. A
socket scoped to a link of another kind was not measured. XNU's receive check is
not what refused them: by default it drops a packet that arrived on another
interface only where its destination address belongs to a utun or ipsec
interface
([ip_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/ip_input.c#L1377-L1387)),
and `lo0` is neither. A family whose IPv4 class address that link does not hold
is not ready.

The exit refuses at startup what it cannot carry:

- a class of `none`, with
  `egress: cap.egress translates 3fff:a::/32 with none, and the exit this build carries opens its own sockets, which send from this host's addresses and never from a leaf's`
- `return`, with
  `egress: cap.egress return is set, and the exit this build carries ends each connection a leaf opens and opens its own toward the server, so no connection comes in from an advertised prefix for it to translate`
- an `advertise` prefix that counts as no default, with
  `egress: cap.egress advertises 198.51.100.0/24, a subnet, and this build's exit carries only defaults, the routes that count as one (outside overlay and shorter than /8 or /16), and egress segments: advertise those alone here, and route the subnet from a node whose exit forwards it`

Per flow, it answers another protocol than TCP, UDP and ICMP with code 13 over
IPv4 and code 1 over IPv6, on every fragment that names it, and a destination
the host holds the same way, but a UDP datagram it hairpins. A flow past its
source's share or past the exit's totals is answered with Host Unreachable over
IPv4 and administratively prohibited over IPv6, counted, and recorded in an
`egress.refused` event at most once every 30 seconds, as
[watching it](#watching-it) gives. No open flow is closed to make room for it.

A family is ready as [readiness](#readiness) gives for macOS. The bytes and the
flows the exit holds are bounded by the host's memory and descriptors, as
[the userspace exit's limits](design/limits.md#the-userspace-exit) give, and
`flows_per_source` is a share inside those totals. What it does not carry is
listed in [gaps on macOS](platforms.md#gaps-on-macos), with each deviation in
[exit translation](design/protocol-deviations.md#exit-translation).

### Host ports

On macOS a port in TIME_WAIT is refused to every bind of port 0 and every
connect from an unbound socket on the host, the host's own connections and the
exit's dials among them. When a leaf closes a TCP connection first, the exit's
socket toward the server closes first too and stays in TIME_WAIT, so a source
closing connections fast could hold every port of the host's automatic range.
The exit on macOS keeps a slot for each such socket. The terms:

- A **slot** is a place in the source's share, in `Flows` and in `HostPorts`,
  which a connection takes at its SYN and keeps past its relay's end while its
  host socket may pin the port.
- A **held slot** is the slot of a TCP connection whose relay has ended and
  whose host socket did not read closed at that end. It stays while the exit
  holds the socket, until a read finds the socket closed or the margin after the
  exit closes it with a linger of 0 has passed, as the table and the slot's end
  below give. A connection still closing toward the leaf is open and holds its
  slot at once, and counts as one flow.
- The **MSL** is the maximum segment lifetime the host reads from
  `net.inet.tcp.msl`, and a TIME_WAIT lasts twice it, 30 seconds at its default
  of 15.
- A **sweep** is the exit's pass every 5 seconds, which ends idle mappings and
  acts on each slot whose state or time has come.
- The **margin** is the 2 seconds a slot is kept past each close with a linger
  of 0 that the relay's end or a sweep makes.

What the exit does:

- **When the relay ends** the exit reads the host socket's state, and each sweep
  reads every socket it watches again before acting on its time:

  | State read                      | What the exit does                | When                                                                |
  | ------------------------------- | --------------------------------- | ------------------------------------------------------------------- |
  | closed                          | closes it and gives its slot back | at that read, with no margin                                        |
  | TIME_WAIT                       | closes it with a linger of 0      | at the first sweep twice the MSL past the first read of TIME_WAIT   |
  | CLOSING or LAST_ACK             | keeps it watched                  | while the exit runs, until a read finds the host's FIN acknowledged |
  | FIN_WAIT_1 or FIN_WAIT_2        | closes it with a linger of 0      | at the first sweep twice the MSL past the relay's end               |
  | any other, or a read that fails | closes it with a linger of 0      | at the relay's end at once, and at a sweep only past its time       |

  The close with a linger of 0 sends the server a reset wherever macOS still
  holds the TIME_WAIT, which it does past twice the MSL until its PCB collector
  runs, as
  [the userspace exit's deviations](design/protocol-deviations.md#the-userspace-exit)
  declare. The exit closes the socket itself rather than wait on that collector,
  whose bound the slot's end below gives. A server that has closed discards that
  reset. Each sweep also reads the range and the MSL again, and a change applies
  from it.
- **No restart.** On a plain TCP socket under no content filter, macOS sets the
  2 MSL timer again on no segment. Every segment in TIME_WAIT fails the
  condition of the step that takes in data
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L6005-L6009))
  and so has its FIN cleared
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L6157-L6173))
  before the FIN's restart. The ACK's restart needs an acknowledgment of new
  data
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L5617-L5619)).
  An acknowledgment of nothing new leaves before it, whether it is one far below
  what the server had acknowledged
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L5100-L5109))
  or a duplicate
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L5173-L5499)).
  A socket enters TIME_WAIT only once the host's FIN is acknowledged, so an
  acknowledgment of new data lies past what the host sent and is dropped
  ([tcp_input.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_input.c#L5089-L5098)).
  A server off the Mac that retransmitted its FIN eight times over 27 seconds
  had each acknowledged and the TIME_WAIT gone 45 seconds after the close, at
  the default MSL.
- **A reset.** A flow the exit resets, at its stop or a relay's error, closes
  its host socket with a linger of 0 in any state before TIME_WAIT, CLOSING and
  LAST_ACK among them, as a reset of the leaf's connection asks, and keeps no
  slot. A socket it reads in TIME_WAIT, where both FINs have passed and a reset
  has nothing left to tell the server, it leaves to the table's TIME_WAIT row
  above.
- **A failed leaf endpoint.** Where the leaf's endpoint fails after the dial,
  the host's socket half closes and is watched, with twice the MSL to reach
  TIME_WAIT or closed. Until its hold ends it still acknowledges and drops what
  the server sends.
- **The linger.** macOS refuses every socket option on a socket shut both ways,
  as one in TIME_WAIT is
  ([uipc_socket.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/uipc_socket.c#L4776-L4782)),
  so the exit sets `SO_NP_EXTENSIONS` with `SONPX_SETOPTSHUT` on each dial's
  socket before its connect. Where macOS still refuses the linger, the socket
  and its slot stay as they were and the next sweep tries again.
- **The slot's end.** After a close with a linger of 0 the host's own binds and
  connects take the port at once, but the port stays reserved until XNU's PCB
  collector disposes of the socket, a reservation that refuses the port to the
  host's Skywalk flows alone
  ([netns.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/skywalk/namespace/netns.c#L696-L703),
  [in_pcb.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L2015-L2020)).
  So the slot comes back at the first sweep past the margin from that close. The
  margin is two of the collector's fast passes. On a Mac in use the reservation
  was gone within 1 second of the close, as measured, and that is no ceiling.
  The collector skips a socket still in use or busy until a later pass
  ([tcp_timer.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_timer.c#L664-L676)),
  which XNU's code bounds by nothing. A pass it gives up
  ([tcp_timer.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/tcp_timer.c#L807-L819))
  re-arms lazily
  ([in_pcb.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L447-L455)),
  due 1 second on with 10 seconds of leeway
  ([in_pcb.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L162),
  [in_pcb.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L472-L494)),
  so on an idle host the next pass comes up to about 11 seconds on. IPv6 was not
  measured. At macOS's default MSL a leaf-first close keeps its slot 35 to 40
  seconds past its relay's end, as does a reset that reads TIME_WAIT, and a
  server-first close whose last acknowledgment has not arrived when the relay
  ends keeps it until the next sweep.
- **The bound.** `HostPorts` is the least of half the ports from
  `net.inet.ip.portrange.first` to `net.inet.ip.portrange.last` and half of
  `Flows`. The exit counts as `host ports` each TCP connection from its SYN
  until its relay ends, its dial included, and each held slot past that, so a
  connection still closing toward the leaf takes one where it holds a slot and
  none where it does not. At a relay's end the hold is counted before the
  connection's own count is given back, so for that moment the connection takes
  two and the count stands one above. A new TCP connection is refused while they
  reach `HostPorts`, so a range of 1 port refuses every one. Since the dials and
  the relayed connections count, where `Flows` is under twice `Connections`
  fewer TCP connections are admitted than `Connections`. Leaf-first closes fill
  `HostPorts` at `HostPorts` / 40 a second across sources, about 205 a second at
  its most of 8192.
- **The share.** A slot held counts in its source's share. A source at its share
  that holds more slots than open flows is refused as `share held`, else as
  `share`, both counted in `ranet3_egress_refused_total`. At the default share
  of 4096 a source closing first is refused past about 102 such closes a second,
  less what it holds open.
- **The stop.** The exit's stop closes every socket it holds with a linger of 0,
  one in CLOSING or LAST_ACK as one in TIME_WAIT however young, since a stopped
  exit counts no slot, and a socket left to run would pin its port uncounted
  beside the next process's `HostPorts`, for as long as its server keeps it. The
  stop has reset every open flow before. What it costs is the last
  unacknowledged bytes of a connection that was closing at the stop. Every slot
  is given back. A socket whose linger macOS refuses then is closed plainly and
  left to run uncounted, and the log says how many.

What it leaves open:

- No cap holds one source's slots below its share. A source filling `HostPorts`,
  a dual-stack leaf from its two shares, refuses every source's new TCP
  connection, at the rate above. While the exit runs, a socket held in CLOSING
  or LAST_ACK lasts until the server acknowledges or the host stops
  retransmitting, or for as long as a server keeps a zero window and answers its
  probes, each counted in its source's share.
- A TIME_WAIT that macOS's own collector or the server's reopening SYN ended
  before the exit read it, and one that began between a reset's read of the
  state and its close, are released with no margin. Its port may then stay
  reserved against the host's Skywalk flows, uncounted, until XNU's collector
  runs, as the slot's end gives.
- After a crash, which closes no socket with a linger of 0, the old sockets run
  their TIME_WAIT uncounted beside the new process's `HostPorts`. After a stop,
  a port may stay reserved against the host's Skywalk flows up to the margin
  into the next process.
- A leaf chooses its own port, and the exit keeps it where the host binds it, so
  a socket held on a port outside the automatic range refuses that port to a
  host server that binds it without `SO_REUSEADDR` or `SO_REUSEPORT`, within the
  source's share.
- The userspace exit on Linux holds nothing and sets no bound on the host ports
  the host sockets of its connections pin past their relay's end. That is a
  limit of the exit, not of Linux, whose hold would be built apart. The
  userspace exit runs on Linux in tests alone today.

## The nftables chains

The translator writes its chains in the nftables table `inet ranet3`, which
[the antispoof filter](antispoof.md#where-it-runs) and
[the kill switch](routing.md#the-kill-switch-on-linux) write theirs in, for each
family it translates: each advertised family, and both beside an egress segment,
whatever `advertise` holds, since an egress segment carries both families. It
writes 2 base chains, which see both families, the regular chain `forward6`
whether it translates IPv6 or not, and for each family 2 sets and 3 timeout
objects. nf_tables
[hooks an inet chain at the IPv4 and IPv6 hooks alone](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n554),
so `forward` meets those two families and no other. Its first line,
`meta nfproto ipv6 goto forward6`, sends IPv6's packets on to `forward6`, which
holds IPv6's lines, and IPv4's lines follow that line in `forward` itself, so a
packet meets none of the other family's lines at the forward hook and an IPv4
packet takes no goto to reach its own. A family's line at the forward hook tests
its family only just before it keys a set by the packet's source, which only a
packet that passes every other compare of the line reaches. Each rule of
`postrouting`, which a flow's first packet of either family meets, tests its
family first:

| Property | Translation        | Forward                        | IPv6                                       |
| -------- | ------------------ | ------------------------------ | ------------------------------------------ |
| Name     | `postrouting`      | `forward`                      | `forward6`                                 |
| Type     | `nat`              | `filter`                       | no type                                    |
| Hook     | `postrouting`      | `forward`                      | no hook, entered by `forward`'s first line |
| Priority | 99, below `srcnat` | 0 (`filter`)                   | no priority                                |
| Policy   | `accept`           | `accept`                       | no policy, `forward`'s at its end          |
| Lines    | both families'     | the goto to `forward6`, IPv4's | IPv6's                                     |

Each family's sets:

| Property | Flows                                            | Untranslated sources                                |
| -------- | ------------------------------------------------ | --------------------------------------------------- |
| Name     | `flows4`, `flows6`                               | `untranslated4`, `untranslated6`                    |
| Key      | the source address                               | the source address                                  |
| Flags    | `dynamic`                                        | `interval`                                          |
| Elements | each source's count, which the limit's rule adds | the sources whose longest covering class is `none`  |
| Read by  | the limit's rule                                 | the line that accepts them, where a class is `none` |

The translation chain holds each class's rules together, the longest `from`
first, since the first rule that translates a connection ends the chain: for a
class that translates, a rule for each protocol attaching its timeouts, then its
translation, and for a class of `none` its binding alone. Where no class covers
every source, the rules of `auto` for the rest follow. The in rules come next,
for each advertised prefix a rule for each protocol attaching its timeouts, then
its translation, and then the local rules of this node's mesh addresses. Each
translation out of the mesh and each local one sets bit 127 of the flow's
connection label after its counter, `ct label set 127`, which
[down and up](#reloads-down-and-up) reads. A family's lines at the forward hook,
IPv4's past `forward`'s first line and IPv6's in `forward6`, hold in IPv4 the 4
ICMP drops first, which take Source Quench and then Information Request and
Reply, out of the mesh and then into it, from any source. Where a class of the
family is `none`, 1 line follows that accepts a packet out of the mesh from a
source the family's set of untranslated sources holds, those whose longest
covering class is `none`, each range of adjacent sources as 1 element. A family
with no class of `none` has no such line, and no line reads its set. The screens
follow, once, for every source: a rule that drops a packet no flow is tracked
for, the refusals of DCCP and of UDP-Lite, which take a packet in its flow's
original direction, and out of the mesh the limit's rule, then under `return`
those for each advertised prefix of the family into the mesh, with no limit. A
packet out of the mesh whose longest covering class is `none` meets that line
and no screen, so no limit, as
[each source's share](#each-sources-share-of-the-flows) describes, and any other
meets the 4 screens once, whatever classes cover it.

The set the limit counts each source's flows in, `flows4` or `flows6`, carries
the share as its comment, `limit 4096`. Each count keeps the share in force when
it began. A set read back under another share, as an instance that ran under
that share and stopped without withdrawing leaves it, makes the pass delete that
set and make it again in the transaction that rewrites the chains, except where
another writer holds the set, as
[sharing a host](coexistence.md#a-writers-own-that-another-writer-holds) gives.
The share is one setting of both families, so where that instance translated
both, the pass makes both sets again.

A pass replaces the chains' rules and the elements of the sets of untranslated
sources in 1 transaction. It leaves a timeout object that reads back as written
as it is, and [timeouts](#timeouts) gives what it does with one that reads back
otherwise. It leaves a set of flows and its counts as they are unless it makes
the set anew, which it does in three cases. Where the set is gone, as after a
flush of the whole ruleset, the pass makes it. Where the set reads back
otherwise in a way nf_tables will not change in place, as under another share,
the pass makes it again, as the paragraph above gives. Where nf_tables refused
the pass's transaction with `file exists`, the pass makes it again in its second
send, as [sharing a host](coexistence.md#the-nftables-table) gives. Each rule
carries a comment that names it, which `nft list ruleset` shows, and a pass
reads each rule back by its comment and by what it does:

- `out via ranet3 ipv4 icmp source quench dropped`
- `in via ranet3 ipv4 icmp information dropped`
- `out via ranet3 ipv6 untranslated passed`
- `out via ranet3 ipv4 untracked dropped`
- `out via ranet3 ipv4 dccp refused`
- `out via ranet3 ipv4 limit 4096`
- `in via ranet3 ipv4 from 198.51.100.0/24 untracked dropped`
- `in via ranet3 ipv4 from 198.51.100.0/24 dccp refused`
- `out via ranet3 ipv4 from 192.0.2.128/25 timeouts udp`
- `out via ranet3 ipv4 from 192.0.2.128/25 source 198.51.100.7`
- `out via ranet3 ipv6 from 3fff:a::/32 untranslated`
- `out via ranet3 ipv4 masquerade`
- `in via ranet3 ipv4 from 198.51.100.0/24 timeouts udp`
- `in via ranet3 ipv4 from 198.51.100.0/24 source 203.0.113.10`
- `local via ranet3 ipv4 from 192.0.2.1/32 masquerade`

A stopped translator's lines sit in the forward hook's chains in place of its
own: each family's limit becomes its drop, of every packet the limit would meet,
the drop of a packet no flow is tracked for and the refusals out of the mesh are
left out, and the other lines stay. The labelled drop, which
[down and up](#reloads-down-and-up) gives, ends each family's chain, in both
families, and where a family has the line that accepts untranslated sources, a
labelled drop of a packet out of the mesh from those sources stands directly
ahead of that line:

- `out via ranet3 ipv4 dropped while stopped`
- `out via ranet3 ipv6 untranslated leaving by another link dropped while stopped`
- `translated via ranet3 ipv4 leaving by another link dropped while stopped`

`forward`'s first line carries the comment `ipv6 to forward6`. nf_tables
[refuses to delete a chain a goto still names](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_tables_api.c?id=940de590b839f71d6dc846160534bf202401b8b7#n3367),
so `forward6` goes missing only with that line, and the pass and the withdrawal
empty `forward` in the transaction that deletes `forward6`. A pass that finds a
chain an earlier version wrote, as
[refusing to advertise](#refusing-to-advertise) names, empties it, every other
such chain and `forward` in its transaction, since a line of one of them may go
to it by a goto or a map and
[the gotos of a line's map go with the line](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_tables_api.c?id=940de590b839f71d6dc846160534bf202401b8b7#n6016).
The same transaction then deletes each such chain that no rule or map element of
another writer's goes to, as [refusing to advertise](#refusing-to-advertise)
gives. A chain under such a name that another writer flagged binding is neither
emptied nor deleted by name, and goes only as
[what goes of another writer's](coexistence.md#what-goes-of-another-writers)
gives. A line at the forward hook tests no family ahead of its prefix, so
`nft list ruleset` prints the prefix as the bytes the line reads, such as
`@nh,96,32 & 0xffffff00 == 0xc0000200` for `192.0.2.0/24`, and its comment names
it. A refusal reads `reject with icmpx admin-prohibited`, which the kernel
[sends](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_reject.c?id=940de590b839f71d6dc846160534bf202401b8b7#n96)
as code 13 in IPv4 and code 1 in IPv6. The limit's rule reads
`reject with icmpx host-unreachable` in IPv4, sent as code 1, and
`reject with icmpx admin-prohibited` in IPv6, sent as code 1 too.

A rule carries `from` unless its prefix covers every address, and the line that
accepts untranslated sources carries `untranslated` in its place, its set listed
apart in `nft list ruleset` and read back with it. A nat chain is consulted once
per connection, so the translation rules' counters count flows, not packets, and
the timeout rules carry none. The limit rule's counter counts the packets it
refused, a dropping rule's the packets it dropped, a refusing rule's the packets
it refused, and the line that accepts untranslated sources carries none. The
ICMP drops' and the refusals' counts reach no field of `ranet3 status`, and
`ranet3 debug egress` and `nft list ruleset` show them.
[Sharing a host](coexistence.md) describes how the table lives beside other
writers.

## Egress segments

An egress segment is a SID a leaf steers its traffic to, so the leaf picks this
exit by its segment list rather than by the default route Babel selects.
[Segment routing](segment-routing.md#egress-segments) describes the segment and
its `allow` list. This page covers what the exit does with the inner packet.

A leaf chooses the exit for its own traffic with `cap.exit.via`, on macOS with
`fallback = "uplink"` written, the SIDs of any waypoints and then this exit's
egress segment, as [mode 3](routing.md#mode-3-on-linux) describes. For a leaf to
use it, the exit writes the segment with `deliver = "egress"` and an `allow`
that holds the leaf's outer source and every inner source it sends, and
originates the SID's `/128` while it is ready, as below. A LAN reaches the
internet through the exit by a subnet router that announces the LAN and names
its link in `forward`, and the exit's `allow` lists the LAN beside the router's
overlay address, as
[the configuration reference](configuration-reference.md#capsegmentlocal) gives.

A leaf sees one state for both families, the SID's `/128` the exit originates as
below, and [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic)
declare what that costs a leaf in mode 3.

The mesh hands each inner packet to the exit, as it hands a packet the
forwarding decision egresses. On Linux the exit writes it into the tun, and the
kernel forwards it by its own routes, translated by the out rules keyed on the
tun under its source's class. On macOS the userspace exit carries it as it
carries any packet the mesh hands it, ending TCP in a stack of its own and
relaying UDP and echo through the host's sockets, as
[the exit on macOS](#the-exit-on-macos) gives. A node with an egress segment
translates both families, whatever `advertise` holds. An inner packet whose
destination lies inside `overlay`, or that the mesh routes itself, to another
node, into a hold or to this node, is refused rather than handed to the exit, as
[segment routing](segment-routing.md#egress-segments) describes.

An exit that serves only egress segments writes `cap.egress` with an empty
`advertise`. It then attracts no default route, and only a leaf naming its SID
uses it:

```toml
overlay = ["203.0.113.0/24", "3fff:a::/36"]

[cap.egress]
advertise = []

[[cap.segment.local]]
sid = "2001:db8:0:6::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["203.0.113.0/25", "3fff:a::/64"]
```

An egress segment needs `overlay`, which turns on
[the antispoof filter](antispoof.md). The daemon refuses a file with an egress
segment and no `overlay`, or with an `allow` list the `overlay` cannot admit, as
[segment routing](segment-routing.md#egress-segments) gives. The outer source
passes only through an entry inside the overlay, which a host on an interface of
a forwarding node cannot forge past the filter unless that node exempts it, and
an entry outside it admits inner sources alone.

An egress segment needs no `cap.table`. On Linux its replies need a route back
into the tun, such as the one `cap.table` gives by the rules of
[the return path](#the-return-path), and the reply lookup reads it. Its packets
wait for their family's [readiness](#readiness). The mesh counts one of a family
not ready as not ready, and its answer about the packet it carries is
Destination Unreachable, code 0, over IPv6 and Network Unreachable, code 0, over
IPv4, from the addresses the [forwarding decision's](routing.md#transit) answers
come from and within their rate limits.

The node originates each egress SID as a `/128` while at least 1 family is ready
and every family the host carries out is: on Linux each family the host
forwards, and on macOS each family where a link outside the mesh reaches any
prefix its [readiness](#readiness) pass looks up, or where any of those lookups
failed. A leaf reads the `/128` as the exit's liveness. An exit carrying out a
single family still serves that family, and an exit whose translation broke in a
family it carries out withdraws the SID. Each pass reads forwarding again on
Linux, and those lookups on macOS, so a family the host starts or stops carrying
out moves the `/128` on the next pass even where readiness stays as it was.
`cap.route` may not announce the SID's `/128`, since it would hold the route up
whatever readiness says.

## Reloads, down and up

A reload refuses a change to `cap.egress` with
`config: cap.egress changed, restart to apply`. Reordering `advertise` or
`translate`, writing a class of `auto` from `0.0.0.0/0` or `::/0`, and writing
out the default `flows_per_source` or `sweep` are not changes. A reload is also
refused when `cap.route` or `cap.table` moves a mesh address of a family the
translator translates, with
`config: cap.route or cap.table moved a mesh address cap.egress translates under, restart to apply`,
since the in rules and the local rules were written from those addresses at
startup. The first egress segment and the last are a restart, since the families
the translator translates are fixed at startup. A reload moving an egress
segment to another SID or editing its `allow` list applies in place, and the
originated `/128` moves with the SID. [Reloading](reloading.md) lists what else
a reload applies.

On Linux `ranet3 down` retracts the advertisement and, in one transaction,
writes a stopped translator's rules in the forward hook's chains in place of its
own, and keeps the translation's chain, `postrouting`, with its rules and
timeout objects as the last pass wrote them. A down exit holds in
`table inet ranet3` what a running one holds there, beside the antispoof
filter's chains: its chains, 2 sets and 3 timeout objects for each family it
translates, and those a pass leaves of a family an earlier run translated, with
the stopped rules in the forward hook's chains. `nft list ruleset` lists each
stopped line with a comment, such as
`out via ranet0 ipv4 dropped while stopped`, and `ranet3 debug egress` lists
each with its counter, each drop counting the packets it dropped. The stop
writes the translation's chain again as it was, so its counters start from zero
at a down, as those of the forward hook's chains do.

Under each class that translates, the stopped rules drop every packet from the
mesh device that leaves by another link, to the internet or to a network this
node routes for, with no answer, a DCCP or UDP-Lite packet among them: the
family's drop, which stands where the family's limit stood. So a packet a
session took before the stop and wrote to the tun after it leaves under no
leaf's address, and its drop leaves no connection entry. The stopped rules sit
at the forward hook, ahead of every source translation, so a packet they drop is
dropped whatever another program's nat chain would make of it. A flow that
another table's flowtable offloads passes the forward hook by and keeps its
translation, since
[the flowtable translates a packet from its own entry](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_flow_table_ip.c?id=940de590b839f71d6dc846160534bf202401b8b7#n507).
A packet under a class of `none` passes and leaves under its own address unless
its connection entry carries the exit's label, as below. A packet the host
routes from the mesh back into the mesh passes. A down exit lets into the mesh
what a running one lets in, since the ICMP drops and, under `return`, the drop
of a packet no flow is tracked for and the refusals into the mesh stay where
they are.

`ranet3 down` closes every session, so no reply reaches a leaf once they have
closed. The exit's label is bit 127 of a flow's connection label, which
[the translation's rules](#the-nftables-chains) set. The stopped rules end the
chain of each family, in both families whatever the configuration translates,
with the labelled drop, which drops every packet the host forwards whose
connection entry carries the label and that would leave by a link other than the
tun, whatever link it came in by. A packet from the tun from an untranslated
source never reaches the end of its family's chain, since the line that accepts
those sources passes it, so the stopped rules put a labelled drop of such a
packet directly ahead of that line, where a family has one. That takes a reply
translated back to the leaf's mesh address once the reconciler has withdrawn the
tun's addresses and routes under `cap.table`, and a packet from the tun of a
flow an earlier run translated, in a family this run does not translate or from
a source it puts under a class of `none`. The flow's binding stays, so after
`ranet3 up` its next packet leaves under the same address and its replies reach
the leaf again, for as long as the host's connection tracking keeps it under
[the exit's timeouts](#timeouts). A reply the labelled drop takes still renews
its flow's entry, which connection tracking does ahead of the forward hook, so a
remote end that keeps sending keeps the binding, its port and its place in the
leaf's share for the whole of a down. The host's own packets from a mesh address
leave under that address's class.

A packet carrying a leaf's mesh address can still leave by another link in these
cases:

- From the reconciler's withdrawal of the tun's routes until the translator's
  commit, under the running chains: a reply translated back to the leaf.
  `ranet3 down` wakes the reconciler and the translator at once, so this is open
  where the withdrawal commits first. A shutdown under `cap.table` withdraws the
  routes before the mesh closes, as its sessions leave, and the translator
  commits only after that, so this is open at every shutdown. The stop begins
  once the translator's turn under way has ended, reads its chains back and
  writes them in one transaction with the translation's chain whole, so its time
  grows with the exit's rules, and a pass under way adds its own.
- While a stop is not taken, which leaves the chains the host held, as below.
- A flow whose connection entry carries no room for a label. The kernel
  [makes that room](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/netfilter/nf_conntrack_labels.h?id=940de590b839f71d6dc846160534bf202401b8b7#n42),
  its labels extension, on each entry it makes while a rule of the network
  namespace sets a label, since such a rule
  [turns the extension on](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_ct.c?id=940de590b839f71d6dc846160534bf202401b8b7#n580),
  or, on a kernel that carries
  [the change that has a rule reading one turn it on too](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=514f1dc8f2ca3101e04cdf452e53baca3a76e544),
  first released in Linux 6.18, reads one, and not where
  [its allocation fails](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1793),
  and a nat chain meets a flow's first packet alone. So a flow translated by a
  version that set no label goes unlabelled until it ends. So does a flow whose
  first packet the kernel tracked before the first pass committed and whose
  translation came after it, at a start where no rule of the namespace turns the
  extension on: one another program wrote or one an earlier run left, as the
  rules a shutdown leaves are, keeps the room made.
- A connection a conntrack helper expects, such as an FTP data connection where
  a rule of the host assigns the FTP helper to forwarded flows. The kernel
  [translates it from its master's binding](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_helper.c?id=940de590b839f71d6dc846160534bf202401b8b7#n179)
  as it makes its entry, so it meets no chain, and
  [copies the master's mark](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1826)
  to it and not its label.
- A packet from the tun that connection tracking finds invalid, such as a TCP
  segment carrying SYN and FIN or an ACK outside the window, which gets no entry
  and so carries no label. Under a class that translates the family's drop takes
  it. Of a flow an earlier run translated, under a class of `none` or in a
  family this run does not translate, it leaves under the leaf's mesh address
  with its old flow's ports.
- Every packet the labelled drop would take, on a kernel that refuses the label,
  as the next paragraph gives.
- [What the host itself sends to a leaf](#what-the-host-itself-sends-to-a-leaf),
  whatever made it, such as an error about a frame from the tun or the host's
  answer to a frame addressed to it.

A kernel built without connection labels refuses a rule that sets or reads one
with `EOPNOTSUPP`, since `CONFIG_NF_CONNTRACK_LABELS` is
[an option a kernel can leave out](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/Kconfig?id=940de590b839f71d6dc846160534bf202401b8b7#n188).
The translator learns which kernel it runs on once a start, ahead of its first
write, by a transaction of its own: it makes a chain holding a rule that sets
the label, which such a kernel refuses as it refuses one that reads it, and ends
with a request the kernel always refuses, so the kernel commits none of it and
the table stays as it was. Where the kernel refuses that rule with `EOPNOTSUPP`,
the exit writes without the label and without the labelled drop, starts as it
does elsewhere at every number of classes, and warns once,
`egress cannot label the flows it translates`, with the cause as `why` and the
kernel's answer as `err`. Any other answer fails that pass, and the next asks
again. The answer to a write is never read for the label, so neither a refusal
of the write, as another writer's change to the table can cause, nor the loss of
its acknowledgments past the socket's buffer turns the label off. Once the label
is off, `ranet3 debug egress` prints a `Labels` line with the same cause, up and
down, until the daemon restarts, and lists no labelled drop.

While down a packet meets no more of the exit's rules than while up, but in 3
cases, each a labelled drop more. On an exit translating one family, a packet of
the other family meets the one that ends its family's chain after the line that
sends it on. A packet from the tun under a class of `none` meets the one ahead
of the line that accepts untranslated sources. So does a packet from the tun
under a class that translates that no flow is tracked for, in a family with that
line, which a running exit drops at the drop that follows the line and the
stopped rules drop at the family's drop in its place. The tree's test holds the
bound over the forward hook's lines in configurations of classes inside one
another, of a class of `none` from every source and of an exit translating one
family alone. A packet the host forwards that did not come in by the tun,
another program's among them, meets in a family the exit translates the rules a
running exit gives it, less the drop of a packet no flow is tracked for and the
refusals of DCCP and UDP-Lite out of the mesh, which the stop leaves out, with
the family's drop in place of its limit, and with the labelled drop that ends
its family's chain and, in a family with the line that accepts untranslated
sources, the labelled drop ahead of that line, which takes only a packet from
the tun. A packet from the tun under a class that translates is dropped at its
family's drop. The kept translation chain is walked to its end by the first
packet of every new flow the host forwards or originates while down, as while
up, since it holds the running exit's rules.

The label costs a running exit too. A flow's first packet meets the label's
setting in the rule that translates it. And every connection entry the host's
network namespace makes while the exit's rules are in place, up, down or left at
a shutdown, carries the labels extension, made as the list above gives. The
extension is 16 bytes, which an entry that already has another extension, as
each flow the exit translates does, holds in the area it has. An entry with
none, as another program's plain flow has at the kernel's default settings, gets
an area of its own for it, of
[at least 128 bytes](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_extend.c?id=940de590b839f71d6dc846160534bf202401b8b7#n114),
allocated as the entry is made.
[Sharing a host](coexistence.md#the-exits-connection-label) gives what another
program that sets or reads the bit meets.

A node that starts down writes the stopped rules at the translator's first turn,
which comes once the daemon has built its parts and, under `cap.exit`'s
`fallback = "none"`, once the reconciler's first pass has ended or 10 seconds
have passed. Until then the table holds what the last run left, and that turn
writes over it. A change another writer makes while down to the translator's
chains, rules or sets, a set's elements or a flag it sets on the table wakes the
translator, which reads them and writes its stopped rules back where they no
longer read back as written. Status tells the table as that read found it, and
until the read and the write it wakes, a packet meets what the other writer
left. A lost notification is read at the next sweep at the latest. A reload
while down leaves the stopped rules as they are, since it refuses each change
the translator reads. They stay until `ranet3 up`, whose next pass writes the
translator's own rules in their place in one transaction, the translation's
chain as it was, and the advertisement follows.

What a run leaves in the table stays until a start with `cap.egress` takes it
over at that first turn, or until the operator deletes it with
`nft delete table inet ranet3` while the daemon is stopped, which takes the
antispoof filter's and the kill switch's chains with it. A start whose
configuration has no `cap.egress` takes no such turn. A daemon killed, or ended
by a second signal while its shutdown waits for the mesh, leaves its chains as
they stood. Where the exit was up, those are the running chains, which go on
translating with no labelled drop, so a reply to a kept binding leaves by
another link where the tun's routes are gone. Where it was down, and where a
shutdown leaves them as below, they are the stopped rules, which act as a down
exit's do. They drop forwarding from the mesh device under the classes that
translated then, and their labelled drop takes a connection another program set
the bit on as it takes the exit's flows. Either kept translation chain still
translates the host's own flows from a mesh address under those classes, and
every connection entry the namespace makes carries the labels extension, as
above.

At shutdown the translator keeps its chains until the mesh has closed, so each
packet the mesh wrote to the tun before meets them, and then ends one of 2 ways,
as [the tun device](design/limits.md#the-tun-device) gives when. It removes its
chains with their sets and objects and leaves nothing of its own in the table.
The bindings then stay in the host's connection tracking, and beside another
program's nat chain in the namespace the kernel keeps translating their replies
back to the leaf's address, which then leave by another link for as long as the
bindings last. Or, at every shutdown over a tun that outlives the daemon, as one
`link.tun` attaches to does, it ends as `ranet3 down` does: it writes the
stopped rules, keeps the translation's chain, and warns
`egress left its stopped rules at shutdown` with the reason as `why`, the line
ending `, which did not read back in place` where it did not read them back in
place. Where the host took that write and its rules could not then be read back
as written, the warning carries that as `err`, and the daemon exits with it.

A stop is not taken where its chains cannot be read before the write, where the
host refuses the write, or where it answers the write with an error and the
rules cannot be read back after. The host can answer with an error a write it
committed, since its acknowledgments of a large transaction can overflow the
socket's receive buffer, so the stop reads the rules back whatever the answer
and counts a write whose rules read back as written as taken. A stop not taken
leaves the table as the host held it. While the daemon runs it is tried again,
as [watching it](#watching-it) shows. At a shutdown it is not: the daemon exits
with `the shutdown saw no write of the stopped rules taken` and the cause. Where
the host read back an up exit's running chains, they stay as a killed daemon
leaves them, above, and translate a frame the tun took before the mesh closed
under the exit's address. A packet leaves under its leaf's address only where
the host held other than the exit's chains, as where another writer had removed
them. Where the rules could not be read back after the write, the host holds
either the stopped rules or what it held before. A set of the translator's in a
family it translates that reads back otherwise than written in a way nf_tables
will not change in place, held by a rule of another writer's, makes the host
refuse the whole of each stop's write, which must delete it, so the table keeps
what it held, an up exit's running rules where the exit was up, as
[a writer's own that another writer holds](coexistence.md#a-writers-own-that-another-writer-holds)
gives.

On macOS `ranet3 down` retracts the advertisement, ends each dial, resets each
connection and ends each mapping, and `ranet3 up` takes flows again from the
next pass, which announces what is ready.

### What the host itself sends to a leaf

On Linux a packet the host itself sends to a leaf's mesh address meets none of
the exit's drops, which sit at the forward hook. Once the reconciler has
withdrawn the tun's addresses and routes under `cap.table`, the host's other
routes send such a packet by another link, the leaf's mesh address its
destination, whatever made it and whatever connection entry it belongs to. The
cause is the mesh's routes, not the exit's rules, so it leaves alike in 3
states: under the running chains from that withdrawal until the stop's commit,
while down, and in the rules a shutdown leaves. Each kind below says what a run
has shown or what is read in the kernel's source, what IPv4's reverse path
filter does to it where the filter is on, as the paragraphs after the list give,
and whether the tree's test holds it:

- The time exceeded for a frame at a TTL or hop limit of 1, which the host's
  forwarding sends ahead of the forward hook, in
  [IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_forward.c?id=940de590b839f71d6dc846160534bf202401b8b7#n118)
  and
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n576),
  for any such frame: one of a labelled flow, the first of a new one, such as
  each probe of a UDP traceroute, or a segment connection tracking finds invalid
  and gives no entry, such as a TCP segment carrying SYN and FIN. A run has
  shown each leaving, and over IPv4 none where the filter is on. The tree's test
  holds the first two, with the filter off.
- The fragmentation needed or packet too big for a frame past the uplink's MTU
  that may not be fragmented, which the host's forwarding sends there too, in
  [IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_forward.c?id=940de590b839f71d6dc846160534bf202401b8b7#n137)
  and
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n672).
  A run has shown it leaving, and over IPv4 not where the filter is on. The
  tree's test holds it, with the filter off.
- The destination unreachable for a frame to a destination the host holds an
  unreachable or a prohibit route for, which the routing sends in
  [IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/route.c?id=940de590b839f71d6dc846160534bf202401b8b7#n2385)
  and
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/route.c?id=940de590b839f71d6dc846160534bf202401b8b7#n4661):
  the host unreachable over IPv4 and the no route over IPv6 for an unreachable
  route, and the administratively prohibited in both for a prohibit route. A run
  has shown each leaving, over IPv4 whatever the filter holds. As read there, a
  frame to a destination the host holds no route for draws the net unreachable
  over IPv4 and the no route over IPv6 the same way, unchecked by the filter
  too. The tree's test holds those of an unreachable and of a prohibit route,
  with the filter strict.
- The parameter problem for an option the host refuses: over IPv4 one it cannot
  read, such as a record route too short to hold its pointer, which
  [IPv4's input reads](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_input.c?id=940de590b839f71d6dc846160534bf202401b8b7#n430)
  after
  [the route lookup](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_input.c?id=940de590b839f71d6dc846160534bf202401b8b7#n407),
  and over IPv6 a hop-by-hop option the host does not know whose type asks for
  an error, which
  [IPv6's input reads](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_input.c?id=940de590b839f71d6dc846160534bf202401b8b7#n321)
  ahead of
  [the prerouting hook](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_input.c?id=940de590b839f71d6dc846160534bf202401b8b7#n351).
  A run has shown it leaving, and over IPv4 not where the filter is on. The
  tree's test holds it, with the filter off.
- The reassembly time exceeded for an IPv6 first fragment whose packet is never
  completed, which
  [the reassembly sends](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/ipv6_frag.h?id=940de590b839f71d6dc846160534bf202401b8b7#n108)
  for a packet connection tracking never tracked. A run has shown it leaving.
  Over IPv4
  [the reassembly sends it](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_fragment.c?id=940de590b839f71d6dc846160534bf202401b8b7#n180)
  only for a packet addressed to the host, as read. The tree's test holds
  IPv6's, with the filter off.
- The port unreachable or TCP reset of another program's reject of the frame,
  the reset sent from the remote end's address. In all 3 states a reject answers
  the frame at the prerouting hook at any priority, at the forward hook ahead of
  the exit's chain, and after that chain where a class of `none` passes the
  frame or where the frame is of a family the exit does not translate, which the
  chain sends on and, while down, the labelled drop passes as a new flow's. A
  run has shown each leaving. Under the running chains a reject after the exit's
  chain answers a frame under a class that translates too, since those chains
  pass it on where the stopped rules drop it, and a run has shown that port
  unreachable leaving in both families. Over IPv4 the answer of a reject at the
  forward hook does not leave where the filter is on, and that of one at the
  prerouting hook leaves whatever the filter holds. The tree's test holds the
  port unreachable of a reject at the forward hook ahead of the exit's chain,
  with the filter off.
- The host's own answer to a frame addressed to one of its addresses: its port
  unreachable or TCP reset for a closed port, its echo reply, and a service's
  answer. A run has shown each leaving, and over IPv4 none where the filter is
  on. The tree's test holds the port unreachable for a closed port and the echo
  reply, with the filter off.

Each error carries as much of the leaf's packet as fits in
[576 octets](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n983)
over IPv4, up to 548 octets of it, and in
[1280](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n803)
over IPv6, up to 1232.

Over IPv4 the host's reverse path filter, strict or loose, refuses a frame from
the tun once the tun's addresses are gone, since
[a link with no IPv4 address fails it](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/fib_frontend.c?id=940de590b839f71d6dc846160534bf202401b8b7#n423),
the kernel taking the larger of `rp_filter` on `all` and on the tun, and the
filter is on where that value is not 0. It checks a frame the host forwards or
delivers to itself at the route lookup. It checks no frame the lookup finds an
unreachable or a prohibit route for, which
[goes to the routing's error unchecked](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/route.c?id=940de590b839f71d6dc846160534bf202401b8b7#n2385),
nor, as read there, one it finds no route for, and none ahead of the lookup. The
daemon sets neither value. Over IPv6 nothing filters such a frame by default.

The tree's test of a down under `cap.table` writes each frame alone and finds
the packet it draws leaving by the uplink in each family that makes one, with
`net.ipv4.icmp_ratemask` and `net.ipv6.icmp.ratemask` empty, since the kernel
limits the rate of each type of error a family's mask names, and with IPv4's
filter strict or off as each kind above gives.

On Linux 5.2 to 6.1 an IPv6 redirect can carry a leaf's mesh address out to a
remote end that is the host's neighbor on the uplink. Where such an end's reply,
translated back to the leaf's mesh address, would leave by the uplink it came in
by, through a gateway its route names by a link-local address, as a default
route from a router advertisement does,
[IPv6's forwarding sends that end a redirect](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=v6.1#n569)
ahead of the forward hook, addressed to it, naming the leaf's mesh address and
carrying the reply. It
[sends none where the host's route to that end has a gateway](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ndisc.c?id=v6.1#n1707).
Those kernels
[take a redirect for no error](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmpv6.c?id=v6.1#n163)
and
[make it no entry](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmpv6.c?id=v6.1#n104),
so nf_nat leaves it as it is and it leaves by the uplink. Linux 6.2 and later
[relate it to the flow's entry](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7d7cfb48d81353e826493d24c7cec7360950968f),
and
[nf_nat drops a redirect related to a translated flow](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_proto.c?id=940de590b839f71d6dc846160534bf202401b8b7#n838).
This is as read in the kernel's source at those tags, and no run has shown it.

## Watching it

On Linux `status` prints 1 line for the translator: where it writes, the rules,
the flows translated and those a class of `none` left untranslated where there
were any, the packets each family refused past a source's share and those it
dropped with no tracked flow where any were, the entries the host's connection
table holds against its maximum, what it announces, what it withholds "until its
family is ready", the families it is ready for and the reason the others are
not, what the lookups skipped, any chain it shares the hook with, the time since
the exit's last pass or stop stored its record, and the record's error, such as
`nftables table inet ranet3 chains forward, forward6 and postrouting, 20 rules, 4100 flows, 12 ipv4 and 3 ipv6 packets refused past 4096 a source, conntrack holding 9000 of 262144 entries, ...`.
A family not ready is named with the reason the record holds, and a family the
node does not translate with none. Before the first pass or stop the line names
no family. The refused counts are the limit rules' counters, of packets, each
retry of a refused flow among them, and the dropped counts are those of the
rules that drop a packet no flow is tracked for. All of them start from zero
when a pass rewrites the chains, and when a stop writes the stopped rules. Down,
the line reads the stopped rules the host holds, the flows the kept translation
chain has counted since the stop wrote it, the dropped counts of the rules into
the mesh it keeps under `return`, no refused count, since a down holds no limit,
no reading of the connection table, no chain it shares the hook with, and each
family not ready because the translator is stopped. From `ranet3 down` until the
translator's turn it wakes, the line still reads the last pass. Until the
stopped rules read back as written, while the stop is under way or not taken, it
reads each family not ready because the translator is stopping, the rules the
host holds as the record before it counts them, the last pass's or the last
stop's, until the stop writes the stopped rules and then as the read after the
write found them, none where that read failed, the other counts, the reading of
the connection table and the chains it shares the hook with as that record holds
them, and the error of the last stop, none until one has failed. Where the
stopped rules read back other than written after a write, the reason names how,
as a pass names a fault, and the error names it too, the error after the write's
answer and the reason after the refusal where that answer read as the host's
refusal. The stopped rules are in place where that read finds the table without
the dormant flag, each of the translator's chains with the type, hook, priority
and policy written and holding them alone, line for line in the order written,
each by its comment and its expressions, and each set and timeout object a
stopped line uses as written, a set with its elements. Where they are not, the
reason says the stopped rules are not in place, ahead of how, whatever the
answer. A rule another writer put in the translator's chains under a stopped
rule's comment that does something else is not that rule. A chain or object an
earlier version wrote that a rule or a map element of another writer's holds, as
[refusing to advertise](#refusing-to-advertise) names, makes them read back so,
and so does a set or object of the translator's that reads back otherwise than
written while another writer holds it, as
[a writer's own that another writer holds](coexistence.md#a-writers-own-that-another-writer-holds)
gives. The stop's write takes or is refused over such a set or object as that
section gives for a pass, and leaves such a chain or object of an earlier
version, and where the host takes the write the stopped rules are in force while
the stop reads as failed. A flag other than dormant another writer gave the
table makes them read back so too, over which the host refuses the write and the
reason names the flag and what clears it, as
[the nftables table](coexistence.md#the-nftables-table) gives. The reason and
the error name such a flag first, then such a set or object of the translator's
that the write is refused on, ahead of a chain or object of an earlier version,
held or not. Where the stopped rules are not in place, both then name the
dormant flag where the table carries it, and the first chain, or set or object a
stopped line uses, that reads back otherwise than the stopped state writes it,
IPv4's and then IPv6's, each unless they named it already. A dormant table runs
none of its chains, so while it is dormant nothing in it filters or translates a
packet. The stop is tried again until the stopped rules read back as written. A
write the host refused and acknowledged reads
`the translator is stopping: the host refused the stopped rules, which are not in place:`
and how. A refused write whose acknowledgments overflowed the socket, as those
of an exit of some hundreds of classes can, reads
`the translator is stopping: the stopped rules are not in place:` and how. A
write that failed before it was sent reads the same. A write the host took, or
committed with its answers lost, reads `the translator is stopping:` and how
where a set or object another writer holds that no stopped line uses, or a chain
of an earlier version's it holds, keeps its readback otherwise than written
while the stopped rules are in place, reads as a write that failed before it was
sent where they are not, and reads the stop in effect where its rules read back
as written. Where the table already held the stopped rules in place, as at a
stop tried again after another writer's change that left them so, each reads
without the words that they are not in place. Where the rules cannot be read
back after the write, each reads
`the translator is stopping: its chains could not be read back`. Whether the
stopped rules are in place is read from the translator's own chains, the sets
and objects its stopped lines use and the table's flags alone, so Status cannot
tell of a base chain another writer adds, in the table `inet ranet3` or in
another, that the kernel runs at a hook ahead of the translator's, of a
flowtable whose flows skip the forward hook, nor of any other rule or anything
else outside the translator's chains.

The line, the `egress` object of the
[status answer](control-socket.md#requests-and-answers), `ranet3 debug egress`
and the egress series of the [metrics](metrics.md) read one record, which the
exit's last pass or its last stop stored, and the configuration, which gives the
prefixes the exit advertises, its classes, whether it translates into the mesh
and each source's share of the flows. Each of the four also gives what it reads
at the time it is asked, as the next sentences name. The line gives where the
kernel exit writes, and the userspace exit's flows and its refused and dropped
counts. On macOS the 2 lines under it give the userspace exit's flows against
its limits, the endpoints it holds in TIME_WAIT, its held slots and host ports,
and the bytes its buffers hold. The status answer carries each of these, and the
TIME_WAIT endpoints the userspace exit reused or closed early and its busiest
sources. `ranet3 debug egress` prints each of these, and the kernel exit's
chains with each rule's counter or the error of reading them, IPv4's reverse
path filters and why the exit writes no label, and Go's memory limit beside the
userspace exit. The metrics give the userspace exit's refused counts and its
held slots. Each exit stores a stop's record at its first turn after
`ranet3 down` wakes it, or at its first turn on a node that starts down, and at
a shutdown's start. The kernel exit stores another at each later turn while
down, as it reads the stopped rules back, and the userspace exit stores none.
The status answer and the metrics serve the record until the daemon exits, so a
read during a shutdown finds a stop's record on a node that is not down. A
stop's record holds the time it was stored and the stop's error, none for a stop
under way. It holds every family not ready, no family's judgment, no prefix
announced and no lookup skipped, so `ranet3 debug egress` lists no judgment. On
Linux it holds the counts the paragraph above gives for each state of a stop. A
shutdown's stop is under way from the shutdown's start. Where the tun outlives
the mesh, or where whether it does cannot be read, the kernel exit then writes
the stopped rules as a down's stop does, and where the tun is gone it withdraws
its chains and the record stays as the stop under way stored it. The userspace
exit's stop stores the time and each family not ready, and nothing it counts.

On macOS the line names the userspace exit and its flows in place of where it
writes and its rules, with the refused counts, the leaves' packets it dropped as
belonging to no flow it carries where there were any, what it announces and
withholds, and the families it is ready for, and 2 lines under it give its flows
against its limits, its [held slots](#host-ports) and the host ports its TCP
connections take against `HostPorts`, and the bytes its TCP endpoints toward the
leaves hold received and not yet read against its budget, such as:

```
Egress   userspace, 23 flows, 2 ipv4 packets refused past 4096 a source, egress ready for ipv4 ipv6, last pass or stop 4 seconds ago
Flows    61 of 10240 allowed: 23 open, 3 dialing and 37 held slots, 2 of them also open while closing and counted once, 19 TCP of 985 allowed: 16 open and 3 dialing, 6 UDP, 1 echo, 210 in TIME_WAIT outside both, 54 host ports of 5120
Buffers  3.1 MiB of 4.0 GiB, a sixteenth of the host's memory
```

The 61 are the flows the exit counts against `Flows`,
[the exit's bound](design/limits.md#the-userspace-exit). The 23 open are the
egress line's figure, the 3 dialing the TCP connections from their SYN until the
exit's stack has completed the leaf's handshake or given it up, so through the
dial toward the server and then the leaf's answer to the stack. The 37 are the
[held slots](#host-ports), and the slots waiting out their margin after the exit
closed their sockets are among them. A connection whose leaf's handshake fails
after its dial stays dialing until the exit has ended it, and where it holds a
slot it counts as held in that time as well. The 2 of the 37 are still closing
toward the leaf, so they are among the 23 open as well, each
[one flow with its held slot](design/limits.md#the-userspace-exit), and the 61
are the 23, the 3 and the 37 less the 2. The 19 are the TCP connections counted
against `Connections`: the 16 open and the 3 dialing. The 210 in TIME_WAIT are
the leaf-side endpoints in the exit's own stack, and the 54 the host ports the
exit counts against `HostPorts`, as [the bound](#host-ports) states them. The
61, the TCP counts, the 37, the 2 and the 54 are read at one instant, and the
5120 and the UDP and echo flows each a moment after it, so in a read during
which a flow opens, ends or moves, the parts need not add up to the 61.

The userspace exit writes the lines of the first table. Of the second, both
exits write `egress translating for N prefixes in <where>`, `egress ready`,
`egress not ready` and `egress advertisement changed`, and the rest are the
kernel exit's on Linux:

| Log line                                                                                                                        | Level | When                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `egress userspace exit started`                                                                                                 | info  | the exit starts, with `steered`, the count of prefixes it advertises as `advertise`, its `lanes`, the `window` of a TCP flow and its `flows` |
| `egress userspace exit started again`                                                                                           | info  | the first pass after `ranet3 up`                                                                                                             |
| `egress userspace exit opened no ICMP socket, so it refuses echo in this family and relays no router's error about its sockets` | warn  | an ICMP socket of a family would not open, with `ipv6` and `err`, at startup                                                                 |
| `egress: the userspace exit opened no raw socket, so a leaf's own ICMP error about a datagram reaches no server`                | warn  | the daemon could not open a raw socket, as one not running as root cannot, with `err`, at startup                                            |
| `egress userspace exit keeps its last bound on host ports`                                                                      | warn  | a sweep could not read the automatic range or the MSL, with `err`, once until a sweep reads them again                                       |
| `egress userspace exit keeps a host socket the host refused to abort, and its slot, and tries again at each sweep`              | warn  | on macOS the host refused the linger of 0 that ends a held socket, with `err`, once for the exit's run                                       |
| `egress userspace exit closed host sockets the host refused to abort, and left them to the host`                                | warn  | on macOS the exit's stop closed held sockets whose linger of 0 the host refused, with `sockets` and `err`                                    |

| Log line                                                                      | Level | When                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `egress translating for N prefixes in <where>`                                | info  | the daemon starts the exit, `<where>` naming the kernel exit's table and chains, and `userspace` under the userspace exit                                                                                                                                        |
| `egress translator started`                                                   | info  | the translator starts, with the tun as `interface` and whether the node holds an egress segment as `steered`                                                                                                                                                     |
| `egress ready`                                                                | info  | a family went ready, or was ready at the exit's first pass, with `family`                                                                                                                                                                                        |
| `egress not ready`                                                            | warn  | a family stopped being ready, or was not ready at the exit's first pass, with `family` and the reason as `detail`                                                                                                                                                |
| `stopped reading nf_tables notifications`                                     | warn  | a read of the notification socket failed, with `table`, `chains` and `err`, after which another writer's change waits for the next sweep                                                                                                                         |
| `egress rules installed`                                                      | info  | a pass wrote the chains                                                                                                                                                                                                                                          |
| `egress advertisement changed`                                                | warn  | the announced prefixes changed after the first pass                                                                                                                                                                                                              |
| `egress is sharing the source translation hook with another writer`           | warn  | a new chain appears at the same hook, once each                                                                                                                                                                                                                  |
| `egress pass failed, retrying`                                                | warn  | a pass failed, retried with backoff                                                                                                                                                                                                                              |
| `egress translator stopped`                                                   | info  | a stop wrote the stopped translator's rules and they read back as written, at the translator's first turn after `ranet3 down` wakes it, at the first turn of a node that starts down, at a later turn while down or at a shutdown that leaves them, with `rules` |
| `egress could not stop its chains, retrying`                                  | warn  | a stop at the translator's first turn after `ranet3 down` wakes it, at the first turn of a node that starts down or at a later turn while down could not write them, read them back or read them back as written, with `err`                                     |
| `egress translator withdrawn`                                                 | info  | its chains, sets and objects are removed, at a shutdown that withdraws them                                                                                                                                                                                      |
| `egress left its stopped rules at shutdown`                                   | warn  | a shutdown found the stopped rules or saw its write of them taken and read them back in place, the tun outliving the mesh or that unread, with the reason as `why`, and `err` where something else then read back otherwise than written                         |
| `egress left its stopped rules at shutdown, which did not read back in place` | warn  | a shutdown saw its write of the stopped rules taken and did not read them back in place, with the reason as `why` and how as `err`                                                                                                                               |
| `egress cannot label the flows it translates`                                 | warn  | the kernel refused a rule carrying the connection label as one built without labels does, once, with the cause as `why` and `err`, after which the exit writes its rules without it                                                                              |
| `egress translator started again`                                             | info  | the first pass after `ranet3 up`                                                                                                                                                                                                                                 |

A stop, `ranet3 down` included, logs at info `egress not ready` for each family
that was ready and `egress advertisement changed` where the exit announced any
prefix, and a stop before the exit's first pass logs neither of the two.

On Linux a pass that writes the chains, changes the announced prefixes or fails
records an `egress.pass` event, and so does a stop whose write of the stopped
rules the host takes or that fails, at the translator's first turn after
`ranet3 down` wakes it, at the first turn of a node that starts down, at a later
turn while down or at a shutdown that leaves them, with `trigger`, `took`,
`installed`, `announced` and, on failure, `err`. A shutdown's stop carries the
`trigger` of the translator's last wake before it. The userspace exit records
`egress.pass` only for a pass that changes the announced prefixes, with
`trigger` and `announced`, and none for its stop. A change of a family's
readiness, of whether the egress SIDs are served or of what the lookups skipped
records `egress.ready`, and so does the exit's first pass, with `ipv4`, `ipv6`,
`sid`, the reason as `reason` and the skip as `skipped`. A reason that changes
while nothing else moves reaches `status` and not the event. On Linux a pass
whose count of a family's refused packets moved records `egress.refused` with
`family` and the packets refused since the pass before as `refused`, counted
from zero after a pass that wrote the chains. A pass that cannot read the
counters back keeps the counts of the record before it, a pass's or a stop's,
the dropped ones among them, unless it rewrote the chains, whose counters start
from zero whether or not it read them back. The userspace exit records
`egress.refused` itself when it refuses a packet, at most once every 30 seconds,
with the `source` and the `reason` of the refusal that falls due and every
packet refused since the last record as `refused`, so a source retrying does not
flood the log.

The packets the userspace exit refuses, each counted by its reason in
`ranet3 debug egress` and in the `refused` of its status, are these, each retry
counted again:

- The packets of a new flow past a limit: its source's share (`share`, or
  `share held` where the source holds more [held slots](#host-ports) than open
  flows) and the total (`total`) for any flow, and for a TCP connection also
  `Dials` (`dials`), `Connections` (`connections`) and, on macOS, the host ports
  (`host ports`).
- The packets of a new flow whose socket would not open: `descriptors` where the
  process or the host had no descriptor left, for a TCP, UDP or echo flow, and
  for a UDP or echo flow otherwise `echo socket` where the host refused an echo
  mapping's ICMP socket as not permitted or not supported, else `socket`.
- The packets the exit answers as each arrives, before any flow takes it: one
  whose TTL or hop limit ran out (`expired`), one of a protocol it does not
  carry (`protocol`), and as `held destination` one toward an address no router
  forwards or toward a group, one toward an address the host or the mesh holds,
  and a UDP datagram toward such an address at a port no UDP mapping of the
  exit's holds. Toward an address the host or the mesh holds, the address alone
  refuses neither a UDP datagram, which only the port refuses, nor an
  unfragmented ICMP Destination Unreachable, Time Exceeded, Parameter Problem
  or, for IPv6, Packet Too Big that has no IPv6 extension header and quotes a
  UDP datagram.
- A UDP datagram or an echo request that the exit had not yet sent when
  `ranet3 down` or the stop ended the mappings of its kind and that the exit
  handles before the next `ranet3 up`, or one whose mapping `ranet3 down` or the
  stop closed while it was sent, that no earlier check refused or dropped
  (`withdrawn`).

| Metric                                   | Meaning                                                                                                                                                                                                                                                                             |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ranet3_egress_rules_installed`          | rules the host holds in this node's chains as the exit's last pass or [stop](#watching-it) read them back, zero where a pass could not read them back or a stop could not after writing them, and the count of the record before a stop that has neither written nor read them back |
| `ranet3_egress_prefixes{state}`          | `advertised` and `announced` prefix counts                                                                                                                                                                                                                                          |
| `ranet3_egress_flows_total`              | connections the rules have translated                                                                                                                                                                                                                                               |
| `ranet3_egress_untranslated_flows_total` | connections a class of `none` left under the source they carry                                                                                                                                                                                                                      |
| `ranet3_egress_refused_total{family}`    | packets refused past their source's share, each retry of a refused flow counted                                                                                                                                                                                                     |
| `ranet3_egress_host_held`                | the macOS userspace exit's [held slots](#host-ports)                                                                                                                                                                                                                                |
| `ranet3_egress_dropped_total{family}`    | packets out of the mesh under a class that translates, and into it under `return`, dropped because no flow is tracked for them                                                                                                                                                      |
| `ranet3_egress_conntrack_entries`        | entries the host's connection table holds, where the exit's record holds a reading of it                                                                                                                                                                                            |
| `ranet3_egress_conntrack_max`            | the most entries the host's connection table takes, where the exit's record holds a reading of it                                                                                                                                                                                   |
| `ranet3_egress_conflicts`                | other nat postrouting chains at priority 99 or below, `inet` ones and another writer's in `inet ranet3` among them, as of the exit's record                                                                                                                                         |
| `ranet3_egress_pass_timestamp_seconds`   | when the exit's record was stored                                                                                                                                                                                                                                                   |
| `ranet3_egress_pass_failed`              | whether the exit's record holds an error                                                                                                                                                                                                                                            |
| `ranet3_egress_ready{family}`            | whether the family is [ready](#readiness), 1 or 0, the exit's judgment                                                                                                                                                                                                              |

The userspace exit writes the prefix counts, the refused counts, the pass's 2
series, readiness and, on macOS, the held slots alone, and none of the rules',
the translation's, the dropped counts', connection tracking's or the conflicts'
series. [Metrics](metrics.md) describes the scrape.
