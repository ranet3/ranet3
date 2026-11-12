---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-11-13
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
installs it. A Mac without `cap.exit` scopes the `/0` to the tun, which no
socket selects unless it asks for the tun by name.

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
   chain would. This node under [`return`](#the-return-path) drops such a reply
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
with the family's digit: `translated-udp4`, `translated-tcp4` and
`translated-icmp4` in IPv4, and `translated-udp6`, `translated-tcp6` and
`translated-icmpv66` in IPv6. They are made once and never changed in place: a
pass that rewrites a chain leaves them, and one that reads back other values in
one deletes that object and makes it again, which leaves the flows that held it
on the host's timeouts. A stop withdraws the objects with the chains, and the
flows it leaves keep their translation under the host's timeouts.

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
  chain sends its packets past the limit, as [the chains](#the-nftables-chains)
  lay out, so none of its flows is counted or refused, and the operator sizes
  the host's table for them, as
  [connection tracking makes them](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1897).
  A source no class takes leaves under `auto` and holds a share.
- **What it does not count.** A TCP connection in TIME_WAIT or closed. The share
  bounds a source's open flows, and its closed ones are bounded by their
  timeouts and by how fast it closes them. The userspace exit on macOS counts a
  closed connection while its host socket may hold a port, as
  [host ports](#host-ports) gives.
- **A full set admits.** Each family's set, `flows4` or `flows6`, keeps a count
  for each source holding flows, up to 65535 sources. Past that a new source is
  not counted and its flows are not limited, until every flow of some source has
  ended and
  [the kernel collects its count](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_set_hash.c?id=940de590b839f71d6dc846160534bf202401b8b7#n393).
- **What its count misses.** The kernel's count of a source's flows can leave a
  flow open and uncounted, past the share, as the row for the flows the kernel
  exit's count misses in [limits](design/limits.md#dataplane-and-sockets) gives.
  Behind
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
announced only while its family is ready, as [readiness](#readiness) describes
for each platform: on Linux while the translator's chains read back exactly as
the node wrote them, `forward6` for IPv6 alone and every other one for both
families, since `forward` holds IPv6's goto ahead of IPv4's lines, with every
rule in order, each by its comment and by what it does, and no other writer's
among them, each at its hook, priority and policy, the family's set and timeout
objects read back as written, in a table with no flags, the host forwards that
family, the host holds every address its classes name and, where its lookups
run, the kernel routes a translated packet of it and its reply. A pass reads the
translator's chains, the family's set and timeout objects, and the elements of
each set a screen of a class of `none`'s chain takes its sources from. Every
chain whose name starts `none_` is the exit's: one no class writes is read as a
fault and deleted. So is `forward4`, the chain an earlier version held IPv4's
lines in. Another chain in the table is neither read nor removed, and a nat
chain at the source translation hook at priority 99 or below is named as a
[conflict](#watching-it). Each pass first rewrites a chain that reads back
otherwise, such as one missing a rule, holding another writer's, a rule edited
under the comment it was written with or in a dormant table, writes a class of
`none`'s chain that is missing and deletes a `none_` chain no class writes and a
`forward4`. Where a rule of another writer's chain goes to that chain, by a
goto, a jump or its vmap, or an element of a named map does, nf_tables will not
delete it, so the pass empties it and writes the rest, and both families stay
not ready with that chain or map named until the rule or the element goes.
nf_tables clears no table flag in place but dormant, and changes no chain's
type, hook or priority, no set's key, flags or comment and no timeout object's
values, so when a chain, set or object of the translator's differs in one of
those the pass deletes that one and makes it again in the same transaction,
leaving everything else in the table as it is. Another table flag holds both
families not ready, the reason naming `nft delete table inet ranet3`, which
alone clears it. When the chains still do not read back as written, the host
stops forwarding the family or a lookup fails, that pass retracts the prefix. A
pass runs at least every `sweep` (30 seconds by default).

On Linux the node reads forwarding from `/proc/sys/net/ipv4/ip_forward` and
`/proc/sys/net/ipv6/conf/all/forwarding`. Any value other than `0` counts as on.
The exit counts a file the node cannot read as on too, and `status` shows it as
`unknown`. The kernel exit acts on them by withholding its advertisement,
because no other node can tell whether it forwards. Transit between sessions
needs neither setting, since the mesh forwards it itself.

`status` names the prefixes it announces and the ones it withholds. The scrape
carries the advertised and the announced counts as `ranet3_egress_prefixes`.

## Readiness

On Linux a family is ready while its chains, its set and its timeout objects
read back as written, the host forwards it, the host holds every address its
classes name, and, where its lookups run, the kernel routes a translated packet
of the family and its reply the way the translation needs. Every node with
`cap.egress` judges each family it translates on every pass, and both modes wait
for the judgment: a packet through an advertised prefix waits for the families
ready that the node announces, and an egress segment's packet for the families
ready, as [what an exit carries out](#what-an-exit-carries-out) and
[egress segments](#egress-segments) describe. A family this node does not
translate is not ready. On Linux `ranet3 debug egress` shows each family's
judgment condition by condition with the lookups the last pass read, as
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
counts as a failed lookup.

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
next sweep. A chain another writer adds to the table is not read unless its name
starts `none_`. That pass reads the family ready with the chain still in place.
The translator's own writes wake no pass of its own, and the antispoof filter's
and the kill switch's writes of their chains, rules and sets in the same table
wake none either. A flush of the ruleset deletes the table and another program
setting it dormant sets a flag on it, so each wakes every writer once. The first
writer's pass after it makes the table again or clears the flag, which wakes no
other: the table it makes holds none of their chains, and with the flag cleared
it bypasses none. Notifications the daemon lost, which another table's large
transaction can overflow its socket with, wake a pass too and leave readiness as
it was, since that pass reads the rules back. A pass that reads another writer's
change back and cannot undo it holds the family the change is in not ready, IPv6
alone for a change to `forward6`, and both families for a change to another
chain, `forward` among them, since it holds IPv6's goto ahead of IPv4's lines,
with the change named, and withholds its prefixes until a later pass does.

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
  identifier where no other mapping holds it, and an idle echo mapping ends
  after 60 seconds. The exit takes only a reply on an identifier a mapping holds
  from a destination that mapping sent to, and counts the rest.
- **Errors** a server or a router raises about a mapping's datagram, or about a
  dial that fails, reach the leaf from the address that raised them. A leaf's
  own error about a reply leaves from the mapping
  [the userspace exit](design/protocol-deviations.md#the-userspace-exit) finds
  for it. Toward a server it goes through a raw socket, which only root opens,
  and toward a leaf whose datagram the exit hairpinned it goes back to that leaf
  with no raw socket. Where the exit finds no mapping, or an error toward a
  server finds no raw socket or fails to send, the error is dropped and counted.
  Any other error a leaf sends reaches the exit's stack only where the exit
  reads its quote down to a TCP header, or is dropped and counted as
  `leaf error quote`. An error in fragments is counted as `leaf error fragment`.
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
    segment's. An error from a node the mesh reaches by another first hop than
    the leaf is dropped too. Over IPv4, the errors a router raises about an open
    connection, net or host unreachable and time exceeded, are soft errors on
    which TCP does not abort it (RFC 1122 section 4.2.3.9). The hard ones,
    protocol and port unreachable, pass from the leaf's own address or from a
    router behind the leaf's session. A filtering router's own port unreachable
    that the mesh reaches by another first hop is dropped like any error from
    another session.
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
IPv6 address on any link or `lo0`, and an IPv4 address on the link itself, since
macOS refused every IPv4 flow from an address on `lo0` of a socket scoped to
another link, where the IPv6 ones carried. A family whose IPv4 class address
that link does not hold is not ready.

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
- **A reset.** A flow the exit resets, at a withdraw or a relay's error, closes
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
  `Flows`. A new TCP connection is refused while the open TCP connections and
  the slots held reach it, counted as `host ports`, so a range of 1 port refuses
  every one. Since the open ones count, where `Flows` is under twice
  `Connections` fewer TCP connections are admitted than `Connections`.
  Leaf-first closes fill `HostPorts` at `HostPorts` / 40 a second across
  sources, about 205 a second at its most of 8192.
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
  its closed connections pin. That is a limit of the exit, not of Linux, whose
  hold would be built apart. The userspace exit runs on Linux in tests alone
  today.

## The nftables chains

The translator writes its chains in the nftables table `inet ranet3`, which
[the antispoof filter](antispoof.md#where-it-runs) and
[the kill switch](routing.md#the-kill-switch-on-linux) write theirs in, for each
family it translates: each advertised family, and both beside an egress segment,
whatever `advertise` holds, since an egress segment carries both families. It
writes 2 base chains, which see both families, the regular chain `forward6`
whether it translates IPv6 or not, a regular chain for each class of `none`, and
for each family a set and 3 timeout objects. nf_tables
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

| Property | Translation        | Forward                        | IPv6                                       | Class of `none`                                       |
| -------- | ------------------ | ------------------------------ | ------------------------------------------ | ----------------------------------------------------- |
| Name     | `postrouting`      | `forward`                      | `forward6`                                 | `none_192_0_2_0_24` for `192.0.2.0/24`                |
| Type     | `nat`              | `filter`                       | no type                                    | no type                                               |
| Hook     | `postrouting`      | `forward`                      | no hook, entered by `forward`'s first line | no hook, entered by its class's rule in a chain above |
| Priority | 99, below `srcnat` | 0 (`filter`)                   | no priority                                | no priority                                           |
| Policy   | `accept`           | `accept`                       | no policy, `forward`'s at its end          | no policy, `forward`'s at its end                     |
| Lines    | both families'     | the goto to `forward6`, IPv4's | IPv6's                                     | its family's                                          |

The translation chain holds each class's rules together, the longest `from`
first, since the first rule that translates a connection ends the chain: for a
class that translates, a rule for each protocol attaching its timeouts, then its
translation, and for a class of `none` its binding alone. Where no class covers
every source, the rules of `auto` for the rest follow. The in rules come next,
for each advertised prefix a rule for each protocol attaching its timeouts, then
its translation, and then the local rules of this node's mesh addresses. A
family's lines at the forward hook, IPv4's past `forward`'s first line and
IPv6's in `forward6`, hold in IPv4 the 4 ICMP drops first, which take Source
Quench and then Information Request and Reply, out of the mesh and then into it,
from any source. The screens follow: a rule that drops a packet no flow is
tracked for, the refusals of DCCP and of UDP-Lite, which take a packet in its
flow's original direction, and out of the mesh the limit's rule. Each class of
`none` has 1 rule that sends every packet from it on to its own chain, among its
family's lines or, for one inside another class of `none`, in the nearest such
class's chain, the longest `from` first. The class's chain holds those rules of
the classes of `none` inside it first, then where a class that translates has
that class of `none` as its nearest shorter class covering it, the 4 screens
once, each taking the sources of every such class as 1 set, and a packet that
reaches its end goes on by `forward`'s policy. The family's screens for every
source follow its classes of `none`'s rules, then under `return` those for each
advertised prefix of the family into the mesh, with no limit. A packet:

- under a class that translates meets 1 limit.
- under a class of `none` meets no limit, as
  [each source's share](#each-sources-share-of-the-flows) describes.
- outside a class of `none` meets 1 rule for it, whatever classes it covers.
- under a class of `none` that directly holds a class that translates meets the
  4 screens in its chain, whatever their count, and none under one that directly
  holds none.

The set the limit counts each source's flows in, `flows4` or `flows6`, carries
the share as its comment, `limit 4096`. Each count keeps the share in force when
it began. A set read back under another share, as an instance stopped without
withdrawing under another one leaves it, makes the pass delete that set and make
it again in the transaction that rewrites the chains, leaving every timeout
object as it is. The share is one setting of both families, so where that
instance translated both, the pass makes both sets again.

A pass replaces the chains' rules in 1 transaction and leaves the sets, their
counts and the objects as they are. Each rule carries a comment that names it,
which `nft list ruleset` shows, and a pass reads each rule back by its comment
and by what it does:

- `out via ranet3 ipv4 icmp source quench dropped`
- `in via ranet3 ipv4 icmp information dropped`
- `out via ranet3 ipv6 from 3fff:a::/32 passed`
- `out via ranet3 ipv4 untracked dropped`
- `out via ranet3 ipv4 dccp refused`
- `out via ranet3 ipv4 limit 4096`
- `out via ranet3 ipv4 translated inside 192.0.2.0/24 limit 4096`
- `in via ranet3 ipv4 from 198.51.100.0/24 untracked dropped`
- `in via ranet3 ipv4 from 198.51.100.0/24 dccp refused`
- `out via ranet3 ipv4 from 192.0.2.128/25 timeouts udp`
- `out via ranet3 ipv4 from 192.0.2.128/25 source 198.51.100.7`
- `out via ranet3 ipv6 from 3fff:a::/32 untranslated`
- `out via ranet3 ipv4 masquerade`
- `in via ranet3 ipv4 from 198.51.100.0/24 timeouts udp`
- `in via ranet3 ipv4 from 198.51.100.0/24 source 203.0.113.10`
- `local via ranet3 ipv4 from 192.0.2.1/32 masquerade`

`forward`'s first line carries the comment `ipv6 to forward6`. nf_tables
[refuses to delete a chain a goto still names](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_tables_api.c?id=940de590b839f71d6dc846160534bf202401b8b7#n3367),
so `forward6` goes missing only with that line, and the pass and the stop empty
`forward` in the transaction that deletes `forward6`. An earlier version held
IPv4's lines in a regular chain `forward4`, which `forward`'s one line sent IPv4
on to by a map. A pass that finds `forward4` reads it as a fault of both
families and, in its transaction, empties `forward` before it deletes
`forward4`, since
[the gotos of a line's map go with the line](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_tables_api.c?id=940de590b839f71d6dc846160534bf202401b8b7#n6016).
A line at the forward hook tests no family ahead of its prefix, so
`nft list ruleset` prints the prefix as the bytes the line reads, such as
`@nh,96,32 & 0xffffff00 == 0xc0000200` for `192.0.2.0/24`, and its comment names
it. A refusal reads `reject with icmpx admin-prohibited`, which the kernel
[sends](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_reject.c?id=940de590b839f71d6dc846160534bf202401b8b7#n96)
as code 13 in IPv4 and code 1 in IPv6. The limit's rule reads
`reject with icmpx host-unreachable` in IPv4, sent as code 1, and
`reject with icmpx admin-prohibited` in IPv6, sent as code 1 too.

A rule carries `from` unless its prefix covers every address, and a screen of a
class of `none`'s chain names that class, its set listed beside it in
`nft list ruleset` and read back with it. A nat chain is consulted once per
connection, so the translation rules' counters count flows, not packets, and the
timeout rules carry none. The limit rule's counter counts the packets it
refused, a dropping rule's the packets it dropped, a refusing rule's the packets
it refused, and a class of `none`'s pass carries none. The ICMP drops' and the
refusals' counts reach no field of `ranet3 status`, and `ranet3 debug egress`
and `nft list ruleset` show them. [Sharing a host](coexistence.md) describes how
the table lives beside other writers.

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

On Linux `ranet3 down` retracts the advertisement and removes the translator's
chains, sets and timeout objects from the table. The flows they leave keep their
translation under the host's timeouts. `ranet3 up` installs them again on the
next pass, and the advertisement follows. On macOS `ranet3 down` retracts the
advertisement, ends each dial, resets each connection and ends each mapping, and
`ranet3 up` takes flows again from the next pass, which announces what is ready.

## Watching it

On Linux `status` prints 1 line for the translator: where it writes, the rules,
the flows translated and those a class of `none` left untranslated where there
were any, the packets each family refused past a source's share and those it
dropped with no tracked flow where any were, the entries the host's connection
table holds against its maximum, what it announces, what it withholds "until its
family is ready", the families it is ready for and the reason the others are
not, what the lookups skipped, any chain it shares the hook with, the time since
the last pass and the last error, such as
`nftables table inet ranet3 chains forward, forward6 and postrouting and a none_ chain for each class of none, 20 rules, 4100 flows, 12 ipv4 and 3 ipv6 packets refused past 4096 a source, conntrack holding 9000 of 262144 entries, ...`.
A family not ready is named with the reason the last pass found, and a family
the node does not translate with none. Before the first pass the line names no
family. The refused counts are the limit rules' counters, of packets, each retry
of a refused flow among them, and the dropped counts are those of the rules that
drop a packet no flow is tracked for. All of them start from zero when a pass
rewrites the chains.

On macOS the line names the userspace exit and its flows in place of where it
writes and its rules, with the refused counts, the leaves' packets it dropped
with no flow to take them where there were any, what it announces and withholds,
and the families it is ready for, and 2 lines under it give its flows against
its limits, the closed connections it holds and the [host ports](#host-ports)
its TCP connections take against `HostPorts`, and its buffers against its
budget, such as:

```
Egress   userspace, 21 flows, 2 ipv4 packets refused past 4096 a source, egress ready for ipv4 ipv6, no pass yet
Flows    14 TCP of 985, 6 UDP, 1 echo of 10240, 3 dialing, 210 in TIME_WAIT, 37 held for host sockets, 54 host ports of 5120
Buffers  3.1 MiB of 4.0 GiB, a sixteenth of the host's memory
```

The 210 in TIME_WAIT are the leaf-side endpoints in the exit's own stack, and
the 37 held the closed connections whose host sockets may pin a port. The 54
host ports are the 14 TCP connections open, the 3 dialing and the 37 held.

The userspace exit writes the lines of the first table. Of the second, both
exits write `egress translating for N prefixes in <where>`, `egress ready`,
`egress not ready` and `egress advertisement changed`, and the rest are the
kernel exit's on Linux:

| Log line                                                                                                                        | Level | When                                                                                                                                |
| ------------------------------------------------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `egress userspace exit started`                                                                                                 | info  | the exit starts, with `steered`, the prefixes it advertises as `advertise`, its `lanes`, the `window` of a TCP flow and its `flows` |
| `egress userspace exit started again`                                                                                           | info  | the first pass after `ranet3 up`                                                                                                    |
| `egress userspace exit opened no ICMP socket, so it refuses echo in this family and relays no router's error about its sockets` | warn  | an ICMP socket of a family would not open, with `ipv6` and `err`, at startup                                                        |
| `egress: the userspace exit opened no raw socket, so a leaf's own ICMP error about a datagram reaches no server`                | warn  | the daemon could not open a raw socket, as one not running as root cannot, with `err`, at startup                                   |
| `egress userspace exit keeps its last bound on host ports`                                                                      | warn  | a sweep could not read the automatic range or the MSL, with `err`, once until a sweep reads them again                              |
| `egress userspace exit keeps a host socket the host refused to abort, and its slot, and tries again at each sweep`              | warn  | on macOS the host refused the linger of 0 that ends a held socket, with `err`, once for the exit's run                              |
| `egress userspace exit closed host sockets the host refused to abort, and left them to the host`                                | warn  | on macOS the exit's stop closed held sockets whose linger of 0 the host refused, with `sockets` and `err`                           |

| Log line                                                            | Level | When                                                                                                                                     |
| ------------------------------------------------------------------- | ----- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `egress translating for N prefixes in <where>`                      | info  | the daemon starts the exit, `<where>` naming the kernel exit's table and chains, and `userspace` under the userspace exit                |
| `egress translator started`                                         | info  | the translator starts, with the tun as `interface` and whether the node holds an egress segment as `steered`                             |
| `egress ready`                                                      | info  | a family went ready, or was ready at the exit's first pass, with `family`                                                                |
| `egress not ready`                                                  | warn  | a family stopped being ready, or was not ready at the exit's first pass, with `family` and the reason as `detail`                        |
| `stopped reading nf_tables notifications`                           | warn  | a read of the notification socket failed, with `table`, `chains` and `err`, after which another writer's change waits for the next sweep |
| `egress rules installed`                                            | info  | a pass wrote the chains                                                                                                                  |
| `egress advertisement changed`                                      | warn  | the announced prefixes changed after the first pass                                                                                      |
| `egress is sharing the source translation hook with another writer` | warn  | a new chain appears at the same hook, once each                                                                                          |
| `egress pass failed, retrying`                                      | warn  | a pass failed, retried with backoff                                                                                                      |
| `egress translator withdrawn`                                       | info  | its chains, sets and objects are removed, at shutdown or at `ranet3 down`                                                                |
| `egress could not withdraw its chains, retrying`                    | warn  | `ranet3 down` could not remove them                                                                                                      |
| `egress translator started again`                                   | info  | the first pass after `ranet3 up`                                                                                                         |

A stop, `ranet3 down` included, logs at info `egress not ready` for each family
that was ready and `egress advertisement changed` where the exit announced any
prefix, and a stop before the exit's first pass logs neither of the two.

On Linux a pass that writes the chains, changes the announced prefixes or fails
records an `egress.pass` event, and so does `ranet3 down`, with `trigger`,
`took`, `installed`, `announced` and, on failure, `err`. The userspace exit
records `egress.pass` only for a pass that changes the announced prefixes, with
`trigger` and `announced`, and none at `ranet3 down`. A change of a family's
readiness, of whether the egress SIDs are served or of what the lookups skipped
records `egress.ready`, and so does the exit's first pass, with `ipv4`, `ipv6`,
`sid`, the reason as `reason` and the skip as `skipped`. A reason that changes
while nothing else moves reaches `status` and not the event. On Linux a pass
whose count of a family's refused packets moved records `egress.refused` with
`family` and the packets refused since the pass before as `refused`, counted
from zero after a pass that wrote the chains. A pass that cannot read the
counters back keeps the last pass's counts, the dropped ones among them, unless
it rewrote the chains, whose counters start from zero whether or not it read
them back. The userspace exit records `egress.refused` itself when it refuses a
flow, past a share, a total, the descriptors or, on macOS, the host ports or a
share of held connections among the reasons, at most once every 30 seconds, with
the `source` and the `reason` of the refusal that falls due and every flow
refused since the last record as `refused`, so a source retrying does not flood
the log.

| Metric                                   | Meaning                                                                                                                        |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `ranet3_egress_rules_installed`          | rules the host holds in this node's chains as of its last pass                                                                 |
| `ranet3_egress_prefixes{state}`          | `advertised` and `announced` prefix counts                                                                                     |
| `ranet3_egress_flows_total`              | connections the rules have translated                                                                                          |
| `ranet3_egress_untranslated_flows_total` | connections a class of `none` left under the source they carry                                                                 |
| `ranet3_egress_refused_total{family}`    | packets refused past their source's share, each retry of a refused flow counted                                                |
| `ranet3_egress_host_held`                | closed TCP connections the macOS userspace exit holds while their host sockets may pin a port, see [host ports](#host-ports)   |
| `ranet3_egress_dropped_total{family}`    | packets out of the mesh under a class that translates, and into it under `return`, dropped because no flow is tracked for them |
| `ranet3_egress_conntrack_entries`        | entries the host's connection table holds, where the pass read it                                                              |
| `ranet3_egress_conntrack_max`            | the most entries the host's connection table takes, where the pass read it                                                     |
| `ranet3_egress_conflicts`                | other nat postrouting chains at priority 99 or below, `inet` ones and another writer's in `inet ranet3` among them             |
| `ranet3_egress_pass_timestamp_seconds`   | when the last pass finished                                                                                                    |
| `ranet3_egress_pass_failed`              | whether the last pass reported an error                                                                                        |
| `ranet3_egress_ready{family}`            | whether the family is [ready](#readiness), 1 or 0, the exit's judgment                                                         |

The userspace exit writes the prefix counts, the refused counts, the pass's 2
series, readiness and, on macOS, the connections held alone, and none of the
rules', the translation's, the dropped counts', connection tracking's or the
conflicts' series. [Metrics](metrics.md) describes the scrape.
