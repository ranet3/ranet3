---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-10-28
order: 50
---

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. 1 action covers both features a customer asks for: an exit node advertises
`0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes behind it, and
each ends at the same operation. A packet arrives on the tun, its source is
translated to an address the far side can answer, or left as it is, by the class
of its source, and the host forwards it by its ordinary routes. An
[egress segment](#egress-segments) ends at the same operation, its inner packets
arriving on the same tun.

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
refused and counted wherever it would be translated, out of the mesh under a
class that translates and into the mesh under `return`, since from Linux 6.17
for DCCP and 7.1 for UDP-Lite the host's source translation
[rewrites neither protocol's checksum](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_proto.c?id=940de590b839f71d6dc846160534bf202401b8b7#n261),
which covers the addresses. A reply is left to cross. The refusal answers
Destination Unreachable, administratively prohibited, code 13 over IPv4 and code
1 over IPv6, where the kernel's reject answers at all. On a kernel before 7.1
the host's connection tracking can give a valid UDP-Lite packet no flow, and the
rule for a packet no flow is tracked for then takes it first, as
[protocol deviations](design/protocol-deviations.md#exit-translation) describes.
Under a class of `none` such a packet leaves as the host forwards it. In IPv4,
Source Quench and Information Request and Reply are dropped and counted out of
the mesh and into it under every class, `none` among them, ahead of every other
rule. [Protocol deviations](design/protocol-deviations.md#exit-translation)
gives the reasons and the packets the refusal leaves unanswered.

The in rule translates to the address of its family's class from `0.0.0.0/0` or
`::/0` where that class names one, and to this node's own mesh address where it
is `auto` or absent. The translator picks that address once at startup, among
the host prefixes (`/32`, `/128`) that `cap.route` announces and `cap.table`
assigns, keeping global unicast and private addresses only. A deployment with
its own address block writes the address out to pin the address return traffic
comes back to. Writing out the address is the only way to make a reply land on a
chosen node.

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

With `return` set and the family's class from `0.0.0.0/0` or `::/0` `auto` or
absent, each advertised family needs exactly 1 candidate mesh address. A family
with none or with several is refused at startup, and the error asks for the
address as the `to` of the class from `0.0.0.0/0` or `::/0` in
`cap.egress translate`. A pick among several would set the source of every flow
out of the LAN. A guess could change after an unrelated edit.

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

A class of `none` from `0.0.0.0/0` or `::/0` is refused at load: an exit that
translates nothing for anyone is an open relay for the overlay's sources onto
its upstream.

A flow under `none` is bound to the source it carries in this node's chain, at
priority 99, ahead of every chain at `srcnat`, so a host's own masquerade there
leaves it alone whatever order the chains were made in. A chain below 99, or one
at 99 made after it, still translates it, as
[sharing a host](coexistence.md#the-packet-filter) describes.

### An address that routes back to this exit

A translated flow's state is held by this exit alone, so the replies to the
address a class names have to reach this exit and no other, and that address
must not be announced by several nodes. Either of these does:

- an address of this exit's uplink, which `auto` picks
- an address of space the mesh announces that the mesh routes to this exit
  alone, such as its own `/32` or `/128`: a reply enters the mesh through any
  node announcing the covering prefix and reaches this exit through it, where
  conntrack reverses the translation as it arrives on the tun

The daemon cannot check the second. A family whose classes name an address is
[ready](#readiness) only while the host holds the address, on any link or `lo`.

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

Each table holds a connection tracking timeout object for each protocol,
`translated-udp`, `translated-tcp` and `translated-icmp` or `translated-icmpv6`.
They are made once and never changed in place: a pass that rewrites a chain
leaves them, and one that reads back other values deletes the family's table and
makes it again, which leaves the flows that held them on the host's timeouts. A
stop withdraws the tables with their objects, and the flows it leaves keep their
translation under the host's timeouts.

## Each source's share of the flows

Each table also holds a filter chain at the forward hook that holds each mesh
source address to a share of the flows through this node. Past
`cap.egress.flows_per_source` open flows in a family, 4096 when left out, a
source's next new flow is refused. The share is per source address and family,
every protocol's flows together, so a dual-stack leaf holds one in each family,
and each address of a prefix a subnet router routes into the mesh holds its own.

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
  packet.
- **What it does not count.** A TCP connection in TIME_WAIT or closed. The share
  bounds a source's open flows, and its closed ones are bounded by their
  timeouts and by how fast it closes them.
- **A full set admits.** Each family's set, `flows4` or `flows6`, keeps a count
  for each source holding flows, up to 65535 sources. Past that a new source is
  not counted and its flows are not limited, until every flow of some source has
  ended and
  [the kernel collects its count](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_set_hash.c?id=940de590b839f71d6dc846160534bf202401b8b7#n393).
- **What it bounds.** The open flows a source holds through this node. A mesh
  source's flows to this node itself, to its mesh or uplink address, take
  entries in the same table and are not counted, as
  [limits](design/limits.md#dataplane-and-sockets) lists.
- **The host's table.** The shares come out of the host's connection tracking
  table, whose size `net.netfilter.nf_conntrack_max` sets and ranet3 never
  writes,
  [its default the kernel's](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n2625).
  Size the shares against it: the shares of the sources an exit serves at once,
  with the host's own connections, held under the table's maximum. An exit
  serving a leaf that translates a LAN behind its one mesh address, which draws
  on one share for every host behind it, takes a larger share.

## The return path

Conntrack reverses the translation before the reply is routed. The reply is then
addressed to a mesh node, and the forwarding lookup has to find a route to it
into the tun, which with `cap.table` is in the reconciler's own table. The rules
the reconciler derives find it there: a reply to an address inside
`cap.border.overlay` ends as rows L3 to L5 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give, and a reply
to another address as rows L6 to L12 give, after main's route longer than /0. An
exit therefore writes the overlay its members' addresses lie in:

```toml
[cap.table]
id = 200

[cap.border]
overlay = ["203.0.113.0/24", "3fff:a::/36"]
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
nodes' packets by every route it selects. A reload that starts announcing a
default makes the node an exit from the next pass.

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
announced only while its family's table reads back exactly as the node wrote it,
both chains with every rule in order and no other writer's among them, each at
its hook, priority and policy, the set and the timeout objects, in a table with
no flags, the host forwards that family, the host holds every address its
classes name and, where its lookups run, the kernel routes a translated packet
of it and its reply, as [readiness](#readiness) describes. A pass reads the
table's 2 chains, its set and its timeout objects. Another chain in the table is
neither read nor removed until the table is made again. Each pass first rewrites
a chain that reads back otherwise, such as one missing a rule, holding another
writer's or in a dormant table. nf_tables clears no table flag in place but
dormant, and changes no chain's type, hook or priority, no set's key, flags or
comment and no timeout object's values, so when one of those differs the pass
deletes the family's table, and any chain another writer put in it, then makes
it again in the same transaction. When the table still does not read back as
written, the host stops forwarding the family or a lookup fails, that pass
retracts the prefix. A pass runs at least every `sweep` (30 seconds by default).

The node reads forwarding from `/proc/sys/net/ipv4/ip_forward` and
`/proc/sys/net/ipv6/conf/all/forwarding`. Any value other than `0` counts as on,
and so does a file the node cannot read. An exit acts on them by withholding its
advertisement, because no other node can tell whether it forwards. Transit
between sessions needs neither setting, since the mesh forwards it itself.

`status` names the prefixes it announces and the ones it withholds. The scrape
carries the advertised and the announced counts as `ranet3_egress_prefixes`.

## Readiness

A family is ready while its 2 chains, its set and its timeout objects read back
as written, the host forwards it, the host holds every address its classes name,
and, where its lookups run, the kernel routes a translated packet of the family
and its reply the way the translation needs. Every node with `cap.egress` judges
each family it translates on every pass, and both modes wait for the judgment: a
packet through an advertised prefix waits for the families ready that the node
announces, and an egress segment's packet for the families ready, as
[what an exit carries out](#what-an-exit-carries-out) and
[egress segments](#egress-segments) describe. A family this node does not
translate is not ready.

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
  forwarded packet's source against the same route. An exit whose
  `cap.border.overlay` leaves its members out has no member to read from, so
  both its lookups are skipped, as the skip below says, and its replies leave as
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
`cap.border.overlay`, overlapping none of this node's own prefixes, taking the
lowest base address first and then the longest prefix. A correctly configured
exit routes its members' addresses into the tun, so a lookup from one reads the
path a real reply takes. Where `cap.table` is written, rows L4 and L5 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give the end of a
lookup to an overlay address no route of the mesh covers.

**The read address** of a prefix is its own address for a host route, and
otherwise the first of these that the kernel's input path takes as a unicast
destination: its middle address, the base with the bit after the length set,
then its base plus 1, then its last address less 1. The middle alone would not
do, since `192.0.0.0/2`'s is `224.0.0.0`, a group. IPv4 refuses the limited
broadcast, `0.0.0.0`, the loopback addresses and the multicast addresses, and
IPv6 the unspecified, loopback, multicast and link-local addresses. Linux 4.20
to 5.2 also refuse `0.0.0.0/8` as a destination, where a lookup of a prefix
inside it fails and holds its family not ready.

**The skip.** The forward and reply lookups of a family are skipped, and the
family judged by its table, its forwarding and its classes' addresses alone,
where the mesh routes no member of it, as before any member is learned, in a
mesh of 1, or with no `cap.border.overlay` prefix of the family. A prefix
holding no address the kernel takes, such as `127.0.0.0/8` or `fe80::/10`, has
its lookup skipped as well, since the kernel forwards nothing to it either way.
A family whose every prefix is skipped is judged as one with no member. `status`
and the `egress.ready` event say what was skipped:

- `lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay`
- `lookup skipped for fe80::/10, which holds no address the kernel takes as a unicast destination`

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

Another writer adding, changing or deleting part of the `ranet3` tables, such as
a `nftables.service` reload that flushes the ruleset, a rule put in a `ranet3`
chain or a table set dormant, holds both families not ready until the pass it
wakes restores them, rather than until the next sweep. A chain another writer
adds to a `ranet3` table is not read, so that pass reads the family ready with
the chain still in place. The daemon's own writes wake nothing. Notifications
the daemon lost, which another table's large transaction can overflow its socket
with, wake a pass too and leave readiness as it was, since that pass reads the
rules back. A pass that reads another writer's change back and cannot undo it
holds that family not ready, with the change named, and its prefixes withheld
until a later pass does.

## The nftables tables

The translator owns 1 table named `ranet3` in each family it translates, `ip`
and `ip6`: each advertised family, and both beside an egress segment, whatever
`advertise` holds, since an egress segment carries both families. Each table
holds 2 chains, a set and 3 timeout objects:

| Property | Translation        | Limit        |
| -------- | ------------------ | ------------ |
| Name     | `postrouting`      | `forward`    |
| Type     | `nat`              | `filter`     |
| Hook     | `postrouting`      | `forward`    |
| Priority | 99, below `srcnat` | 0 (`filter`) |
| Policy   | `accept`           | `accept`     |

The translation chain holds each class's rules together, the longest `from`
first, since the first rule that translates a connection ends the chain: for a
class that translates, a rule for each protocol attaching its timeouts, then its
translation, and for a class of `none` its binding alone. Where no class covers
every source, the rules of `auto` for the rest follow. The in rules come next,
for each advertised prefix a rule for each protocol attaching its timeouts, then
its translation, and then the local rules of this node's mesh addresses. The
limit chain holds in IPv4 the 4 ICMP drops first, then the rules for a packet no
flow is tracked for, then the limit's 1 rule, then the refusals of DCCP and of
UDP-Lite. The ICMP drops take Source Quench and then Information Request and
Reply, out of the mesh and then into it, from any source. Down to the shortest
class of `none`, each class has a rule for a packet no flow is tracked for, the
longest `from` first, which passes the packet under `none` and drops it under a
class that translates, and 1 rule after them drops the rest. Under `return` 1
rule for each advertised prefix of the family follows, which drops such a packet
into the mesh. Each protocol's refusals take a packet in its flow's original
direction and follow the same walk of the classes as the rules for a packet no
flow is tracked for, passing under `none` and refusing under a class that
translates and into the mesh, and come after the limit, so a pass skips no
share. The set the limit counts each source's flows in, `flows4` or `flows6`,
carries the share as its comment, `limit 4096`. Each count keeps the share in
force when it began, so a set read back under another share, as an instance
stopped without withdrawing under another one leaves it, makes the pass delete
the table and make it again.

A pass replaces the chains' rules in 1 transaction and leaves the set, its
counts and the objects as they are. Each rule carries its identity as its
comment, which `nft list ruleset` shows:

- `out via ranet3 ipv4 icmp source quench dropped`
- `in via ranet3 ipv4 icmp information dropped`
- `out via ranet3 ipv6 from 3fff:a::/32 untracked passed`
- `out via ranet3 ipv4 untracked dropped`
- `in via ranet3 ipv4 from 198.51.100.0/24 untracked dropped`
- `out via ranet3 ipv4 limit 4096`
- `out via ranet3 ipv6 from 3fff:a::/32 udplite passed`
- `out via ranet3 ipv4 dccp refused`
- `in via ranet3 ipv4 from 198.51.100.0/24 dccp refused`
- `out via ranet3 ipv4 from 192.0.2.128/25 timeouts udp`
- `out via ranet3 ipv4 from 192.0.2.128/25 source 198.51.100.7`
- `out via ranet3 ipv6 from 3fff:a::/32 untranslated`
- `out via ranet3 ipv4 masquerade`
- `in via ranet3 ipv4 from 198.51.100.0/24 timeouts udp`
- `in via ranet3 ipv4 from 198.51.100.0/24 source 203.0.113.10`
- `local via ranet3 ipv4 from 192.0.2.1/32 masquerade`

A rule carries `from` unless its prefix covers every address. A nat chain is
consulted once per connection, so the translation rules' counters count flows,
not packets, and the timeout rules carry none. The limit rule's counter counts
the packets it refused, a dropping rule's the packets it dropped, a refusing
rule's the packets it refused, and a passing rule carries none. The ICMP drops'
and the refusals' counts reach no field of `ranet3 status`, and
`nft list ruleset` shows them. [Sharing a host](coexistence.md) describes how
the tables live beside other writers.

## Egress segments

An egress segment is a SID a leaf steers its traffic to, so the leaf picks this
exit by its segment list rather than by the default route Babel selects.
[Segment routing](segment-routing.md#egress-segments) describes the segment and
its `allow` list. This page covers what the exit does with the inner packet.

The mesh hands each inner packet to the exit, as it hands a packet the
forwarding decision egresses, and the exit writes it into the tun. The kernel
forwards it by its own routes, translated by the out rules keyed on the tun
under its source's class. A node with an egress segment translates both
families, whatever `advertise` holds. An inner packet whose destination lies
inside `cap.border.overlay`, or that the mesh routes itself, to another node,
into a hold or to this node, is refused rather than handed to the exit, as
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
not cover. The list names mesh sources, which a host on a link of a forwarding
node could otherwise forge, among them that node's own, and send through that
node to the SID.

An egress segment needs no `cap.table`, though its replies need a route back
into the tun, such as the one `cap.table` gives by the rules of
[the return path](#the-return-path), and the reply lookup reads it. Its packets
wait for their family's [readiness](#readiness), and the mesh counts one of a
family not ready as not ready. Both families also wait while the border filter's
chain is not read back, since the border is 1 chain for both.

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

`ranet3 down` retracts the advertisement and removes the tables, with their set
and timeout objects. The flows they leave keep their translation under the
host's timeouts. `ranet3 up` installs the tables again on the next pass, and the
advertisement follows.

## Watching it

`status` prints 1 line for the translator: where it writes, the rules, the flows
translated, the packets each family refused past a source's share and those it
dropped with no tracked flow where any were, the entries the host's connection
table holds against its maximum, what it announces, what it withholds "until its
family is ready", the families it is ready for and the reason the others are
not, what the lookups skipped, any chain it shares the hook with, the time since
the last pass and the last error, such as
`nftables table ip and ip6 ranet3 chains forward and postrouting, 20 rules, 4100 flows, 12 ipv4 and 3 ipv6 packets refused past 4096 a source, conntrack holding 9000 of 262144 entries, ...`.
A family not ready is named with the reason the last pass found, and a family
the node does not translate with none. Before the first pass the line names no
family. While the border filter holds the egress segments back, the line says
`until the border filter is read back`. The refused counts are the limit rules'
counters, of packets, each retry of a refused flow among them, and the dropped
counts the dropping rules', which all start from zero when a pass rewrites the
chains.

| Log line                                                            | Level | When                                                                                                               |
| ------------------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------ |
| `egress translating for N prefixes in <where>`                      | info  | the daemon starts the translator                                                                                   |
| `egress translator started`                                         | info  | the translator starts, with the tun as `interface` and whether the node holds an egress segment as `steered`       |
| `egress ready`                                                      | info  | a family went ready, with `family`                                                                                 |
| `egress not ready`                                                  | warn  | a family stopped being ready, with `family` and the reason as `detail`                                             |
| `egress stopped reading nf_tables notifications`                    | warn  | a read of the notification socket failed, with `err`, after which another writer's change waits for the next sweep |
| `egress rules installed`                                            | info  | a pass wrote the chains                                                                                            |
| `egress advertisement changed`                                      | warn  | the announced prefixes changed after the first pass                                                                |
| `egress is sharing the source translation hook with another writer` | warn  | a new chain appears at the same hook, once each                                                                    |
| `egress pass failed, retrying`                                      | warn  | a pass failed, retried with backoff                                                                                |
| `egress translator withdrawn`                                       | info  | the tables are removed, at shutdown or at `ranet3 down`                                                            |
| `egress could not withdraw its tables, retrying`                    | warn  | `ranet3 down` could not remove the tables                                                                          |
| `egress translator started again`                                   | info  | the first pass after `ranet3 up`                                                                                   |

A pass that writes the chains, changes the announced prefixes or fails records
an `egress.pass` event. So does `ranet3 down`. The event carries `trigger`,
`took`, `installed`, `announced` and, on failure, `err`. A change of a family's
readiness, of whether the egress SIDs are served or of what the lookups skipped
records `egress.ready` with `ipv4`, `ipv6`, `sid`, the reason as `reason` and
the skip as `skipped`. A reason that changes while nothing else moves reaches
`status` and not the event. A pass whose count of a family's refused packets
moved records `egress.refused` with `family` and the packets refused since the
pass before as `refused`, counted from zero after a pass that wrote the chains.
A pass that cannot read the counters back keeps the last pass's counts, the
dropped ones among them, unless it rewrote the chains, whose counters start from
zero whether or not it read them back.

| Metric                                   | Meaning                                                                                                                  |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `ranet3_egress_rules_installed`          | rules the host holds in this node's limit and translation chains as of its last pass                                     |
| `ranet3_egress_prefixes{state}`          | `advertised` and `announced` prefix counts                                                                               |
| `ranet3_egress_flows_total`              | connections the rules have translated                                                                                    |
| `ranet3_egress_untranslated_flows_total` | connections a class of `none` left under the source they carry                                                           |
| `ranet3_egress_refused_total{family}`    | packets refused past their source's share, each retry of a refused flow counted                                          |
| `ranet3_egress_dropped_total{family}`    | packets out of the mesh a class that translates, and into it under `return`, dropped because no flow is tracked for them |
| `ranet3_egress_conntrack_entries`        | entries the host's connection table holds, where the pass read it                                                        |
| `ranet3_egress_conntrack_max`            | the most entries the host's connection table takes, where the pass read it                                               |
| `ranet3_egress_conflicts`                | other nat postrouting chains at priority 99 or below, which can run ahead of the exit's                                  |
| `ranet3_egress_pass_timestamp_seconds`   | when the last pass finished                                                                                              |
| `ranet3_egress_pass_failed`              | whether the last pass reported an error                                                                                  |
| `ranet3_egress_ready{family}`            | whether the family is [ready](#readiness), 1 or 0, the translator's judgment without the border filter's hold            |

[Metrics](metrics.md) describes the scrape.
