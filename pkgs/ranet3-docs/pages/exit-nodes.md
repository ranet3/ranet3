---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Exit nodes and subnet routers"
description: "Translating traffic at an exit node, and routing a subnet behind one."
created: 2026-09-22
updated: 2026-10-03
order: 50
---

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. One action covers both features a customer asks for: an exit node
advertises `0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes
behind it, and each ends at the same operation. A packet arrives on the TUN, its
source is translated to an address the far side can answer, and the host
forwards it by its ordinary routes. linux only for now; the capability is
refused by name where there is no packet filter to write into, because a node
that accepted the configuration and translated nothing would advertise itself
and then drop every flow that took it.

A translating node needs both shapes of policy rule, not only the one selecting
on its own source. Conntrack reverses the translation before the reply is
routed, so the reply is addressed into the mesh and has to meet a rule sending
it to the mesh table. Without that rule the outbound half works and looks right,
the translation counter moves, and every reply leaves by the physical uplink
instead, which presents as an exit that answers nothing rather than as a rule
that is missing. Measured on two nodes on one switch: with the `from` rule alone
the counter reported the flow and the ping lost every packet; adding the `to`
rule made it 4 of 4.

Both interfaces are matched, never one. A packet that arrives on the TUN and
leaves by it again is mesh transit, and rewriting its source would put this
node's address on a packet it is only relaying. A packet this host generated
itself has no arrival interface at all, which recent kernels report as the empty
name rather than as a failure to read, so the inbound direction tests the
interface index against zero as well: without it, this node's own mesh traffic
would go out under the return source, which on an exit is an address belonging
to somebody else.

`source4` and `source6` say what the source becomes. Omitted, or written as
`auto`, the host's own routes decide it per packet, which is the only answer
available to a deployment that owns no address block: on the way out of the mesh
that is the address of the link the packet leaves by, and on the way in it is
this node's own mesh address, which is unique per node and routable within the
mesh. An address written out is used unchanged in both directions, which is how
a deployment with an address block of its own pins the address return traffic
comes back to, and the only way to make a reply land on a chosen node rather
than on whichever one it reaches first.

`return: true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow. A node carrying more
than one mesh address of a family is refused rather than picked from, because
the choice decides the address every flow out of its LAN appears as and a guess
would change under an unrelated edit.

**An exit that cannot translate refuses to advertise.** Babel carries no
capability signal: a node that advertises a prefix is promising to carry it, and
the only thing a peer ever learns is the advertisement, so an exit whose rule
will not install would attract traffic and drop it with nothing to tell the
sender. The advertisement is therefore published by the capability rather than
by the configuration, per family and on every pass: a prefix is announced only
while its rule is installed and `net.ipv4.ip_forward` or
`net.ipv6.conf.all.forwarding` is on for its family, and it is retracted the
moment either stops being true. `status` prints what is being announced and what
is being withheld, and the scrape carries both counts. It is the same fact
[the transit warning](design/limits.md) is about, read from the same place and
acted on here because this end is the only one that knows.

The return path is conntrack's. A reply arriving for a translated flow has its
destination put back before the forwarding lookup runs, so the route to the peer
has to be in a table that lookup consults: with the mesh's routes in a table of
the reconciler's own, that means a `cap.table.rules` entry sending the mesh
prefixes there. Without one the translation works and every reply is dropped.

```toml
[cap.egress]
advertise = ["198.51.100.0/24"] # an exit node writes ["0.0.0.0/0", "::/0"]
# source4 = "auto"                # or an address; auto lets the host's routes decide
# source6 = "auto"
# return = true                   # also translate into the mesh, for a subnet router
# sweep = "30s"
```
