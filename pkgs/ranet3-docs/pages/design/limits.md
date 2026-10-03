---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "What it deliberately doesn't do"
description: "What ranet3 deliberately does not do, and why."
created: 2026-08-17
updated: 2026-10-03
order: 10
---

**ranet3 carries transit in this fork.** Upstream is an RFC 8966 Appendix E stub
that never re-advertises a learned route, which made it loop-free by
construction. The speaker here implements the source table and the feasibility
condition instead, and redistributes its selected routes, so loop freedom comes
from the mechanism the RFC provides rather than from an inability to relay. A
node that advertises transit still has to be able to forward it, which is three
things this binary does not do for you: `net.ipv4.ip_forward` and
`net.ipv6.conf.all.forwarding` have to be on, the learned routes have to reach a
kernel table the node actually consults, which
[`cap.table`](../configuration.md) is for, and the TUN has to be allowed to
forward back out of itself. Advertising transit without them means announced
paths blackhole. [`cap.egress`](../exit-nodes.md) acts on the same fact rather
than warning about it: a prefix an exit node offers to carry is advertised only
while its translation rule is installed and the kernel forwards its family, and
is retracted the moment either stops being true.

`dial.all` dials every node the trust document names, the N-to-N reconciliation
ranet performs. Entries in `dial.to` still apply and win for their node, which
is the only way to pin a `serial`. Reach against a fleet running BIRD requires
it, because that Babel channel exports only its own directly connected routes: a
node learns a prefix from the node that originates it or not at all, so dialing
a few exits reaches those exits and nothing behind them.

A node that takes an exit-announced default should set `link.underlay`. It is
one block covering both platforms because it is one idea: keep the one UDP
socket carrying IKE and ESP out of the reach of the routes the mesh installs.
The transport binds the wildcard and lets the kernel pick the source by route,
so on a node whose mesh address is the only global address of its family the
kernel picks that address, a `from <mesh address>` policy rule sends the
datagram to the mesh table, and an exit-announced default there routes the ESP
underlay into the tun carrying it.

`link.underlay.mark` is `SO_MARK`, linux only, and the reconciler installs the
rule matching it: write it under `cap.table.rules`, as
`{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }`. The two
halves are one setting written in two blocks, so a node that writes `cap.table`
and leaves that rule out is refused by name: a marked socket no rule selects on
follows the mesh table exactly as an unmarked one would. A node configuring its
routes elsewhere writes no `cap.table`, and the rule goes wherever those routes
do.

`link.underlay.bind` is `IP_BOUND_IF` and `IPV6_BOUND_IF`, darwin only, set to
the interface the host's own default route leaves by and moved with `setsockopt`
on the live descriptor when that changes, so a laptop crossing from wifi to a
dock keeps every SA. It scopes that socket's route lookups to that interface,
which is the only thing on that platform that can make a real default out of the
tun safe, so the same setting tells the reconciler to install an announced
default plain rather than interface-scoped. Leaving it off keeps the scoping
described under [the platform notes](../platforms.md): reachable, and reachable
by nothing that did not name the tun, so the node can hold an exit-announced
address and cannot send its traffic through the exit.

Binding is necessary and, on macOS 26, not sufficient on its own, which
`TestDarwinBoundSocketNeedsAScopedDefault` measures. `IP_BOUND_IF` does not take
a socket out of the forwarding table: the scoped lookup still finds the most
specific route, and where that route leaves another interface it falls back only
to a route already on the bound one. So while the mesh holds `0.0.0.0/1` and
`128.0.0.0/1` out of the tun, a bound socket answers `ENETUNREACH` unless the
underlay's own interface carries a default scoped to it, the route
`route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>` writes. macOS
writes exactly that for every interface but the primary one, which is why
binding looks sufficient right up until the mesh takes the default away from the
primary.

ranet3 writes it, and it is the only route this tree puts out of an interface it
does not own, so the rules around it are narrower than the tun's.

It is written whenever the socket is bound rather than only when the mesh looks
like it is capturing. Writing it under a condition meant every set that slipped
past the condition took the machine off the network with nothing to fall back
on, and three ordinary announcements are such a set. It duplicates the host's
own default on the interface that already carries it, so it costs nothing when
nothing needs it.

The reconciler asks once a pass, and drops from that pass every capturing route
whose own family the underlay cannot fall back on, so such a route is neither
installed nor left behind: the host's default moving to another interface
withdraws one that is already in the kernel. The answer is per family, because
the fallback is: a bound socket resolves the unspecified address of the
destination's own family, so a covered IPv4 does nothing for a `::/0` capture.
That is an invariant rather than a sequence, on both edges.

It is reconciled rather than remembered. The kernel drops this route on its own,
clearing `IFF_UP` purges it and bringing the interface back up does not restore
it, so every pass reads the table back and writes what is missing; a record
saying it was written says nothing about whether it is there. The record is the
claim to delete it and nothing else.

It follows the host's own default: the interface it is going to is written
before the socket moves onto it and the one it left is cleared after that, which
leaves no moment with no usable route. Only a route this tool recorded writing
is ever withdrawn, only after a readback finds it still carrying `RTF_IFSCOPE`,
the recorded interface and the recorded next hop, and a delete that is not
interface-scoped cannot be encoded at all. An add that answers `EEXIST` is
success and not ownership, so a route macOS wrote for a secondary interface is
used and never removed. Nothing is withdrawn while a capture is still in the
kernel, so a withdrawal that failed upstream cannot take the fallback away from
under one.

The record outlives the process. It is written to
`/var/run/ranet3/underlay.json`, beside the control socket's lock, before the
route is written and after it is withdrawn, so a daemon killed with `SIGKILL` is
cleaned up by the next one rather than leaking. That is the same ownership claim
made durable, not a weaker one: a restart withdraws a recorded route only when
the kernel still holds one matching its destination, interface index, next hop
and `RTF_IFSCOPE`, only when the recorded interface name still resolves to the
recorded index, and only when that interface also carries the host's own
unscoped default. The last clause separates our route from the system's, because
macOS writes a scoped default for every interface except the one holding the
unscoped default; `TestNoOtherProgramScopesADefaultToThePrimaryInterface`
asserts that on whatever machine the suite runs on rather than taking it on
trust. A record failing any clause is kept where nothing in the process can
delete it, so the clauses are not undone by the next ordinary withdrawal, and
the next start weighs them again. The file is locked before it is read, so a
second daemon starting beside a running one reclaims nothing and overwrites
nothing; a state file that is missing, truncated or not JSON is reported and
treated as empty, because a node that will not start is worse than a route left
behind.

The edge that leaves is worth knowing. The last clause is a snapshot, so a host
that makes another interface primary while our route is in place, and later
makes it primary again, could have a restart withdraw a scoped default macOS
wanted there. That is one route on one interface until the next link event,
which macOS answers by rewriting it.

Either way, a route that would carry this machine's own traffic is held back
until at least one session is live, withdrawn once none has been live for
`cap.table.capture_grace` (10s by default) and restored on the next live
session. Such a route is one covering half a family's address space or more, or
one covering that family's unspecified address however small, which is the
kernel's own trigger rather than a rule of thumb: measured for both families,
`0.0.0.0/24` out of the tun costs a bound socket as much as `0.0.0.0/1` does and
`::/64` costs it as much as `::/1`, while a set with no member larger than a
quarter took this machine off the network. `capture_grace` has a floor of one
second, refused by name below it: the gate is sampled once a pass and a pass
reads the routing table, so a shorter grace only sets how often that happens,
and the wake it asks for is armed only while a capturing route is actually in
play. A session counts as live only while it is still proving its peer is there
and only while the underlay socket is where `link.underlay` says it should be.
Without that rule a laptop whose mesh has gone loses every network it has rather
than only the mesh, and it cannot recover on its own, because reaching the peers
needs the network the default just took.

The capture itself has to be the pair of halves rather than a real default.
darwin has no route replace, so `0.0.0.0/0` out of the tun collides with the
host's own and is refused, while `0.0.0.0/1` with `128.0.0.0/1` wins the lookup
outright. `::/1` with `8000::/1` is the same arrangement for IPv6 and is handled
the same way throughout: the gate, the scoping decision and the scoped default
all read a prefix of length zero or one as carrying this machine's own traffic,
whichever family it is. What announces that pair is the exit, not this node.

A leaf should write `transit = false` under `cap.route`, which advertises only
the prefixes this node announces and never relays one it learned. Redistribution
serves a converted fleet and turns a laptop into a transit router for everybody
else. The BIRD side of a ranet fleet draws the same line with
`export where proto = "dbabel0"`. Refusing to advertise cannot close a loop, so
this only narrows what the feasibility condition already bounds.

It implements genuine source-specific routing
([SADR, RFC 9079](https://www.rfc-editor.org/rfc/rfc9079)): the mesh's route
table is keyed by `(source, destination)` prefix pairs, resolved per RFC
8966/SADR's rule (longest destination match first, source prefix as a tiebreaker
among equally-specific destinations) using each packet's real source address as
it arrives on the TUN device, not an approximation based on a single configured
"our address".

**ranet3 does not manage the TUN device's address or routes unless you ask it
to.** It creates the device and brings it up, or attaches to the configured
`tun` device, and by default assigning its addresses and kernel routes is
external. This fork adds an optional reconciler, `internal/kernel`, which
mirrors the learned routes into one routing table it owns, or on darwin into the
single table that platform has, scoping the ones that would otherwise capture
the machine, and can assign the configured addresses. See the `cap.table` block
in [the configuration](../configuration.md). It is off unless enabled.

Babel only exchanges control packets inside authenticated ESP tunnels; a local
routing daemon cannot peer with the embedded speaker over the TUN. Learned
routes select the outgoing ESP peer after the kernel has routed a packet to the
TUN.

IPv4 announcements use the control link's IPv6 link-local next hop (AE 4). The
BIRD peer needs Babel's `extended next hop` support, enabled by default in
BIRD 3. Both ordinary IPv4 updates and AE 4 updates are accepted on receive.

On Linux, ranet3 opens one multiqueue TUN lane per Go execution context and
keeps inner flows on a stable lane. When more than one execution context is
available, an existing named TUN must therefore be created with
`IFF_MULTI_QUEUE` (for a systemd-networkd `.netdev`, set `MultiQueue=yes` in its
`[Tun]` section). Single-core processes can also attach to a legacy single-queue
TUN. TUN readers hand bounded batches to shared encryption workers; sequence
reservation and queue submission preserve packet order across workers.

The Babel control state and forwarding publication share one mutex. Selection
runs over feasible routes only, against the source table this fork added, since
a speaker that re-advertises what it learns can no longer rely on the structural
loop freedom of
[RFC 8966 Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E).
Every finite advertisement leaves through one function, which records the
feasibility distance before the packet is built. Local prefixes take precedence
even after a router-ID change. Remote Hello, IHU, and Update expiration is
scheduled independently of local send intervals.

Packet lookups read an immutable SADR trie snapshot without locking. Route
changes copy the affected path and publish it atomically; diagnostics iterate
the same snapshot. ESP batches similarly capture an immutable set of installed
SAs, retaining keys for work already in flight during a rekey. One-core receive
processing runs inline; multicore receive workers authenticate concurrently and
commit replay state in intake order before delivering TUN batches. Linux UDP
receive reads a full 128-message vector and returns excess GRO segments before
reusing its buffers. Replay checks and nonce storage are amortized across ESP
batches, and already-completed send/receive batches are combined without waiting
for additional traffic. Encryption workers reuse packed ciphertext buffers only
after the ordered sender finishes its UDP call, retaining separate storage for
work in flight. Replaced inbound SAs remain usable for five seconds after their
Delete acknowledgment so queued and reordered packets can drain during a rekey.
