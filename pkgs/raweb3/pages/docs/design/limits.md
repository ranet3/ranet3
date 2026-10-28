---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "What it deliberately doesn't do"
description: "What ranet3 deliberately does not do, and why."
created: 2026-08-17
updated: 2026-10-28
order: 10
---

This page covers what ranet3 leaves to the host and the bounds it holds itself
to. [Limits by area](#limits-by-area) lists the bounds in tables.

## Transit

**ranet3 carries transit where `cap.transit` allows it.** The Babel speaker
re-advertises the routes it selects. Loop freedom comes from the source table
and the feasibility condition of
[RFC 8966 section 3.5.1](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.5.1).
A node that carries transit decrypts other nodes' packets from one session and
encrypts them again onto the next, so it sees their plaintext.

ranet3 forwards transit itself. A packet a session delivers goes to the next
session by the mesh's own route table, with its hop limit or TTL taken down, and
never through the host. A relay needs its tun and nothing more: the host's
forwarding settings, its firewall's forward chain and its kernel tables play no
part in transit. The tun carries what the mesh delivers to this host and the
networks behind it, what the host sends or its kernel forwards into it from its
other links, which [the checks at the mesh's edge](../routing.md#transit) meet,
and, on an exit, the egress it hands the host to carry out. An exit or a subnet
router carries transit the same way, so transit for a prefix another node
announces never leaves by the uplink.

A packet this node does not forward is answered as a router answers it, from the
node's router-id: Time Exceeded at a hop limit or TTL of 1, Packet Too Big or
Fragmentation Needed past the next session's size, and Destination Unreachable
with no route or inside a held prefix. [Routing](../routing.md#transit) lists
the answers and their codes.

[`cap.egress`](../exit-nodes.md) still reads the host's forwarding, for what an
exit sends out of its uplink. A prefix an exit node offers to carry is
advertised only while its family's 2 chains, its set and its timeout objects
read back exactly as written, with no other writer's rule in its chains and in a
table with no flags, the host forwards the family, holds every address its
classes name and, where they run, the kernel's lookups of a translated packet
and its reply pass. It is retracted on the first pass that finds any of them
untrue. A pass runs every 30 seconds unless `cap.egress.sweep` names another
interval.

With transit off, a node advertises only the prefixes it announces and never
relays one it learned. A packet for another node that reaches it all the same is
answered administratively prohibited, unless an End.DT46 SID of this node
delivering to the mesh took it out of its outer header. Transit is off unless
[`cap.transit`](../configuration-reference.md) writes `enable = true`, and a
leaf leaves it out. Refusing to advertise cannot close a loop, so this only
narrows what the feasibility condition already bounds.

**A host's own tunnel through the mesh has its inner sources checked.** The
forwarding decision opens every IPv6 read off the tun that ends at an inner IPv4
or IPv6 packet, one level deep, since the mesh keeps no registry of other nodes'
SIDs to tell a host's own IP-in-IPv6 or 6in6 tunnel from a packet steered to a
SID. A tunnel to a peer's overlay address, carrying traffic a host forwards for
a LAN, therefore has its inner sources judged as the host's own: a LAN source
the node does not own is dropped toward a default as `unowned_source`, and one
the table routes to another node is `forged`. An operator tunneling a LAN
through the mesh announces the LAN's prefix, which makes its sources the node's
own, or carries the tunnel in UDP, which the walk does not open.

**The inner check covers what ranet3's own SIDs decapsulate.** The walk stops at
a fragment header or an authentication header without opening what follows, and
ranet3's own `End.DT46` decapsulates no packet behind either. An `End.DT46` of
another implementation processes the extension headers before the upper-layer
header, as
[RFC 8986 section 4.8](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.8)
has it, and may decapsulate a packet behind them. A packet carried that way to
such a SID passes this node with its inner packet unchecked.

**A prefix only one of two nodes announces is dropped at the other.** A packet
from a subnet two nodes can reach, announced by only one of them, has at the
other a source the table routes to the announcing node, so a read of it is
dropped there as `forged`, whatever its destination. An anycast source a node
does not announce is dropped there the same way, as `forged` where another node
announces it or it lies in the overlay, and otherwise as `unowned_source` toward
a route that counts as a default. Both are fixed by announcing the prefix at the
node that drops them.

**A steered packet is checked before it is steered.** A packet
[`cap.segment.steer`](../segment-routing.md#steering) steers is judged by the
destination it was read with, before the steer puts its segment list on. It is
dropped as `forged` wherever any read would be, and a steered packet whose
source this node does not own is otherwise dropped, as `unowned_source`, only
where a route counting as a default covers that destination. A steer toward a
destination no route covers has no owned-source check yet. The arm that would
add it waits for the steering mode that carries such a packet.

## Who a node dials

`dial.all` dials every other node the trust document names. Entries in `dial.to`
still apply and win for their node, which is the only way to pin a `serial`. A
node needs `dial.all` when its peers relay no learned routes, as a node with
transit off does. It then learns each prefix only from the node that originates
it, so dialing a few exits reaches those exits and nothing behind them.

## The underlay socket

On Linux the UDP sockets that carry IKE and ESP stay out of reach of the routes
the mesh installs where the process may set the mark: a marked datagram bound to
no device ends at row L1 or L2 of
[where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux), an
IPv4 reply pinned to the interface its request arrived on as row B1 gives, and
an IPv6 one, which also names the address its request arrived at, as row L2
gives. The head of that account says what another program's rule or another
writer's route does. On macOS with `link.underlay.bind` they stay out of reach
as row D4 of
[where a lookup ends on macOS](../routing.md#where-a-lookup-ends-on-macos)
gives. On macOS without it, the reconciler scopes a route of the mesh covering a
literal endpoint address the trust document lists, while an endpoint written as
a hostname has no listed address, so a route of the mesh covering the address it
resolves to goes in unscoped unless it is a hold, carries a source prefix or
counts as a default, row D5. The transport binds the wildcard address, and for a
session this node dialed it lets the kernel pick each datagram's source by
route. On a node whose mesh address is its only global address of a family, the
kernel picks that address. An unmarked datagram looked up from it, as on a
socket connected from it, would end as rows L6 to L12 give, and where that is
row L11, the ESP underlay would go into the tun that carries it.

On Linux every underlay socket carries `SO_MARK` 0x72, a constant no key sets,
where the process may set it, as
[sharing a host](../coexistence.md#the-underlays-mark) says. The mark and the
rules that read it come from 1 constant, so neither can name a mark the other
does not. A node configuring its routes elsewhere writes no `cap.table`, and a
rule reading the mark goes wherever those routes do.

On Linux the endpoint resolver marks its query the same way, where the process
may set the mark, when the nameserver lies outside `cap.border.overlay`. Where
`cap.table` is written the query then ends at row L1 or L2, on the host or by
its own routes, so it never waits on a session that only the name it asks for
can dial. A nameserver in a subnet another node announces outside the overlay
keeps the mark for that reason, since the subnet is reached through a session. A
nameserver on the host itself, such as systemd-resolved's `127.0.0.53`, takes
the query at row L1, and its own query upstream carries no mark, so it can wait
on such a session. A query to a nameserver inside the overlay carries no mark,
whatever zone follows its address in `/etc/resolv.conf`, and where `cap.table`
is written ends as rows L1 to L5 give. A link-local nameserver lies outside an
overlay of the mesh's own prefixes, so its query is marked where the process may
set the mark. An IPv6 one ends by main's route out of the link its zone names,
and an IPv4 one at row L2 by main's route for it.

`link.underlay.bind` is `IP_BOUND_IF` and `IPV6_BOUND_IF`, macOS only. It binds
the socket to the interface the host's own default route leaves by. When that
interface changes, ranet3 moves the binding with `setsockopt` on the live
descriptor, so a laptop crossing from Wi-Fi to a dock keeps every SA. The
binding scopes that socket's route lookups to that interface, which on macOS is
the only way to make a real default out of the tun safe.

With `bind` set, the reconciler installs a plain `/0` as its zero-free cover, 8
unscoped routes per family that hold every address but `0.0.0.0/8` and `::/8`,
as [routing](../routing.md#the-zero-free-cover-on-macos) describes. Any other
route that carries the host's own traffic is installed unscoped too, unless it
covers a literal endpoint address the trust document lists or carries a source
prefix. Without `bind`, the reconciler scopes every route that counts as a
default to the tun, as [platforms](../platforms.md#macos) describes. No unbound
socket selects a scoped route. A node without `bind` can hold an exit-announced
address and still cannot send its traffic through the exit.

## The scoped default on macOS

Binding is necessary but not sufficient on its own. `IP_BOUND_IF` does not take
a socket out of the forwarding table: the scoped lookup still finds the most
specific route, and where that route leaves another interface it falls back to a
longest-prefix match on the family's zero address, which must be on the bound
one. So while an unscoped route out of another interface holds `0.0.0.0`, such
as a real `0.0.0.0/1` out of the tun, a bound socket answers `ENETUNREACH`
unless the underlay's own interface carries a default scoped to it, the route
`route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>` writes. macOS
writes exactly that for every interface but the primary one.

The zero-free cover holds no zero address, so it leaves that fallback to the
host's own default. Its members take every other address from the host's default
by longest prefix.

ranet3 writes the scoped default, and it is the only route this tree puts out of
an interface it does not own, so the rules around it are narrower than the
tun's.

It is written for a family only while an unscoped route out of an interface
other than the underlay's holds that family's zero address. That is a route the
reconciler wants that is not a cover member, or another program's route out of
an interface that is neither the tun nor the underlay's. Scoped, cloned,
link-layer and reject routes do not count. With only the cover installed,
nothing is written outside the tun, and the host's own router selection
([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861) section 6.3.6) stays in
charge of its default.

The reconciler asks the underlay on every pass, and the transport asks before it
moves the socket onto another interface. The underlay reads the table, writes a
missing scoped default before it answers and withdraws one no family needs any
more. A pass that deletes a capturing route that is not a cover member asks a
second time after the deletes, so the default it no longer needs goes in the
same pass. Under `bind` the platform watcher wakes a pass on a route change
anywhere on the host, so another program's capture strands a bound socket for
the 250 millisecond settle and 1 pass at most. A Mac measured 240 milliseconds
from another program's `0.0.0.0/1` to the scoped default and 264 milliseconds
from its removal to the withdrawal. 40 changes of a host route in a burst cost
it 1 pass.

A route the reconciler would install unscoped over a zero address is left out of
the pass while its family has no scoped default, and so is the cover of a family
the host has no default of its own for. Neither is installed, and a copy already
in the kernel is withdrawn, such as after the host's default moves to another
interface. A route over no zero address, such as a real `128.0.0.0/1`, needs
neither. The check is per family, because a bound socket falls back only to the
default of the destination's own family. A scoped IPv4 default does nothing for
a `::/1` route.

It is reconciled rather than remembered. The kernel drops this route on its own,
clearing `IFF_UP` purges it and bringing the interface back up does not restore
it, so every pass reads the table back and writes what is missing. A record
saying it was written says nothing about whether it is there. The record is the
claim to delete it and nothing else.

It follows the host's own default: the interface it is going to is written
before the socket moves onto it and the one it left is cleared after that, which
leaves no moment with no usable route. When the next hop changes on the same
interface, the old route is withdrawn before the new one is written. Only a
route this tool recorded writing is ever withdrawn, only after a readback finds
it still carrying `RTF_IFSCOPE`, the recorded interface and the recorded next
hop, and a delete that is not interface-scoped cannot be encoded at all. An add
that answers `EEXIST` is success and not ownership, so a route macOS wrote for a
secondary interface is used and never removed. At shutdown nothing is withdrawn
while a capture is still in the kernel, so a withdrawal that failed upstream
cannot take the fallback away from under one.

The record outlives the process. It is written to
`/var/run/ranet3/underlay.json`, beside the control socket's lock, before the
route is written and after it is withdrawn, so a daemon killed with `SIGKILL` is
cleaned up by the next one rather than leaking. That is the same ownership claim
made durable, not a weaker one: a restart withdraws a recorded route only when
the kernel still holds one matching its destination, interface index, next hop
and `RTF_IFSCOPE`, only when the recorded interface name still resolves to the
recorded index, and only when that interface also carries the host's own
unscoped default. The last clause separates ranet3's route from the system's,
because macOS writes a scoped default for every interface except the one holding
the unscoped default. `TestNoOtherProgramScopesADefaultToThePrimaryInterface`
asserts that on whatever machine the suite runs on rather than taking it on
trust. A record failing any clause is kept where nothing in the process can
delete it, so the clauses are not undone by the next ordinary withdrawal, and
the next start weighs them again. The file is locked before it is read, so a
second daemon starting beside a running one reclaims nothing and overwrites
nothing.

A state file that is unreadable, truncated, not JSON or holds more than 32
records is reported and treated as empty, because a node that will not start is
worse than a route left behind. A missing one is treated as empty without a
report.

The last clause has 1 gap. It is a snapshot, so a host that makes another
interface primary while ranet3's route is in place, and later makes it primary
again, could have a restart withdraw a scoped default macOS wanted there. That
is 1 route on 1 interface until the next link event, which macOS answers by
rewriting it.

## Routes that carry the host's own traffic

On Linux and macOS, a route that would carry this host's own traffic is held
back until at least 1 session is live. It is withdrawn once none has been live
for `cap.table.capture_grace` (10 seconds by default), and restored on the next
live session. Such a route is one that
[counts as a default](../routing.md#routes-that-count-as-a-default). A hold of
such a route, and this node's own prefix that counts, are never installed, and
an [exit](../exit-nodes.md#an-exits-own-traffic) installs no such route at all,
live session or not.

On Linux the kernel's holds do not refuse a socket bound to the uplink's device,
as rows B1 and B2 of
[where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) give. Its
packet to a held subnet outside the overlay leaves by a route of main longer
than /0 out of the uplink where one covers it. Otherwise, and to an overlay
address under the overlay's hold, an unmarked one goes over IPv4 onto the
uplink's link for the destination itself, where before ranet3 it went by main's
route, and a host of that link holding the address receives it, and over IPv6 by
main's route out of the uplink, where it went before ranet3. A marked one, such
as ranet3's own paired IPv4 socket, goes by main's route, as rows L2 and B1
give. None of it enters the mesh.

The rule about the unspecified address follows the macOS kernel. A bound
socket's lookup falls back to the route for the unspecified address of its
family, and needs that route on the bound interface. A route out of the tun as
small as `0.0.0.0/24` takes that fallback away.

`capture_grace` has a floor of 1 second. A value above 0 and under 1 second is
refused by name, and 0 takes the default. The hold is checked once a pass, and
each pass reads the routing table, so a shorter grace would only make passes
more frequent. The reconciler wakes for the grace only while a capturing route
is in play.

A session counts as live for 20 seconds after it last received authenticated IKE
from its peer, and for 20 to 30 seconds after its last authenticated ESP, which
the session notices up to 10 seconds late. It counts only while the underlay
socket is where `link.underlay` says it should be. Without that rule a laptop
whose mesh has gone loses every network it has rather than only the mesh, and it
cannot recover on its own, because reaching the peers needs the network the
default just took.

On macOS an unscoped `/0` out of the tun would collide with the host's own
default, because macOS has no route replace. With `bind` set, the reconciler
installs it as the zero-free cover instead, and the hold judges the cover by its
`/0`. The cover's members stay unscoped even over a literal endpoint address the
trust document lists, because the transport's socket is bound to the underlay
interface. An exit serving Macs advertises the `/0` only, as
[exit nodes](../exit-nodes.md#what-to-advertise) describes.

## Source-specific routing

ranet3 implements source-specific routing
([RFC 9079](https://www.rfc-editor.org/rfc/rfc9079)). The mesh's route table is
keyed by `(source, destination)` prefix pairs. A lookup uses each packet's real
source address as it arrives on the tun, not a single configured address.

The destination comes first. The longest destination that holds an entry whose
source matches wins. Among that destination's entries, the longest matching
source wins. A destination with no matching source falls back to a shorter
destination.

## The tun device

**ranet3 does not manage the tun device's address or routes unless you ask it
to.** It creates the device and brings it up. On Linux it attaches instead to an
existing device that `link.tun` names, but never to one of the default name
`ranet3`. An optional reconciler, `internal/kernel`, mirrors the learned routes
into 1 routing table it owns, or on macOS into the single table that platform
has. On macOS without `link.underlay.bind` it scopes the routes that would
otherwise capture the host, on Linux its policy rules give a route that counts
as a default by its length the traffic from this node's own prefixes to a
destination outside the overlay, for a lookup bound to no device where the rows
before it pass the lookup on, as rows L6 to L12 of
[where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) give, and it
can assign the configured addresses. The `cap.table` block in
[the configuration reference](../configuration-reference.md) turns it on. It is
off unless enabled. Without it, another program assigns the addresses and
installs the kernel routes.

## Babel

Babel only exchanges control packets inside authenticated ESP tunnels. A local
routing daemon cannot peer with the embedded speaker over the tun. Learned
routes select the outgoing ESP peer after the kernel has routed a packet to the
tun.

IPv4 announcements use the control link's IPv6 link-local next hop, AE 4 of
[RFC 9229](https://www.rfc-editor.org/rfc/rfc9229). A peer has to accept IPv4
routes with an IPv6 next hop. AE 4 updates are accepted on receive, and so are
ordinary IPv4 updates that follow an IPv4 Next Hop TLV in their packet.

The Babel control state and forwarding publication share 1 mutex. Selection runs
over feasible routes only, against the source table. A speaker that
re-advertises what it learns cannot rely on the structural loop freedom of
[RFC 8966 Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E).
Every finite advertisement leaves through 1 function, which records the
feasibility distance before the packet is built. Local prefixes take precedence
even after a router id change. Remote Hello, IHU, and Update expiration is
scheduled independently of local send intervals.

When a neighbor comes up, a node sends it a Hello at once and asks it for its
whole table with a wildcard Route Request, which
[RFC 8966 section 3.8.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.8.2)
allows at any time. The end that dialed, which can start its session just after
its neighbor, then learns the neighbor and its routes about 1 round trip after
the neighbor hears it, not after the neighbor's next Hello and next periodic
update, up to 4 and 16 seconds at the defaults. A neighbor that sends no Hello
when a session comes up is learned at its next Hello, up to 1 hello interval
later.

## Dataplane

On Linux, ranet3 opens 1 tun queue per CPU the Go runtime uses, up to 256, and
keeps each inner flow on 1 queue. When the Go runtime uses more than 1 CPU, an
existing named tun must therefore be created with `IFF_MULTI_QUEUE` (for a
systemd-networkd `.netdev`, set `MultiQueue=yes` in its `[Tun]` section). A
process on 1 CPU can also attach to a single-queue tun. ranet3 sets that
device's `gso_max_segs` to the 128 packets 1 read holds, so the kernel splits a
larger GSO frame before a read would cut it. 1 read lays its packets out in 1
buffer of 131070 bytes, which holds the largest GSO frame the tun hands over and
a packet of 65535 bytes, whatever `link.mtu` is.

Tun readers hand bounded batches to shared encryption workers, and sequence
reservation and queue submission preserve packet order across workers. Each peer
admits a read's packets against a budget of its own, 5,734,400 bytes with each
packet counted as at least 1400 bytes, without waiting. The packets of a read
bound for a peer whose budget lacks room are dropped and counted, so a peer
whose transport stalls costs the others nothing. The budget lasts about 5
milliseconds at 10 Gbit/s and 15 milliseconds at 3 Gbit/s, and holds at most
4096 packets. A read larger than the whole budget is taken only when the peer
holds nothing else, and above a `link.mtu` of about 45 KB such a read, cut into
fragments for a narrow session, can carry more than 4096. Its sender bounds the
delay through that queue with CoDel, dropping 1 packet at the head once the
delay has stayed above 5 milliseconds for 100 milliseconds. The readers wait
only for the read batches every peer shares.

Packet lookups read an immutable SADR trie snapshot without locking. Route
changes copy the affected path and publish it atomically. Diagnostics iterate
the same snapshot. ESP batches similarly capture an immutable set of installed
SAs, retaining keys for work already in flight during a rekey. Receive
processing on 1 core runs inline. Multicore receive workers authenticate
concurrently and commit replay state in intake order before delivering tun
batches. Each packet is decrypted in place and written to the tun from the
datagram it arrived in, whose 16 bytes of ESP header and IV are the room a tun
write takes in front of a packet. No packet is copied between decryption and the
tun, and a packet an exit takes out of its outer header is written from the same
datagram. Linux UDP receive reads a full vector, of 128 messages on a shared
socket and 4 on a socket connected to 1 peer, and returns excess GRO segments
before reusing its buffers. Replay checks and nonce storage are amortized across
ESP batches, and already-completed send/receive batches are combined without
waiting for additional traffic. Encryption workers reuse packed ciphertext
buffers only after the ordered sender finishes its UDP call, retaining separate
storage for work in flight. Replaced inbound SAs remain usable for 5 seconds
after their Delete acknowledgment, or until their lifetime ends if that comes
first, so queued and reordered packets can drain during a rekey.

## Paths under 1280 bytes

On Linux and macOS ranet3 does not let its own datagrams fragment, outside 1
case. There each session searches its path for the largest packet it carries,
between 1280 and `link.mtu`, and a larger packet is answered with Packet Too Big
or fragmentation needed, or cut when it is IPv4 without DF, or dropped where it
cannot be cut, as [path MTU](../path-mtu.md) describes. A path that cannot carry
1280 bytes in 1 datagram is under the floor. 1280 bytes is the least IPv6 asks
of any link. An IPv4 path is under the floor below 1344 bytes, and an IPv6 path
below 1364 bytes. A session on such a path holds its budget at 1280 and lets the
host fragment its datagrams.

On Linux, while any session of a family is under the floor, that family's
sockets let the host fragment their datagrams, the shared one and each one
connected to 1 peer. The IPv4 sockets set `IP_PMTUDISC_DONT` and send without
DF. The IPv6 sockets set `IPV6_PMTUDISC_WANT`. Every other session of that
family pauses its search meanwhile, because a probe the host may fragment
measures nothing. macOS does the same for IPv4, because `IP_DONTFRAG` holds for
a whole socket. For IPv6 it lets only that session's datagrams fragment. A
session under the floor sends 1 datagram per message rather than segmenting.

Fragmenting has 3 limits. IPv6 is fragmented only where it is sent, so an IPv6
path under 1364 bytes whose narrow hop sends no Packet Too Big stays a black
hole. Every 10 minutes the session confirms the floor with DF again, so behind
such a hop it can lose its largest datagrams for up to 18 seconds every 600
seconds. And under sustained loss of fragments the receiver's 4 MB of reassembly
memory fills with datagrams that never complete, and it then reassembles nothing
until they expire, in both families. A steered IPv6 packet of 1280 bytes through
a narrow session is lost too, as [segment routing](../segment-routing.md)
describes.

An IKE message does not wait for the host to fragment it. Where both ends sent
`IKEV2_FRAGMENTATION_SUPPORTED` in `IKE_SA_INIT`, as ranet3 always does, a
message larger than the path goes in the fragments of
[RFC 7383](https://www.rfc-editor.org/rfc/rfc7383.html), each cut to fit the
threshold: the path MTU the host holds for the peer, or 1280 bytes for IPv6 and
576 for IPv4 where the host knows none or a smaller one. `IKE_SA_INIT` always
goes whole. A request that goes unanswered twice under a threshold above its
family's floor steps to the floor at its next send, the schedule's or a probe's,
as a network change or `ranet3 debug probe` asks for one. A request too large to
go whole at the floor is cut for it at the step, and its waits start over. A
request that fits the floor whole, such as a liveness check, only moves its
threshold and keeps its 5 sends over 62 seconds. From a step that cuts a request
down to the floor, taken on the path the request was readied or last cut on,
which every send of it went on since, the step's own included, the session's
threshold is the floor for every later message, request or answer, across rekeys
of its IKE SA. That lasts until a send or a status read finds the peer's address
or port or the path MTU the host reads changed since the step, or until the
session is asked to probe its path, as each network change asks. A step that
cuts nothing leaves later messages at the path's threshold, since its sends were
no larger than the floor. So does a step where a send of the request since its
readying or its last cut, the step's own included, found that the peer moved,
that the path MTU the host reads changed or that the session probed its path,
even where the step finds the path as it was then, since that send went on a
path that may have differed. A path that widens where the host sees no change
keeps the floor until one of those comes or the session ends, the suboptimal
fragmentation the downward search of RFC 7383 section 2.5.2 accepts. A narrower
hop that sends no ICMP message, or one beyond the interface on macOS, which
reads only the interface's MTU, then delays a session by 6 seconds once instead
of failing it, and its later exchanges start at the floor. An answer never steps
down by itself. It is cut for the path's threshold at each send, and within the
largest datagram of the peer's request in fragments, or of the repeat that draws
it again, where that is smaller, never under the floor. A responder behind such
a hop thereby follows the initiator's step, and the first answer to a request in
fragments already fits the datagrams that request came in.

## ML-KEM and the path

A kex entry joined by `mlkem768` or `mlkem1024` adds 1 `IKE_INTERMEDIATE`
exchange to the handshake, as
[`cap.crypto.ike`](../configuration-reference.md#capcryptoike) describes. Its
request carries the ML-KEM-768 encapsulation key in an IKE message of 1249
octets, a datagram of 1281 bytes over IPv4 and 1301 over IPv6 with the Non-ESP
Marker and the UDP and IP headers. Its response carries the ciphertext in 1153
octets, a datagram of 1185 and 1205 bytes. ML-KEM-1024's key makes the request
1633 octets, a datagram of 1665 bytes over IPv4 and 1685 over IPv6.
`IKE_SA_INIT` carries no ML-KEM key. A joined entry adds to the `IKE_SA_INIT`
request a proposal of its own, which holds an `ADDKE1` transform of 8 octets,
and an `INTERMEDIATE_EXCHANGE_SUPPORTED` notify of 8 octets.

An IKE SA rekey that runs a joined entry, either end's, and a peer's Child SA
creation or rekey that runs one add 1 `IKE_FOLLOWUP_KE` exchange after the
`CREATE_CHILD_SA`. Its request carries the same key and the 16-octet
`ADDITIONAL_KEY_EXCHANGE` notify that links it to the `CREATE_CHILD_SA`, an IKE
message of 1265 octets, a datagram of 1297 bytes over IPv4 and 1317 over IPv6.
Its response carries the ciphertext in 1153 octets, as above. With ML-KEM-1024
the request is the 1265 octets with the 384 more that its key adds, 1649 octets,
a datagram of 1681 bytes over IPv4 and 1701 over IPv6.

Linux and macOS send IKE with DF, so a message larger than the path never
arrives whole. To a peer that supports RFC 7383 it goes in fragments, as
[paths under 1280 bytes](#paths-under-1280-bytes) describes. The ML-KEM-768
request of 1301 bytes over IPv6 crosses a 1280-byte path that way, and the
requests of ML-KEM-1024 cross a 1500-byte one, in a rekey's `IKE_FOLLOWUP_KE`
too and at the IPv4 floor of 576 bytes as well. A peer without RFC 7383 still
needs the whole path. There a path that carries less than the request, such as
an IPv6 path at the 1280-byte minimum or a tunnel of 1280 bytes, loses it. The
handshake then fails, and a rekey's `IKE_FOLLOWUP_KE` goes unanswered until the
IKE SA is deemed failed and the session ends. The one exception is a family
whose sockets let the host fragment while a session of that family is under the
floor, as above.

## Limits by area

Each table gives a fixed bound, its value, and what happens past it. Bounds you
can configure are in
[the configuration reference](../configuration-reference.md).

### IKE

| Limit                                          | Value                                                                                   | Past it                                                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Half-open SAs before a cookie                  | 32 in all, or 2 from 1 address                                                          | An `IKE_SA_INIT` without a valid cookie is answered with one (RFC 7296 section 2.6)                    |
| Half-open SAs                                  | 256 in all, 16 from 1 address                                                           | A further `IKE_SA_INIT` is dropped unanswered, and its sender retransmits                              |
| Error answers sent in the clear                | 256 at once, then 32 a second, for the whole node                                       | A further one is not sent, and at most 1 log line every minute counts those held back                  |
| Responder handshake                            | 30 seconds                                                                              | The handshake is abandoned                                                                             |
| `IKE_INTERMEDIATE` exchanges in a handshake    | 1 for each additional key exchange of the chosen kex entry, at most 1                   | A further one, or an `IKE_AUTH` ahead of the last, is answered `INVALID_SYNTAX` and the handshake ends |
| Wait for a peer's next `IKE_FOLLOWUP_KE`       | 62 seconds from this end's last answer in the rekey                                     | The peer's rekey is dropped, and its next `IKE_FOLLOWUP_KE` is answered `STATE_NOT_FOUND`              |
| Rekeys in a row answered `STATE_NOT_FOUND`     | 3                                                                                       | The IKE SA is deleted, and the session ends                                                            |
| Canceled dial's wait for its `IKE_AUTH` answer | 2 seconds                                                                               | The dial ends, and a peer whose answer is late keeps its session until liveness fails                  |
| Sends of a request not cut again               | 5, waiting 2, 4, 8, 16 and 32 seconds after each                                        | The exchange fails after 62 seconds, and its IKE SA is deemed failed                                   |
| Sends while the peer's other traffic continues | 20, about 9 minutes in all                                                              | The exchange fails, and its IKE SA is deemed failed though the peer's ESP still arrives                |
| Silence before a liveness check                | 10 seconds                                                                              | The session sends an `INFORMATIONAL` request, retransmitted on the schedule above                      |
| Live session                                   | 20 seconds since the peer's last authenticated IKE, 20 to 30 seconds since its last ESP | The session no longer counts as live                                                                   |
| Reconnect delay                                | 10 seconds                                                                              | A dialer whose session ended waits this long before it dials again                                     |
| Sends of the Delete that ends an IKE SA        | 2, waiting 2 and 4 seconds after each                                                   | The IKE SA is deemed failed after 6 seconds                                                            |
| SA lifetime                                    | `cap.crypto.rekey.child` and `cap.crypto.rekey.ike`                                     | A Child SA goes unused and an IKE SA starts only its Delete, and with no rekey the IKE SA is deleted   |
| `TEMPORARY_FAILURE` answers on 1 IKE SA        | 5 minutes with no rekey of either SA completed by either end                            | The IKE SA is deleted, and the session ends                                                            |
| Peer rekeys                                    | 1 per second for each kind of SA                                                        | A faster rekey is answered `TEMPORARY_FAILURE`                                                         |
| Replaced Child SA awaiting the peer's Delete   | up to 30 seconds, then this end deletes it                                              | Every Child SA rekey in either direction, and a peer's IKE SA rekey, is refused meanwhile              |
| Replaced IKE SA awaiting the peer's Delete     | up to 2 minutes, and no longer than its lifetime                                        | A peer's IKE SA rekey is answered `TEMPORARY_FAILURE` meanwhile                                        |
| Messages in reassembly                         | 1 for each direction of an IKE SA, beside the repeats below                             | A fragment of another message drops the fragments held                                                 |
| Fragments of 1 message in reassembly           | 16 KiB of the IKE messages they came in                                                 | The IKE SA ends, and a dial fails                                                                      |
| Wait for the rest of a message's fragments     | 62 seconds from the first fragment of its cut                                           | The fragments held are dropped                                                                         |
| Answers to the peer's repeats of 1 request     | 20 from the peer's own address and port                                                 | A further repeat from there draws nothing                                                              |
| Other addresses repeating 1 request            | 4, each with a credit of the bytes it sent repeating it                                 | A newcomer takes the place of the one heard from least recently                                        |

The second row holds even for a request with a valid cookie. More than 16 nodes
behind 1 NAT that restart at once therefore wait for their retransmissions.

The errors the third row limits are `INVALID_MAJOR_VERSION`,
`UNSUPPORTED_CRITICAL_PAYLOAD` and `NO_PROPOSAL_CHOSEN`, sent in the clear to a
request that no IKE SA protects. Each of them ends the exchange. A `COOKIE`, an
`INVALID_KE_PAYLOAD` and an `IKE_SA_INIT` response that carries the handshake
forward are outside the limit: an initiator goes on after each of them, and one
source that spends the limit cannot stop another's dial. A `COOKIE` is the
defense against a flood of `IKE_SA_INIT` requests that
[RFC 7296 section 2.6](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.6)
gives a responder. An `INVALID_KE_PAYLOAD` is 1 IKE message of 38 octets
answering a request of at least 102 octets, and it gives its half-open slot back
as it is sent. Neither cookies nor the half-open limit bound how many go out. An
`IKE_SA_INIT` response holds its half-open slot until `IKE_AUTH`, and the
half-open limits and cookies bound it. The burst of 256 error answers can answer
every half-open slot at once, and the rate of 32 a second fills the burst again
within the reconnect delay.

No ML-KEM key travels in `IKE_SA_INIT`. A responder runs ML-KEM only for an
initiator that holds a half-open slot, past the cookies. The responder's 30
seconds for a handshake cover its `IKE_INTERMEDIATE` exchange. A half-open SA
that has answered one keeps the answer as it was sent, to answer a retransmitted
request: the sealed message, its inner payloads in plaintext and its datagrams,
with digests of the request and the 2 values of IntAuth. That is 2249 octets for
an ML-KEM-768 answer sent whole (1153 and 1096), 3528 for one cut at the IPv4
floor, and 5029 for an ML-KEM-1024 answer cut at the IPv4 floor (1633, 1576 and
1820 in 4 datagrams). The 256 half-open SAs keep up to 1,287,424 octets of it,
under 1.25 MiB, whatever the initiators send.

An IKE SA gathers 1 message of the peer's in fragments for each direction, the
peer's requests and its answers to this end's. The fragments of a message are
held only within 16 KiB, counted as the IKE messages they carry, headers, IV and
ICV included, rather than as their decrypted content. Past that limit:

- an established session closes without a Delete, logs a warning and records
  `ike.sa.closed` with the reason `fragment limit`
- a replaced or redundant IKE SA still kept for a Delete ends alone
- a half-open SA ends
- a dial fails

Fragments left incomplete go after 62 seconds, the sends of one cut of a
request. That is shorter than the 68 seconds of a request that the step cuts for
its family's floor, as
[RFC 7383 section 2.6](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.6)
allows: "Implementations can use a shorter timeout to conserve memory." Each new
cut, which comes with a larger Total Fragments, starts the message over. A
half-open SA's fragments go with the SA at the 30 seconds of its handshake,
before that.

Beside its own queues, the exchange an IKE SA last answered holds up to 4
repeats from other addresses in reassembly, 1 for each credit below, each within
the 16 KiB and gone at the next exchange, after the 62 seconds or with the SA.
An established IKE SA thus holds at most 6 messages in reassembly, a half-open
SA 5, since it takes no answer, and the 256 half-open SAs at most 20 MiB of
fragments. Fragments from a peer that did not send
`IKEV2_FRAGMENTATION_SUPPORTED` are dropped before anything of them is held.

A peer's repeat of a request this end has answered draws the kept answer again
under 1 rule wherever it comes: in a half-open SA's wait for `IKE_AUTH`, whose
initiator holds the keys before it has authenticated, and past `IKE_AUTH`, where
anyone who captured a fragment of the request can replay it from any address.
The origin is the peer's own address and port: in a half-open SA the one the
`IKE_SA_INIT` came from, and past `IKE_AUTH` the session's endpoint, where the
peer's last fresh request came from. From the origin a repeat draws the answer
on the request whole as it came or on its fragment 1, at most 20 times in each
exchange, the bound on the sends of 1 request that ranet3 counts. Every counted
repeat of a peer that resends as ranet3 does is answered, the 7 sends of a
request that the step cuts for its family's floor among them. A probe that cuts
nothing resends a request without counting it, which lets a peer asked to probe
its path many times in 1 exchange send more, and its repeats past the 20 draw
nothing. From any other address and port, only the request whole as it came, or
the whole set of its fragments from there reassembled to the request's content,
draws the answer, which goes there. It draws it only within the bytes that
address sent repeating the request in the exchange, each datagram counted with
its IP header, UDP header and Non-ESP Marker. Each answer there spends its
datagrams as that send cuts them. An answer the credit does not cover draws
nothing, a later repeat adds to the credit, and the answer spends that address's
credit alone and nothing of the origin's 20. The exchange keeps such a credit,
with that address's repeat in fragments, for at most 4 addresses. A newcomer
past them takes the place of the one whose last datagram came least recently,
and the exchange forgets them all at the next one. A repeat never touches the
queue the next request is gathered in.

So an address that never proved it receives draws no more bytes than were sent
in its name, a moved initiator is answered 1 retransmission later, and a
datagram replayed from a third address takes nothing from it or from the origin.
To hold a moved initiator, an observer has to send from more than 3 fresh
addresses between every 2 of its datagrams, and one that keeps up that rate can
hold it until its exchange times out. A datagram replayed in the origin's own
address and port spends the origin's count, so a captured fragment 1 can aim at
most 20 answers an exchange at the origin: 38,960 bytes on the wire for an
ML-KEM-1024 answer at the IPv4 floor. When the path MTU falls before every
answer, the 20 come to up to 78,020 bytes over IPv4 and up to 83,500 over IPv6.
An ML-KEM-1024 answer is kept in at most 4 datagrams at or above the IPv4 floor
and in at most 2 at or above the IPv6 floor, and each fall cuts it into 2 more.
Its 20 answers then run from 6 to 44 datagrams over IPv4 and from 4 to 42 over
IPv6, where each datagram's IP header takes 40 bytes against IPv4's 20.

The wait for a peer's next `IKE_FOLLOWUP_KE` is the time this end resends 1 cut
of a request to a silent peer, 62 seconds, and each answer in the peer's rekey
starts it again. A peer's new rekey of the same SA drops the earlier one before
its wait ends. Either way the dropped rekey records `ike.followup.dropped`, as
[debugging](../development/debug.md#events) describes. This end's own
`IKE_FOLLOWUP_KE` is resent as any request is, until it is answered or the IKE
SA is deemed failed, and its answer settles the rekey whenever it comes. Through
a step to the floor and 1 or 2 falls of the path MTU its sends still come within
the peer's wait. The last comes at most 40 seconds after the answer before it
where the schedule's own sends see the falls, and at most 52 where probes see
them, since each cut starts the count of sends toward the step over and a
probe's send adds nothing to it. A chain of falls can carry the last send past
it: 4 falls that probes see, or 13 that the schedule's sends see. A
`STATE_NOT_FOUND` that answers a send made 62 seconds or more after the answer
before it fails the rekey without counting toward the 3 in a row, since the peer
was free to drop the rekey by then. The schedule retries a failed rekey after
its backoff, and no SA is lost. A session sends no liveness check, not even when
asked to probe its path, while its own rekey may run `IKE_FOLLOWUP_KE`
exchanges, nor while it waits for the peer's after losing a simultaneous rekey
to it. That wait ends when the peer's rekey replaces the IKE SA or is dropped,
or when the IKE SA starts to close.

An IKE SA deemed failed ends the session when it is the session's current IKE
SA, and the node that dialed it dials again. A replaced or redundant IKE SA
still kept for a Delete holds no Child SA once the rekey has moved them to its
successor. It alone ends, and the session goes on.

The 5 sends of a request are those of 1 cut. A request that steps to its
family's floor from a threshold above it, and is too large to go whole there, is
cut for the floor at the step as
[paths under 1280 bytes](#paths-under-1280-bytes) describes. It is sent 7 times,
at 0, 2, 6, 8, 12, 20 and 36 seconds, and fails after 68 seconds. A request
whose threshold is already the floor takes no step. That covers an IPv6 path of
1280 bytes, an IPv4 path of 576, a path whose MTU the host cannot read, as on
FreeBSD and OpenBSD, and a session an earlier step holds at the floor, as that
section says, until the floor ends there. Such a request, where it is too large
to go whole, is cut for the floor at its first send. It keeps its 5 sends over
62 seconds, as does a request that fits the floor whole, such as a liveness
check, through any step. Each cut again for a path MTU that fell starts its
waits over, up to 20 sends, which bound the sends of every request this end
counts however it is cut. A request is sent up to 20 times while the peer's
authenticated traffic has arrived within the last 10 seconds. The exchange holds
the only outstanding request this end allows. Rekeys, Deletes and liveness
checks wait until it ends. A liveness check and a Delete of an IKE SA never take
the longer schedule, and neither does an exchange still outstanding when its IKE
SA reaches its lifetime. A request on the session's current IKE SA waits behind
the Delete of a replaced or redundant IKE SA for at most 6 seconds. Behind a
liveness check left on an IKE SA the peer rekeyed, it waits for that check's 5
sends, up to 62 seconds, unless the peer's Delete of that IKE SA ends the check
first.

Every Delete of an IKE SA has the 2 sends, since a peer that took it has deleted
the SA and ignores a resend, as
[RFC 7296 section 2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
asks of a responder that has forgotten its response. They are the sends of a
session that ends its IKE SA itself once it runs, at a lifetime, after 5 minutes
of `TEMPORARY_FAILURE` with no rekey completed by either end in between, or on a
failure of its own, of either end of an `IKE_AUTH` whose Child SA the responder
refused, of a rekey's Delete of the replaced or redundant IKE SA, of the Delete
of an IKE SA whose PRF a reload left out, as
[reloading](../reloading.md#capcrypto) describes, and of a node closing a
session. A session whose dataplane refuses its first Child SA has not started to
run, and sends its Delete once without waiting for an answer. The session's own
Delete waits for an exchange already out. A node closing a session, as at
shutdown, waits 2 seconds for its Delete to be answered. Once a Delete of the
session's IKE SA has gone out, whoever sent it, the session starts no other
request or liveness check on that IKE SA, and sends no Delete of its own when it
then ends.

An `INVALID_SYNTAX`, sent or received, ends the IKE SA it came on at once and
without a Delete. On the session's current IKE SA the session ends, and the node
that dialed it dials again. On a replaced or redundant IKE SA still kept for a
Delete, that IKE SA alone ends, and the session goes on. A peer that answers
this end's Delete of a Child SA with an error still holds its inbound and
outbound SAs of that Child SA. This end keeps both of its own out of the
dataplane, does not ask again, and gives the Child SA's inbound SPI to no later
Child SA of the session.

[The configuration reference](../configuration-reference.md#capcryptorekey) says
what happens at an SA's lifetime, and
[Lifetimes](protocol-deviations.md#lifetimes) what an IKE SA still carries past
it. A replaced Child SA's keys leave the dataplane at its lifetime where its
drain would end later. A replaced IKE SA the peer owes a Delete is dropped at
its lifetime, and one this end deletes is kept for that Delete.

The limit on peer rekeys counts a rekey once the offer is settled, before its
key exchange. A rekey answered with `INVALID_KE_PAYLOAD` does not count, so the
retry in the group asked for is taken. A rekey whose key exchange then fails
counts, and is answered with `INVALID_SYNTAX`.

### Babel

| Limit                                  | Value                                   | Past it                                                        |
| -------------------------------------- | --------------------------------------- | -------------------------------------------------------------- |
| Route table                            | 16,384 destination and source pairs     | Routes to a new pair are refused, with a warning               |
| Source table                           | 65,536 entries                          | An origin this node has never advertised is unfeasible         |
| Origins of 1 prefix                    | 1,024, of which 256 through 1 neighbor  | The same                                                       |
| Source entries through 1 neighbor      | 8,192                                   | The same                                                       |
| Control packets queued for 1 neighbor  | 256                                     | A periodic update that needs more packets is cut short         |
| Full dumps for wildcard Route Requests | 1 per update interval for each neighbor | A further wildcard request within the interval goes unanswered |
| Seqno requests tracked                 | 4,096, of which 1,024 from 1 neighbor   | A request past either cap is not forwarded                     |

The queue's 256 packets carry about 9,700 prefixes of length 64 from distinct
origins, and more when prefixes share an origin. A larger table walks its routes
afresh on each periodic update, so each update carries a different subset. A
prefix left out of updates for 3.5 update intervals, 56 seconds at the defaults,
expires at the neighbor.

The per-neighbor caps on the source table keep 1 neighbor from spending the
whole table. A peer that draws a new router id at each start adds a new origin
for every prefix it announces each time it restarts. The caps sit far above what
such restarts produce.

### Dataplane and sockets

| Limit                                       | Value                                                                                                                         | Past it                                                                                                                                                                                                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| ESP receive queue of 1 session              | 8 MiB or 1,024 batches                                                                                                        | A batch is dropped before decryption, and each of its datagrams is counted in `ranet3_receive_dropped_total`                                                                                                                                |
| IKE receive queue of 1 session              | 16 datagrams                                                                                                                  | A datagram is dropped and counted the same way                                                                                                                                                                                              |
| IKE datagrams waiting for the responder     | 64                                                                                                                            | A datagram is counted in `ranet3_receive_refused_total`, and its sender retransmits                                                                                                                                                         |
| UDP socket buffers                          | 7 MiB each way                                                                                                                | Linux grants more than `net.core.rmem_max` or `net.core.wmem_max` only with `CAP_NET_ADMIN`                                                                                                                                                 |
| Datagrams in 1 `UDP_SEGMENT` send           | 64                                                                                                                            | Linux before 6.9 refuses more                                                                                                                                                                                                               |
| Sockets connected to 1 peer each            | 256                                                                                                                           | A busy peer past the cap stays on the shared socket                                                                                                                                                                                         |
| Bytes before a peer gets such a socket      | 1 MiB within 30 seconds, sent and received                                                                                    | Less leaves the peer on the shared socket, and the count starts over every 30 seconds                                                                                                                                                       |
| Socket buffers of such a socket             | 4 MiB each way                                                                                                                | Linux grants more than `net.core.rmem_max` or `net.core.wmem_max` only with `CAP_NET_ADMIN`                                                                                                                                                 |
| Read buffers of such a socket               | 4 messages of 64 KiB on Linux, 256 KiB                                                                                        | 64 MiB at the cap. A read takes 4 messages at most, and the kernel holds the rest for the next                                                                                                                                              |
| ICMP errors to 1 source                     | 6 at once, then 1 a second over IPv4 and 1 every 100 milliseconds over IPv6, Packet Too Big and fragmentation needed left out | The error is not sent, and `ranet3_icmp_withheld_total{limit="source"}` counts it                                                                                                                                                           |
| Sources the ICMP limit keeps a bucket for   | 6,144, in 64 shards of 96 by a seeded hash of the address                                                                     | In a full shard, the source that drew least recently gives its place, and starts full when it returns                                                                                                                                       |
| ICMP errors of the whole node               | 10,000 at once, then 10,000 a second, of either family and every kind                                                         | The error is not sent, and `ranet3_icmp_withheld_total{limit="node"}` counts it                                                                                                                                                             |
| Open flows of 1 mesh source through an exit | `cap.egress.flows_per_source` in each family, 4096 by default                                                                 | The source's next new flow is refused, answered from the exit, and counted in `ranet3_egress_refused_total`                                                                                                                                 |
| Mesh sources an exit counts flows for       | 65,535 in each family                                                                                                         | A further source's flows go uncounted and unlimited until [the kernel frees a count](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_set_hash.c?id=940de590b839f71d6dc846160534bf202401b8b7#n393) |
| Flows of 1 mesh source to the node itself   | Not bounded by the share                                                                                                      | Each takes an entry in the host's connection tracking table beside the flows through the exit, uncounted                                                                                                                                    |

[Platforms](../platforms.md) lists the tun queues and the socket differences
between Linux and macOS, and describes the
[sockets connected to 1 peer](../platforms.md#sockets-connected-to-1-peer).
[Path MTU](../path-mtu.md#packets-that-do-not-fit) describes the ICMP rate
limits.

### Kernel routes

| Route                                                               | What the reconciler does                                                                  |
| ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| An IPv4 source-specific route                                       | Never installs it, and warns once. The mesh's own table still applies it                  |
| A multicast, link-local or loopback prefix, or `255.255.255.255/32` | Never installs it. Each names a link or the host rather than a destination                |
| A route another program changed without a notification              | Repairs it at the next pass, every 30 seconds unless `cap.table.reconcile` says otherwise |

The kernel's IPv4 table has no source-specific lookup. Installing such a route
as an ordinary one would take traffic from every other source. The mesh's own
table applies it to packets the kernel sends into the tun.
[Platforms](../platforms.md#macos) describes which routes macOS scopes to the
tun.

### ESP

| Limit                                | Value                                      | Past it                                                 |
| ------------------------------------ | ------------------------------------------ | ------------------------------------------------------- |
| Sequence numbers                     | 32 bits, no extended sequence numbers      | An SA asks for a rekey 2^28 packets before they run out |
| Last sequence number                 | `2^32 - 1`                                 | The SA refuses to send                                  |
| Replaced inbound SA after its Delete | 5 seconds, and no longer than its lifetime | The SA is removed                                       |
| Replaced inbound SA without a Delete | 30 seconds after the rekey, then 5 seconds | This end deletes the SA, which drains and is removed    |

The scheduled rekey, hourly by default, comes long before the sequence numbers
run out. The early request covers a link fast enough to use them up within 1
rekey interval. The first ask past the mark waits a random 0 to 1 second, so 2
ends that cross it together do not ask at once. Once the last sequence number is
used, the SA refuses to send, and the session logs
`ike Child SA ran out of sequence numbers` once for the SA, with both SPIs, both
identities, the local socket address, the peer's address and the sequence number
the refused packet needed. Unless a rekey replaces the SA, the IKE SA is then
deleted as at the end of a lifetime.

### Configuration bounds

[The configuration reference](../configuration-reference.md) gives the range of
every setting. These 2 bounds have consequences the ranges do not show:

| Setting           | Bound                                  | Consequence                                                                                     |
| ----------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `cap.babel.hello` | up to 655.35 seconds                   | Above 10 seconds, IKE liveness checks fill the gaps between Hellos, so a NAT mapping stays open |
| `link.port`       | not checked against the trust document | Peers dial the port the trust document lists, so a mismatch leaves the node unreachable by them |

On a session without data traffic, Babel Hellos and IKE liveness checks keep a
NAT mapping open, as
[protocol deviations](protocol-deviations.md#nat-traversal-and-ports) describes.
An end sends a liveness check only after 10 seconds with nothing authenticated
from its peer. [The trust document](../trust.md) lists each node's port.
