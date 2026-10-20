---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "What it deliberately doesn't do"
description: "What ranet3 deliberately does not do, and why."
created: 2026-08-17
updated: 2026-10-20
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

A node that advertises transit still has to forward it, which takes 2 things:

- Forwarding is on for both families, `net.ipv4.ip_forward` and
  `net.ipv6.conf.all.forwarding` on Linux, `net.inet.ip.forwarding` and
  `net.inet6.ip6.forwarding` on macOS. With `cap.transit.enable = true` and
  either family off, ranet3 logs a warning at startup.
- The learned routes reach a kernel table the node consults.
  [`cap.table`](../configuration-reference.md) installs them, or another program
  does.

Advertising transit without them means announced paths blackhole.
[`cap.egress`](../exit-nodes.md) acts on the same fact rather than warning about
it. A prefix an exit node offers to carry is advertised only while its family's
translation chain reads back exactly as written and the host forwards the
family. It is retracted on the first pass that finds either untrue. A pass runs
every 30 seconds unless `cap.egress.sweep` names another interval.

An exit or subnet router set up as
[exit nodes](../exit-nodes.md#the-return-path) describes should not carry
transit. Its `cap.table.rules` send only the mesh prefixes to the mesh table. A
transit packet for a prefix another node announces outside them therefore leaves
by the host's own routes out of the uplink. It leaves translated to the node's
address in a family `advertise` covers, and under the sender's mesh address in
any other.

With transit off, a node advertises only the prefixes it announces and never
relays one it learned. Transit is off unless
[`cap.transit`](../configuration-reference.md) writes `enable = true`, and a
leaf leaves it out. Refusing to advertise cannot close a loop, so this only
narrows what the feasibility condition already bounds.

## Who a node dials

`dial.all` dials every other node the trust document names. Entries in `dial.to`
still apply and win for their node, which is the only way to pin a `serial`. A
node needs `dial.all` when its peers relay no learned routes, as a node with
transit off does. It then learns each prefix only from the node that originates
it, so dialing a few exits reaches those exits and nothing behind them.

## The underlay socket

A node that takes an exit-announced default should set `link.underlay`. The
block keeps the UDP sockets that carry IKE and ESP out of reach of the routes
the mesh installs, on Linux and macOS alike. The transport binds the wildcard
address and lets the kernel pick each datagram's source by route. On a node
whose mesh address is its only global address of a family, the kernel picks that
address. A `from <mesh address>` policy rule then sends the datagram to the mesh
table, where an exit-announced default routes the ESP underlay into the tun that
carries it.

`link.underlay.mark` is `SO_MARK`, Linux only. The rule matching it goes under
`cap.table.rules`, such as
`{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }`, and the
reconciler installs it. The mark and its rule are 1 setting written in 2 blocks.
A node that writes `cap.table` without that rule is refused by name, because a
marked socket that no rule selects follows the mesh table like any other socket.
A node configuring its routes elsewhere writes no `cap.table`, and the rule goes
wherever those routes do.

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
covers a literal endpoint address the trust document lists. Without `bind`, the
reconciler scopes a `/0` and the `/1` halves to the tun, as
[platforms](../platforms.md#macos) describes. No unbound socket selects a scoped
route. A node without `bind` can hold an exit-announced address and still cannot
send its traffic through the exit.

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
live session. Such a route is one covering half a family's address space or
more, or one covering that family's unspecified address however small.

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
has. It scopes the routes that would otherwise capture the host, and it can
assign the configured addresses. The `cap.table` block in
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

ranet3 does not let its own datagrams fragment, outside 1 case. Each session
searches its path for the largest packet it carries, between 1280 and
`link.mtu`, and a larger packet is answered with Packet Too Big or fragmentation
needed, or cut when it is IPv4 without DF, as [path MTU](../path-mtu.md)
describes. A path that cannot carry 1280 bytes in 1 datagram is under the floor.
1280 bytes is the least IPv6 asks of any link. An IPv4 path is under the floor
below 1344 bytes, and an IPv6 path below 1364 bytes. A session on such a path
holds its budget at 1280 and lets the host fragment its datagrams.

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

## Limits by area

Each table gives a fixed bound, its value, and what happens past it. Bounds you
can configure are in
[the configuration reference](../configuration-reference.md).

### IKE

| Limit                                          | Value                                                                                   | Past it                                                                                   |
| ---------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Half-open SAs before a cookie                  | 32 in all, or 2 from 1 address                                                          | An `IKE_SA_INIT` without a valid cookie is answered with one (RFC 7296 section 2.6)       |
| Half-open SAs                                  | 256 in all, 16 from 1 address                                                           | A further `IKE_SA_INIT` is dropped unanswered, and its sender retransmits                 |
| Error answers sent in the clear                | 256 at once, then 32 a second, for the whole node                                       | A further one is not sent, and at most 1 line a minute counts those held back             |
| Responder handshake                            | 30 seconds                                                                              | The handshake is abandoned                                                                |
| Canceled dial's wait for its `IKE_AUTH` answer | 2 seconds                                                                               | The dial ends, and a peer whose answer is late keeps its session until liveness fails     |
| Sends of a request                             | 5, waiting 2, 4, 8, 16 and 32 seconds after each                                        | The exchange fails after 62 seconds, and its IKE SA is deemed failed                      |
| Sends while the peer's other traffic continues | 20, about 9 minutes in all                                                              | The exchange fails, and its IKE SA is deemed failed though the peer's ESP still arrives   |
| Silence before a liveness check                | 10 seconds                                                                              | The session sends an `INFORMATIONAL` request, retransmitted on the schedule above         |
| Live session                                   | 20 seconds since the peer's last authenticated IKE, 20 to 30 seconds since its last ESP | The session no longer counts as live                                                      |
| Reconnect delay                                | 10 seconds                                                                              | A dialer whose session ended waits this long before it dials again                        |
| Sends of the Delete that ends an IKE SA        | 2, waiting 2 and 4 seconds after each                                                   | The IKE SA is deemed failed after 6 seconds                                               |
| SA lifetime                                    | `cap.crypto.rekey.child` and `cap.crypto.rekey.ike`                                     | The SA is no longer used, and without a rekey replacing it the IKE SA is deleted          |
| `TEMPORARY_FAILURE` answers on 1 IKE SA        | 5 minutes                                                                               | The IKE SA is deleted, and the session ends                                               |
| Peer rekeys                                    | 1 per second for each kind of SA                                                        | A faster rekey is answered `TEMPORARY_FAILURE`                                            |
| Replaced Child SA awaiting the peer's Delete   | up to 30 seconds, then this end deletes it                                              | Every Child SA rekey in either direction, and a peer's IKE SA rekey, is refused meanwhile |
| Replaced IKE SA awaiting the peer's Delete     | up to 2 minutes, and no longer than its lifetime                                        | A peer's IKE SA rekey is answered `TEMPORARY_FAILURE` meanwhile                           |

The second row holds even for a request with a valid cookie. More than 16 nodes
behind 1 NAT that restart at once therefore wait for their retransmissions.

The errors the third row limits are `INVALID_MAJOR_VERSION`,
`UNSUPPORTED_CRITICAL_PAYLOAD` and `NO_PROPOSAL_CHOSEN`, sent in the clear to a
request that no IKE SA protects, which end the exchange. A `COOKIE`, an
`INVALID_KE_PAYLOAD` and an `IKE_SA_INIT` response that carries the handshake
forward are outside the limit: an initiator goes on after each of them, so one
source that spends the limit cannot stop another's dial. A `COOKIE` is the
defense against a flood of `IKE_SA_INIT` requests that
[RFC 7296 section 2.6](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.6)
gives a responder. An `INVALID_KE_PAYLOAD` is 1 answer of 38 octets to a request
of at least 102, and it gives its half-open slot back as it is sent, so neither
cookies nor the half-open limit bound how many go out. An `IKE_SA_INIT` response
holds its half-open slot until `IKE_AUTH`, and the half-open limits and cookies
bound it. 256 answers every half-open slot at once, and 32 a second refills them
within the reconnect delay.

An IKE SA deemed failed ends the session when it is the session's current IKE
SA, and the node that dialed it dials again. A replaced or redundant IKE SA
still kept for a Delete holds no Child SA once the rekey has moved them to its
successor. It alone ends, and the session goes on.

A request is sent up to 20 times while the peer's authenticated traffic has
arrived within the last 10 seconds. The exchange holds the only outstanding
request this end allows. Rekeys, Deletes and liveness checks wait until it ends.
A liveness check and a Delete of an IKE SA never take the longer schedule, and
neither does an exchange still outstanding when its IKE SA reaches its lifetime.
A request on the session's current IKE SA waits behind the Delete of a replaced
or redundant IKE SA for at most 6 seconds. Behind a liveness check left on an
IKE SA the peer rekeyed, it waits for that check's 5 sends, up to 62 seconds,
unless the peer's Delete of that IKE SA ends the check first.

Every Delete of an IKE SA has the 2 sends, since a peer that took it has deleted
the SA and ignores a resend, as
[RFC 7296 section 2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
asks of a responder that has forgotten its response. They are the sends of a
session that ends its IKE SA itself, at a lifetime, after 5 minutes of
`TEMPORARY_FAILURE` or on a failure of its own, of a responder that refused the
Child SA in `IKE_AUTH`, of a rekey's Delete of the replaced or redundant IKE SA,
of the Delete of an IKE SA whose PRF a reload left out, as
[reloading](../reloading.md#capcrypto) describes, and of a node closing a
session. The session's own Delete waits for an exchange already out. A node
closing a session, as at shutdown, waits 2 seconds for its Delete to be
answered. Once a Delete of the session's IKE SA has gone out, whoever sent it,
the session starts no other request or liveness check on that IKE SA, and sends
no Delete of its own when it then ends.

An `INVALID_SYNTAX`, sent or received, ends the IKE SA it came on at once and
without a Delete. On the session's current IKE SA the session ends, and the node
that dialed it dials again. On a replaced or redundant IKE SA still kept for a
Delete, that IKE SA alone ends, and the session goes on. A peer that answers
this end's Delete of a Child SA with an error keeps its half of the pair. This
end keeps its own half down, does not ask again, and gives that SPI to no later
Child SA of the session.

[The configuration reference](../configuration-reference.md#capcryptorekey) says
what happens at an SA's lifetime. A Child SA's keys leave the dataplane at its
lifetime whatever exchange is under way, and a replaced one leaves then too if
its drain would end later. An IKE SA past its lifetime starts nothing but its
Delete. It still carries the exchange outstanding at its lifetime and answers
the peer's requests, a rekey with `TEMPORARY_FAILURE`. A replaced IKE SA the
peer owes a Delete is dropped at its lifetime, and one this end deletes is kept
for that Delete.

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

| Limit                                   | Value                                      | Past it                                                                                                      |
| --------------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| ESP receive queue of 1 session          | 8 MiB or 1,024 batches                     | A batch is dropped before decryption, and each of its datagrams is counted in `ranet3_receive_dropped_total` |
| IKE receive queue of 1 session          | 16 datagrams                               | A datagram is dropped and counted the same way                                                               |
| IKE datagrams waiting for the responder | 64                                         | A datagram is counted in `ranet3_receive_refused_total`, and its sender retransmits                          |
| UDP socket buffers                      | 7 MiB each way                             | Linux grants more than `net.core.rmem_max` or `net.core.wmem_max` only with `CAP_NET_ADMIN`                  |
| Datagrams in 1 `UDP_SEGMENT` send       | 64                                         | Linux before 6.9 refuses more                                                                                |
| Sockets connected to 1 peer each        | 256                                        | A busy peer past the cap stays on the shared socket                                                          |
| Bytes before a peer gets such a socket  | 1 MiB within 30 seconds, sent and received | Less leaves the peer on the shared socket, and the count starts over every 30 seconds                        |
| Socket buffers of such a socket         | 4 MiB each way                             | Linux grants more than `net.core.rmem_max` or `net.core.wmem_max` only with `CAP_NET_ADMIN`                  |
| Read buffers of such a socket           | 4 messages of 64 KiB on Linux, 256 KiB     | 64 MiB at the cap. A read takes 4 messages at most, and the kernel holds the rest for the next               |

[Platforms](../platforms.md) lists the tun queues and the socket differences
between Linux and macOS, and describes the
[sockets connected to 1 peer](../platforms.md#sockets-connected-to-1-peer).
[Path MTU](../path-mtu.md#packets-that-do-not-fit) gives the ICMP rate limit all
answers share.

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
