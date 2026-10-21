---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Platforms"
description: "What differs between Linux, macOS and other platforms: the tun, the route reconciler, the underlay socket, the sockets connected to 1 peer, moving hosts and path MTU."
created: 2026-09-21
updated: 2026-10-22
order: 100
---

The reconciler's job is the same everywhere and the facilities under it are not,
so the configuration names what it wants and each backend reaches it the way its
kernel allows. A backend that cannot reach a setting refuses it by name, at
startup or on a reload. The sections below note where a backend ignores a
setting or skips a route instead.

## At a glance

|                                      | Linux                                                                     | macOS                                                   |
| ------------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------------- |
| Kernel                               | Linux 4.20 or later                                                       | no minimum checked                                      |
| Tun                                  | `ranet3`, or the device `link.tun` names                                  | `utun` for the next free unit, or `utunN`               |
| Tun queues                           | 1 per CPU the Go runtime uses, up to 256                                  | 1                                                       |
| Underlay sockets                     | 1 per family, batched with `recvmmsg`, `UDP_GRO` and `UDP_SEGMENT`        | 1 per family, 1 datagram per call                       |
| Sockets connected to 1 peer          | 1 per busy address pair, up to 256, batched like the shared ones          | 1 per busy address pair, up to 256, 1 datagram per call |
| Keeping the underlay out of the mesh | `link.underlay.mark` with a `cap.table.rules` entry                       | `link.underlay.bind`                                    |
| Route ownership                      | the table `cap.table.id` and the protocol `cap.table.proto`               | the utun and the shape of the routes ranet3 installs    |
| `cap.table.rules`, `cap.table.vrf`   | supported                                                                 | refused                                                 |
| `cap.table.prefsrc4`                 | supported                                                                 | refused                                                 |
| `cap.table.metric`                   | supported                                                                 | ignored                                                 |
| `cap.egress`                         | nftables                                                                  | refused                                                 |
| Egress segments                      | a second tun, `link.tun` plus `e`                                         | refused                                                 |
| `cap.border`                         | an nftables chain at prerouting                                           | refused                                                 |
| Network watch                        | rtnetlink                                                                 | routing socket                                          |
| Don't fragment                       | `IP_PMTUDISC_DO`, `IPV6_PMTUDISC_DO`                                      | `IP_DONTFRAG`, `IPV6_DONTFRAG`                          |
| Path MTU a search starts from        | the route's MTU, including a path MTU the host learned                    | the MTU of the interface the session sends through      |
| Forwarding read from                 | `/proc/sys/net/ipv4/ip_forward`, `/proc/sys/net/ipv6/conf/all/forwarding` | `net.inet.ip.forwarding`, `net.inet6.ip6.forwarding`    |
| Control socket caller                | `SO_PEERCRED`                                                             | `LOCAL_PEERCRED`, `LOCAL_PEERPID`                       |
| Default state directory              | `/var/lib/ranet3`                                                         | `/var/db/ranet3`                                        |

The forwarding settings decide whether a node warns about transit it cannot
carry, whether it warns about forwarding without `cap.border`, and whether
`cap.egress` advertises its prefixes. On macOS `cap.border` is refused at
startup with
`egress: cap.border is an nftables chain, which darwin does not have, so this node cannot filter what enters the mesh from its other links`,
and a Mac that forwards gets the warning instead. The caller's credentials
decide who may use the debug paths beyond the read paths.

## The tun device

On Linux the tun is `ranet3` unless `link.tun` names another device. The daemon
creates `ranet3` itself and never attaches to an existing device of that name,
so a second instance on the same host needs a `link.tun` of its own. A
`link.tun` that names an existing device attaches to it. The tun opens 1 queue
per CPU the Go runtime uses, up to 256, and sets the device's `gso_max_segs` to
its read batch.

On macOS the tun is a utun with 1 queue. `link.tun` takes `utun` for the next
free unit or `utunN` for unit N, because the utun control creates nothing else.
The daemon refuses any other name at startup. The reconciler works on the name
the device got, such as `utun6`, rather than the one configured.

## Linux

Linux has policy rules and 2^32 tables. Every node needs Linux 4.20 or later,
because the network watch and the reconciler both open rtnetlink with
`NETLINK_GET_STRICT_CHK`. With that option the kernel filters the reconciler's
route dumps to its own table, so a host holding a full table in `main` costs it
no more than its own routes. The reconciler marks its rules with `FRA_PROTOCOL`,
which arrived in Linux 4.17. `cap.table.rules` are installed with `FRA_PROTOCOL`
set to `cap.table.proto`, the same ownership marker the routes carry, so a dump
reads back only this reconciler's and a delete can never reach another writer's.
systemd-networkd stamps `RTPROT_STATIC` on the rules it writes, so the 2 sets
stay apart. `cap.table.prefsrc4` takes an IPv4 address in its plain spelling.
The IPv4-mapped one, `::ffff:203.0.113.5` for instance, is refused with the
spelling to write instead.

`cap.table.vrf.create` makes the master device the mesh table is bound to when
no device of that name exists. One this process created is removed again at
shutdown, found by the index it was created under, so a device somebody else
made under the same name in the meantime stays with everything in its table. A
VRF the process found is left alone, whatever table it is bound to. If it is
bound to another table, the tun's lookups go to that table instead of
`cap.table.id`. A device of another kind holding the name is refused by name
rather than answered with a bare errno.

Every pass that finds the tun in the VRF reads which table the VRF is bound to,
and warns once per change when that is another table than `cap.table.id`, so a
VRF made or remade while ranet3 runs is reported as well as one made before it.
Traffic inside the VRF is looked up in the VRF's own table and falls through to
main wherever nothing there matches, so it reaches the mesh's routes only
through a policy rule, and a ping that leaves by the uplink proves nothing.

The warning's `fix` attribute offers 2 changes: bind the VRF to `cap.table.id`
in whatever creates it, or set `cap.table.id` to the VRF's table. `cap.table.id`
refuses 253 to 255, so the second is offered only for another table. The warning
never suggests deleting the device. Deleting it would detach the VRF's other
links, and the device recreated in its place would be one this process removes
at shutdown.

3 more behaviors are Linux only:

- At startup the reconciler warns when another routing protocol writes its
  table. An install refuses a key another writer already holds, so where both
  write a prefix, the first writer keeps it.
- With the mesh in a VRF, the node warns when `net.ipv4.tcp_l3mdev_accept` or
  `net.ipv4.udp_l3mdev_accept` is off. A socket outside the VRF then misses
  every reply that arrives through it.
- A deleted rule that carries `cap.table.proto` wakes the reconciler, and the
  next pass puts the rule back. systemd-networkd deletes such rules when it
  configures a link.

## macOS

macOS has 1 forwarding table and lacks policy rules and VRFs. Its reconciler
refuses `cap.table.rules`, `cap.table.vrf` and `cap.table.prefsrc4` by name. It
also refuses any `cap.table.id` or `cap.table.proto` other than the defaults,
200 and 155. It takes `cap.table.metric` and ignores it, because a macOS route
carries no metric.

A route belongs to the reconciler when it leaves the utun with the shape ranet3
installs, a prefix route whose gateway is the interface itself. The reconciler
adopts and withdraws such a route even when another process installed it, so
give ranet3 a utun no other program writes. macOS cannot replace a route. A
route another program holds under the same key stays, and the reconciler warns
about it once.

Interface scope does on macOS what policy rules do on Linux. It keeps the host's
own traffic from being captured, and it keeps the ESP underlay out of the tunnel
carrying it. The reconciler installs these routes scoped to the tun, where no
unbound socket can select them:

- a source-specific route
- a retracted route, which it holds as a reject route, unless the route counts
  as a default, whose hold it does not install at all
- any route that contains a literal endpoint address the trust document lists
- without `link.underlay.bind`, any route that
  [counts as a default](routing.md#routes-that-count-as-a-default)

A source-specific route is installed only when its source prefix holds an
address on the tun, because interface scope stands in for "from an address of
ours". A destination holds 1 scoped route, the one with the most specific
source. The reconciler skips every other scoped route to that destination and
logs it once.

`link.underlay.mark` is refused on macOS, because macOS has no rule to select a
mark. `link.underlay.bind` is the macOS spelling. It binds the underlay socket
to the interface the host's default route leaves by. The socket follows the
host's default to another interface 250 milliseconds after a change. It stays
unbound until the host has a default route, and stays where it is while the host
briefly has none.

With `link.underlay.bind` set, the reconciler installs a plain `/0` as its
zero-free cover, 8 unscoped routes per family that leave `0.0.0.0/8` and `::/8`
to the host's own default, as [routing](routing.md#the-zero-free-cover-on-macos)
describes. A Mac with `bind` set takes a mesh exit through the cover.

The daemon gives the socket's interface a default scoped to it only while an
unscoped route out of another interface holds that family's zero address, such
as a real `0.0.0.0/1` the mesh installs or another program's full-tunnel route.
It withdraws it once no such route is left, and with only the cover installed it
writes nothing outside the tun. `/var/run/ranet3/underlay.json` records the
scoped defaults it writes, and the next start withdraws the ones an earlier run
recorded.

With `link.underlay.bind` set, a route that contains a literal endpoint address
the trust document lists still stays scoped to the tun, unless it is a member of
the cover. Unscoped, it would carry an unbound socket's ESP to that peer into
the tunnel.

`ranet3 down` takes a scoped default the daemon wrote away with the capture that
needed it, and `ranet3 up` writes it again once a capture needs it. A
source-specific route and a retracted one stay scoped with or without
`link.underlay.bind`. Interface scope is the only way macOS expresses a source.
An unscoped reject route at a default would answer the whole host's traffic with
an error.

## Other platforms

On a platform other than Linux and macOS:

- `cap.table` fails the start with
  `route reconciliation is unsupported on this platform`.
- `cap.egress`, `cap.border` and both `link.underlay` settings are refused.
- An egress segment fails the start, naming its SID, since the egress device is
  a Linux tun the kernel forwards from.
- The node has no network watch, so a moved host waits for each session's own
  liveness check.
- Every peer shares the 1 socket of its family, busy or not.
- The tun takes its MTU only when it opens, so a change to `link.mtu` or to the
  steering that moves the tun needs a restart. A reload applies one that leaves
  the tun where it was.
- The node assumes the host forwards both families.
- The node reads no caller credentials, so the debug tree answers only on its
  read paths.
- Datagrams leave without DF, as [path MTU](#path-mtu) below describes.
- Answers leave from the kernel's choice of source, not the address the request
  reached.

## Moving hosts

A node keeps its sessions when its own addresses change, as a laptop's do when
it moves from Wi-Fi to a dock or a DHCP lease renews, and when its peer's do.
Every session follows its peer to the address and port its latest fresh
authenticated request came from, and answers a request from the address it
arrived on. Beyond those answers, a session this node dialed leaves the source
address to the kernel. Its sends leave from whatever address the host holds at
the time. A session a peer opened sends from the address the peer's latest
request arrived on, on Linux and macOS alike, and a request that reaches another
of this host's addresses moves it there. Once that address has gone and the
kernel refuses a send from it, the session sends from the kernel's choice until
a later request moves it to the address that one arrived on. On other platforms
the kernel always chooses.

Where the host still holds the address but has no route from it to the peer, the
session's traffic leaves from the kernel's choice too. A fresh request to the
address within 1 minute of the fallback changes nothing, and the session keeps
sending from the kernel's choice. The first one after that minute, which a peer
sends once that traffic is lost, moves the session back to the address. If the
address still has no route, the session falls back again, at most once every
minute. Where the session's traffic from the other address still reaches the
peer, the session works, and it stays there until the peer's next request, such
as a rekey. Each answer to a request that reaches the address is sent from the
address itself first, so answers leave from it as soon as it routes again.

A session that cannot send at all, because the host has no route to the peer,
holds while its liveness check retransmits on the usual schedule, and ends once
the check has gone unanswered through its whole budget of 62 seconds. Its dialer
then dials again. The first send that fails is logged as a warning, and the
failures after it at debug until a send goes out again.

A node also watches the host's network, so it does not wait for a liveness
deadline to find a moved path. On Linux it follows the link, address and route
notifications of rtnetlink, keeping only defaults in `main`. On macOS it follows
the routing socket. 250 milliseconds after a notification it reads, for each
family, the host's own default route, its interface and gateway, and the global
unicast addresses of the interfaces that are up. The mesh's own device is left
out of both, so the reconciler's writes to its table and to the tun never count.
When the reading differs from the last one acted on, every session sends a
liveness check at once, every dialer that is waiting out its reconnect delay
dials again, and a `network.changed` event records what moved. A dialer that
finds its session healthy stands down as it does after any wake. A change the
host shows nowhere, such as a captive portal that lets nothing through, needs
`ranet3 redial --all` instead.

## Sockets connected to 1 peer

On Linux and macOS the transport listens on 1 UDP socket per family, bound to
the wildcard address on `link.port`, and every peer starts on it. A busy peer
then gets a socket of its own. The kernel keeps a socket's datagrams on 1
transmit queue only while the socket is connected. A busy peer's ESP sent from
the shared socket leaves over as many queues as its sender visits CPUs, arrives
reordered, and makes the TCP inside it retransmit.

The transport counts the bytes each address pair carries, sent and received
together. A pair is this host's address and the peer's address and port. On
Linux and macOS the address of a session a peer opened is the one the peer's
request arrived on, and a session this node dialed, or one whose sends fell back
from that address, leaves it to the route. A pair that carries 1 MiB within 1
sweep of 30 seconds gets a socket on `link.port`, the listener's port, bound to
its address or to the one the route picks then, and connected to the peer. The
peer sees the same address and port as before. The pair's sends leave on that
socket. The kernel hands the socket the peer's datagrams to that address ahead
of the listener, and a reader of its own takes them to the same sessions. Before
Linux 5.4, once 2 such sockets share 1 address, the kernel hands each datagram
to that address from a peer with a socket of its own to 1 of them by a hash, so
a peer's datagrams can arrive on another peer's socket. Every reader takes them
to the same sessions, so none is lost. A node holds at most 256 such sockets. A
pair past the cap stays on the shared socket.

On Linux the socket of a session a peer opened also leaves by the interface the
peer's request arrived on, as the shared socket's replies do. An IPv4 socket
binds to that interface with `SO_BINDTOIFINDEX`, which Linux allows a process
without `CAP_NET_RAW` from 5.7. On an older kernel the bind is refused, and such
a session stays on the shared socket. An IPv6 socket names the interface with
`IPV6_UNICAST_IF`, which like the reply's own choice prefers that interface only
among the routes of the lowest metric. A link-local address binds on that
interface alone. On macOS a link-local peer's socket binds on the interface the
peer's zone names.

A socket connected to 1 peer closes:

- when it carried nothing for a whole sweep.
- when the last session sending on it ends, or moves to another address.
- when the host's network changes, as [moving hosts](#moving-hosts) describes. A
  busy pair connects again at its next send, from the address its pair names
  then.
- on macOS, when the underlay socket moves onto another interface.
- when a send or a read on it fails, other than for an ICMP error, as below, or
  for a refusal of its segments, as [path MTU](#path-mtu) describes. Its
  datagrams then leave the shared socket, and the pair waits for the next sweep
  before it connects again.

The kernel hands a connected socket the ICMP errors its datagrams draw, such as
a port unreachable from a peer that restarted or a smaller path MTU from a hop
on the way. The next read or send on the socket reports such an error, and none
of them closes the socket. The read goes on reading, and the send goes again
with its datagrams. A datagram past the path MTU is refused on that socket too.
It then goes to the shared socket, whose refusal reports the path to the
session's search, and the socket stays.

A connected socket keeps the source address it bound. On Linux an IPv4 send from
an address the host lost is refused, and the socket closes at once. An IPv6 send
from such an address still leaves, so only the network change closes the socket.
Naming the source on each IPv6 send instead would cost the socket the cached
route that keeps its transmit queue.

Each such socket follows the path MTU discovery mode of its family's shared
socket. While a session of its family is under the floor, it lets the host
fragment its datagrams as the shared socket does, as [path MTU](#path-mtu) below
describes. A socket the host does not let change its mode closes as failed.

On Linux each socket connected to 1 peer reads 4 messages of 64 KiB at once,
which is 256 KiB of buffers per socket and 64 MiB at the cap, and asks the
kernel for 4 MiB of socket buffer each way. Before Linux 6.13 the kernel matches
each datagram to an address on the port against every socket bound to that
address, up to 256, before it reaches the listener. From 6.13 a datagram from a
peer with a socket of its own finds that socket at once, and the others still
pass every socket bound to their address. On macOS each socket reads 1 datagram
of 64 KiB at a time.

Sharing the port takes `SO_REUSEPORT` on Linux. The listener binds without it
and sets it once bound. A socket connected to 1 peer sets it before it binds 1
address on the port. Linux lets a socket bind a port another socket holds only
when both set `SO_REUSEPORT` and both belong to the same effective user ID. A
second ranet3 on the port is refused, and so is any process that binds the port
without `SO_REUSEPORT`. A process running as the daemon's own user, which is
root under the [service](service.md), can still bind the port when it sets
`SO_REUSEPORT` before its bind. On the wildcard address it takes a share of the
datagrams the listener would get. On 1 of the host's addresses it takes every
datagram to that address from a peer without a socket of its own.

macOS needs no option on the listener. A socket connected to 1 peer sets
`SO_REUSEADDR` and binds 1 address beside the wildcard listener, which macOS
allows for a specific address. macOS refuses a bind to a port that a socket of
another user holds, unless the process binding is root's. A process running as
the daemon's own user, which is root under launchd, can still bind 1 of the
host's addresses on the port with `SO_REUSEADDR`. It then takes every datagram
to that address from a peer without a socket of its own. That holds with or
without sockets connected to 1 peer. macOS reads a held socket's options at each
later bind, and skips the user check for 2 binds of the wildcard address when
the held socket has `SO_REUSEPORT`. A listener that set it after its bind would
let a process of any user share the wildcard address, so ranet3 leaves it unset
there.

## Path MTU

On Linux and macOS each session searches its path for the largest packet it
carries, as [path MTU](path-mtu.md) describes. The platforms differ in what the
host tells that search.

On Linux every datagram leaves with `IP_PMTUDISC_DO` or `IPV6_PMTUDISC_DO` while
no session of its family fragments. The host refuses a datagram past the path
MTU its route holds, including a smaller one learned from an ICMP answer. The
session then reads that MTU and lowers its budget to it, and the datagrams
within it still go.

A batch of ESP for 1 peer goes out as segmented messages where it can. Linux can
refuse a segmented message where it takes single datagrams. This happens on a
route through an IPsec policy, on a kernel before 6.14 when a segment exceeds
the path MTU, and on a socket that fragments for a session under the floor.
ranet3 then sends those datagrams again, 1 per message. That peer gets single
datagrams for 10 minutes, the time Linux keeps a path MTU it learned. Every
other peer keeps segmenting. On a socket that fragments, a message refused with
`EMSGSIZE` is first sent once more segmented, because a socket connected to 1
peer holds the `EMSGSIZE` of a Packet Too Big for its next send alone. Only a
second refusal stops the segments. A
[socket connected to 1 peer](#sockets-connected-to-1-peer) does the same and
stays open. The stop holds for that peer on the shared socket and on its own
alike.

On macOS every datagram leaves with `IP_DONTFRAG` or `IPV6_DONTFRAG`. The host
refuses one past the MTU of the interface it leaves by, rather than past a path
MTU it learned. A socket that `link.underlay.bind` holds to an interface sends
through it. Otherwise a session the peer opened sends through the interface
holding the address it sends from, the one the peer's latest request reached
until a send from it falls back, as [moving hosts](#moving-hosts) describes. Any
other session, one whose send fell back included, sends through the interface
its route leaves by. A session's search starts from the MTU of the interface it
sends through, and the probes alone find a narrower hop beyond it.

A session on a path under the floor fragments on either platform as
[the design's limits](design/limits.md) describe. While one does, Linux lets the
host fragment every datagram of that family, and macOS does the same for IPv4.
On macOS an IPv6 peer under the floor has only its own datagrams fragmented. On
any other platform datagrams leave without DF, nothing is searched and every
session carries `link.mtu`, which leaves a narrower path to the host's and the
routers' fragmenting.

## The control surface

The control surface is an HTTP handler that serves JSON over any listener. The
`control` package binds it to a Unix socket. On Linux and macOS it also reads
each caller's credentials from that socket. Elsewhere it reads none, and the
debug tree answers a caller it cannot name only on its read paths.
