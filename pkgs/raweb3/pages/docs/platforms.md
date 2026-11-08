---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Platforms"
description: "What differs between Linux, macOS and other platforms: the tun, the route reconciler, the underlay socket, the sockets connected to 1 peer, moving hosts and path MTU."
created: 2026-09-21
updated: 2026-11-09
order: 100
---

The reconciler's job is the same everywhere and the facilities under it are not,
so the configuration names what it wants and each backend reaches it the way its
kernel allows. A backend that cannot reach a setting refuses it by name, at
startup or on a reload. The sections below note where a backend ignores a
setting or skips a route instead.

## At a glance

|                                                        | Linux                                                                                                                                                                                                                                                                    | macOS                                                                                                                                                                                                                                               |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Kernel                                                 | Linux 4.20 or later, and 5.2 or later for `cap.egress`                                                                                                                                                                                                                   | no minimum checked                                                                                                                                                                                                                                  |
| Tun                                                    | `ranet3`, or the device `link.tun` names                                                                                                                                                                                                                                 | `utun` for the next free unit, or `utunN`                                                                                                                                                                                                           |
| Tun queues                                             | 1 per CPU the Go runtime uses, up to 256                                                                                                                                                                                                                                 | 1                                                                                                                                                                                                                                                   |
| Underlay sockets                                       | 1 per family, batched with `recvmmsg`, `UDP_GRO` and `UDP_SEGMENT`                                                                                                                                                                                                       | 1 per family, 1 datagram per call                                                                                                                                                                                                                   |
| Sockets connected to 1 peer                            | 1 per busy address pair, up to 256, batched like the shared ones                                                                                                                                                                                                         | 1 per busy address pair, up to 256, 1 datagram per call                                                                                                                                                                                             |
| Keeping the underlay out of the mesh                   | [the mark 0x72](coexistence.md#the-underlays-mark) on every underlay socket where the process may set it, which ends a lookup bound to no device at row L1 or L2 of [where a lookup ends](routing.md#where-a-lookup-ends-on-linux)                                       | each datagram names the interface the selection answers or the source its pin holds, see [the underlay's interface](routing.md#the-underlays-interface-on-macos)                                                                                    |
| Route ownership                                        | the table `cap.table.id` and the protocol `cap.table.proto`                                                                                                                                                                                                              | the utun and the shape of the routes ranet3 installs                                                                                                                                                                                                |
| Policy rules                                           | derived from `overlay` and this node's own prefixes                                                                                                                                                                                                                      | none                                                                                                                                                                                                                                                |
| An own prefix this node originates outside the overlay | a throw route, for one that counts as no default, that the mesh can carry and that carries no IPv4 source, row L10 of [where a lookup ends](routing.md#where-a-lookup-ends-on-linux)                                                                                     | nothing, row D2 of [where a lookup ends on macOS](routing.md#where-a-lookup-ends-on-macos) for a socket bound to no interface and no address of the utun                                                                                            |
| Hold of each overlay prefix                            | installed for each, but one a carve-out equals, as [carve-outs](antispoof.md#carve-outs) describe                                                                                                                                                                        | the same, as a reject route on `lo0`, unscoped, in every mode, as [the kill switch on macOS](routing.md#the-kill-switch-on-macos) gives                                                                                                             |
| A link's network inside the overlay                    | a throw of each carve-out, in place of the hold of an overlay prefix it equals, but none where the mesh's table holds the carve-out itself for every source, and accepted from its own interface by chain `antispoof`, as [carve-outs](antispoof.md#carve-outs) describe | no hold where the network holds the overlay prefix whole, and otherwise the network's own route, longer than the hold, and accepted from its own interface by chain `antispoof` in the pf anchor, as [carve-outs](antispoof.md#carve-outs) describe |
| `cap.egress`                                           | the kernel exit, translating each class of `translate` with nftables, with its timeouts and each source's share of the flows                                                                                                                                             | the userspace exit, ending each TCP connection and relaying UDP and echo through the host's sockets, `none`, `return` and a subnet refused                                                                                                          |
| Egress segments                                        | the mesh tun, translated by `cap.egress`                                                                                                                                                                                                                                 | the userspace exit, through `cap.egress`                                                                                                                                                                                                            |
| A `cap.route` entry that counts as a default           | loaded, with a warning unless it is a default, making this node an exit for its family                                                                                                                                                                                   | refused, as [gaps on macOS](#gaps-on-macos) gives                                                                                                                                                                                                   |
| `overlay`                                              | loaded, and chain `antispoof` at prerouting in the nftables table `inet ranet3`, with an accept for each `cap.antispoof` exemption                                                                                                                                       | loaded, bounding the local segments' outer sources and the forwarding decision, and chain `antispoof` in the pf anchor `com.apple/ranet3`, which turns pf on, with a pass for each `cap.antispoof` exemption                                        |
| Local segments                                         | `End` and `End.DT46`, the outer source checked against the overlay                                                                                                                                                                                                       | `End` and `End.DT46`, the outer source checked against the overlay                                                                                                                                                                                  |
| Entry chain                                            | chain `mesh_entry` at postrouting in `inet ranet3` on every node, with no key, as [the antispoof filter](antispoof.md#the-entry-chain) describes                                                                                                                         | none, the tun read drops a source this node does not own toward all but an IPv6 link-local destination, and a Mac with no `overlay` that forwards is warned                                                                                         |
| `cap.exit`                                             | the policy rules 5405, 5435 and 5440 of [exit mode](routing.md#exit-mode-on-linux)                                                                                                                                                                                       | the routes of [the zero-free cover](routing.md#the-zero-free-cover-on-macos) in each family the tun holds an overlay address of, and `forward` and `inbound` refused, as [gaps on macOS](#gaps-on-macos) gives                                      |
| `cap.exit.fallback = "none"`                           | the rules 5445 and 5450 and the chains `fallback` at postrouting and `output` at output in the nftables table `inet ranet3`, of [the kill switch](routing.md#the-kill-switch-on-linux), which gives what each stop leaves of them                                        | 18 reject routes on `lo0` at the zero-free cover's keys, of [the kill switch on macOS](routing.md#the-kill-switch-on-macos), which gives what each stop leaves of them                                                                              |
| `cap.exit.via`                                         | two steered defaults out of the tun under exit mode's rules, and the dataplane's steer along the path, of [mode 3](routing.md#mode-3-on-linux)                                                                                                                           | the steered defaults as the zero-free cover, and the dataplane's steer along the path, with the kill switch unless `fallback = "uplink"` is written                                                                                                 |
| Network watch                                          | rtnetlink, with each link outside the mesh and its networks                                                                                                                                                                                                              | routing socket and kernel events, with each link outside the mesh and its networks                                                                                                                                                                  |
| Don't fragment                                         | `IP_PMTUDISC_DO`, `IPV6_PMTUDISC_DO`                                                                                                                                                                                                                                     | `IP_DONTFRAG`, `IPV6_DONTFRAG`                                                                                                                                                                                                                      |
| Route MTU a path search takes                          | the route's MTU, including a path MTU the host learned                                                                                                                                                                                                                   | the MTU of the interface the session sends through                                                                                                                                                                                                  |
| Forwarding read from                                   | `/proc/sys/net/ipv4/ip_forward`, `/proc/sys/net/ipv6/conf/all/forwarding`                                                                                                                                                                                                | `net.inet.ip.forwarding`, `net.inet6.ip6.forwarding`                                                                                                                                                                                                |
| Control socket caller                                  | `SO_PEERCRED`                                                                                                                                                                                                                                                            | `LOCAL_PEERCRED`, `LOCAL_PEERPID`                                                                                                                                                                                                                   |
| Default state directory                                | `/var/lib/ranet3`                                                                                                                                                                                                                                                        | `/var/db/ranet3`                                                                                                                                                                                                                                    |

The forwarding settings decide whether a node with no antispoof filter warns
about forwarding, and whether the kernel exit advertises its prefixes. The
userspace exit reads no forwarding setting. Transit needs neither, since the
mesh forwards it between sessions itself on every platform. On macOS `overlay`
turns pf on and writes chain `antispoof` into the anchor `com.apple/ranet3`, as
[the antispoof filter](antispoof.md#on-macos) gives, and a Mac with no `overlay`
that forwards gets the warning. A Mac whose main ruleset does not call
`anchor "com.apple/*"` for every packet in, or skips an interface outside the
mesh, does not start with `overlay`, as
[pf on macOS](coexistence.md#pf-on-macos) says. [Gaps on macOS](#gaps-on-macos)
lists what `cap.exit` refuses there. The BSDs, Android and iOS refuse `cap.exit`
at startup and on a reload, as
`kernel: cap.exit is refused on freebsd, where this build has no exit mode: remove cap.exit, and this host keeps its own default`,
so a BSD host has no kill switch. On Android and iOS no reconciler runs, and the
platform's own setting holds the host's traffic to the tunnel: Android's
always-on VPN with blocking, and iOS's include-all-networks, which only the user
can turn on. The caller's credentials only name who asked, in the records
[who may use it](control-socket.md#who-may-use-it) describes.

The exit a build carries is chosen when it is built, and no setting names it. A
Linux build carries the kernel exit, which writes what it carries into the tun
and translates it with nftables on the way out of the host: every class of
`translate`, `none` among them, the timeouts of the flows it translates and
[the share of the flows](exit-nodes.md#each-sources-share-of-the-flows) of each
source under a class that translates. A macOS build carries the userspace exit,
which ends each TCP connection the mesh hands it and dials the destination from
this host's own sockets, relays UDP and echo through them, and carries the
classes `auto` and an address. Every other build carries none and refuses
`cap.egress` at startup with
`egress: cap.egress asks this node to carry other nodes' traffic out of the mesh, and this build for freebsd carries no exit`,
naming its own platform where this one names `freebsd`. The loader is the same
on every build, so a block it refuses, such as one whose classes leave under
`none` every IPv4 source a router forwards a packet from, is refused for the
same reason everywhere, before a build without an exit refuses the block whole.
A node that accepted the block and carried nothing would advertise an exit and
drop every flow that took it. A node on any platform still uses an exit.

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
the device got, such as `utun6`, rather than the one configured. Where
`link.tun` is `utun`, as by default, the daemon writes that name to the file the
environment variable `WG_TUN_NAME_FILE` names, as wireguard-go does, so an
environment that sets it for another program's tunnel finds this node's utun
there instead. A packet the Mac sends to an address of its own on the utun
crosses the utun twice, once into the mesh and once
[written back](routing.md#transit).

## Linux

Linux has policy rules and 2^32 tables. Every node needs Linux 4.20 or later,
because the network watch and the reconciler both open rtnetlink with
`NETLINK_GET_STRICT_CHK`. With that option the kernel filters the reconciler's
route dumps to its own table, so a host holding a full table in `main` costs it
no more than its own routes. The reconciler derives its policy rules, as
[routing](routing.md#policy-rules-on-linux) lists them, and marks each with
`FRA_PROTOCOL`, which arrived in Linux 4.17, set to `cap.table.proto`, the same
ownership marker the routes carry. A dump therefore reads back only this
reconciler's rules, and a delete can never reach another writer's.
systemd-networkd stamps `RTPROT_STATIC` on the rules it writes, so the 2 sets
stay apart.

An exit needs Linux 5.2 or later, the first to take a `nat` chain in an `inet`
table
([`d164385ec572`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=d164385ec572cbe3335a635ac308760e126d4ec0)),
where [the translator](exit-nodes.md#the-nftables-chains) writes its translation
beside the antispoof filter and the kill switch.

3 more behaviors are Linux only:

- At startup the reconciler warns when another routing protocol writes its
  table. The reconciler's install refuses a key another writer already holds, so
  it never takes another writer's route, while a writer that replaces a key can
  take the reconciler's.
- A deleted rule that carries `cap.table.proto` wakes the reconciler, and the
  next pass puts the rule back. systemd-networkd deletes such rules when it
  configures a link, unless its `ManageForeignRoutingPolicyRules` is off, as the
  NixOS module sets it by default and
  [routes on Linux](coexistence.md#routes-on-linux) describes.
- The reconciler asks the lookups
  [sharing a host](coexistence.md#another-programs-rules) describes. macOS has
  no policy rules and asks the overlay's alone.

### Kernels with tun GRO bugs

The tun coalesces the packets the mesh writes into the host, TCP on every kernel
and UDP where the kernel takes UDP segmentation offload on a tun, from Linux
6.2. The daemon turns neither off, so two kernel bugs reach it:

- Linux 5.15.165 and 5.15.166, 6.1.103 to 6.1.106, 6.6.44 and 6.6.45, and 6.10.3
  and 6.10.4 carry
  [`e269d79c7d35`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e269d79c7d35aa3808b1f3c1737d63dab504ddc8)
  without its fix,
  [`89add40066f9`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=89add40066f9ed9abe5f7f886fe5789ff7e0c50e).
  The tun refuses some coalesced writes with `EINVAL`, and the packets each
  holds are lost. `ranet3_tun_writes_failed_total` climbs, the
  [`netstack tun refused a write`](metrics.md#tun-reads) warning carries
  `invalid argument`, and TCP into the host through the mesh slows. The fix is
  5.15.167, 6.1.107, 6.6.46, 6.10.5 or a later release of the same series.
- Linux 6.2 to 6.8.4 lacks
  [`3d010c8031e3`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=3d010c8031e39f5fa1e8b13ada77e0321091011f),
  except 6.6.26 and every later 6.6, which carry it. A coalesced UDP write bound
  for a vxlan or geneve interface on the host is lost after the tun takes it,
  and no counter of the daemon's sees the loss. The fix is 6.8.5 or later, or
  6.6.26 or later on 6.6.

## macOS

macOS has 1 forwarding table and lacks policy rules, so its reconciler installs
none. It refuses any `cap.table.id` or `cap.table.proto` other than the
defaults, 200 and 155. It installs nothing for an own prefix it originates
outside the overlay, where Linux installs a throw route, so a lookup for one
from a socket bound to no interface and no address of the utun ends as row D2 of
[where a lookup ends on macOS](routing.md#where-a-lookup-ends-on-macos) gives.
Its hold of each overlay prefix, and the kill switch under
`cap.exit.fallback = "none"`, are reject routes on `lo0`, as
[the kill switch on macOS](routing.md#the-kill-switch-on-macos) gives.

A route belongs to the reconciler when it leaves the utun with the shape ranet3
installs, a prefix route whose gateway is the interface itself, or at full
length a host route whose gateway is the interface. The reconciler adopts and
withdraws such a route even when another process installed it, so give ranet3 a
utun no other program writes. On `lo0` it owns the reject routes of the switch's
shape at the switch's keys and the overlay's alone. macOS cannot replace a
route. A route another program holds under the same key stays, and the
reconciler warns about it once.

macOS has no rule to select a mark, so its underlay sockets carry none. In mode
off and under `cap.exit` alike, each underlay datagram names the interface the
selection answers or the source its pin holds, as
[the underlay's interface](routing.md#the-underlays-interface-on-macos)
describes.

Interface scope on macOS takes the place of the policy rules on Linux. In mode
off it keeps the host's own traffic from being captured.
[Where a lookup ends on macOS](routing.md#where-a-lookup-ends-on-macos) gives
each route's scope and where each lookup ends. The reconciler installs these
routes scoped to the tun, which no socket selects unless it asks for the tun by
name:

- a source-specific route
- a retracted route, which it holds as a reject route, unless the route counts
  as a default, whose hold it does not install at all
- any route outside the overlay inside an unscoped route of the host's longer
  than `/0` out of another interface, a member of the zero-free cover among
  them, as Linux's rule 5410 answers by such a route ahead of the mesh's table,
  and the pieces outside the overlay of one there that holds a prefix of the
  overlay, as
  [where a lookup ends on macOS](routing.md#where-a-lookup-ends-on-macos) gives
- in mode off, or in a family `cap.exit` leaves out, any route that
  [counts as a default](routing.md#routes-that-count-as-a-default)

A source-specific route is installed only when its source prefix holds an
address on the tun, because interface scope stands in for "from an address of
ours". A destination holds 1 scoped route. A scoped route a pass still wants
keeps its destination. Otherwise the pass installs the route with the most
specific source, and skips and logs the rest once.

Under `cap.exit` a Mac takes a mesh exit through
[the zero-free cover](routing.md#the-zero-free-cover-on-macos), which gives the
routes each mode and family installs. A family the tun holds no overlay address
of is left out of the mode and keeps mode off's form. Where the utun holds no
address of a family at all, in either mode, the reconciler installs none of its
routes, as
[the limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) give. In
either mode a route of the mesh holding an address the underlay sends to goes in
as the pieces of it around the address in the cases
[where a lookup ends on macOS](routing.md#where-a-lookup-ends-on-macos) gives.
In either mode the daemon writes no route outside the tun but the reject routes
on `lo0`, the overlay's holds and the kill switch's, as
[the kill switch on macOS](routing.md#the-kill-switch-on-macos) gives, and a
reload moves the routes between the two forms with no restart.

A source-specific route and a retracted one stay scoped in either mode.
Interface scope is the only way macOS expresses a source. An unscoped reject
route at a default would answer the whole host's traffic with an error.

### Gaps on macOS

`cap.exit` on macOS is routes in the one table. These parts of it are refused at
startup and on a reload, each for what this build lacks there:

- `cap.exit.forward`, refused with
  `kernel: cap.exit forward is refused on macOS, where this build has no rule that routes a forwarded packet by the link it arrived on: remove forward, and a packet this host forwards toward an exit in a family the mode covers follows the mode into the tun as the host's own does, which drops a source this node does not own`.
  On Linux that rule is 5440 of [exit mode](routing.md#exit-mode-on-linux).
- `cap.exit.inbound`, refused with
  `kernel: cap.exit inbound is refused on macOS, where this build's kill switch is reject routes with no line passing a listed service's replies: while no exit is live and after a crash a service's replies leave by the uplink over IPv6 TCP whether it is bound to the uplink's address or to the wildcard and over UDP where it is bound to the uplink's address, and are refused over IPv4 TCP and over UDP on the wildcard, whatever inbound lists, so remove inbound`.
  On Linux the switch's reply lines pass what it lists, as
  [the kill switch](routing.md#the-kill-switch-on-linux) gives.

`cap.exit.lan` loads and widens nothing on macOS, where
[the kill switch](routing.md#the-kill-switch-on-macos) passes every connected
network by its own route.

A `cap.route` entry that
[counts as a default](routing.md#routes-that-count-as-a-default) is refused at
startup and on a reload too, with
`config: cap.route announces ::/0, which counts as a default and asks this node to carry other nodes' traffic out of the mesh, and this build for darwin carries that traffic only through cap.egress, since it runs no entry chain to pass the replies of what its kernel forwards into the mesh`.

`cap.egress` on macOS is the userspace exit. It refuses a class of `none`,
`return` and a subnet at startup, answers every protocol but TCP, UDP and ICMP
as refused, and carries no connection from outside to a leaf, as
[the exit on macOS](exit-nodes.md#the-exit-on-macos) gives with each refusal and
what it carries.

A Mac that forwards under `cap.exit` loses some of what it forwards toward an
exit, and the daemon warns, as
[the limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) give.

## Other platforms

On a platform other than Linux, macOS, iOS and Android:

- `cap.table` fails the start with `kernel: unsupported on this platform`.
- `cap.egress` and `cap.exit` are refused in words that name the platform, and
  the underlay sockets carry no mark.
- `overlay` and `cap.antispoof` load, and the antispoof filter is not enforced,
  as [the antispoof filter's platforms](antispoof.md#platforms) say.
- An egress segment fails the start, since it needs `cap.egress`, which is
  refused. A `cap.route` entry that counts as a default is refused at startup
  and on a reload, as [gaps on macOS](#gaps-on-macos) gives.
- The node has no network watch, so a moved host waits for each session's own
  liveness check.
- Every peer shares the 1 socket of its family, busy or not.
- The tun takes its MTU only when it opens, so a change to `link.mtu` or to the
  steering that moves the tun needs a restart. A reload applies one that leaves
  the tun where it was.
- The node reads no forwarding setting, so `status` shows forwarding as
  `unknown` and logs no antispoof warning.
- The node reads no caller credentials, so its records of who asked name no
  caller.
- Datagrams leave without DF, as [path MTU](#path-mtu) below describes.
- Answers leave from the kernel's choice of source, not the address the request
  reached.
- The ECN field of a datagram's outer header is not read, so a CE mark a hop set
  on the underlay is lost, as [ECN](design/protocol-deviations.md#ecn)
  describes.

iOS and Android build the underlay sockets, the sockets connected to 1 peer, the
path MTU search, the forwarding read and the caller credentials of macOS and
Linux, but none of the reconciler, the network watch, `cap.egress`, the
antispoof filter or the entry chain. Neither drops a mesh source from outside,
since iOS has no packet filter an application can write and an Android
application cannot filter the device's inbound traffic. Each refuses every way
of becoming an exit, a `cap.route` entry that counts as a default among them, so
no exit's replies need the entry chain there. A device the node reads as
forwarding is warned, as [at a glance](#at-a-glance) gives. An Android build,
which Go makes with the `linux` build tag, and an iOS build, which it makes with
the `darwin` one, refuse `cap.egress` at startup, and `cap.exit` and a
`cap.route` entry that counts as a default at startup and on a reload, in the
same words, naming `android` or `ios`, and load `overlay` with no filter, as the
BSDs do. `cap.table` fails the start there too, and a moved host waits for each
session's own liveness check. An iOS build opens no selection, so its underlay
datagrams name no interface and leave by the host's own routes. A session there
that sends from the kernel's choice of source reads its path MTU from the
interface holding the source the kernel picks for a socket connected to the
peer, and one the peer opened from the interface holding the address it sends
from.

## Moving hosts

A node keeps its sessions when its own addresses change, as a laptop's do when
it moves from Wi-Fi to a dock or a DHCP lease renews, and when its peer's do.
Every session follows its peer as
[endpoint updates](design/protocol-deviations.md#endpoint-updates) gives, and
answers a request from the address it arrived on. Beyond those answers, a
session this node dialed leaves the source address to the kernel. Its sends
leave from whatever address the host holds at the time. A session a peer opened
sends from the address the peer's latest fresh request or answer arrived on, on
Linux and macOS alike, and one that reaches another of this host's addresses
moves it there. Once that address has gone and the kernel refuses a send from
it, the session sends from the kernel's choice until a later fresh request or
answer moves it to the address that one arrived on. On other platforms but iOS
and Android the kernel always chooses.

The session falls back to the kernel's choice whenever the kernel refuses a send
from the address with `ENETUNREACH`, `EHOSTUNREACH`, `EINVAL`, `ENODEV`,
`EADDRNOTAVAIL` or `ENXIO`. Once a send from the kernel's choice has gone after
`EHOSTUNREACH`, a fresh request or answer to the address within 1 minute changes
nothing, and the session keeps sending from the kernel's choice. The first one
after that minute moves the session back to the address, and a send refused with
`EHOSTUNREACH` again falls back again, at most once every minute. After any of
the other refusals, the next fresh request or answer that reaches the address
moves the session back at once. Where the session's traffic from the other
address still reaches the peer, the session works, and it stays there until a
fresh request or answer reaches the address. Each answer to a request that
reaches the address is sent from the address itself first, so answers leave from
it as soon as it routes again.

A session that cannot send at all, because the host has no route to the peer,
holds while its liveness check retransmits on the usual schedule, and ends once
the check has gone unanswered through its whole budget of 62 seconds. Its dialer
then dials again. The first send that fails is logged as a warning, and the
failures after it at debug until a send goes out again.

A node also watches the host's network, so it does not wait for a liveness
deadline to find a moved path. On Linux it follows the link, address and route
notifications of rtnetlink, keeping only defaults in `main`. On macOS it follows
the route, address and link messages of the
[routing socket](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/rtsock.c#L1610),
and beside them the kernel's
[network events](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/net_kev.h#L34)
of the subclasses that can bring a link, take one away or move its addresses,
`KEV_INET_SUBCLASS`, `KEV_DL_SUBCLASS`, `KEV_INET6_SUBCLASS` and
`KEV_ND6_SUBCLASS`, since neither alone reports every change. 250 milliseconds
after a notification it reads, for each family, the host's own default route,
its interface and gateway, the global unicast addresses of the interfaces that
are up, and each link that is up, the loopback among them, with its prefixes and
point-to-point far ends. An IPv6 address counts once duplicate address detection
ends, and never where detection found it duplicated. On Linux a far end counts
as the network the kernel routes by it. On macOS a far end, and an IPv4 address
on a point-to-point link or the loopback, count as hosts
([`in_ifinit`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in.c#L1787)).
The mesh's own device is left out of all three, so the reconciler's writes to
its table and to the tun never count. When the default or an address differs
from the reading last acted on, every session is asked to prove its path at
once, as `ranet3 debug probe` asks it, and every dialer that is waiting out its
reconnect delay, or the wait after a dial the host had no route for, dials
again. A change of links alone probes no session and wakes no dialer, and wakes
the reconciler only under [`cap.exit`](routing.md#exit-mode-on-linux). Either
change is recorded as a `network.changed` event naming what moved. A dialer that
finds its session healthy stands down as it does after any wake, and so does one
behind a [`preferred`](control-socket.md#requests-and-answers) session its own
dial would not replace. A change the host shows nowhere, such as a captive
portal that lets nothing through, needs `ranet3 redial --all` instead.

The watch also reads the host every 30 seconds whether or not a notification
came, and acts only where the reading moved, which finds a change whose
notification a full receive buffer dropped
([`netlink_overrun`](https://github.com/torvalds/linux/blob/v7.3/net/netlink/af_netlink.c#L351),
[`raw_input`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/net/raw_usrreq.c#L90)).
A read that fails is read again after 1 second, the wait doubling to 30 seconds
until a read succeeds, and no notification shortens it. While its reads fail the
watch keeps the reading of its last read that succeeded, `ranet3 debug netmon`
shows since when they fail, how many did and the last error, and a
`network.read` event records each turn to failing and back that the daemon sees.

## Sockets connected to 1 peer

On Linux and macOS the transport listens on 1 UDP socket per family, bound to
the wildcard address on `link.port`, and every peer starts on it. A busy peer
then gets a socket of its own, connected to it, whose sends keep 1 cached route.
On Linux that cached route holds the socket's datagrams to 1 transmit queue, as
the kernel's queue selection in
[dev.c](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/core/dev.c)
chooses it.

The transport counts the bytes each address pair carries, sent and received
together. A pair is this host's address and the peer's address and port. On
Linux and macOS the address of a session a peer opened is the one the peer's
latest fresh request or answer arrived on, and a session this node dialed, or
one whose sends fell back from that address, leaves it to the route. A pair that
carries 1 MiB within 1 sweep of 30 seconds gets a socket on `link.port`, the
listener's port, bound to its address or to the one the route picks then, and
connected to the peer. The peer sees the same address and port as before. The
pair's sends leave on that socket. The kernel hands the socket the peer's
datagrams to that address ahead of the listener, and a reader of its own takes
them to the same sessions. Before Linux 5.4, once 2 such sockets share 1
address, the kernel hands each datagram to that address from a peer with a
socket of its own to 1 of them by a hash, so a peer's datagrams can arrive on
another peer's socket. Every reader takes them to the same sessions, so none is
lost. A node holds at most 256 such sockets. A pair past the cap stays on the
shared socket.

On Linux the socket of a session a peer opened also leaves by the interface the
peer's latest fresh request or answer arrived on, as the shared socket's replies
do. An IPv4 socket binds to that interface with `SO_BINDTOIFINDEX`, which Linux
has from 5.1 and allows a process without `CAP_NET_RAW` from 5.7. Where the
kernel refuses the bind, such a session stays on the shared socket. An IPv6
socket names the interface with `IPV6_UNICAST_IF`, which like the reply's own
choice prefers that interface only among the routes of the lowest metric. A
link-local address binds on that interface alone. On macOS the socket of a
session the peer opened binds the address the peer's latest fresh request or
answer reached, and an IPv6 link-local one also its arrival interface. Only a
socket whose sends leave the source to the kernel binds on the interface
[the selection](routing.md#the-underlays-interface-on-macos) names for the peer,
from the source the route scoped to that interface picks, and moves with it.

A socket connected to 1 peer closes:

- when it carried nothing for a whole sweep.
- when the last session sending on it ends, or moves to another address.
- on a move of the host's default or one of its addresses, as
  [moving hosts](#moving-hosts) describes. A busy pair connects again at its
  next send, from the address its pair names then.
- on macOS, when the selection names another interface for the peer. The next
  send connects a socket on that interface.
- when a read on it fails other than for an ICMP error, or a send fails other
  than once for an ICMP error, as below, or for a refusal of its segments, as
  [path MTU](#path-mtu) describes. Its datagrams then leave the shared socket,
  and the pair waits for the next sweep before it connects again.

The kernel hands a connected socket the ICMP errors its datagrams draw, such as
a port unreachable from a peer that restarted or a smaller path MTU from a hop
on the way. The next read or send on the socket reports such an error. A read
goes on past it. A send that reports one is written once more on the socket,
which stays when that succeeds or is refused for size, and closes when it fails
again. A datagram past the path MTU is refused on that socket too. It then goes
to the shared socket, whose refusal reports the path to the session's search,
and the socket stays.

A connected socket keeps the source address it bound. On Linux an IPv4 send from
an address the host lost is refused, and the socket closes at once. An IPv6 send
from such an address still leaves, so only a move of the host's default or one
of its addresses closes the socket. Naming the source on each IPv6 send instead
would cost the socket the cached route that keeps its transmit queue.

Each such socket follows the path MTU discovery mode of its family's shared
socket. While a session of its family is under the floor, it lets the host
fragment its datagrams as the shared socket does, as [path MTU](#path-mtu) below
describes. A socket the host does not let change its mode closes as failed.

On Linux each socket connected to 1 peer reads 4 messages of 64 KiB at once,
which is 256 KiB of buffers per socket and 64 MiB at the cap, and asks the
kernel for 4 MiB of socket buffer each way. Before Linux 6.13 the kernel matches
each datagram to an address on the port against every socket bound to that
address, up to 256, before it reaches the listener. From 6.13, on a kernel built
without `CONFIG_BASE_SMALL`, a datagram from a peer with a socket of its own
finds that socket at once, and the others still pass every socket bound to their
address. On macOS each socket reads 1 datagram of 64 KiB at a time.

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

On macOS the listener binds with neither `SO_REUSEADDR` nor `SO_REUSEPORT`. A
socket connected to 1 peer sets `SO_REUSEADDR` before it binds 1 address on the
listener's port beside it. No socket sets `SO_REUSEPORT`.

## Path MTU

On Linux and macOS each session searches its path for the largest packet it
carries, as [path MTU](path-mtu.md) describes. The platforms differ in what the
host tells that search.

On Linux every datagram leaves with `IP_PMTUDISC_DO` or `IPV6_PMTUDISC_DO` while
no session of its family fragments. The host refuses a datagram past the path
MTU its route holds, including a smaller one learned from an ICMP answer. The
session then reads that MTU and lowers its budget to the largest packet it
leaves room for, as [path MTU](path-mtu.md) describes, and the datagrams within
it still go.

A batch of ESP for 1 peer goes out as segmented messages where it can. Linux can
refuse a segmented message where it takes single datagrams. This happens on a
route through an IPsec policy, on a kernel before 6.14 when a segment exceeds
the path MTU, and on a socket that fragments for a session under the floor. The
node then sends those datagrams again, 1 per message. That peer gets single
datagrams for 10 minutes, the time Linux keeps a path MTU it learned. Every
other peer keeps segmenting. On a socket that fragments, a message refused with
`EMSGSIZE` is first sent once more segmented, because a socket connected to 1
peer holds the `EMSGSIZE` of a Packet Too Big for its next send alone. Only a
second refusal stops the segments. A
[socket connected to 1 peer](#sockets-connected-to-1-peer) does the same and
stays open. The stop holds for that peer on the shared socket and on its own
alike.

On macOS every datagram leaves with `IP_DONTFRAG` or `IPV6_DONTFRAG`, but for
those the host fragments for a session under the floor, as below. A send refused
for its size reads the MTU of the interface it sends through, and the session's
search takes that as its route's MTU. A session the peer opened sends through
the interface holding the address it sends from, the one the peer's latest fresh
request or answer reached until a send from it falls back, as
[moving hosts](#moving-hosts) describes, and an IPv6 link-local one through the
interface that request or answer arrived on. Any other session, one whose send
fell back included, sends through the interface
[the selection](routing.md#the-underlays-interface-on-macos) names for its peer.
The search reads the same MTU when it starts, and the probes alone find a
narrower hop beyond it.

A session on a path under the floor fragments on either platform as
[the design's limits](design/limits.md) describe. While one does, Linux lets the
host fragment every datagram of that family, and macOS does the same for IPv4.
On macOS an IPv6 peer under the floor has only its own datagrams fragmented. On
any other platform but iOS and Android datagrams leave without DF, nothing is
searched and every session carries `link.mtu`, which leaves a narrower path to
the host's and the routers' fragmenting.

## The control surface

The control surface is an HTTP handler that serves JSON over any listener. The
`control` package binds it to a Unix socket. On Linux and macOS, and on iOS and
Android, it also reads each caller's credentials from that socket. Elsewhere it
reads none, and its records of who asked name no caller.
