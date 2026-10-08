---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Platforms"
description: "What the route reconciler can do on Linux and on macOS, and how sessions follow a host that moves."
created: 2026-09-21
updated: 2026-10-08
order: 100
---

The reconciler's job is the same everywhere and the facilities under it are not,
so the configuration names what it wants and each backend reaches it the way its
kernel allows. A backend that cannot reach something refuses the configuration
by name, at startup or on a reload, rather than coming up with a working mesh
and no steering, which is the failure that reads as a routing problem for a day.

The tun is `ranet3` on linux unless `link.tun` names another device, and a utun
on darwin, `utun` for the next free unit or `utunN` for unit N, since the utun
control creates nothing else. Either way the reconciler works on the name the
device was given rather than the one configured, which on darwin is the unit it
got, `utun6` for instance.

**linux** has policy rules and 2^32 tables, and the reconciler needs linux 4.20
or later. It asks the kernel to filter its route dumps to its own table, with
`NETLINK_GET_STRICT_CHK`, so a host holding a full table in main costs it no
more than its own routes, and it marks rules with `FRA_PROTOCOL`, which arrived
in 4.17. `cap.table.rules` are installed with `FRA_PROTOCOL` set to
`cap.table.proto`, the same ownership marker the routes carry, so a dump reads
back only this reconciler's and a delete can never reach another writer's.
systemd-networkd stamps `RTPROT_STATIC` on the rules it writes, so a node
mid-migration keeps the two sets apart on its own. `cap.table.prefsrc4` takes an
IPv4 address in its plain spelling. The IPv4-mapped one, `::ffff:198.18.104.5`
for instance, is refused with the spelling to write instead.

`cap.table.vrf.create` makes the master device the mesh table is bound to when
no device of that name exists. One this process created is removed again at
shutdown, found by the index it was created under, so a device somebody else
made under the same name in the meantime stays with everything in its table. One
it found is left alone with everything in its table, whatever table that is: a
device somebody else bound to another table is adopted as it stands, so the
tun's lookups go there rather than to `cap.table.id`. A device of another kind
holding the name is refused by name rather than answered with a bare errno.

Every pass that finds the tun in the VRF reads which table the VRF is bound to,
and warns once per change when that is another table than `cap.table.id`, so a
VRF made or remade while ranet3 runs is reported as well as one made before it.
Traffic inside the VRF is looked up in the VRF's own table and falls through to
main wherever nothing there matches, so it reaches the mesh's routes only
through a policy rule, and a ping that leaves by the uplink proves nothing. The
warning's `fix` attribute names the change to make: bind the VRF to
`cap.table.id` in whatever creates it, or set `cap.table.id` to the VRF's table,
the second offered only outside 253 to 255, which `cap.table` refuses. It never
advises deleting the device, which would detach the VRF's other links and leave
the one recreated in its place a device this process removes at shutdown.

**darwin** has one forwarding table, no rules and no VRFs, and refuses
`cap.table.rules`, `cap.table.vrf` and `cap.table.prefsrc4` by name. It reaches
the two ends the rules exist for with interface scope instead: an announced
default and a source-specific route are installed scoped to the tun, so no
unbound socket can select either, which keeps the machine from being captured
and the ESP underlay out of the tunnel carrying it. `link.underlay.mark` is
refused there for the same reason, since there is nothing for a mark to select
and nothing to select it with; `link.underlay.bind` is the local spelling, and
with it set the socket's lookups are scoped to the underlay interface, that
interface is given a default of its own, and an announced default is installed
plain, without which a node cannot use a mesh exit. A source-specific route and
a retracted one stay scoped either way: interface scope is the only thing on
this platform that expresses a source at all, and an unscoped hold at a default
answers the whole machine's traffic with an error.

**iOS and Android**, planned rather than present, have less again: the tunnel is
a `NEPacketTunnelProvider` or a `VpnService`, the process is handed a list of
routes to include and exclude, and there is no table, no rule and no netlink at
all. The underlay stays out of the tunnel because the platform keeps it out,
`VpnService.protect` on one side and the provider's own socket handling on the
other, so a mark is unnecessary there as well. What the reconciler computes, the
set of prefixes the mesh reaches and the source prefix each one is for, maps
onto those lists directly; what it will not have is a table to put them in.

A node keeps its sessions when its own addresses change, as a laptop's do when
it moves from wifi to a dock or a DHCP lease renews, and when its peer's do.
Every session follows its peer to the address and port its latest fresh
authenticated request came from, and answers a request from the address it
arrived on. Beyond those answers, a session this node dialed leaves the source
address to the kernel, so its sends leave from whatever address the host holds
at the time, while a session a peer opened sends from the address the peer's
latest request arrived on. On linux, once that address has gone and the kernel
refuses a send from it, the session sends from the kernel's choice until a later
request moves it to the address that one arrived on. darwin never names a
source, so there the kernel always chooses.

A session that cannot send at all, because the host has no route to the peer,
holds while its liveness check retransmits on the usual schedule, and ends once
the check has gone unanswered through its whole budget of 62 seconds. Its dialer
then dials again. The first send that fails is logged as a warning, and the
failures after it at debug until a send goes out again.

A node also watches the host's network, so it does not wait for a liveness
deadline to find a moved path. On linux it follows the link, address and route
notifications of rtnetlink, keeping only defaults in `main`, and on darwin the
routing socket. 250 milliseconds after a notification it reads, for each family,
the host's own default route, its interface and gateway, and the global unicast
addresses of the interfaces that are up. The mesh's own device is left out of
both, so the reconciler's writes to its table and to the tun never count. When
the reading differs from the last one acted on, every session sends a liveness
check at once, every dialer that is waiting out its reconnect delay dials again,
and a `network.changed` event records what moved. A dialer that finds its
session healthy stands down as it does after any wake. A change the host shows
nowhere, such as a captive portal that lets nothing through, needs
`ranet3 redial --all` instead.

On linux a batch of ESP for one peer goes out as segmented messages where it
can. A path too narrow for the segments refuses such a message, and its
datagrams go again one to a message. That peer is then sent single datagrams for
10 minutes, the time linux keeps a path MTU it learned, and every other peer
keeps segmenting. Only a refusal that segments can cause, and that single
datagrams then pass, stops segmentation.

The control surface is platform-neutral by construction. `control` holds the
types and the handler and speaks no transport of its own, so the unix socket is
how linux and darwin reach it and a mobile app reads the same JSON over the
extension's own channel.
