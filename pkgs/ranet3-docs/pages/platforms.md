---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Platforms"
description: "What the route reconciler can do on Linux and on macOS."
created: 2026-09-21
updated: 2026-10-06
order: 100
---

The reconciler's job is the same everywhere and the facilities under it are not,
so the configuration names what it wants and each backend reaches it the way its
kernel allows. A backend that cannot reach something refuses the configuration
by name at startup rather than coming up with a working mesh and no steering,
which is the failure that reads as a routing problem for a day.

The tun is `ranet3` on linux unless `link.tun` names another device, and a utun
on darwin, `utun` for the next free unit or `utunN` for unit N, since the utun
control creates nothing else. Either way the reconciler works on the name the
device was given rather than the one configured, which on darwin is the unit it
got, `utun6` for instance.

**linux** has policy rules and 2^32 tables. `cap.table.rules` are installed with
`FRA_PROTOCOL` set to `cap.table.proto`, the same ownership marker the routes
carry, so a dump reads back only this reconciler's and a delete can never reach
another writer's. systemd-networkd stamps `RTPROT_STATIC` on the rules it
writes, so a node mid-migration keeps the two sets apart on its own.
`cap.table.vrf.create` makes the master device the mesh table is bound to when
no device of that name exists. One this process created is removed again at
shutdown. One it found is left alone with everything in its table, whatever
table that is: a device somebody else bound to another table is adopted as it
stands, so the tun's lookups go there rather than to `cap.table.id`.

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

The control surface is platform-neutral by construction. `control` holds the
types and the handler and speaks no transport of its own, so the unix socket is
how linux and darwin reach it and a mobile app reads the same JSON over the
extension's own channel.
