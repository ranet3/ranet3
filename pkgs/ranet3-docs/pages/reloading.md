---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Reloading"
description: "What a reload applies without dropping a session, and what needs a restart."
created: 2026-09-12
updated: 2026-10-07
order: 70
---

`SIGHUP` re-reads the config file and the registry and reconciles rather than
restarting. It applies the registry itself, the peers dialed, the prefixes
originated and `cap.table`, so a node joining or leaving the mesh costs one
dialer instead of dropping every SA this node is carrying. ranet's own
`ExecReload` works the same way, and it matters because the registry is
rewritten every time any node joins.

A reload also decides which sessions stay. The registry is the trust root a
handshake is checked against, so a node taken out of it stops being carried:
every session whose authenticated peer the new registry no longer names is
closed, and the line naming it says so. A registry read mid-write fails to parse
rather than arriving empty, so the sweep never runs against half a file.

A session this node dialed also ends when its dialer does, and taking the peer
out of `peers:` stops that dialer. One the peer opened against this node's
`responder` survives, because nothing was dialing it.

Revocation tests whether the organization still names the node and its key still
parses, not which endpoint the peer asserted. Renumbering a serial is a registry
edit rather than a revocation, and a node whose own endpoints were renumbered
has done nothing to lose the session it is carrying.

A reload hands a changed `cap.table` to the running reconciler, which takes a
new `metric`, `prefsrc4`, `addresses`, `assign_announced` with the `cap.route`
announcements it expands into, `rules`, `reconcile` and `capture_grace`. The
reconciler checks the block as it would at startup, takes it, and runs a pass at
once. That pass moves every route to the new metric and preferred source,
deletes the rules the block no longer names and installs the new ones, and takes
off the tun each address it added that the block no longer assigns. An address
another writer put on the tun stays, named or not. On linux one kind of change
still costs routes. A tun whose only IPv4 address takes another prefix length,
or is replaced within its subnet while `promote_secondaries` is off, has no IPv4
address for a moment, and linux then drops every IPv4 route through it. The pass
puts the reconciler's own routes back, and another writer's stay gone. From then
on the periodic sweep runs every `reconcile`, and an announced default outlives
the last live session by `capture_grace`. A reconciler stopped with
`ranet3 disable reconciler` takes the block as well and installs it once it is
started again. So a running exit takes a new priority rule, a renumbered tun or
another metric without dropping a session or withdrawing the mesh table from the
rest of the fleet.

A change to `cap.table.id`, `cap.table.proto` or `cap.table.vrf` is refused by
name, and so is writing the block where there was none or taking it out. The
reconciler reads and writes its routes and rules in the table and under the
protocol it started with, and its tun is bound to the VRF, so a restart applies
them. A reload asking for something the platform does not have is refused as a
startup is, rules or `prefsrc4` on darwin for instance.

A reload is recorded as a `daemon.reload` event whose `applied` names the
capabilities it changed, `applied=cap.table` for one that changed the table, and
none for one that changed only the trust document. The reconciler's pass after
it is a `kernel.pass` with `trigger=reload`, recorded whether or not it moved
anything. A reconciler stopped with `ranet3 disable reconciler` runs no pass
when it takes the block, and the pass that installs it once the reconciler is
started again is recorded with `trigger=enable`.

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, TUN device and local endpoints each change what peers have
already authenticated or what the dataplane is attached to. So does the private
key. It is read once at startup and the responder holds its own copy, so a
reload re-reads the file only to compare: a rotation is refused by name whether
it moved the path or rewrote the file in place, rather than reported as applied
while the node keeps signing with the key it started on. The `babel` block is
built into the speaker once, apart from the prefixes it originates, which a
reload does apply. `cap.egress` is read once at startup as well: the capability
owns the tables it created under the families the old block named, and a new one
applied here would leave the host holding rules from a configuration nothing is
running. With `return` set it also picked then, for each family it advertises
with no `source4` or `source6` written, the source among this node's mesh
addresses, the host prefixes `cap.route` announces and `cap.table` assigns. A
reload whose addresses would pick another source is refused, naming the blocks,
and one that leaves none or more than one to pick from is refused as a startup
would be. A reload that moves only addresses the pick does not consider is
applied: any of them under a written source, one of a family the node does not
advertise, a link-local one, or one assigned under a prefix shorter than a host
prefix, `10.66.0.7/24` for instance. The rekey and replay settings are captured
by a session when it is created, so applying them to new sessions alone would
leave the node running two policies at once. And `responder` decides whether the
node answers at all, which is wired up before the reload path exists. A restart
is the honest way to change any of them, and a refused reload changes nothing:
not the registry, the dialers, the announcements or the table.
