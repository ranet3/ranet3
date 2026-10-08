---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Reloading"
description: "What a reload applies without dropping a session, and what needs a restart."
created: 2026-09-12
updated: 2026-10-08
order: 70
---

`SIGHUP` re-reads the config file and the registry and reconciles rather than
restarting. It applies the registry itself, the peers dialed, the prefixes
originated, `cap.babel`, `cap.segment`, `link.listen` and `cap.table`, so a node
joining or leaving the mesh costs one dialer instead of dropping every SA this
node is carrying. ranet's own `ExecReload` works the same way, and it matters
because the registry is rewritten every time any node joins.

A reload also decides which sessions stay. The registry is the trust root a
handshake is checked against, so a node taken out of it stops being carried:
every session whose authenticated peer the new registry no longer names is
closed, and the line naming it says so. A registry read mid-write fails to parse
rather than arriving empty, so the sweep never runs against half a file.

A session this node dialed also ends when its dialer does, and taking the peer
out of `dial.to` stops that dialer. One the peer opened against this node
survives, because nothing was dialing it, unless the same reload turns
`link.listen` off.

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
another writer put on the tun stays, named or not. The tun keeps an IPv4 address
throughout, since linux drops every IPv4 route through a device left with none,
another writer's included. A new prefix length of an IPv4 address goes on before
the old one comes off, and the reconciler turns `promote_secondaries` on for the
tun when it starts, which lets a new address within the old one's subnet take
its place instead of leaving with it. From then on the periodic sweep runs every
`reconcile`, and an announced default outlives the last live session by
`capture_grace`. A reconciler stopped with `ranet3 disable reconciler` takes the
block as well and installs it once it is started again. So a running exit takes
a new priority rule, a renumbered tun or another metric without dropping a
session or withdrawing the mesh table from the rest of the fleet.

A change to `cap.table.id`, `cap.table.proto` or `cap.table.vrf` is refused by
name, and so is writing the block where there was none or taking it out. The
reconciler reads and writes its routes and rules in the table and under the
protocol it started with, and its tun is bound to the VRF, so a restart applies
them. A reload asking for something the platform does not have is refused as a
startup is, rules or `prefsrc4` on darwin for instance.

A reload hands a changed `cap.babel` to the running speaker, every field of it:
`hello`, `update`, `quality` and `cost`. The speaker keeps its sequence number
and the Hello history of every neighbor, computes each link cost again and
reruns route selection under the new cost. It then sends every neighbor a Hello
with its IHU and its whole table at once, and runs its timers on the new
intervals from there. RFC 8966 lets a node lengthen its Hello and IHU intervals
only just before a Hello that says so, sections 3.4.1 and 3.4.2, and a neighbor
expires a route at 3.5 times the update interval it last heard, Appendix B, so
the new intervals reach every neighbor before the old ones run out. A
`cap.babel` that describes the speaker already running, an omitted field written
out as its default for instance, changes nothing and sends nothing.

A reload builds the tables a changed `cap.segment` describes, as a startup does,
and installs them: the segments this node answers for and its steering. A packet
already in flight is acted on under the table it met. The tun's MTU is set once,
when the tun is made, from the longest segment list the steering carries, so a
reload whose steering needs another MTU is refused by name and a restart applies
it. A steering stopped with `ranet3 disable steering` stays stopped with the new
table installed.

Turning `link.listen` on starts the responder. Turning it off stops it
answering, closes every session this node answered with a Delete, as a shutdown
does, and wakes every dialer, so a peer this node also dials comes back at once
rather than after the reconnect delay. The sessions this node dialed stay. The
hub drops the handshakes it had queued for the responder and queues none while
it is off, so a responder started again later answers only what arrives after
it. A responder stopped with `ranet3 disable responder` stays stopped across a
reload.

A reload is recorded as a `daemon.reload` event whose `applied` lists the blocks
it changed among `cap.babel`, `cap.route`, `cap.segment`, `cap.table` and
`link.listen`, comma separated: `applied=cap.table` for one that changed the
table, and none for one that changed only the trust document or the peers
dialed. The speaker records a `babel.config.applied` with the intervals and the
cost it took, and turning `link.listen` on or off records a `responder.changed`
whose `closed` counts the answered sessions it closed. The reconciler's pass
after it is a `kernel.pass` with `trigger=reload`, recorded whether or not it
moved anything. A reconciler stopped with `ranet3 disable reconciler` runs no
pass when it takes the block, and the pass that installs it once the reconciler
is started again is recorded with `trigger=enable`.

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, TUN device and local endpoints each change what peers have
already authenticated or what the dataplane is attached to. So does the private
key. It is read once at startup and the responder holds its own copy, so a
reload re-reads the file only to compare: a rotation is refused by name whether
it moved the path or rewrote the file in place, rather than reported as applied
while the node keeps signing with the key it started on. `cap.egress` is read
once at startup as well: the capability owns the tables it created under the
families the old block named, and a new one applied here would leave the host
holding rules from a configuration nothing is running. With `return` set it also
picked then, for each family it advertises with no `source4` or `source6`
written, the source among this node's mesh addresses, the host prefixes
`cap.route` announces and `cap.table` assigns. A reload whose addresses would
pick another source is refused, naming the blocks, and one that leaves none or
more than one to pick from is refused as a startup would be. A reload that moves
only addresses the pick does not consider is applied: any of them under a
written source, one of a family the node does not advertise, a link-local one,
or one assigned under a prefix shorter than a host prefix, `10.66.0.7/24` for
instance. The rekey and replay settings are captured by a session when it is
created, so applying them to new sessions alone would leave the node running two
policies at once. A restart is the honest way to change any of them, and a
refused reload changes nothing: not the registry, the dialers, the
announcements, the speaker, the segment tables, the responder or the table.
