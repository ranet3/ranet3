---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Reloading"
description: "What a reload applies without dropping a session, and what needs a restart."
created: 2026-09-12
updated: 2026-10-30
order: 70
---

`SIGHUP` re-reads the config file and the trust document and reconciles instead
of restarting. A reload applies the trust document, the peers dialed,
`auth.aliases`, the prefixes originated, `cap.babel`, `cap.segment`, the
transform lists of `cap.crypto`, `link.listen`, `link.mtu` and most of
`cap.table`. A node joining or leaving the mesh then costs 1 dialer, and every
other session this node carries stays up. This matters because the trust
document is rewritten every time any node joins.

## Asking for a reload

`ranet3 reload` asks for the same reload over the
[control socket](control-socket.md). Both re-read the file the daemon was
started with. When the daemon refuses the reload, `ranet3 reload` prints the
refusal and exits 1. After `SIGHUP`, the refusal goes to the log, on a line
starting `reload:`, and to the `err` of the `daemon.reload` event. On NixOS,
`systemctl reload ranet3` runs `ranet3 reload`, as
[running it as a service](service.md) describes.

## What a reload does with each key

The table lists every key of the configuration file. The
[configuration reference](configuration-reference.md) gives each key's default.
A key marked "refused when its effective value changes" can be written out as
its default, or reordered, without a restart. A refused reload changes nothing,
as [what a reload refuses](#what-a-reload-refuses) describes.

| Key                                                                  | Reload                                   | Notes                                                                                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `node`                                                               | refused                                  |                                                                                                                                                                                                                                                                                                                                             |
| `auth.key`                                                           | refused when the key changes             | A new path to a file holding the same key is applied.                                                                                                                                                                                                                                                                                       |
| `auth.trust`                                                         | applied                                  | The path and the document. The new document is checked as [checks against the trust document](#checks-against-the-trust-document) describes.                                                                                                                                                                                                |
| `auth.aliases.remote`, `auth.aliases.local`                          | applied                                  | To the handshakes after the reload. A session already up keeps its peer. An empty table and none are the same.                                                                                                                                                                                                                              |
| `link.port`                                                          | refused                                  |                                                                                                                                                                                                                                                                                                                                             |
| `link.endpoints`                                                     | refused                                  | Compared as a set, so a new order is no change.                                                                                                                                                                                                                                                                                             |
| `link.listen`                                                        | applied                                  |                                                                                                                                                                                                                                                                                                                                             |
| `link.tun`                                                           | refused                                  | Compared as written. Writing the default name where the file left it out is a change.                                                                                                                                                                                                                                                       |
| `link.mtu`                                                           | applied                                  | Refused when the tun cannot move. An omitted `mtu` and `1400` are the same.                                                                                                                                                                                                                                                                 |
| `link.underlay.bind`                                                 | refused                                  |                                                                                                                                                                                                                                                                                                                                             |
| `dial.all`, `dial.to`                                                | applied                                  |                                                                                                                                                                                                                                                                                                                                             |
| `cap.route.announce`                                                 | applied                                  | Refused when it moves a mesh address of a family `cap.egress` translates. A prefix it drops is retracted and held, as [routing](routing.md#retracted-routes) describes. A default it starts announcing makes this node an [exit](exit-nodes.md#an-exits-own-traffic) from the reconciler's next pass.                                       |
| `cap.transit`, written, removed, or `enable`                         | refused when its effective value changes | A left-out block and `enable = false` are the same.                                                                                                                                                                                                                                                                                         |
| `cap.babel` and every key under it                                   | applied                                  |                                                                                                                                                                                                                                                                                                                                             |
| `cap.table`, written or removed                                      | refused                                  |                                                                                                                                                                                                                                                                                                                                             |
| `cap.table.id`, `cap.table.proto`                                    | refused when its effective value changes |                                                                                                                                                                                                                                                                                                                                             |
| `cap.table.metric`, `cap.table.reconcile`, `cap.table.capture_grace` | applied                                  |                                                                                                                                                                                                                                                                                                                                             |
| `cap.table.addresses`, `cap.table.assign_announced`                  | applied                                  | Refused when it moves a mesh address of a family `cap.egress` translates.                                                                                                                                                                                                                                                                   |
| `cap.segment` and every key under it                                 | applied                                  | Refused when the tun cannot move, and when it adds the first egress segment or removes the last.                                                                                                                                                                                                                                            |
| `cap.crypto.ike`, `cap.crypto.esp` and every key under them          | applied                                  | To each exchange after it. An SA holding a transform they leave out is rekeyed or replaced, as [`cap.crypto`](#capcrypto) says.                                                                                                                                                                                                             |
| `cap.crypto.replay`, `cap.crypto.rekey` and every key under it       | refused when its effective value changes |                                                                                                                                                                                                                                                                                                                                             |
| `cap.egress`, written, removed, or any key under it                  | refused when its effective value changes | A new order of `advertise` or `translate`, a class of `auto` from `0.0.0.0/0` or `::/0`, and `flows_per_source` or `sweep` written as its default are no change.                                                                                                                                                                            |
| `cap.border`, written or removed                                     | refused                                  |                                                                                                                                                                                                                                                                                                                                             |
| `cap.border.overlay`                                                 | applied                                  | The filter rewrites its chain on the pass the reload wakes, and the forwarding decision answers by the new overlay at once, every route judged again for whether it counts as a default. With `cap.table`, the reconciler's pass moves its rules at 5110 and its holds of the overlay. A new order is no change.                            |
| `cap.exit`, written, removed, or `forward`                           | applied                                  | The reconciler's next pass adds or removes [exit mode's](routing.md#exit-mode-on-linux) rules, with no restart. Refused on an exit, off Linux, and where `forward` names the tun or a default's link. A new order of `forward` is no change.                                                                                                |
| `cap.exit.fallback`, `cap.exit.inbound`, `cap.exit.lan`              | applied                                  | The reconciler's next pass writes or deletes [the kill switch's](routing.md#the-kill-switch-on-linux) rules and table, or rewrites the table's sets, in one pass. A reload to `"uplink"` or without `cap.exit` withdraws the switch. A new order or spelling of `inbound` that lists the same ports, or a new order of `lan`, is no change. |

## Sessions the trust document no longer admits

A reload also decides which sessions stay. It closes with a Delete every session
whose authenticated peer the new trust document no longer names, or names under
another key than the one that verified the session. A node taken out of the
document stops being carried, and so does one whose organization now holds
another key.

The log line `peer <path>: <reason>, closing the session` and an
`ike.session.revoked` event say which and why. A trust document read mid-write
fails to parse and refuses the reload, so the sweep never runs against half a
file.

A handshake that began under the old document is checked against the new one
when its session is installed. A revoked peer cannot slip in between the sweep
and the end of its handshake. The responder checks each handshake against the
document and the `auth.aliases` in force when it arrives. It refuses an
initiator that names this node itself, whatever the document says. It also
refuses one whose ID names a node and no endpoint, or an endpoint the document
lists in the other family than the one the request arrived in, and a request
whose IDr names an endpoint it does not answer as. A request arriving in a
family where `link.endpoints` holds none or more than 1 entry is refused unless
its IDr names one of them. [The trust document](trust.md#families) lists these
refusals, each with `AUTHENTICATION_FAILED`. The families the document lists
therefore decide which handshakes are taken. Once a reload moves a peer's
endpoint to the other family, its next handshake in the old family is refused.

A session this node dialed also ends when its dialer does, and taking the peer
out of `dial.to` stops that dialer. One the peer opened against this node
survives, because nothing was dialing it, unless the same reload turns
`link.listen` off.

A dialer stopped while its `IKE_AUTH` request is unanswered waits up to 2
seconds for the answer, and closes with a Delete the session that answer opened
on the peer. When no answer comes in that time it sends nothing more, and the
peer's session ends once its liveness check goes unanswered.

Revocation tests whether the organization still names the node and still gives
it the key the session was verified under, not which endpoint the peer asserted.
Renumbering a peer's serial is an edit, not a revocation, and the peer keeps the
session it is carrying. Renumbering this node's own endpoints refuses the
reload, as
[checks against the trust document](#checks-against-the-trust-document)
describes.

## `cap.table`

A reload hands a changed `cap.table` to the running reconciler. It takes a new
`metric`, `addresses`, `assign_announced` with the `cap.route` announcements it
expands into, `reconcile` and `capture_grace`. The reconciler checks the block
as it would at startup and runs a pass at once. From then on the periodic pass
runs every `reconcile`, and an announced default outlives the last live session
by `capture_grace`. A reload that moves `cap.border.overlay` hands the
reconciler the new overlay with its block too, and its pass judges again which
routes [count as a default](routing.md#routes-that-count-as-a-default).

A reload also hands the reconciler the prefixes `cap.route` announces, with its
block, whenever they start or stop making this node an
[exit](exit-nodes.md#an-exits-own-traffic). A reload announcing a default
therefore makes the node an exit from the next pass, which withholds every route
that counts as a default, a learned one already installed among them. A reload
that stops making the node an exit lets the next pass install them again while a
session is live, on macOS with `link.underlay.bind` one holding its family's
zero address as the members of the zero-free cover it contains, as
[routing](routing.md#the-zero-free-cover-on-macos) describes.

On Linux that first pass moves every route but a hold or a throw to the new
metric, which macOS does not store. It derives the policy rules again, as
[routing](routing.md#policy-rules-on-linux) lists them, from the new overlay and
this node's own prefixes, deletes the ones it no longer derives and installs the
new ones. It takes off the tun each address it added that the block no longer
assigns. An address another writer put on the tun stays, named or not. The
mesh's own table holds each newly assigned address as this node's at once, and
gives back each one the block no longer assigns at once too, unless this node
still announces its host route. An address given back is held only while an
update this node sent naming it reachable has yet to expire at a neighbor, as
[routing](routing.md#retracted-routes) describes.

On Linux the tun keeps an IPv4 address throughout while the new block assigns
one, because Linux drops every IPv4 route through a device left with none,
another writer's included. A block that assigns none removes the last address
this node added, and the IPv4 routes through the tun go with it. A new prefix
length of an IPv4 address goes on before the old one comes off, and the
reconciler turns on `promote_secondaries` for the tun when it starts, so a new
address within the old one's subnet takes its place instead of leaving with it.
On macOS the old prefix length of an address comes off before the new one goes
on.

A reconciler stopped with `ranet3 disable reconciler` takes the block as well,
and installs it once it is started again. A running exit takes a new overlay, a
renumbered tun or another metric without dropping a session or withdrawing the
mesh table from the rest of the fleet. [Routing](routing.md) describes the
reconciler.

A change to `cap.table.id` or `cap.table.proto` is refused by name, and so is
writing the block where there was none or taking it out. The reconciler reads
and writes its routes and rules in the table and under the protocol it started
with, so a restart applies them.

## `cap.babel`

A reload hands a changed `cap.babel` to the running speaker, every field of it:
`hello`, `update`, `quality` and `cost`. The speaker keeps its sequence number
and the Hello history of every neighbor, computes each link cost again and
reruns route selection under the new cost. It then sends every neighbor a Hello
with its IHU and its whole table at once, and runs its timers on the new
intervals from there. RFC 8966 sections 3.4.1 and 3.4.2 let a node lengthen its
Hello and IHU intervals only when it sends a Hello announcing them at once. A
neighbor expires a route at 3.5 times the last update interval it heard (RFC
8966 Appendix B). Sending everything at once lets every neighbor learn the new
intervals before the old ones run out. A `cap.babel` that describes the speaker
already running, an omitted field written out as its default for instance,
changes nothing and sends nothing.

A changed `cost.extra` takes the same path. The speaker charges every running
neighbor the amount the new block selects for it, before selection reruns, so a
route through a neighbor whose amount rose moves at once, and the Hello it sends
carries the new receive cost in its IHU. A reload naming an organization with no
node in the new trust document, or a node it does not hold, is refused by name,
and so is one naming this node.

## `cap.segment` and `link.mtu`

A reload builds the tables a changed `cap.segment` describes, as a startup does,
and installs them: the segments this node answers for and its steering. A packet
already in flight is acted on under the table it met. The tun runs at `link.mtu`
less the header the longest steer list puts in front of a packet, and a reload
whose steering has a longer or a shorter longest list moves the tun with it. A
table whose longest list is longer than the one in force goes in after the tun
moves. Any other table goes in before the tun moves. Either way, the tun's MTU
plus the steering header in force stays within the larger of the old and the new
`link.mtu`. A steering stopped with `ranet3 disable steering` stays stopped with
the new table installed.

The families the translator translates are fixed at startup, and a node with an
egress segment translates both, whatever it advertises. A reload adding the
first egress segment is refused with
`config: cap.segment adds the first egress segment, restart to apply`, and one
removing the last with
`config: cap.segment removes the last egress segment, restart to apply`. A
reload moving an egress segment to another SID, adding a second or editing an
`allow` list applies, and the originated `/128` follows the SIDs. A reordered
`allow` list is no change.

A changed `link.mtu` moves the tun the same way. A read off the tun takes a
packet of up to 65535 bytes whatever `link.mtu` the node started with, so the
tun moves to any MTU its kernel takes. A running session whose budget is past a
lower `link.mtu` drops to it at once, and one whose search has settled searches
up toward a higher one, probing each size before its budget moves there. A
session made after the reload searches within the new `link.mtu` from its start,
and one under the floor stays there. A session whose sends leave without DF is
not searched, and it takes the new `link.mtu` at once, lower or higher. On a
platform other than Linux and macOS the tun takes its MTU only when it is
opened, and a reload that moves the tun is refused there. A reload whose
`link.mtu` and steering leave the tun where it was is applied there as well.
[Path MTU](path-mtu.md) describes the search.

## `link.listen`

Turning `link.listen` on starts the responder. Turning it off stops it
answering, closes every session this node answered with a Delete, as a shutdown
does, and wakes every dialer, so a peer this node also dials comes back at once
rather than after the reconnect delay. The sessions this node dialed stay. The
daemon drops the handshakes it had queued for the responder and queues none
while it is off, so a responder started again later answers only what arrives
after it. A responder stopped with `ranet3 disable responder` stays stopped
across a reload.

## `cap.crypto`

A reload applies the lists of `cap.crypto.ike` and `cap.crypto.esp` in place.
Every exchange after it, a new handshake or a rekey of a live session, offers
and accepts what the new lists hold, and a new order changes which transform an
answering node takes. `cap.crypto.replay` and `cap.crypto.rekey` need a restart,
as [what a reload refuses](#what-a-reload-refuses) describes. `ranet3 sessions`
shows the transforms each session runs, and a reload can be seen taking hold
there. Its column for the Child SA names the cipher, followed by the kex entry
of the Child SA's own key exchanges where it ran any, as the `suite` of an
`ike.suite.unlisted` does, which the session records once a reload left that
entry out.

Each live session then checks its SAs against the new lists. An SA whose cipher
or kex entry they leave out is rekeyed under them, and the session records an
`ike.suite.unlisted` with `action=rekey`. The rekey starts after a delay drawn
up to `cap.crypto.rekey.jitter`, so 2 ends that reload the same lists at once
rarely rekey the SA together and refuse each other's rekey, as
[RFC 7296 section 2.8.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8.1)
asks. The delay ends no later than the SA's scheduled rekey, which keeps the
margin before its lifetime. When one reload leaves out a transform of both the
IKE SA and its Child SA, the IKE SA rekeys first, since the Child SA's keys come
from it. The Child SA draws its own delay once the IKE SA's rekey has ended, its
Delete of the replaced IKE SA included. A rekey already under way at the reload
runs under the lists it started with, and the forced rekeys wait for it. The
removed transform can stay in use for up to 2 delays, a rekey already under way,
the IKE SA's rekey with its Delete, and the Child SA's rekey. A Child SA that an
earlier reload already left out keeps the delay it drew then, and can rekey
before an IKE SA that a later reload left out. A reload that only adds
transforms or kex entries, a joined entry among them, starts no rekey.

A forced rekey the peer refuses is retried on the backoff of
`cap.crypto.rekey.retry` for as long as the lists leave the SA out. Once a later
reload lists it again, the SA goes back to its scheduled rekey, or to none where
its interval is 0. A forced rekey runs inside the SA's lifetime like any other:
an SA whose peer keeps refusing reaches its lifetime and closes the IKE SA, as
[the configuration reference](configuration-reference.md#capcryptorekey)
describes. An SA whose interval is 0 has no lifetime, and its forced rekey keeps
retrying while the lists leave it out.

An IKE SA whose PRF the lists leave out is not rekeyed, since a rekey keeps the
PRF. The session records an `ike.suite.unlisted` with `action=replace`, deletes
the IKE SA, which closes its Child SA, and ends, and the node that dialed it
dials again at once under the new lists. A node that only answered the session
wakes its own dialer of that peer, if one stood down behind the session. When
both ends replace the same IKE SA and their Deletes cross, each session still
ends for a new handshake, and each end dials again or wakes its dialer as above.
The Delete is the last request the session sends, and it has the 2 sends of
[the Delete that ends an IKE SA](design/limits.md#ike) from its first send. Past
the IKE SA's lifetime it goes out as that IKE SA's own Delete, and no second
Delete follows. When both sends go unanswered, the session still ends for a new
handshake, and its log line says the session ended before its Delete was
answered, with `peer unresponsive after 2 attempts`. A lost answer alone does
that: the peer answers no resend of a Delete it took.

A peer's offer the new lists refuse with `NO_PROPOSAL_CHOSEN` has the session
check its SAs as well. A peer's rekey of an SA the lists left out then starts
this end's own rekey or replacement of it.

## Events

A reload is recorded as a `daemon.reload` event that names the file in `path`.
Its `applied` lists the blocks the reload changed among `auth.aliases.local`,
`auth.aliases.remote`, `cap.babel`, `cap.border`, `cap.crypto.esp.cipher`,
`cap.crypto.ike.cipher`, `cap.crypto.ike.kex`, `cap.crypto.ike.prf`, `cap.exit`,
`cap.route`, `cap.segment`, `cap.table`, `link.listen` and `link.mtu`, comma
separated, such as `applied=cap.table` for one that changed the table. A reload
that changed only the trust document or the peers dialed carries no `applied`. A
refused reload carries `err` instead. `cap.route` is listed when `announce`
changed, and `cap.border` when its `overlay` did. `cap.transit` is never listed,
since a reload that would change it is refused, and writing out the value in
force changes nothing.

The speaker records a `babel.config.applied` with the intervals and the cost it
took, and a `babel.neighbor.extra` for each neighbor whose amount the reload
changed. Turning `link.listen` on or off records a `responder.changed` with
`listen`, and its `closed` counts the answered sessions it closed. The
reconciler's pass after it is a `kernel.pass` with `trigger=reload`, recorded
whether or not it moved anything. A reconciler stopped with
`ranet3 disable reconciler` runs no pass when it takes the block, and the pass
that installs it once the reconciler is started again is recorded with
`trigger=enable`.

## A node that is down

A node `ranet3 down` took off the mesh applies a reload and stays down. Its
dialers, its responder and its speaker start at `ranet3 up` as the new file
describes them, the dialer of a peer the reload added included, and the
reconciler takes a changed `cap.table` as a stopped one does and installs it at
`ranet3 up`. `ranet3 down` withdraws the kill switch with the rest, as a clean
stop does, so a node taken off the mesh sends its traffic by its own default
until `ranet3 up`.

## What a reload refuses

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, tun and local endpoints each change what peers have already
authenticated or what the dataplane is attached to. So does turning
[`cap.transit`](configuration-reference.md) on or off, since the speaker reads
transit as it builds each packet and keeps it for its life, and the forwarding
decision reads it once at startup. `link.underlay` is read once, by the
reconciler at its start.

So does the private key. It is read once at startup, and the responder holds its
own copy. A reload reads the key file only to compare it. A new key is refused
by name, whether the path moved or the file was rewritten in place. The node
keeps signing with the key it started with until a restart.

`cap.egress` is read once at startup as well. The capability owns the tables it
created under the families it translated at startup, the advertised ones and
both beside an egress segment. A new block applied here would leave the host
holding rules from a configuration nothing is running.

`cap.border` appearing or going is refused with
`config: cap.border added, restart to apply` or
`config: cap.border removed, restart to apply`, since the filter and its pass
are built once at startup, as the translator is. Its `overlay` list reloads in
place, and so do the SIDs it drops, which follow `cap.segment.local`: the reload
hands both to the running filter, which rewrites its chain on the pass the
reload wakes. The reload also hands the new overlay to the
[forwarding decision](routing.md#transit) at once, which answers an IPv4
destination no route holds Host Unreachable inside it and Network Unreachable
outside it. In the same step the decision judges again, for every route the mesh
holds, whether it
[counts as a default](routing.md#routes-that-count-as-a-default), which decides
where an exit [carries a packet out](exit-nodes.md#what-an-exit-carries-out). A
reload of a node whose host forwards and whose file writes no `cap.border` logs
the warning [the border filter](border-filter.md#nodes-that-forward-without-it)
describes.

The daemon reads this node's global unicast and private mesh addresses of each
family `cap.egress` translates once at startup, among the host prefixes
`cap.route` announces and those `cap.table` assigns. Under `return`, the In
direction translates to one of them where the class from `0.0.0.0/0` or `::/0`
names no address. This node's own traffic from each leaves under that address's
class. A reload that moves one is refused with
`config: cap.route or cap.table moved a mesh address cap.egress translates under, restart to apply`.
With `cap.egress.return` set, a reload that leaves none or more than 1 to pick
from, in a family whose class from `0.0.0.0/0` or `::/0` names no address, is
refused as a startup would be, and the refusal asks for the address as the `to`
of that class in `cap.egress translate`. A reload that moves only other
addresses is applied: one of a family the node does not translate, a link-local
one, or one assigned under a prefix shorter than a host prefix, `203.0.113.7/24`
for instance.

The rekey and replay settings are captured by a session when it is created.
Applying them to new sessions alone would run 2 policies at once, so a change to
them needs a restart.

A refused reload leaves the trust document, the dialers, the announcements, the
speaker, the segment tables, the tun, the responder and the table as they were.
The only exception is a tun that refuses its new MTU after the rest has applied,
which happens only to a device on its way out.

### Checks on the file

A reload loads the file as a startup does. A file that fails to parse or names
an unknown key is refused whole. The checks across blocks run again:

- the longest `cap.segment` steer list must leave the tun at 1280 bytes or more
- a `cap.segment.local` SID must not be an address `cap.table` assigns to the
  tun
- a `cap.route` announcement must not equal a `cap.egress.advertise` prefix,
  which it would announce whether or not the translation rule is installed
- an egress segment needs `cap.egress`, and `cap.route` must not announce its
  SID's `/128`
- an egress segment needs `cap.border`, whose `overlay` covers every entry of
  its `allow` list, and a `cap.egress.advertise` entry longer than 0 bits must
  not overlap the `overlay`
- `auth.aliases.local` needs at most 1 `link.endpoints` entry in each family,
  and its `keyid` values must not spell an endpoint of another node, as
  [the configuration reference](configuration-reference.md#authaliases) lists
  with the other refusals of `auth.aliases`

### Checks against the trust document

A reload is refused when the new trust document:

- does not name this node
- holds a key for this node's organization other than the one `auth.key` holds
- does not list one of this node's `link.endpoints`, or lists it in another
  family

### Peers the trust document cannot support

A reload logs a peer the new trust document cannot support and does not dial it.
The log line reads `reload: <reason>, so nothing will dial it`. At startup, some
of the same peers refuse the start: a `dial.to` node the document does not name,
a pinned endpoint it does not list, and a pinned endpoint in a family this node
has no endpoint in. The [trust document](trust.md) page describes the document
itself.

An `auth.aliases` entry naming a node the new document does not name, or an
endpoint it does not list, is logged the same way and the reload applies. The
line reads `reload: <reason>, so no handshake can use it`. At startup the same
entry refuses the start.
