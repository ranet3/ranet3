---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Sharing a host"
description: "Sharing a host with other routing daemons, firewalls and VPNs."
created: 2026-09-12
updated: 2026-10-20
order: 110
---

ranet3 is built to run next to Tailscale, NetBird, ZeroTier, an SD-WAN agent, or
anything else that owns interfaces and routes on the same host, and the
reconciler's ownership rules make that true rather than a hope. `cap.egress`
follows the same rules in the host's packet filter, see below.
[Routing](routing.md) describes what the reconciler installs.

## Routes on Linux

On Linux the reconciler reads back only the routes in its own table that carry
its own `rt_proto`. Of those, it keeps the unicast routes out of its own tun and
the unreachable holds it installs, which name no device. A delete list therefore
never contains another writer's route. `RTM_DELROUTE` carries `rtm_protocol` as
well, so the kernel refuses too.

The reconciler writes routes only into its own table. Its policy rules carry the
same protocol as `FRA_PROTOCOL`, and it reads back and removes only those. It
never touches another writer's routes or rules.

systemd-networkd removes every policy rule it did not ask for whenever it
configures a link, on resume, on a `.network` change and on its own restart. The
reconciler's route monitor also listens for rule notifications, and a deleted
rule carrying its protocol wakes it, so the pass after the 250 millisecond
settle puts the rule back. A rule another writer adds or deletes for itself
wakes nothing.

Installing is where a router daemon usually takes over from its neighbors, and
this one does not. It asks for the route exclusively, and a key something else
already holds is left alone and reported once.

Exclusive installs matter most in a VRF table. The kernel files its own local
and connected entries there for every address on an enslaved link. A replace
compares neither the protocol nor the route type, so it would displace those
entries. An IPv4 route with no configured metric sits at the same priority as
they do.

At startup, before its first pass, the reconciler logs
`kernel is sharing its table with another routing protocol` when another
protocol writes its table. The warning's `fix` attribute names the change the
node can make. On a node with a VRF, which looks that table up, the fix is to
stop the other writer exporting into the table. On any other node, the fix is to
give the reconciler a table of its own.

The check counts unicast routes only. When the reconciler's own VRF is bound to
its table, the check leaves out the kernel's own entries there, which carry the
protocol `kernel`.

A node that sets `link.underlay.mark` and writes `cap.table` is refused at load
unless a `cap.table.rules` entry sends that mark to a table other than
`cap.table.id`. Without such a rule, the marked socket follows the mesh table
like any other socket. The error names the entry to add, for example
`{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }`.

## Routes on macOS

On macOS there are no tables and no `rt_proto`, so ownership is by interface and
by shape: a route out of its own utun whose gateway is a link address naming
that interface. The guarantee holds while nothing else writes routes out of
ranet3's utun. Tailscale's `100.64.0.0/10` on its own utun has exactly the shape
described above, so a reconciler pointed at that interface would adopt and
withdraw it.

The way ranet3 creates its device keeps that from happening. It asks for the
next free utun unit, or for the unit `link.tun` names. Creating a named unit
fails while another tunnel holds it, so the device is never one another tunnel
is already using.

Other tools install interface-scoped routes too. A macOS host running Tailscale
carries a scoped `255.255.255.255` entry with a link gateway and `RTF_STATIC`.
The reconciler leaves `255.255.255.255/32` out of every dump by destination and
never installs it.

Any other scoped route of the reconciler's shape out of its own utun is read
back as its own. A pass withdraws it when the mesh does not select it. macOS
keeps no source with a route, so a source-specific route an earlier instance
left behind is withdrawn and installed again.

The reconciler installs 4 kinds of route scoped to the utun. A scoped route is
invisible to an ordinary lookup and visible to a socket bound to an address on
the utun.

- A source-specific route. Interface scope is the only thing on this platform
  that draws the distinction a source prefix draws.
- An unreachable hold. macOS has 1 forwarding table, and an unscoped hold would
  shadow every other way to its prefix.
- A route that covers a literal endpoint address the trust document lists.
  Unscoped, it would carry this node's own ESP to that peer into the tunnel.
- A route that would carry the host's own traffic, unless `link.underlay.bind`
  is set. Such a route has a prefix length of 0 or 1, or contains the family's
  unspecified address.

With `bind` set, every route outside the first 3 kinds is installed unscoped, so
the mesh is reachable from the Mac without every program binding first.

Tailscale makes the same split on the same host. Its exit-node default is scoped
to its utun, and its `100.64.0.0/10` is not.

An unscoped `0.0.0.0/0` or `::/0` out of the utun would collide with the host's
own default. With `bind` set, the reconciler installs a plain default as its
zero-free cover instead, 8 unscoped routes per family that hold every address
but `0.0.0.0/8` and `::/8`. No member holds the zero address, so a socket bound
to the host's interface keeps its fallback, and the members stay unscoped even
over a listed endpoint address. `64:ff9b::/96` lies in `::/8` and stays on the
host's own route. Until exit selection exists, a Mac with `bind` set takes
whichever `/0` Babel selects. [Routing](routing.md#the-zero-free-cover-on-macos)
describes the cover, and [exit nodes](exit-nodes.md#what-to-advertise) why an
exit advertises the `/0` only.

What a scoped route does not give you is automatic use of an exit-announced
address. Invisibility to an ordinary lookup is the safety property, and it
applies to every unbound socket, so Safari, curl and ssh keep the address of
whatever interface the host was already using. macOS has no `ip rule`: selecting
a scoped route means `bind()` to an address on the tun or `IP_BOUND_IF` to the
tun itself, per application, and ranet3 provides neither.

There is a second-order effect too. On an IPv4-only network the mesh address can
be the host's only global IPv6 address. RFC 6724 rule 5 then makes it a
candidate source for traffic outside the mesh. Those packets die at the first
BCP 38 filter, and nothing on the host shows why.

An install that collides with a route another program holds is reported once and
left alone. macOS has no route replace, and the collision does not resolve
itself. The route stays in the diff, and every pass attempts the install again
without another report. A collision at a member of the zero-free cover keeps
that family's whole cover out, as
[routing](routing.md#the-zero-free-cover-on-macos) describes.

The `kernel routes reconciled` line leaves such a route out of `added`. `status`
and the scrape count it as skipped, the scrape as
`ranet3_kernel_routes_skipped`. A pass that moved nothing logs no
`kernel routes reconciled` line at all.

## The underlay default on macOS

With `link.underlay.bind` set, ranet3 can write a default out of an interface it
does not own, scoped to the physical interface the underlay socket is bound to.
A socket bound with `IP_BOUND_IF` falls back to a longest-prefix match on its
family's zero address, so an unscoped route out of another interface that holds
that address takes the fallback away. The default is written for a family only
while such a route is in the table:

- one the reconciler installs that is not a cover member, a real `0.0.0.0/1` or
  a `0.0.0.0/24` out of the utun, or
- another program's, out of an interface that is neither ranet3's utun nor the
  underlay's, such as a full-tunnel VPN's `0.0.0.0/1`. Scoped, cloned,
  link-layer and reject routes do not count, and neither does the host's own
  default.

The reconciler checks on every pass, and the transport before it moves the
socket onto another interface. A route change anywhere on the host wakes a pass
after a 250 millisecond settle, so another program's capture strands the socket
for that settle and 1 pass at most. The first check that finds the last such
route gone withdraws the default. With only the cover installed, nothing is
written, and the host's own router selection (RFC 4861 section 6.3.6) stays in
charge of its default. ranet3 never touches the other program's route.

The ownership rules of this default are narrower than the utun's:

- ranet3 deletes only a default it recorded writing.
- Before a delete, it reads the kernel back and requires a route with the same
  scope, interface and next hop as the record.
- An add that answers `EEXIST` counts as use, not ownership. A scoped default
  macOS wrote for a secondary interface is used and never withdrawn.
- The record is kept in `/var/run/ranet3/underlay.json`. The next instance
  withdraws what a killed instance recorded only when the route still matches
  the record, the interface name still has the recorded index, and that
  interface still carries the host's own default.

## Addresses and the VRF

Addresses are narrower still: only an address this process added is ever
removed, and one already on the link belongs to whoever put it there. An address
the link already holds at another prefix length is left alone and reported as
`kernel is leaving an address another writer holds`. An address the reconciler
added is removed only while the link still holds it at the length it was added
with.

Only a tun the operator created outlives the process. An instance killed
outright leaves its addresses on such a device. The next instance finds them
already there and treats them as another writer's, so it keeps them even at a
clean shutdown. The routes the killed instance left carry the protocol marker,
and the next instance takes them back as its own.

On Linux the reconciler turns on `promote_secondaries` for the tun at start.
When a primary IPv4 address comes off the tun, the kernel promotes the next
address of that subnet instead of removing it too. A tun with no IPv4 address
loses every IPv4 route through it, another writer's among them.

The tun is enslaved to a VRF only while it has no master at all, so
systemd-networkd keeps whatever it already claimed. Enslaving cycles the device.
The kernel then removes every route out of the tun, in every table and whoever
wrote it. A route out of the VRF device itself stays. The startup report of
other writers therefore runs before the first pass, which enslaves.

With `cap.table.vrf.create` set, the reconciler creates the VRF only when no
device of that name exists. A VRF that already exists keeps the table it is
bound to, and the reconciler never rebinds it. When that table is not
`cap.table.id`, the reconciler logs
`kernel's vrf is bound to another table than the one it writes`. At shutdown it
removes only a VRF it created, found by the index it was created under.

Under the default name the device itself is only ever created: a `ranet3` that
already exists is refused rather than joined, so it never takes a device another
tunnel is using.

## The packet filter

`cap.egress` writes into the packet filter, where the same 3 rules hold. It
creates 1 nftables table named after this tool for each address family it
translates, the advertised ones and both beside an egress device, `ip ranet3`
and `ip6 ranet3`, each holding 1 nat postrouting chain. That name is the whole
of its ownership claim, as `rt_proto` is the reconciler's. It writes only inside
those tables and reads back every rule of their chains, so a rule another writer
puts in one, which changes what the chain does to a packet, is removed by the
next pass. It reads other writers' tables, chains and rules to find its own and
to report conflicts, and writes, replaces or deletes nothing outside its own
tables. It replaces the chain's contents in 1 transaction, so no packet is ever
evaluated against half a ruleset.

It removes its tables at shutdown and at `ranet3 down`. A table left behind by
an earlier instance carries the same name and is adopted, then brought to what
the configuration now asks for, and one in a family the configuration no longer
covers is removed at startup rather than left translating under rules nothing is
maintaining.

Nothing here writes iptables. The 2 are separate registries in the kernel, an
`iptables-nft` rule is visible here as an ordinary nftables table, and the
conflicts everybody remembers between firewall managers are an iptables problem
this declines to join. A host still running legacy iptables is invisible to the
conflict report below for the same reason.

Other source translation at the same hook is reported rather than fought over.
Several nat postrouting chains coexist at `srcnat` priority, Docker's and
Tailscale's among them, and the first one to translate a connection keeps it for
that connection's lifetime. Deleting a neighbor's rule to win that race would
break whatever installed it.

`status` and the log name the other chains instead and leave them alone. Their
rules and this one are usually disjoint, since this one matches on the mesh
device in both directions.

The scrape counts the other chains as `ranet3_egress_conflicts`. The report
covers nat postrouting chains in `ip` and `ip6` tables of the families it
translates. It leaves out chains in `inet` tables.

`cap.border` adds a third table under the same name, `inet ranet3`, holding 1
filter chain at prerouting, priority `raw` (-300).
[The border filter](border-filter.md) describes it. The same rules hold: it
writes only inside its table, replaces the chain in 1 transaction, adopts a
table an earlier instance left, and removes it at shutdown. Unlike the
translator's tables it stays through `ranet3 down`. The conflict report above
leaves its chain out, since it is in an `inet` table and translates nothing.
Another base chain at the same hook, such as a firewall's own raw chain, runs
beside it: both see every packet, and only a drop in either ends the hook. A
firewall reload that flushes the whole ruleset deletes the table, and the filter
puts it back on the pass the deletion wakes. A table or chain another writer
changed in a way nf_tables will not undo in place is deleted and made again in 1
transaction, any chain another writer put in the table with it.
