---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Sharing a host"
description: "Sharing a host with other routing daemons, firewalls and VPNs."
created: 2026-09-12
updated: 2026-10-08
order: 110
---

ranet3 is built to run next to Tailscale, NetBird, ZeroTier, an SD-WAN agent, or
anything else that owns interfaces and routes on the same box, and the
reconciler's ownership rules make that true rather than a hope. `cap.egress`
follows the same rules in the host's packet filter, see below.

On Linux it reads back only routes whose table, `rt_proto` and output interface
all match its own, so a delete list can never contain another writer's route,
and `RTM_DELROUTE` carries `rtm_protocol` as well, so the kernel refuses too. It
never touches another table, another device, or any policy rule.

systemd-networkd removes every policy rule it did not ask for whenever it
configures a link, on resume, on a `.network` change and on its own restart. The
reconciler's route monitor also listens for rule notifications, and a deleted
rule carrying its protocol wakes it, so the pass after the 250 millisecond
settle puts the rule back. A rule another writer adds or deletes for itself
wakes nothing.

Installing is where a router daemon usually takes over from its neighbors, and
this one does not. It asks for the route exclusively, and a key something else
already holds is left alone and reported once. That matters most in a VRF table,
which a mesh node hands it: a replace compares neither the protocol nor the
route type, so it would have displaced the kernel's own local and connected
entries for an address on an enslaved link, at the same priority an IPv4 route
with no configured metric uses. The reconciler also names any other routing
protocol it finds in the table at startup, before its first pass, with the one
change that node can make in a `fix` attribute: on a node with a VRF, which
looks that table up, to stop the other writer exporting into it, and on any
other node to give the reconciler a table of its own.

On darwin there are no tables and no `rt_proto`, so ownership is by interface
and by shape: a route out of its own utun whose gateway is a link address naming
that interface. That condition is the whole guarantee: nothing else writes
routes out of our utun. Tailscale's `100.64.0.0/10` on its own utun has exactly
the shape described above, so a reconciler pointed at that interface would adopt
and withdraw it. Two things keep that from happening. The device is created by
asking for the next free unit, or for the unit `link.tun` names, whose creation
fails while another tunnel holds it, so it is never one another tunnel is
already using, and XNU allocates interface indices by incrementing a counter
with no free list, so a destroyed utun's index is never handed out again.

Interface-scoped routes are narrower still, because this reconciler installs a
scoped route for a source-specific announcement, and so do other tools. A macOS
host running Tailscale carries a scoped `255.255.255.255` entry with a link
gateway and `RTF_STATIC`, so a scoped route counts as this reconciler's only
when this process scoped that destination. One left behind by a crash is left
alone rather than deleted on a guess.

Two kinds of route are scoped, for two different reasons. A source-specific
announcement is scoped because interface scope is the only thing on this
platform that draws the distinction a source prefix draws at all. An announced
default is scoped because it would otherwise capture the machine: darwin has one
FIB and no equivalent of the fleet's table plus policy rule, so nothing keeps
the peers' own endpoints out of it and the ESP underlay would route into the
tunnel carrying it. Anything more specific is installed unscoped, so the mesh is
reachable from the Mac without every program binding first. Tailscale makes the
same split on the same machine: its exit-node default is scoped to its utun, its
`100.64.0.0/10` is not.

What a scoped route does not give you is automatic use of an exit-announced
address. Invisibility to an ordinary lookup is the safety property, and it
applies to every unbound socket, so Safari, curl and ssh keep the address of
whatever interface the machine was already using. macOS has no `ip rule`:
selecting a scoped route means `bind()` to an address on the tun or
`IP_BOUND_IF` to the tun itself, per application, and ranet3 provides neither.
There is a second-order effect too. Once the outgoing interface has no address
of a family, which happens on an IPv4-only network where the mesh address is the
box's only global IPv6, RFC 6724 rule 5 makes the mesh address a candidate
source for traffic that is not going through the mesh at all, and those packets
die at the first BCP 38 filter with nothing to show for it locally.

An install that collides with a route another program holds is reported once and
left alone. darwin has no replace, and the collision does not resolve itself, so
the route stays in the diff and the install is attempted again on every pass,
silently after that first report. The reconcile line counts it as not installed
rather than as added, and says nothing at all about a pass that moved nothing.

Addresses are narrower still: only an address this process added is ever
removed, and one already on the link belongs to whoever put it there. That rule
has one consequence worth knowing about on a TUN the operator created rather
than one ranet3 made, which is the only kind that outlives the process. An
instance killed outright leaves its addresses on the device, and the next one
finds them already there, so it never adds them, never records them as its own,
and never removes them, even on a clean shutdown. Its routes do come back, since
they carry the protocol marker that identifies them. The TUN is enslaved to a
VRF only while it has no master at all, so systemd-networkd keeps whatever it
already claimed. Enslaving cycles the device, and the kernel then removes every
route out of it, in every table and whoever wrote it. Measured in a namespace of
its own: another writer's `198.51.100.0/24` and `2001:db8:5::/48`, both
`proto static` in table 200 out of the tun, were gone after
`ip link set probe0 master mesh`, while a route out of the VRF device itself
stayed. That is why the startup report of other writers runs before the first
pass, which enslaves. Under the default name the device itself is only ever
created: a `ranet3` that already exists is refused rather than joined, so it
never takes a device another tunnel is using.

`cap.egress` writes into the packet filter, where the same three rules hold. It
creates an nftables table named after this tool, one per address family, holding
one nat postrouting chain; that name is the whole of its ownership claim, as
`rt_proto` is the reconciler's. It writes only inside those tables, reads back
only rules it wrote, replaces the chain's contents in one transaction rather
than editing it rule by rule, so no packet is ever evaluated against half a
ruleset, and removes both tables at shutdown. A table left behind by an earlier
instance carries the same name and is adopted, then brought to what the
configuration now asks for, and one in a family the configuration no longer
covers is removed at startup rather than left translating under rules nothing is
maintaining.

Nothing here writes iptables. The two are separate registries in the kernel, an
`iptables-nft` rule is visible here as an ordinary nftables table, and the
conflicts everybody remembers between firewall managers are an iptables problem
this declines to join. A host still running legacy iptables is invisible to the
conflict report below for the same reason.

Other source translation at the same hook is reported rather than fought over.
Several nat postrouting chains coexist at `srcnat` priority, docker's and
Tailscale's among them, and the first one to translate a connection keeps it for
that connection's lifetime. Deleting a neighbor's rule to win that race would
break whatever installed it, so `status` and the scrape name the other chains
instead and leave them alone. Their rules and this one are usually disjoint,
since this one matches on the mesh device in both directions.
