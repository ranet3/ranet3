---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Sharing a host"
description: "Sharing a host with other routing daemons, firewalls and VPNs."
created: 2026-09-12
updated: 2026-10-27
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
the unreachable holds and throw routes it installs, which name no device, though
an IPv6 one reads back as `dev lo`. A delete list therefore never contains
another writer's route. `RTM_DELROUTE` carries `rtm_protocol` as well, so the
kernel refuses too.

The reconciler writes routes only into its own table. Its policy rules carry the
same protocol as `FRA_PROTOCOL`, and it reads back and removes only those. It
never touches another writer's routes or rules.

systemd-networkd removes every policy rule it did not ask for whenever it
configures a link, on resume, on a `.network` change and on its own restart. The
reconciler's route monitor also listens for rule notifications, and a deleted
rule carrying its protocol wakes it, so the pass after the 250 millisecond
settle puts the rule back. A rule another writer adds or deletes for itself
wakes nothing. `ManageForeignRoutingPolicyRules=no` in `networkd.conf` keeps
networkd from removing the rules at all.

Installing is where a router daemon usually takes over from its neighbors, and
this one does not. It asks for the route exclusively, and a key something else
already holds is left alone and reported once. A replace compares neither the
protocol nor the route type, so it would take the route from the writer that
holds it.

At startup, before its first pass, the reconciler logs
`kernel is sharing its table with another routing protocol` when another
protocol writes its table. The warning's `fix` attribute says to give the
reconciler a table of its own. The check counts unicast routes only.

The reconciler writes its rules in 2 blocks, 5100 to 5190 and 5400 to 5490, on
either side of Tailscale's 5210 to 5270, which Tailscale uses at its default
base of 5200, as [routing](routing.md#policy-rules-on-linux) lists them.
[Where a lookup ends](routing.md#where-a-lookup-ends-on-linux) gives where each
lookup ends while no rule of another program is in the policy database.

### The underlay's mark

Every underlay socket on Linux carries the mark 0x72 where the process may set
it, so a lookup of ranet3's own ESP and IKE bound to no device ends at row L1 or
L2 and never follows the mesh's table into its tun. The endpoint resolver marks
its query to a nameserver outside `cap.border.overlay` too, where the process
may set the mark, a nameserver in a subnet another node announces among them, so
where `cap.table` is written the query ends at row L1 or L2 and never waits on a
session that only the name it asks for can dial. A nameserver on the host
itself, such as systemd-resolved's `127.0.0.53`, takes the query at row L1, and
its own query upstream carries no mark, so it can wait on such a session. Its
query to a nameserver inside the overlay carries no mark, whatever zone
`/etc/resolv.conf` writes after the address, and where `cap.table` is written
ends as any other program's does, rows L1 to L5. A link-local nameserver lies
outside an overlay of the mesh's own prefixes, so its query carries the mark
where the process may set it. An IPv6 one ends by main's route out of the link
its zone names, and an IPv4 one at row L2 by main's route for it. The mark is a
constant, with no key to set it. Setting it takes `CAP_NET_ADMIN` or
`CAP_NET_RAW`. A process that holds neither logs
`transport leaves the underlay sockets unmarked` once, at info, and sends its
underlay datagrams and its resolver queries unmarked, which end as an unmarked
lookup does in [where a lookup ends](routing.md#where-a-lookup-ends-on-linux).
Without `CAP_NET_ADMIN` no rule reads the mark either: a node with `cap.table`
refuses to start, since the reconciler cannot set `promote_secondaries` on the
tun, and a node without it writes no rule at all.

Other programs mark packets too, and their rules select a value of the mark read
under a mask. Under each mask these programs read at their defaults, 0x72 reads
as 0, as an unmarked packet's mark does, but under Cilium's 0xfffffeff, where it
reads as 0x72, a value none of Cilium's rules selects:

- Kubernetes: kube-proxy masquerades a packet carrying 0x4000, its
  `masqueradeBit` of 14
  ([defaults.go](https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/apis/config/v1alpha1/defaults.go)),
  and the kubelet's drop mark is 0x8000, its `iptablesDropBit` of 15
  ([defaults.go](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/apis/config/v1beta1/defaults.go)).
- Cilium reads three masks
  ([mark.go](https://github.com/cilium/cilium/blob/main/pkg/datapath/linux/linux_defaults/mark.go)):
  0x0f00, its `MagicMarkHostMask`, under which its rules select 0x200 for
  traffic to its proxy and 0xa00 and 0xb00 for traffic from it. It reads 0x0e00,
  its `MagicMarkProxyMask`, for 0xa00 and 0x800, and 0xfffffeff, its
  `MagicMarkProxyNoIDMask`, for 0xa00 on the proxy's replies. Its rule
  `fwmark 0x200/0xf00 lookup 2004` sends a lookup marked for its L7 proxy to a
  table whose default delivers on the host itself
  ([routes.go](https://github.com/cilium/cilium/blob/main/pkg/proxy/routes.go),
  the rule as [cilium/cilium#32932](https://github.com/cilium/cilium/pull/32932)
  quotes it).
- Tailscale reads 0xff0000, its `LinuxFwmarkMask`
  ([linuxfw.go](https://github.com/tailscale/tailscale/blob/main/tsconst/linuxfw.go)).
- The CNI portmap plugin masquerades a packet carrying 0x2000, its `markMasqBit`
  of 13
  ([main.go](https://github.com/containernetworking/plugins/blob/main/plugins/meta/portmap/main.go)).
- mwan3 reads 0x3f00, its `mmx_mask`
  ([common.sh](https://github.com/openwrt/packages/blob/master/net/mwan3/files/lib/mwan3/common.sh)).
- The Amazon VPC CNI plugin marks connections with 0x80, its
  `AWS_VPC_K8S_CNI_CONNMARK`
  ([network.go](https://github.com/aws/amazon-vpc-cni-k8s/blob/master/pkg/networkutils/network.go)).
- Calico reads 0xffff0000, Felix's `IptablesMarkMask`
  ([Felix configuration](https://docs.tigera.io/calico/latest/reference/felix/configuration)).

A program set to another mask, or one that selects by an inverted mark, can
still meet 0x72, as [another program's rules](#another-programs-rules) gives.

### Another program's rules

ranet3 leaves another program's rules alone, and they share the policy database
with its own. The kernel walks the rules in priority order, and a rule of
another program that the walk meets before the rule of ranet3's that would
answer a lookup it selects changes where the lookup ends:

- A lookup of another table ends at that table's longest match, unless the
  rule's own `suppress_prefixlength` skips that match, the match is a throw, or
  the table holds nothing for the destination, and the walk then goes on.
- A rule whose action is `unreachable`, `blackhole` or `prohibit` refuses the
  lookup.
- A `goto` jumps to the first rule at its target priority and goes on from
  there, and one whose target holds no rule is passed over.

A rule selects a marked lookup too unless it selects by mark. One selecting
another mark, such as Tailscale's `0x80000/0xff0000`, leaves 0x72 out, and one
selecting by an inverted mark, such as wg-quick's `not fwmark 0xca6c`, takes it.
The gotos at 5100 and 5400 jump to the first rule at 5190 and 5490, so another
program's rule at 5101 to 5189 or 5401 to 5489 meets only unmarked lookups, and
one at 5190 or 5490 added before the reconciler's `nop` is the rule the `goto`
lands on. The kernel puts a new rule after those already at its priority, so
another program's rule comes ahead of ranet3's at the same priority whenever it
was added first, such as before the reconciler adds its own at a start. A rule
added with no priority goes to the second rule's priority less one, 5099 while
no rule sits between local's and 5100.

Measured layouts, each in a network namespace holding the reconciler's rules and
table, with the host's own addresses at row L1 ahead of every one:

- **Tailscale at its default base** puts its rules at 5210 to 5270, after 5110
  and before 5410. A lookup of table 52 at 5270 leaves an overlay destination
  5110 answers to 5110, a live one into the tun and a held one refused, and
  takes every other destination table 52 covers, one 5110 passes on as row L5
  gives and a marked one among them, ahead of main's routes longer than /0 at
  5410.
- **Tailscale on OpenWrt with mwan3** moves its rules to 1310 to 1370, ahead of
  5100. A lookup of table 52 ahead of 5100 takes every destination table 52
  covers, an overlay destination live or held and a marked one among them, so
  while Tailscale uses an exit node, that exit's default takes them all. ranet3
  does not handle that case.
- **A full tunnel of wg-quick** adds 2 rules with no priority, so added after
  the reconciler's, with no rule between local's and 5100, they go to 5099 and
  5098: `lookup main suppress_prefixlength 0` at 5098 and
  `not fwmark 0xca6c lookup 51820` at 5099. A route of main longer than /0 that
  covers the destination answers at 5098. WireGuard's table, which holds a
  default, takes every other lookup at 5099 but one carrying WireGuard's own
  mark, an overlay destination live or held and one marked 0x72 among them.

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
invisible to an ordinary lookup and visible to a socket bound to the utun or to
an address on it.

- A source-specific route. Interface scope is the only thing on this platform
  that draws the distinction a source prefix draws.
- An unreachable hold. macOS has 1 forwarding table, and an unscoped hold would
  shadow every other way to its prefix.
- A route that covers a literal endpoint address the trust document lists, but
  for a member of the zero-free cover. Unscoped, it would carry an unbound
  socket's ESP to that peer into the tunnel.
- A route that would carry the host's own traffic, unless `link.underlay.bind`
  is set. Such a route is one that
  [counts as a default](routing.md#routes-that-count-as-a-default).

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
be the host's only global IPv6 address. The host's own source address selection
([RFC 6724 section 5](https://www.rfc-editor.org/rfc/rfc6724.html#section-5))
picks the source for traffic outside the mesh, and ranet3 takes no part in it. A
packet the host sends from the mesh address dies at the first BCP 38 filter, and
nothing on the host shows why.

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
while such a route is in the table. For a route of the mesh's own that holds the
zero address ranet3 writes the default in the pass that installs the route,
before the route goes in. Such a route is:

- one the reconciler installs that is not a cover member, a real `0.0.0.0/1` or
  a `0.0.0.0/24` out of the utun, or
- another program's, out of an interface that is neither ranet3's utun nor the
  underlay's, such as a full-tunnel VPN's `0.0.0.0/1`. Scoped, cloned,
  link-layer and reject routes do not count, and neither does the host's own
  default.

The reconciler checks on every pass, and the transport before it moves the
socket onto another interface. A route change on any interface wakes the
reconciler, where `cap.table` runs one, and one another process makes on any
interface but the utun wakes the transport, each after a 250 millisecond settle,
so another program's capture strands the socket for that settle and 1 check at
most. With `cap.table` written, the first pass that finds the last such route
gone withdraws the default, and without it the default stays until the socket
moves onto another interface or the daemon stops. With only the cover installed,
nothing is written, and the host's own router selection (RFC 4861 section 6.3.6)
stays in charge of its default. ranet3 never touches the other program's route.

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

## Addresses and the tun

Only an address this process added is ever removed, and one already on the link
belongs to whoever put it there. An address the link already holds at another
prefix length is left alone and reported as
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

Under the default name the device itself is only ever created: a `ranet3` that
already exists is refused rather than joined, so it never takes a device another
tunnel is using.

## The packet filter

`cap.egress` writes into the packet filter, where the same 3 rules hold. It
creates 1 nftables table named after this tool for each address family it
translates, the advertised ones and both beside an egress segment, `ip ranet3`
and `ip6 ranet3`. Each holds a nat chain at postrouting, a filter chain at
forward, the set that chain counts each mesh source's flows in and the timeout
objects of the flows it translates. That name is the whole of its ownership
claim, as `rt_proto` is the reconciler's. It writes only inside those tables and
reads back every rule of its 2 chains, with the tables' flags, the chains' type,
hook, priority and policy, the set's key, flags, size and comment and the
objects' values, so a rule another writer puts in one or a table it sets
dormant, which changes what the chain does to a packet, is undone by the next
pass. It does not read back the set's counts, so a count another writer changes
or removes stays as that writer left it, and another chain in its table is
neither read nor removed until the table is made again. It reads other writers'
tables, chains and rules to find its own and to report conflicts, and writes,
replaces or deletes nothing outside its own tables. It replaces the chains'
rules in 1 transaction, so no packet is ever evaluated against half a ruleset,
and deletes and makes a table again in that transaction where nf_tables will not
change it in place, any chain another writer put in the table with it.

It removes its tables at shutdown and at `ranet3 down`, with any chain another
writer put in them. A table left behind by an earlier instance carries the same
name and is adopted, then brought to what the configuration now asks for, and
one in a family the configuration no longer covers is removed at startup rather
than left translating under rules nothing is maintaining.

Nothing here writes iptables. The 2 are separate registries in the kernel, an
`iptables-nft` rule is visible here as an ordinary nftables table, and the
conflicts everybody remembers between firewall managers are an iptables problem
this declines to join. A host still running legacy iptables is invisible to the
conflict report below for the same reason.

Other source translation at the same hook is reported rather than fought over.
Several nat postrouting chains coexist at `srcnat` priority, Docker's and
Tailscale's among them, and the first one to translate a connection
[keeps it](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n929)
for that connection's lifetime. The translator's chain is at priority 99, 1
below `srcnat`, so it runs ahead of every chain at `srcnat` whatever order the
chains were made in. An operator who wants to translate a mesh flow itself
writes a chain below 99, or one at 99 made after the translator's. A flow such a
chain translates leaves without this node's translation, its timeouts and its
count of translated flows, and the limit still holds it to its source's share.
Deleting a neighbor's rule instead would break whatever installed it.

`status` and the log name the other chains instead and leave them alone. Their
rules and this one are usually disjoint, since this one matches on the mesh
device in both directions.

The scrape counts the other chains as `ranet3_egress_conflicts`. The report
covers nat postrouting chains at priority 99 or below, which can run ahead of
the translator's, in `ip` and `ip6` tables of the families it translates. It
leaves out chains in `inet` tables and chains past 99, which run after it.

A class of `none` binds its flows to the source they carry in the translator's
chain, at priority 99, so a host's masquerade at `srcnat` or after leaves them
alone, and a chain below 99, or one at 99 made after the translator's, still
translates them.

The filter chain at forward, priority 0, runs beside the host's own filter
chains at that hook: a packet passes only where no chain drops it, so its
refusal of a flow past its source's share, and its drop of a packet no flow is
tracked for out of the mesh under a class that translates or into it under
`return`, end that packet whatever the others say. A packet a host rule exempts
from connection tracking, such as a `notrack` in a raw chain, counts as one no
flow is tracked for, and leaves the mesh only under a class of `none`.

The kernel settings an exit's traffic crosses stay the host's, but for the
connection tracking timeouts of the flows it translates. The translator writes
no routing rule and no sysctl, neither the mesh tun's nor an uplink's, so the
rules the reconciler derives and those of other programs, the host's routes,
`forwarding` and reverse path filtering decide where a packet goes. It reads
`net.netfilter.nf_conntrack_count` and `nf_conntrack_max` and writes neither.
Its timeout objects set the timeouts of its translated flows alone, and every
other connection keeps the host's. It asks the kernel where an exit's packets
would go and back instead. A family the answer does not carry out of the tun and
back again is [not ready](exit-nodes.md#readiness), and the reason names the
device's IPv4 `forwarding` at 0 or reverse path filtering, the larger of
`net.ipv4.conf.all.rp_filter` and the device's own, when either is set where the
lookup failed.

While the exit runs, `nft list ruleset` lists its ICMP timeout objects in a form
nft 1.1.7 does not load back, so a full listing saved then fails to load whole.
Save the ruleset table by table with `nft list table <family> <name>`, leaving
out the tables named `ranet3`, which the translator makes again on the pass a
load wakes.

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

## What forwarded traffic meets

A node that forwards for others routes a neighbor's packet by its destination,
and a mesh destination leads into the tun. The host's own kernel, a Docker
bridge, or a LAN behind a subnet router can put a packet into the tun this way.
The forwarding decision checks what the tun hands this node before the packet
enters the mesh, as [the border filter](border-filter.md) checks what arrives on
the links outside the mesh. A drop sends no answer and counts on the `Transit`
line, as [metrics](metrics.md#transit-counters) lists.

- A read from a source the table routes to another node or holds unreachable,
  through a route that does not count as a default, or from an overlay source
  this node does not own, is dropped and counted `forged`. A host beside a
  forwarding node cannot put another node's address into the mesh, though it can
  put that forwarding node's own.
- A read carrying an IPv6 routing header of type 0, 1 or 4, or a type the mesh
  does not recognize, is dropped and counted `routing_header`, and one addressed
  to this node's own SID is dropped and counted `sid`. A neighbor cannot steer
  through the mesh by writing a segment list of its own.
- Every IPv6 read whose walk ends at an inner IPv4 or IPv6 packet has that
  packet checked one level deep with the inner source and destination, whatever
  the read's destination. The mesh cannot tell another node's SID, an `End.DT46`
  that node would decapsulate, from any other address. The inner packet meets
  every check here, and one that is itself encapsulated is dropped and counted
  `nested`. [The limits](design/limits.md#transit) say what this costs a host's
  own tunnel.
- A read toward an exit's default from a source this node does not own is
  dropped and counted `unowned_source`, the owned-source rule. Only this node's
  own traffic leaves the mesh through its exits.

Replies to the mesh's overlay and to subnets the mesh routes are untouched by
the owned-source rule: an exit's egress replies, translated back by the kernel,
carry the internet's sources and are bound for a leaf's overlay address, out of
that rule's reach. A host tunneling its LAN through the mesh announces the LAN's
prefix, which makes its sources this node's own, or carries the tunnel in UDP.
[The limits](design/limits.md#transit) say so.
