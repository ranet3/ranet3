---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Sharing a host"
description: "Sharing a host with other routing daemons, firewalls and VPNs."
created: 2026-09-12
updated: 2026-11-08
order: 110
---

The daemon is built to run next to Tailscale, NetBird, ZeroTier, an SD-WAN
agent, or anything else that owns interfaces and routes on the same host, and
the reconciler's ownership rules make that true rather than a hope. `cap.egress`
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
networkd from removing the rules at all. The NixOS module sets it to `false`, by
`mkDefault`, wherever `systemd.network.enable` is on, as nixpkgs' wg-quick
module does for its own rules, and a host that sets it itself keeps its own
value.

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
its query to a nameserver outside `overlay` too, where the process may set the
mark, a nameserver in a subnet another node announces among them, so where
`cap.table` is written the query ends at row L1 or L2 and never waits on a
session that only the name it asks for can dial. A nameserver on the host
itself, such as systemd-resolved's `127.0.0.53`, takes the query at row L1, and
its own query upstream carries no mark, so it can wait on such a session. Its
query to a nameserver inside the overlay carries no mark, whatever zone
`/etc/resolv.conf` writes after the address, and where `cap.table` is written
ends as any other program's does, rows L1 to L5. A link-local nameserver lies
outside the overlay, since [`overlay`](configuration-reference.md#top-level)
refuses a link-local prefix, so its query carries the mark where the process may
set it. An IPv6 one ends by main's route out of the link its zone names, and an
IPv4 one at row L2 by main's route for it. The mark is a constant, with no key
to set it. Setting it takes `CAP_NET_ADMIN` or `CAP_NET_RAW`. A process that
holds neither logs `transport leaves the underlay sockets unmarked` once, at
info, and sends its underlay datagrams and its resolver queries unmarked, which
end as an unmarked lookup does in
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux). Without
`CAP_NET_ADMIN` no rule reads the mark either: a node with `cap.table` refuses
to start, since the reconciler cannot set `promote_secondaries` on the tun, and
a node without it writes no rule at all.

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

The reconciler leaves another program's rules alone, and they share the policy
database with its own. The kernel walks the rules in priority order, and a rule
of another program that the walk meets before the rule of ranet3's that would
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
  while Tailscale uses an exit node, that exit's default takes them all. The
  reconciler reports each overlay prefix taken, as below.
- **A full tunnel of wg-quick** adds 2 rules with no priority, so added after
  the reconciler's, with no rule between local's and 5100, they go to 5099 and
  5098: `lookup main suppress_prefixlength 0` at 5098 and
  `not fwmark 0xca6c lookup 51820` at 5099. A route of main longer than /0 that
  covers the destination answers at 5098. WireGuard's table, which holds a
  default, takes every other lookup at 5099 but one carrying WireGuard's own
  mark, an overlay destination live or held and one marked 0x72 among them.
  Added before the reconciler's, with no rule but the kernel's own, they go to
  32765 and 32764, and 5110 answers every overlay destination ahead of them.

The reconciler takes no lookup back from another program's rule, and reports one
that takes it. After each pass that applies without error, among the passes
[when a pass runs](routing.md#when-a-pass-runs) lists, it asks the kernel where
2 kinds of lookup end, on the socket it writes with:

- An unmarked lookup of one address of each overlay prefix it holds: the first
  address after the prefix's network address outside every prefix `cap.table`
  assigns, or where the assigned prefixes leave none, the first that no assigned
  address equals, or the one address of a full length prefix, and none where
  `cap.table` assigns every address of the prefix. The prefix is taken when the
  answer is anything but a route out of the tun, from any table, or the refusal
  of an unreachable route, the hold's among them.
- A lookup marked 0x72 for each send of a live session, in both families: toward
  the address the session sends its underlay to, from the source and out of the
  interface its datagrams carry where they carry one. A session a peer opened
  sends from the address and interface its peer's datagram reached, a session
  sending on a socket connected to its peer from the address that socket is
  bound to, with the interface of its pin where it has one, and an unpinned
  session to a link-local peer out of the interface the peer's zone names
  ([the underlay socket](design/limits.md#the-underlay-socket),
  [sockets connected to 1 peer](platforms.md#sockets-connected-to-1-peer)).
  Sends carrying the same address, source and interface are asked once. A lookup
  naming an interface no device holds when the pass names it is answered
  `a refusal (no such device)`, which is `ENODEV`, and nothing is asked, unless
  its send goes on an IPv6 socket connected to the peer, whose lookup is asked
  ([ip6_datagram_send_ctl](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/datagram.c#L855),
  [ip_route_output_key_hash_rcu](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L2804),
  [udpv6_sendmsg](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/udp.c#L1683)).
  The lookup is taken when the answer is a route out of the tun, from any table
  but local. Another program's table answering it out of another device is not
  reported, since ranet3's underlay inside another tunnel is a setup that works.

The reconciler reports a lookup when it becomes taken, when a taken one's answer
changes and when it stops being taken, in the log, on the Kernel line of
`ranet3 status`, in 2 gauges and as the `kernel.taken` event, as
[watching it](routing.md#watching-it) lists. The check has these limits:

- It asks 1 address of each prefix, so a rule that takes only part of a prefix
  is reported only where that part holds the address, and another program's
  unreachable route at that address reads as the hold.
- It asks the addresses live sessions send to, so a rule that takes the underlay
  toward a peer no session reaches is not reported.
- The reconciler sends an overlay lookup its destination, and an underlay lookup
  its destination, the mark and the source and interface its send carries, and
  nothing else. The kernel fills in the rest
  ([inet_rtm_getroute](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L3319),
  [inet6_rtm_getroute](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/route.c#L6232)),
  so a rule selecting by anything else a send carries, such as its ports, meets
  the lookup as those functions decide, and may take traffic the check never
  asks about.
- It asks what the sends carried when the pass ran, so a send that moves between
  a pin, a connected socket and neither is asked anew at the next pass, and the
  lookup it left is reported as no longer asked where it was taken.
- A route is judged by the first next hop the kernel's answer names, so another
  hop of a multipath route is not read. Which hop comes first is the kernel's
  ([fib_add_multipath](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/fib_semantics.c#L1709),
  [rt6_fill_node](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/route.c#L5902)).
- Another program's rule wakes no pass, so a rule added between passes is
  reported by the next periodic pass, `cap.table.reconcile` later at most.
- macOS has no policy rules and asks nothing.

### A BGP speaker on the same host

A BGP speaker such as BIRD or FRR beside ranet3 often reaches a multihop
neighbor by main's default alone. Its sessions are unmarked lookups, so 5410
skips main's default for them. Where the mesh's longest match for the neighbor
is a route longer than /7 for IPv4 or /15 for IPv6, 5420 sends the session into
the tun, as row L8 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) gives. Where the
speaker's source lies in this node's own prefixes, 5430 sends it to the mesh's
route of any length, its default among them, as row L11 gives. The session then
rides the mesh and fails with the mesh's route, even though main reaches the
neighbor. Where the mesh's longest match is a hold, 5420 refuses the session
instead, as row L9 gives, and where it is a throw, the lookup goes on past 5420
and 5430 to main at 32766, as row L10 gives, and main reaches the neighbor.

A rule `from <its sources> lookup main` between the reconciler's 2 blocks, at a
priority from 5191 to 5399, keeps those sessions on main:

```sh
ip -4 rule add priority 5300 from 192.0.2.1 lookup main
ip -6 rule add priority 5300 from 2001:db8::1 lookup main
```

It comes after 5110, so a destination inside `overlay` still reads the mesh's
table, a live one into the tun and a held one refused, and before 5410 to 5430,
so main's longest match, its default among them, answers every other lookup from
those sources that main holds a route for. Such a lookup then ends in main
whatever the mesh's table holds for it, a subnet another node announces outside
the overlay among them. The reconciler writes only the rules it derives from the
config, so this one is the host's own, written by `ip rule` or networkd's
`[RoutingPolicyRule]`.

### Exit mode beside other programs

[Exit mode](routing.md#exit-mode-on-linux) adds 5405, 5435 and 5440 to the
second block. Each layout below was measured in network namespaces holding the
reconciler's rules and table with `cap.exit.forward` naming a bridge, a LAN host
behind another link it leaves out, and an internet host beyond the uplink, in
both families and in 3 states: the mesh's defaults live, the defaults retracted,
and after the daemon was killed with `SIGKILL`. In the last 2 the mesh's table
holds no default, so 5440 finds none and the lookup goes on to main, as
[limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) declares.
After `SIGKILL` the rules stay, the tun goes with the process, and a held
overlay destination is refused by its hold.

- **Tailscale using an exit node.** Tailscale 1.104.2 writes its rules at 5210
  to 5270 and holds in table 52 a default through its tun, with throws for the
  loopback, the uplink's network and over IPv6 `fe80::/64`. Its rule at 5270
  comes ahead of 5440, so in every state table 52's default takes the host's own
  traffic, the bridge's and the LAN's into Tailscale's tun. An overlay
  destination still reaches the mesh at 5110. Tailscale's own sockets, marked
  `0x80000/0xff0000`, leave by main at 5210. The node's underlay skips 5110 to
  5190 and then meets 5270, so it leaves by Tailscale's tun, but toward the
  uplink's own network, which table 52 throws. This is a case ranet3 cannot
  hold: while Tailscale uses an exit node, ranet3's sessions to a peer beyond
  the uplink's network ride inside Tailscale's tunnel and fail with it, and the
  host's traffic follows Tailscale's exit rather than the mesh's. Removing
  `cap.exit` leaves the host's traffic to Tailscale's exit alone, and the
  underlay leaves Tailscale's tunnel only while Tailscale uses no exit node, as
  [Tailscale at its default base](#another-programs-rules) measures.
- **A firewall restoring the conntrack mark with the full mask,**
  `meta mark set ct mark` in a route chain at output with no save. The
  underlay's datagram leaves the chain with mark 0 and is routed again from the
  uplink's address with `iif lo`, which 5405 sends by main, so the underlay's
  datagrams, UDP as IKE's and an IP protocol with no port as ESP's, reach the
  far side by the uplink in every state and never enter ranet3's own tun.
- **kube-proxy and Cilium.** kube-proxy's masquerade reads `0x4000` and Cilium's
  rule at 9 reads `0x200/0xf00`, and neither reads a bit of 0x72. The underlay
  leaves by the uplink in every state, the masquerade counts no packet of
  ranet3's, and the host's own traffic and the bridge's follow the mode.
- **Docker 29.9.1.** Its `DOCKER-FORWARD` chain accepts whatever enters by its
  bridge, so with `forward` naming the bridge the bridge's IPv4 flow enters the
  tun masqueraded to the tun's address by Docker's own
  `oifname != "docker0" masquerade`, under either `FORWARD` policy. Docker sets
  `ip filter`'s policy to `drop` where forwarding was off before it started, and
  that policy drops every other forwarded IPv4 packet, a LAN's among them,
  before it leaves, whatever the mode. A link `forward` names other than
  Docker's bridge then needs an accept in `DOCKER-USER`, as
  [Docker's packet filtering](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
  describes. Docker leaves `ip6 filter`'s policy at `accept` and writes no IPv6
  masquerade, so a container's IPv6 flow enters the tun from its own address,
  which the tun read drops unless this node announces the bridge's network.

5435 selects the networks of each link `forward` leaves out, as
[exit mode](routing.md#exit-mode-on-linux) lists, so a `fib` expression's
reverse path check of a reply to one finds main's route, as row E2 of
[where a lookup ends](routing.md#where-a-lookup-ends-on-linux) gives. A strict
`fib` chain's IPv4 check finds the mesh and drops the reply to a network routed
beyond such a link, to a network 5435 leaves out for overlapping the overlay,
and to the hosts of a network 5435 leaves out for overlapping this node's own
prefixes that lie outside those prefixes. The hosts inside this node's own
prefixes reach the mesh through 5430 both ways, and their replies pass. Naming
the link in `forward` serves only traffic the owned-source rule passes,
masqueraded to the tun's address or announced, as
[what forwarded traffic meets](#what-forwarded-traffic-meets) states. For the
rest, keep the chain's IPv4 check off that traffic.

### The kill switch beside other programs

Under `cap.exit.fallback = "none"`
[the kill switch](routing.md#the-kill-switch-on-linux) adds 5445 and 5450 to the
second block and writes the table `inet ranet3_fallback`, whose chains filter at
`output` and at `postrouting` at priority 2147483646, over the reach that page
gives.

- **A firewall's author.** A chain at 2147483647 at postrouting sees only what
  the switch passed and can drop or count, since a filter chain
  [routes nothing again](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_chain_filter.c?id=940de590b839f71d6dc846160534bf202401b8b7#n15)
  and a route chain
  [hooks output alone](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_chain_route.c?id=940de590b839f71d6dc846160534bf202401b8b7#n138).
  At output the switch's chain reads the link of the packet's first route
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n120),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/output_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n116))
  whatever priority a route chain or NAT there runs at. A route chain that marks
  or rewrites a packet at output, NAT at output, and a filter chain marking at
  `raw`, `mangle` or `filter` all run before the postrouting chain, which judges
  the link the packet leaves by after them
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n437),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/ip6_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n248)).
  Output's fib line passes a packet whose destination `fib daddr type` reads
  local
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter/nft_fib_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n58),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter/nft_fib_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n89)),
  whatever gave the packet that destination, NAT at output or a route chain
  rewriting it, and postrouting judges that packet by the link the reroute at
  output gives it
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter.c?id=940de590b839f71d6dc846160534bf202401b8b7#n49),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter.c?id=940de590b839f71d6dc846160534bf202401b8b7#n44)).
  The labs measured three such layouts in both families. A send beyond the LAN
  that a route chain at output marked into a table holding a local default on
  `lo`, its destination not read local, met output's drop. A send bound to the
  uplink that NAT at output sent to 127.0.0.1 or ::1, or to an address the host
  held on another link, passed output's fib line, left by the uplink and met
  postrouting's drop. One bound to the uplink that NAT at output sent to the
  uplink's own address left by `lo` and was delivered. A kernel tunnel's outer
  packet meets output's lines by the link of its first route and postrouting's
  with the tunnel as its input link, so one first routed into the tun or `lo`
  that a route chain at output routes beyond the LAN passes output's `oifname`
  line, and postrouting's forwarded line where the tunnel is outside `forwarded`
  and `fib daddr type` does not read its destination local. Each is as
  [limits](design/limits.md#routes-that-carry-the-hosts-own-traffic) declares.
  Each of these layouts, a socket's own mark, route chains marking, overwriting
  and clearing the mark at mangle, at 400 and at 2147483647, filter chains
  marking at filter, at mangle and at raw, restores of the connection's mark
  guarded and unguarded, NAT at output after the tun and to the uplink's own
  address, was measured in both families with the mesh's defaults present,
  retracted and after `SIGKILL`, and no packet of the host's own reached the
  internet host by the uplink.
- **Tailscale and other VPNs.** Tailscale marks its own sockets `0x80000`, which
  its rule at 5210 sends to main, a kernel WireGuard with a `fwmark` marks its
  own, and the host's own IPsec sends its ESP by the uplink. The mark line
  passes ranet3's mark 0x72 alone, so it passes none of them. Each, and a kernel
  tunnel's outer packet, GRE, IPIP, SIT or WireGuard, meets output with no input
  link
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/ip_output.c?id=940de590b839f71d6dc846160534bf202401b8b7#n120),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/output_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n116)),
  so output's lines judge it as the host's own, and their drop takes one beyond
  the LAN unless another line of [the list](routing.md#the-kill-switch-on-linux)
  passes it. The tunnel lab, with the host opening every flow and `inbound`
  empty, measured no outer packet of GRE in IPv4 or of WireGuard in either
  family reaching the internet host, with the mesh's defaults present, retracted
  and after `SIGKILL`.
- **A firewall restoring the conntrack mark with the full mask,**
  `meta mark set ct mark` or `CONNMARK --restore-mark` at output. It sets
  ranet3's own IKE and ESP to mark 0, so routing sends them into the tun or to
  5450, and the chains' drop takes what leaves by the uplink beyond the LAN
  unless another line passes it. Under the switch ranet3 then loses its underlay
  to each peer beyond the LAN whose packets no other line passes, and no exit
  can be reached by it. A restore that leaves 0x72 alone keeps it: one guarded
  on an unmarked packet, `meta mark 0 meta mark set ct mark`, or one under a
  mask holding none of 0x72's bits,
  `CONNMARK --restore-mark --nfmask 0xff00 --ctmask 0xff00`.
- **kube-proxy and Cilium.** The chains' mark line passes ranet3's underlay only
  while its mark reads 0x72 exactly, so with any other bit set on it the
  underlay meets the other lines, and their drop beyond the LAN unless another
  line passes it. kube-proxy's `0x4000` and Cilium's `0x200/0xf00` go on the
  packets their rules select, which ranet3's underlay is not, so the mark line
  passes it. A pod's traffic forwarded from a link `forward` leaves out keeps
  its routes and passes the chain's forwarded line toward a destination
  `fib daddr type` does not read local
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter/nft_fib_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n58),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter/nft_fib_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n89)),
  and one `forward` names follows the switch as the host's own.
- **Docker.** A bridge `forward` names follows the switch as the host's own: its
  containers' lookups meet 5410, 5440, 5445 and 5450 as the host's do, and what
  leaves by a link outside the mesh meets the chains, where the forwarded line
  does not pass it and the drop takes it unless another line passes it. A bridge
  `forward` leaves out keeps the routes it had and passes the chain's forwarded
  line whatever the state, toward a destination `fib daddr type` does not read
  local
  ([IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/netfilter/nft_fib_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7#n58),
  [IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv6/netfilter/nft_fib_ipv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n89)).

A reverse path check, rp_filter's strict mode or NixOS's strict and loose fib
chains, passes under the switch as it does without it: the replies of a flow
from a link `forward` leaves out, of a listed service and of the underlay.

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
keeps no source with a route, so a source-specific route another program wrote
there is withdrawn and installed again.

The reconciler installs 4 kinds of route scoped to the utun. A scoped route is
invisible to an ordinary lookup and visible to a socket bound to the utun or to
an address on it.

- A source-specific route. Interface scope is the only thing on this platform
  that draws the distinction a source prefix draws.
- An unreachable hold. macOS has 1 forwarding table, and an unscoped hold would
  shadow every other way to its prefix.
- A route outside the overlay inside another program's or the host's unscoped
  route longer than `/0` out of another interface, a member of the zero-free
  cover among them, and the pieces outside the overlay of one there that holds a
  prefix of the overlay. Linux answers by such a route of `main` ahead of the
  mesh's table, and macOS by its one longest match, so the mesh's route, if left
  unscoped, would take that route's traffic, as
  [where a lookup ends](routing.md#where-a-lookup-ends-on-macos) gives.
- A route that would carry the host's own traffic, in mode off or in a family
  [`cap.exit`](configuration-reference.md#capexit) leaves out. Such a route is
  one that [counts as a default](routing.md#routes-that-count-as-a-default).

Under `cap.exit` without `via`, in each family the tun holds an overlay address
of, every route outside the first 3 kinds is installed unscoped, so the Mac's
own traffic takes the mesh's exit without every program binding first. In mode 3
the reconciler declines every route that counts as a default but its steered
defaults, as [routing](routing.md#the-zero-free-cover-on-macos) describes.

Tailscale makes the same split on the same host. Its exit-node default is scoped
to its utun, and its `100.64.0.0/10` is not.

An unscoped `0.0.0.0/0` or `::/0` out of the utun would collide with the host's
own default. Under `cap.exit`, in a family the mode covers, the reconciler
installs a route holding its family's zero address as the members of the
zero-free cover it contains, as
[routing](routing.md#the-zero-free-cover-on-macos) describes, with which `/0` a
Mac takes. [Exit nodes](exit-nodes.md#what-to-advertise) says why an exit
advertises the `/0` only.

ranet3 writes nothing outside its utun. A datagram it sends without a pin names
the interface the selection answers from the host's routes, so another VPN's
full tunnel or a second uplink's route carries it as it carries any other
program's traffic. One sent from a pin names the address the peer reached as its
source and leaves by the interface the kernel takes for that address, as
[routing](routing.md#the-underlays-interface-on-macos) describes.

What a scoped route does not give you is automatic use of an exit-announced
address. Invisibility to an ordinary lookup is the safety property, and it
applies to every unbound socket, so Safari, curl and ssh keep the address of
whatever interface the host was already using. macOS has no `ip rule`: selecting
a scoped route means `bind()` to an address on the tun or `IP_BOUND_IF` to the
tun itself, per application, and ranet3 provides neither. `cap.exit` takes the
host's own traffic into the mesh unscoped instead, as above.

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
forward with
[a chain for each class of `none`](exit-nodes.md#the-nftables-tables) beside it,
the set that chain counts flows in for
[each source's share](exit-nodes.md#each-sources-share-of-the-flows), the
anonymous sets the screens of a class of `none`'s chain take their sources from,
and the timeout objects of the flows it translates. That name is the whole of
its ownership claim, as `rt_proto` is the reconciler's. It writes only inside
those tables and reads them back as
[refusing to advertise](exit-nodes.md#refusing-to-advertise) lists, so a rule
another writer puts in one of its chains or edits there, or a table it sets
dormant, which changes what the chain does to a packet, is undone by the next
pass. It does not read back the set's counts, so a count another writer changes
or removes stays as that writer left it. Every chain in its table whose name
starts `none_` is its own, as
[refusing to advertise](exit-nodes.md#refusing-to-advertise) describes. Another
chain in its table is neither read nor removed until the table is made again. It
reads other writers' tables, chains and rules to find its own and to report
conflicts, and writes, replaces or deletes nothing outside its own tables. It
replaces the chains' rules in 1 transaction, so no packet is ever evaluated
against half a ruleset, and deletes and makes a table again in that transaction
where nf_tables will not change it in place, any chain another writer put in the
table with it.

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
writes a chain below 99, or one at 99
[made after the translator's](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n147).
A flow such a chain translates leaves without this node's translation, its
timeouts and its count of translated flows, and the limit still holds it to its
source's [share](exit-nodes.md#each-sources-share-of-the-flows). Deleting a
neighbor's rule instead would break whatever installed it.

`status` and the log name the other chains instead and leave them alone. Their
rules and this one are usually disjoint, since this one matches on the mesh
device in both directions.

The scrape counts the other chains as `ranet3_egress_conflicts`. The report
covers nat postrouting chains at priority 99 or below, which can run ahead of
the translator's, in `ip` and `ip6` tables of the families it translates and in
`inet` tables, whose chains hook both families, another writer's chain in the
translator's own table among them. It leaves out chains past 99, which run after
it.

A class of `none` binds its flows to the source they carry in the translator's
chain, at priority 99, so a host's masquerade at `srcnat` or after leaves them
alone, and a chain below 99, or one at 99 made after the translator's, still
translates them, as [for every mesh flow above](#the-packet-filter).

The filter chain at forward, priority 0, runs beside the host's own filter
chains at that hook: a packet passes only where no chain drops it, so its
refusal of a flow past its source's
[share](exit-nodes.md#each-sources-share-of-the-flows), and its drop of a packet
no flow is tracked for out of the mesh under a class that translates or into it
under `return`, end that packet whatever the others say. A packet a host rule
exempts from connection tracking, such as a `notrack` in a raw chain, counts as
one no flow is tracked for, and leaves the mesh only under a class of `none`.

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

[The antispoof filter](antispoof.md) adds a third table under the same name,
`inet ranet3`, on every Linux node: filter chain `mesh_entry` at postrouting,
priority `srcnat` + 10 (110), and with `overlay` filter chain `antispoof` at
prerouting, priority `raw` (-300). The same rules hold: it writes only inside
its table and replaces its chains and sets in 1 transaction.
[Its lifetime](antispoof.md#where-it-runs) says when the table is taken over,
kept and removed. The conflict report above leaves its chains out, since they
are filter chains and translate nothing. Another base chain at the same hook,
such as a firewall's own raw chain, runs beside it: both see every packet, and
only a drop in either ends the hook. A firewall reload that flushes the whole
ruleset deletes the table, and the filter puts it back on the pass the deletion
wakes. A table or chain another writer changed in a way nf_tables will not undo
in place is deleted and made again in 1 transaction, any chain another writer
put in the table with it.

For a firewall's author, `mesh_entry` reads the source a packet leaves by the
tun with, after every source translation: each NAT chain at postrouting runs
inside NAT's own hook at 100, whatever priority it names, so the translator's at
99, Docker's masquerade at `srcnat` and any other have run by 110. A container
masqueraded to the tun's address therefore enters the mesh, and one a bridge
forwards unmasqueraded does not. Another filter chain at 110 runs before or
after `mesh_entry` by the order the chains were made in, the later first, and
neither changes the source the other reads. A packet it drops meets no chain
after it at postrouting,
[the kill switch](routing.md#the-kill-switch-on-linux)'s among them.

`overlay` must not hold another overlay's space, such as Tailscale's
`100.64.0.0/10`: the antispoof filter would drop that program's peers' sources
arriving on its own interface. Tailscale's sources forwarded from `tailscale0`
into the tun are dropped by `mesh_entry` unless a masquerade gives them the
tun's address, since this node owns none of them.

### pf on macOS

On macOS [the antispoof filter](antispoof.md#the-pf-anchor-on-macos) writes into
pf where `overlay` is written, through
[pfctl(8)](https://keith.github.io/xcode-man-pages/pfctl.8.html) alone, in the
grammar of [pf.conf(5)](https://keith.github.io/xcode-man-pages/pf.conf.5.html).
Apple's
[TN3165](https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api)
says pf is not API, so a macOS release can change what pfctl prints or does, and
a pass that reads the anchor back otherwise than written reads not ready. The
same rules hold as for nftables: it writes only inside the anchor
`com.apple/ranet3`, a child of `com.apple` beside Apple's own, loads it whole or
its tables alone in 1 transaction each, and never runs `pfctl -e`, `pfctl -d`,
`pfctl -F` without `-a`, or `pfctl -f` without `-a`. It holds pf enabled by a
reference of its own, which leaves another program's reference and pf's running
state as they were when it gives its own back.

- The stock main ruleset in `/etc/pf.conf` calls `anchor "com.apple/*"`, and pf
  evaluates `com.apple`'s children in the order of their names. An operator's
  own rule for a source the anchor drops or passes, a block of part of an
  exemption among them, goes in the main ruleset ahead of the call, and a
  stateful rule of one's own that a flow over the mesh's utun can match keeps
  its states to their interface, with `set state-policy if-bound` in the main
  ruleset or `(if-bound)` on the rule, as
  [the limits](design/limits.md#the-antispoof-filter) give.
- `pfctl -F all` or another VPN's ruleset loaded over the stock one removes the
  call, and pf then evaluates no rule of the anchor. A call counts only where it
  evaluates the anchor for every packet into every interface in both families:
  `anchor "com.apple/*"`, which pfctl prints as `anchor "com.apple/*" all`, or
  the same with `in`. One that names `out`, an interface, `inet` or `inet6`, a
  protocol or an address leaves packets out of the anchor, and counts as none,
  and so does one inside an inline anchor's braces, such as
  `anchor in { anchor "com.apple/*" }`, which pf resolves relative to that
  inline anchor. A start with `overlay` written then refuses to run, as a Linux
  start refuses a filter its first pass does not read back, with
  `egress: the antispoof filter in pf anchor com.apple/ranet3 is not ready, since pf's main ruleset calls neither anchor "com.apple/*" all nor anchor "com.apple/*" in all at its own depth, so pf may evaluate no rule of com.apple/ranet3 for a packet in: a call that names out, an interface, a family, a protocol or an address leaves packets out of it, one inside an inline anchor's braces resolves relative to that anchor, pfctl -f /etc/pf.conf loads the stock ruleset again, and a ruleset loaded in its place needs that line`.
  A running filter that finds the call gone reads not ready with the same reason
  and keeps running. Either way the fix is the host's: load the stock ruleset
  again, or keep `anchor "com.apple/*"` with no qualifier in a ruleset of one's
  own, ahead of any `quick` pass meant to come after ranet3's drops. The daemon
  never edits the main ruleset.
- A `set skip` naming an interface outside the mesh, loaded with the main
  ruleset, makes pf pass every packet on it before any rule, a forged overlay
  source among them, and the start refuses the same way, with
  `pf skips en0, as a set skip loaded with the main ruleset asks, so pf evaluates no rule for a packet arriving there and a forged overlay source passes: pfctl -f /etc/pf.conf loads the stock ruleset again, which skips no interface`
  as the reason, naming every such interface. `pfctl -s Interfaces -v` lists
  whether an interface has a skip rule activated, as `man pfctl` on a Mac says,
  and prints `(skip)` after its name where it has one. A skip of the mesh's utun
  or `lo0`, as `set skip on lo0` asks, changes nothing the anchor drops.
- `pfctl -d` stops pf and ends every reference, the daemon's among them. The
  next pass, within 5 seconds, takes a new reference, which turns pf back on, as
  [readiness](antispoof.md#readiness) says with what the pass logs and how to
  turn the filter off.
- A crash leaves the anchor, its drops sparing a utun that went with the
  process, and the reference held. The next start takes both over on its own, or
  gives both back where it has no `overlay`, and
  [the anchor's lifetime](antispoof.md#the-pf-anchor-on-macos) gives the
  commands that clear them while ranet3 stays down.

## What forwarded traffic meets

A node that forwards for others routes a neighbor's packet by its destination,
and a mesh destination leads into the tun. The host's own kernel, a Docker
bridge, or a LAN behind a subnet router can put a packet into the tun this way.
The forwarding decision checks what the tun hands this node before the packet
enters the mesh, as [the antispoof filter](antispoof.md) checks what arrives on
the interfaces outside the mesh. A drop sends no answer and counts on the
`Transit` line, as [metrics](metrics.md#transit-counters) lists. On Linux the
antispoof filter's [entry chain](antispoof.md#the-entry-chain) meets such a
packet first, before the tun, and passes only a source this node owns, a reply,
a destination a `none` class takes, or an IPv6 link-local or multicast
destination, so the checks below read what it passed.

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
- A read toward an exit's default, or under
  [`cap.exit.via`](routing.md#mode-3-on-linux) toward a destination outside the
  overlay that no entry covers, from a source this node does not own is dropped
  and counted `unowned_source`, the owned-source rule. Only this node's own
  traffic leaves the mesh through its exits. On every platform but Linux the
  rule takes more, as [the platforms](antispoof.md#platforms) say.

[Exit mode](routing.md#exit-mode-on-linux) sends what a link `cap.exit.forward`
names forwards into the tun toward the mesh's default, so the owned-source rule
decides it. A Docker bridge's IPv4 flows pass, masqueraded to the tun's address.
A LAN this node announces through `cap.route` or advertises through `cap.egress`
passes. Any other LAN's packets are dropped and counted `unowned_source`. On
Linux the [entry chain](antispoof.md#the-entry-chain) drops them before the tun,
toward any destination but a `none` class's, and counts them as `mesh_entry`. On
every other platform the read drops them toward the overlay and any subnet the
mesh routes as well, and counts them `unowned_source`.

On Linux replies to the mesh's overlay and to subnets the mesh routes are
untouched by the owned-source rule: an exit's egress replies, translated back by
the kernel, carry the internet's sources and are bound for a leaf's overlay
address, out of that rule's reach. No other platform runs an exit. A host
tunneling its LAN through the mesh announces the LAN's prefix, which makes its
sources this node's own, or carries the tunnel in UDP.
[The limits](design/limits.md#transit) say so.
