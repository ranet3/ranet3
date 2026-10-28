---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Debugging a running node"
description: "The debug tree: who may call it, what it promises, its commands and how a view is added."
created: 2026-10-04
updated: 2026-10-31
order: 30
---

`ranet3 debug` is a command tree for looking inside a running node. Most of its
commands speak to the daemon over the control socket, under paths starting with
`/v0/debug/`. `debug buildinfo` reads the binary it runs in, and `debug socket`
sends a request to any path.

The tree is not a stable interface. A debug path, a field of its answer, an
event kind and a command may each change or go in any revision. A client and a
daemon built from the same revision agree, and nothing wider is promised.
`ranet3 debug --help` lists its commands, and [command line](../cli.md) lists
every command, this tree included.

Every command but `debug socket` prints text, or the wire form with `--json`.
`debug socket` prints the answer's body as it arrives. Every command that could
run for long is bounded by a flag, `--for` or `--timeout`, so a script can call
one without having to interrupt it. Arguments and flags that name a peer, an
event kind, a path or the socket complete in bash, zsh and fish, the shells
`ranet3 completion` writes for.

## Who may call it

The socket's mode decides who can connect at all. That is enough for the reads
and the verbs outside this tree, because each of those acts on something the
node's own file already decides. A debug path can show or do what the file never
decides, so debug paths are authorized by who is calling instead.

The daemon asks the kernel for the credentials of every connection it accepts,
`SO_PEERCRED` on Linux and `LOCAL_PEERCRED` on macOS. Every debug path has a
class:

- **read**: snapshots that carry no key material, and the event stream. Open to
  everyone who can open the socket, as `ranet3 status` is.
- **root**: every debug action. `debug probe` is the only one. Open to uid 0 and
  to the user the daemon runs as. Each such call is logged at info with the
  caller's uid and pid.
- **plaintext**: what the node reads of the packets it handles, other nodes'
  traffic among them. `debug trace` is the only one. Open to uid 0 alone. Each
  such call is logged at info with the caller's uid and pid and its query, which
  holds the filter and the payload length asked for.

The daemon serves 11 debug paths:

| Path                 | Class     | Commands                     |
| -------------------- | --------- | ---------------------------- |
| `/v0/debug/egress`   | read      | `debug egress`               |
| `/v0/debug/events`   | read      | `debug events`, `debug wait` |
| `/v0/debug/netmon`   | read      | `debug netmon`               |
| `/v0/debug/pmtu`     | read      | `debug pmtu`                 |
| `/v0/debug/probe`    | root      | `debug probe`                |
| `/v0/debug/route`    | read      | `debug route`                |
| `/v0/debug/rules`    | read      | `debug rules`                |
| `/v0/debug/runtime`  | read      | `debug runtime`              |
| `/v0/debug/segments` | read      | `debug segments`             |
| `/v0/debug/trace`    | plaintext | `debug trace`                |
| `/v0/debug/updown`   | read      | `debug updown`               |

Profiles are not a debug path. The daemon's `--pprof` serves them on an address
of its own, and no class covers that address.

The daemon's `--debug-access` sets how far the root class reaches. `root` is the
default. `group` opens the root class to everyone who can open the socket, and
`off` refuses every debug path, the read class included. `group` leaves the
plaintext class to uid 0, since the packets it shows are other nodes' too. The
modules carry no option of their own for it: `extraArgs` passes the flag. The
daemon reads the caller's credentials on Linux and macOS only, so on every other
platform a connection reaches the read class alone under `root` and `group`,
nothing under `off`, and the root and plaintext classes refuse every call there.

A debug request the daemon does not answer with 200 gets one of these statuses:

| Status | When                                                                                                                                                                                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400    | an events or trace query, an action body or a `debug route` packet that does not parse, a trace query out of its bounds, a link `debug route` refuses as the arrival, such as the mesh's tun, or an action the node refuses, such as `debug probe` while it is down |
| 403    | the class refuses the caller, and the answer names the rule and the caller's uid or the missing credentials                                                                                                                                                         |
| 404    | no debug path has that name, except under `off`, which answers 403                                                                                                                                                                                                  |
| 405    | a read sent with a method other than GET or HEAD, a trace sent with one other than GET, or an action sent with one other than POST                                                                                                                                  |
| 501    | the server behind the socket does not implement the view, and the answer names it. The `ranet3` daemon implements every view                                                                                                                                        |
| 503    | the daemon already holds 4 streams, event and trace streams together, or a trace asked for while the daemon stops                                                                                                                                                   |

On a NixOS host and on macOS the daemon runs as root, so the root and plaintext
classes mean `sudo`. In an `unshare -rn` lab the caller already reads as uid 0.

## Commands

Every command in the tree takes these 2 flags:

| Flag        | Default                        | What it sets                        |
| ----------- | ------------------------------ | ----------------------------------- |
| `--control` | `/var/run/ranet3/control.sock` | the control socket to ask           |
| `--json`    | off                            | print the wire form instead of text |

These commands take flags of their own:

| Command        | Flag             | Default              | What it sets                                                    |
| -------------- | ---------------- | -------------------- | --------------------------------------------------------------- |
| `debug socket` | `--timeout`      | 10 seconds           | how long the whole exchange may take, a stream included         |
| `debug probe`  | `--all`          | off                  | probe every session instead of one peer's                       |
| `debug events` | `-f`, `--follow` | off                  | print later events as they come                                 |
| `debug events` | `--for`          | 30 seconds           | how long `-f` follows                                           |
| `debug events` | `--kind`         | every kind           | a kind, or the part of one before a dot, given up to 16 times   |
| `debug events` | `--peer`         | every peer           | one peer, named as `redial` names one                           |
| `debug events` | `--since`        | every recorded event | how recent a recorded event must be                             |
| `debug route`  | `--iif`          | none                 | the link the packet arrives on, none for this host's own        |
| `debug wait`   | `--attr`         | none                 | a `key=value` the event must carry, given up to 16 times        |
| `debug wait`   | `--past`         | 0                    | how recent a recorded event may be and still end the wait       |
| `debug wait`   | `--peer`         | every peer           | one peer, named as `redial` names one                           |
| `debug wait`   | `--timeout`      | 10 seconds           | how long to wait                                                |
| `debug trace`  | `--src`          | every source         | a prefix or an address the source lies in, given up to 16 times |
| `debug trace`  | `--dst`          | every destination    | a prefix or an address the destination lies in, up to 16 times  |
| `debug trace`  | `--proto`        | every protocol       | a protocol by name, such as `udp` or `icmpv6`, or by number     |
| `debug trace`  | `--decision`     | every decision       | `deliver`, `forward`, `egress`, `answer` or `drop`              |
| `debug trace`  | `--peer`         | every peer           | one peer, named as `redial` names one                           |
| `debug trace`  | `--rate`         | 1000                 | the most records a second, from 1 to 10000                      |
| `debug trace`  | `--payload`      | 0                    | the bytes of each packet a record carries, up to 65535          |
| `debug trace`  | `--for`          | 30 seconds           | how long to trace                                               |

- `debug socket [METHOD] PATH [BODY|-]` sends 1 request as written and prints
  the answer's body as it arrives, with the status line on standard error, and
  exits 1 on anything but a 2xx. The method is GET, or POST where a body follows
  the path, and `-` reads the body from standard input. `--timeout`, 10 seconds
  by default, bounds the whole exchange, a stream included. It reaches a path no
  command covers yet, or a daemon of another revision. Its completion offers
  GET, HEAD and POST, then every control and debug path.
- `debug runtime` is the daemon's process: its version and revision, the Go
  version, GOMAXPROCS and the CPUs, goroutines, the OS threads the runtime has
  started, open descriptors against `RLIMIT_NOFILE`, the heap and the collector,
  uptime, and the resolver an endpoint's hostname goes through, the daemon's one
  lookup. `go` there means Go's own resolver answers it, which on Linux it
  always does, and `cgo` that the lookup may go to the C library, which holds an
  OS thread for as long as it takes. The view is read without stopping the
  daemon's goroutines, so polling it leaves the data path running. It also shows
  the memory taken from the system, the total pause of the collector, and
  whether the build's tree had uncommitted changes.
- `debug buildinfo` prints this binary's own Go build information.
- `debug netmon` is the host's network as the node's watch last read it: for
  each family the default route, its interface and gateway, and the global
  unicast addresses of the interfaces that are up, the mesh's own device left
  out, and on Linux each of those links with its addresses under their lengths
  and its point-to-point far ends as `IPv4 links`, which
  [exit mode](../routing.md#exit-mode-on-linux) derives its rules from, then the
  last change the watch acted on and what moved in it, the links after it where
  one came, went or moved an address or a far end. A change of links alone
  probes no session, and wakes the reconciler only under `cap.exit`. A platform
  without a watch says so. Linux and macOS have a watch.
- `debug rules` is every policy rule the kernel holds, whoever wrote it, in a
  table per family with its priority, its selectors, the table it names, shown
  as `0` for an `l3mdev` rule, which names no table, with any
  `suppress_prefixlength`, or its action, such as `goto 5190` or `nop`, and its
  owner: `ranet3` for a rule carrying `cap.table.proto`, `kernel` for the
  kernel's own, and the protocol number for anybody else's. Then, as
  `Wanted and missing`, the rules the reconciler's last pass derived that the
  kernel does not hold, as [routing](../routing.md#policy-rules-on-linux) lists
  them. Then, under `Lookups`, each lookup the reconciler last asked to find
  another program's rule ahead of its own, as
  [sharing a host](../coexistence.md#another-programs-rules) describes, with its
  kind, `overlay` or `underlay`, its family, the overlay prefix, the address
  asked, on Linux the source and interface a live session's send carries for an
  `underlay` lookup, `-` where it carries none, whether it is taken and the
  kernel's answer, also when the dump failed, or `Lookups: none` where the dump
  answered and the reconciler asked none. On macOS, which has no policy rules,
  `Lookups` lists the `underlay` rows, their source and interface `-`, the pin's
  interface named in the answer. A row is one address live sessions send to, a
  link-local one with its zone, with the interface of the pin their sends carry
  where that pin has one. A pin has the interface its index names, or with no
  index, the interface holding its address, and
  [routing](../routing.md#the-underlays-interface-on-macos) gives which sends
  carry a pin. Sessions whose sends carry no pin, or a pin with no interface,
  share the address's row. A row with an interface shows `dev` with its name, or
  its index where the host has no interface of that index, and no matched route.
  A row without one shows `dev` with the interface
  [the selection](../routing.md#the-underlays-interface-on-macos) names and the
  route it matched, or `no route`. No row is taken. An IPv4 datagram can ride
  the shared socket's cached route of another interface instead, as
  [limits](../design/limits.md#the-underlay-socket) gives. Then, on a node with
  `cap.border`, the border filter's chain: its table and hook, when its last
  pass read it and whether it is ready, then each rule with the packets and
  bytes each drop counted, any rule the chain does not hold yet, and any rule it
  holds that the filter did not write, by its comment or as
  `a rule with no comment`. Then, under `cap.exit.fallback = "none"`, the table
  `ranet3_fallback` as `Fallback table` with its two chains, their hooks and
  priority and the switch's state, each line of each chain with the packets and
  bytes the drop counted, and each named set with its elements, or `not held`
  where the kernel holds no table. The dump and the chains are each read now
  through a socket of their own, so an operator who sends a test packet reads
  the counters of that moment, and neither the reconciler's socket nor the
  filter's serves a reader. A platform with no policy rules says so. A rule
  carrying a selector the view keeps no value of, `uidrange`, `ipproto`,
  `sport`, `dport`, `dscp`, `flowlabel` or `tun_id`, or carrying
  `suppress_ifgroup`, shows that name among its selectors.
- `debug route <src> <dst> [--iif link]` follows one packet to where the kernel
  sends it: this host's own packet, or with `--iif` one arriving on that link.
  An unspecified `src`, such as `0.0.0.0`, is this host's own packet sent with
  no source. The mesh's tun is refused as `--iif`, since a packet written into
  it is this host's own. The packet is taken unmarked and well formed. The view
  makes 1 route lookup, and a second where an IPv6 one answers a route or an
  IPv4 one answers `EHOSTUNREACH`, through one socket, and 1 rule dump through
  another, now, and shows the route the kernel matched with its prefix, table
  and next hops, each marked `dead` or `linkdown` where the kernel marks it,
  beside the type the kernel gives the packet, and where the route leaves by: a
  link, this host, nowhere, or into the mesh's tun, where this view ends. It
  reads no nftables chain, so a link it names is where the route leaves by, not
  what [the kill switch](../routing.md#the-kill-switch-on-linux) lets leave. For
  this host's own IPv6 packet to `::`, the unspecified address, it names no path
  the packet leaves by, and says in a line of its own, whatever the lookup
  answers, that a socket sends such a packet to `::1` or by the route, or
  refuses it, as its type and the platform decide, so the answer may not be the
  packet's path (Linux's rewrite is in
  [`udpv6_sendmsg`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/udp.c#L1459)).
  The kernel names no rule, so the rule shown is the one a walk of the dumped
  rules ends on for that answer, as far as the answer tells: the view walks them
  by priority as
  [`fib_rules_lookup`](https://github.com/torvalds/linux/blob/master/net/core/fib_rules.c)
  does, following `goto` and `nop`, applying `invert`, and applying
  `suppress_prefixlength` as
  [`fib4_rule_suppress`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/fib_rules.c#L147)
  and
  [`fib6_rule_suppress`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/fib6_rules.c#L281)
  read it, reading an IPv6 answer through a route the kernel cached for its
  destination alone, a path MTU's or a redirect's, as a /128
  ([`ip6_rt_cache_alloc`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/route.c#L1369)),
  and matching this host's own packet as arriving on `lo`. Where no rule fits
  the answer, it says so and names none. Where an IPv4 lookup answers
  `EHOSTUNREACH`, the view asks again without `RTM_F_FIB_MATCH`, and a route
  that then answers is shown as the kernel's own for the destination, with no
  table entry behind it
  ([`inet_rtm_getroute`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L3319)),
  and no rule or forwarding setting named. For an IPv4 arrival to a group or to
  `0.0.0.0/8` the view names no rule
  ([`ip_route_input_rcu`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L2522),
  [`ip_route_input_slow`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L2291)),
  and shows its `EINVAL` as a group this host has not joined on the link or a
  source refused for it, or for `0.0.0.0/8` as a martian destination or source.
  Such a group's route is shown delivered to this host, which joined the group
  on the link, or beyond `224.0.0.0/24` taken by multicast routing where the
  view reads the link's and `all`'s `mc_forwarding` both on, and both ways where
  it cannot read one. Such a group's `EHOSTUNREACH` beyond `224.0.0.0/24` is
  shown as an answer the kernel's multicast routing withholds
  ([`rt_fill_info`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv4/route.c#L2978)),
  naming no forwarding cause for it, and where the view cannot read `all`'s
  `mc_forwarding`, as meaning multicast routing is on. An arrival whose route is
  a broadcast one is shown delivered to this host, which `bc_forwarding` changes
  as `ip_route_input_slow` reads it. For an IPv6 arrival to a group answered
  with `EMSGSIZE`
  ([`rt6_fill_node`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/route.c#L5787))
  the view names no rule or route. It never names an `l3mdev` rule, whose table
  the dump does not carry. A rule carrying a selector the walk does not read,
  one of those `debug rules` names, is listed ahead of the rule shown under
  `Unread` where every selector the walk reads holds, inverted or not, and the
  walk took it as not taking the packet. Where a selector the walk reads fails,
  an inverted rule is walked as matching and any other is passed over. A lookup
  rule carrying `suppress_ifgroup`, whose table holds the answer, is listed
  under `Unread` the same way, the walk taking it as having suppressed the
  answer. Where the errno also has a cause outside the walk, as IPv4's `EINVAL`
  does, and `ENETUNREACH` for this host's own IPv4 packet from a source it may
  not hold, a rule that answers the same errno is shown as the rule the walk
  ended on if it reached it, beside those causes. For a lookup the kernel
  refused, the view shows the errno and, where the errno has several causes,
  reads the settings that decide it rather than guessing: for an IPv4 `EINVAL`
  other than one to `0.0.0.0/8` the `rp_filter` of `all` and of the link, naming
  reverse path filtering only where the larger is 1 or 2, and for an IPv4
  `EHOSTUNREACH` other than a group's beyond `224.0.0.0/24` the link's
  `forwarding`, naming forwarding off only where it reads 0. For an IPv6 arrival
  the kernel answers with a route other than a local one, the view reads the
  `forwarding` of `all` and the link's `force_forwarding` where the kernel has
  one,
  [since 6.17](https://github.com/torvalds/linux/commit/f24987ef6959a7efaf79bffd265522c3df18d431),
  and names forwarding off only where `all` reads 0 and `force_forwarding` reads
  0 or is absent, not reading the link's own `forwarding`, after
  [`ip6_forward`](https://github.com/torvalds/linux/blob/940de590b839f71d6dc846160534bf202401b8b7/net/ipv6/ip6_output.c#L521).
  A setting it cannot read is shown unread. macOS looks up this host's own
  packets only, with no policy rules and without the source, which its lookup
  does not take, so its `ENETUNREACH` is no route alone. The BSDs look up none.
- `debug egress` is the exit: its status line as `ranet3 status` gives it but
  for the border filter's hold on the egress segments, each rule of its chains
  with its counter read now through a socket of its own, a rule of the
  translation's chain counting flows and the bytes of their first packets, one
  of the forward hook's chain counting packets, and one that keeps no counter
  shown uncounted, any rule it asks for and the chains do not hold, any they
  hold that it did not write, counted by the chain it was read from, then each
  family as the last pass judged it: ready or why not, its chains read back, the
  host's forwarding, and each route lookup the pass read with its answer, the
  reply's lookup included, as [exit nodes](../exit-nodes.md) describes the
  readiness. Then IPv4's `rp_filter` of `all` and of each link a route of those
  lookups leaves by, read now. The lookups are the last pass's and are not asked
  again. A node with no `cap.egress` says so.
- `debug segments` is each segment the node answers for, an egress segment with
  whether its SID is announced and the families the mesh hands to the exit
  through it, then the steering policies, on or stopped, with the overhead the
  tun's MTU leaves room for and each policy's selector, source, path and
  overhead, then the segment counters `ranet3 status` reports. A node with
  neither says so.
- `debug pmtu [peer]` is the path MTU of every session, or of one peer's: first
  `link.mtu`, the steering header and the tun's MTU, with the answers sent to
  packets past a session's budget and the SYNs whose MSS was clamped, both for
  the node as a whole. `Answer sources` is the router-id of each family, an
  address rather than the 16 hex digits of Babel's router id that `debug updown`
  shows, and `Answer SID` the answer SID, each `none` where the node holds none,
  as [path MTU](../path-mtu.md#where-answers-come-from) describes. Then for each
  session its path, the peer node it is with, its endpoint and whether its
  datagrams leave with DF, the state of its search, which is `confirming`,
  `searching up`, `searching down`, `confirmed`, `under the floor`, or
  `not searched` where datagrams leave without DF, its budget and the MSS it
  clamps to, the route's MTU when last read and the target it sets, the probe
  out and how the last one ended, its probes sent, acked and lost, the sends the
  host refused as too large for the path, and the budget's last change with its
  reason. A session that is `not searched` shows its path, peer, endpoint, state
  and budget, and no probes. Its budget follows `link.mtu`, and it records no
  change. A probe whose target the search moves while it is out counts as sent,
  and as neither acked nor lost. A refusal, the route read lower after a move of
  the host's default or one of its addresses or `debug probe`, a change of
  `link.mtu` and a move to another endpoint can each move the target. A probe
  answered after its wait ran out counts as both acked and lost, so the 3 counts
  need not add up. `ranet3_pmtu_probes_total` counts acked and lost probes the
  same way and has no series for probes sent. The peer is named as `rekey` names
  one, and completes to the nodes of the sessions the daemon holds. The command
  fails for a peer the node holds no session with.
- `debug probe <peer>` and `debug probe --all` ask the sessions of one peer, or
  every session, to send a liveness check now and to probe their path MTU
  budget, as each does after a move of the host's default or one of its
  addresses ([moving hosts](../platforms.md#moving-hosts)), and name the
  sessions asked. A session with a request outstanding resends that request
  instead. One with none sends no liveness check while its IKE SA is past its
  lifetime or a Delete of it has gone out, or while a rekey of its own may run
  `IKE_FOLLOWUP_KE` exchanges or waits on the peer's. It is an action, so it
  takes the root class, and it is recorded as a `control.verb` like the other
  verbs. It completes to the peers the node dials and the nodes it holds a
  session with. The daemon refuses it while the node is down, and when no
  session matches.
- `debug updown` is whether the node is on the mesh and since when, the flag
  that keeps it off through a restart and whether the flag is there, and the
  last move between up and down with its cause, a request or the flag at start.
  Where the flag and the node disagree, it says what a restart would do. It also
  shows the node's Babel router id and seqno, with the state file a restart
  starts them from and the seqno limit the file holds, read when the view is
  asked for. A router id the file does not hold is one a restart would not keep,
  and a seqno past the limit, as a failed save leaves one, is one a restart
  could send again.
- `debug events [-f] [--kind K]... [--peer P] [--since 5m] [--for 30s]` prints
  the events the daemon has recorded and exits, or with `-f` goes on printing
  the ones after them until `--for` has passed. `--kind`, given up to 16 times,
  takes a kind or any part of one that ends at a dot, so `babel` takes every
  Babel event, and `--peer` names a peer the way `redial` does. Without `-f` the
  exchange is bounded at 10 seconds, and `--for` is ignored.
- `debug wait <kind> [--peer P] [--attr k=v]... [--past 2s] [--timeout 10s]`
  waits for one event of that kind carrying every attribute named, up to 16,
  each with the value the event prints for it, prints the event and how long
  after the wait began it happened, and exits 0. It exits 1 when none came
  within the timeout, and 2 when it could not watch for one: no daemon
  answering, a refusal, every stream place taken, a mistyped command line, or
  the stream ending or dropping such an event first. The daemon applies the
  kind, the peer and the attributes before an event enters the stream's queue,
  so a burst of other events cannot push out the one awaited. `--past` takes an
  event that recent from the recorder as well, for one that may have happened
  just before the wait began. The recorder holds such an event only until 1024
  later events of its subsystem have come, and the wait does not see one evicted
  before it subscribed. A recorded event is judged by its stamp on the daemon's
  clock, and one that comes after the wait subscribed is taken whatever its
  stamp, so a clock stepped back during the wait hides nothing. With `--json` it
  prints 1 object with the `event` and `after`, the time from the start of the
  wait to the event. `after` is negative for an event recorded before the wait
  began.
- `debug trace [--src P]... [--dst P]... [--proto P] [--decision D] [--peer P] [--rate 1000] [--payload 0] [--for 30s]`
  prints a record of each packet the node's forwarding decision handles and the
  filter selects, as the node decides it, until `--for` has passed, and then
  exits 0. It needs uid 0, as the plaintext class above says. A record is
  described below. A packet the forwarding decision never sees, such as Babel's
  own or IKE and ESP on the underlay, never appears. With `--json` each line is
  an object holding a `packet` or a `note`.

## Trace records

A record names the decision, `deliver`, `forward`, `egress`, `answer` or `drop`,
and for an answer or a drop its reason, as the `reason` label of
`ranet3_transit_packets_total` names it, or `budget` for a packet its next
peer's send budget refused. It names how the packet arrived, `session` with the
session's path, `tun` for a packet read off the tun, or `none` for one of no
session, and the next peer's session for a forward. A packet a steering policy
sent through a segment carries that first segment, one an End segment of this
node sent on carries the next segment, and one a segment of this node egressed
or dropped carries the segment that did, past any End of this node that sent the
packet on to it. Then come the source and destination, the protocol after the
IPv6 extension headers, or an IPv4 packet's, the names of those headers or of
the IPv4 options, the ports and TCP flags or the ICMP type and code where the
packet's first fragment carries them, the hop limit or TTL and the length, and
how many fragments a forward cut the packet into. An answer names its ICMP error
and what became of it: `sent`, `withheld` by the
[ICMP rate limits](../path-mtu.md#packets-that-do-not-fit), `unanswered` where
the node holds no address of the family to send it from, `not_answerable` for a
packet no ICMP error may answer, or `unsent` for one built for, or due to, a
source the mesh routes it no way back to, or one its session had no room for.

Every field is read from the packet as it arrived, before the node took its hop
limit down, clamped its MSS or handed it on, except in a `drop` record of reason
`budget`. That record follows the packet's `forward` record, goes to the traces
whose filter takes the packet as that record shows it, and shows the packet as
it was queued for its peer. A packet a peer's queue later drops for its delay,
or that the session's SA refuses, is counted in `ranet3_peer_send_dropped_total`
and has no record of its own.

A record carries none of the packet's bytes unless `--payload` asks for them,
and then that many bytes from the IP header on, or the whole packet where it is
shorter. The filter takes a packet whose source lies in any one of the `--src`
prefixes and whose destination lies in any one of the `--dst` prefixes, where an
IPv4-mapped IPv6 address lies in no IPv4 prefix, and `--peer` takes a packet
that arrived on that peer's session or goes to it. The rate is a bucket of 1
second's worth, which only a packet the filter takes draws on, and a packet past
it builds no record. Before the node rewrites a packet, a trace whose bucket has
room copies it if its filter may still take its record, as a filter of
`--decision drop` or `answer` may take a forward's, which may yet drop or answer
the packet, and a filter of `--peer` that of each IPv6 packet a session delivers
to a node with segments of its own, which an End segment may send on to any
peer. A packet past the rate is counted, but not one that arrived at a segment
of this node while no trace whose filter may take it had room, whether End sent
it on or a segment refused it before or after End's rewrite. An inner packet an
egress segment took out past its allow list is counted, whether the segment sent
it out or refused it. Each trace has a queue of its own, and what the rate and
the queue refused is counted in a `stream.dropped` line once a second, with
`rate` and `queue` each the records refused since the line before.

Each session's packets are decided on a goroutine of their own, and so are each
tun queue's reads. Records of one session or one queue come in the order the
node decided them, and records of different ones interleave in no defined order.
A trace stream is one of the daemon's 4 streams, and it is dropped and its trace
closed once a write has waited 5 seconds on its reader. With no trace open, each
step of the forwarding decision a batch passes reads one pointer to learn so.

## Events

The daemon records what it did, a state change and never a packet. An event
carries a sequence number without gaps, the time on the daemon's clock and how
long after its start, a kind written `subsystem.what` or `subsystem.thing.what`,
the peer it is about where there is one, and attributes. Each subsystem, the
first word of a kind, keeps its last 1024 events, so a flood in one cannot evict
another's history.

A follow answers with the recorded events, then a `stream.live` line, then each
later event as it comes. A stream never makes the node wait for its reader. Each
open stream's filter runs at every event the node records, on the goroutine that
records it, and an event the stream takes is rendered there and handed to its
queue. Each reader has a queue of its own, and the events its queue has no room
for are counted and reported in a `stream.dropped` line where they were lost,
once the stream has written the events before them. A quiet stream writes a
`stream.heartbeat` line every 15 seconds, so a reader can tell a quiet daemon
from a dead one. A stream is dropped once a write has waited 5 seconds on its
reader. The socket buffers what a reader has not taken, so one that stopped
reading keeps its place until that buffer is full, at once under a flood of
events and after up to about an hour of heartbeats on a quiet daemon. A stream
whose daemon is stopping ends with a `stream.closed` line saying so. A daemon
holds 4 streams at once and refuses a 5th with 503, which leaves the rest of its
connections to the reads.

| Kind                                  | When                                                                                      |
| ------------------------------------- | ----------------------------------------------------------------------------------------- |
| `daemon.started`, `daemon.stopping`   | the node is up, and its shutdown has begun                                                |
| `daemon.reload`                       | the file and trust document were read again, with what applied or the error               |
| `daemon.ttl`                          | a reload could not read the host's default TTL, which ICMPv4 answers carry                |
| `node.down`, `node.up`                | the node went off the mesh or came back, by a request or from its flag                    |
| `responder.changed`                   | a reload turned `link.listen` on or off, with the answered sessions closed                |
| `control.verb`                        | a verb over the socket, under each session or dialer it acted on or missed                |
| `control.trace.started`, `.ended`     | a trace of the forwarding decision opened, and closed                                     |
| `dial.attempt`, `dial.failed`         | a dialer sent a handshake, or ended short of a session                                    |
| `dial.woken`                          | a dialer was set going before its delay, as `redial` does                                 |
| `ike.handshake.failed`                | the responder refused a handshake, as often as it logs one                                |
| `ike.kex.rejected`                    | a peer's ML-KEM key or ciphertext was refused                                             |
| `ike.followup.dropped`                | a peer's rekey was dropped before its last `IKE_FOLLOWUP_KE`                              |
| `ike.id.resolved`                     | a handshake took the peer's ID as naming the endpoint it authenticated as                 |
| `ike.session.established`, `.ended`   | a session started serving, and stopped                                                    |
| `ike.session.resolved`                | 2 sessions for 1 path were resolved to 1                                                  |
| `ike.session.revoked`                 | the trust in force refused a session's peer and closed it with a Delete                   |
| `ike.rekey.started`, `.completed`     | a rekey this end started, of the Child SA or of the IKE SA                                |
| `ike.rekey.failed`                    | the same rekey failing, with its error                                                    |
| `ike.sa.expired`                      | a Child SA reached its lifetime, and its keys left the dataplane                          |
| `ike.sa.closed`                       | a session decided to delete its IKE SA, and why                                           |
| `ike.suite.unlisted`                  | an SA runs a transform the lists left out, and its rekey or replacement                   |
| `ike.endpoint.moved`                  | a session moved to the addresses of its peer's latest fresh request or answer             |
| `ike.send.failed`, `.recovered`       | a session's sends to its peer began to fail, and one went out again                       |
| `ike.probe`                           | asked to prove its path, a session started a check or resent its request                  |
| `ike.notify.invalid_spi`              | a session told its peer of ESP on an SPI this node does not hold                          |
| `ike.message.fragmented`              | a session cut an IKE message into the fragments of RFC 7383                               |
| `babel.neighbor.up`, `.down`          | a neighbor's Hellos started arriving, or stopped or its session ended                     |
| `babel.neighbor.fragmented`           | a neighbor's first Babel packet in fragments was read whole, with its size                |
| `babel.request.sent`                  | this node asked a neighbor that came up for its whole table                               |
| `babel.neighbor.extra`                | a neighbor's `cost.extra` amount changed, as it joined or on a reload                     |
| `babel.config.applied`                | the speaker took a reloaded `cap.babel`, with its intervals and cost                      |
| `babel.own.changed`                   | the prefixes this node announces or the addresses `cap.table` assigns moved               |
| `babel.route.selected`, `.retracted`  | a prefix's next hop changed, every time rather than once a second as logged               |
| `babel.seqno.requested`               | a seqno request naming this node's own router id arrived                                  |
| `babel.seqno.raised`                  | this node's own seqno rose, at a start of the speaker or for a request                    |
| `babel.state.unsaved`, `.unreadable`  | a seqno limit could not be saved, or the state file not read at start                     |
| `kernel.pass`                         | a reconciler pass that took a reload, changed, skipped anew or failed                     |
| `kernel.cover`                        | a family's zero-free cover went into the kernel or came out, on macOS                     |
| `kernel.taken`                        | a reconciler lookup became taken or not, or a taken one changed its answer, on Linux      |
| `kernel.forward`                      | a link `cap.exit.forward` matched began or stopped being left out of the mode             |
| `kernel.exit`                         | under `cap.exit`, the tun came to hold no overlay address of a family, or the state ended |
| `kernel.fallback`                     | the kill switch began holding, passing or not holding, or ended                           |
| `egress.pass`                         | a translator pass that rewrote its rules, moved its prefixes or failed                    |
| `egress.ready`                        | the exit's readiness, its SIDs or its skipped lookups moved                               |
| `egress.refused`                      | a pass read a family's count of packets refused past a source's share move                |
| `border.pass`                         | a border filter pass that rewrote its chain or failed                                     |
| `border.ready`                        | the border filter's chain went ready or not ready, with `ready`                           |
| `border.dropped`                      | a pass read a drop counter that moved, at most once per pass                              |
| `network.changed`                     | the host's default, addresses or links moved, every session probed for the first two      |
| `transport.underlay.selected`         | a peer's datagrams named their first interface, or another one                            |
| `transport.endpoint.unpinned`         | sends to a peer left the address its datagram reached, gone or unroutable                 |
| `transport.endpoint.unsegmented`      | sends to a peer stopped segmenting, since its route refused a segment                     |
| `transport.pair.connected`, `.closed` | a busy peer got a socket connected to it, or that socket closed, with why                 |
| `pmtu.changed`                        | a session's path MTU budget moved, with the size before and the reason                    |
| `pmtu.floor`                          | a session's path went under 1280 bytes in one datagram, or came back                      |
| `pmtu.steering`                       | a session fell under what a steered 1280-byte packet needs, or rose back                  |
| `esp.ecn.unused`                      | a session's packets came in ECN pairs no tunnel sends, at most every 10 seconds           |
| `netstack.codel.dropping`             | a peer's sender began dropping for a queue delay above its target                         |
| `netstack.codel.drained`              | that peer's queue emptied, or its delay fell back below the target                        |
| `netstack.tun.refused`                | the tun handed over a frame that could not be read as packets                             |
| `netstack.tun.failed`                 | the tun went away under the running node, which then stops                                |
| `netstack.transit.dropped`            | the forwarding decision dropped a packet a session delivered, with why                    |
| `netstack.icmp.withheld`              | an ICMP rate limit withheld answers, at most once every 30 seconds per limit              |
| `netstack.answer.source`              | a router-id or the answer SID `debug pmtu` shows moved                                    |

`egress.pass`, `egress.ready`, `egress.refused` and the 3 `border` kinds are
recorded on Linux alone. `transport.endpoint.unsegmented` is recorded on Linux
and Android, which build the Linux sockets. `transport.underlay.selected` is
recorded on macOS alone, because only macOS names each underlay datagram's
interface, as [routing](../routing.md#the-underlays-interface-on-macos)
describes. `transport.endpoint.unpinned`, `transport.pair.connected` and
`transport.pair.closed` are recorded on Linux, macOS, iOS and Android, the
platforms that answer from the address a request reached and connect a socket to
1 busy peer, as [platforms](../platforms.md#sockets-connected-to-1-peer)
describes. `esp.ecn.unused` is recorded on the same 4, the platforms that read a
datagram's outer ECN field, and the same record is written at the debug level as
`esp packets arrived with an ecn combination no tunnel sends`, with the same
fields, as [ECN](../design/protocol-deviations.md#ecn) describes.

Each kind carries these attributes:

| Kind                                          | Attributes                                                                                                                                                                                      |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `daemon.started`                              | `version`, `config`                                                                                                                                                                             |
| `daemon.stopping`                             | none                                                                                                                                                                                            |
| `daemon.reload`                               | `path`, `applied`, `err`                                                                                                                                                                        |
| `daemon.ttl`                                  | `ttl`, the TTL the answers keep, and `err`                                                                                                                                                      |
| `node.down`                                   | `cause`, `since`, `closed`                                                                                                                                                                      |
| `node.up`                                     | `cause`                                                                                                                                                                                         |
| `responder.changed`                           | `listen`, `closed`                                                                                                                                                                              |
| `control.verb`                                | `verb`, `peer`, `uid`, `pid`, `err`, and `all` or `subsystem` for a verb that takes one                                                                                                         |
| `control.trace.started`                       | `filter`, `rate`, `payload`, `uid`, `pid`                                                                                                                                                       |
| `control.trace.ended`                         | `reason`, `recorded`, `refused_rate`, `refused_queue`                                                                                                                                           |
| `dial.attempt`                                | `remote`                                                                                                                                                                                        |
| `dial.failed`                                 | `err`                                                                                                                                                                                           |
| `dial.woken`                                  | none                                                                                                                                                                                            |
| `ike.handshake.failed`                        | `from`, `err`                                                                                                                                                                                   |
| `ike.kex.rejected`                            | `exchange`, `method`, `side`, and `from` at the answering end of a handshake                                                                                                                    |
| `ike.followup.dropped`                        | `sa`, which is `child` or `ike`, `reason`                                                                                                                                                       |
| `ike.id.resolved`                             | `type`, `id`, `sent`                                                                                                                                                                            |
| `ike.session.established`                     | `role`, `spi_in`, `spi_out`, `ike`, `esp`                                                                                                                                                       |
| `ike.session.ended`                           | `role`, `spi_in`, `spi_out`, `ike`, `esp`, `err`                                                                                                                                                |
| `ike.session.resolved`                        | `kept`                                                                                                                                                                                          |
| `ike.session.revoked`                         | `reason`, `peer`, `endpoint`, `err`                                                                                                                                                             |
| `ike.rekey.started`                           | `sa`, which is `child` or `ike`                                                                                                                                                                 |
| `ike.rekey.completed`                         | `sa`, which is `child` or `ike`, `suite`                                                                                                                                                        |
| `ike.rekey.failed`                            | `sa`, `err`                                                                                                                                                                                     |
| `ike.sa.expired`                              | `spi_in`, `spi_out`, and `sa`, which is always `child`                                                                                                                                          |
| `ike.sa.closed`                               | `sa`, which is `child` or `ike`, `reason`, `err`                                                                                                                                                |
| `ike.suite.unlisted`                          | `sa`, which is `child` or `ike`, `suite`, `action`                                                                                                                                              |
| `ike.endpoint.moved`                          | `endpoint`, `packet`, which is `request` or `response`                                                                                                                                          |
| `ike.send.failed`                             | `err`                                                                                                                                                                                           |
| `ike.send.recovered`                          | `failed`                                                                                                                                                                                        |
| `ike.probe`                                   | `action`, `message_id`                                                                                                                                                                          |
| `ike.notify.invalid_spi`                      | `spi`                                                                                                                                                                                           |
| `ike.message.fragmented`                      | `exchange`, `message_id`, `fragments`, `threshold`                                                                                                                                              |
| `babel.neighbor.up`, `.down`                  | none                                                                                                                                                                                            |
| `babel.neighbor.fragmented`                   | `size`                                                                                                                                                                                          |
| `babel.request.sent`                          | none                                                                                                                                                                                            |
| `babel.neighbor.extra`                        | `from`, `extra`                                                                                                                                                                                 |
| `babel.config.applied`                        | `hello`, `update`, `quality`, `rx`, `rtt_weight`, `rtt_min`, `rtt_max`                                                                                                                          |
| `babel.own.changed`                           | `set`, and `added`, `removed` and `held` where they name a route                                                                                                                                |
| `babel.route.selected`                        | `route`, `metric`                                                                                                                                                                               |
| `babel.route.retracted`                       | `route`                                                                                                                                                                                         |
| `babel.seqno.requested`                       | `route`, `asked`, `seqno`, `raised`                                                                                                                                                             |
| `babel.seqno.raised`                          | `cause`, `from`, `to`, `limit` where a state file is kept, and `router_id` at the process's start, with `drawn` where that router id is new                                                     |
| `babel.state.unsaved`                         | `limit`, `seqno`, `err`                                                                                                                                                                         |
| `babel.state.unreadable`                      | `file`, `err`                                                                                                                                                                                   |
| `kernel.pass`                                 | `trigger`, `took`, `added`, `removed`, `skipped`, `installed`, `err`                                                                                                                            |
| `kernel.cover`                                | `family`, `installed`                                                                                                                                                                           |
| `kernel.taken`                                | `family`, `lookup` (`overlay` or `underlay`), `prefix` and `address` for an overlay lookup or `endpoint` with `source` and `interface` where the send carries them, `answer`, `taken`           |
| `kernel.forward`                              | `entry`, `link`, `reason` (the tun, the loopback link, or the link a family's default leaves by), `skipped`                                                                                     |
| `kernel.exit`                                 | `family`, `addressed` (false where the family came to run mode off's rules, as [limits](../design/limits.md#routes-that-carry-the-hosts-own-traffic) says, and true where the state then ended) |
| `kernel.fallback`                             | `state` and `was`, each `holding`, `passing`, `not holding` or `off`                                                                                                                            |
| `egress.pass`                                 | `trigger`, `took`, `installed`, `announced`, `err`                                                                                                                                              |
| `egress.ready`                                | `ipv4`, `ipv6`, `sid`, `reason` (why a family is not ready), `skipped` (the lookups left out and why)                                                                                           |
| `egress.refused`                              | `family`, `refused` (the packets refused since the pass before, from zero after a pass that rewrote the chains)                                                                                 |
| `border.pass`                                 | `trigger`, `took`, `installed`, `err`                                                                                                                                                           |
| `border.ready`                                | `ready`                                                                                                                                                                                         |
| `border.dropped`                              | `overlay_source_ipv4`, `overlay_source_ipv6`, `routing_header`, `sid_destination`, each the packets since the pass before                                                                       |
| `network.changed`                             | `ipv4_default`, `ipv4_default_was`, `ipv4_added`, `ipv4_removed`, `ipv4_links_added`, `ipv4_links_removed`, `ipv4_links_changed`, the same 7 for `ipv6`, `probed`, `woken`                      |
| `transport.underlay.selected`                 | `endpoint`, `interface`, empty where no route holds the endpoint, `interface_index`, 0 then                                                                                                     |
| `transport.endpoint.unpinned`, `.unsegmented` | `endpoint`, `errno`                                                                                                                                                                             |
| `transport.pair.connected`                    | `local`, `remote`                                                                                                                                                                               |
| `transport.pair.closed`                       | `local`, `remote`, `reason`, and `err` when the reason is `failed`                                                                                                                              |
| `pmtu.changed`                                | `endpoint`, `budget`, `budget_was`, `reason`                                                                                                                                                    |
| `pmtu.floor`                                  | `endpoint`, `under`                                                                                                                                                                             |
| `pmtu.steering`                               | `budget`, `need`, `under`                                                                                                                                                                       |
| `esp.ecn.unused`                              | `outer`, `inner`, `count` (the packets since the session's last record), `header` (the first one's IP header in hex)                                                                            |
| `netstack.codel.dropping`, `.drained`         | `sojourn`, `target`                                                                                                                                                                             |
| `netstack.tun.refused`                        | `interface`, `frames`, `err`                                                                                                                                                                    |
| `netstack.tun.failed`                         | `interface`, `err`                                                                                                                                                                              |
| `netstack.transit.dropped`                    | `reason`, `src`, `dst`                                                                                                                                                                          |
| `netstack.icmp.withheld`                      | `interface`, `limit`, `withheld`                                                                                                                                                                |
| `netstack.answer.source`                      | `ipv4`, `ipv6`, `sid`, each only where the node holds it                                                                                                                                        |

`err` appears on `daemon.reload`, `control.verb`, `kernel.pass`, `egress.pass`
and `border.pass` only when the step failed, and on a `control.verb` under a
session the verb missed it is the reason the answer gives. The `trigger` of a
`kernel.pass` is `start`, `sweep`, `retry`, `grace`, `disable`, `enable`,
`reload`, `network` when the network watch delivered a change, `mesh` or
`kernel`. The `trigger` of an `egress.pass` is `start`, `sweep`, `retry`,
`disable`, `enable`, `changed` when another writer added, changed or deleted
part of its tables, or `missed` when the daemon lost nf_tables notifications to
an overflow or could not read one, whoever's tables they were about. The
`trigger` of a `border.pass` is `start`, `sweep`, `retry`, `reload`, `changed`
when another writer added, changed or deleted part of its table, or `missed` as
for an `egress.pass`.

An `ike.sa.expired` is recorded for the current Child SA and for a replaced one
still waiting for its Delete, with both SPIs in hexadecimal. The `reason` of an
`ike.sa.closed` is `lifetime` when the SA named by `sa` reached its lifetime
with no rekey replacing it, `sequence space` when the Child SA ran out of
sequence numbers with none replacing it, `temporary failure` when the peer had
answered this end's rekeys with `TEMPORARY_FAILURE` for 5 minutes with no rekey
of the IKE SA or the Child SA completed by either end in between,
`invalid syntax` when the peer answered a request of this end's on the current
IKE SA with `INVALID_SYNTAX`, which ends it without a Delete, `fragment limit`
when the peer's fragments of 1 message passed the reassembly limit
[limits](../design/limits.md#ike) gives, which ends it without a Delete too, and
`local failure` when this node failed on its own side, as when its dataplane
refused a change to a Child SA. An IKE SA rekey of this node's that runs
`IKE_FOLLOWUP_KE` adds 3 more: `rekey answer refused` when this node refused the
peer's answer that selected an additional key exchange or carried its link, or
when an `IKE_FOLLOWUP_KE` response linked no next exchange the rekey still
needs, `kex rejected` when the peer's ML-KEM ciphertext was refused, and
`state not found` when 3 rekeys in a row drew `STATE_NOT_FOUND`. Each closes the
IKE SA with a Delete. `err` says what ended it, and the `ike.session.ended` that
follows carries it as well. An `INVALID_SYNTAX` this end sends on the current
IKE SA records no `ike.sa.closed`: the session logs a warning and ends with
`ike.session.ended`.

The `ike` of an `ike.session.established` names the IKE SA's cipher, PRF and kex
entry by their `cap.crypto` names, joined by `/`, such as
`aes256gcm/sha384/x25519`, or `aes256gcm/sha384/x25519+mlkem768` for an IKE SA
whose keys came from X25519 and ML-KEM-768, and its `esp` names the Child SA's
cipher, such as `aes256gcm`. The `ike.session.ended` that follows carries the
same 2, the transforms the session started with. The `suite` of an
`ike.rekey.completed` names the replacement's transforms the same way, the IKE
SA's for `sa=ike` and the Child SA's for `sa=child`. A Child SA rekey this node
starts runs no key exchange, so the `suite` of `sa=child` is the cipher alone. A
peer's rekey records no `ike.rekey.completed`. A Child SA the peer's creation or
rekey keyed with key exchanges of its own has their kex entry after its cipher,
such as `aes128gcm/p256` or `aes128gcm/x25519+mlkem768`, in the `suite` of an
`ike.suite.unlisted`. Where the peer refuses this node's IKE SA rekey with an
error notify after this node answered the peer's own rekey of the same SA, its
last `IKE_FOLLOWUP_KE` included where it ran any, this node takes the SA the
peer's rekey made, and the `ike.rekey.completed` names that SA. Every error
notify does so but `INVALID_SYNTAX`, which ends the IKE SA, and an
`INVALID_KE_PAYLOAD` naming a group this node offered is retried once in that
group first. A refusal that comes while the peer's rekey still runs its
`IKE_FOLLOWUP_KE` records `ike.rekey.failed`, and the last of those exchanges
then makes the peer's SA current with no `ike.rekey.completed`, since a peer's
rekey records none. An IKE SA rekey whose Delete of the replaced or redundant
IKE SA goes unanswered or is refused records `ike.rekey.completed`, since the
surviving IKE SA is current by then. The session logs
`ike replaced IKE SA was not deleted by this end` or
`ike redundant IKE SA was not deleted by this end` with the error.

An `ike.suite.unlisted` is recorded when a session schedules a rekey or a
replacement for an SA running a transform the lists in force leave out. An SA
whose rekey is already running, due, scheduled this way or backing off from a
failure records none. The event's `sa` names the SA, its `suite` the transforms
that SA runs, named as above, and its `action` what the session does about it:
`rekey` for a rekey under the lists, or `replace` when the lists left out the
IKE SA's PRF, which no rekey changes, so the session deletes the IKE SA for a
new handshake, as [reloading](../reloading.md#capcrypto) describes.

An `ike.kex.rejected` is recorded when this node refuses the peer's side of an
ML-KEM key exchange. Its `exchange` is `IKE_INTERMEDIATE` in a handshake and
`IKE_FOLLOWUP_KE` after a `CREATE_CHILD_SA`, its `method` the ML-KEM method by
its `cap.crypto` name, `mlkem768` or `mlkem1024`, and its `side` what was
refused. `side=key` names the encapsulation key of the peer that sent the
request, which the check of FIPS 203 section 7.2 refused, and the answer is
`INVALID_SYNTAX`. In a handshake the answer ends the handshake, and the event
carries the source in `from`. It is recorded beside the `ike.handshake.failed`
that follows and as often as that one, since anyone past `IKE_SA_INIT` can send
such a key. In an `IKE_FOLLOWUP_KE` the `INVALID_SYNTAX` ends the IKE SA without
a Delete. `side=ciphertext` names the ciphertext of the peer that answered,
which the check of section 7.3 refused, or a response whose KE payload is
missing, appears twice or names another method. A dial then ends without
`IKE_AUTH`, and an IKE SA rekey ends the IKE SA with a Delete and records
`ike.sa.closed` with the reason `kex rejected`.

An `ike.followup.dropped` is recorded once for each rekey of the peer's that
this node drops before its last `IKE_FOLLOWUP_KE`. Its `sa` names the SA the
rekey would have made. Its `reason` is `expired` when the peer's next
`IKE_FOLLOWUP_KE` did not come within the wait [limits](../design/limits.md#ike)
gives, and `superseded` when a new rekey of the peer's replaced it, the IKE SA
it ran on was replaced, or this node's own rekey won a simultaneous rekey
against it. The peer's next `IKE_FOLLOWUP_KE` for a dropped rekey is answered
`STATE_NOT_FOUND`, or `TEMPORARY_FAILURE` where that exchange is the one that
found this node's own rekey had won.

An `ike.message.fragmented` is recorded each time a session cuts an IKE message
into fragments, a request cut again for a smaller threshold included, as
[limits](../design/limits.md#paths-under-1280-bytes) describes. Its `exchange`
names the exchange, such as `IKE_INTERMEDIATE` or `IKE_FOLLOWUP_KE`, as in
`ike.kex.rejected`, its `message_id` the message, its `fragments` their count
and its `threshold` the largest IP datagram they were cut to fit. A half-open SA
has no recorder, so the answers of a responder's handshake record none. The
session also logs `ike sending a message in fragments` and
`ike reassembled a message from fragments` at debug level, each with the
exchange, the Message ID and the fragments,
`ike dropped the fragments of a message the peer left incomplete` at info level,
and
`ike the peer's fragments of one message passed the reassembly limit, which ends the IKE SA`
as a warning.

An `ike.notify.invalid_spi` is recorded each time a session sends its peer an
`INFORMATIONAL` request carrying `INVALID_SPI`, for ESP from the peer's address
and port on an SPI this node does not hold. Its `spi` is that SPI in
hexadecimal, as `ike.sa.expired` names SPIs. The node looks for such a session
at most once every 10 seconds, whoever sent the ESP, and an SPI this node let go
of in the 10 seconds before draws none, as
[protocol deviations](../design/protocol-deviations.md#errors-outside-an-exchange)
describes. `ranet3 sessions` counts the requests each session sent. A peer's
`INVALID_SPI` records nothing: the session logs
`ike the peer received ESP on an SPI it holds no Child SA for` at debug level
with the SPI it names.

A `transport.pair.connected` names in `local` the address the socket bound and
in `remote` the peer it is connected to. The `reason` of a
`transport.pair.closed` is `idle` for a socket that carried nothing for a whole
sweep, `released` once the last session sending on it ended or moved, on macOS
to another interface the selection named among them, `network` for a move of the
host's default or one of its addresses, `failed` for a send or a read on it that
failed, and `closed` when the transport closed. Neither an ICMP error an earlier
datagram drew nor a refusal of the socket's segments counts as `failed`, as
[platforms](../platforms.md#sockets-connected-to-1-peer) describes. Each
`failed` also counts in `ranet3_transport_pair_fallbacks_total`, and
`ranet3_transport_pair_sockets` counts the sockets open, as
[metrics](../metrics.md) lists.

A move of the host's default or one of its addresses also wakes every dialer,
and a change of links alone wakes none and probes no session. A
`network.changed` names only what moved. `ipv4_default` and `ipv4_default_was`
hold the new IPv4 default and the one before it. `ipv4_added` and `ipv4_removed`
hold the IPv4 addresses that came and went. `ipv4_links_added` and
`ipv4_links_removed` name the links outside the mesh that came and went, and
`ipv4_links_changed` those whose prefixes or far ends moved, which
`debug netmon` lists in full. The `ipv6` attributes do the same for IPv6.
`probed` counts the sessions asked to probe, and `woken` counts the dialers
woken.

A `daemon.reload` names in `applied` the capabilities the reload changed in
place, and carries none when it changed only the trust document or the peers
dialed. A `babel.config.applied` carries the `hello` and `update` intervals, the
`quality` and the `rx` and `rtt_weight`, `rtt_min` and `rtt_max` cost the
speaker now runs, and a `responder.changed` carries `listen` and, in `closed`,
how many sessions this node had answered and closed with a Delete. A
`kernel.pass` names what woke the reconciler in `trigger`, and the pass a reload
causes reads `trigger=reload` and is recorded whether or not it moved anything.
A reconciler stopped with `disable` runs no pass when it takes a reload, and the
pass that installs the block once it is enabled again reads `trigger=enable`.
The same holds for a reconciler `ranet3 down` stopped, until `ranet3 up`. The
withdrawal such a stop runs records a `kernel.pass` only when it fails, and no
`kernel.cover` for the cover it takes out. It records a `kernel.taken` with
`taken=false` for each lookup the reconciler last found taken.

A `daemon.ttl` is recorded when a reload cannot read the host's default TTL,
`net.ipv4.ip_default_ttl` on Linux or `net.inet.ip.ttl` on macOS. Its `ttl` is
the TTL the node's ICMPv4 answers keep, and its `err` names the setting and why
the read failed. The reload applies the rest of the file, as
[path MTU](../path-mtu.md#packets-that-do-not-fit) describes.

A `node.down` carries its `cause`, `request` for `ranet3 down` and `flag` for a
daemon that found the flag when it started, and in `since` the moment the flag
holds. One a request caused carries in `closed` how many sessions it closed with
a Delete, and a `node.up` carries `cause=request`.

A `control.verb` carries the caller's uid and pid, and in its `peer` attribute
the peer as the verb named it, when it named one. The event's peer is the path
of the session or dialer it was recorded under, which `--peer` takes by any name
of that peer. A verb is recorded under each path its answer lists in `acted` or
`missed`, and one that lists none, a refused one included, is recorded once
without a peer.

A `control.trace.started` and a `control.trace.ended` record who read the
packets the node handles. The first carries the trace's `filter` as one line,
such as `dst=192.0.2.3/32 decision=forward`, or `all`, its `rate` and the
`payload` bytes it asked for, and the caller's `uid` and `pid`. The second
carries in `reason` why the trace closed, `the reader left`,
`the reader stopped reading` or `the daemon is stopping`, in `recorded` the
records its queue took, and in `refused_rate` and `refused_queue` the records
the rate and the queue refused.

A `babel.own.changed` is recorded once for each change to the routes this node
owns, at the start, on a reload and when `cap.egress` moves what the node
announces. Its `set` is `originated` for the prefixes it announces and
`assigned` for the host routes of the addresses `cap.table` assigns it. `added`
and `removed` name the routes that joined the set and left it, and `held` the
ones among those that left which the node now holds unreachable, as
[routing](../routing.md#retracted-routes) describes. Each names its routes in
order, separated by commas, with a source prefix after `from`. A change that
leaves the set as it was records none.

A `babel.request.sent` is recorded when the node decides to send the request,
and a send queue with no room can still refuse it, which
`ranet3_peer_send_dropped_total` counts.

A `babel.neighbor.fragmented` is recorded once for each session, when the
speaker first reads a Babel packet its neighbor's stack cut into fragments, and
carries in `size` that packet's length once whole, its IPv6 header included.
`ranet3_babel_reassembled_total` counts every such packet and
`ranet3_babel_reassembly_dropped_total` the datagrams dropped and why, as
[the metrics](../metrics.md) describe.

A `pmtu.changed` carries the session's `endpoint`, its `budget` and the
`budget_was` before it, and in `reason` what moved it: `probe` for an answered
or lost probe, `route` for the route read again, `refusal` for a send the host
refused as too large, `endpoint change` for a session that moved, `floor` for a
path under 1280 bytes and `link.mtu` for a reload. The first budget a session
starts at records none. A `pmtu.floor` carries the `endpoint` and `under`, true
when the session's datagrams began to leave in fragments and false when they
stopped. `debug pmtu` shows the last change of the session running now, and none
of a session it replaced on the same path. A `pmtu.steering` carries the
session's `budget`, in `need` what a 1280-byte packet behind the longest segment
list takes, and `under`, true when the budget fell under that and false when it
rose back, as [segment routing](../segment-routing.md) describes.

A `babel.seqno.requested` names the neighbor that sent the request as its peer
and carries the `route` asked about, the seqno it `asked` for, the node's own
`seqno` when it arrived and whether it `raised` that seqno. A request raises it
only where it asks past the seqno of a prefix this node originates, and at most
once per packet. A `babel.seqno.raised` carries its `cause`, `start` or
`request`, the seqno it went `from` and `to`, and where a state file is kept the
seqno `limit` the speaker last saved, which a restart starts past. The raise a
process makes as it starts carries the `router_id` as well, and `drawn` where
that router id is a new one, saying why: `no state file`,
`the state file names example/alpha` for a file another node wrote, or
`the state file is unreadable`. The run of the speaker after `ranet3 up` makes a
raise with `cause=start` of its own. A `babel.state.unsaved` carries the `limit`
the speaker could not save, the `seqno` in use and the `err`, and the seqno
rises all the same. A `babel.state.unreadable` carries the state `file` and the
`err`, and the node starts under a new router id from seqno 1.

An `ike.id.resolved` is recorded by each end of a handshake under the session's
path, once that end has verified the peer's AUTH and taken its ID, so it is
recorded even where the Child SA is then refused. Its `type` is the type of the
ID the peer sent: `dn`, `ipv4`, `ipv6`, `fqdn`, `email` or `keyid`. `id` holds
that ID, an address, a name or a key ID in hex, and is left out for a DN. `sent`
is the type of the ID this end sent. A strongSwan peer that `auth.aliases` names
by an FQDN reads, for instance, `type=fqdn id=gw.example.net sent=fqdn`, as
[the trust document](../trust.md#ids-on-the-wire) describes.

An `ike.session.revoked` is recorded under the session's path before the session
closes, so it comes before that session's `ike.session.ended`. Its `reason` is
`handshake` where a handshake finished under a trust that no longer admits its
peer, or `reload` where a reload's sweep closed a live session. It carries the
`peer`, the endpoint the peer authenticated as, such as `example/gateway:1`, the
`endpoint` address the session sends to, such as `198.51.100.7:13000`, and the
trust's refusal as `err`, such as
`the trust document holds another key for example/gateway` when the
organization's key changed.

An `ike.endpoint.moved` is recorded when an established session takes a fresh
message, as
[endpoint updates](../design/protocol-deviations.md#endpoint-updates) gives,
that comes from another peer address or port, or, in a session the peer opened,
reaches this node at an address other than the one the session's sends name. Its
`packet` is `request` or `response`. In a session that names an interface, as it
does on Linux and for an IPv6 link-local address on macOS, a fresh message
arriving on another interface records it too. Its `endpoint` names the peer's
address and port, which in these two cases can be the same as before. A session
whose sends fell back from an address that is gone names no address, and its
next fresh message records an `ike.endpoint.moved` wherever it arrives. A
session that fell back after the kernel refused its address with `EHOSTUNREACH`
moves back to it, recording an `ike.endpoint.moved`, only at the first fresh
message 1 minute or more after the fallback, and one that fell back after any
other refusal at its next fresh message that reaches the address, as
[moving hosts](../platforms.md#moving-hosts) describes.

A `transport.endpoint` event carries the peer's `endpoint` and the `errno` the
kernel refused the send with. An `unpinned` event is recorded once for an
endpoint, at its first fallback. Every answer is sent to its request's own
endpoint. While the kernel refuses sends from a session's address, each answer
to a request that reaches the address therefore records an `unpinned` event, and
a fresh request or answer that moves the session back to the address records one
at its first fallback after the move, at most one every minute after
`EHOSTUNREACH`. An `unsegmented` one is recorded each time segmentation stops,
which for a route that keeps refusing segments is at most once every 10 minutes.
A send refused only for its size records none, since it lowers that session's
budget instead. On a socket that fragments, a segmented message refused with
`EMSGSIZE` twice in a row records an `unsegmented` one with that `errno`, as
[platforms](../platforms.md#path-mtu) describes. An `ike.send.failed` carries
the error of the first send that failed, and its `ike.send.recovered` how many
failed before one went out. A reply to a retransmitted request counts toward
neither, since a replay can come from any address.

A `netstack.codel` event carries the `sojourn` of the batch that changed the
state, how long that batch had waited since it was reserved, and the `target`. A
`drained` recorded because the queue emptied carries a `sojourn` of 0. The
sender drops 1 packet at a time on its own schedule and records no event per
packet, so `ranet3_peer_send_delay_dropped_total` is where the drops are
counted.

A `netstack.tun.refused` is recorded at most once every 30 seconds, as is its
warning in the log, and its `frames` is how many frames were refused since the
one before. `err` is why the last of them was refused.
`ranet3_tun_frames_refused_total` counts every one, as
[metrics](../metrics.md#tun-reads) describes. Only a tun on Linux refuses a
frame, so the event is recorded there alone. A `netstack.tun.failed` is recorded
once, before the node starts the shutdown it ends with, and `err` is the error
the read returned. On Linux, a tun whose link was deleted reads
`file already closed`.

A `netstack.transit.dropped` is recorded at most once every 30 seconds, as is
its warning in the log, for the packet that dropped first in that time. `reason`
is the `reason` label of `ranet3_transit_packets_total`, which counts every
drop, as [metrics](../metrics.md#transit-counters) describes. `src` and `dst`
read `invalid IP` for a frame that holds no whole IP packet.

A `netstack.icmp.withheld` is recorded when one of the
[ICMP rate limits](../path-mtu.md#packets-that-do-not-fit) withholds an answer
and that limit recorded none in the 30 seconds before, so a limit that starts
withholding is recorded at once and one that goes on withholding once every 30
seconds. Each limit is recorded apart from the other. `limit` names it as the
metric's label does, `source` for the buckets of the sources answered or `node`
for the node's cap, and `withheld` is how many answers it withheld since its
last event, this one included. `ranet3_icmp_withheld_total` counts every one.

A `netstack.answer.source` is recorded at start where the node holds a router-id
or a SID, and again each time a reload moves one. Its `ipv4` and `ipv6` are the
router-id of each family and its `sid` the answer SID, as
[path MTU](../path-mtu.md#where-answers-come-from) describes. An attribute is
left out where the node holds no such address.

## Adding a view

A view is 3 new files, and no file of the tree needs an edit for it:

- `control/debug_<view>.go` holds the wire types, the interface the daemon
  implements, the path registered from `init` with its class, the text renderer
  and the client method. `debugRead` registers a snapshot. `registerDebug`
  registers a view that takes a query or acts, as `pmtu` and `probe` do.
- `internal/client/debug_<view>.go` implements that interface on the daemon's
  side.
- `cmd/ranet3/debug_<view>.go` appends the command to `debugCommands` from
  `init`, with a completion for each of its arguments and flags.

Each renderer and wire form has a golden file under `control/testdata/debug`,
which `go test ./control -update` rewrites. A renderer prints the ages the
daemon computed rather than reading the clock, so its output is the same on
every run. The check that no debug answer has room for key material, and the
property that every wire type survives a trip through JSON, walk each registered
path's type without being told about a new one.
