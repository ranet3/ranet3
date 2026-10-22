---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Debugging a running node"
description: "The debug tree: who may call it, what it promises, its commands and how a view is added."
created: 2026-10-04
updated: 2026-10-25
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

The daemon serves 7 debug paths:

| Path                | Class | Commands                     |
| ------------------- | ----- | ---------------------------- |
| `/v0/debug/events`  | read  | `debug events`, `debug wait` |
| `/v0/debug/netmon`  | read  | `debug netmon`               |
| `/v0/debug/pmtu`    | read  | `debug pmtu`                 |
| `/v0/debug/probe`   | root  | `debug probe`                |
| `/v0/debug/rules`   | read  | `debug rules`                |
| `/v0/debug/runtime` | read  | `debug runtime`              |
| `/v0/debug/updown`  | read  | `debug updown`               |

Profiles are not a debug path. The daemon's `--pprof` serves them on an address
of its own, and no class covers that address.

The daemon's `--debug-access` sets how far the root class reaches. `root` is the
default. `group` opens the root class to everyone who can open the socket, and
`off` refuses every debug path, the read class included. The modules carry no
option of their own for it: `extraArgs` passes the flag. A connection whose
caller the kernel does not name, which is every platform but Linux and macOS,
reaches the read class alone under `root` and `group`, and nothing under `off`.

A debug request the daemon does not answer with 200 gets one of these statuses:

| Status | When                                                                                                                         |
| ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| 400    | an events query or an action body that does not parse, or an action the node refuses, such as `debug probe` while it is down |
| 403    | the class refuses the caller, and the answer names the rule and the caller's uid or the missing credentials                  |
| 404    | no debug path has that name, except under `off`, which answers 403                                                           |
| 405    | a read sent with a method other than GET or HEAD, or an action sent with one other than POST                                 |
| 501    | the server behind the socket does not implement the view, and the answer names it. The `ranet3` daemon implements every view |
| 503    | the daemon already holds 4 streams                                                                                           |

On a NixOS host the unit runs the daemon as root, so the root class means
`sudo`. In an `unshare -rn` lab the caller already reads as uid 0.

## Commands

Every command in the tree takes these 2 flags:

| Flag        | Default                        | What it sets                        |
| ----------- | ------------------------------ | ----------------------------------- |
| `--control` | `/var/run/ranet3/control.sock` | the control socket to ask           |
| `--json`    | off                            | print the wire form instead of text |

These commands take flags of their own:

| Command        | Flag             | Default              | What it sets                                                  |
| -------------- | ---------------- | -------------------- | ------------------------------------------------------------- |
| `debug socket` | `--timeout`      | 10 seconds           | how long the whole exchange may take, a stream included       |
| `debug probe`  | `--all`          | off                  | probe every session instead of one peer's                     |
| `debug events` | `-f`, `--follow` | off                  | print later events as they come                               |
| `debug events` | `--for`          | 30 seconds           | how long `-f` follows                                         |
| `debug events` | `--kind`         | every kind           | a kind, or the part of one before a dot, given up to 16 times |
| `debug events` | `--peer`         | every peer           | one peer, named as `redial` names one                         |
| `debug events` | `--since`        | every recorded event | how recent a recorded event must be                           |
| `debug wait`   | `--attr`         | none                 | a `key=value` the event must carry, given up to 16 times      |
| `debug wait`   | `--past`         | 0                    | how recent a recorded event may be and still end the wait     |
| `debug wait`   | `--peer`         | every peer           | one peer, named as `redial` names one                         |
| `debug wait`   | `--timeout`      | 10 seconds           | how long to wait                                              |

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
  uptime, and the resolver a lookup can reach. `cgo` there means a lookup may go
  to the C library, which holds an OS thread for as long as it takes. The view
  is read without stopping the daemon's goroutines, so polling it leaves the
  data path running. It also shows the memory taken from the system, the total
  pause of the collector, and whether the build's tree had uncommitted changes.
- `debug buildinfo` prints this binary's own Go build information.
- `debug netmon` is the host's network as the node's watch last read it: for
  each family the default route, its interface and gateway, and the global
  unicast addresses of the interfaces that are up, the mesh's own device left
  out, then the last change the watch acted on and what moved in it. A platform
  without a watch says so. Linux and macOS have a watch.
- `debug rules` is every policy rule the kernel holds, whoever wrote it, in a
  table per family with its priority, its selectors, the table it reads or its
  action, and its owner: `ranet3` for a rule carrying `cap.table.proto`,
  `kernel` for the kernel's own, and the protocol number for anybody else's.
  Then the rules `cap.table` asks for that the kernel does not hold, and on a
  node with `cap.border` the border filter's chain: its table and hook, when its
  last pass read it and whether it is ready, then each rule with the packets and
  bytes each drop counted, any rule the chain does not hold yet, and any rule it
  holds that the filter did not write, by its comment or as
  `a rule with no comment`. The dump and the chain are each read now through a
  socket of their own, so an operator who sends a test packet reads the counters
  of that moment, and neither the reconciler's socket nor the filter's serves a
  reader. A platform with no policy rules says so.
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
  and as neither acked nor lost. A refusal, the route read lower after a network
  change or `debug probe`, a change of `link.mtu` and a move to another endpoint
  can each move the target. A probe answered after its wait ran out counts as
  both acked and lost, so the 3 counts need not add up.
  `ranet3_pmtu_probes_total` counts acked and lost probes the same way and has
  no series for probes sent. The peer is named as `rekey` names one, and
  completes to the nodes of the sessions the daemon holds. The command fails for
  a peer the node holds no session with.
- `debug probe <peer>` and `debug probe --all` ask the sessions of one peer, or
  every session, to send a liveness check now and to probe their path MTU
  budget, as each does after a network change, and name the sessions asked. A
  session with a request outstanding resends that request instead. One with none
  sends no liveness check while its IKE SA is past its lifetime or a Delete of
  it has gone out, or while a rekey of its own may run `IKE_FOLLOWUP_KE`
  exchanges or waits on the peer's. It is an action, so it takes the root class,
  and it is recorded as a `control.verb` like the other verbs. It completes to
  the peers the node dials and the nodes it holds a session with. The daemon
  refuses it while the node is down, and when no session matches.
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

| Kind                                  | When                                                                         |
| ------------------------------------- | ---------------------------------------------------------------------------- |
| `daemon.started`, `daemon.stopping`   | the node is up, and its shutdown has begun                                   |
| `daemon.reload`                       | the file and trust document were read again, with what applied or the error  |
| `daemon.ttl`                          | a reload could not read the host's default TTL, which ICMPv4 answers carry   |
| `node.down`, `node.up`                | the node went off the mesh or came back, by a request or from its flag       |
| `responder.changed`                   | a reload turned `link.listen` on or off, with the answered sessions closed   |
| `control.verb`                        | a verb over the socket, under each session or dialer it acted on or missed   |
| `dial.attempt`, `dial.failed`         | a dialer sent a handshake, or ended short of a session                       |
| `dial.woken`                          | a dialer was set going before its delay, as `redial` does                    |
| `ike.handshake.failed`                | the responder refused a handshake, as often as it logs one                   |
| `ike.kex.rejected`                    | a peer's ML-KEM key or ciphertext was refused                                |
| `ike.followup.dropped`                | a peer's rekey was dropped before its last `IKE_FOLLOWUP_KE`                 |
| `ike.id.resolved`                     | a handshake took the peer's ID as naming the endpoint it authenticated as    |
| `ike.session.established`, `.ended`   | a session started serving, and stopped                                       |
| `ike.session.resolved`                | 2 sessions for 1 path were resolved to 1                                     |
| `ike.session.revoked`                 | the trust in force refused a session's peer and closed it with a Delete      |
| `ike.rekey.started`, `.completed`     | a rekey this end started, of the Child SA or of the IKE SA                   |
| `ike.rekey.failed`                    | the same rekey failing, with its error                                       |
| `ike.sa.expired`                      | a Child SA reached its lifetime, and its keys left the dataplane             |
| `ike.sa.closed`                       | a session decided to delete its IKE SA, and why                              |
| `ike.suite.unlisted`                  | an SA runs a transform the lists left out, and its rekey or replacement      |
| `ike.endpoint.moved`                  | a session moved to the addresses of its peer's latest fresh request          |
| `ike.send.failed`, `.recovered`       | a session's sends to its peer began to fail, and one went out again          |
| `ike.probe`                           | asked to prove its path, a session started a check or resent its request     |
| `ike.message.fragmented`              | a session cut an IKE message into the fragments of RFC 7383                  |
| `babel.neighbor.up`, `.down`          | a neighbor's Hellos started arriving, or stopped or its session ended        |
| `babel.neighbor.fragmented`           | a neighbor's first Babel packet in fragments was read whole, with its size   |
| `babel.request.sent`                  | this node asked a neighbor that came up for its whole table                  |
| `babel.neighbor.extra`                | a neighbor's `cost.extra` amount changed, as it joined or on a reload        |
| `babel.config.applied`                | the speaker took a reloaded `cap.babel`, with its intervals and cost         |
| `babel.own.changed`                   | the prefixes this node announces or the addresses `cap.table` assigns moved  |
| `babel.route.selected`, `.retracted`  | a prefix's next hop changed, every time rather than once a second as logged  |
| `babel.seqno.requested`               | a seqno request naming this node's own router id arrived                     |
| `babel.seqno.raised`                  | this node's own seqno rose, at a start of the speaker or for a request       |
| `babel.state.unsaved`, `.unreadable`  | a seqno limit could not be saved, or the state file not read at start        |
| `kernel.pass`                         | a reconciler pass that took a reload, changed, skipped anew or failed        |
| `kernel.cover`                        | a family's zero-free cover went into the kernel or came out, on macOS        |
| `egress.pass`                         | a translator pass that rewrote its rules, moved its prefixes or failed       |
| `egress.ready`                        | the egress device's readiness or its SIDs moved, with `ipv4`, `ipv6`, `sid`  |
| `egress.device`                       | the egress device was created or withdrawn, with `name` and `action`         |
| `border.pass`                         | a border filter pass that rewrote its chain or failed                        |
| `border.ready`                        | the border filter's chain went ready or not ready, with `ready`              |
| `border.dropped`                      | a pass read a drop counter that moved, at most once per pass                 |
| `network.changed`                     | the host's default or addresses moved, so every session was probed           |
| `transport.underlay.bound`            | the underlay socket moved onto another interface                             |
| `transport.endpoint.unpinned`         | sends to a peer left the address its datagram reached, gone or unroutable    |
| `transport.endpoint.unsegmented`      | sends to a peer stopped segmenting, since its route refused a segment        |
| `transport.pair.connected`, `.closed` | a busy peer got a socket connected to it, or that socket closed, with why    |
| `pmtu.changed`                        | a session's path MTU budget moved, with the size before and the reason       |
| `pmtu.floor`                          | a session's path went under 1280 bytes in one datagram, or came back         |
| `pmtu.steering`                       | a session fell under what a steered 1280-byte packet needs, or rose back     |
| `netstack.codel.dropping`             | a peer's sender began dropping for a queue delay above its target            |
| `netstack.codel.drained`              | that peer's queue emptied, or its delay fell back below the target           |
| `netstack.tun.refused`                | the tun handed over a frame that could not be read as packets                |
| `netstack.tun.failed`                 | the tun went away under the running node, which then stops                   |
| `netstack.transit.dropped`            | the forwarding decision dropped a packet a session delivered, with why       |
| `netstack.icmp.withheld`              | an ICMP rate limit withheld answers, at most once every 30 seconds per limit |
| `netstack.answer.source`              | a router-id or the answer SID `debug pmtu` shows moved                       |

`egress.pass`, `egress.ready`, `egress.device`, the 3 `border` kinds and
`transport.endpoint.unsegmented` are recorded on Linux alone, and
`transport.endpoint.unpinned` on Linux and macOS alone, the platforms that
answer from the address a request reached. `transport.underlay.bound` is
recorded on macOS alone, because only macOS binds the underlay socket to an
interface. `transport.pair.connected` and `transport.pair.closed` are recorded
on Linux and macOS alone, the platforms that connect a socket to 1 busy peer, as
[platforms](../platforms.md#sockets-connected-to-1-peer) describes.

Each kind carries these attributes:

| Kind                                          | Attributes                                                                                                                                  |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `daemon.started`                              | `version`, `config`                                                                                                                         |
| `daemon.stopping`                             | none                                                                                                                                        |
| `daemon.reload`                               | `path`, `applied`, `err`                                                                                                                    |
| `daemon.ttl`                                  | `ttl`, the TTL the answers keep, and `err`                                                                                                  |
| `node.down`                                   | `cause`, `since`, `closed`                                                                                                                  |
| `node.up`                                     | `cause`                                                                                                                                     |
| `responder.changed`                           | `listen`, `closed`                                                                                                                          |
| `control.verb`                                | `verb`, `peer`, `uid`, `pid`, `err`, and `all` or `subsystem` for a verb that takes one                                                     |
| `dial.attempt`                                | `remote`                                                                                                                                    |
| `dial.failed`                                 | `err`                                                                                                                                       |
| `dial.woken`                                  | none                                                                                                                                        |
| `ike.handshake.failed`                        | `from`, `err`                                                                                                                               |
| `ike.kex.rejected`                            | `exchange`, `method`, `side`, and `from` at the answering end of a handshake                                                                |
| `ike.followup.dropped`                        | `sa`, which is `child` or `ike`, `reason`                                                                                                   |
| `ike.id.resolved`                             | `type`, `id`, `sent`                                                                                                                        |
| `ike.session.established`                     | `role`, `spi_in`, `spi_out`, `ike`, `esp`                                                                                                   |
| `ike.session.ended`                           | `role`, `spi_in`, `spi_out`, `ike`, `esp`, `err`                                                                                            |
| `ike.session.resolved`                        | `kept`                                                                                                                                      |
| `ike.session.revoked`                         | `reason`, `peer`, `endpoint`, `err`                                                                                                         |
| `ike.rekey.started`                           | `sa`, which is `child` or `ike`                                                                                                             |
| `ike.rekey.completed`                         | `sa`, which is `child` or `ike`, `suite`                                                                                                    |
| `ike.rekey.failed`                            | `sa`, `err`                                                                                                                                 |
| `ike.sa.expired`                              | `spi_in`, `spi_out`, and `sa`, which is always `child`                                                                                      |
| `ike.sa.closed`                               | `sa`, which is `child` or `ike`, `reason`, `err`                                                                                            |
| `ike.suite.unlisted`                          | `sa`, which is `child` or `ike`, `suite`, `action`                                                                                          |
| `ike.endpoint.moved`                          | `endpoint`                                                                                                                                  |
| `ike.send.failed`                             | `err`                                                                                                                                       |
| `ike.send.recovered`                          | `failed`                                                                                                                                    |
| `ike.probe`                                   | `action`, `message_id`                                                                                                                      |
| `ike.message.fragmented`                      | `exchange`, `message_id`, `fragments`, `threshold`                                                                                          |
| `babel.neighbor.up`, `.down`                  | none                                                                                                                                        |
| `babel.neighbor.fragmented`                   | `size`                                                                                                                                      |
| `babel.request.sent`                          | none                                                                                                                                        |
| `babel.neighbor.extra`                        | `from`, `extra`                                                                                                                             |
| `babel.config.applied`                        | `hello`, `update`, `quality`, `rx`, `rtt_weight`, `rtt_min`, `rtt_max`                                                                      |
| `babel.own.changed`                           | `set`, and `added`, `removed` and `held` where they name a route                                                                            |
| `babel.route.selected`                        | `route`, `metric`                                                                                                                           |
| `babel.route.retracted`                       | `route`                                                                                                                                     |
| `babel.seqno.requested`                       | `route`, `asked`, `seqno`, `raised`                                                                                                         |
| `babel.seqno.raised`                          | `cause`, `from`, `to`, `limit` where a state file is kept, and `router_id` at the process's start, with `drawn` where that router id is new |
| `babel.state.unsaved`                         | `limit`, `seqno`, `err`                                                                                                                     |
| `babel.state.unreadable`                      | `file`, `err`                                                                                                                               |
| `kernel.pass`                                 | `trigger`, `took`, `added`, `removed`, `skipped`, `installed`, `err`                                                                        |
| `kernel.cover`                                | `family`, `installed`                                                                                                                       |
| `egress.pass`                                 | `trigger`, `took`, `installed`, `announced`, `err`                                                                                          |
| `egress.ready`                                | `ipv4`, `ipv6`, `sid`                                                                                                                       |
| `egress.device`                               | `name`, `action` (`created` or `withdrawn`)                                                                                                 |
| `border.pass`                                 | `trigger`, `took`, `installed`, `err`                                                                                                       |
| `border.ready`                                | `ready`                                                                                                                                     |
| `border.dropped`                              | `overlay_source_ipv4`, `overlay_source_ipv6`, `routing_header`, `sid_destination`, each the packets since the pass before                   |
| `network.changed`                             | `ipv4_default`, `ipv4_default_was`, `ipv4_added`, `ipv4_removed`, the same 4 for `ipv6`, `probed`, `woken`                                  |
| `transport.underlay.bound`                    | `interface_index`                                                                                                                           |
| `transport.endpoint.unpinned`, `.unsegmented` | `endpoint`, `errno`                                                                                                                         |
| `transport.pair.connected`                    | `local`, `remote`                                                                                                                           |
| `transport.pair.closed`                       | `local`, `remote`, `reason`, and `err` when the reason is `failed`                                                                          |
| `pmtu.changed`                                | `endpoint`, `budget`, `budget_was`, `reason`                                                                                                |
| `pmtu.floor`                                  | `endpoint`, `under`                                                                                                                         |
| `pmtu.steering`                               | `budget`, `need`, `under`                                                                                                                   |
| `netstack.codel.dropping`, `.drained`         | `sojourn`, `target`                                                                                                                         |
| `netstack.tun.refused`                        | `interface`, `frames`, `err`                                                                                                                |
| `netstack.tun.failed`                         | `interface`, `err`                                                                                                                          |
| `netstack.transit.dropped`                    | `reason`, `src`, `dst`                                                                                                                      |
| `netstack.icmp.withheld`                      | `interface`, `limit`, `withheld`                                                                                                            |
| `netstack.answer.source`                      | `ipv4`, `ipv6`, `sid`, each only where the node holds it                                                                                    |

`err` appears on `daemon.reload`, `control.verb`, `kernel.pass`, `egress.pass`
and `border.pass` only when the step failed, and on a `control.verb` under a
session the verb missed it is the reason the answer gives. The `trigger` of a
`kernel.pass` is `start`, `sweep`, `retry`, `grace`, `disable`, `enable`,
`reload`, `mesh` or `kernel`. The `trigger` of an `egress.pass` is `start`,
`sweep`, `retry`, `disable`, `enable`, `changed` when another writer added,
changed or deleted part of its tables, or `missed` when the daemon lost
nf_tables notifications to an overflow or could not read one, whoever's tables
they were about. The `trigger` of a `border.pass` is `start`, `sweep`, `retry`,
`reload`, `changed` when another writer added, changed or deleted part of its
table, or `missed` as for an `egress.pass`.

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

A `transport.pair.connected` names in `local` the address the socket bound and
in `remote` the peer it is connected to. The `reason` of a
`transport.pair.closed` is `idle` for a socket that carried nothing for a whole
sweep, `released` once the last session sending on it ended or moved, `network`
for a change of the host's network, `underlay` for a move of the underlay socket
onto another interface, `failed` for a send or a read on it that failed, and
`closed` when the transport closed. Neither an ICMP error an earlier datagram
drew nor a refusal of the socket's segments counts as `failed`, as
[platforms](../platforms.md#sockets-connected-to-1-peer) describes. Each
`failed` also counts in `ranet3_transport_pair_fallbacks_total`, and
`ranet3_transport_pair_sockets` counts the sockets open, as
[metrics](../metrics.md) lists.

A change of the host's network also wakes every dialer. A `network.changed`
names only what moved. `ipv4_default` and `ipv4_default_was` hold the new IPv4
default and the one before it. `ipv4_added` and `ipv4_removed` hold the IPv4
addresses that came and went. The `ipv6` attributes do the same for IPv6.
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
The same holds for a reconciler `ranet3 down` stopped, until `ranet3 up`.

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

An `ike.endpoint.moved` is recorded when a fresh request comes from another peer
address or port, or, in a session the peer opened, reaches this node at an
address other than the one the session's sends name. In a session that names an
interface, as it does on Linux and for a link-local address on macOS, a fresh
request arriving on another interface records it too. Its `endpoint` names the
peer's address and port, which in these two cases can be the same as before. A
session whose sends fell back from an address that is gone names no address, and
its next fresh request records an `ike.endpoint.moved` wherever it arrives. A
session that fell back from an address with no route to the peer moves back to
it, recording an `ike.endpoint.moved`, only at the first fresh request 1 minute
or more after the fallback.

A `transport.endpoint` event carries the peer's `endpoint` and the `errno` the
kernel refused the send with. An `unpinned` event is recorded once for an
endpoint, at its first fallback. Every answer is sent to its request's own
endpoint. While a session's address has no route to the peer, each answer to a
request that reaches the address therefore records an `unpinned` event, and the
session's own sends record at most one every minute. An `unsegmented` one is
recorded each time segmentation stops, which for a route that keeps refusing
segments is at most once every 10 minutes. A send refused only for its size
records none, since it lowers that session's budget instead. On a socket that
fragments, a segmented message refused with `EMSGSIZE` twice in a row records an
`unsegmented` one with that `errno`, as [platforms](../platforms.md#path-mtu)
describes. An `ike.send.failed` carries the error of the first send that failed,
and its `ike.send.recovered` how many failed before one went out. A reply to a
retransmitted request counts toward neither, since a replay can come from any
address.

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
