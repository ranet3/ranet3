---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Debugging a running node"
description: "The debug tree: who may call it, what it promises, its commands and how a view is added."
created: 2026-10-04
updated: 2026-10-06
order: 30
---

`ranet3 debug` is a command tree for looking inside a running node. It speaks to
the daemon over the control socket, under paths starting with `/v0/debug/`, and
it is not a stable interface: a debug path, a field of its answer, an event kind
and a command may each change or go in any revision. A client and a daemon built
from the same revision agree, and nothing wider is promised.
`ranet3 debug --help` lists its commands.

Every command prints text, or the wire form with `--json`, and every command
that could run for long is bounded by a flag, `--for` or `--timeout`, so a
script can call one without having to interrupt it. Every argument and flag
completes in the shells `ranet3 completion` writes for, and in nushell through
carapace's cobra bridge.

## Who may call it

The socket's mode decides who can connect at all, and it is enough for the reads
and the verbs outside this tree, because each of those acts on something the
node's own file already decides. A profile, a packet capture or a log level is
nothing the file can express, so the debug paths are authorized by who is
calling instead. The daemon asks the kernel for the credentials of every
connection it accepts, `SO_PEERCRED` on linux and `LOCAL_PEERCRED` on darwin,
and every debug path has a class:

- **read**: snapshots that carry no key material, and the event stream. Open to
  everyone who can open the socket, as `ranet3 status` is.
- **root**: profiles, goroutine dumps, logs, packet capture, the trust document
  and every debug action. Open to uid 0 and to the user the daemon runs as. Each
  such call is logged at info with the caller's uid and pid.

The daemon's `--debug-access` sets how far the root class reaches. `root` is the
default. `group` opens the root class to everyone who can open the socket, and
`off` refuses every debug path, the read class included. The modules carry no
option of their own for it: `extraArgs` passes the flag. A connection whose
caller the kernel does not name, which is every platform but linux and darwin,
reaches the read class alone under `root` and `group`, and nothing under `off`.

A refusal answers 403 with the rule and the caller's uid, and a path whose view
the daemon does not serve answers 501 naming the view. On a NixOS host the unit
runs the daemon as root, so the root class means `sudo`. In an `unshare -rn` lab
the caller already reads as uid 0.

## Commands

- `debug socket [METHOD] PATH [BODY|-]` sends one request as written and prints
  the answer's body as it arrives, with the status line on stderr, and exits 1
  on anything but a 2xx. The method is GET, or POST where a body follows the
  path, and `-` reads the body from stdin. `--timeout`, 10 seconds by default,
  bounds the whole exchange, a stream included. It reaches a path no command
  covers yet, or a daemon of another revision.
- `debug runtime` is the daemon's process: its version and revision, the go
  version, GOMAXPROCS and the CPUs, goroutines, the OS threads the runtime has
  started, open descriptors against `RLIMIT_NOFILE`, the heap and the collector,
  uptime, and the resolver a lookup can reach. `cgo` there means a lookup may go
  to the C library, which holds an OS thread for as long as it takes. The view
  is read without stopping the daemon's goroutines, so polling it leaves the
  data path running.
- `debug buildinfo` prints this binary's own go build information.
- `debug events [-f] [--kind K]... [--peer P] [--since 5m] [--for 30s]` prints
  the events the daemon has recorded and exits, or with `-f` goes on printing
  the ones after them until `--for` has passed. `--kind`, given up to 16 times,
  takes a kind or any part of one that ends at a dot, so `babel` takes every
  babel event, and `--peer` names a peer the way `redial` does.
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
  stamp, so a clock stepped back during the wait hides nothing.

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
holds 4 streams at once and refuses a fifth with 503, which leaves the rest of
its connections to the reads.

| kind                                 | when                                                                        |
| ------------------------------------ | --------------------------------------------------------------------------- |
| `daemon.started`, `daemon.stopping`  | the node is up, and its shutdown has begun                                  |
| `daemon.reload`                      | the file and the trust document were read again, with the error if any      |
| `control.verb`                       | a verb over the socket, once under each session or dialer it acted on       |
| `dial.attempt`, `dial.failed`        | a dialer sent a handshake, or ended short of a session                      |
| `dial.woken`                         | a dialer was set going before its delay, as `redial` does                   |
| `ike.handshake.failed`               | the responder refused a handshake, as often as it logs one                  |
| `ike.session.established`, `.ended`  | a session started serving, and stopped                                      |
| `ike.session.resolved`               | two sessions for one path were resolved to one                              |
| `ike.rekey.started`, `.completed`    | a rekey this end started, of the Child SA or of the IKE SA                  |
| `ike.rekey.failed`                   | the same rekey failing, with its error                                      |
| `babel.neighbor.up`, `.down`         | a neighbor's hellos started arriving, or stopped or its session ended       |
| `babel.route.selected`, `.retracted` | a prefix's next hop changed, every time rather than once a second as logged |
| `kernel.pass`                        | a reconciler pass that changed the kernel, skipped anew or failed           |
| `egress.pass`                        | a translator pass that rewrote its rules, moved its prefixes or failed      |
| `transport.underlay.bound`           | the underlay socket moved onto another interface                            |
| `netstack.codel.dropping`            | a peer's sender began dropping for a queue delay above its target           |
| `netstack.codel.drained`             | that peer's queue emptied, or its delay fell back below the target          |

A `control.verb` carries the caller's uid and pid, and in its `peer` attribute
the peer as the verb named it, when it named one. The event's peer is the path
of the session or dialer it was recorded under, which `--peer` takes by any name
of that peer. A verb that acted on none, a refused one included, is recorded
once without a peer.

A `netstack.codel` event carries the `sojourn` of the batch that changed the
state, how long that batch had waited since it was reserved, and the `target`. A
`drained` recorded because the queue emptied carries a `sojourn` of 0. The
sender drops one packet at a time on its own schedule and records no event per
packet, so `ranet3_peer_send_delay_dropped_total` is where the drops are
counted.

## Adding a view

A view is three new files, and no file of the tree needs an edit for it:

- `control/debug_<view>.go` holds the wire types, the interface the daemon
  implements, the path registered from `init` with its class, the text renderer
  and the client method. `debugRead` registers a snapshot.
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
