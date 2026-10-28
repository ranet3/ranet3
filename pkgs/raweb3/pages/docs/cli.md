---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Command line"
description: "Every ranet3 command and flag, the signals the daemon takes and the exit status of each command."
created: 2026-10-16
updated: 2026-10-28
order: 75
---

`ranet3` is 1 binary. `ranet3 daemon` runs the node. Most other commands ask a
running node through its [control socket](control-socket.md), and fail when no
daemon answers there.

These commands run without a daemon:

- `ranet3 daemon`
- `ranet3 version` without `--daemon`, and `ranet3 --version`
- `ranet3 licenses`
- `ranet3 completion`
- `ranet3 help`
- `ranet3 debug buildinfo`

Every command takes `-h` or `--help`. A word that names no command is refused,
with the commands spelled within 2 edits of it.

## Running the node

`ranet3 daemon` runs the node ("Run the ranet3 node"). It takes no arguments.

| Flag                    | Default                                               | Sets                                                                                                                                                                                |
| ----------------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-c`, `--config`        | `/etc/ranet3/config.toml`                             | The configuration file. The extension picks the format: `.toml`, `.yaml`, `.yml` or `.json`.                                                                                        |
| `--control`             | `/var/run/ranet3/control.sock`                        | The control socket to serve. `""` serves none.                                                                                                                                      |
| `--state-dir`           | `/var/lib/ranet3` on Linux, `/var/db/ranet3` on macOS | The directory for the flag `ranet3 down` leaves, and for the Babel router id and seqno limit in `babel.json`. The daemon makes it at mode 0700 when it is missing. `""` is refused. |
| `--log-level`           | `info`                                                | The least severe level the log keeps: `debug`, `info`, `warn` or `error`.                                                                                                           |
| `--debug-access`        | `root`                                                | Who may use the debug paths: `root`, `group` or `off`.                                                                                                                              |
| `--metrics`             | `""`                                                  | An address to serve `/metrics` on, such as `127.0.0.1:9669`. Empty serves none.                                                                                                     |
| `--pprof`               | `""`                                                  | An address to serve pprof on, such as `127.0.0.1:6060`. Empty serves none.                                                                                                          |
| `--contention-profiles` | `false`                                               | Records mutex and blocking profiles while pprof is served. This costs a lot of overhead.                                                                                            |

The `--debug-access` values set who may use the root class of debug paths, such
as `debug probe`:

- `root` admits uid 0 and the user the daemon runs as.
- `group` admits everyone who can open the socket.
- `off` refuses every debug path, the read class included.

The daemon logs to standard error. A CPU profile is at `/debug/pprof/profile` on
the pprof address, and this opens one as a flame graph:

```sh
go tool pprof -http=:8081 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
```

[Control socket](control-socket.md) describes the socket and its debug classes.
[Metrics](metrics.md) lists the series.

### Signals

| Signal              | Effect                                                                                                                                                                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SIGHUP`            | Reloads the file `--config` names and the trust document it names. A refusal goes to the log as `reload: <reason>`, and the node runs on as before. See [reloading](reloading.md).                                                                        |
| `SIGINT`, `SIGTERM` | Starts a clean shutdown. The daemon closes every session with a Delete, withdraws the routes, rules, addresses and egress tables it installed, waits for every dialer, and then withdraws the border filter. A second signal exits at once with status 1. |
| `SIGUSR1`           | Writes the mesh route table to the log.                                                                                                                                                                                                                   |

## Reading state

| Command           | Help                                      | Flags                   |
| ----------------- | ----------------------------------------- | ----------------------- |
| `status`          | Show state of this node                   | `--control`, `--json`   |
| `neighbors`       | Show Babel neighbors and link costs       | `--control`, `--json`   |
| `routes`          | Show the Babel route table                | `--control`, `--json`   |
| `sessions`        | Show IKE sessions                         | `--control`, `--json`   |
| `peers`           | Show peers and their connection state     | `--control`, `--json`   |
| `whois <address>` | Show the prefix and peer that reach an IP | `--control`, `--json`   |
| `ip`              | Show mesh IP addresses                    | `--control`, `--json`   |
| `exit list`       | List exit nodes and the one in use        | `--control`, `--json`   |
| `bugreport`       | Print node state for a bug report         | `--control`             |
| `metrics`         | Print metrics in Prometheus format        | `--control`             |
| `version`         | Print ranet3 version                      | `--daemon`, `--control` |

`--control` names the socket to read, `/var/run/ranet3/control.sock` by default.
`--json` prints JSON instead of the table.

- `status` shows the counters of the [forwarding decision](routing.md#transit)
  on its `Transit` line: the packets sessions delivered that went on to a peer
  or to the tun, those and the reads off the tun it dropped with each reason
  above 0, and the ICMP errors answered and unanswered about them. `--json`
  carries them under `transit`.
- `status` on a node with `cap.egress` names, on its `nftables` line, the
  families the exit is [ready](exit-nodes.md#readiness) for and, for a family
  that is not, the reason, such as
  `the lookup of 198.51.100.128 for 198.51.100.0/24 from 192.0.2.1 arriving on ranet3 failed: no route to host, with net.ipv4.conf.ranet3.forwarding at 0`.
  A lookup the exit had no address to make says so, as
  `lookup skipped, the mesh routes no other node's ipv6 prefix inside cap.border.overlay`.
  `--json` carries them under `egress`, in `ready`, `unready` and `skipped`.
- `sessions` names the transforms of each IKE SA and of its Child SA by their
  `cap.crypto` names. A Child SA the peer's creation or rekey keyed with key
  exchanges of its own has their kex entry after its cipher, such as
  `aes256gcm/x25519+mlkem768`, until this node's own rekey of it, which runs
  none. Its Fragments column is `no` where the 2 ends did not both say they
  support the IKE fragmentation of RFC 7383, and otherwise the path's threshold,
  the largest IP datagram this node cuts a new IKE message to fit. That is the
  family's floor, 576 or 1280, once a step cut a request of the session down to
  it, taken on the path the request was readied or last cut on, which every send
  of it went on since, the step's own included, until a send or this read finds
  that the peer moved or that the path MTU the host reads changed, or the
  session is asked to probe its path. Its Invalid SPI column counts the
  `INVALID_SPI` notifies the session sent its peer about ESP on an SPI this node
  does not hold, as
  [protocol deviations](design/protocol-deviations.md#errors-outside-an-exchange)
  describes.
- `whois` takes 1 address. It prints the longest prefix that covers the address,
  then the shorter ones it falls back to.
- `ip` prints the host prefixes this node announces, 1 address per line.
- `exit` on its own prints its help.
- `bugreport` prints 1 JSON object of every read, and names any read that
  failed.
- `version` prints the version of the binary. With `--daemon` it prints the
  version of the running node.

[Reading a node](control-socket.md#reading-a-node) shows the output of each.

## Acting on the node

| Command                                     | Help                                 | Flags                          |
| ------------------------------------------- | ------------------------------------ | ------------------------------ |
| `disable <reconciler\|steering\|responder>` | Disable a subsystem                  | `--control`, `--json`          |
| `enable <reconciler\|steering\|responder>`  | Enable a subsystem                   | `--control`, `--json`          |
| `redial [peer]`                             | Reconnect to a peer now              | `--all`, `--control`, `--json` |
| `rekey [peer]`                              | Rekey sessions now                   | `--all`, `--control`, `--json` |
| `reload`                                    | Reload the config and trust document | `--control`, `--json`          |
| `down`                                      | Take this node off the mesh          | `--control`, `--json`          |
| `up`                                        | Put this node back on the mesh       | `--control`, `--json`          |

`redial`, `rekey` and `debug probe` take 1 peer, or `--all` and no peer. The
command refuses a peer given together with `--all`, and a call with neither,
before it asks the daemon. [Naming a peer](control-socket.md#naming-a-peer)
lists the names a peer takes.

[Acting on a running node](control-socket.md#acting-on-a-running-node) describes
each verb.
[Taking a node off the mesh](control-socket.md#taking-a-node-off-the-mesh)
describes `down` and `up`, and [reloading](reloading.md) describes `reload`.

## Debug

Most commands under `ranet3 debug` look inside a running node. They are not a
stable interface. A command, its output and the events it reports may change in
any revision. `--control` and `--json` on `debug` apply to every command under
it. [Debugging](development/debug.md) describes each command and the events.

| Command                                | Help                                                       | Flags                                                                 |
| -------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------- |
| `debug socket [METHOD] PATH [BODY\|-]` | Send a raw control socket request                          | `--timeout` (10 seconds)                                              |
| `debug buildinfo`                      | Print Go build information                                 | none                                                                  |
| `debug events`                         | Show node events                                           | `-f`, `--follow`, `--for` (30 seconds), `--kind`, `--since`, `--peer` |
| `debug wait <kind>`                    | Wait for a node event                                      | `--attr key=value`, `--past` (0), `--timeout` (10 seconds), `--peer`  |
| `debug netmon`                         | Show the host network the node watches                     | none                                                                  |
| `debug pmtu [peer]`                    | Show each session's path MTU                               | none                                                                  |
| `debug probe [peer]`                   | Probe sessions now                                         | `--all`                                                               |
| `debug rules`                          | Show the host's policy rules and the border filter's chain | none                                                                  |
| `debug runtime`                        | Show daemon runtime state                                  | none                                                                  |
| `debug updown`                         | Show whether the node is on the mesh                       | none                                                                  |

- `debug socket` sends GET, or POST when a body follows the path. A body of `-`
  is read from standard input. The answer goes to standard output and its status
  line to standard error.
- `debug buildinfo` prints the build of this binary. `debug runtime` prints the
  build of the running node.
- `debug events` prints the recorded events and exits. With `--follow` it prints
  new events until `--for` has passed. `--kind` may be repeated, and a kind also
  selects the kinds under it, so `babel` selects every Babel event. `--since`
  takes a duration and keeps only the events recorded within it.
- `debug wait` prints the first event of the kind and how long after the start
  it came. `--attr` may be repeated, and every attribute must match. `--past`
  takes a duration and also matches an event recorded within it.
- `debug pmtu` shows every session, or the sessions of 1 peer.

## Other commands

| Command                      | Help                                  |
| ---------------------------- | ------------------------------------- |
| `licenses`                   | Print open source license information |
| `completion bash\|zsh\|fish` | Generate shell completion scripts     |
| `help [command]`             | Show help for any command             |
| `--version`                  | Print ranet3 version                  |

## Exit status

| Command        | Status                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| every command  | 0 on success. 1 on an error, which goes to standard error.                                                                                                                                                                                                                                                                                                                                                      |
| `daemon`       | 0 after a clean shutdown. 1 when it refuses to start, when a second signal cuts the shutdown short, when the pprof listener, the metrics listener, the control socket or the mesh failed while it ran, when its tun went away under it, or when the route reconciler, the egress translator or the border filter could not withdraw what it installed. A failed pass of any of them does not change the status. |
| `debug socket` | 1 when the answer's status is not 2xx.                                                                                                                                                                                                                                                                                                                                                                          |
| `debug wait`   | 0 when the event came. 1 when none came within `--timeout`. 2 when it could not watch for the event or lost it, or refused an argument or flag.                                                                                                                                                                                                                                                                 |
| `rekey`        | 1 when a session did not rekey, after the answer lists it with the reason.                                                                                                                                                                                                                                                                                                                                      |

The daemon logs why it refuses to start at the error level, which every
`--log-level` keeps. A flag value it refuses goes to standard error as plain
text instead.

## Shell completion

`ranet3 completion bash`, `ranet3 completion zsh` or `ranet3 completion fish`
writes the script for that shell to standard output.

These complete without a daemon:

- every command and flag
- the subsystems of `disable` and `enable`
- the shells of `completion`
- the values of `--log-level` and `--debug-access`
- the methods and paths of `debug socket`
- a directory for `--state-dir`
- a `.sock` file for `--control` under `debug`

These ask the daemon at the socket the command line names, or at the default
socket:

- the peer of `redial`, `rekey` and `debug probe`, from the peers the daemon
  dials and the nodes it holds a session with
- the peer of `debug pmtu`, from the nodes of its sessions
- the kind of `debug wait`, and `--kind` of `debug events`, from the kinds of
  the recorded events
- `--peer` of `debug events` and `debug wait`, from the peers the recorded
  events name

When the daemon does not answer, completion offers nothing. A completion from
the recorded events or from `debug pmtu` waits at most 1 second. A completion
for `redial`, `rekey` or `debug probe` makes 2 reads, and waits up to 10 seconds
for each.
