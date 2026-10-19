---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Control socket"
description: "Asking a running node questions, and the verbs that act on one."
created: 2026-09-21
updated: 2026-10-20
order: 80
---

`--control /var/run/ranet3/control.sock` is where the daemon answers, and is the
default, so a node is askable without having been configured to be.
`--control ""` turns it off. The socket is mode 0660 in the daemon's group,
which the unit names, and that mode authorizes every path outside `/v0/debug/`.
[The verbs](#acting-on-a-running-node) say what keeps it sufficient for them.

The debug paths are authorized by the caller's peer credentials instead. Their
snapshots and the event stream are open to whoever can open the socket.
`debug probe`, the only action among them, takes root or the daemon's own user.
The daemon's `--debug-access` changes this. `group` opens the probe to whoever
can open the socket, and `off` refuses every debug path, as
[debugging](development/debug.md) describes.

The daemon bounds each connection by an idle timeout. It also bounds the
connections open at once across every caller. Each connection costs a
descriptor, and a node out of descriptors cannot answer anyone. Past the limit,
the daemon closes a new connection as it accepts it. That client learns at once
that it was refused, and a shutdown never waits for a free place.
[Limits](#limits) gives the values.

## Socket directory

The socket takes the daemon's group on every platform. Each directory the daemon
makes on the way to the socket gets the same group and mode 0750. Linux gives a
new file the group of the process that makes it, outside a setgid directory.
macOS gives a new file the group of its directory, which under `/var/run` is
`daemon`. The daemon sets the group before the mode lets that group in.

On macOS, the record that `link.underlay.bind` keeps shares the default socket's
directory, `/var/run/ranet3`. Whichever of the 2 the daemon writes first makes
the directory.

A directory that already exists keeps its group and mode. On macOS, a directory
in the group `daemon` keeps the socket out of reach of the daemon's group. Stop
the daemon, give the directory the daemon's group with `chgrp`, and start the
daemon again. A reboot works as well, because it clears `/var/run` and the
daemon makes the directory again.

Removing the directory instead also removes the record of the routes
`link.underlay.bind` wrote, and that record is the only way the daemon knows to
withdraw them. [Running it as a service](service.md#nix-darwin) gives the
commands for the nix-darwin job. Under the NixOS module, systemd makes
`/run/ranet3` in the unit's group and removes it when the unit stops.

## Who owns the path

An exclusive lock on a sibling file decides which process owns the path. The
lock file is the socket's path with `.lock` appended. The daemon does not dial
the socket to see whether anything answers. A live daemon out of descriptors
fails to answer, as does one whose socket the caller cannot open, and both still
own their path.

Under the lock, the daemon removes a socket a dead instance left behind. It
refuses a path that is not a socket, naming it. A second daemon on the same path
is refused, because the first holds the lock. A path named with `--control` that
the daemon cannot bind refuses the startup. The default path warns and carries
on instead, because it is on without having been asked for.

## Version

The version a node reports is `version.txt` and the commit the binary was built
from. `ranet3 version` reports the binary, without a node running.
`ranet3 version --daemon` reports the running node, which tells the 2 apart
after an upgrade.

## Reading a node

The read subcommands print a table, or the wire form with `--json`. `metrics`
prints the scrape, and `bugreport` prints JSON alone. [Command line](cli.md)
lists every command and its flags.

```
$ ranet3 status
Node        example/laptop
Version     2026.912.0+860393bf1c2e
Uptime      3h12m0s
Port        13000
Endpoints   0/ip6 1/ip4
TUN         ranet0 MTU 1400 queues 16
Role        initiator, responder, full mesh, no transit
Forwarding  IPv4 on IPv6 on
Registry    /etc/ranet/registry.json, 142 nodes in 31 organizations
Kernel      table 200 protocol 155, 609 installed, last pass 12 seconds ago
Egress      off, this node carries no traffic for others
Dialers     117 running
Sessions    83
Neighbors   83, 81 alive
Routes      611 prefixes, 604 selected, 3 originated
Originate   198.18.104.117/32 3fff:a::198:18:104:117/128 3fff:1:69c:8c0::/60
Segments    3fff:1:69c:8c6::1 End.DT46 (0 forwarded, 5 delivered, 0 dropped)
Steering    from 3fff:a::198:18:104:117/128 via 3fff:1:69c:98d6::1 (12 steered, 2 with no route to their first segment)
ESP         41822931 in, 0 dropped, 14 refused

$ ranet3 neighbors
Peer                 State  Cost  Extra  Rx cost  RTT      Routes  Expires  Dropped  Failed
example/gateway:0@0  up     116   0      96       27.2ms   15      11.3s    0        0
other/relay:2@1      up     1218  1024   96       176.7ms  130     9.8s     0        0

$ ranet3 routes
Destination  From         Via                  Metric  Router ID         Seqno  Paths
::/0         3fff:a::/36  example/gateway:0@0  212     0a1b2c3d4e5f6071  42     7
```

`neighbors` is the counterpart of `birdc show babel neighbors`. It shows the
neighbor's reported Rx cost beside this node's cost, which tells a link that
carries 1 way from one that carries neither. Extra is the part of the cost
`cap.babel.cost.extra` charges the neighbor, which this node's IHUs add to the
receive cost they report as well. It also shows 2 dataplane counters BIRD lacks.

`routes` is the counterpart of `birdc show route`. It reads the Babel route
table, not the forwarding table, so a prefix every neighbor has retracted still
shows as a row. `sessions` is the counterpart of `swanctl --list-sas`. `peers`
lists who this node dials, from the config file or from the trust document under
`dial.all`, and whether it got there.

### Naming a peer

A node is named `organization/name`. Each of its endpoints is named
`organization/name:serial`, as [configuration](configuration.md#names)
describes. `status` shows this node's own name in that form.

| Name     | Example               | Names                                                                                      |
| -------- | --------------------- | ------------------------------------------------------------------------------------------ |
| node     | `example/gateway`     | a node                                                                                     |
| endpoint | `example/gateway:0`   | 1 endpoint of a node                                                                       |
| session  | `example/gateway:0@0` | the session between the peer's endpoint and this node's endpoint `0`, whichever end dialed |
| dialer   | `example/gateway@0`   | the dialer of a node with no endpoint pinned, from this node's endpoint `0`                |

`peers` shows a peer by the endpoint `dial.to` pins, or by its node. The session
of a dialer with no endpoint pinned is named by the endpoint that answered.

- `rekey`, `debug probe` and `debug pmtu` take a session by its name, its peer's
  endpoint, that endpoint's node, or the node's name alone. The name alone takes
  that name in every organization. A dialer's name matches only a session of
  exactly that name. To take the sessions of a dialer with no endpoint pinned,
  name their node.
- `redial` takes the same names and a dialer by its name. The name of an
  endpoint or a session also wakes the dialer of that node with no endpoint
  pinned.
- `debug events --peer` takes the same names as `rekey` and a dialer's name. A
  dialer's name selects a dial's events until its endpoint resolves.

A name matches whole. `example/isere` takes no session of `example/isere2`. A
name with a serial and no organization, such as `isere:1`, names nothing. For
`redial`, `rekey` and `debug probe`, completion offers the peers the daemon
dials and the nodes it holds a session with. For `debug pmtu`, it offers the
nodes of its sessions. For `debug events --peer`, it offers the names the
recorded events carry.

### Questions

4 more commands answer questions instead of printing 1 subsystem:

- `whois <address>` is a longest prefix match over the Babel route table. It
  prints the prefix that covers the address and the peer this node reaches it
  through, then what the address would fall back to. It names the peer, not the
  originating node, because Babel carries a router id and no name, and ranet3
  gives each speaker a random router id.
- `ip` prints this node's own mesh addresses, 1 per line, taken from the host
  prefixes it announces.
- `exit list` prints the defaults the mesh advertises, with the 2 `/1` halves of
  a family that 1 node advertises together, and which of them this node would
  take. It tells a withdrawn default from one that carries traffic.
- `bugreport` prints every subsystem in 1 JSON object. A read that did not
  answer leaves its own line in the report, so a node that is half up still
  produces one.

`metrics` prints the same scrape the metrics listener serves, read over the
control socket, so a node's counters are readable without it binding a port a
fleet then has to firewall.

## Endpoints

Every path starts with `/v0`. A read answers GET and HEAD, and a verb answers
POST. The class says who may call a path. `mode` is anyone the socket's mode
lets in. `read` and `root` are the debug classes described above.

| Path                | Method    | Class  | Request                                         | Answer                            |
| ------------------- | --------- | ------ | ----------------------------------------------- | --------------------------------- |
| `/v0/status`        | GET, HEAD | `mode` | none                                            | the node, a JSON object           |
| `/v0/neighbors`     | GET, HEAD | `mode` | none                                            | Babel neighbors, a JSON list      |
| `/v0/routes`        | GET, HEAD | `mode` | none                                            | Babel routes, a JSON list         |
| `/v0/sessions`      | GET, HEAD | `mode` | none                                            | IKE sessions, a JSON list         |
| `/v0/peers`         | GET, HEAD | `mode` | none                                            | dialed peers, a JSON list         |
| `/v0/metrics`       | GET, HEAD | `mode` | none                                            | the Prometheus text format        |
| `/v0/disable`       | POST      | `mode` | `subsystem`                                     | a result                          |
| `/v0/enable`        | POST      | `mode` | `subsystem`                                     | a result                          |
| `/v0/redial`        | POST      | `mode` | `peer` or `all`                                 | a result                          |
| `/v0/rekey`         | POST      | `mode` | `peer` or `all`                                 | a result                          |
| `/v0/reload`        | POST      | `mode` | empty body                                      | a result                          |
| `/v0/down`          | POST      | `mode` | empty body                                      | a result                          |
| `/v0/up`            | POST      | `mode` | empty body                                      | a result                          |
| `/v0/debug/events`  | GET, HEAD | `read` | query `kind`, `peer`, `attr`, `since`, `follow` | events, 1 JSON object per line    |
| `/v0/debug/pmtu`    | GET, HEAD | `read` | query `peer`                                    | path MTU view, a JSON object      |
| `/v0/debug/runtime` | GET, HEAD | `read` | none                                            | process view, a JSON object       |
| `/v0/debug/updown`  | GET, HEAD | `read` | none                                            | up and down view, a JSON object   |
| `/v0/debug/netmon`  | GET, HEAD | `read` | none                                            | network watch view, a JSON object |
| `/v0/debug/rules`   | GET, HEAD | `read` | none                                            | rules view, a JSON object         |
| `/v0/debug/probe`   | POST      | `root` | `peer` or `all`                                 | a result                          |

### Requests and answers

A verb's body is a JSON object with the fields `subsystem`, `peer` and `all`.
Each verb reads the fields it needs and ignores the others. An empty body is the
empty request, which `reload`, `down` and `up` take. A verb answers with a
result. Its `acted` lists the subsystems or paths the verb reached, and its
`detail` is the sentence the command prints.

The reads answer JSON. A duration is a string such as `"4s"`. A time follows
RFC 3339. An address or a prefix is its text form. An optional field with no
value is left out, such as `down` on a node that is up or `err` after a pass
that succeeded. `endpoints` and `originate` are always present and read `[]`
when empty, and every counter is always present. Other lists, such as
`segments`, `disabled` and `acted`, are left out when empty.

| Answer             | Fields                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| status             | `version`, `node`, `port`, `endpoints` (`serial/family`), `tun`, `mtu`, `queues`, `started_at`, `uptime`, `responder` (`link.listen` is on), `full_mesh` (`dial.all` is on), `no_transit` (`cap.transit` is off), `forwards_ipv4`, `forwards_ipv6`, `registry`, `kernel`, `egress`, `border` (absent without `cap.border`), `counts`, `esp`, `originate`, `segments`, `steering`, `segment_counters`, `disabled`, `down` |
| `registry`         | `path`, `organizations`, `nodes`, `read_at`                                                                                                                                                                                                                                                                                                                                                                              |
| `kernel`           | `enabled`, `where`, `table`, `protocol`, `metric`, `vrf`, `l3mdev_accept`, `pass_at`, `installed`, `skipped`, `added`, `removed`, `cover`, `err`                                                                                                                                                                                                                                                                         |
| `egress`           | `enabled`, `where`, `device` (the egress device, on a node with an egress segment), `ready` (`ipv4`, `ipv6`), `unready` (why a family is not ready, a reason a node with no egress device also carries after another writer's change or a stop), `source4`, `source6`, `return`, `advertise`, `announced`, `pass_at`, `installed`, `flows`, `bytes`, `conflicts`, `err`                                                  |
| `border`           | `where`, `inside`, `overlay`, `sids`, `ready`, `unready`, `pass_at`, `installed`, `dropped` (`overlay_source_ipv4`, `overlay_source_ipv6`, `routing_header`, `sid_destination`, each in packets as of the last pass), `err`                                                                                                                                                                                              |
| `counts`           | `dialers`, `sessions`, `neighbors`, `neighbors_alive`, `prefixes`, `selected`, `originated`                                                                                                                                                                                                                                                                                                                              |
| `esp`              | `inbound_packets`, `inbound_dropped`, `receive_dropped`, `receive_refused`, `keepalives`                                                                                                                                                                                                                                                                                                                                 |
| `originate`        | a list of `prefix` and `from`                                                                                                                                                                                                                                                                                                                                                                                            |
| `segment_counters` | `forwarded`, `delivered`, `dropped`, `steered`, `unsteered`, `unrouted`, `answered`, `egressed`, `refused`, `not_ready`, `drained`                                                                                                                                                                                                                                                                                       |
| `down`             | `since`, `for`                                                                                                                                                                                                                                                                                                                                                                                                           |
| neighbor           | `peer`, `address`, `alive`, `cost`, `extra`, `reported_cost` (absent until an IHU arrives), `rtt` (absent until a timestamped IHU arrives), `routes`, `expires`, `dropped`, `send_failed`                                                                                                                                                                                                                                |
| route              | `destination`, `from`, `via` (absent for a prefix held unreachable), `metric`, `router_id`, `seqno`, `candidates`, `originated`                                                                                                                                                                                                                                                                                          |
| session            | `path`, `peer` (the peer's node), `remote` (address and port), `preferred`, `active`, `local_spi`, `remote_spi`, `ike_cipher`, `ike_prf` and `ike_kex` (the IKE SA's transforms by their `cap.crypto` names), `esp_cipher` (the Child SA's), `started_at`, `age`, `idle`                                                                                                                                                 |
| peer               | `path`, `peer`, `connected`, `generated` (taken from the trust document under `dial.all`)                                                                                                                                                                                                                                                                                                                                |
| result             | `acted`, `detail`                                                                                                                                                                                                                                                                                                                                                                                                        |

### Status codes

| Code | When                                                                                                                                         |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| 200  | The read or the verb succeeded.                                                                                                              |
| 400  | The node refused a verb, a body or query does not parse, or a query names more kinds or attributes than the limits allow. The body says why. |
| 403  | The caller may not use this debug path. The body names the rule and the caller's uid.                                                        |
| 404  | No such path. Under `--debug-access off`, an unknown debug path answers 403.                                                                 |
| 405  | The method does not fit the path. `Allow` names the one that does.                                                                           |
| 500  | The daemon could not encode its answer. The body says why.                                                                                   |
| 501  | The program serving the socket does not implement that verb or debug view. The daemon implements them all.                                   |
| 503  | A 5th event stream asked to follow while 4 are open.                                                                                         |

### Limits

| Limit                                                     | Value                                                   |
| --------------------------------------------------------- | ------------------------------------------------------- |
| Connections open at once                                  | 32, and the daemon closes the next one as it accepts it |
| Idle connection between requests                          | closed after 30 seconds                                 |
| Request headers                                           | 5 seconds                                               |
| Writing an answer, a stream excepted                      | 30 seconds                                              |
| Verb body the daemon reads                                | 64 KiB                                                  |
| Event streams open at once                                | 4                                                       |
| 1 stream write waiting on its reader                      | 5 seconds, then the stream ends                         |
| Heartbeat on a quiet stream                               | every 15 seconds                                        |
| Kinds in 1 events query                                   | 16                                                      |
| Attributes in 1 events query                              | 16                                                      |
| Socket path                                               | 103 bytes                                               |
| 1 exchange of `ranet3` with the daemon, a stream excepted | 10 seconds                                              |
| Answer `ranet3` reads                                     | 64 MiB                                                  |
| 1 stream line `ranet3` reads                              | 1 MiB                                                   |
| Events in 1 stream write                                  | 64                                                      |

## Acting on a running node

7 subcommands change what a node is doing right now. `disable` and `enable` stop
and start a subsystem, which is `reconciler`, `steering` or `responder`.
`redial` and `rekey` take a peer or `--all`. `rekey` asks each session to
replace its Child SA. After a failed Child SA rekey, it leaves the replacement
to the retry the session has scheduled, as `cap.crypto.rekey.retry` sets.
`reload` does what SIGHUP does, so a supervisor is not the only way to ask.
`down` takes the node off the mesh and `up` puts it back, as
[taking a node off the mesh](#taking-a-node-off-the-mesh) describes.
`debug probe` acts as well, under the debug rules above.

None of them changes the configuration. A node's configuration is its file, and
that stays its only entry point. What these act on is operational state the file
already decides: `cap.table`, `cap.segment`'s steering, `link.listen`, the peers
list and the file itself. `down` asks for no more than a file without peers,
`link.listen`, `cap.table` or `cap.egress` would. Whoever may edit that file
could already ask for every one of them, by editing and restarting or by editing
and sending SIGHUP. The socket's mode therefore grants nothing the file's
permissions did not. A verb that reached past what the file can express would
break that, and is refused on those grounds. The subsystem names are a closed
set for the same reason. The 2 halves are told apart by method rather than by
path: a read answers GET and HEAD and nothing else, and a verb answers POST
alone.

The state lives in the process, apart from the flag `down` leaves. A restart
starts every subsystem the file names. A reload leaves a stopped subsystem
stopped. The trust document changes whenever a node joins, and a reload that
started a subsystem again would undo an operator's decision.

A node running less than its file says reports it on the `Disabled` line of
`ranet3 status`, and in the `disabled` field of its JSON. No other read shows
that difference.

`disable` and `enable` refuse a name outside those 3. They also refuse a
subsystem the file never turned on:

- `reconciler` on a node without `cap.table`
- `steering` where `cap.segment` names no steer policy
- `responder` while `link.listen` is off

A subsystem already in the state asked for is reported as such, and the command
succeeds. `enable` is refused while the node is down.

Each verb acts as follows:

- `disable reconciler` withdraws every route, address and rule the reconciler
  installed, as `birdc disable` does to a kernel protocol, instead of freezing a
  table nobody maintains. A withdrawal the kernel refuses in part is retried on
  the backoff of a failed pass until it completes. The `Kernel` line of
  `ranet3 status` carries its error until then.
- `disable steering` leaves the policies loaded and stops acting on them, so a
  diagnostic still reports what was stopped.
- `disable responder` refuses the next handshake and leaves the sessions this
  node already holds alone.
- `redial` is for a peer that dials this node and cannot be dialed back. Such a
  peer does not retry on its own. `redial` drops what this node holds for that
  peer and sets its dialers going at once, instead of after the reconnect delay.
- `redial --all` does the same for every session and every dialer. It is for a
  network change the node's watch cannot see, such as a captive portal that
  changes no address or route.

`redial`, `rekey` and `debug probe` refuse a call that names a peer and `--all`,
and a call that names neither.

`reload` re-reads the file the daemon was started with. When the daemon refuses
the reload, the command prints the refusal and exits 1. After SIGHUP, the same
refusal goes to the log and to the `err` of the `daemon.reload` event.
[Reloading](reloading.md) says what a reload applies.

## Taking a node off the mesh

`ranet3 down` takes a node off the mesh and leaves its daemon running. Every
dialer stops and no new one starts, the responder stops answering IKE where
`link.listen` is on, every session is closed with an IKE Delete, and the Babel
speaker stops. Where `cap.table` is set, the reconciler withdraws the routes,
rules and tun addresses it installed, and on an exit node the translator
withdraws its tables and its advertisement. The daemon, the tun, the control
socket, the metrics and the debug views stay, and the node still answers every
read. A ranet3 peer drops its routes through the node when the Delete arrives,
rather than when the Babel neighbor would have timed out.

`down` writes the flag `down` in the daemon's state directory before it acts,
holding the moment the node went down, and a daemon that starts with the flag
there comes up down: its tun, control socket and metrics open, and nothing else
of the mesh starts. A node taken off the mesh to be worked on stays off through
the restarts and reboots the work brings, which makes `down` the only verb whose
state outlives the process. `--state-dir` names the directory. It defaults to
`/var/lib/ranet3` on Linux and `/var/db/ranet3` on macOS, and the daemon makes
it at mode 0700 when it is missing. The flag is written beside its final name,
synced and renamed into place, and the directory is synced after it, so a crash
leaves the flag as it was or as asked.

`ranet3 up` removes the flag before it acts. It then puts back the addresses,
rules and routes as the reconciler does at start, and on an exit node the
translator's tables and advertisement. It starts every dialer, the responder and
the speaker. A subsystem somebody disabled stays disabled. A `down` on a node
that is down and an `up` on one that is up succeed and say so. While the node is
down, `redial`, `rekey`, `enable` and `debug probe` are refused with an error
saying it is down. A reload applies the file and the trust document and leaves
the node down, and a peer the reload adds is dialed after `up`.

```
$ ranet3 down
This node is off the mesh with 2 session(s) closed, and it stays off through a restart until ranet3 up
  example/bravo:0@0
  example/charlie:0@0

$ ranet3 status
Node        example/gateway
Down        since 2026-10-12 21:04:05 UTC, 3 minutes ago, until ranet3 up
Version     2026.912.0+860393bf1c2e
Uptime      26h0m0s
Port        13000
Endpoints   0/ip4 1/ip6
TUN         ranet3 MTU 1400 queues 4
Role        initiator, responder, transit
Forwarding  IPv4 on IPv6 on
Registry    /etc/ranet3/registry.json, 12 nodes in 1 organizations
Kernel      table 100 protocol 155, 0 installed, last pass 3 minutes ago
Egress      off, this node carries no traffic for others
Dialers     0 running
Sessions    0
Neighbors   0, 0 alive
Routes      0 prefixes, 0 selected, 1 originated
Originate   2001:db8:a::/48
Segments    off
Steering    off
ESP         0 in, 0 dropped, 0 refused

$ ranet3 up
This node is back on the mesh
```

`ranet3 status` carries the `Down` line under the node's name for as long as the
node is down. `ranet3 debug updown` adds where the flag is and whether it is
there. It also shows the last move between up and down with its cause, and the
Babel router id and seqno in use, with the seqno limit `babel.json` holds. Each
move is recorded as a `node.down` or `node.up` event, as
[debugging](development/debug.md#events) describes.

The state directory also holds `babel.json`, the node's Babel router id and a
seqno limit, which a restart starts from, as
[running it as a service](service.md#the-state-directory) describes. A `down`
and an `up` keep the router id, and the speaker the `up` starts sends a seqno
past every one it sent before the `down`.

ranet3 has no login flow. A node's identity is its private key and its entry in
the trust document, both in place before the daemon starts.
