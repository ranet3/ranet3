---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Control socket"
description: "Asking a running node questions, and the verbs that act on one."
created: 2026-09-21
updated: 2026-11-10
order: 80
---

`--control /var/run/ranet3/control.sock` is where the daemon answers, and is the
default, so a node is askable without having been configured to be.
`--control ""` turns it off. The socket is mode 0660, owned by the daemon's
user, root under both modules, and in the daemon's group, which the unit names.

The daemon bounds each connection by an idle timeout. It also bounds the
connections open at once across every caller. Each connection costs a
descriptor, and a node out of descriptors cannot answer anyone. Past the limit,
the daemon closes a new connection as it accepts it. That client learns at once
that it was refused, and a shutdown never waits for a free place.
[Limits](#limits) gives the values.

## Who may use it

Whoever can open the socket runs every command, the `ranet3 debug` tree
included, and nothing past the socket's mode checks the caller. Root, the
daemon's user and the members of the daemon's group can open it, which makes the
group root-equivalent for the daemon. A member can:

- take the node off the mesh with `down`, which holds through restarts and
  reboots until `up`
- withdraw [the kill switch's](routing.md#the-kill-switch-on-linux) rule and
  chains, or on macOS [its rejects](routing.md#the-kill-switch-on-macos), with
  `disable reconciler`, as [the verbs](#acting-on-a-running-node) describe, and
  stop steering or the responder
- read in plaintext with `debug trace` the packets the node's forwarding
  decision handles, up to the trace's rate, other users' and other nodes'
  traffic among them
- send probes as the node with `debug probe`

Give the group only to someone who may already act as root on the daemon.
[Running it as a service](service.md#options) names the group each module uses.

The events `control.verb` and `control.trace.started` carry the caller's uid and
pid, as [debugging](development/debug.md) lists. They are an in-memory record,
the last 1024 events of their subsystem, which a restart clears. Each request
for a verb also writes a `control verb` line at info to the daemon's log, and
each `debug probe` and `debug trace` request a `control debug call` line, with
its path, the caller's uid and pid, and a trace's query, before the daemon
checks the request. A read writes none. These lines are the lasting record of
who acted on the node, who probed and who traced while the daemon logs at `info`
or `debug` and its log is kept. A `logLevel` of `warn` or `error` drops them,
and so does nix-darwin's `logFile = null`, which discards the daemon's output,
as [the options](service.md#options) say.

## Socket directory

The socket and each directory the daemon makes on the way to it take the
daemon's group before their mode lets that group in, whichever group the system
gives a new file ([Linux](https://man7.org/linux/man-pages/man2/open.2.html),
[macOS](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/open.2.html)).
A directory the daemon makes is mode 0750. The daemon binds the socket first in
a directory of its own beside the path, mode 0700 and named `.control-` and a
number, sets the socket's group and mode there and renames it onto the path, so
only the daemon's user can reach it before its mode is set. That directory is
removed once the socket is in place, and its name adds up to 20 bytes to the
path the socket is first bound at, which [limits](#limits) counts.

A directory that already exists keeps its group and mode. On macOS, a directory
in the group `daemon` keeps the socket out of reach of the daemon's group. Stop
the daemon, give the directory the daemon's group with `chgrp`, and start the
daemon again. A reboot works as well, because it clears `/var/run` and the
daemon makes the directory again.
[Running it as a service](service.md#nix-darwin) gives the commands for the
nix-darwin job. Under the NixOS module, systemd makes `/run/ranet3` in the
unit's group and removes it when the unit stops.

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

```console
$ ranet3 status
Node        example/laptop
Version     2026.912.0+860393bf1c2e
Uptime      3h12m0s
Port        13000
Endpoints   0/ip6 1/ip4
TUN         ranet0 MTU 1400 queues 16
Role        initiator, responder, full mesh, no transit
Forwarding  IPv4 on IPv6 on
Registry    /etc/ranet/registry.json, 6 nodes in 2 organizations
Kernel      table 200 protocol 155, 14 installed, last pass 12 seconds ago
Egress      off, this node carries no traffic for others
Antispoof   nftables table inet ranet3 chains antispoof and mesh_entry, inside ranet0 lo, 3 overlay prefixes, dropped 2 overlay sources and 0 carved sources, dropped 0 entering the mesh
Dialers     5 running
Sessions    2
Neighbors   2, 2 alive
Routes      14 prefixes, 11 selected, 3 originated
Originate   203.0.113.10/32 3fff:a::203:0:113:10/128 3fff:b:0:100::/60
Segments    3fff:b:0:106::1 End.DT46 (0 forwarded, 5 delivered, 0 dropped)
Steering    from 3fff:a::203:0:113:10/128 via 3fff:b:0:206::1 (12 steered, 2 with no route to their first segment)
Transit     0 forwarded, 5 delivered, 4 dropped (3 multicast, 1 forged)
ESP         41822931 in, 0 dropped by their sessions, 14 datagrams refused

$ ranet3 neighbors
Peer                 State  Cost  Extra  Rx cost  RTT      Routes  Expires  Dropped  Failed
example/gateway:0@0  up     116   0      96       27.2ms   7       11.3s    0        0
other/relay:2@1      up     1218  1024   96       176.7ms  5       9.8s     0        0

$ ranet3 routes
Destination        From         Via                  Metric  Router ID         Seqno  Paths
::/0               3fff:a::/36  example/gateway:0@0  212     0a1b2c3d4e5f6071  42     2
3fff:b:0:100::/60               this node            0                         0      0
```

`neighbors` is the counterpart of `birdc show babel neighbors`. It shows the
neighbor's reported Rx cost beside this node's cost, which tells a link that
carries 1 way from one that carries neither. Extra is the part of the cost
`cap.babel.cost.extra` charges the neighbor, which this node's IHUs add to the
receive cost they report as well. It also shows 2 dataplane counters BIRD lacks.

`routes` is the counterpart of `birdc show route`. It reads the Babel route
table, not the forwarding table, so a prefix every neighbor has retracted still
shows as a row. A prefix this node announces and an address `cap.table` assigns
it show as rows via `this node`. `sessions` is the counterpart of
`swanctl --list-sas`. `peers` lists who this node dials, from the config file or
from the trust document under `dial.all`, and whether it got there.

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

- `rekey`, `debug probe`, `debug pmtu` and `debug sender` take a session by its
  name, its peer's endpoint, that endpoint's node, or the node's name alone. The
  name alone takes that name in every organization. A dialer's name matches only
  a session of exactly that name. To take the sessions of a dialer with no
  endpoint pinned, name their node.
- `redial` takes the same names and a dialer by its name. The name of an
  endpoint or a session also wakes the dialer of that node with no endpoint
  pinned.
- `debug events --peer` takes the same names as `rekey` and a dialer's name. A
  dialer's name selects a dial's events until its endpoint resolves.

A name matches whole. `example/gateway` takes no session of `example/gateway2`.
A name with a serial and no organization, such as `gateway:1`, names nothing.
For `redial`, `rekey` and `debug probe`, completion offers the peers the daemon
dials and the nodes it holds a session with. For `debug pmtu` and
`debug sender`, it offers the nodes of its sessions. For `debug events --peer`,
it offers the names the recorded events carry.

### Questions

4 more commands answer questions instead of printing 1 subsystem:

- `whois <address>` is a longest prefix match over the Babel route table. It
  prints the prefix that covers the address and the peer this node reaches it
  through, then what the address would fall back to. It names the peer, not the
  originating node, because Babel carries a router id and no name, and ranet3
  gives each speaker a random router id. A prefix of this node's own is named as
  originated by this node, or as assigned to it for an address `cap.table`
  assigns.
- `ip` prints this node's own mesh addresses, 1 per line, the `mesh_addresses`
  of its status.
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
POST.

| Path                 | Method    | Request                                                            | Answer                              |
| -------------------- | --------- | ------------------------------------------------------------------ | ----------------------------------- |
| `/v0/status`         | GET, HEAD | none                                                               | the node, a JSON object             |
| `/v0/neighbors`      | GET, HEAD | none                                                               | Babel neighbors, a JSON list        |
| `/v0/routes`         | GET, HEAD | none                                                               | Babel routes, a JSON list           |
| `/v0/sessions`       | GET, HEAD | none                                                               | IKE sessions, a JSON list           |
| `/v0/peers`          | GET, HEAD | none                                                               | dialed peers, a JSON list           |
| `/v0/metrics`        | GET, HEAD | none                                                               | the Prometheus text format          |
| `/v0/disable`        | POST      | `subsystem`                                                        | a result                            |
| `/v0/enable`         | POST      | `subsystem`                                                        | a result                            |
| `/v0/redial`         | POST      | `peer` or `all`                                                    | a result                            |
| `/v0/rekey`          | POST      | `peer` or `all`                                                    | a result                            |
| `/v0/reload`         | POST      | empty body                                                         | a result                            |
| `/v0/down`           | POST      | empty body                                                         | a result                            |
| `/v0/up`             | POST      | empty body                                                         | a result                            |
| `/v0/debug/events`   | GET, HEAD | query `kind`, `peer`, `attr`, `since`, `follow`                    | events, 1 JSON object per line      |
| `/v0/debug/pmtu`     | GET, HEAD | query `peer`                                                       | path MTU view, a JSON object        |
| `/v0/debug/sender`   | GET, HEAD | query `peer`                                                       | sender view, a JSON object          |
| `/v0/debug/runtime`  | GET, HEAD | none                                                               | process view, a JSON object         |
| `/v0/debug/updown`   | GET, HEAD | none                                                               | up and down view, a JSON object     |
| `/v0/debug/netmon`   | GET, HEAD | none                                                               | network watch view, a JSON object   |
| `/v0/debug/rules`    | GET, HEAD | none                                                               | rules view, a JSON object           |
| `/v0/debug/route`    | GET, HEAD | query `src`, `dst`, `iif`, `peer`                                  | route view, a JSON object           |
| `/v0/debug/egress`   | GET, HEAD | none                                                               | exit view, a JSON object            |
| `/v0/debug/segments` | GET, HEAD | none                                                               | segments view, a JSON object        |
| `/v0/debug/probe`    | POST      | `peer` or `all`                                                    | a result                            |
| `/v0/debug/trace`    | GET       | query `src`, `dst`, `proto`, `decision`, `peer`, `rate`, `payload` | trace lines, 1 JSON object per line |

A trace's query takes `src` and `dst` each up to 16 times, a prefix or an
address, `proto` a protocol number or one of `icmp`, `tcp`, `udp`, `gre`, `esp`,
`ah`, `icmpv6` and `sctp`, `decision` one of `deliver`, `forward`, `egress`,
`answer` and `drop`, `peer` a peer named as `redial` names one, `rate` from 1 to
10000 records a second, 1000 where it is left out, and `payload` from 0 to 65535
bytes. Each line is an object holding a `packet` or a `note`. A `note` is
`stream.live` first, then `stream.dropped` once a second while records were
refused, with `rate` and `queue`, `stream.heartbeat` on a quiet stream, and
`stream.closed` with its `reason` when the daemon ends the trace. A `packet`
holds `arrival`, `from`, `decision`, `reason`, `next`, `segment`, `src`, `dst`,
`proto`, `headers`, `transport`, `src_port`, `dst_port`, `tcp_flags`,
`icmp_type`, `icmp_code`, `hop_limit`, `length`, `fragments`, `answer`,
`outcome` and `payload`, the bytes in base64, as
[debugging](development/debug.md#trace-records) describes, each but `arrival`,
`decision`, `src`, `dst`, `proto`, `hop_limit` and `length` left out where it is
empty or 0.

### Requests and answers

A verb's body is a JSON object with the fields `subsystem`, `peer` and `all`.
Each verb reads the fields it needs and ignores the others. Once the node runs,
a body that names a field twice, names a member other than these 3, a field
written in another case among them, or holds a string that is not valid UTF-8 is
answered 400 and the verb does not run. An empty body is the empty request,
which `reload`, `down` and `up` take. A verb answers with a result. Its `acted`
lists the subsystems or paths the verb reached, its `missed` each path the verb
did not reach, by `entry` and `reason`, and its `detail` is the sentence the
command prints. A command whose answer holds a `missed` exits 1 once it has
printed the answer.

The reads answer JSON. A duration is a string such as `"4s"`. A time follows
RFC 3339. An address or a prefix is its text form. An optional field with no
value is left out, such as `down` on a node that is up or `err` after a pass
that succeeded. `endpoints`, `originate` and `mesh_addresses` are always present
and read `[]` when empty, and every counter is always present but
`kernel.exit.fallback.dropped`, which is absent until a read of the kill
switch's chains by this process has succeeded, and on macOS always. Other lists,
such as `segments`, `disabled`, `taken`, `acted` and `missed`, are left out when
empty.

| Answer             | Fields                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| status             | `version`, `node`, `port`, `endpoints` (`serial/family`), `tun`, `mtu`, `queues`, `started_at`, `uptime`, `initiator` (this node has a peer to dial, from `dial.to` or `dial.all`), `responder` (`link.listen` is on), `full_mesh` (`dial.all` is on), `no_transit` (`cap.transit` is off), `forwards_ipv4`, `forwards_ipv6` (`null` where the node cannot read the setting, which `status` prints as `unknown`), `registry`, `kernel`, `egress`, `antispoof` (absent off Linux where no `overlay` is written), `counts`, `esp`, `originate`, `mesh_addresses` (the address of each host prefix `cap.route` announces or `cap.table` assigns, once, among which an exit's in rule takes its address under `auto`, as [classes](exit-nodes.md#classes) describes), `segments`, `steering`, `segment_counters`, `transit`, `disabled`, `down`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `registry`         | `path`, `organizations`, `nodes`, `read_at`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `kernel`           | `enabled`, `where`, `table`, `protocol`, `pass_at`, `installed`, `skipped`, `added`, `removed`, `cover` (each family whose zero-free cover the last pass left in, on macOS), `taken` (each lookup another program's rule takes, or on macOS another program's route, overlay lookups alone, as [sharing a host](coexistence.md#another-programs-rules) describes: `family`, then `prefix` and the `address` asked inside it for an overlay prefix or `endpoint` for the underlay with the `source` and `interface` the live session's send carries, each absent where it carries none, and `answer`), `exit` (absent in mode off, and on macOS holding `unaddressed` and `fallback` alone: `forwarded`, the links `cap.exit.forward` expanded to on the last pass, `skipped`, each link an entry matched and the pass left out as `entry`, `link` and `reason`, and `unaddressed`, each family the tun holds no overlay address of, as [watching it](routing.md#watching-it) gives, and `fallback`, absent but under `fallback = "none"`: `state`, `holding`, `passing` or `not holding`, `reason` while it does not hold, `dropped`, the `packets` and `bytes` the last lines of both chains have dropped, summed, absent until a read of its chains by this process has succeeded, `uncounted`, true on macOS, whose [rejects](routing.md#the-kill-switch-on-macos) count no drops, where `dropped` stays absent, `captured`, each connected network left out of the LAN as it captures the machine, `public`, each one the private and link-local ranges and `cap.exit.lan` leave out in whole or in part, or of one sharing an address with the overlay each such prefix of its part outside the overlay, `unresolved`, each endpoint name whose last lookup failed, in any state of the switch, and `resolvers`, on Linux each DNS server beyond the LAN as `link` and `address`), `exit_path` (absent outside [mode 3](routing.md#mode-3-on-linux): `via`, `source`, `state`, `up` or `down`, `down` and `verdict`, the first segment that does not resolve and the mesh's answer, `installed`, the families whose steered default, or on macOS its zero-free cover, the last pass left in the table, and `steered` and `unrouted`, the path's part of `segment_counters`' totals), `err` |
| `egress`           | `enabled`, `where`, `ready` (`ipv4`, `ipv6`, the families the last pass judged ready, by the route lookups where they ran), `unready` (why a family it translates is not ready, such as a lookup that failed or left by another device, with the sysctls that explain it, or an address of its classes the host does not hold), `skipped` (the lookups the pass left out and why), `translate` (each class's `from` and `to`, `none`, `auto` or an address), `return`, `advertise`, `announced`, `flows_per_source` (the share in force), `refused` (`ipv4`, `ipv6`, the packets refused past it as of the last pass, from zero after a pass that rewrote the chains), `dropped` (`ipv4`, `ipv6`, the packets dropped with no tracked flow, out of the mesh under a class that translates and into it under `return`, counted as `refused` is), `pass_at`, `installed`, `flows`, `bytes`, `untranslated` (the connections a class of `none` left under their source), `conntrack_count` and `conntrack_max` (the host's connection table, each left out where the pass could not read it), `conflicts`, `err`, `userspace` (the userspace exit's detail, absent for an exit that installs rules, whose rules' counts then read zero and conntrack's are absent: `tcp`, `udp` and `echo` (`ipv4`, `ipv6`, the flows open, a UDP mapping and each of its destinations one flow each), `dialing`, `time_wait`, `limits` (`budget`, `from` (`go_limit` or `host`), `flows`, `connections`, `dials`, `time_wait`, `window`, `lanes`, `link`), `buffered` (the bytes its TCP buffers hold now), `refused` and `dropped` (by reason), `reused` (the endpoints in TIME_WAIT a new SYN reused), `closed` (those closed early past the cap), `sources` (`source`, `flows`, the sources holding the most flows, most first)). Under the userspace exit `refused` counts the flows refused past their source's share as they happen                                                                                                                                                                                                                                                                                                                                                                         |
| `antispoof`        | `where`, `inside`, `overlay`, `carved` (each carve-out's `link` and `prefix`), `ready`, `unready`, `pass_at`, `installed`, `dropped` (`overlay_source_ipv4`, `overlay_source_ipv6`, `carved_source_ipv4`, `carved_source_ipv6`, `mesh_entry_ipv4`, `mesh_entry_ipv6`, each in packets as of the last pass and present where a rule of that pass writes the drop, which leaves out the last 2 on macOS), `err`, on macOS `pf` (`anchor`, `token`, a string since it uses all 64 bits, `pid`, `listed`, whether pf lists the token under the pid, and `called`, whether the main ruleset calls `com.apple/*` for every packet in, as the last pass read them), and on a platform that runs no filter `unenforced_on`, the platform, and `overlay`, with `inside` and `dropped` null, `ready` false and `installed` 0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `counts`           | `dialers`, `sessions`, `neighbors`, `neighbors_alive`, `prefixes`, `selected`, `originated`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `esp`              | `inbound_packets`, `inbound_dropped`, `inbound_ce`, `inbound_ecn_unused`, `receive_dropped`, `receive_refused`, `keepalives`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `originate`        | a list of `prefix` and `from`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `segment_counters` | `forwarded`, `delivered`, `dropped`, `steered`, `unsteered`, `unrouted`, `answered`, `egressed`, `refused`, `not_ready`, `ecn_unused`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `transit`          | `forwarded`, `delivered`, `expired`, `no_route`, `held`, `refused`, `invalid`, `martian`, `source_route`, `unrouted_source`, `not_ready`, `too_big`, `session_multicast`, `multicast`, `forged`, `routing_header`, `sid`, `unowned_source`, `nested`, `looped`, `answered`, `unanswered`, `unsent`, as [metrics](metrics.md#transit-counters) counts them                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `down`             | `since`, `for`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| neighbor           | `peer`, `address`, `alive`, `cost`, `extra`, `reported_cost` (absent until an IHU arrives), `rtt` (absent until a timestamped IHU arrives), `routes`, `expires`, `dropped`, `send_failed`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| route              | `destination`, `from`, `via` (absent for a prefix held unreachable and for this node's own), `metric`, `router_id`, `seqno`, `candidates`, `originated` (this node announces it), `assigned` (an address `cap.table` assigns, announced only where `originated` is set too)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| session            | `path`, `peer` (the peer's node), `remote` (address and port), `preferred` (whether the end whose endpoint sorts first dialed the session, the same at both ends, endpoints sorting by their unescaped organization, then name, then serial, each byte by byte: a session the other end dials does not replace that one unless its `IKE_AUTH` carried the other end's `INITIAL_CONTACT` and that one was taken before it started, as [closing SAs](design/protocol-deviations.md#closing-sas) describes, a newer one the same end dials does, and the other end's dialer stands down behind it, healthy or not, until it ends), `role` (`initiator` where this node sent the session's `IKE_SA_INIT` and `responder` where it answered it), `active`, `local_spi`, `remote_spi`, `ike_cipher`, `ike_prf` and `ike_kex` (the IKE SA's transforms by their `cap.crypto` names, `ike_kex` its whole kex entry, such as `x25519+mlkem768`), `esp_cipher` and `esp_kex` (the Child SA's, `esp_kex` the kex entry of its own key exchanges, absent for a Child SA keyed from the IKE SA alone), `ike_fragments` (whether both ends said they support the IKE fragmentation of RFC 7383) and, where they did, `ike_fragment_threshold` (the path's threshold, the largest IP datagram this node cuts a new IKE message to fit, as [paths under 1280 bytes](design/limits.md#paths-under-1280-bytes) gives it), `started_at`, `age`, `idle`, `invalid_spi_reports` (the `INVALID_SPI` notifies the session sent its peer)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| peer               | `path`, `peer`, `connected`, `generated` (taken from the trust document under `dial.all`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| result             | `acted`, `missed` (`entry`, `reason`), `detail`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Status codes

| Code | When                                                                                                                                                                                                                                                                         |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 200  | The read or the verb succeeded.                                                                                                                                                                                                                                              |
| 400  | The node refused a verb, a body or query does not parse, a query names more kinds, attributes or prefixes than the limits allow, or a trace's rate or payload is out of its bounds. The body says why.                                                                       |
| 404  | No such path.                                                                                                                                                                                                                                                                |
| 405  | The method does not fit the path. `Allow` names the one that does.                                                                                                                                                                                                           |
| 500  | The daemon could not encode its answer. The body says why.                                                                                                                                                                                                                   |
| 501  | The program serving the socket does not implement that verb or debug view. The daemon implements them all.                                                                                                                                                                   |
| 503  | A 5th stream, of events or a trace, asked for while 4 are open, a trace asked for while the daemon stops, or any request but `reload` while the start waits for the key or the trust document, as [restarts and the network](service.md#restarts-and-the-network) describes. |

### Limits

| Limit                                                     | Value                                                                                     |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Connections open at once                                  | 32, and the daemon closes the next one as it accepts it                                   |
| Idle connection between requests                          | closed after 30 seconds                                                                   |
| Request headers                                           | 5 seconds                                                                                 |
| Writing an answer, a stream excepted                      | 30 seconds                                                                                |
| Verb body the daemon reads                                | 64 KiB                                                                                    |
| Streams open at once, of events and traces together       | 4                                                                                         |
| Source and destination prefixes in 1 trace query          | 16 of each                                                                                |
| 1 stream write waiting on its reader                      | 5 seconds, then the stream ends                                                           |
| Heartbeat on a quiet stream                               | every 15 seconds                                                                          |
| Kinds in 1 events query                                   | 16                                                                                        |
| Attributes in 1 events query                              | 16                                                                                        |
| Socket path                                               | 83 bytes, the 103 a unix socket holds less the 20 the directory it is first bound in adds |
| 1 exchange of `ranet3` with the daemon, a stream excepted | 10 seconds                                                                                |
| Wait of `rekey` for the rekeys it asked for               | 5 seconds                                                                                 |
| Answer `ranet3` reads                                     | 64 MiB                                                                                    |
| 1 stream line `ranet3` reads                              | 1 MiB                                                                                     |
| Events in 1 stream write                                  | 64                                                                                        |

The table holds once the daemon serves the node. While the start waits for the
key or the trust document, as
[restarts and the network](service.md#restarts-and-the-network) describes, the
socket bounds reading a request and writing its answer to 10 seconds each, and
holds no bound on the connections open at once.

## Acting on a running node

7 subcommands change what a node is doing right now. `disable` and `enable` stop
and start a subsystem, which is `reconciler`, `steering` or `responder`.
`redial` and `rekey` take a peer or `--all`. `rekey` asks each session to
replace its Child SA, all at once, and answers when every rekey has ended, after
5 seconds at most, or once its caller has gone away. Its `acted` lists the
sessions that rekeyed, and its `missed` each that did not with the error the
session's rekey gave, such as the peer's refusal, a rekey already under way, a
rekey still running at 5 seconds, or a failed Child SA rekey whose replacement
waits for the retry the session has scheduled, as `cap.crypto.rekey.retry` sets.
A rekey still running goes on, and `ike.rekey.completed` or `ike.rekey.failed`
tells how it ended. `reload` does what SIGHUP does once the node runs, so a
supervisor is not the only way to ask, and the start's wait for the key or the
trust document answers it otherwise, as
[restarts and the network](service.md#restarts-and-the-network) describes.
`down` takes the node off the mesh and `up` puts it back, as
[taking a node off the mesh](#taking-a-node-off-the-mesh) describes.
`debug probe` acts as well.

None of them changes the configuration. A node's configuration is its file, and
that stays its only entry point. What these act on is operational state the file
already decides: `cap.table`, `cap.segment`'s steering, `link.listen`, the peers
list and the file itself. `down` asks for no more than a file without peers,
`link.listen`, `cap.table` or `cap.egress` would. No verb reaches past what the
file can express, such as a peer, a key or an address, and the subsystem names
are a closed set. The 2 halves are told apart by method rather than by path: a
read answers GET and HEAD and nothing else, and a verb answers POST alone.

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
- `steering` where `cap.segment` names no steer policy, `cap.exit.via` or not
- `responder` while `link.listen` is off

A subsystem already in the state asked for is reported as such, and the command
succeeds. `enable` is refused while the node is down.

Each verb acts as follows:

- `disable reconciler` withdraws every route, address and rule the reconciler
  installed, as `birdc disable` does to a kernel protocol, instead of freezing a
  table nobody maintains. Under
  [the kill switch](routing.md#the-kill-switch-on-linux) that takes 5450 and the
  kill switch's chains in `inet ranet3` too, or on macOS
  [the rejects](routing.md#the-kill-switch-on-macos), so the host's traffic
  leaves by the uplink until `enable reconciler`. A withdrawal the kernel
  refuses in part is retried on the backoff of a failed pass until it completes.
  The `Kernel` line of `ranet3 status` carries its error until then.
- `disable steering` leaves the steer policies loaded and stops acting on them,
  so a diagnostic still reports what was stopped. It leaves `cap.exit.via`'s
  path, which removing `via` turns off, as
  [segment routing](segment-routing.md#steering) says.
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

The daemon binds the socket while it starts. While the start waits for the key
or the trust document, the socket answers at once, as
[restarts and the network](service.md#restarts-and-the-network) describes. From
the end of that wait, the node answers on the socket once the start has waited
for the reconciler's first pass, so a command sent before then is answered once
that wait ends, unless its own timeout ends first. A stop while the daemon
builds its parts or waits for that pass closes the socket without serving it,
and a command sent in the meantime fails with the connection reset. Once a
daemon that serves the socket has begun to stop, on a signal or the mesh's
failure, `up`, `reload` and `redial` are refused with an error saying the node
is stopping, and the reads answer until the socket closes as the daemon exits. A
refusal rather than a closed socket keeps `status` and the debug views answering
through a slow withdrawal. No verb sent once the stop has begun starts a dialer,
and the dialers running then, one an `up` already under way started among them,
stop with the mesh once the reconciler and the egress translator have withdrawn.

## Taking a node off the mesh

`ranet3 down` takes a node off the mesh and leaves its daemon running. Every
dialer stops and no new one starts, the responder stops answering IKE where
`link.listen` is on, every session is closed with an IKE Delete, and the Babel
speaker stops. Where `cap.table` is set, the reconciler withdraws the routes,
rules and tun addresses it installed and
[the kill switch's](routing.md#the-kill-switch-on-linux) chains, or on macOS
[its rejects](routing.md#the-kill-switch-on-macos). On an exit node the exit
withdraws its advertisement, and on Linux its chains, while on macOS it ends
each dial, resets each connection and ends each mapping. The daemon, the tun,
the control socket, the metrics and the debug views stay, and the node still
answers every read. A ranet3 peer drops its routes through the node when the
Delete arrives, rather than when the Babel neighbor would have timed out.

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

`ranet3 up` removes the flag before it acts. It then starts every dialer, the
responder and the speaker at once, and answers without waiting for what it hands
back. The addresses, rules and routes, and
[the kill switch's](routing.md#the-kill-switch-on-linux) chains, or on macOS
[its rejects](routing.md#the-kill-switch-on-macos), where `fallback = "none"`
asks for it, come back on the reconciler's next pass, which `up` wakes. On an
exit node the advertisement, and on Linux the translator's chains, come back on
the exit's next pass, which `up` wakes too. Unlike a start, which waits for the
reconciler's first pass before it dials, `up` can dial before the switch is
back. A subsystem somebody disabled stays disabled. A `down` on a node that is
down and an `up` on one that is up succeed and say so. While the node is down,
`redial`, `rekey`, `enable` and `debug probe` are refused with an error saying
it is down. A reload applies the file and the trust document and leaves the node
down, and a peer the reload adds is dialed after `up`.

```console
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
Transit     0 forwarded, 0 delivered, 0 dropped
ESP         0 in, 0 dropped by their sessions, 0 datagrams refused

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

There is no login flow. A node's identity is its private key and its entry in
the trust document, both in place before the daemon starts.
