---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Control socket"
description: "Asking a running node questions, and the verbs that act on one."
created: 2026-09-21
updated: 2026-10-08
order: 80
---

`--control /var/run/ranet3/control.sock` is where the daemon answers, and is the
default, so a node is askable without having been configured to be.
`--control ""` turns it off. The socket is mode 0660 in the daemon's group,
which the unit names, and that mode authorizes every path outside `/v0/debug/`.
[The verbs](#acting-on-a-running-node) say what keeps it sufficient for them.
The debug paths are authorized by the caller's peer credentials instead. Their
snapshots and the event stream are open to the socket's group, and profiles,
dumps, logs, captures, the trust document and every action take root or the
daemon's own user, as [debugging](development/debug.md) describes. A caller is
bounded by an idle timeout and by a limit on the connections open at once across
every caller, because a client that accumulates them costs the daemon a
descriptor apiece and a node out of descriptors is one that cannot be asked
anything at all. Past that limit a connection is closed as it is accepted, so a
client holding every place is refused at once rather than left waiting, and a
shutdown is not held up behind it.

The socket takes the daemon's group on every platform, and so does each
directory the daemon makes on the way to it, at mode 0750. linux gives a new
file the group of the process that makes it, outside a setgid directory, while
darwin gives it the group of the directory it is made in, which under `/var/run`
is `daemon`. The daemon sets the group itself, before the mode lets that group
in. A directory that is already there is left as it is, and one an earlier
version made keeps its group until it is removed, which on darwin leaves the
socket out of its group's reach. Stop the daemon, remove the directory and start
the daemon again, which makes it afresh.
[Running it as a service](service.md#nix-darwin) gives the commands for the
nix-darwin job. Under the nixos module systemd makes `/run/ranet3` in the unit's
group and removes it when the unit stops, so an earlier version's directory
never outlives that version.

Which process owns the path is settled by an exclusive lock on a sibling file
rather than by dialing the socket to see whether anything answers, since a live
daemon out of descriptors and one whose socket the caller cannot open both fail
to answer and neither has stopped owning its path. A socket a dead instance left
behind is cleared under that lock, a path that is not a socket is refused by
name, and a path an operator named and this node cannot bind refuses the
startup. The default path warns and carries on instead, because it is on without
having been asked for.

The version a node reports is `version.txt` and the commit the binary was built
from, because `version.txt` moves once per release and a fleet is converted one
node at a time in between. `ranet3 version` asks the binary the same question
without a node running, and `ranet3 version --daemon` asks the node, which is
how the two are told apart during a conversion.

The subcommands read it and print a table, or the wire form with `--json`:

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
Peer               State  Cost  Rx cost  RTT      Routes  Expires  Dropped  Failed
example/gateway@0  up     116   96       27.2ms   15      11.3s    0        0
example/relay@1    up     194   96       176.7ms  130     9.8s     0        0

$ ranet3 routes
Destination  From         Via                Metric  Router ID         Seqno  Paths
::/0         3fff:a::/36  example/gateway@0  212     0a1b2c3d4e5f6071  42     7
```

`neighbors` answers `birdc show babel neighbors`, with the neighbor's own
reported Rx cost beside this node's cost so a link that carries one way can be
told from one that carries neither, and with the two dataplane counters BIRD has
no equivalent of. `routes` answers `birdc show route`, over the Babel route
table rather than the forwarding table, so a prefix every neighbor has retracted
is still a row, which is the case an operator is looking for. `sessions` answers
`swanctl --list-sas`. `peers` lists who this node dials, from the config file or
from the trust document under `dial.all`, and whether it got there.

Four more answer questions rather than printing one subsystem. `whois <address>`
is a longest prefix match over that route table: it says which prefix covers an
address and which peer this node reaches it through, then what the address would
fall back to. It names the peer and not the originating node, because Babel
carries a router id and no name and this tree gives each speaker a random one,
so an origin is nameable only where it is a neighbor. `ip` prints this node's
own mesh addresses, one per line, taken from the host prefixes it announces.
`exit list` is the defaults the mesh advertises and which of them this node
would take, with a withdrawn one told from one that is carrying traffic.
`bugreport` is every subsystem in one JSON object, and a read that did not
answer leaves its own line in it rather than replacing the report, so a node
that is half up still produces one.

`metrics` prints the same scrape the metrics listener serves, read over the
control socket, so a node's counters are readable without it binding a port a
fleet then has to firewall.

## Acting on a running node

Five subcommands change what a node is doing right now. `disable` and `enable`
stop and start a subsystem, which is `reconciler`, `steering` or `responder`.
`redial` and `rekey` take a peer or `--all`. `reload` does what SIGHUP does, so
a supervisor is not the only way to ask.

None of them changes the configuration. A node's configuration is its file, and
that stays its only entry point. What these act on is operational state the file
already decides: `cap.table`, `cap.segment`'s steering, `link.listen`, the peers
list and the file itself. Whoever may edit that file could already ask for every
one of them, by editing and restarting if not by editing and sending SIGHUP, so
the socket's mode grants nothing the file's permissions did not, and a verb that
reached past what the file can express would break that and is refused on those
grounds. The subsystem names are a closed set for the same reason. The two
halves are told apart by method rather than by path: a read answers GET and
nothing else, and a verb answers POST alone.

The state lives in the process. A restart starts everything the file names, and
a reload leaves a stopped subsystem stopped, because the trust document is
rewritten every time any node joins the mesh and a reload that started one again
would undo a decision an operator took minutes earlier on a schedule nobody
chose. A node running less than its file says reports it on the `Disabled` line
of `ranet3 status`, which is the only place that difference shows.

`disable reconciler` withdraws every route, address and rule the reconciler
installed, as `birdc disable` did to a kernel protocol, rather than freezing a
table nobody is maintaining. A withdrawal the kernel refuses part of is retried
on the backoff of a failed pass until it completes, and the `Kernel` line of
`ranet3 status` carries its error until then. `disable steering` leaves the
policies loaded and stops acting on them, so a diagnostic still reports what was
stopped. `disable responder` refuses the next handshake and leaves the sessions
this node already holds alone. `redial` is for a peer that dials this node and
cannot be dialed back, which does not retry on its own and has been seen to
carry a dead session for sixteen minutes. It drops what this node holds for that
peer and sets its dialers going at once rather than after the reconnect delay.
`redial --all` does the same for every session and every dialer, for a network
change the node's watch cannot see, such as a captive portal that changes no
address or route. Both refuse a peer together with `--all`, and neither.

This is still not the daemon and client split tailscale has: there is no login
flow here, identity being a static key and a registry entry that nix and sops
put in place before the process starts.
