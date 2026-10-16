---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Configuration reference"
description: "Every key the configuration file takes, its default and what it refuses."
created: 2026-10-16
updated: 2026-10-17
order: 35
---

This page lists every key the configuration file takes.
[Configuration](configuration.md) describes the file as a whole.
[Reloading](reloading.md) says which keys a reload applies and which need a
restart.

Keys are written as TOML paths, such as `cap.table.rules`. YAML and JSON nest
the same names. A key not listed here is refused when the file loads.

## When a value is checked

- **At load**: every time the file is read, at startup and on every reload. A
  file that fails is refused whole.
- **At startup**: when the daemon starts. These checks need the platform or the
  trust document. A file that names a Linux-only key loads on macOS, and the
  daemon there refuses to start on it.
- **On reload**: a reload runs the checks of `node`, `auth.key` and
  `link.endpoints` against the trust document again, and refuses a file that
  fails them. It refuses a key the platform lacks, and a `cap.route` entry equal
  to a `cap.egress.advertise` prefix, as a startup does. It logs a peer the
  trust document cannot support instead of refusing the file.

## Spellings

| Kind     | Spelling                                                           | Example                      |
| -------- | ------------------------------------------------------------------ | ---------------------------- |
| duration | as Go writes one, or a bare `0`                                    | `"4s"`, `"250ms"`, `"1h30m"` |
| prefix   | an address and a length                                            | `"2001:db8::/48"`            |
| address  | no length and no zone                                              | `"2001:db8::1"`              |
| table    | a number, or `main` (254), `local` (255) or `default` (253)        | `200`, `"main"`              |
| integer  | whole digits, and hex in TOML and YAML                             | `13000`, `0x726c`            |
| name     | `organization/name`, or `organization/name:serial` for an endpoint | `"example/gateway:0"`        |

- JSON has no hex spelling. A `.json` file writes the decimal number.
- An integer written with a fraction, an exponent or a minus sign is refused
  with its line.
- In a name, a byte outside letters, digits, `-`, `.`, `_` and `~` is written as
  `%` and 2 uppercase hex digits. The organization `nick cao` is `nick%20cao`.
  No other spelling is taken.

## Top level

| Key    | Value | Default  | Meaning                                   |
| ------ | ----- | -------- | ----------------------------------------- |
| `node` | name  | required | This node, as the trust document names it |

- `node` names a node. An endpoint name is refused. This node's endpoints are
  `link.endpoints`.
- At startup and on every reload, the trust document must name the node. The
  public half of `auth.key` must be the key of the organization block that lists
  the node.

## `auth`

| Key     | Value | Default  | Meaning                                                 |
| ------- | ----- | -------- | ------------------------------------------------------- |
| `key`   | path  | required | This node's private key, a PKCS8 PEM Ed25519 file       |
| `trust` | path  | required | The [trust document](trust.md), a ranet `registry.json` |

## `link`

| Key         | Value   | Default                                      | Meaning                                          |
| ----------- | ------- | -------------------------------------------- | ------------------------------------------------ |
| `port`      | integer | required                                     | UDP port of the socket that carries IKE and ESP  |
| `endpoints` | list    | required, at least 1                         | This node's endpoints in the trust document      |
| `listen`    | boolean | `false`                                      | Answer handshakes from peers, as well as dialing |
| `tun`       | string  | `ranet3` on Linux, next free `utun` on macOS | The device the mesh runs on                      |
| `mtu`       | integer | `1400`                                       | Largest packet a session carries inside ESP      |

- `port` is bound for every address family the platform has. Port 500 is
  refused. Every IKE message here carries the Non-ESP Marker, and RFC 7296
  section 2.23 forbids UDP encapsulation on port 500.
- Each `endpoints` entry is `{ serial = "0", family = "ip4" }`. `serial` is a
  non-empty string, unique in the list. `family` is `ip4` or `ip6`.
- At startup and on every reload, each `endpoints` entry must match an endpoint
  the trust document gives this node, in the same family. A local endpoint dials
  only remote endpoints of its own family.
- With `listen` off and `dial.all` off, `dial.to` needs at least 1 entry.
- On Linux, `tun` attaches to an existing device of that name and creates it
  otherwise. The default `ranet3` is never attached to: the daemon refuses to
  start when a device called `ranet3` exists. On macOS, `tun` takes only `utun`
  and `utunN`, and the daemon refuses any other name at startup.
- The device runs at `mtu` less the header of the longest `cap.segment.steer`
  list. A value that leaves the device under 1280 bytes, or a value over 65470,
  is refused at load. [Path MTU](path-mtu.md) describes how sessions use it.

### `link.underlay`

This block keeps the socket that carries IKE and ESP out of the routes the mesh
installs. A node that takes an exit's default route needs the key for its
platform. `mark` is refused at startup on every platform but Linux, and `bind`
on every platform but macOS.

| Key    | Value   | Default    | Meaning                                                                  |
| ------ | ------- | ---------- | ------------------------------------------------------------------------ |
| `mark` | integer | `0` (none) | Linux only. `SO_MARK` on the socket                                      |
| `bind` | boolean | `false`    | macOS only. Bind the socket to the interface of the host's default route |

- `mark` does nothing until a policy rule sends marked packets to a table the
  mesh does not write. Write that rule under `cap.table.rules`, for example
  `{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }`.
- When `cap.table` is written and none of its rules selects `mark` and looks up
  a table other than `id`, the file is refused at load. A rule with an `iif`
  other than `lo` does not count, since the socket's own packets arrive on `lo`.
- `bind` sets `IP_BOUND_IF` and `IPV6_BOUND_IF`. The socket follows the default
  route's interface as it changes.
- With `bind`, the reconciler installs a plain `/0` that Babel selects as its
  zero-free cover, 8 unscoped routes per family that hold every address but
  `0.0.0.0/8` and `::/8`, so other sockets use the mesh exit. `64:ff9b::/96`
  lies in `::/8` and stays on the host's own route. Until exit selection exists,
  a Mac with `bind` set takes whichever `/0` Babel selects.
- With `bind`, any other route that carries this host's own traffic is installed
  unscoped too, except one that covers an endpoint address listed in the trust
  document, which stays scoped to the tun.
- With `bind`, the daemon writes a default scoped to the socket's interface only
  for a family whose zero address an unscoped route out of another interface
  holds: a real lower half, `0.0.0.0/1` or `::/1`, or a route like `0.0.0.0/24`
  the mesh installs, or another program's, such as a full-tunnel VPN's. It
  withdraws it once no such route is left. With only the cover installed it
  writes nothing outside the tun.

## `dial`

| Key   | Value         | Default | Meaning                                             |
| ----- | ------------- | ------- | --------------------------------------------------- |
| `to`  | list of names | none    | The peers this node dials                           |
| `all` | boolean       | `false` | Also dial every other node the trust document names |

- A node name in `to` dials, from each local endpoint, the first endpoint of
  that node in the same family that carries an address and resolves. It chooses
  again on every attempt.
- An endpoint name in `to` dials that endpoint alone. This is the way to pin a
  serial.
- An empty entry and an entry written twice are refused at load.
- At startup, a node or endpoint the trust document does not name is refused. So
  is an endpoint in a family no local endpoint has.
- A node with no endpoint in a local family is logged and not dialed. So is a
  node or endpoint with no address.
- `all` dials the other nodes in the trust document's order. An entry in `to`
  wins for its node.

## `cap.route`

What this node puts into the mesh. Without this block, the node announces
nothing.

| Key        | Value | Default | Meaning                           |
| ---------- | ----- | ------- | --------------------------------- |
| `announce` | list  | none    | The prefixes this node originates |

- An `announce` entry is a prefix, `"10.66.0.5/32"`, or a prefix and the source
  it serves, `{ prefix = "::/0", from = "2001:db8:1::/48" }`. An exit announces
  its default in the second form.
- A source-specific entry is IPv6 only. Its `from` is in the same family as its
  `prefix`. A `from` of length 0 is refused.
- A prefix of length 0 with host bits set, such as `"2001:db8::/0"`, is refused
  as a typo for a default.
- `transit` under `cap.route` is refused at load, with a message naming
  `cap.transit`. That key meant transit on when left out, and a node that relied
  on it carries no transit until it writes `cap.transit.enable = true`.

## `cap.transit`

Whether this node relays the routes it learns to its neighbors. A node that
relays carries other nodes' traffic: it decrypts each of their packets from one
session and encrypts it again onto the next.

| Key      | Value   | Default  | Meaning                           |
| -------- | ------- | -------- | --------------------------------- |
| `enable` | boolean | required | Relay the routes this node learns |

- Without this block, transit is off, as with `enable = false`, and the node
  advertises only the prefixes it originates. `enable = true` is the only way to
  turn transit on, whatever `link.listen` and the host's forwarding are.
- A written block states `enable`. A block without it is refused at load.
- The daemon reads `enable` at startup. A reload that would turn transit on or
  off is refused with `config: cap.transit enable changed, restart to apply`. A
  reload between a left-out block and `enable = false` changes nothing.
- With `enable = true` and forwarding off for either family, the daemon logs a
  warning at startup: peers that select this node would have their traffic
  dropped. It reads forwarding from the settings [platforms](platforms.md)
  lists.

## `cap.babel`

The Babel speaker's timers and link quality. `hello` and `update` default to the
values of RFC 8966 Appendix B.

| Key       | Value           | Default     | Meaning                                                     |
| --------- | --------------- | ----------- | ----------------------------------------------------------- |
| `hello`   | duration        | `"4s"`      | Interval between Hellos                                     |
| `update`  | duration        | 4 x `hello` | Interval between full route updates                         |
| `quality` | `etx` or `none` | `etx`       | How Hello loss raises a link's cost (RFC 8966 Appendix A.2) |

- Each interval is between 10 milliseconds and 655.35 seconds. An omitted
  `update` is capped at 655.35 seconds.
- `quality = "none"` stops Hello loss from raising a link's cost. The round-trip
  penalty of `cap.babel.cost` still applies.

### `cap.babel.cost`

A fixed cost plus a round-trip penalty (RFC 9616), named after BIRD's Babel
interface options. Each key keeps its own default, so writing 1 key leaves the
other 3 as they were.

| Key          | Value    | Default    | Meaning                                   |
| ------------ | -------- | ---------- | ----------------------------------------- |
| `rx`         | integer  | `96`       | Cost of a lossless link                   |
| `rtt.weight` | integer  | `1024`     | Largest penalty the round trip adds       |
| `rtt.min`    | duration | `"10ms"`   | Round trip below which nothing is added   |
| `rtt.max`    | duration | `"1024ms"` | Round trip at which `rtt.weight` is added |

- Between `rtt.min` and `rtt.max` the penalty scales linearly.
- `rx` is at least 1. `rx` plus `rtt.weight` is at most 65534, since 65535 means
  unreachable.
- `rtt.min` is at least 0 and at most `rtt.max`.

### `cap.babel.cost.extra`

An amount this node adds to the cost of a neighbor, chosen by the identity the
neighbor's session authenticated. [Routing](routing.md#link-cost) says where it
goes. Left out, every neighbor pays nothing.

```toml
[cap.babel.cost.extra]
foreign = 1024                    # any organization other than this node's own
org = { gravity = 2048 }          # by organization
node = { "ysun/lagern" = 300 }    # by organization/name
```

| Key       | Value                          | Default | Meaning                                          |
| --------- | ------------------------------ | ------- | ------------------------------------------------ |
| `foreign` | integer                        | `0`     | Amount for every organization but this node's    |
| `org`     | table of organization: integer | none    | Amount for each organization named               |
| `node`    | table of `org/name`: integer   | none    | Amount for each node named, any of its endpoints |

- The most specific key wins: `node`, then `org`, then `foreign`, then nothing.
  The amounts do not add up, so an organization listed under `org` pays its own
  amount and not `foreign` as well.
- Each amount is 0 to 65534.
- Every organization named is an organization with a node in the trust document,
  and every node named is a node in it, at startup and on each reload. One that
  is not is refused by name, as in
  `config: cap.babel cost.extra node ysun/lagern is not a node of the trust document`.
  An organization is written as the trust document writes it. A node is
  `organization/name`, with no serial. A node of this node's own organization
  may be named. This node itself is refused.
- A node key is only as strong as its organization's key. IKE proves the
  organization a peer belongs to, and the name inside it is asserted: every
  holder of that organization's key can claim any of its names, and so take the
  amount set for another of them.
- A reload applies a change, as [reloading](reloading.md) describes for
  `cap.babel`.

## `cap.table`

The route reconciler. Writing this block turns it on. It mirrors the routes
Babel selects into a kernel routing table, through the tun.
[Routing](routing.md) describes how it behaves. Without this block, ranet3
writes no route through the tun and assigns no address, and the tun is yours to
configure.

| Key                | Value            | Default        | Meaning                                                                          |
| ------------------ | ---------------- | -------------- | -------------------------------------------------------------------------------- |
| `id`               | table            | `200`          | The table the reconciler owns                                                    |
| `proto`            | integer          | `155`          | Route protocol that marks what the reconciler owns                               |
| `metric`           | integer          | kernel default | Priority of every installed route                                                |
| `prefsrc4`         | IPv4 address     | none           | Linux only. Preferred source on every IPv4 route                                 |
| `addresses`        | list of prefixes | none           | Addresses assigned to the tun                                                    |
| `assign_announced` | boolean          | `false`        | Also assign every prefix `cap.route` announces                                   |
| `reconcile`        | duration         | `"30s"`        | Interval of the periodic pass that corrects drift                                |
| `capture_grace`    | duration         | `"10s"`        | How long a route carrying this host's own traffic outlives the last live session |

- `id` 253, 254 and 255 are refused. They are `default`, `main` and `local`.
- `proto` 1 to 4 are refused. They belong to the kernel and to systemd-networkd.
  The reconciler reads back and deletes only routes and rules that carry its
  `proto`.
- The kernel's default `metric` is 0 for IPv4 and 1024 for IPv6. The reconciler
  does not take over a route another writer holds under the same key. A table
  shared with BIRD needs a metric BIRD does not use.
- macOS has 1 forwarding table and no route protocol. It refuses at startup an
  `id` or `proto` other than the default, and refuses `prefsrc4`. It ignores
  `metric`.
- `prefsrc4` written as an IPv4-mapped IPv6 address is refused.
- An `addresses` entry is assigned when missing and removed at shutdown or when
  a reload drops it. The reconciler removes only addresses it added. Each entry
  needs a length above 0.
- A default is announced and never assigned, even with `assign_announced`.
- A negative `reconcile` is refused.
- A route that would carry this host's own traffic, such as an announced
  default, is installed only after a session has been live. A `capture_grace` of
  `0` takes the default. Any other value under 1 second is refused.
- A `cap.segment.local` SID that is also an address this block assigns is
  refused at load.

### `cap.table.vrf`

Linux only. The daemon refuses the block at startup on other platforms.

| Key      | Value   | Default  | Meaning                                               |
| -------- | ------- | -------- | ----------------------------------------------------- |
| `name`   | string  | required | VRF device the tun is enslaved to                     |
| `create` | boolean | `false`  | Create the VRF, bound to `id`, when it does not exist |

- The tun is enslaved only while it has no master.
- A VRF the daemon created is removed at shutdown.

### `cap.table.rules`

Policy rules the reconciler owns. Linux only, and the daemon refuses them at
startup on other platforms. Each rule carries `proto` and is removed at
shutdown. The reconciler installs the rules in order of `priority`, not in the
order written. A rule only selects a table to look up.

| Key        | Value                    | Default             | Meaning                                 |
| ---------- | ------------------------ | ------------------- | --------------------------------------- |
| `to`       | prefix                   | none                | Destination the rule matches            |
| `from`     | prefix                   | none                | Source the rule matches                 |
| `fwmark`   | integer                  | `0` (none)          | Packet mark the rule matches            |
| `fwmask`   | integer                  | `0` (whole mark)    | Mask applied to the mark                |
| `iif`      | device name              | none                | Device the packet arrived on            |
| `table`    | table                    | required            | Table to look up                        |
| `priority` | integer                  | required            | Position of the rule                    |
| `family`   | `ipv4`, `ipv6` or `both` | from `to` or `from` | Address family of a rule with no prefix |

- A rule must match on `to`, `from`, `fwmark` or `iif`.
- A `to` or `from` prefix with bits set below its length, of length 0, or of the
  other family is refused.
- `fwmask` without `fwmark` is refused.
- `iif` longer than 15 bytes, `.`, `..`, or a name holding `/`, `:`, a NUL,
  ASCII whitespace or the byte `0xa0` is refused. The kernel refuses such a name
  for a device, and cuts a name at its first NUL.
- `iif` may name a device that does not exist yet. The kernel holds the rule and
  applies it once the device appears.
- `priority = 0` is refused. It belongs to the `local` table.
- `family` is required on a rule that has neither `to` nor `from`, and refused
  on a rule with `to` or `from`. `both` installs the rule once per family.
- 2 entries that install the same rule are refused.

## `cap.segment`

Segment routing (RFC 8986), done in this process on every platform.
[Segment routing](segment-routing.md) describes how it behaves. Every SID,
segment and source is a unicast IPv6 address, never IPv4-mapped. A steering
selector may be IPv4.

| Key      | Value   | Default | Meaning                                                   |
| -------- | ------- | ------- | --------------------------------------------------------- |
| `source` | address | none    | Outer source of a steered packet, for entries naming none |

### `cap.segment.local`

The segments this node answers for.

| Key        | Value               | Default  | Meaning                             |
| ---------- | ------------------- | -------- | ----------------------------------- |
| `sid`      | address             | required | The segment identifier              |
| `behavior` | `End` or `End.DT46` | required | What this node does with the packet |

- `End` sends the packet to its next segment. `End.DT46` removes the outer
  header and delivers the inner packet.
- `behavior` is read in any case.
- A SID written twice is refused.

### `cap.segment.steer`

Which packets read off the tun take a segment list. That covers this node's own
traffic and any traffic the host forwards into the mesh.

| Key      | Value             | Default              | Meaning                                   |
| -------- | ----------------- | -------------------- | ----------------------------------------- |
| `from`   | prefix            | any                  | Source the entry matches                  |
| `to`     | prefix            | any                  | Destination the entry matches             |
| `source` | address           | `cap.segment.source` | Outer source for this entry               |
| `via`    | list of addresses | required             | Segments in visiting order, the exit last |

- An entry names `from`, `to` or both. Both are in the same family. An omitted
  one matches every address of the other's family.
- A prefix of length 0, or with bits set below its length, is refused.
- An entry with no `source` and no `cap.segment.source` is refused.
- `via` holds 1 to 16 segments. At the default `link.mtu` of 1400 bytes, a list
  of more than 4 segments leaves the tun under 1280 bytes and is refused.
- 2 entries with the same `from` and `to` are refused.
- A steered packet carries its list inside the tunnel. The tun's MTU is
  `link.mtu` less 40 bytes of outer header, 8 bytes of routing header, and 16
  bytes per segment of the longest list.

## `cap.crypto`

Key lifetimes and the replay window. A session takes these values when its SA is
set up.

| Key      | Value   | Default | Meaning                            |
| -------- | ------- | ------- | ---------------------------------- |
| `replay` | integer | `4096`  | ESP anti-replay window, in packets |

- `replay` is at most 1048576. `0` turns replay checking off.

### `cap.crypto.rekey`

| Key      | Value    | Default | Meaning                                                  |
| -------- | -------- | ------- | -------------------------------------------------------- |
| `child`  | duration | `"1h"`  | Child SA rekey interval. `0` turns it off                |
| `ike`    | duration | `"3h"`  | IKE SA rekey interval. `0` turns it off                  |
| `margin` | duration | `"5m"`  | Taken off every interval                                 |
| `jitter` | duration | `"1m"`  | Up to this much more, at random, taken off each interval |

- No value is negative.
- `margin` plus `jitter` is less than every interval that is on.

### `cap.crypto.rekey.retry`

A scheduled rekey that fails is retried with capped exponential backoff.

| Key     | Value    | Default | Meaning       |
| ------- | -------- | ------- | ------------- |
| `first` | duration | `"5s"`  | First delay   |
| `max`   | duration | `"5m"`  | Longest delay |

- Both are positive. `first` is at most `max`.

## `cap.egress`

Carry other nodes' traffic out of the mesh, as an exit node or a subnet router.
Linux only, and the daemon refuses it at startup on other platforms.
[Exit nodes](exit-nodes.md) describes the translation and the policy rules it
needs.

| Key         | Value             | Default  | Meaning                                                           |
| ----------- | ----------------- | -------- | ----------------------------------------------------------------- |
| `advertise` | list of prefixes  | required | Prefixes this node offers to carry                                |
| `source4`   | `auto` or address | `auto`   | IPv4 source of a translated packet                                |
| `source6`   | `auto` or address | `auto`   | IPv6 source of a translated packet                                |
| `return`    | boolean           | `false`  | Also translate traffic from the advertised prefixes into the mesh |
| `sweep`     | duration          | `"30s"`  | Interval of the periodic pass                                     |

- An exit advertises `0.0.0.0/0` and `::/0` only, for Linux and macOS clients
  alike. The `/1` halves would win over every `/0` exit by longest prefix, as
  [exit nodes](exit-nodes.md#what-to-advertise) describes. A subnet router
  advertises the prefixes behind it.
- A prefix is announced only while its family's translation rule is installed
  and the host forwards that family.
- An `advertise` prefix with bits set below its length, written as IPv4-mapped
  IPv6, or written twice is refused at load.
- At startup and on every reload, an `advertise` prefix that `cap.route` also
  announces is refused. That announcement would go out whether or not the rule
  is installed.
- For traffic leaving the mesh, `auto` uses the address of the link the packet
  leaves by. The host's routes pick it for each packet.
- For traffic entering the mesh, `auto` uses this node's mesh address. The
  daemon picks it once at startup, from the host prefixes `cap.route` announces
  and `cap.table` assigns.
- A written `source4` or `source6` is used in both directions. It must be global
  unicast or private.
- A subnet router needs `return` when the mesh has no route back to its LAN.
  With `return`, each advertised family whose source is `auto` needs exactly 1
  global unicast or private mesh address of that family. The daemon refuses to
  start with none or with more than 1.
- The periodic pass reinstalls a removed table and reads the forwarding sysctls
  again. `sweep` also caps the delay between retries of a failed pass. A
  negative `sweep` is refused.

## Daemon flags

The daemon's own settings are flags, listed on [command line](cli.md).
