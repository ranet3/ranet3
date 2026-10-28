---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Configuration reference"
description: "Every key the configuration file takes, its default and what it refuses."
created: 2026-10-16
updated: 2026-10-28
order: 35
---

This page lists every key the configuration file takes.
[Configuration](configuration.md) describes the file as a whole.
[Reloading](reloading.md) says which keys a reload applies and which need a
restart.

Keys are written as TOML paths, such as `cap.table.addresses`. YAML and JSON
nest the same names. A key not listed here is refused when the file loads.

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
  trust document cannot support, and an `auth.aliases` entry naming what the
  document lacks, instead of refusing the file.

## Spellings

| Kind     | Spelling                                                           | Example                      |
| -------- | ------------------------------------------------------------------ | ---------------------------- |
| duration | as Go writes one, or a bare `0`                                    | `"4s"`, `"250ms"`, `"1h30m"` |
| prefix   | an address and a length                                            | `"2001:db8::/48"`            |
| address  | no length and no zone                                              | `"2001:db8::1"`              |
| table    | a number, or `main` (254), `local` (255) or `default` (253)        | `200`, `"main"`              |
| integer  | whole digits, and hex in TOML and YAML                             | `13000`, `0xc8`              |
| name     | `organization/name`, or `organization/name:serial` for an endpoint | `"example/gateway:0"`        |

- JSON has no hex spelling. A `.json` file writes the decimal number.
- An integer written with a fraction, an exponent or a minus sign is refused
  with its line.
- In a name, a byte outside letters, digits, `-`, `.`, `_` and `~` is written as
  `%` and 2 uppercase hex digits. The organization `example org` is
  `example%20org`. No other spelling is taken.

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

| Key       | Value | Default  | Meaning                                                 |
| --------- | ----- | -------- | ------------------------------------------------------- |
| `key`     | path  | required | This node's private key, a PKCS8 PEM Ed25519 file       |
| `trust`   | path  | required | The [trust document](trust.md), a ranet `registry.json` |
| `aliases` | table | none     | IDs other than a DN, for a peer that is not ranet3      |

### `auth.aliases`

The IDs of RFC 7296 section 3.5 other than a DN, for a peer such as strongSwan
that names itself, or expects this node to be named, by an address, a domain
name, an email address or a key ID. A ranet3 peer names itself by its DN and
needs no entry. [The trust document](trust.md#ids-on-the-wire) describes how a
handshake reads an ID.

```toml
[auth.aliases.remote.fqdn]
"gw.example.net" = "example/gateway:0"

[auth.aliases.local]
"example/gateway" = { fqdn = "laptop.example.net" }
```

| Key            | Value                        | Default | Meaning                                                            |
| -------------- | ---------------------------- | ------- | ------------------------------------------------------------------ |
| `remote.ip`    | table of address: name       | none    | The endpoint a peer presenting `ID_IPV4_ADDR` or `ID_IPV6_ADDR` is |
| `remote.fqdn`  | table of domain name: name   | none    | The endpoint a peer presenting `ID_FQDN` is                        |
| `remote.email` | table of email address: name | none    | The endpoint a peer presenting `ID_RFC822_ADDR` is                 |
| `remote.keyid` | table of hex octets: name    | none    | The endpoint a peer presenting `ID_KEY_ID` is                      |
| `local`        | table of name: ID            | none    | The ID this node presents to a peer in place of its DN             |

- A `remote` value is an endpoint, `organization/name:serial`. The key that must
  verify the peer is still that endpoint's key in the trust document.
- An address under `ip` is an `ID_IPV4_ADDR` when it is IPv4 and an
  `ID_IPV6_ADDR` otherwise, an IPv4-mapped address included. The 2 types never
  match each other.
- A domain name, and the domain of an email address, match in ASCII without
  case. The part of an email address before its last `@`, an address and a key
  ID match exactly. A domain name is ASCII, so an internationalized name is
  written in its `xn--` form.
- An `ID_KEY_ID` whose octets spell an endpoint as `organization/name:serial`
  names that endpoint with no entry.
- A `local` key is a peer as `dial.to` writes one, a node or an endpoint, and an
  endpoint's entry wins over its node's. Its value writes exactly 1 of `ip`,
  `fqdn`, `email` and `keyid`, spelled as the `remote` table of that type spells
  a key. This node sends it as IDi when it dials that peer, and as IDr when that
  peer dials it and sends no IDr.
- Dialing an endpoint `remote` names by 1 ID, this node asks for that ID in IDr.
  Where `remote` names it by several, it asks for none, and where by none, it
  asks for the endpoint's DN.
- At load, the file is refused for a key or value that does not parse, an empty
  one, a control character or a line or paragraph separator in a domain name or
  an email address, a character outside ASCII in a domain name, an email address
  without a local part and a domain on either side of its last `@`, and 2 keys
  of 1 table that name 1 ID, such as `gw.example.net` and `GW.example.net`.
- At load, the file is also refused for a `remote` value naming a node, a
  `remote.keyid` key spelling an endpoint other than its value, a `local` entry
  writing none or several types, and a `local` `keyid` spelling an endpoint of
  another node.
- At load, `local` is refused on a node whose `link.endpoints` holds 2 entries
  of 1 family, since a peer could not tell them apart by the ID they present.
- At startup, every node and endpoint the tables name must be in the trust
  document, and one it lacks refuses the start. A reload logs the entry instead,
  as [reloading](reloading.md#peers-the-trust-document-cannot-support)
  describes.
- A reload applies both tables to the handshakes after it, and a session already
  up keeps its peer.

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
- A responder takes a handshake in 1 family. It refuses a peer whose ID names an
  endpoint the trust document lists in the other family than the one the request
  arrived in, and an IDr naming one of this node's endpoints of the other
  family. With no IDr, or one that names no endpoint and holds an ID
  `auth.aliases.local` presents, it answers as the one `endpoints` entry of that
  family, and refuses where there is none or more than 1. A node with 1 `ip4`
  entry refuses a request that reaches it over IPv6, with or without an IDr.
  [The trust document](trust.md#families) describes these refusals.
- With `listen` off and `dial.all` off, `dial.to` needs at least 1 entry.
- On Linux, `tun` attaches to an existing device of that name and creates it
  otherwise. The default `ranet3` is never attached to: the daemon refuses to
  start when a device called `ranet3` exists. On macOS, `tun` takes only `utun`
  and `utunN`, and the daemon refuses any other name at startup.
- The device runs at `mtu` less the header of the longest `cap.segment.steer`
  list. A value that leaves the device under 1280 bytes, or a value over 65470,
  is refused at load. [Path MTU](path-mtu.md) describes how sessions use it.

### `link.underlay`

This block decides how a Mac installs an exit's default route. A Mac that takes
an exit's default route needs `bind`. It is refused at startup on every platform
but macOS.

| Key    | Value   | Default | Meaning                                                                                        |
| ------ | ------- | ------- | ---------------------------------------------------------------------------------------------- |
| `bind` | boolean | `false` | macOS only. Install a route holding its family's zero address unscoped, as its zero-free cover |

- On Linux the block takes no key. Every underlay socket carries the mark 0x72
  where the process may set it. A marked lookup bound to no device ends as rows
  L1 and L2 of [where a lookup ends](routing.md#where-a-lookup-ends-on-linux)
  give, an IPv4 reply pinned to the interface its request arrived on as row B1
  gives, and an IPv6 one, which also names the address its request arrived at,
  as row L2 gives. [Sharing a host](coexistence.md#the-underlays-mark) says what
  a process the kernel refuses the mark does.
- On macOS, with or without `bind`, each underlay datagram names the interface
  the host's own routes send it by, ranet3's utun left out, as
  [the underlay's interface](routing.md#the-underlays-interface-on-macos)
  describes.
- With `bind`, the reconciler installs a route Babel selects that holds its
  family's zero address as the members of
  [the zero-free cover](routing.md#the-zero-free-cover-on-macos) it contains, so
  other sockets use the mesh exit. Until exit selection exists, a Mac with
  `bind` set takes whichever `/0` Babel selects.
- With `bind`, any other route that carries this host's own traffic is installed
  unscoped too, except one that covers an endpoint address listed in the trust
  document, which stays scoped to the tun, and a source-specific IPv6 one,
  scoped to the tun where its source prefix holds an address of the tun and
  otherwise not installed, while a source-specific IPv4 one is never installed.
- Without `bind`, every route that carries this host's own traffic is scoped to
  the tun, which no socket follows unless it asks for the tun by name. Either
  way the daemon writes nothing outside the tun.

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
nothing but what [`cap.egress`](#capegress) and an egress segment add, as
[routing](routing.md#what-a-node-announces) describes.

| Key        | Value | Default | Meaning                           |
| ---------- | ----- | ------- | --------------------------------- |
| `announce` | list  | none    | The prefixes this node originates |

- An `announce` entry is a prefix, `"203.0.113.10/32"`, or a prefix and the
  source it serves, `{ prefix = "::/0", from = "2001:db8:1::/48" }`, such as a
  default for 1 source prefix alone. `cap.egress` announces an exit's prefixes
  with no source.
- A source-specific entry is IPv6 only. Its `from` is in the same family as its
  `prefix`. A `from` of length 0 is refused.
- A prefix of length 0 with host bits set, such as `"2001:db8::/0"`, is refused
  as a typo for a default.
- A prefix that
  [counts as a default](routing.md#routes-that-count-as-a-default), such as one
  outside `cap.border.overlay` shorter than `/8` for IPv4 or `/16` for IPv6,
  makes this node an exit for its family. Such an entry other than a default
  loads with a warning.
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
- The mesh forwards transit itself, so the host's forwarding settings play no
  part in it. With transit off, a packet for another node that reaches this one
  all the same is answered administratively prohibited, unless an End.DT46 SID
  of this node delivering to the mesh took it out of its outer header.
  [Routing](routing.md#transit) lists the decision and its answers.

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
- `quality = "none"` keeps the rxcost this node advertises unscaled by its Hello
  loss, and takes the cost a neighbor reports without scaling it by this node's
  own Hello loss. A neighbor that measures loss still raises what it reports.
  The round-trip penalty of `cap.babel.cost` still applies.

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
foreign = 1024                      # any organization other than this node's own
org = { other = 2048 }              # by organization
node = { "example/gateway" = 300 }  # by organization/name
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
  `config: cap.babel cost.extra node example/gateway is not a node of the trust document`.
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
| `metric`           | integer          | kernel default | Priority of every installed route but a hold or a throw, which sits last         |
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
  `id` or `proto` other than the default. It ignores `metric`.
- On Linux the reconciler derives its policy rules from `cap.border.overlay`,
  this node's own prefixes and `cap.exit`, and no key writes a rule.
  [Routing](routing.md#policy-rules-on-linux) lists them. macOS installs none.
- An `addresses` entry is assigned when missing and removed at shutdown or when
  a reload drops it. The reconciler removes only addresses it added. Each entry
  needs a length above 0.
- On Linux an IPv4 route through the tun names no source, so the kernel picks
  one of the tun's own IPv4 addresses for a socket bound to no address, or
  another link's address where the tun has none.
- The mesh's own table holds each address this block assigns as this node's, at
  its host route, and announces it only if it originates that route too. A route
  a neighbor offers for that host route never replaces it, as
  [routing](routing.md#what-a-node-announces) describes.
- A default is announced and never assigned, even with `assign_announced`.
- A negative `reconcile` is refused.
- A route that [counts as a default](routing.md#routes-that-count-as-a-default),
  such as a default or `2000::/3` a neighbor announces, is installed only after
  a session has been live, and its hold never. This node's own prefix that
  counts is never installed, and an [exit](exit-nodes.md#an-exits-own-traffic)
  installs no such route at all. A `capture_grace` of `0` takes the default. Any
  other value under 1 second is refused.
- A `cap.segment.local` SID that is also an address this block assigns is
  refused at load.

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

| Key        | Value               | Default  | Meaning                                                  |
| ---------- | ------------------- | -------- | -------------------------------------------------------- |
| `sid`      | address             | required | The segment identifier                                   |
| `behavior` | `End` or `End.DT46` | required | What this node does with the packet                      |
| `deliver`  | `mesh` or `egress`  | `mesh`   | Where `End.DT46` hands the inner packet                  |
| `allow`    | list of prefixes    | none     | Sources an egress segment carries, outer and inner alike |

- `End` sends the packet to its next segment. `End.DT46` removes the outer
  header and delivers the inner packet, to the mesh's
  [forwarding decision](routing.md#transit) or, with `deliver = "egress"`, to
  the exit, which writes it into the mesh tun for the host to carry out of the
  mesh, refusing an inner destination inside `cap.border.overlay` or that the
  mesh routes itself. The decision writes it to the tun, hands it to the exit,
  forwards it, answers it or drops it, as it does a session's packet and as
  [routing](routing.md#transit) lists. An inner packet an End.DT46 delivers to
  the mesh takes that path whatever `cap.transit` says.
- `behavior` is read in any case.
- A SID written twice is refused.
- `deliver = "egress"` is refused on `End`, and `allow` on anything but an
  egress segment.
- An egress segment's `allow` is required. An entry of length 0, an IPv4 entry
  shorter than `/8`, an IPv6 entry shorter than `/12`, an entry with bits set
  below its length, an IPv4 address written as IPv6, an entry written twice and
  a list with no IPv6 entry are refused. The order does not matter.
- Every segment needs `cap.border` with an IPv6 prefix in its `overlay`, and
  acts only on a packet whose outer source lies in those prefixes.
- An egress segment needs `cap.egress`, which may advertise nothing, and
  `cap.border` whose `overlay` covers every `allow` entry. It needs no
  `cap.table`. `cap.route` may not announce its SID's `/128`, which the node
  originates while the exit is ready.

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

The transforms a session negotiates, key lifetimes and the replay window. A
session takes the replay window and the rekey timers when its SA is set up, and
reads the lists of `cap.crypto.ike` and `cap.crypto.esp` at each exchange.

| Key      | Value   | Default | Meaning                            |
| -------- | ------- | ------- | ---------------------------------- |
| `replay` | integer | `4096`  | ESP anti-replay window, in packets |

- `replay` is at most 1048576. `0` turns replay checking off.

### `cap.crypto.rekey`

| Key      | Value    | Default | Meaning                                                  |
| -------- | -------- | ------- | -------------------------------------------------------- |
| `child`  | duration | `"1h"`  | Child SA lifetime and rekey interval. `0` turns both off |
| `ike`    | duration | `"3h"`  | IKE SA lifetime and rekey interval. `0` turns both off   |
| `margin` | duration | `"5m"`  | How long before its SA's lifetime a rekey falls due      |
| `jitter` | duration | `"1m"`  | Up to this much earlier, at random                       |

- No value is negative.
- `margin` is positive whenever `child` or `ike` is on, since a rekey due at the
  end of its SA's lifetime could never replace it.
- `margin` plus `jitter` is less than every interval that is on.

`jitter` also delays the rekey a reload forces on an SA whose transform the new
lists leave out, as [how the lists are used](#how-the-lists-are-used) describes.

An SA's lifetime starts when the SA is made, and its rekey counts from there, so
`margin` is the time the rekey has before the lifetime ends however late the
last rekey finished. At the end of its lifetime a Child SA is no longer used,
and an IKE SA starts nothing but its Delete. A Child SA's keys leave the
dataplane then, whatever exchange is under way. An SA that reaches its lifetime
with no rekey replacing it, or a Child SA that runs out of sequence numbers with
none replacing it, closes the IKE SA. The session logs `ike deleting the IKE SA`
with the reason, records `ike.sa.closed`, sends a Delete for the IKE SA and
ends, and the node that dialed it dials again. A rekey still under way at the
lifetime may yet replace the SA, and the IKE SA closes only if that rekey fails.
A peer that answers this end's rekeys on 1 IKE SA with `TEMPORARY_FAILURE` for 5
minutes closes it the same way. A rekey of the IKE SA or the Child SA that
completes, whichever end started it, ends those 5 minutes, and the next
`TEMPORARY_FAILURE` starts them again.

### `cap.crypto.rekey.retry`

A rekey that fails is retried with capped exponential backoff. For the Child SA
the backoff holds back the next rekey whichever path asks for it: the schedule,
the ask as the sequence numbers near their end, the replacement of a Child SA
the peer deleted, or `ranet3 rekey`. The retries stop at the SA's lifetime, or
once a rekey the peer starts replaces the SA, whose next rekey then counts from
the SA the peer made.

| Key     | Value    | Default | Meaning       |
| ------- | -------- | ------- | ------------- |
| `first` | duration | `"5s"`  | First delay   |
| `max`   | duration | `"5m"`  | Longest delay |

- Both are positive. `first` is at most `max`.

### `cap.crypto.ike`

The IKE SA's transforms, each list most preferred first.

| Key      | Value           | Default                                          | Meaning        |
| -------- | --------------- | ------------------------------------------------ | -------------- |
| `cipher` | list of names   | `["aes256gcm", "aes128gcm", "chacha20poly1305"]` | IKE SA ciphers |
| `prf`    | list of names   | `["sha384", "sha256"]`                           | IKE SA PRFs    |
| `kex`    | list of entries | `["x25519+mlkem768", "x25519", "p384", "p256"]`  | Key exchanges  |

- `aes256gcm` and `aes128gcm` are AES-GCM with a 16-octet tag and a 256 or
  128-bit key, and `chacha20poly1305` is ChaCha20-Poly1305. `sha384` and
  `sha256` are HMAC-SHA2-384 and HMAC-SHA2-256. `x25519`, `p384` and `p256` are
  Curve25519 and the NIST curves P-384 and P-256, and `mlkem768` and `mlkem1024`
  are ML-KEM-768 and ML-KEM-1024 of FIPS 203.
- A list left out holds the default above, which for `cipher` and `prf` is every
  name the list takes. An empty list, an entry written twice and a name not in
  the default, other than `mlkem1024` joined in a `kex` entry, are refused, and
  names are lowercase.
- A `kex` entry is a classical key exchange, alone or joined with `+` by
  `mlkem768` or `mlkem1024`, as in `x25519+mlkem768`. At setup the classical key
  exchange runs in `IKE_SA_INIT`, and the ML-KEM method runs after it in an
  `IKE_INTERMEDIATE` exchange of its own, as
  [RFC 9370 section 2.2](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2)
  and [RFC 9242](https://www.rfc-editor.org/rfc/rfc9242.html) describe. In a
  rekey the classical key exchange runs in `CREATE_CHILD_SA`, and the ML-KEM
  method after it in an `IKE_FOLLOWUP_KE` exchange of its own, as
  [section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
  describes. The SA's keys come from both.
- The load refuses these `kex` entries, and its error names the entry:
  - An entry that starts with an ML-KEM name or is one alone, such as
    `mlkem768`, since ML-KEM runs only after a classical key exchange.
  - An entry that joins a classical name, such as `x25519+p256`.
  - An entry that joins more than 1 name.
  - An entry that names `mlkem512` or any other name `kex` does not take.
- A peer's Child SA creation or rekey may run any entry of `kex`, a joined
  entry's ML-KEM method in `IKE_FOLLOWUP_KE`. A proposal that offers `NONE` for
  an additional key exchange the entry does not use gets `NONE` back. A Child SA
  rekey this node starts runs no key exchange.

A node that writes no `kex` offers X25519 with ML-KEM-768 first, and a peer
without ML-KEM takes a classical entry from a later proposal. A list of joined
entries alone, such as `["x25519+mlkem768"]`, refuses every peer without
ML-KEM-768. A list that also holds a classical entry lets a session fall back to
it. Between 2 nodes that both list a classical entry, an attacker on the path
who can break the classical key exchange while the handshake runs can steer them
to that entry.
[The ML-KEM draft's section 3](https://datatracker.ietf.org/doc/html/draft-ietf-ipsecme-ikev2-mlkem-09#section-3)
says "The simplest way to prevent such active attacks is to disable support for
traditional-only sequences of key exchanges whenever possible." List only joined
entries for peers known to run ML-KEM-768. The `IKE_INTERMEDIATE` request of
ML-KEM-768 is a datagram of 1281 bytes over IPv4 and 1301 over IPv6, and the
`IKE_FOLLOWUP_KE` request of a rekey 1297 and 1317. The requests of ML-KEM-1024
pass 1500 bytes. A message larger than the path goes in the fragments of
[RFC 7383](https://www.rfc-editor.org/rfc/rfc7383.html) to a peer that supports
them, and needs the whole path with one that does not, as
[limits](design/limits.md#ml-kem-and-the-path) describes.

### `cap.crypto.esp`

The Child SA's ciphers, most preferred first, by the names and under the rules
of `cap.crypto.ike.cipher`.

| Key      | Value         | Default                                          | Meaning          |
| -------- | ------------- | ------------------------------------------------ | ---------------- |
| `cipher` | list of names | `["aes256gcm", "aes128gcm", "chacha20poly1305"]` | Child SA ciphers |

### How the lists are used

A dialing node offers 1 proposal for each `kex` entry, in the list's order, each
holding every listed cipher and PRF, and sends its key exchange in the group of
the first entry. With the default `kex` that is 4 proposals and a key exchange
in X25519. An offer holding a joined entry also asks the peer for
`IKE_INTERMEDIATE`. A proposal holds an entry when it offers the entry's group
and its ML-KEM method, and `NONE` in any additional key exchange type the entry
does not use. An answering node takes the first entry of its own `kex` that a
proposal of the offer holds, and of 2 proposals holding it the earlier. A
proposal that offers an additional key exchange counts only when the offer asked
for `IKE_INTERMEDIATE`. Of each other kind the node takes the first transform of
its own list that the proposal holds, whatever order the offer gives. With the
default lists, a strongSwan initiator that proposes `chacha20poly1305` first, as
a host without AES instructions does, gets `aes256gcm`. An offer whose key
exchange is in another group than the chosen entry's is answered with
`INVALID_KE_PAYLOAD` naming that group, and the peer tries again in it, which
costs 1 round trip. A dialing node asked for another group moves the first
proposal in that group ahead of the rest, which keep their order.

An offer the lists share no transform of one kind with is refused with
`NO_PROPOSAL_CHOSEN`, in `IKE_SA_INIT`, in the Child SA of `IKE_AUTH` and in
every `CREATE_CHILD_SA`. A dialing node refuses an answer that takes a transform
its lists do not hold.

A Child SA rekey this node starts offers only the cipher of the SA it replaces
while `esp.cipher` holds it. Answering a peer's Child SA rekey, it takes that
cipher first when the offer and `esp.cipher` both hold it. An IKE SA rekey keeps
the PRF and takes the cipher as a new IKE SA does. While `kex` holds the IKE
SA's entry, either end's rekey of the SA may run only an entry that keeps each
ML-KEM method of it, so an IKE SA of `x25519+mlkem768` keeps ML-KEM-768 across
its rekeys and an IKE SA of a classical entry may move to a joined one. A peer's
rekey that offers no such entry is refused with `NO_PROPOSAL_CHOSEN`. Once a
reload leaves the SA's entry out, a rekey may run any entry of `kex`. An IKE SA
rekey this node starts runs its key exchange in the SA's group while one of the
entries it may run has that group, and a peer's rekey whose key exchange is in
the SA's group keeps the SA's entry while `kex` holds it. `ranet3 sessions` and
the `ike.session.established` event name the transforms each session runs, an
IKE SA's joined entry with its `+`, such as `x25519+mlkem768`.

A reload applies the lists to the next exchange, as
[reloading](reloading.md#capcrypto) describes. An SA holding a cipher or a kex
entry the new lists leave out is rekeyed under them after a delay drawn up to
`cap.crypto.rekey.jitter`, and no later than its scheduled rekey, unless a rekey
of it is already due, under way or backing off, which goes on its own timer
under the lists then in force. A Child SA whose IKE SA is rekeyed for the same
reload waits for that rekey to end or fail. An IKE SA whose PRF they leave out
is deleted, and a new handshake replaces it.

## `cap.egress`

Carry other nodes' traffic out of the mesh, as an exit node or a subnet router.
Linux only, and the daemon refuses it at startup on other platforms.
[Exit nodes](exit-nodes.md) describes the translation and the return path it
needs.

| Key                | Value            | Default | Meaning                                                             |
| ------------------ | ---------------- | ------- | ------------------------------------------------------------------- |
| `advertise`        | list of prefixes | none    | Prefixes this node offers to carry                                  |
| `translate`        | list of classes  | none    | What the source of a packet leaving the mesh becomes, by its source |
| `return`           | boolean          | `false` | Also translate traffic from the advertised prefixes into the mesh   |
| `flows_per_source` | integer          | `4096`  | The most flows 1 mesh source address holds open in a family         |
| `sweep`            | duration         | `"30s"` | Interval of the periodic pass                                       |

- `advertise` is required unless the node has an egress segment, where it may be
  empty or left out unless `return` is set. Such a node serves that segment
  alone and attracts no route.
- An exit advertises `0.0.0.0/0` and `::/0` only, for Linux and macOS clients
  alike. The `/1` halves would win over every `/0` exit by longest prefix, as
  [exit nodes](exit-nodes.md#what-to-advertise) describes. A subnet router
  advertises the prefixes behind it.
- An `advertise` prefix that
  [counts as a default](routing.md#routes-that-count-as-a-default) makes this
  node an exit for its family, as under `cap.route`, and loads with a warning
  unless it is a default.
- A prefix is announced only while its family is
  [ready](exit-nodes.md#readiness): its 2 chains, its set and its timeout
  objects read back exactly as written, with no other writer's rule in its
  chains and in a table with no flags, the host forwards that family and holds
  every address its classes name, and, where they run, the kernel's lookups of a
  translated packet and its reply pass.
- The lookups of a translated packet and its reply read from the address of a
  mesh member inside `cap.border.overlay`. A node with no `cap.border`, or whose
  mesh routes no other node's prefix of a family inside the overlay, skips that
  family's forward and reply lookups and judges it by its table, its forwarding
  and its classes' addresses alone, and `status` says so.
- A node with an egress segment translates both families, whatever `advertise`
  holds.
- An `advertise` prefix with bits set below its length, written as IPv4-mapped
  IPv6, or written twice is refused at load.
- At startup and on every reload, an `advertise` prefix that `cap.route` also
  announces is refused. That announcement would go out whether or not the rule
  is installed.
- Each class of `translate` is a `from` prefix and a `to` of `none`, `auto` or
  an address of `from`'s family, such as
  `{ from = "3fff:a::/32", to = "none" }`. A source takes the class of the
  longest `from` covering it, and `auto` where none covers it, so the order does
  not matter and a class of `auto` from `0.0.0.0/0` or `::/0` says what leaving
  it out says. The classes decide for traffic an egress segment carries as for
  traffic from an advertised prefix, and for this node's own traffic from its
  mesh addresses out of another link, as [exit nodes](exit-nodes.md#classes)
  describes.
- For traffic leaving the mesh, `auto` uses the address of the link the packet
  leaves by. The host's routes pick it for each packet. An address is used
  unchanged, and `none` leaves the source as the packet carries it, under the
  conditions [exit nodes](exit-nodes.md#none) lists.
- A family whose classes name an address is ready only while the host holds that
  address, on any link or `lo`.
- A `from` with bits set below its length, written as IPv4-mapped IPv6, or
  written twice is refused at load, and so is a class that names no `to`, an
  address of the other family, one with a zone, one written as IPv4-mapped IPv6,
  or one no reply can be sent to, global unicast and private addresses being the
  ones it can. A class of `none` from `0.0.0.0/0` or `::/0` is refused, since it
  would relay every mesh source onto the upstream untranslated.
- For traffic entering the mesh, under `return`, the source is the address of
  the family's class from `0.0.0.0/0` or `::/0` where that class names one, and
  this node's mesh address where it is `auto` or absent. The daemon picks that
  address once at startup, from the host prefixes `cap.route` announces and
  `cap.table` assigns.
- A subnet router needs `return` when the mesh has no route back to its LAN.
  With `return`, each advertised family whose class from `0.0.0.0/0` or `::/0`
  is `auto` or absent needs exactly 1 global unicast or private mesh address of
  that family. The daemon refuses to start with none or with more than 1, and
  asks for the address as that class's `to`.
- `flows_per_source` is each mesh source address's share of the flows through
  this node in each family, every protocol's together, past which its next new
  flow is refused, as
  [exit nodes](exit-nodes.md#each-sources-share-of-the-flows) describes. `0` or
  leaving it out is the default, and a value past 2147483647 is refused. The
  shares come out of the host's connection tracking table, which ranet3 never
  sizes, so size the two together.
- The periodic pass reinstalls a removed table and reads the forwarding sysctls
  again. `sweep` also caps the delay between retries of a failed pass. A
  negative `sweep` is refused.
- With `cap.border` written, an `advertise` entry longer than 0 bits that
  overlaps an `overlay` entry is refused: the hosts behind this node would
  arrive on a link outside the mesh with a mesh source, and the filter would
  drop them. The exit defaults, `0.0.0.0/0` and `::/0`, are left out of the
  test.

## `cap.border`

Drop what arrives on a link outside the mesh carrying a mesh source, an IPv6
routing header of any type or one of this node's SIDs. Linux only, and the
daemon refuses it at startup on other platforms.
[The border filter](border-filter.md) describes what it drops and where.

| Key       | Value            | Default  | Meaning                                      |
| --------- | ---------------- | -------- | -------------------------------------------- |
| `overlay` | list of prefixes | required | The prefixes the mesh numbers its nodes from |

- An empty list is refused, since the filter would pass every forged mesh
  source.
- An entry of length 0, an IPv4 entry shorter than `/8`, an IPv6 entry shorter
  than `/12`, an entry with bits set below its length, an IPv4 address written
  as IPv6 and an entry written twice are refused. The order does not matter.
- Every node of the mesh writes the same list, which covers every exit's `allow`
  list.
- On an exit, the list enables the kernel lookups of its
  [readiness](exit-nodes.md#readiness), which read from a member's address
  inside it. A family with no prefix in it skips them.
- On an exit, the list also keeps an address inside it off the uplink, as
  [exit nodes](exit-nodes.md#what-an-exit-carries-out) describe: the forwarding
  decision egresses none, and an egress segment refuses one. An exit without
  `cap.border` sends an address no node announces out of its uplink as any other
  destination outside the mesh.
- With `cap.table` on Linux, each prefix gets a policy rule at 5110 that reads
  the mesh's table for its destinations and, unless it holds its family's
  unspecified address or the mesh cannot carry it, an unreachable hold in that
  table. A lookup bound to no device for an overlay address then ends as rows L1
  to L5 of [where a lookup ends](routing.md#where-a-lookup-ends-on-linux) give.
- A file with a local segment and no `cap.border` is refused, and so is one
  whose `overlay` holds no IPv6 prefix, since every local SID acts only on an
  outer source in those prefixes. An egress segment's `allow` entry no `overlay`
  entry covers is refused too.
- The SIDs it drops are those of `cap.segment.local`, and the devices it accepts
  are derived, so neither is a key.

## `cap.exit`

Exit mode. Writing this block turns it on. The mesh's default of lowest metric
becomes this host's default, for its own traffic and for what it forwards from
the links `forward` names. Linux only. [Routing](routing.md#exit-mode-on-linux)
lists the rules it adds, and
[sharing a host](coexistence.md#exit-mode-beside-other-programs) what other
programs' rules do beside them.

| Key       | Value         | Default | Meaning                                                           |
| --------- | ------------- | ------- | ----------------------------------------------------------------- |
| `forward` | list of names | none    | Links whose forwarded traffic follows the mode as the host's does |

- The file is refused without `cap.table`, whose reconciler writes the mode's
  rules, and without `cap.border`, whose overlay keeps the mode's sources by
  main apart from the mesh's.
- The file is refused on an exit, with the reason it is one:
  `config: cap.exit sends this node's own traffic out through another exit, and this node is an exit (cap.egress advertises 0.0.0.0/0), whose own traffic and whose egress leave by its own uplink: remove cap.exit, or stop offering the exit`.
  The other reasons read
  `cap.route announces <prefix>, which counts as a default` and
  `cap.segment local <sid> delivers to egress`.
  [Exit nodes](exit-nodes.md#an-exits-own-traffic) say why.
- `via` is refused by name. This version follows the mesh's default of lowest
  metric.
- Each `forward` entry is a link's name or a pattern as Go's
  [`path.Match`](https://pkg.go.dev/path#Match) reads one, such as `docker*` or
  `br-*`. An empty entry, a malformed pattern and `lo` are refused at load. The
  order does not matter, and an entry written twice counts once.
- At startup and on every reload, a name that is the tun or the link either
  family's default leaves by is refused, since that traffic never follows the
  mode. A pattern matching one of them, or a name that becomes the uplink later,
  is skipped at each pass and logged, as [watching it](routing.md#watching-it)
  lists.
- macOS, the BSDs, Android and iOS refuse the block at startup:
  `kernel: cap.exit is refused on <platform>, where this build has no exit mode: remove cap.exit, and this host keeps its own default`.

## Daemon flags

The daemon's own settings are flags, listed on [command line](cli.md).
