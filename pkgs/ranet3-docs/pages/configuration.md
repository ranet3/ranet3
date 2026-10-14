---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Configuration"
description: "The configuration file: the node, its links, and the capabilities it turns on."
created: 2026-08-17
updated: 2026-10-14
order: 30
---

ranet3 needs two files:

- A **trust document**, today a `registry.json` in the exact format ranet itself
  uses (see `internal/registry/testdata/registry.json` for a fully worked,
  synthetic example spanning multiple organizations, nodes, and endpoint address
  families).
- A **configuration file**, read by the extension it carries: `.toml` goes to
  the TOML parser, and `.yaml`, `.yml` and `.json` go to the YAML one. A `.json`
  file is read as YAML, and JSON that YAML reads otherwise loads differently or
  not at all. The YAML parser refuses a `\/` escape, the surrogate pair escape
  of a character outside the Basic Multilingual Plane, a raw DEL and a key
  written twice, among others, and reads a raw NEL, LS or PS in a string as a
  line break. In those files the loader refuses a number written with a
  fraction, an exponent or a minus sign in an integer field such as `link.port`,
  with its line, where the parser alone cuts `13000.5` to `13000` and reads `-0`
  as zero. It refuses a merge key (`<<`) with its line too, because TOML and
  JSON have no spelling for one, and a file that shares settings through it
  writes them out where each is used. An extension neither knows is refused by
  name rather than sniffed. Both decoders are strict, so an unknown key is an
  error under either: a mistyped capability that silently does nothing is the
  worst failure a configuration file has. See
  [`examples/config.toml`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.toml)
  for the annotated reference,
  [`examples/config.yaml`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.yaml)
  for the same schema in YAML, and
  [`examples/config.json`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.json)
  for it in JSON. All three describe one node, which a test holds by loading
  each and comparing the three whole. JSON carries no comment and the decoder
  refuses an unknown key, so that example cannot annotate itself and cannot
  smuggle an explanation in under a spare key either. It is the form a generator
  or a control plane writes, and the TOML file is where the keys are explained.
  PHP's `json_encode` writes a solidus as `\/` unless given
  `JSON_UNESCAPED_SLASHES`. It and Python's `json.dumps` write a character
  outside the Basic Multilingual Plane as a surrogate pair unless given
  `JSON_UNESCAPED_UNICODE` and `ensure_ascii=False` respectively, as `jq` does
  with `-a`.

The top level says what the node **is**. Everything it **does** lives under
`cap`, one block per capability, and writing the block turns that capability on.
There is no `enabled` field to forget. A default deployment writes `node`,
`auth`, `link` and `dial` and stops:

```toml
[node]
org = "example"
name = "my-laptop"

[auth]
key = "/etc/ranet3/key.pem"     # this node's own PKCS8 PEM Ed25519 key
trust = "/etc/ranet3/trust.json" # the document saying who may join

[link]
port = 13000
endpoints = [{ serial = "0", family = "ip4" }]
# listen = true                     # answer peers that dial this node
# tun = "ranet0"                    # this device rather than ranet3, see below
# mtu = 1400                        # the largest packet a session carries, see below
# [link.underlay]                   # keep the underlay out of the mesh's own routing
# mark = 0x726c                     # SO_MARK plus a rule under cap.table.rules, linux only
# bind = true                       # IP_BOUND_IF plus a scoped default, darwin only

[dial]
# all = true                        # dial every node the trust document names
to = [{ name = "gateway", serial = "0" }]

[cap.route]
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8:1::/48" }]
# transit = false                   # stop relaying what this node learns
```

Required: `node.org`, `node.name`, `auth.key`, `auth.trust`, `link.port`, at
least one `link.endpoints` entry, and, unless `link.listen` or `dial.all` is
set, at least one `dial.to` entry. Everything else has a default, and an absent
capability is its own default: a node with no `cap.babel` runs the 4s and 16s
intervals of RFC 8966 Appendix B, and a node with no `cap.route` announces
nothing and still carries transit.

`link.tun` names the device the mesh runs on. Left out, linux creates `ranet3`
and darwin takes the next free `utun`. A queue opened under the name of a
multiqueue TUN joins that device, and `ranet3` is therefore only ever created,
never attached to: ranet3 refuses to start, naming the device, when one called
`ranet3` already exists, and a second instance on one host names a device of its
own in `link.tun`. Any other name is attached to on linux when the device
exists, such as one systemd-networkd made with `MultiQueue=yes`, and created
when it does not. Two instances given the same name share that one device when
it is multiqueue, as every device ranet3 creates is, and a single-queue TUN made
by something else admits one queue and refuses the second instance with `EBUSY`.
darwin's utun control creates nothing but `utun`, its next free unit, and
`utunN`, unit N, and ranet3 refuses to start there on any other name, while the
file itself loads on either platform, as with `link.underlay`. The name the
device was given, `utun6` for instance, is the one ranet3 logs at startup,
reports in `ranet3 status` and hands the route reconciler.

`link.mtu` is the largest packet a session carries inside ESP, 1400 bytes when
it is left out, which a 1500 byte path carries over IPv4 and IPv6 alike. The tun
runs at `link.mtu` less the header the longest steer list in `cap.segment` puts
in front of a packet, 40 bytes of outer IPv6 header, 8 of routing header and 16
for each segment, because a steered packet carries that header inside the
tunnel. A value that leaves the tun under the 1280 bytes IPv6 requires of every
link, or one past 65470, the most one ESP-in-UDP datagram carries over IPv4, is
refused when the file loads. The buffers the tun is read into are sized at
startup for `link.mtu`, and at least 2048 bytes, which bounds how far a reload
can raise it, as [reloading](reloading.md) describes.

On linux and darwin `link.mtu` is the most a session carries, and each session
searches the path to its peer's endpoint for its budget, the largest packet it
carries, as the datagram path MTU discovery of
[RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) does. Every datagram
leaves with DF set, so a hop too narrow for one drops it rather than cutting it,
and [the platforms](platforms.md) say how each sets it and what a platform that
cannot does instead. The target is the lesser of `link.mtu` and what the host's
route to the endpoint carries. A session starts at the lesser of its target and
1400 and probes that size with a Babel Ack Request padded with PadN to it, which
the peer's speaker answers with an Ack. Each answered probe moves the budget up
to its size, and the search probes halfway between the largest size the path
carried and the least it lost until the two meet. A size is lost once 3 probes
of it in a row went unanswered for 6 seconds each, which is under the 15 seconds
RFC 8899 recommends, since a search through a dozen sizes would wait minutes on
that, and past the 4.8 seconds FRR took to answer an Ack Request where it was
measured. A settled session probes its budget again every 30 seconds while it
carries data, and when a confirmation is lost it drops to 1280 at once and
searches the sizes under the one it lost. Every 10 minutes it reads the route
again and searches up, which finds a path that widened. A send the host refuses
as larger than the path carries reports the route's MTU, which lowers the budget
at once and never raises it. A session that moves to another endpoint searches
the new path from the start, and a network change or `ranet3 debug probe` has
every session probe its budget at once. The budget stays between 1280 and
`link.mtu`, and [`ranet3 debug pmtu`](development/debug.md) shows each session's
search. A path too narrow to carry 1280 bytes in one datagram puts its session
under the floor, where the host fragments the session's datagrams, with the
limits [the design's limits](design/limits.md) give.

A packet larger than its session carries is not sent as it is. One read off the
tun is answered with Packet Too Big when it is IPv6 and with fragmentation
needed when it is IPv4 with DF set, naming what the session carries less the
steering header the packet would take. The answer is written into the tun from
the address the packet was going to, and the host that sent the packet records
that smaller path MTU for the destination. An IPv4 packet without DF is cut into
fragments that fit, as RFC 791 has a router do, and its destination puts it back
together. A node moving a steered packet on to its next segment answers or cuts
the packet it carries the same way when the session to that segment carries less
than the segment, as [segment routing](segment-routing.md) describes. Every
answer comes out of one budget per node, 8 at once and then one each 250
milliseconds, shared with the Time Exceeded and Parameter Problem a refused
segment gets, and a packet past it is dropped without one.

A TCP SYN or SYN-ACK read off the tun has its MSS option lowered to what its
session carries, less 40 bytes of headers under IPv4 and 60 under IPv6, and less
the steering header when a policy steers it. One arriving through a session has
its MSS lowered the same way to what that session carries back. The clamp only
ever lowers an MSS and updates the checksum with it, and a host behind either
end then learns an MSS that fits the sessions of both ends. A SYN with no MSS
option, a fragment, IPv6 with an extension header before TCP and an option list
that does not describe itself pass untouched.

The capabilities, each documented in full in the example:

| block         | what it turns on                                                             |
| ------------- | ---------------------------------------------------------------------------- |
| `cap.route`   | what this node announces, and whether it relays what it learns               |
| `cap.babel`   | the speaker's own timers, link quality estimator and costs                   |
| `cap.table`   | the route reconciler: a routing table, addresses, a VRF and policy rules     |
| `cap.segment` | segment routing, RFC 8986: the SIDs this node answers for and what it steers |
| `cap.crypto`  | the replay window and the rekey timers                                       |

A capability is defined once, by the package that implements it, and validates
itself there: `cap.table` is the type `internal/kernel` takes, `cap.segment`'s
members are `srv6`'s, and `internal/babel` takes `cap.babel` and `cap.route`
directly. `internal/config` holds the node's own facts and the checks that span
two capabilities, such as a SID that is also an address the reconciler assigns.
The scalar spellings, a duration, a prefix, an address, a table and an
announcement, live in `schema` and carry both decoders, so a field parses the
same way whichever extension the file has.

**Your trust document and private key are sensitive.** They identify and
authenticate a real node in a real mesh. Never commit real copies of either:
only synthetic fixtures belong in version control (see `.gitignore`).
