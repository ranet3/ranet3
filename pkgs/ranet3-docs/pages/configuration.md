---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Configuration"
description: "The configuration file: the node, its links, and the capabilities it turns on."
created: 2026-08-17
updated: 2026-10-20
order: 30
---

A node reads 3 files:

- The **configuration file**, which this page describes. `ranet3 daemon` reads
  `/etc/ranet3/config.toml` unless `--config` names another.
- The **trust document**, which names every node that may join and the key each
  of them signs with. It is a ranet `registry.json`, described in
  [trust document and keys](trust.md).
- The node's **private key**, a PKCS8 PEM Ed25519 file.

[The configuration reference](configuration-reference.md) lists every key with
its default and what it refuses.

## Formats

The file's extension picks the parser:

| Extension                | Parser |
| ------------------------ | ------ |
| `.toml`                  | TOML   |
| `.yaml`, `.yml`, `.json` | YAML   |

Any other extension is refused by name. The daemon does not guess the format
from the contents.

Both parsers are strict. An unknown key is an error, so a mistyped capability
fails at load instead of doing nothing. A key written twice is refused. So is a
key whose spelling differs from the real one only in case.

The loader also refuses, with the line number:

- A number with a fraction, an exponent or a minus sign in an integer field such
  as `link.port`. The YAML parser alone would cut `13000.5` to `13000` and read
  `-0` as zero.
- A YAML merge key (`<<`). TOML and JSON have no spelling for one, so a file
  writes each setting where it is used.

A second YAML document after the first, such as 2 files joined with `cat`, is
refused too.

### JSON files

A `.json` file goes to the YAML parser, which reads most JSON the same way.
These JSON spellings are refused or read differently:

- The escape `\/`. PHP's `json_encode` writes it unless given
  `JSON_UNESCAPED_SLASHES`.
- A surrogate pair escape for a character outside the Basic Multilingual Plane.
  PHP's `json_encode` writes it unless given `JSON_UNESCAPED_UNICODE`, Python's
  `json.dumps` unless given `ensure_ascii=False`, and `jq` with `-a`.
- A raw DEL character in a string.
- A raw NEL, LS or PS character in a string, which YAML reads as a line break.

### Examples

The repository ships 1 node in all 3 formats. A test loads each and checks that
they describe the same node.

- [`examples/config.toml`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.toml)
  carries comments on its keys.
- [`examples/config.yaml`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.yaml)
  is the same file in YAML.
- [`examples/config.json`](https://github.com/ranet3/ranet3/blob/master/pkgs/ranet3/examples/config.json)
  is the form a generator or a control plane writes. JSON has no comments.

## Structure

The top level says what the node **is**. Everything the node **does** lives
under `cap`, 1 block per capability. Writing `cap.table`, `cap.segment`,
`cap.egress` or `cap.border` turns that capability on. Writing `cap.route`,
`cap.babel` or `cap.crypto` changes its defaults. There is no `enabled` field.

A node that only joins the mesh writes `node`, `auth`, `link` and `dial`:

```toml
node = "example/my-laptop"

[auth]
key = "/etc/ranet3/key.pem"       # this node's private key
trust = "/etc/ranet3/trust.json"  # the trust document

[link]
port = 13000
endpoints = [{ serial = "0", family = "ip4" }]

[dial]
to = ["example/gateway:0"]

[cap.route]
announce = ["10.66.0.5/32"]       # this node's own mesh address
```

These keys are required:

- `node`
- `auth.key` and `auth.trust`
- `link.port` and at least 1 `link.endpoints` entry
- at least 1 `dial.to` entry, unless `link.listen` or `dial.all` is set

Every other key has a default. A left-out `cap.route`, `cap.babel` or
`cap.crypto` runs its defaults. A left-out `cap.table`, `cap.segment`,
`cap.egress`, `cap.border` or [`cap.transit`](configuration-reference.md) is
off. A node with no `cap.babel` sends Hellos every 4 seconds and updates every
16 seconds (RFC 8966 Appendix B). A node with no `cap.route` announces nothing.

### Capabilities

| Block         | What it turns on                                                              |
| ------------- | ----------------------------------------------------------------------------- |
| `cap.route`   | What this node announces                                                      |
| `cap.transit` | Whether this node relays the routes it learns, and so other nodes' traffic    |
| `cap.babel`   | The speaker's timers, link quality estimator and costs                        |
| `cap.table`   | The route reconciler: a routing table, addresses, a VRF and policy rules      |
| `cap.segment` | Segment routing (RFC 8986): the SIDs this node answers for and what it steers |
| `cap.crypto`  | The transforms, the replay window and the rekey timers                        |
| `cap.egress`  | Source translation for an exit node or a subnet router, Linux only            |
| `cap.border`  | A filter for forged mesh traffic arriving from other links, Linux only        |

[Routing](routing.md), [segment routing](segment-routing.md),
[exit nodes](exit-nodes.md) and [the border filter](border-filter.md) describe
what the larger blocks do.

## Names

`node` names this node as `organization/name`: the organization and common name
the trust document holds it under. The node's endpoints are its `link.endpoints`
entries, so `node` written as an endpoint is refused.

A `dial.to` entry names a peer the same way. `organization/name:serial` names 1
endpoint of a peer and dials that endpoint alone. A node name dials the first
endpoint of the node in a matching address family that carries an address and
resolves.

Every name is written in full. An organization has 1 level. These are refused:

- An entry without an organization.
- A table of `org` and `name` in place of the string.
- An entry written twice.

A byte outside letters, digits, `-`, `.`, `_` and `~` is written as `%` and 2
uppercase hex digits. The organization `nick cao` is written `nick%20cao`, and
no other spelling is taken.

The control socket, the command line, the logs and the events name nodes and
endpoints in the same form. A session is named by the peer's endpoint, `@` and
the serial of this node's own endpoint, such as `example/gateway:0@0`.

## The tun device

`link.tun` names the device the mesh runs on. The name the device actually got,
such as `utun6`, is the one ranet3 logs at startup, shows in `ranet3 status` and
gives the route reconciler.

On Linux:

- The default is `ranet3`. The daemon always creates it and never attaches to an
  existing one. It refuses to start, naming the device, when a device called
  `ranet3` exists.
- Any other name is attached to when the device exists, and created when it does
  not. A device systemd-networkd made with `MultiQueue=yes` works.
- The daemon opens 1 queue per CPU it may use, up to 256. Every device ranet3
  creates is multiqueue.
- Under a name other than `ranet3`, a second instance opens queues on the first
  instance's device. Give each instance a `link.tun` of its own.
- A single-queue tun made by another tool is attached only when the daemon opens
  1 queue. A second instance on it is refused with `EBUSY`.

On macOS:

- The default takes the next free `utun`.
- `utunN` takes unit N.
- Any other name is refused when the daemon starts. The file still loads, so 1
  file can serve a Linux node and a Mac.

## Packet size

`link.mtu` is the largest packet a session carries inside ESP, 1400 bytes by
default. A 1500 byte path carries that over IPv4 and IPv6.
[Path MTU](path-mtu.md) describes how each session finds what its path carries,
and what happens to a packet that does not fit.

## Where each capability is defined

Each capability is a type in the package that implements it, and validates
itself there:

- `cap.table` is `internal/kernel`'s `Table`.
- `cap.segment` is `srv6`'s `Segments`.
- `cap.route` and `cap.babel` are `internal/babel`'s `Routes` and `Config`.
- `cap.crypto` is `ike`'s `Crypto`.
- `cap.egress` is `internal/egress`'s `Egress`.
- `cap.border` is `internal/egress`'s `Border`.

`internal/config` holds the node's own keys and the checks that span 2
capabilities, such as a SID that is also an address the reconciler assigns. The
scalar spellings (duration, prefix, address, table and announcement) live in
`schema`. Both parsers read them the same way.

## Keep secrets out of version control

The trust document and the private key identify and authenticate a real node.
Never commit real copies of either. The repository's `.gitignore` excludes the
`.pem` files at its root and every `registry.json` but the synthetic fixture in
`internal/registry/testdata`. Only synthetic fixtures are committed.
