---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Configuration"
description: "The configuration file: the node, its links, and the capabilities it turns on."
created: 2026-08-17
updated: 2026-10-06
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
authenticate a real node in a real mesh. Never commit real copies of either;
only synthetic fixtures belong in version control (see `.gitignore`).
