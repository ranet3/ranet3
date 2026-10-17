---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Trust document and keys"
description: "The document naming who may join the mesh, and the key files nodes authenticate with."
created: 2026-10-16
updated: 2026-10-17
order: 38
---

The trust document names every node that may join the mesh, its endpoints, and
the key it signs with. Every node reads it from `auth.trust`. A handshake
succeeds only between nodes the document names, each proving it holds the key of
the block that lists it.

The format is the `registry.json` of ranet: a JSON array of organizations.

## Format

```json
[
  {
    "organization": "example",
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----",
    "nodes": [
      {
        "common_name": "gateway",
        "endpoints": [
          {
            "serial_number": "0",
            "address_family": "ip4",
            "address": "192.0.2.1",
            "port": 13000
          },
          {
            "serial_number": "1",
            "address_family": "ip6",
            "address": "gateway.example.net",
            "port": 13000
          }
        ],
        "remarks": {}
      }
    ]
  }
]
```

### Organization

| Field          | Meaning                                                                                 |
| -------------- | --------------------------------------------------------------------------------------- |
| `organization` | The organization's name, the first half of every node name                              |
| `public_key`   | The Ed25519 public key every node of this block signs with, as a PEM `PUBLIC KEY` block |
| `nodes`        | The nodes of this organization                                                          |

An organization may appear in more than 1 block, each with its own key. A node
is verified with the key of the block that lists it.

### Node

| Field         | Meaning                                     |
| ------------- | ------------------------------------------- |
| `common_name` | The node's name within its organization     |
| `endpoints`   | The addresses peers dial this node at       |
| `remarks`     | Any JSON value. ranet3 reads and ignores it |

The node's full name is `organization/common_name`, written as
[configuration](configuration.md#names) describes.

### Endpoint

| Field            | Meaning                                                               |
| ---------------- | --------------------------------------------------------------------- |
| `serial_number`  | The endpoint's name within its node, the part after `:`               |
| `address_family` | `ip4` or `ip6`                                                        |
| `address`        | A literal address, a hostname, or `null` for an endpoint nobody dials |
| `port`           | The UDP port peers dial                                               |

- A literal address of another family is never dialed.
- A hostname is resolved on every dial, filtered to the endpoint's family.
- An endpoint with no address, an empty one, or a name holding `:`, `/` or a
  space is never dialed. Its node can still dial out and be answered.
- Peers dial the `port` listed here. Keep it equal to the node's own
  `link.port`, which ranet3 does not check.

## What is refused

The whole document is refused, and the daemon does not start or reload, when:

- It is not a JSON array of organizations, or carries a field this page does not
  list.
- Anything follows the array.
- An organization has no name, or its `public_key` is not an Ed25519 key in PEM.
- A node has no `common_name`, or its name appears twice in 1 organization,
  across all of that organization's blocks.
- An endpoint has no `serial_number`, a `port` of 0, or an `address_family`
  other than `ip4` and `ip6`.
- 2 endpoints of 1 node share a `serial_number`.

## How a node uses it

At startup and on every reload, a node checks itself against the document:

- The document must name `node`.
- The public half of `auth.key` must be the key the document holds for the node.
- Each `link.endpoints` entry must be an endpoint the document lists for the
  node, in the same family.
- Every node and endpoint `auth.aliases` names must be in the document. One it
  lacks refuses the start, and a reload logs it instead.

A reload reads the document again. It closes every session whose peer the new
document drops or lists under a different key. [Reloading](reloading.md)
describes the rest. `ranet3 status` shows how many organization blocks and nodes
the document holds.

### IDs on the wire

On the wire, each side of a handshake names an endpoint in an ID payload. A
ranet3 node names itself by an X.501 distinguished name of O, CN and
serialNumber (`ID_DER_ASN1_DN`), unless `auth.aliases.local` gives it another ID
toward that peer. The other side reads the endpoint the ID names, looks it up in
the document and verifies the signature with that node's key (RFC 7427 with
Ed25519, RFC 8420). The ID only selects the endpoint, and the key always comes
from the document. An initiator that refuses the responder's ID or signature
says so with `AUTHENTICATION_FAILED` in the exchange that follows, and a ranet3
responder then ends the session it had opened.

An ID names an endpoint when it is:

- a DN of O, CN and serialNumber
- an `ID_KEY_ID` whose octets spell the endpoint as `organization/name:serial`
- an `ID_IPV4_ADDR`, `ID_IPV6_ADDR`, `ID_FQDN`, `ID_RFC822_ADDR` or `ID_KEY_ID`
  that an entry of `auth.aliases.remote` matches, as the
  [configuration reference](configuration-reference.md#authaliases) describes

Any other ID is refused with `AUTHENTICATION_FAILED`: one no entry matches, an
address ID whose length is not that of its family, and an ID of another type. So
is an initiator whose ID names a node and no endpoint, such as a DN without
serialNumber. An address ID is never compared with the address the packet came
from.

An initiator asks for the endpoint it dials in IDr: by its DN where
`auth.aliases.remote` names it by no ID, by the 1 ID that names it, and not at
all where several do, since it cannot know which one the responder holds. It
accepts only an IDr that names the endpoint it dialed.

A responder answers as an endpoint the initiator asked for, or refuses with
`AUTHENTICATION_FAILED`. It never answers as another one.

- An IDr that names an endpoint, by its DN, by a key ID spelling it or through
  this node's own `auth.aliases.remote`, is answered as that endpoint when it is
  one of this node's endpoints of the family the request arrived in, and refused
  otherwise. This holds even where `auth.aliases.local` presents the same ID.
- With no IDr, or one that names no endpoint and holds an ID
  `auth.aliases.local` presents to some peer, the responder answers as its 1
  endpoint of the family the request arrived in.
- Any other IDr is refused.

The responder sends back the ID asked for, a DN in its own encoding. With no IDr
it sends the ID `auth.aliases.local` presents to the initiator, or else its DN.
Each end records which ID named its peer in an `ike.id.resolved` event, as
[debugging](development/debug.md#events) describes.

### Families

A local endpoint dials only remote endpoints of its own family, so a responder
takes a handshake only where the families agree. Once the initiator's signature
verifies, the responder refuses with `AUTHENTICATION_FAILED`:

- an initiator whose ID names an endpoint the document lists in the other family
  than the one the request arrived in
- an IDr naming one of this node's endpoints of the other family
- a request it would answer by family when this node's `link.endpoints` holds
  none or more than 1 entry of that family

A node with 1 IPv4 endpoint therefore refuses a request that reaches it over
IPv6, with or without an IDr. A request from an IPv4-mapped address counts as
IPv4. A node with 2 endpoints in 1 family still answers as either of them a peer
that asks for it in IDr, as a ranet3 peer does unless its `auth.aliases.remote`
names that endpoint by several IDs.

## Key files

`auth.key` is the node's private key: an Ed25519 key in a PKCS8 PEM
`PRIVATE KEY` block. Every node of an organization block holds the same key.

OpenSSL writes both halves:

```sh
openssl genpkey -algorithm ed25519 -out key.pem
openssl pkey -in key.pem -pubout -out pub.pem
jq -Rs . pub.pem    # the public key as a JSON string for public_key
```

## Keep it private

The private key authenticates every node of its organization. Store it with mode
0600, outside any version-controlled tree, and pass it to the node by path. The
[NixOS and nix-darwin modules](service.md) refuse a `settings.auth.key` in the
Nix store.

The trust document holds no secret, but it lists every node's address. The
repository's `.gitignore` excludes every `registry.json` except the synthetic
fixture in `internal/registry/testdata`.
