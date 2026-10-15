---
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: CC-BY-4.0
title: "Trust document and keys"
description: "The document naming who may join the mesh, and the key files nodes authenticate with."
created: 2026-10-16
updated: 2026-10-16
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

On the wire, each side of a handshake names its endpoint as an X.501
distinguished name of O, CN and serialNumber (`ID_DER_ASN1_DN`). The other side
looks the name up in the document and verifies the signature with that node's
key (RFC 7427 with Ed25519, RFC 8420).

A reload reads the document again. It closes every session whose peer the new
document drops or lists under a different key. [Reloading](reloading.md)
describes the rest. `ranet3 status` shows how many organization blocks and nodes
the document holds.

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
