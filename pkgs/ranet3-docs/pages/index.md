---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "ranet3"
description: "What ranet3 is, and how a node turns a registry into encrypted routes."
created: 2026-08-17
updated: 2026-10-06
order: 10
---

A slim client for a [ranet](https://github.com/NickCao/ranet) mesh: a minimal
IKEv2 initiator, userspace ESP, a real Linux TUN device, and an embedded Babel
routing speaker, all in a single Go binary.

It reads the exact same `registry.json` and Ed25519 key files as `ranet` itself,
so it can join an existing deployment without re-provisioning anything, but it
has its own local config format (see [Configuration](configuration.md)) suited
to dialing out to one or a few existing mesh nodes rather than participating in
ranet's full N-to-N reconciliation.

## How it works

- **IKEv2** ([RFC 7815](https://www.rfc-editor.org/rfc/rfc7815)-style minimal
  initiator) using X25519, P-384 or P-256, AES-GCM / ChaCha20-Poly1305,
  SHA-256/384. Authenticates with a raw Ed25519 key via
  [RFC 7427](https://www.rfc-editor.org/rfc/rfc7427) Digital Signature auth
  ([RFC 8420](https://www.rfc-editor.org/rfc/rfc8420) EdDSA), and forces UDP
  encapsulation unconditionally on the one explicit registry port, interoperates
  with a real strongSwan responder as provisioned by ranet.
- **ESP** ([RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)) tunnel-mode AEAD
  encap and decap with anti-replay, entirely in userspace, with no kernel XFRM
  state.
- A real **TUN device**, so local applications talk to the mesh over ordinary IP
  sockets through the kernel's own TCP/IP stack, with no SOCKS5 proxy and no
  userspace network stack. Creating the device needs `CAP_NET_ADMIN`. Address
  and route configuration also require administrative privileges and are managed
  separately (see [Configuration](configuration.md)).
- An embedded minimal **Babel** speaker
  ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)), including the RTT
  extension ([RFC 9616](https://www.rfc-editor.org/rfc/rfc9616)) and IPv4
  announcements with an IPv6 next hop
  ([RFC 9229](https://www.rfc-editor.org/rfc/rfc9229)). Interoperates with
  [BIRD](https://bird.network.cz/) as the reference peer implementation.
