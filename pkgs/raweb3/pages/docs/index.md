---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "ranet3"
description: "What ranet3 is, and where each part of it is documented."
created: 2026-08-17
updated: 2026-10-26
order: 10
---

ranet3 is a mesh node in a single Go binary. Nodes authenticate each other with
IKEv2 and carry packets in ESP, both in userspace. An embedded Babel speaker
chooses the route to every prefix. Local applications reach the mesh through the
tun, a TUN device on Linux or a utun on macOS, over the kernel's own TCP/IP
stack.

A node dials the peers `dial.to` names. With `dial.all` it also dials every
other node in the trust document. With `link.listen` it also answers peers that
dial it. The trust document names every node of the mesh, its endpoints and the
Ed25519 key it signs with.

## Protocols

| Part           | Standard                                                                                                                                                                                                                                                                                                |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Transport      | ESP ([RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)) in tunnel mode, in UDP ([RFC 3948](https://www.rfc-editor.org/rfc/rfc3948))                                                                                                                                                                    |
| Handshake      | IKEv2 ([RFC 7296](https://www.rfc-editor.org/rfc/rfc7296)) in the minimal shape of [RFC 7815](https://www.rfc-editor.org/rfc/rfc7815), as initiator and as responder, with the IKE fragmentation of [RFC 7383](https://www.rfc-editor.org/rfc/rfc7383)                                                  |
| Authentication | Ed25519 signatures ([RFC 7427](https://www.rfc-editor.org/rfc/rfc7427), [RFC 8420](https://www.rfc-editor.org/rfc/rfc8420))                                                                                                                                                                             |
| Key exchange   | X25519, P-256 or P-384, alone or followed by ML-KEM-768 or ML-KEM-1024 ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) in `IKE_INTERMEDIATE` at setup and `IKE_FOLLOWUP_KE` at a rekey ([RFC 9242](https://www.rfc-editor.org/rfc/rfc9242), [RFC 9370](https://www.rfc-editor.org/rfc/rfc9370)) |
| Ciphers        | AES-GCM or ChaCha20-Poly1305                                                                                                                                                                                                                                                                            |
| Routing        | Babel ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)) with RTT costs ([RFC 9616](https://www.rfc-editor.org/rfc/rfc9616)) and source-specific routes ([RFC 9079](https://www.rfc-editor.org/rfc/rfc9079))                                                                                          |
| IPv4 over IPv6 | IPv4 routes with IPv6 next hops ([RFC 9229](https://www.rfc-editor.org/rfc/rfc9229))                                                                                                                                                                                                                    |
| Steering       | SRv6 ([RFC 8754](https://www.rfc-editor.org/rfc/rfc8754), [RFC 8986](https://www.rfc-editor.org/rfc/rfc8986)) with the End and End.DT46 behaviors                                                                                                                                                       |
| Path MTU       | Datagram path MTU discovery ([RFC 8899](https://www.rfc-editor.org/rfc/rfc8899)) over Babel probes                                                                                                                                                                                                      |

IKE and ESP share 1 UDP port, `link.port`. ESP always travels in UDP, and every
IKE message carries the 4-byte Non-ESP Marker from `IKE_SA_INIT` on, whether or
not a NAT is in the path. The integration checks run ranet3 against strongSwan
as initiator and as responder, against BIRD as a Babel neighbor, and against
Linux seg6local for SRv6.

## Capabilities

The top of the config file says what the node is: its name in `node`, its key
and trust document in `auth`, its port, endpoints and tun in `link`, and its
peers in `dial`. Everything else it does is a block under `cap`. `cap.table`,
`cap.segment`, `cap.egress` and `cap.border` are off until the file writes them,
and `cap.transit` until it writes `enable = true`. `cap.route`, `cap.babel` and
`cap.crypto` run with their defaults when the file leaves them out.

| Block         | What it does                                                                                                           |
| ------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `cap.route`   | Names the prefixes this node announces                                                                                 |
| `cap.transit` | Relays the routes this node learns, and so carries other nodes' traffic                                                |
| `cap.babel`   | Sets the Babel timers, the link quality estimator and the link costs                                                   |
| `cap.table`   | Runs the route reconciler, which installs routes, addresses and, on Linux, the policy rules it derives in the kernel   |
| `cap.segment` | Steers traffic by source and destination prefix through SRv6 waypoints, and lists the segments this node answers for   |
| `cap.egress`  | Translates source addresses for exit nodes and subnet routers, on Linux                                                |
| `cap.border`  | Drops what arrives from outside the mesh with a mesh source, a routing header of any type or this node's SID, on Linux |
| `cap.crypto`  | Chooses and orders the ciphers, PRFs and key exchanges, and sets the rekey intervals and the ESP replay window         |

## Running a node

`ranet3 daemon` runs the node. Most other subcommands ask it a question or tell
it to act through its control socket, `/var/run/ranet3/control.sock`. With
`--metrics` the daemon serves Prometheus metrics, and `ranet3 metrics` prints
the same series over the socket. SIGHUP or `ranet3 reload` applies most changes
to the config file and the trust document without a restart.
[Reloading](reloading.md) lists the ones that need a restart.

## Where to read next

- [Getting started](getting-started.md): building the binary and running a node
  by hand.
- [Configuration](configuration.md) and
  [the configuration reference](configuration-reference.md): the config file and
  every key it takes.
- [The trust document](trust.md): who may join the mesh, and the key files.
- [Running it as a service](service.md): the NixOS and nix-darwin modules.
- [Routing](routing.md): Babel, link costs, transit and the route reconciler.
- [Exit nodes and subnet routers](exit-nodes.md): translating traffic at an
  exit, and routing a subnet behind one.
- [Segment routing](segment-routing.md): steering through SRv6 waypoints and
  exits.
- [Path MTU](path-mtu.md): the path MTU search, Packet Too Big and MSS clamping.
- [Reloading](reloading.md): what a reload applies, and what needs a restart.
- [Command line](cli.md): every subcommand, the daemon's flags and its signals.
- [Control socket](control-socket.md) and [Metrics](metrics.md): asking a
  running node, and the series it exports.
- [Platforms](platforms.md): what differs between Linux, macOS and other
  platforms.
- [Sharing a host](coexistence.md): running beside other routing daemons,
  firewalls and VPNs.
- [What it deliberately doesn't do](design/limits.md) and
  [deliberate protocol deviations](design/protocol-deviations.md).
- [Debugging a running node](development/debug.md),
  [Testing](development/testing.md) and
  [Repository layout](development/layout.md).
