---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Deliberate protocol deviations"
description: "Where ranet3 departs from the IKEv2, ESP, Babel, IPv6 and ICMP specifications on purpose."
created: 2026-08-23
updated: 2026-10-16
order: 20
---

ranet3 departs from the specifications it implements in the places this page
lists. The table summarizes them, and the sections below give the details.

| RFC and section                    | The RFC says                                                                 | ranet3                                                                  | Why                                                  |
| ---------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------- |
| RFC 7296 section 2.23              | IKE starts on UDP port 500 and moves to 4500 behind a NAT                    | IKE and ESP share `link.port` from the first message                    | 1 port per node, with no transition to track         |
| RFC 7296 section 2.23              | NAT detection hashes the real source address and port                        | The source hash covers a random address, so it never matches            | The peer always encapsulates ESP in UDP              |
| RFC 7296 section 2.23              | Follow any validated packet when not behind a NAT, and none behind one       | Every session follows a fresh authenticated request, and nothing else   | A session follows a peer that moved                  |
| RFC 7296 section 2.25.1            | Complete both colliding Child SA rekeys and keep 1                           | The peer's rekey is answered `TEMPORARY_FAILURE`                        | 1 Child SA per session                               |
| RFC 7296 section 2.8               | The responder may switch to the new SA once it sends its response            | It switches just before sending the response                            | The difference is the time to encrypt 1 message      |
| RFC 7296 section 2.18              | An IKE SA rekey may choose a new PRF                                         | The PRF stays the same                                                  | strongSwan expands keys with the old PRF             |
| RFC 7296 section 4                 | After `NO_ADDITIONAL_SAS`, delete the old SA and create a new one            | The old SA stays, and the rekey is retried                              | Not implemented                                      |
| RFC 7296 section 4                 | Accept configured RSA certificates and shared keys                           | Ed25519 signatures only, against the trust document                     | Keys come from the trust document                    |
| RFC 7296 section 2.9               | Refuse unacceptable traffic selectors with `TS_UNACCEPTABLE`, or narrow them | Only the full IPv4 and IPv6 ranges, anything else `NO_PROPOSAL_CHOSEN`  | Babel picks the peer for each packet                 |
| RFC 7296 section 3.2               | Ignore the critical bit on a payload type the recipient understands          | A response that sets it on any payload is refused                       | A known gap                                          |
| RFC 8247, RFC 8221                 | Support AES-CBC, MODP group 14, HMAC integrity and RSA signatures            | AEAD ciphers and elliptic curve groups only                             | Legacy transforms are left out                       |
| RFC 4303 sections 2.6 and 2.7      | Be able to generate dummy packets                                            | None are generated, and no traffic flow confidentiality padding is sent | A known gap                                          |
| RFC 3948 section 4                 | Send NAT keepalives                                                          | None are sent                                                           | Hellos and IKE liveness checks keep the mapping open |
| RFC 4443 section 2.2               | Answer from an address of the node's own                                     | Packet Too Big comes from the packet's destination                      | A leaf may hold no address of the packet's family    |
| RFC 8966 section 3.2.2             | Raise the node's own seqno only when asked                                   | The seqno rises at every start                                          | Peers take a restarted node's routes at once         |
| RFC 8966 section 3.7.2             | Try to reach every neighbor with a triggered update                          | It is sent once                                                         | Each link is 1 ESP tunnel that delivers in order     |
| RFC 8966 sections 3.8.1.1, 3.8.1.2 | Answer a request when a selected route exists                                | Split horizon applies to replies                                        | The requester is the route's next hop                |
| RFC 8966 section 3.8.1.2           | Forward a seqno request only while advertising the prefix                    | Forwarded whenever a route exists                                       | Starvation leaves nothing advertised                 |
| RFC 8966 section 3.8.2.3           | Ask for a selected route shortly before it expires                           | No such request is sent                                                 | Not implemented                                      |
| RFC 8966 section 4                 | Make packets as large as the link's MTU allows                               | At most 1232 octets of UDP payload                                      | Every session carries 1280 bytes                     |
| RFC 8966 Appendix A.3              | Smooth the metric as an average                                              | An increase takes effect at once                                        | A route that went bad is left at once                |
| RFC 8200 section 4.5               | Wait 60 seconds for fragments, and answer errors with ICMP                   | Wait 16 seconds, send no ICMP, drop more                                | Fragments of 1 packet cross 1 session together       |

## NAT traversal and ports

ranet3 uses a private IKEv2 transport profile rather than general-purpose
[RFC 7296 NAT traversal](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
The RFC uses UDP ports 500 and 4500, hashes the actual source and destination
address/port pairs in the `NAT_DETECTION_*_IP` notifications, and moves
subsequent traffic to port 4500 when NAT is detected. In contrast:

- Each node listens on its `link.port`. A peer dials the port the trust document
  lists for the endpoint it dials. The local and remote ports are independent
  and need not have the same value. NAT may rewrite either one again.
- IKE and ESP always share that 1 UDP path. Every IKE packet, including
  `IKE_SA_INIT`, has the 4-byte Non-ESP Marker, while an ESP packet starts
  directly with its nonzero SPI.
- Both roles hash a random IPv4 address and port 0 in `NAT_DETECTION_SOURCE_IP`.
  The hash never matches, so the peer encapsulates ESP in UDP even when no NAT
  is present. The destination notification hashes a real address and port. The
  initiator hashes the endpoint it dials, and the responder the address and port
  the request came from.
- Received NAT-detection notifications are not used to select a transport: there
  is no port-500-to-4500 transition and no dedicated
  [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) NAT keepalive. The
  userspace transport accepts UDP-encapsulated ESP only, not raw IP ESP.

A strongSwan peer must therefore set `charon.port_nat_t` to the port the trust
document lists for it. Otherwise it moves to port 4500 once it detects the NAT
the mismatch reports, and nothing listens there. This profile remains usable
when a NAT changes the observed source port: replies follow the observed source,
and a fresh authenticated IKE request can update the stored peer endpoint. It is
deliberately not interoperable with an otherwise generic peer expecting standard
RFC 7296 port selection or raw ESP.

ranet3 sends no NAT keepalive, which
[RFC 3948 section 4](https://www.rfc-editor.org/rfc/rfc3948.html#section-4) asks
of a peer behind a NAT. Babel Hellos and IKE liveness checks keep the mapping
open instead. An end that has received nothing authenticated from its peer for
10 seconds sends a liveness check, and the peer answers it. Neither end of a
live session stays silent for the 2 minutes after which a NAT may drop an idle
mapping
([RFC 4787 REQ-5](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3)),
whatever `cap.babel.hello` holds. A NAT keepalive that arrives is counted and
ignored.

## Endpoint updates

Every session moves the stored peer endpoint to the address and port of a fresh
request whose integrity protection validates, and of nothing else.
[RFC 7296 section 2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23)
asks a host that is not behind a NAT to follow "a packet whose integrity
protection validates", which takes in IKE responses and ESP packets as well, and
asks a host behind a NAT not to follow at all. ranet3 departs from both. A
response or an ESP packet from a new address moves nothing, and a fresh request
moves the endpoint whether or not the node is behind a NAT. A node never learns
whether it is behind one, because it does not compare the
`NAT_DETECTION_DESTINATION_IP` it receives with its own address.

Behind a NAT, someone who captures a request and resends it from another address
before the original arrives can move a session's sends to that address. The
peer's next fresh request moves them back. The peer sends one once it has heard
nothing from this node for its liveness interval, 10 seconds on a ranet3 peer.
In exchange a session follows a peer that moved, whichever end dialed.

## Rekeying

ranet3 departs from a SHOULD of
[RFC 7296 section 2.25.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.1).
If both peers initiate a rekey of the same Child SA concurrently, ranet3 answers
the peer's rekey with `TEMPORARY_FAILURE`. The RFC recommends completing both
exchanges, temporarily retaining the redundant SAs, and using the 4 nonces to
decide which new SA to delete. Returning the error keeps ranet3's
single-Child-SA state machine simple. Both ends fail at the same instant and
reset the same backoff, so the retry is drawn from the upper half of its window
rather than run at the window's end. Without that spread the retry reproduces
the phase difference that caused the collision and collides again indefinitely,
which is the jitter
[RFC 7296 section 2.8.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8.1)
asks for.

A responder switches its outbound Child SA to the replacement just before it
sends the rekey response rather than just after.
[RFC 7296 section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8)
permits sending on the new SA "as soon as it sends its response", so the
difference is the time to encrypt 1 message. Either way, the peer cannot decrypt
the new SA until the response reaches it, so a peer-initiated rekey loses
outbound traffic for the response's flight time. The same section also allows a
conservative option, staying on the old SA until the peer proves it has the new
one. That option would close the gap. Rekeying runs about once an hour per peer
at the defaults, whichever end drives it. Babel's own traffic is periodic enough
not to notice.

IKE rekeys retain the negotiated PRF. This avoids differing key expansion
behavior between
[strongSwan](https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/keymat_v2.c)
and
[RFC 7296 section 2.18](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.18)
when the PRF changes, while allowing fresh DH keys and a different encryption
algorithm. Peer Child-SA rekeys can use X25519, P-256, or P-384 for PFS. Locally
initiated Child rekeys derive keys from the IKE SA without an additional DH
exchange.

A Child SA rekey keeps the cipher of the SA it replaces, in both directions.
[RFC 7296 section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8)
says a rekeyed Child SA "SHOULD NOT have different Traffic Selectors and
algorithms than the old one", and ranet3 holds a peer to that. It offers only
the current cipher when it rekeys. A peer's rekey that does not offer the
current cipher is refused with `NO_PROPOSAL_CHOSEN`. This is within the RFC.

When a peer refuses a rekey with `NO_ADDITIONAL_SAS`,
[RFC 7296 section 4](https://www.rfc-editor.org/rfc/rfc7296.html#section-4)
requires that the node can delete the old SA and create a new one instead.
ranet3 keeps the old SA and retries the rekey on its backoff, from 5 seconds up
to 5 minutes at the defaults. Only `CHILD_SA_NOT_FOUND` makes it create a new
Child SA from scratch.

## Authentication

Authentication is an Ed25519 signature
([RFC 7427](https://www.rfc-editor.org/rfc/rfc7427.html),
[RFC 8420](https://www.rfc-editor.org/rfc/rfc8420.html)) checked against the key
[the trust document](../trust.md) holds for the peer. There is no certificate,
shared key or EAP.
[RFC 7296 section 4](https://www.rfc-editor.org/rfc/rfc7296.html#section-4)
requires that every implementation can be configured to accept PKIX certificates
signed by RSA keys and shared key authentication. ranet3 supports neither.

The minimal profile of [RFC 7815](https://www.rfc-editor.org/rfc/rfc7815.html)
does not cover this. It describes an initiator only (section 1), and it carries
a raw public key in a CERT payload (Appendix B.2). ranet3 also answers as a
responder and sends no CERT payload. Refusing additional Child SAs with
`NO_ADDITIONAL_SAS` is within RFC 7296.

A node answers handshakes as a responder only when `link.listen` is set. A full
mesh needs every node to answer as well as dial.

Identities are compared by name rather than by their DER bytes. ranet3 writes
`O` and `CN` as `UTF8String`, while strongSwan picks the string type from the
value. The same name therefore reaches the wire in 2 encodings. AUTH signs the
bytes as received either way, so the name only selects which key must verify it.

## Critical payloads

[RFC 7296 section 3.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.2)
says the critical bit "MUST be ignored by the recipient if the recipient
understands the payload type code". ranet3 holds the requests it receives to
that, but refuses a response that sets the bit on any payload, a type it
implements included. An initiator that refuses an `IKE_AUTH` response this way
tells the responder in the `INFORMATIONAL` exchange that follows, with
`INVALID_SYNTAX` for a payload type ranet3 implements and
`UNSUPPORTED_CRITICAL_PAYLOAD` for one it does not.

## Algorithms

ranet3 offers and accepts only these algorithms:

| Use            | Algorithms                                                          |
| -------------- | ------------------------------------------------------------------- |
| IKE encryption | AES-GCM with a 16-octet tag, 256 or 128-bit keys, ChaCha20-Poly1305 |
| IKE PRF        | HMAC-SHA2-384, HMAC-SHA2-256                                        |
| Key exchange   | X25519, P-384, P-256                                                |
| Authentication | Ed25519                                                             |
| ESP encryption | AES-GCM with a 16-octet tag, 256 or 128-bit keys, ChaCha20-Poly1305 |
| ESP integrity  | none, since every cipher is AEAD                                    |

[RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html) makes `ENCR_AES_CBC`
(section 2.1), `AUTH_HMAC_SHA2_256_128` (section 2.3), MODP group 14 (section
2.4), and RSA and shared key authentication (section 3.1) MUST for IKEv2.
[RFC 8221](https://www.rfc-editor.org/rfc/rfc8221.html) makes `ENCR_AES_CBC` and
`ENCR_NULL` (section 5) and `AUTH_HMAC_SHA2_256_128` (section 6) MUST for ESP.
ranet3 implements none of them. A peer has to support at least 1 algorithm in
each row of the table.

## Traffic selectors

Every Child SA carries exactly 2 traffic selectors on each side, the full IPv4
range and the full IPv6 range. ranet3 proposes those and accepts nothing else. A
request with any other selectors is refused with `NO_PROPOSAL_CHOSEN`.
[RFC 7296 section 2.9](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.9)
has a responder narrow the selectors, or refuse with `TS_UNACCEPTABLE` when it
accepts no part of them. ranet3 never narrows and never sends `TS_UNACCEPTABLE`.
Babel picks the peer for each packet after the kernel routes it to the tun, so
every session carries all traffic of both families.

## ESP

[RFC 4303 section 2.6](https://www.rfc-editor.org/rfc/rfc4303.html#section-2.6)
says a transmitter must be capable of generating dummy packets, with next header
59. ranet3 generates none, and discards those it receives. It also sends no
traffic flow confidentiality padding
([section 2.7](https://www.rfc-editor.org/rfc/rfc4303.html#section-2.7)), which
the SA management protocol would have to negotiate. ranet3 treats the 2 as a
known gap rather than a decision.

## ICMP answers

A packet larger than its session carries is answered from the address it was
going to rather than from one of this node's own.
[RFC 4443 section 2.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.2)
has a node answer a packet addressed elsewhere from a unicast address of its
own, and
[RFC 1812 section 4.3.2.4](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.4)
has a router answer from an address of the interface the answer leaves by.
ranet3 answers from the destination for 2 reasons. The node that read the packet
off its tun writes the answer back into the tun, and that node is often a leaf
with no address of the packet's family. A waypoint is a hop inside the tunnel
that the sender never addressed.

The sender's stack matches an ICMP error to its connection by the packet the
error quotes. Linux takes the smaller path MTU to the destination from such an
answer. The `internal/netstack` root tests check this for both families, at the
node that read the packet and behind a waypoint. The Time Exceeded and Parameter
Problem a refused segment gets also come from the segment's destination. That
address is one of this node's own segments, which is within the RFC.

## Babel

### The seqno at start

A node's own Babel seqno rises at every start of its speaker, which
[RFC 8966 section 3.2.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.2.2)
asks a node not to do unprompted, since a higher seqno leaves other nodes fewer
feasible routes to fall back on. A process keeps the router id the node had
before, from the file [the state directory](../service.md#the-state-directory)
holds, and starts 1 past the seqno limit there, which is ahead of every seqno
the node has sent unless a write of the limit failed or the node starts from an
older copy of its state directory. The speaker that `ranet3 up` starts again
sends 1 past the seqno of the run before it. A node still holding the old
routes, with the feasibility distance it recorded for them, finds the new ones
newer and takes them at once. A seqno that did not move would leave them
unfeasible there until seqno requests raised it, or for the 3 minutes the source
entry lives after its last update. The limit runs 256 ahead of the seqno in use,
so a start moves the seqno on by at most 257, and the order of
[section 3.2.1](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.2.1)
compares 2 seqnos less than 32768 apart. That leaves room for 127 starts in a
row, inside the time a node keeps a feasibility distance, before one recorded
before the first could read as newer than the seqno after the last.

### Packet size

The speaker makes its packets at most 1232 octets of UDP payload, which with the
IPv6 and UDP headers is the 1280 octets IPv6 asks of any link, where
[RFC 8966 section 4](https://www.rfc-editor.org/rfc/rfc8966.html#section-4) has
a speaker make them as large as the link's MTU allows. The link is a session
whose budget its search moves, and a packet sized to the budget it had when it
was built could meet a smaller one, while every session carries 1280 whatever
its path. A full table then goes in more packets: about 38 prefixes of length 64
to a packet when each has its own origin, up to about 61 when they share one,
and fewer with longer prefixes or a source prefix. The only Babel packet past
1232 is the probe the search sends, an Ack Request padded with PadN to the size
it measures, which any speaker answers with its Ack and otherwise ignores.

### Updates and requests

| RFC 8966 section | The RFC says                                                                            | ranet3                                                                           |
| ---------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| 3.7.2            | Make a reasonable attempt to reach every neighbor with a triggered update or retraction | Sends it once, with no acknowledgment and no repeat                              |
| 3.8.1.1          | Send an update for a requested prefix that has a selected route                         | Sends a retraction when the selected route's next hop is the requester           |
| 3.8.1.2          | Send an update for a seqno request the selected route satisfies                         | Forwards the request instead when the selected route's next hop is the requester |
| 3.8.1.2          | Forward a seqno request only while advertising the prefix                               | Forwards it whenever it has a route to the prefix                                |
| 3.8.2.3          | Send a route request to the neighbor shortly before a selected route expires            | Sends none                                                                       |
| Appendix A.3     | Smooth the metric as an exponential average                                             | Follows an increase at once and smooths only improvements                        |

Each link is 1 ESP tunnel that delivers in order rather than lossy multicast.
The periodic update and the retraction hold cover a lost triggered update.

Forwarding a seqno request matters most when every route to a prefix has become
unfeasible. Nothing is advertised then, so the RFC's rule would forward nothing.

The smoothed metric is the worst the route has been over the last few time
constants. A route that has gone bad is left at once. A route still has to stay
good before it is switched to, as Appendix A.3 asks.

### Reassembly

A Babel packet a neighbor's stack cut into fragments is put back together before
the speaker reads it. Other speakers send packets of up to 1443 UDP octets,
which their stacks may fragment. A speaker on a kernel socket has the kernel
reassemble them. ranet3 reads the inner packets of each session itself, so it
reassembles, as
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
describes, the fragments sent to its speaker: an IPv6 packet whose next header
is Fragment, from a link-local address, to `ff02::1:6` or to the speaker's own
link-local address. Such a fragment is the speaker's whether its packet
completes or not, and never reaches the tun. Any other fragment, ordinary
traffic to an address of the mesh among them, goes to the tun as it arrived, and
the kernel reassembles it for its socket. The packet put back together goes
through the checks an unfragmented one does, and on to the neighbor of the
session its fragments came through.

The reassembly departs from RFC 8200 in 5 places, each toward dropping:

- A datagram waits 16 seconds after its first fragment rather than 60. The
  fragments of 1 packet leave the neighbor together over 1 session, and a packet
  still missing one after an update interval, 16 seconds at the defaults BIRD
  and babeld share, is repeated by the neighbor's next periodic update long
  before the routes it carried expire.
- No ICMP error is sent, neither the Time Exceeded for a datagram that ran out
  of time nor the Parameter Problem for a fragment with more to come whose
  length is not a multiple of 8 octets or one past the largest packet.
  [RFC 4443 section 2.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
  forbids most errors about a packet sent to a multicast group, where nearly
  every Babel packet goes, and the speaker sends none for the few sent to it
  alone.
- A packet may be 65535 octets with its IPv6 header, the largest
  [RFC 8966 section 4](https://www.rfc-editor.org/rfc/rfc8966.html#section-4)
  allows, where RFC 8200 allows a payload that long after the header. A fragment
  that runs past it drops its datagram.
- The first fragment must begin with a UDP header to the Babel port, which is
  the whole header chain [RFC 7112](https://www.rfc-editor.org/rfc/rfc7112.html)
  asks for in a packet that carries no extension header but its Fragment header.
  A first fragment without it drops its datagram.
- A fragment wrong in itself drops its whole datagram rather than only itself:
  one that carries nothing, one with more to come that is not a multiple of 8
  octets, one past the largest packet, one past the end the last fragment set,
  and a last one ending before octets another brought.

A fragment overlapping octets another brought drops its datagram and every
fragment of it still to come, as
[RFC 5722](https://www.rfc-editor.org/rfc/rfc5722.html) asks, unless every octet
it carries is already held with the same value. Such a copy goes alone, which
RFC 8200 allows for an exact duplicate, and the same holds for one spanning 2
fragments. A datagram read or dropped stays for the rest of its 16 seconds
unless a newer one takes its place, so a fragment of it arriving late goes with
it and a copy is not read twice. An atomic fragment, at offset 0 with no more to
come, is read at once as the packet it carries, as
[RFC 6946 section 4](https://www.rfc-editor.org/rfc/rfc6946.html#section-4)
asks, provided it begins with a UDP header to the Babel port.

Each neighbor holds at most 16 datagrams, under way, read or dropped, and 256
KiB of storage for the ones under way, 4 packets of the largest size. A datagram
not read keeps its place, and one under way its storage, for at least 1 second
after its first fragment. The fragments of 1 packet cross a session back to
back, and a session of 1 Mbit/s carries even the largest Babel packet within
that second. Once the 16 places are taken, a new datagram takes the place of the
oldest one read, or dropped and past that second, and failing that of the oldest
one under way past it, which it drops. It reuses the bookkeeping of the datagram
it replaces. The storage a datagram grows into comes from the oldest others
under way past that second. A fragment that finds no place, or a datagram no
storage, is refused. Each place then goes to at most 1 datagram not read each
second, and a datagram allocates under 128 KiB of storage in all. A neighbor
flooding fragments of datagrams that never complete has the node allocate under
2 MiB of storage a second and hold under 280 KiB, its bookkeeping included, and
it evicts and refuses only datagrams of its own. A datagram that completes
allocates under 4 times the octets its fragments carry. The state belongs to the
session's neighbor, so a session that ends takes its datagrams along.
[The metrics](../metrics.md) count each neighbor's packets read from fragments,
the largest of them, and the datagrams dropped and why. A datagram refused a
place counts once for each of its fragments.
