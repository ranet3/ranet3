---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Deliberate protocol deviations"
description: "Where ranet3 departs from the IKEv2, ESP, Babel, IPv6 and ICMP specifications on purpose."
created: 2026-08-23
updated: 2026-10-14
order: 20
---

ranet3 uses a private IKEv2 transport profile tailored to a ranet deployment
rather than general-purpose
[RFC 7296 NAT traversal](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
The RFC uses UDP ports 500 and 4500, hashes the actual source and destination
address/port pairs in the `NAT_DETECTION_*_IP` notifications, and moves
subsequent traffic to port 4500 when NAT is detected. In contrast:

- Each ranet node listens on its registry-assigned UDP port. The local and
  remote ports are independent and need not have the same value. NAT may rewrite
  either one again.
- IKE and ESP always share that one UDP path. Every IKE packet, including
  `IKE_SA_INIT`, has the four-byte Non-ESP Marker, while an ESP packet starts
  directly with its nonzero SPI.
- The initiator deliberately hashes a random IPv4 address and port zero in
  `NAT_DETECTION_SOURCE_IP`, guaranteeing a mismatch so that strongSwan installs
  UDP encapsulation even when no NAT is present. The destination notification
  hashes the configured remote endpoint normally.
- Received NAT-detection notifications are not used to select a transport: there
  is no port-500-to-4500 transition and no dedicated
  [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) NAT keepalive. The
  userspace transport accepts UDP-encapsulated ESP only, not raw IP ESP.

The strongSwan peer must therefore be provisioned for the same custom port and
forced UDP encapsulation (`encap = true`). This profile remains usable when a
NAT changes the observed source port: replies follow the observed source, and a
fresh authenticated IKE request can update the stored peer endpoint. It is
deliberately not interoperable with an otherwise generic peer expecting standard
RFC 7296 port selection or raw ESP.

Every session moves the stored peer endpoint to the address and port of a fresh
request whose integrity protection validates, as
[RFC 7296 section 2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23)
asks of a host that is not behind a NAT. The section asks a host behind a NAT
not to, and a node never learns whether it is behind one, since it does not
compare the `NAT_DETECTION_DESTINATION_IP` it receives with its own address.
Behind a NAT this lets a request captured and resent from another address ahead
of the original move a session's sends there, until the peer's next fresh
request moves them back, which comes once the peer has heard nothing for its
liveness interval. In exchange a session follows a peer that moved, whichever
end dialed.

There is one separate SHOULD-level deviation from
[RFC 7296 section 2.25.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.1).
If both peers initiate a rekey of the same Child SA concurrently, ranet3 answers
the peer's rekey with `TEMPORARY_FAILURE`. The RFC recommends completing both
exchanges, temporarily retaining the redundant SAs, and using the four nonces to
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
[RFC 7296 section 2.8.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8.1)
permits sending on the new SA "as soon as it sends its response", so the
difference is the time to encrypt one message. What the same section also offers
is the conservative option, continuing on the old SA until the peer proves it
has the new one, and that would close the gap outright: either way the peer
cannot decrypt until the response reaches it, so a peer-initiated rekey costs
the response's flight time of outbound traffic. Since the end with the shorter
lifetime drives rekeying, on a mixed fleet that is strongSwan, hourly, per peer,
and babel's own traffic is periodic enough not to notice.

The remaining narrow feature set is not counted as RFC non-compliance.
Raw-public-key authentication without certificates or EAP and refusal to create
additional Child SAs are both within the
[RFC 7815 minimal-initiator profile](https://www.rfc-editor.org/rfc/rfc7815.html).

This fork adds the responder role, which upstream lists as out of scope, because
a full mesh needs every node to answer as well as dial. It is off unless
`link.listen` is set. Identities are compared by name rather than by their DER
bytes: ranet writes `O` and `CN` as `UTF8String` while strongSwan picks the
string type from the value, so one name legitimately reaches the wire in two
encodings. AUTH signs the bytes as received either way, so the name only selects
which key must verify it.

IKE rekeys retain the negotiated PRF. This avoids differing key expansion
behavior between
[strongSwan](https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/keymat_v2.c)
and
[RFC 7296 section 2.18](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.18)
when the PRF changes, while allowing fresh DH keys and a different encryption
algorithm. Peer Child-SA rekeys can use X25519, P-256, or P-384 for PFS. Locally
initiated Child rekeys derive keys from the IKE SA without an additional DH
exchange.

A packet larger than its session carries is answered from the address it was
going to rather than from one of this node's own.
[RFC 4443 section 2.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.2)
has a node answer a packet addressed elsewhere from a unicast address of its
own, and
[RFC 1812 section 4.3.2.4](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.4)
has a router answer from an address of the interface the answer leaves by. The
headend writes its Packet Too Big or fragmentation needed into the tun, where a
leaf often holds no address of the packet's family to answer from, and a
waypoint is a hop inside the tunnel that the sender never addressed. The
sender's stack matches an ICMP error to what it concerns by the packet the error
quotes, and linux takes the smaller path MTU to the destination from such an
answer, which the `internal/netstack` root tests hold for both families at the
headend and behind a waypoint. The Time Exceeded and Parameter Problem a refused
segment gets come from the segment's destination too, which is one of this
node's own segments and within the RFC.

A node's own Babel seqno rises at every start of its speaker, which
[RFC 8966 section 3.2.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.2.2)
asks a node not to do unprompted, since a higher seqno leaves other nodes fewer
feasible routes to fall back on. A process keeps the router id the node had
before, from the file [the state directory](../service.md#the-state-directory)
holds, and starts one past the seqno limit there, which is ahead of every seqno
the node has sent unless a write of the limit failed or the node starts from an
older copy of its state directory. The speaker that `ranet3 up` starts again
sends one past the seqno of the run before it. A node still holding the old
routes, with the feasibility distance it recorded for them, finds the new ones
newer and takes them at once. A seqno that did not move would leave them
unfeasible there until seqno requests raised it, or for the 3 minutes the source
entry lives after its last update. babeld resumes one past the seqno its own
state file holds as well. The limit runs 256 ahead of the seqno in use, so a
start moves the seqno on by at most 257, and the order of
[section 3.2.1](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.2.1)
compares two seqnos less than 32768 apart. That leaves room for 127 starts in a
row, inside the time a node keeps a feasibility distance, before one recorded
before the first could read as newer than the seqno after the last.

The speaker makes its packets at most 1232 octets of UDP payload, which with the
IPv6 and UDP headers is the 1280 octets IPv6 asks of any link, where
[RFC 8966 section 4](https://www.rfc-editor.org/rfc/rfc8966.html#section-4) has
a speaker make them as large as the link's MTU allows. The link is a session
whose budget its search moves, and a packet sized to the budget it had when it
was built could meet a smaller one, while every session carries 1280 whatever
its path. A full table then goes in more packets, about 38 prefixes to a packet,
or 31 with a source prefix. The one Babel packet past 1232 is the probe the
search sends, an Ack Request padded with PadN to the size it measures, which any
speaker answers with its Ack and otherwise ignores.

A Babel packet a neighbor's stack cut into fragments is put back together before
the speaker reads it. Some speakers send packets of 1422 to 1443 UDP octets,
which their own stacks fragment at 1368 or 1384, and BIRD and babeld read Babel
through a kernel socket that reassembles them. ranet3 reads the inner packets of
each session itself, so it reassembles, as
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
describes, the fragments sent to its speaker: an IPv6 packet whose next header
is Fragment, from a link-local address, to `ff02::1:6` or to the speaker's own
link-local address. Such a fragment is the speaker's whether its packet
completes or not, and never reaches the tun. Any other fragment, ordinary
traffic to an address of the mesh among them, goes to the tun as it arrived, and
the kernel reassembles it for its socket. The packet put back together goes
through the checks an unfragmented one does, and on to the neighbor of the
session its fragments came through.

The reassembly departs from RFC 8200 in five places, each toward dropping:

- A datagram waits 16 seconds after its first fragment rather than 60. The
  fragments of one packet leave the neighbor together over one session, and a
  packet still missing one after an update interval, 16 seconds at the defaults
  BIRD and babeld share, is repeated by the neighbor's next periodic update long
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
RFC 8200 allows for an exact duplicate, and the same holds for one spanning two
fragments. A datagram read or dropped stays for the rest of its 16 seconds
unless a newer one takes its place, so a fragment of it arriving late goes with
it and a copy is not read twice. An atomic fragment, at offset 0 with no more to
come, is read at once as the packet it carries, as
[RFC 6946 section 4](https://www.rfc-editor.org/rfc/rfc6946.html#section-4)
asks.

Each neighbor holds at most 16 datagrams, under way, read or dropped, and 256
KiB of storage for the ones under way, four packets of the largest size. A
datagram not read keeps its place, and one under way its storage, for at least 1
second after its first fragment. The fragments of one packet cross a session
back to back, and a session of 1 Mbit/s carries even the largest Babel packet
within that second. Once the 16 places are taken, a new datagram takes the place
of the oldest one read, or dropped and past that second, and failing that of the
oldest one under way past it, which it drops. It reuses the bookkeeping of the
datagram it replaces. The storage a datagram grows into comes from the oldest
others under way past that second. A fragment that finds no place, or a datagram
no storage, is refused. Each place then goes to at most one datagram not read
each second, and a datagram allocates under 128 KiB of storage in all. A
neighbor flooding fragments of datagrams that never complete has the node
allocate under 2 MiB of storage a second and hold under 280 KiB, its bookkeeping
included, and it evicts and refuses only datagrams of its own. A datagram that
completes allocates under four times the octets its fragments carry. The state
belongs to the session's neighbor, so a session that ends takes its datagrams
along. [The metrics](../metrics.md) count each neighbor's packets read from
fragments, the largest of them, and the datagrams dropped and why.
