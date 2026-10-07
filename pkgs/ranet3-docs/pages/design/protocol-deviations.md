---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Deliberate protocol deviations"
description: "Where ranet3 departs from the IKEv2, ESP and Babel specifications on purpose."
created: 2026-08-23
updated: 2026-10-07
order: 20
---

ranet3 uses a private IKEv2 transport profile tailored to a ranet deployment
rather than general-purpose
[RFC 7296 NAT traversal](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
The RFC uses UDP ports 500 and 4500, hashes the actual source and destination
address/port pairs in the `NAT_DETECTION_*_IP` notifications, and moves
subsequent traffic to port 4500 when NAT is detected. In contrast:

- Each ranet node listens on its registry-assigned UDP port. The local and
  remote ports are independent and need not have the same value; NAT may rewrite
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
algorithm. Peer Child-SA rekeys can use X25519, P-256, or P-384 for PFS; locally
initiated Child rekeys derive keys from the IKE SA without an additional DH
exchange.
