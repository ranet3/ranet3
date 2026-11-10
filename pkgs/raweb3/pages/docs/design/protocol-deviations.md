---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Deliberate protocol deviations"
description: "Where ranet3 departs from the IKEv2, ESP, Babel, IPv6, ICMP and NAT specifications on purpose."
created: 2026-08-23
updated: 2026-11-10
order: 20
---

Each row of this page names a section of a specification ranet3 implements and
the place where ranet3 departs from it. The table summarizes them, and the
sections below give the details.

| RFC and section                                                                           | The RFC says                                                                                                                                                                                                              | ranet3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Why                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 7296 section 2.23, RFC 9242 section 3.2                                               | IKE starts on UDP port 500 and moves to 4500 behind a NAT, in the first `IKE_INTERMEDIATE` where one runs                                                                                                                 | IKE and ESP share `link.port` from the first message                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 1 port per node, with no transition to track                                                                                                                                                                                                                                                                                                                               |
| RFC 7296 section 2.23                                                                     | NAT detection hashes the real source address and port                                                                                                                                                                     | The source hash covers a random address, so it never matches                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | The peer always encapsulates ESP in UDP                                                                                                                                                                                                                                                                                                                                    |
| RFC 7296 section 2.23                                                                     | Follow any validated packet when not behind a NAT, and none behind one                                                                                                                                                    | From its established IKE SA on, every session follows a fresh authenticated request and the authenticated answer to its own request, behind a NAT too, and no ESP packet                                                                                                                                                                                                                                                                                                                                                                                                             | A session follows a peer that moved, and a node never learns whether it is behind a NAT. The initiator's handshake answers come before the IKE SA exists, and a dial sends to the endpoint it dials. ESP following a validated packet too is scheduled, see Endpoint updates                                                                                               |
| RFC 7296 section 2.11                                                                     | Answer from the address and port the request reached                                                                                                                                                                      | The kernel's choice once that address is gone or has no route                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | No answer otherwise, see Answer addresses                                                                                                                                                                                                                                                                                                                                  |
| RFC 7296 section 2.11                                                                     | Answer from the address and port the request reached                                                                                                                                                                      | The kernel's choice on FreeBSD and OpenBSD                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | No source kept, see Answer addresses                                                                                                                                                                                                                                                                                                                                       |
| RFC 7296 section 2.25.1                                                                   | Complete both colliding Child SA rekeys and keep 1                                                                                                                                                                        | The peer's rekey is answered `TEMPORARY_FAILURE`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 1 Child SA per session                                                                                                                                                                                                                                                                                                                                                     |
| RFC 7296 section 2.8                                                                      | The responder may switch to the new SA once it sends its response                                                                                                                                                         | It switches just before sending the response                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | The difference is the time to encrypt 1 message                                                                                                                                                                                                                                                                                                                            |
| RFC 7296 section 2.18                                                                     | An IKE SA rekey may choose a new PRF                                                                                                                                                                                      | The PRF stays, and a reload that drops it replaces the IKE SA                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | strongSwan expands keys with the old PRF                                                                                                                                                                                                                                                                                                                                   |
| RFC 7296 section 4                                                                        | After `NO_ADDITIONAL_SAS`, delete the old SA and create a new one                                                                                                                                                         | Without a crossing peer rekey held, the old SA stays and the rekey is retried                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Deleting the old SA first leaves the session with no SA for the round trip a new one takes, while the old one carries traffic until a retry, the peer's rekey or the end of its lifetime replaces it, see Rekeying                                                                                                                                                         |
| RFC 7296 section 2.25.2                                                                   | Answer as usual a rekey of an IKE SA this end is rekeying too                                                                                                                                                             | Past the IKE SA's lifetime it is answered `TEMPORARY_FAILURE`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Section 2.8: an SA past its lifetime is not used                                                                                                                                                                                                                                                                                                                           |
| RFC 7296 section 2.8                                                                      | An SA past its lifetime is not used                                                                                                                                                                                       | It finishes its exchange, answers the peer and sends its Delete                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Sections 2.1 and 2.3 keep 1 request until it ends                                                                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.8                                                                      | A rekeyed Child SA keeps the algorithms of the old one                                                                                                                                                                    | A Child SA rekey may move to another listed cipher                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Either end's lists left the old cipher out                                                                                                                                                                                                                                                                                                                                 |
| RFC 7296 section 2.8                                                                      | A rekeyed Child SA keeps the algorithms of the old one                                                                                                                                                                    | This end's own Child SA rekey drops the key exchanges a peer's rekey ran                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | No Child SA key exchange of its own, see Rekeying                                                                                                                                                                                                                                                                                                                          |
| RFC 7296 section 1.3.1                                                                    | A failed Child SA does not tear down the IKE SA                                                                                                                                                                           | When the Child SA in `IKE_AUTH` fails, both ends delete the IKE SA                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | An IKE SA carries nothing without its Child SA                                                                                                                                                                                                                                                                                                                             |
| RFC 7296 section 2.4                                                                      | Send a Delete for an IKE SA closed while the peer still answers                                                                                                                                                           | None when a Message ID space is spent, a message cannot be built, the peer's fragments of 1 message pass the reassembly limit, or a newer IKE SA of the path carries the peer's `INITIAL_CONTACT`                                                                                                                                                                                                                                                                                                                                                                                    | A Delete needs a Message ID and the same encoding, RFC 7383 section 5 drops the connection, and section 2.4 lets the recipient of the notice delete the other IKE SAs to the same identity, see Closing SAs                                                                                                                                                                |
| RFC 7296 section 2.1                                                                      | A retransmission is bitwise identical to the original request                                                                                                                                                             | A request cut again for a smaller threshold is not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | RFC 7383 section 2.5.2 has it refragmented, see IKE fragmentation                                                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.4                                                                      | Retransmission times increase exponentially                                                                                                                                                                               | Each new cut of a request starts them over, and once the IKE SA starts to close, the request outstanding takes its next counted send at once                                                                                                                                                                                                                                                                                                                                                                                                                                         | RFC 7383 section 2.5.2 has the timers start over, and the close's send frees the window of 1 within a round trip, so the Delete leaves before the node stops waiting for it, for 1 datagram a close and no send past the request's budget, see IKE fragmentation                                                                                                           |
| RFC 7296 section 2.11                                                                     | Answer a request at the address and port it came from                                                                                                                                                                     | A repeat from another address draws the answer only within the bytes it sent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | A replayed fragment would aim answers at any address                                                                                                                                                                                                                                                                                                                       |
| RFC 7383 section 2.5.1                                                                    | Use the path MTU the sender knows for the fragments                                                                                                                                                                       | Never less than 1280 bytes over IPv6 or 576 over IPv4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The values the section gives where the path MTU is unknown                                                                                                                                                                                                                                                                                                                 |
| RFC 7383 section 5                                                                        | Bound the decrypted content of the fragments held                                                                                                                                                                         | The fragments are bounded as the IKE messages they came in                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | They hold more than their content                                                                                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.21.3                                                                   | Answer each erroneous request on an authenticated IKE SA with an error                                                                                                                                                    | A replaced IKE SA past its lifetime answers no request                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Section 2.8: an SA past its lifetime is not used                                                                                                                                                                                                                                                                                                                           |
| RFC 7296 section 4                                                                        | Accept configured RSA certificates and shared keys                                                                                                                                                                        | Ed25519 signatures only, against the trust document                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Keys come from the trust document                                                                                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.9                                                                      | Narrow the selectors to a subset the policy accepts, holding the initiator's first choices where it accepts those (MUST), and refuse with `TS_UNACCEPTABLE` only selectors it accepts no part of                          | Selectors that hold the full IPv4 and IPv6 ranges are answered with those 2, and any that lack either are refused with `TS_UNACCEPTABLE`, never narrowed                                                                                                                                                                                                                                                                                                                                                                                                                             | Babel picks the peer for each packet, see Traffic selectors                                                                                                                                                                                                                                                                                                                |
| RFC 7296 sections 1.5 and 2.21.4                                                          | Tell the peer of an error outside a request, such as ESP on an unknown SPI, over an IKE SA to the source's address or else in the clear                                                                                   | Told over a session's IKE SA alone, for ESP from that session's exact address and port, after at most 1 look for the session every 10 seconds for the whole node, and never for an SPI let go of in the 10 seconds before                                                                                                                                                                                                                                                                                                                                                            | A message in the clear would let anyone make the node send to any address, and a stranger's ESP can take the look a peer needed, see Errors outside an exchange                                                                                                                                                                                                            |
| RFC 7296 section 2.21.4                                                                   | Answer a suspicious message from a peer's address over its IKE SA                                                                                                                                                         | ESP on an unknown SPI from a session's exact address and port is told over its IKE SA, at most once for each session from each look, and at most 1 look every 10 seconds for the whole node, as the row above says. Any other suspicious message, such as an IKE message that fails its integrity check, is dropped, and nothing is sent over the SA                                                                                                                                                                                                                                 | A spoofed address could make the node send, which the 10 seconds bound for ESP, see Errors outside an exchange                                                                                                                                                                                                                                                             |
| RFC 7296 section 3.3.4                                                                    | Let an administrator enter new Diffie-Hellman groups and their parameters                                                                                                                                                 | No such interface                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Elliptic curve groups only, fixed in code                                                                                                                                                                                                                                                                                                                                  |
| RFC 7296 section 3.3.5                                                                    | Accept an offer of a longer key than the one configured                                                                                                                                                                   | A key length the lists leave out is refused                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Section 3.3.4's suite controls are a MUST                                                                                                                                                                                                                                                                                                                                  |
| RFC 8247, RFC 8221                                                                        | Support AES-CBC, MODP 14, `PRF_HMAC_SHA1`, `AUTH_HMAC_SHA1_96`, HMAC integrity and RSA signatures                                                                                                                         | AEAD ciphers and elliptic curve groups only                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Legacy transforms are left out                                                                                                                                                                                                                                                                                                                                             |
| RFC 4303 sections 2.6 and 2.7                                                             | Be able to generate dummy packets                                                                                                                                                                                         | None are generated, and no traffic flow confidentiality padding is sent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | A known gap                                                                                                                                                                                                                                                                                                                                                                |
| RFC 4303 sections 3.3.3 and 4                                                             | Log a sequence number overflow with the source address and IPv6 Flow ID                                                                                                                                                   | The log names the local port, not the source address, and no Flow ID                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | A wildcard socket, and no flow label is set                                                                                                                                                                                                                                                                                                                                |
| RFC 4303 sections 3.4.2 and 4, RFC 4301 section 5.2                                       | Log ESP on an SPI with no SA, with the SPI, the time, both addresses, the sequence number and the IPv6 Flow ID                                                                                                            | Counted, and recorded only when reported to the session's peer, with the SPI and the time. ESP on an SPI a session holds with no SA can be named in a warning at most once every 10 seconds                                                                                                                                                                                                                                                                                                                                                                                          | A log line for each such datagram would let a flood fill the log, see ESP                                                                                                                                                                                                                                                                                                  |
| RFC 4303 section 4                                                                        | Let a system administrator turn auditing for ESP on and off                                                                                                                                                               | No switch: both counters and `ike.notify.invalid_spi` are always on, and the debug line for a peer's `INVALID_SPI` and the warning of dropped ESP follow `--log-level`                                                                                                                                                                                                                                                                                                                                                                                                               | The record holds at most 1 report for each session from each look, and at most 1 look every 10 seconds for the whole node, so a switch would be a setting no deployment needs, see ESP                                                                                                                                                                                     |
| RFC 3948 section 2.1                                                                      | Send the IPv4 UDP checksum as zero                                                                                                                                                                                        | Every IPv4 datagram carries a computed checksum                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Linux refuses segmented sends without one                                                                                                                                                                                                                                                                                                                                  |
| RFC 3948 section 4                                                                        | Send NAT keepalives                                                                                                                                                                                                       | None are sent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Hellos and IKE liveness checks keep the mapping open                                                                                                                                                                                                                                                                                                                       |
| RFC 7296 section 2.24, RFC 6040 sections 4.1 and 4.3                                      | Encapsulate in the normal mode, which copies the inner ECN field to the outer header                                                                                                                                      | Every ESP datagram's outer header is sent Not-ECT, RFC 6040's compatibility mode, the encapsulation of RFC 3168's limited functionality mode                                                                                                                                                                                                                                                                                                                                                                                                                                         | A Not-ECT outer header hides no congestion signal, see ECN                                                                                                                                                                                                                                                                                                                 |
| RFC 7296 section 2.24, RFC 6040 section 4.2                                               | Decapsulate by the outer and the inner ECN field                                                                                                                                                                          | The outer field is not read on FreeBSD and OpenBSD, so a hop's CE mark is lost there                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | The bind reads no control data there, see ECN                                                                                                                                                                                                                                                                                                                              |
| RFC 4443 section 2.2                                                                      | Answer from an address of the node's own                                                                                                                                                                                  | A tun read's Packet Too Big and Destination Unreachable come from the packet's destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Where the host routes the destination into the tun, only the destination passes every check, see ICMP answers                                                                                                                                                                                                                                                              |
| RFC 4443 sections 2.4 and 3.2                                                             | Answer the packet that could not be forwarded, to its source                                                                                                                                                              | `End` answers a segment it admits too large for its next session about the packet it carries, to that packet's source                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The headend relays no answer to the sender, see ICMP answers                                                                                                                                                                                                                                                                                                               |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                                                    | Originate from an address of the router's own, of the interface the answer leaves by                                                                                                                                      | An ICMPv4 answer to a tun read comes from the packet's destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Where the host routes the destination into the tun, only the destination passes `rp_filter` 1 and a strict chain, see ICMP answers                                                                                                                                                                                                                                         |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                                                    | Originate from an address of the router's own, of the interface the answer leaves by                                                                                                                                      | With no IPv4 router-id, `End`'s IPv4 answer comes from the packet's destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `rp_filter` 1 and a strict chain drop it from 192.0.0.8                                                                                                                                                                                                                                                                                                                    |
| RFC 4443 section 2.2, RFC 1812 sections 4.2.2.11 and 4.3.2.4                              | Answer from an address of the node's own                                                                                                                                                                                  | `End`'s answer to a segment larger than its next session, to a source an entry of this node's own that counts as no default reaches, goes into the tun from the destination of the packet it answers, whatever router-id the node holds                                                                                                                                                                                                                                                                                                                                              | Only this host or a network behind it receives it, and only the destination passes every check, see ICMP answers                                                                                                                                                                                                                                                           |
| RFC 1812 section 4.3.2.6                                                                  | Reverse a source route the packet carries into the error, unless a policy known to the router would keep the error from its sender                                                                                        | No ICMPv4 answer carries a source route                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | A Linux or macOS host drops a source-routed packet at its defaults, see ICMP answers                                                                                                                                                                                                                                                                                       |
| RFC 4443 section 3.2                                                                      | Send Packet Too Big for a packet larger than the next link, one to a multicast group included                                                                                                                             | `End` sends none for a segment carrying a packet to a multicast group                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | The mesh routes no multicast, and a ranet3 headend steers no packet to a group                                                                                                                                                                                                                                                                                             |
| RFC 1812 section 5.3.5.1                                                                  | Limited broadcasts MUST NOT be discarded                                                                                                                                                                                  | A read off the tun to 255.255.255.255 is dropped and counted with the multicast reads. A packet a session delivers to it is dropped and counted `session_multicast` before either exit takes it, by the forwarding decision, and by an egress segment for an inner packet that its allow list let through, but a Not-ECT one that arrived under an outer CE, which an earlier drop takes. An inner packet the list refuses is refused. The userspace exit also refuses one it is handed, as a destination none of its sockets sends to                                               | No service of ranet3 takes a broadcast, and the same section forbids forwarding it. Written to the tun, a session's broadcast would reach the host's services that listen on the link, DHCP among them, from a peer of another organization through the mesh                                                                                                               |
| RFC 4443 section 2.4 (e.1)                                                                | Originate no ICMPv6 error in answer to an ICMPv6 error                                                                                                                                                                    | One behind 9 extension headers or more is answered where any other packet would be, but for a code 8 refusal                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Refusing at the bound would withhold the errors sections 3.2 and 3.3 require from a packet not shown to be an error                                                                                                                                                                                                                                                        |
| RFC 8883 section 2.5                                                                      | Answer a packet discarded for a chain past a limit on its extension headers with Parameter Problem, code 8 (SHOULD)                                                                                                       | `End` and `End.DT46` drop with no answer such a packet whose search for an ICMPv6 error ends unfinished past 16 extension headers                                                                                                                                                                                                                                                                                                                                                                                                                                                    | RFC 4443 section 2.4 (e.1) lets no error answer an ICMPv6 error, which such a packet may be, see ICMP answers                                                                                                                                                                                                                                                              |
| RFC 4443 section 2.4 (f)                                                                  | Make the rate limit's parameters configurable, since "the best defaults depend on where the implementation is expected to be deployed"                                                                                    | Fixed in code, the Linux kernel's defaults but for the bound on sources kept                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Buckets per source scale the node's budget with the senders it answers, and the cap bounds a flood's cost on the smallest node                                                                                                                                                                                                                                             |
| RFC 1812 section 4.3.2.8                                                                  | Make the rate limit's parameters settable in the router's configuration                                                                                                                                                   | Fixed in code, the Linux kernel's defaults but for the bound on sources kept                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Buckets per source scale the node's budget with the senders it answers, and the cap bounds a flood's cost on the smallest node                                                                                                                                                                                                                                             |
| RFC 4443 section 2.4 (f), RFC 1812 section 4.3.2.8                                        | Limit the rate of the ICMPv6 errors a node originates (MUST), and be able to limit a router's Destination Unreachable (SHOULD)                                                                                            | Packet Too Big and fragmentation needed go out past every limit, neither a source's bucket nor the node's cap holding one back                                                                                                                                                                                                                                                                                                                                                                                                                                                       | The Linux kernel leaves both out of its limits, see ICMP answers                                                                                                                                                                                                                                                                                                           |
| RFC 4443 section 2.2, RFC 1812 sections 4.2.2.11 and 4.3.2.4                              | Answer from an address of the node's own                                                                                                                                                                                  | A transit answer to a packet whose source an entry of this node's not counting as a default reaches goes into the tun from the packet's destination, whichever session delivered it                                                                                                                                                                                                                                                                                                                                                                                                  | Only this host or a network behind it receives it, and only the destination passes every check, see Transit answers                                                                                                                                                                                                                                                        |
| RFC 4443 section 2.2                                                                      | Answer from an address of the node's own                                                                                                                                                                                  | With no IPv6 router-id and no SID, a transit Packet Too Big comes from the packet's destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Path MTU discovery needs the answer more than its source                                                                                                                                                                                                                                                                                                                   |
| RFC 4443 section 2.2 (a)                                                                  | Answer a packet sent to an address of the node's from that same address                                                                                                                                                   | A session's packet to an address of the host that no route of this node covers is answered from the router-id                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | The decision reads no host address list, see Transit answers                                                                                                                                                                                                                                                                                                               |
| RFC 4443 sections 3.1, 3.2 and 3.3                                                        | Send Destination Unreachable (SHOULD), Packet Too Big and Time Exceeded (MUST)                                                                                                                                            | No ICMPv6 error of any kind is sent for transit from a source only this node's own default reaches, but for the beyond scope answer to a link-local source, which goes back on its session                                                                                                                                                                                                                                                                                                                                                                                           | Any peer could make the node send errors carrying bytes the peer chose to any host past its uplink, and the mesh routes no reply to such a source, see Transit answers                                                                                                                                                                                                     |
| RFC 1812 sections 4.3.3.5 and 5.3.1                                                       | Send Parameter Problem and Time Exceeded (MUST)                                                                                                                                                                           | No ICMPv4 error of any kind, Destination Unreachable and Fragmentation Needed among them, is sent for transit from a source only this node's own default reaches                                                                                                                                                                                                                                                                                                                                                                                                                     | Any peer could make the node send errors carrying bytes the peer chose to any host past its uplink, and the mesh routes no reply to such a source, see Transit answers                                                                                                                                                                                                     |
| RFC 4443 sections 3.3 and 3.1                                                             | Send Time Exceeded (MUST) and Destination Unreachable (SHOULD)                                                                                                                                                            | Neither is sent for transit where the node holds no IPv6 router-id and no SID                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | No address of the node could be the source, see ICMP answers                                                                                                                                                                                                                                                                                                               |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                                                    | Originate from an address of the router's own, of the interface the answer leaves by                                                                                                                                      | With no IPv4 router-id, a transit answer comes from 192.0.0.8, a Fragmentation Needed from the packet's destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | A session has no address, see ICMP answers                                                                                                                                                                                                                                                                                                                                 |
| RFC 1812 section 4.2.2.2                                                                  | Insert the router-id into an option where the interface has no address                                                                                                                                                    | With no IPv4 router-id, Record Route and Timestamp insert 192.0.0.8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | The address its IPv4 answers come from                                                                                                                                                                                                                                                                                                                                     |
| RFC 1812 section 5.2.2                                                                    | Answer a truncated packet with Parameter Problem (SHOULD)                                                                                                                                                                 | A truncated transit IPv4 packet is dropped and counted with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Linux's `ip_rcv_core` drops it the same way                                                                                                                                                                                                                                                                                                                                |
| RFC 1812 section 5.3.13.4                                                                 | Support source route options, with any discarding option off by default                                                                                                                                                   | A transit IPv4 packet carrying a source route is dropped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Source routing bypasses controls, see ICMP answers                                                                                                                                                                                                                                                                                                                         |
| RFC 1812 section 5.2.2                                                                    | Answer a strict source route for another node with Parameter Problem (SHOULD)                                                                                                                                             | It is dropped and counted with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Linux's `ip_rcv_options` drops it the same way                                                                                                                                                                                                                                                                                                                             |
| RFC 4443 section 3.1                                                                      | Allow sending Destination Unreachable to be disabled, preferably per interface (SHOULD)                                                                                                                                   | The forwarding decision's and a tun read's cannot be turned off, and each draws on its source's bucket and the node's cap                                                                                                                                                                                                                                                                                                                                                                                                                                                            | The decision's goes only to a source the node's table routes, or for code 2 back on its session, and a tun read's only back into the tun, see Transit answers                                                                                                                                                                                                              |
| RFC 4443 section 3.1, RFC 1812 section 5.3.9                                              | Answer a packet refused for its source with Destination Unreachable, code 5, over IPv4 code 13                                                                                                                            | The antispoof filter drops with no answer a source inside `overlay` from outside the mesh, but what [carve-outs](../antispoof.md#carve-outs) and [exemptions](../antispoof.md#exemptions) pass                                                                                                                                                                                                                                                                                                                                                                                       | An answer to an overlay source would be routed into the mesh, to the address's holder there or nowhere, rather than to the sender, which may have forged it                                                                                                                                                                                                                |
| RFC 4443 section 3.1, RFC 1812 section 5.3.9                                              | Answer a packet refused for its source with Destination Unreachable, code 5, over IPv4 code 13, and let filtering be set to forward all packets (SHOULD)                                                                  | On Linux `mesh_entry` drops with no answer a packet entering the tun from a source this node does not own, unless it is a reply, toward a `none` class or to an IPv6 link-local or multicast destination, and has no switch                                                                                                                                                                                                                                                                                                                                                          | A source entering the tun may be forged, so an answer could reach a bystander, and a UDP send from the host fails with `EPERM` instead. The chain keeps a host beside a forwarding node out of the mesh, see Drops with no answer                                                                                                                                          |
| RFC 1812 section 5.3.9                                                                    | Count the packets a filter does not forward, and allow selective logging of them (SHOULD)                                                                                                                                 | The antispoof filter counts each drop by rule and family, in `ranet3_antispoof_dropped_packets_total`, `status`, `ranet3 debug rules` and the `antispoof.dropped` event, and logs no line for a dropped packet, as [Drops with no answer](#drops-with-no-answer) says                                                                                                                                                                                                                                                                                                                | A line per forged packet would let its sender write the host's log                                                                                                                                                                                                                                                                                                         |
| RFC 4443 section 3.1                                                                      | Answer a packet refused for its source with Destination Unreachable, code 5                                                                                                                                               | A SID drops an outer source outside the overlay with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | An answer tells the sender which addresses are SIDs                                                                                                                                                                                                                                                                                                                        |
| RFC 4443 section 3.1                                                                      | Answer a packet refused for its source with Destination Unreachable, code 5                                                                                                                                               | An egress segment drops an outer source outside its allow list's entries inside the overlay, or an inner source outside the list, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                     | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1, RFC 1812 section 5.2.7.1                                            | Answer a packet with no route with Destination Unreachable, code 0, over IPv4 Host Unreachable where other hosts of its network may be reachable                                                                          | An egress segment drops an inner packet for a destination inside `overlay` with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1, RFC 1812 section 5.3.9                                              | Answer a packet a firewall refuses with Destination Unreachable, code 1, over IPv4 code 13                                                                                                                                | An egress segment drops an inner packet for a destination the mesh routes itself with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1                                                                      | Answer a packet refused for its source with Destination Unreachable, code 5                                                                                                                                               | An exit drops a packet it would egress, and the mesh routes no reply to, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | No route would carry the answer back either                                                                                                                                                                                                                                                                                                                                |
| RFC 1812 section 5.3.8                                                                    | Have source address validation off by default (MUST)                                                                                                                                                                      | An exit always drops a packet it would egress, and the mesh routes no reply to                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | The check is loose, so an asymmetric path passes it, a LAN the exit shares with another node among them                                                                                                                                                                                                                                                                    |
| RFC 4443 section 3.1                                                                      | Answer a packet that cannot be delivered with Destination Unreachable (SHOULD)                                                                                                                                            | An exit drops a packet for a family it stopped announcing or holds not ready with no answer, until the family is ready or it retracts the prefix                                                                                                                                                                                                                                                                                                                                                                                                                                     | The retraction decides the packets after it                                                                                                                                                                                                                                                                                                                                |
| RFC 4443 section 3.1                                                                      | Answer a packet that cannot be delivered with Destination Unreachable (SHOULD)                                                                                                                                            | An egress segment drops a packet of a family not ready with no answer, until the node withdraws the SID's `/128`, or while the other family is ready if the host does not carry this one out                                                                                                                                                                                                                                                                                                                                                                                         | The withdrawal decides the packets after it, and none holds while the `/128` stays, see Drops with no answer                                                                                                                                                                                                                                                               |
| RFC 4787 sections 4.1 and 8, RFC 5382 section 4.1                                         | Map 1 external port to each inside endpoint whatever the destination, and change that mapping under no conditions                                                                                                         | The kernel exit takes another port once another inside host holds it toward the same destination, and under `auto` each flow's address by its route. The userspace exit keeps 1 external endpoint toward every server per leaf TCP port and source address while connected, under `auto` 1 per route's address, and per leaf UDP port while its mapping lives, under `auto` on its first destination's, a datagram lost where another link refuses or drops it. A TCP connection whose 4-tuple the host holds or whose port a host listener took leaves from another port            | conntrack maps per connection, and masquerade takes each flow's address by its route. A source address is its uplink's, which another uplink's network or a tunnel peer may drop ([RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html#section-3)), and a gone one carries nothing. The host's TCP holds the 4-tuple or the listener's port, see The userspace exit      |
| RFC 4787 section 4.1 (REQ-2), RFC 6888 section 3 (REQ-2)                                  | An "IP address pooling" behavior of "Paired" (RECOMMENDED), and "Paired" as a CGN's default (MUST)                                                                                                                        | Under `auto`, the kernel exit takes each flow's address by its route, and the userspace exit each TCP connection's, with a mapping on each address, and each UDP mapping's by its first destination, which its later ones keep, so on an uplink holding several addresses of a family one source can leave under several at once                                                                                                                                                                                                                                                     | Under `auto` neither exit tracks the uplink's addresses. Masquerade and the userspace exit's TCP take each flow's address by its route, since a source address is its uplink's, and UDP keeps its first destination's. A class naming an address pairs, see Exit translation                                                                                               |
| RFC 5508 section 3.1                                                                      | Map an ICMP query identifier the same toward every external host (SHOULD)                                                                                                                                                 | The kernel exit takes another identifier once another inside host holds that identifier toward the same host                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | conntrack maps an identifier as it maps a port, see Exit translation                                                                                                                                                                                                                                                                                                       |
| RFC 5508 section 3.1 (REQ-1)                                                              | Permit ICMP queries a private host sends to external hosts, and their responses (MUST)                                                                                                                                    | The kernel exit drops a query of a type the host's connection tracking keeps no flow for, an RFC 8335 extended echo among them, out of the mesh under a class that translates and into it under `return`                                                                                                                                                                                                                                                                                                                                                                             | Untracked, it would leave under its own source, see Exit translation                                                                                                                                                                                                                                                                                                       |
| RFC 5508 section 3.1 (REQ-1)                                                              | Permit ICMP queries a private host sends to external hosts, and their responses (MUST)                                                                                                                                    | A query the exit sends itself from a mesh address, of a type the host's connection tracking keeps no flow for, leaves untranslated under that mesh address                                                                                                                                                                                                                                                                                                                                                                                                                           | A drop there needs a chain at the output hook, which every packet the exit sends meets, see Exit translation                                                                                                                                                                                                                                                               |
| RFC 5508 section 3.1 (REQ-1)                                                              | Permit ICMP queries a private host sends to external hosts, and their responses (MUST)                                                                                                                                    | On macOS the userspace exit takes an echo reply for a leaf where it carries the identifier the leaf's mapping holds and comes from one of the last 16 destinations that mapping sent to, so a reply to another program's echo on that identifier from such a destination reaches the leaf as well                                                                                                                                                                                                                                                                                    | macOS gives no ICMP datagram socket an identifier of its own, see Exit translation                                                                                                                                                                                                                                                                                         |
| RFC 5508 section 4.1                                                                      | Drop an ICMP error whose embedded IP checksum fails to validate (SHOULD)                                                                                                                                                  | The kernel exit translates the error and passes it on                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Linux checks only the outer ICMP checksum, see Exit translation                                                                                                                                                                                                                                                                                                            |
| RFC 4787 section 4.2.2                                                                    | Map an even port to an even port and an odd port to an odd port (RECOMMENDED)                                                                                                                                             | Each exit keeps parity only while it keeps the port, and a port it takes on a clash has either parity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | No nf_tables statement keeps parity, and the userspace exit binds the next port it tries or any the host gives, see Exit translation                                                                                                                                                                                                                                       |
| RFC 4787 section 5, RFC 5382 section 4.3, RFC 6888 section 3 (REQ-7)                      | Endpoint-independent or address-dependent filtering (RECOMMENDED)                                                                                                                                                         | The kernel exit admits to a mapping only the replies of the flow that opened it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | An external endpoint can name several leaves at once, and a map entry keeps the value it was made with, so no destination translation per endpoint holds, see Exit translation                                                                                                                                                                                             |
| RFC 5382 section 4.3 (REQ-4), RFC 5382 section 4.2 (REQ-2a)                               | Answer no unsolicited inbound SYN for at least 6 seconds (MUST), then answer it Port Unreachable (SHOULD), and handle a TCP simultaneous open (MUST)                                                                      | The exit's own stack answers a SYN to a port of its address that no mapping holds as it answers one to a port of its own, with a reset at once where nothing listens in place of a Port Unreachable, which ends a simultaneous open whose inbound SYN reaches the exit before the leaf's                                                                                                                                                                                                                                                                                             | The exit leaves the host's answer to a SYN as the host gives it, since a rule dropping a SYN no socket takes would silence the host's own closed ports too, see Exit translation                                                                                                                                                                                           |
| RFC 5382 section 4.3 (REQ-3), RFC 5382 section 7.2 (REQ-8), RFC 5382 section 4.2 (REQ-2a) | Endpoint-independent or address-dependent filtering for TCP (RECOMMENDED), hairpinning for TCP (MUST), and handle a TCP simultaneous open (MUST)                                                                          | The userspace exit ends each connection a leaf opens and opens its own toward the server, so no connection from outside reaches a leaf: a SYN from outside meets the host's own TCP, a leaf's connection to the exit's own address is refused as one to any address the host holds, and a simultaneous open opens through the host's socket in SYN-SENT                                                                                                                                                                                                                              | A terminating exit has no inbound half, see Exit translation                                                                                                                                                                                                                                                                                                               |
| RFC 5382 section 7.3 (REQ-9)                                                              | Translate ICMP Destination Unreachable messages about TCP (SHOULD)                                                                                                                                                        | The userspace exit relays a router's or a server's error about a dial that fails to the leaf from the address that raised it, and an error about a connection that is open reaches the host's TCP and never the leaf                                                                                                                                                                                                                                                                                                                                                                 | The leaf's connection ends in the exit's own stack, so an open connection's error is about the host's own socket, see Exit translation                                                                                                                                                                                                                                     |
| RFC 1191 section 3                                                                        | Reduce the path MTU estimate on a Datagram Too Big by its next-hop MTU (MUST), never below 68 octets (MUST)                                                                                                               | The userspace exit drops a leaf's Fragmentation Needed about a TCP segment below 552 bytes, Linux's default `min_pmtu`, and counts it as `leaf error mtu`, so its stack lowers no connection's path MTU below 552. So a leaf behind a link under 552 bytes, or behind a router that reports a smaller next-hop MTU or none, has those errors dropped, and its TCP connections stall on segments larger than its path carries                                                                                                                                                         | At 68 gVisor cuts its segments below its own least of 48 bytes, so a forged error, the attack on path MTU discovery of RFC 5927 section 7.1, from any leaf would stall the connection, since one at the floor or above reaches the stack from any session, see Exit translation                                                                                            |
| RFC 5508 section 4.2.2 (REQ-5)                                                            | Revert the embedded packet of an ICMP error from the private realm with its mapping and forward it (MUST)                                                                                                                 | The userspace exit on a phone, or wherever it was given no raw socket, drops a leaf's own ICMP error about a server's datagram and counts it, and the server sees no error                                                                                                                                                                                                                                                                                                                                                                                                           | An app opens no raw socket, and only a raw socket sends an error from the mapping's address, see the userspace exit under Exit translation                                                                                                                                                                                                                                 |
| RFC 4787 section 4.2.1 (REQ-3)                                                            | If the host's source port was in the range 0-1023, the NAT's source port be in the same range (RECOMMENDED)                                                                                                               | The userspace exit on a phone maps a leaf's port below 1024 to one the host gives, at or above 1024                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | An app may bind no port below 1024, so the first low port refused ends the search, see the userspace exit under Exit translation                                                                                                                                                                                                                                           |
| RFC 4787 section 6, RFC 5382 section 7.2, RFC 5508 section 5                              | Support hairpinning                                                                                                                                                                                                       | The kernel exit takes a packet to a mapping on its own address as its own, and refuses it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | An external endpoint can name several leaves at once, and a map entry keeps the value it was made with, so no destination translation per endpoint holds, see Exit translation                                                                                                                                                                                             |
| RFC 4787 section 4.2.1 (REQ-3), RFC 5382 section 7.1 (REQ-7)                              | A "Port assignment" behavior of "Port overloading" (MUST NOT)                                                                                                                                                             | The kernel exit gives 2 inside endpoints 1 external endpoint toward different destinations. The userspace exit meets REQ-3 and REQ-7                                                                                                                                                                                                                                                                                                                                                                                                                                                 | conntrack keeps a translated connection unique with its destination, and no nf_tables statement keeps an external port for 1 inside endpoint, see Exit translation                                                                                                                                                                                                         |
| RFC 4787 section 4.4 (REQ-7)                                                              | A NAT whose external address is configured dynamically keeps its internal network from conflicting with it, or translates and forwards between every internal node and every external node whose address conflicts (MUST) | No external host whose address lies inside `overlay` is reachable through the exit: a held address reaches its node, and the forwarding decision refuses an unheld one, on an exit whose uplink lease overlaps the overlay too, which carves the lease for its own host alone. No node reaches the lease's hosts at an address the mesh routes                                                                                                                                                                                                                                       | The overlay is the mesh's own space, and a destination in it is refused rather than carried to a stranger, see Exit translation                                                                                                                                                                                                                                            |
| RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1              | Meet RFC 5597 for the DCCP it forwards (MUST), answer a flow it cannot set up with Destination Unreachable, code 13, and in IPv6 an undeliverable packet (SHOULD)                                                         | The kernel exit refuses a DCCP or UDP-Lite packet in its flow's original direction under a class that translates, with code 13 over IPv4 and code 1 over IPv6 where the kernel's reject answers, and before 7.1 drops first a UDP-Lite packet the host's tracking gives no flow. One the exit sends itself from a mesh address leaves translated, its checksum stale on a kernel with no tracker for it. The userspace exit refuses every protocol but TCP, UDP and ICMP, DCCP and UDP-Lite among them, with code 13 over IPv4 and code 1 over IPv6, on every fragment that names it | Refused on any kernel: nf_nat leaves the address-covering checksum stale for a protocol with no tracker. Only a raw socket sends either protocol from the exit, and a rule for the exit's own packets needs a chain at the output hook, which every packet the exit sends meets. The host's ordinary sockets send no other protocol from its address, see Exit translation |
| RFC 5508 section 7.3                                                                      | Forward no outbound ICMP message whose outer or inner IP header carries a source route option (SHOULD NOT)                                                                                                                | The kernel exit translates and forwards a leaf's ICMP error whose quoted header carries a source route                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | No packet carrying a source route enters the mesh, so such an error quotes a packet the leaf made itself, see Exit translation                                                                                                                                                                                                                                             |
| RFC 6633 section 8                                                                        | Log the drop of a Source Quench as a security fault (SHOULD)                                                                                                                                                              | While it runs and `cap.egress` translates IPv4, the kernel exit drops each Source Quench it forwards out of the mesh or into it, counts it in its rule's counter, and logs none                                                                                                                                                                                                                                                                                                                                                                                                      | A log line for each message any host can send would let a sender fill the log, see Exit translation                                                                                                                                                                                                                                                                        |
| RFC 6633 section 8                                                                        | Hosts, security gateways and firewalls silently discard a received Source Quench (MUST)                                                                                                                                   | Outside the kernel exit's drop, which holds while it runs and `cap.egress` translates IPv4, a node carries a Source Quench between its host and the mesh in either direction                                                                                                                                                                                                                                                                                                                                                                                                         | A known gap, see Exit translation                                                                                                                                                                                                                                                                                                                                          |
| RFC 6888 section 3 (REQ-3)                                                                | Put no limit on the size or contiguity of the external address pool, and take contiguous or non-contiguous IPv4 address ranges (SHOULD NOT, MUST)                                                                         | A class naming an address translates to it alone, and an `auto` class to the address the host's route gives each flow, as the pooling row above says, and no class names a pool or a range                                                                                                                                                                                                                                                                                                                                                                                           | An exit carries the mesh's own nodes, which split its addresses by class, see Exit translation                                                                                                                                                                                                                                                                             |
| RFC 6888 section 3 (REQ-10)                                                               | Make the CGN manageable, by the NAT MIB of RFC 4008 by preference (SHOULD, RECOMMENDED)                                                                                                                                   | The exit reports through status, metrics and events, and implements no MIB                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | The node speaks no SNMP, see Exit translation                                                                                                                                                                                                                                                                                                                              |
| RFC 6888 section 3 (REQ-8)                                                                | Reallocate an external port no sooner than 120 seconds after it is freed (SHOULD NOT), but where the CGN tracks TCP sessions or filters by address (MAY), with the time and the ports held configurable (MUST)            | The userspace exit takes its ports from the host's own sockets, which the host frees at once on close, and holds none 120 seconds, with nothing to configure                                                                                                                                                                                                                                                                                                                                                                                                                         | Met through exceptions (a) and (c): the host's TCP tracks each connection of the exit's, TIME_WAIT included, and the UDP mappings filter by address, see Exit translation                                                                                                                                                                                                  |
| RFC 4787 section 4.3                                                                      | An idle UDP mapping is kept 5 minutes or more by default (RECOMMENDED)                                                                                                                                                    | The kernel exit keeps a translated UDP flow 2 minutes until it has a reply and a packet more than 2 seconds after its first, and 5 minutes from then on. The userspace exit keeps a mapping 5 minutes, and 30 seconds toward port 53 as REQ-5a allows                                                                                                                                                                                                                                                                                                                                | An unanswered flow carries nothing back, and the shorter timer bounds what a source's unanswered flows hold, see Exit translation                                                                                                                                                                                                                                          |
| RFC 5508 section 3.2                                                                      | Make the ICMP query session timer configurable (RECOMMENDED)                                                                                                                                                              | Each exit keeps a query 60 seconds, fixed in code                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | No deployment found needing another value, see Exit translation                                                                                                                                                                                                                                                                                                            |
| RFC 7857 section 2.1                                                                      | Make the timeouts of a TCP connection opening and closing configurable apart (SHOULD)                                                                                                                                     | Each exit's timeouts for a connection are fixed in code, the userspace exit's 60 seconds of TIME_WAIT gVisor's                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | No deployment found needing other values, see Exit translation                                                                                                                                                                                                                                                                                                             |
| RFC 5382 section 5 (REQ-5)                                                                | Abandon a partially open TCP connection only once it has been idle 4 minutes (MUST)                                                                                                                                       | The kernel exit keeps a translated connection opening 4 minutes from its first SYN, which a retransmitted SYN does not renew. The userspace exit holds a leaf's opening connection while its own dial to the server runs, and answers the leaf once the host's TCP gives that dial up                                                                                                                                                                                                                                                                                                | A SYN that renewed it would let a port a client or a NAT reuses keep the entry forever, see Exit translation                                                                                                                                                                                                                                                               |
| RFC 7857 section 2.2                                                                      | Keep a TCP session 4 minutes after a reset that matches it (SHOULD)                                                                                                                                                       | The kernel exit keeps a translated connection 10 seconds after a reset, the kernel's own, and none after a reset before any reply. The userspace exit frees a connection at once after a reset                                                                                                                                                                                                                                                                                                                                                                                       | A closed connection is outside its source's share, so its timeout bounds what the source holds past it, see Exit translation                                                                                                                                                                                                                                               |
| RFC 5508 section 6                                                                        | Answer a new flow the NAT cannot set up with an ICMP destination unreachable, code 13 (SHOULD)                                                                                                                            | Each exit answers an IPv4 flow past its source's share with code 1, Host Unreachable, and the userspace exit one past its totals too, but a DCCP or UDP-Lite flow, which its protocol's refusal answers with code 13 ahead of the share                                                                                                                                                                                                                                                                                                                                              | RFC 6888 REQ-11 asks code 1 of a refusal under a quota, see Exit translation                                                                                                                                                                                                                                                                                               |
| RFC 1812 section 5.2.7.1                                                                  | Answer a packet the router filters administratively with Destination Unreachable, code 13 (SHOULD)                                                                                                                        | Each exit answers an IPv4 flow past its source's share with code 1, Host Unreachable, and the userspace exit one past its totals too, but a DCCP or UDP-Lite flow, which its protocol's refusal answers with code 13 ahead of the share                                                                                                                                                                                                                                                                                                                                              | RFC 6888 REQ-11 answers a refusal under a quota, see Exit translation                                                                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1, RFC 1812 section 5.2.7.1                                            | Allow sending Destination Unreachable to be disabled, preferably per interface (SHOULD), and offer an option that generates no code 13 (MAY)                                                                              | Each exit's answers to a flow past its source's share and to a DCCP or UDP-Lite packet it refuses cannot be turned off, and no option withholds the refusal's code 13, nor the userspace exit's answer past its totals                                                                                                                                                                                                                                                                                                                                                               | The host's rate limit on ICMP errors thins them, and a host outside the mesh draws one only by sending into it a protocol the exit refuses, see Exit translation                                                                                                                                                                                                           |
| RFC 5508 section 7.7                                                                      | Copy into an ICMP error the diffserv class of the packet that caused it (SHOULD)                                                                                                                                          | Every IPv4 ICMP error the kernel exit originates, its answers to a flow past a source's share and to a protocol it refuses among them, carries precedence 6, internet control                                                                                                                                                                                                                                                                                                                                                                                                        | Linux marks every ICMP error it originates so, and the nf_tables reject has no option for it, see Exit translation                                                                                                                                                                                                                                                         |
| RFC 5508 section 6                                                                        | Answer a new flow the NAT cannot set up with an ICMP destination unreachable, code 13 (SHOULD)                                                                                                                            | Past the host's connection table, or with no port left, the kernel exit drops the packet with no answer. The userspace exit answers a flow past its totals with Host Unreachable over IPv4 and administratively prohibited over IPv6                                                                                                                                                                                                                                                                                                                                                 | The drop happens inside connection tracking, where no rule sees it, see Exit translation                                                                                                                                                                                                                                                                                   |
| RFC 6888 section 3 (REQ-11)                                                               | Answer a mapping it cannot create with Host Unreachable and a notification (SHOULD), and delete no existing mapping to make room (MUST)                                                                                   | Past the host's connection table, the kernel evicts a flow or drops the packet, with no answer, count or event. The userspace exit answers a flow past a share or its totals with Host Unreachable over IPv4 and administratively prohibited over IPv6, counts it, records `egress.refused` at most once every 30 seconds, and closes no open flow to make room, but the oldest endpoint in TIME_WAIT past its cap                                                                                                                                                                   | The table is the host's, see Exit translation                                                                                                                                                                                                                                                                                                                              |
| RFC 4787 section 4.3 (REQ-5), RFC 5382 section 5 (REQ-5), RFC 5508 section 3.2 (REQ-2)    | Keep an idle UDP mapping at least 2 minutes, a TCP connection established 2 hours 4 minutes and one opening or closing 4 minutes, and an ICMP query 60 seconds (MUST)                                                     | Once the host's connection table is full, the kernel may evict a translated flow before its timeout. The userspace exit keeps a leaf's closed connection in TIME_WAIT 60 seconds, gVisor's, and closes the oldest past its `TimeWait` cap                                                                                                                                                                                                                                                                                                                                            | The table is the host's, see Exit translation                                                                                                                                                                                                                                                                                                                              |
| RFC 4787 section 4.3 (REQ-5), RFC 5382 section 5 (REQ-5), RFC 5508 section 3.2 (REQ-2)    | Keep an idle UDP mapping at least 2 minutes, a TCP connection established 2 hours 4 minutes and one opening or closing 4 minutes, and an ICMP query 60 seconds (MUST)                                                     | A flow whose timeout object the kernel exit deletes, by a pass that makes a stale one again, at a stop or `ranet3 down`, or in a firewall reload's flush of the ruleset, keeps the host's shorter timeouts for the rest of its life                                                                                                                                                                                                                                                                                                                                                  | nf_tables changes no timeout object in place, deleting one clears it from every flow it timed, and a flow takes one only on its first packet, see Exit translation                                                                                                                                                                                                         |
| RFC 1122 section 4.2.2.13                                                                 | Linger in TIME-WAIT 2xMSL after an active close (MUST), and reopen on a new SYN (MAY) only with an initial sequence number past the old one's largest (1), back to TIME-WAIT for an old duplicate (2)                     | The userspace exit's endpoint toward a leaf lingers 60 seconds, gVisor's, the oldest is closed past the `TimeWait` cap, and a bare SYN past RCV.NXT, one past the leaf's FIN, closes it, with neither condition checked. gVisor's initial sequence number is a keyed hash of the four-tuple plus 64 ns ticks, so the new one falls at or before the old one's last where the old used more sequence numbers than ticks passed between the SYNs, past about 15.6 MB a second, or where over 2^31 ticks, 137 seconds, passed. A closed endpoint cannot return to TIME-WAIT             | gVisor hands a SYN in TIME_WAIT to no forwarder, so without the close a leaf that reopens a port waits out the 60 seconds. The previous connection's initial and next sequence numbers are read from gVisor only through a probe on every segment, see Exit translation                                                                                                    |
| RFC 6888 section 3 (REQ-4 and REQ-5)                                                      | Limit the rate at which one subscriber creates mappings (RECOMMENDED, SHOULD)                                                                                                                                             | Each exit bounds the flows a source holds open, and the userspace exit the connections being dialed with `Dials`, not the rate a source opens them                                                                                                                                                                                                                                                                                                                                                                                                                                   | A known gap, see Exit translation                                                                                                                                                                                                                                                                                                                                          |
| RFC 7567 section 4.2                                                                      | Use an AQM algorithm to measure local congestion and to determine the packets to mark or drop so that the congestion is managed (SHOULD)                                                                                  | The userspace exit's link queue runs RFC 8289's controlled delay, which holds its delay to 5 ms below its bound of 4,096 packets. On the exit's bench at full rate the queue stood at that bound, most of what it held was the exit's own pure ACKs, and the bound's tail drop took far more than the controlled delay, see Exit translation                                                                                                                                                                                                                                         | A pure ACK is cumulative, so dropping one slows no sender. The data toward the leaves, whose drops would, was 3 to 8% of the packets the pump took, and its senders held windows of 1 to 5 segments at their median, see Exit translation                                                                                                                                  |
| RFC 6888 section 3 (REQ-6)                                                                | Turn translation off by administration for given destination addresses or ports (MUST)                                                                                                                                    | Each exit chooses whether to carry a flow out by the flow's source alone                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | A known gap, see Exit translation                                                                                                                                                                                                                                                                                                                                          |
| RFC 6888 section 3 (REQ-9)                                                                | Implement a protocol giving subscribers explicit control over their mappings, PCP by preference (MUST)                                                                                                                    | No such protocol                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | A known gap, see Exit translation                                                                                                                                                                                                                                                                                                                                          |
| RFC 4443 section 3.1                                                                      | Answer a packet refused for its source with Destination Unreachable, code 5                                                                                                                                               | The forwarding decision drops a tun read from a source the table routes to another node or holds unreachable, through a route that does not count as a default, or from an overlay source this node does not own, with no answer                                                                                                                                                                                                                                                                                                                                                     | The source is forged, so an answer would reach the node it names                                                                                                                                                                                                                                                                                                           |
| RFC 4443 section 3.1                                                                      | Answer a packet refused for its source with Destination Unreachable, code 5                                                                                                                                               | The forwarding decision drops a tun read from a source this node does not own toward a route that counts as a default, or, under `cap.exit.via`, toward a destination outside the overlay that no entry covers, and on every platform but Linux toward any destination but an IPv6 link-local one, with no answer                                                                                                                                                                                                                                                                    | Only this node's own traffic leaves through an exit, or enters the mesh where no entry chain runs, and an unowned source may be forged                                                                                                                                                                                                                                     |
| RFC 1812 section 5.3.8                                                                    | Have source address validation off by default (MUST)                                                                                                                                                                      | The three source rules are always on, with no setting: an IPv4 tun read is dropped toward any destination from a source the table routes to another node or holds unreachable through a route that does not count as a default, or from an overlay source this node does not own, and from every source it does not own toward a default, under `cap.exit.via` toward an uncovered address outside the overlay, or anywhere off Linux                                                                                                                                                | The mesh keeps a source it does not own out at its edge, as RFC 8754 section 7 and BCP 38 ask of the domain's ingress. A path that is asymmetric costs what [the limits](limits.md#transit) say                                                                                                                                                                            |
| RFC 4443 section 3.1                                                                      | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                                                                                                   | The forwarding decision drops a tun read whose walk finds a routing header of type 0, 1 or 4, or a type it does not recognize, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                        | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                                                      | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                                                                                                   | The forwarding decision drops a tun read addressed to one of this node's own SIDs, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | An answer tells the host which addresses are SIDs                                                                                                                                                                                                                                                                                                                          |
| RFC 4443 section 3.1                                                                      | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                                                                                                   | The forwarding decision drops a tun read whose inner packet, opened one level deep, is itself IP-in-IP, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                               | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                                                      | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                                                                                                   | The forwarding decision drops a tun read whose chain runs past 16 hop-by-hop, destination options, routing and authentication headers and atomic fragments' headers, with no answer                                                                                                                                                                                                                                                                                                                                                                                                  | The walk that finds a routing header or an inner packet must end, and no deployment sends such a chain                                                                                                                                                                                                                                                                     |
| RFC 4443 section 3.4                                                                      | Discard a packet whose header cannot be processed and answer it with Parameter Problem (SHOULD)                                                                                                                           | The forwarding decision drops a tun read whose chain ends inside a header the walk reads, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.4                                                                      | Discard a packet whose header cannot be processed and answer it with Parameter Problem (SHOULD)                                                                                                                           | The forwarding decision drops a tun read whose inner packet, opened one level deep, has a header that cannot be read, with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                 | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                                                      | Answer a packet for a subnet of its own arrival link with Destination Unreachable, code 3, and never forward it back onto that link (MUST NOT)                                                                            | The forwarding decision writes a tun read to an address the tun holds, one of this node's own addresses, back into the tun, which the MUST NOT leaves out. It drops any other tun read the table answers as this node's own, with no answer, so that one never goes back into the tun                                                                                                                                                                                                                                                                                                | A known gap                                                                                                                                                                                                                                                                                                                                                                |
| RFC 8966 section 3.1                                                                      | Send buffered TLVs after a random delay, and space the packets sent on 1 interface (SHOULD)                                                                                                                               | No send is jittered and a pass's packets go back to back, but triggered updates to 1 neighbor are paced                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Each link is 1 ESP session to 1 neighbor, with no medium shared with other speakers, see Sending and link cost                                                                                                                                                                                                                                                             |
| RFC 8966 section 3.2.2                                                                    | Raise the node's own seqno only when asked                                                                                                                                                                                | The seqno rises at every start                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Peers take a restarted node's routes at once                                                                                                                                                                                                                                                                                                                               |
| RFC 8966 section 3.4.2, Appendix B                                                        | Send IHUs less often than Hellos (SHOULD), with every third Hello on a lossless link, naming 3 Hello intervals                                                                                                            | An IHU goes with every Hello and names the Hello interval                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | RFC 9616 takes 1 round-trip sample from each Hello and IHU pair                                                                                                                                                                                                                                                                                                            |
| RFC 8966 section 3.5.3, RFC 9079 section 5.1                                              | Create a route table entry for each finite update, and take an expired or retracted one to infinity before a flush                                                                                                        | An update for the destination and source of this node's own prefix or assigned address is kept outside the route table as its neighbor's offer while the key is its own, and dropped with no hold at its expiry or a retraction, and one for its own host address from another source is dropped                                                                                                                                                                                                                                                                                     | Appendix E: the directly attached prefix is preferred, and the host's kernel delivers its own address whatever the source. A selected route's hold exists to keep what this node told its neighbors, and an offer was never told                                                                                                                                           |
| RFC 8966 section 3.5.3                                                                    | Create a route table entry for each finite update a neighbor sends                                                                                                                                                        | An update under a router-id of all zeroes or all ones is dropped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Section 4.1.3 forbids that router-id, and Appendix C allows the filter                                                                                                                                                                                                                                                                                                     |
| RFC 8966 section 3.5.3                                                                    | Create a route table entry for each finite update a neighbor sends                                                                                                                                                        | An update under this node's own router-id takes out the route or offer its neighbor last sent, as a retraction does                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | It is this node's own route come back, so the neighbor has no other to give                                                                                                                                                                                                                                                                                                |
| RFC 8966 section 3.5.4                                                                    | End a hold once every neighbor acknowledges a retraction                                                                                                                                                                  | The hold lasts until an expiry timer runs out, transit for the prefix answered unreachable meanwhile                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | The RFC's own reason: "The former option is simpler"                                                                                                                                                                                                                                                                                                                       |
| RFC 8966 section 3.5.4                                                                    | Forward no packet inside a held prefix by a shorter route                                                                                                                                                                 | The kernel keeps no hold that counts as a default, so the host's traffic there ends by the routes left, the host's own or a shorter route back into the tun, as [where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) gives                                                                                                                                                                                                                                                                                                                                              | That hold in the kernel would cut the host off                                                                                                                                                                                                                                                                                                                             |
| RFC 8966 section 3.5.4                                                                    | Forward no packet inside a held prefix by a shorter route                                                                                                                                                                 | A packet inside a hold that does not count from a socket carrying the underlay's mark, from one bound to a device, or on macOS from one bound to no interface and no address of the tun ends where rows L2 and B1 to B4 of [where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux) and rows D1 and D2 of [where a lookup ends on macOS](../routing.md#where-a-lookup-ends-on-macos) give                                                                                                                                                                          | The node's marked underlay stays out of the tun that carries it, a bound socket asked for its device, and on macOS an unscoped hold would shadow every other way to its prefix, see Updates and requests                                                                                                                                                                   |
| RFC 8966 section 3.5.4                                                                    | Forward no packet inside a held prefix by a shorter route                                                                                                                                                                 | On Linux, a packet the host sends or forwards inside a hold that does not count ends outside `overlay` at a route of main longer than /0 that covers it, as row L6 of [where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) gives, and where another program's rule comes first as [sharing a host](../coexistence.md#another-programs-rules) describes                                                                                                                                                                                                                  | Outside the overlay every route of main longer than /0 answers ahead of the mesh's table, which keeps the host's LAN reachable, and ranet3 leaves another program's rules ahead of its own alone, see Updates and requests                                                                                                                                                 |
| RFC 8966 section 3.7.2                                                                    | Try to reach every neighbor with a triggered update                                                                                                                                                                       | It is sent once                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Each link is 1 ESP tunnel that delivers in order                                                                                                                                                                                                                                                                                                                           |
| RFC 8966 sections 3.8.1.1, 3.8.1.2                                                        | Answer a request when a selected route exists                                                                                                                                                                             | Split horizon applies to replies                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | The requester is the route's next hop                                                                                                                                                                                                                                                                                                                                      |
| RFC 8966 section 3.8.1.2                                                                  | Forward a seqno request only while advertising the prefix                                                                                                                                                                 | Forwarded whenever a route exists                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Starvation leaves nothing advertised                                                                                                                                                                                                                                                                                                                                       |
| RFC 8966 section 3.8.1.2                                                                  | Forward a seqno request to a feasible route's next hop, or failing that to an unfeasible route's                                                                                                                          | One under a router-id of all zeroes or all ones is not forwarded                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Section 4.1.3 forbids sending that router-id                                                                                                                                                                                                                                                                                                                               |
| RFC 8966 section 3.8.2.1                                                                  | Name in a starving node's seqno request the router-id of the route it has just lost                                                                                                                                       | A prefix of this node's own given back with only unfeasible offers asks each offer's neighbor for that offer's router-id                                                                                                                                                                                                                                                                                                                                                                                                                                                             | The lost route is this node's own, and only the offer's router-id can make the offer feasible                                                                                                                                                                                                                                                                              |
| RFC 8966 section 3.8.2.3                                                                  | Ask for a selected route shortly before it expires                                                                                                                                                                        | No such request is sent                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Not implemented                                                                                                                                                                                                                                                                                                                                                            |
| RFC 8966 section 4                                                                        | Make packets as large as the link's MTU allows                                                                                                                                                                            | At most 1232 octets of UDP payload                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Every session carries 1280 bytes                                                                                                                                                                                                                                                                                                                                           |
| RFC 8966 section 6                                                                        | Implement BABEL-MAC (SHOULD), and protect all Babel traffic with a cryptographic protocol (RECOMMENDED)                                                                                                                   | Neither BABEL-MAC nor Babel over DTLS                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Every Babel packet travels inside an ESP session that authenticated its neighbor                                                                                                                                                                                                                                                                                           |
| RFC 8966 Appendix A.3                                                                     | Smooth the metric as an average                                                                                                                                                                                           | An increase takes effect at once                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | A route that went bad is left at once                                                                                                                                                                                                                                                                                                                                      |
| RFC 8966 Appendix A.3                                                                     | Switch to a route lower on both the metric and the smoothed metric                                                                                                                                                        | The smoothed metric must also be lower by more than the margin [route selection](../routing.md#route-selection) gives                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Section 3.6 leaves selection to local policy, and the margin keeps 2 routes whose costs move around 1 value from trading places                                                                                                                                                                                                                                            |
| RFC 8966 Appendix B                                                                       | An urgent timeout of 0.2 seconds                                                                                                                                                                                          | An urgent update that follows another to the same neighbor waits out the pace [route selection](../routing.md#route-selection) gives                                                                                                                                                                                                                                                                                                                                                                                                                                                 | A route that flaps costs each neighbor 1 update a pace, as BIRD paces them, and the raises that requests owe in it go out as 1                                                                                                                                                                                                                                             |
| RFC 8966 Appendix B                                                                       | Time a request out after 2 seconds, doubled at each of up to 3 resends                                                                                                                                                    | A seqno request is repeated up to 4 times, 3, 3, 6 and 12 seconds apart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | A first delay past the 2 second window in which a request is redundant keeps a repeat from being dropped                                                                                                                                                                                                                                                                   |
| RFC 8966 Appendix B                                                                       | Estimate a wired link's cost 2-out-of-3 with C=96                                                                                                                                                                         | ETX on every link, unless `cap.babel.quality` is `none`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Every link is a tunnel, and ETX measures the loss of the path it crosses                                                                                                                                                                                                                                                                                                   |
| RFC 9616 section 4.2                                                                      | Default to rtt-max = 120 ms and max-rtt-penalty = 150 (RECOMMENDED)                                                                                                                                                       | rtt-max is 1024 milliseconds and the penalty 1024                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | In a global mesh 120 milliseconds saturates every intercontinental path, and a penalty of 150 against a wired cost of 96 makes a satellite hop cost less than 3 wired ones                                                                                                                                                                                                 |
| RFC 8200 section 4.5                                                                      | Wait 60 seconds for fragments, and answer errors with ICMP                                                                                                                                                                | Wait 16 seconds, send no ICMP, drop more                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Fragments of 1 packet cross 1 session together                                                                                                                                                                                                                                                                                                                             |
| RFC 7045 section 2.1, RFC 5095 section 4.2                                                | Discard a standard extension header only by a policy configurable per type, allow them by default, and forward routing types other than 0                                                                                 | A tun read's routing header of type 0, 1 or 4, or of a type ranet3 does not recognize, is dropped by a policy fixed in code, and types 2, 3, 253 and 254 pass                                                                                                                                                                                                                                                                                                                                                                                                                        | Types 0 and 1 are deprecated, and type 4 entering from a host is a packet entering the SR domain, which RFC 8754 section 5.1 drops at the edge. A type defined later can steer a packet as the SRH does, and the walk cannot tell one that does from one that does not. No deployment needs another policy                                                                 |
| RFC 7045 section 2.1                                                                      | Forward a packet regardless of the extension headers present                                                                                                                                                              | A tun read whose chain runs past 16 hop-by-hop, destination options, routing and authentication headers and atomic fragments' headers is dropped                                                                                                                                                                                                                                                                                                                                                                                                                                     | The walk that finds a routing header or an inner packet must end, and no deployment sends such a chain                                                                                                                                                                                                                                                                     |
| RFC 8754 section 4.2                                                                      | A transit node forwards an SRH it is not the destination of                                                                                                                                                               | The tun read's walk drops an SRH whatever its destination                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | The mesh is the SR domain and the tun its edge, section 5.1                                                                                                                                                                                                                                                                                                                |
| RFC 8754 section 5.4                                                                      | Handle errors as RFC 2473 does, and send them to sources in the SR domain                                                                                                                                                 | `End` answers a segment it admits too large for its next session about the packet it carries, to that packet's source, in the mesh or not                                                                                                                                                                                                                                                                                                                                                                                                                                            | The headend relays no answer to the sender, see ICMP answers                                                                                                                                                                                                                                                                                                               |
| RFC 8754 section 5.4                                                                      | Handle the errors an encapsulated packet meets as RFC 2473 does                                                                                                                                                           | A headend writes an ICMPv6 error about its encapsulation into its tun, for a steer entry's packets and, under `cap.exit.via`, for every packet of the host that only a default would carry                                                                                                                                                                                                                                                                                                                                                                                           | A known gap, declared for mode 3 in limits, see ICMP answers                                                                                                                                                                                                                                                                                                               |
| RFC 8986 section 4.8                                                                      | The End.DT46 SID MUST be the last segment in an SR Policy                                                                                                                                                                 | A headend takes any SID as the last of `cap.exit.via` or a steer entry's `via`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | A node keeps no list of other nodes' SIDs, so the operator writes the End.DT46 last, see ICMP answers                                                                                                                                                                                                                                                                      |
| RFC 8986 section 6                                                                        | Keep a pair of traffic counters, one for packets and one for bytes, per local SID entry (SHOULD)                                                                                                                          | Node totals of what its SIDs forward, deliver, egress, refuse and drop, in `ranet3 status` and `ranet3 debug segments`, none per SID                                                                                                                                                                                                                                                                                                                                                                                                                                                 | A counter per SID costs an atomic write a packet on each SID's path, and the node counts all its SIDs together                                                                                                                                                                                                                                                             |
| RFC 8200 sections 4.5 and 5                                                               | Reassemble fragments at the destination, one of up to 1500 octets once whole                                                                                                                                              | `End` and `End.DT46` drop a fragment of a larger packet with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | A fragment of a larger packet needs reassembly the SID does not do, see ICMP answers                                                                                                                                                                                                                                                                                       |
| RFC 8200 section 4.1                                                                      | Accept and attempt to process extension headers in any order, occurring any number of times                                                                                                                               | `End` and `End.DT46` refuse a packet with a ninth extension header they would step past, with RFC 8883's Parameter Problem, code 8                                                                                                                                                                                                                                                                                                                                                                                                                                                   | A sender cannot choose what one packet costs, see ICMP answers                                                                                                                                                                                                                                                                                                             |
| RFC 8986 section 4.1, RFC 8754 section 4.3.1.1                                            | Forward a packet with segments left whose routing header describes itself                                                                                                                                                 | `End` refuses an SRH holding more than 16 segments with segments left, with RFC 8883's Parameter Problem, code 6                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | A sender cannot choose the list a waypoint carries on, see ICMP answers                                                                                                                                                                                                                                                                                                    |
| RFC 8986 section 4.1                                                                      | Submit the packet to the FIB lookup for its new destination                                                                                                                                                               | `End` drops with no answer a packet whose next segment is no SID of this node and lies inside a prefix this node originates that counts as no default                                                                                                                                                                                                                                                                                                                                                                                                                                | None holds, see ICMP answers                                                                                                                                                                                                                                                                                                                                               |
| RFC 8754 section 4.3.2                                                                    | At a local interface that is no SID, process the next header at segments left 0                                                                                                                                           | `End` drops with no answer a packet at segments left 0 whose next segment is an address `cap.table` assigns this node                                                                                                                                                                                                                                                                                                                                                                                                                                                                | None holds, see ICMP answers                                                                                                                                                                                                                                                                                                                                               |
| RFC 8200 sections 4 and 4.2                                                               | Process extension headers in order, and an unrecognized option by its type's 2 high bits: skip it, discard the packet, or discard and answer                                                                              | `End` and `End.DT46` read no option of a hop-by-hop or destination options header they walk past, so `End` forwards and `End.DT46` decapsulates a packet such an option says to discard                                                                                                                                                                                                                                                                                                                                                                                              | None holds: Linux acts on the options of a hop-by-hop header in the first place, see ICMP answers                                                                                                                                                                                                                                                                          |
| RFC 8200 section 4.4, RFC 4443 section 3.2                                                | Discard a packet larger than the link its routing header sends it onto, and answer it with Packet Too Big (MUST)                                                                                                          | `End` cuts a carried IPv4 packet without DF, and drops with no answer one it cannot cut but for its options                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | RFC 1812 has a router cut IPv4 and silently discard a bad header, and none holds for the rest, see ICMP answers                                                                                                                                                                                                                                                            |
| RFC 4443 sections 3.2, 3.3 and 3.4                                                        | Send Packet Too Big and Time Exceeded (MUST) and Parameter Problem (SHOULD) to the packet's source                                                                                                                        | The Time Exceeded, Parameter Problem and Destination Unreachable a refused segment gets go only through a session, so none goes to a source an entry of this node's own reaches, this host or a network behind it among them. The answer to a segment larger than its next session, or to its packet's unreadable options, goes into the tun where that entry counts as no default, and nowhere where it counts as one                                                                                                                                                               | A host's strict reverse path check drops an answer from a SID, which the host never routes into the tun, and the mesh routes no reply to a source only this node's own default reaches, see ICMP answers                                                                                                                                                                   |
| RFC 8200 section 3, RFC 4443 section 3.4                                                  | Payload Length counts the octets after the IPv6 header, and a field keeping a packet from being processed gets Parameter Problem (SHOULD)                                                                                 | An IPv6 packet a session delivers whose Payload Length runs past its octets, or is 0 with octets after its header, is dropped with no answer                                                                                                                                                                                                                                                                                                                                                                                                                                         | A jumbogram fits no session, which covers the drop at 0. The session drops the packet before the mesh, whose one entry for a session's packets hands one to a SID of this node to that SID before any answer, see Transit answers                                                                                                                                          |
| RFC 8754 section 7                                                                        | Admit at ingress only the sources of the attached networks, as BCP 38 does                                                                                                                                                | The antispoof filter denies the mesh's own space from outside, but what [carve-outs](../antispoof.md#carve-outs) and [exemptions](../antispoof.md#exemptions) pass, and admits the rest, and on Linux `mesh_entry` admits into the tun only this node's own sources, a reply, a `none` class's destination and an IPv6 link-local or multicast destination                                                                                                                                                                                                                           | The permit half needs first-hop source validation                                                                                                                                                                                                                                                                                                                          |
| RFC 8754 section 7                                                                        | Admit at ingress only the sources of the attached networks, as BCP 38 does                                                                                                                                                | On Linux a tun read from a source this node does not own, outside the overlay and covered by no route but one that counts as a default, passes toward a mesh destination. Every other platform drops it, since no exit's replies cross the tun there                                                                                                                                                                                                                                                                                                                                 | Owning every source would drop the replies to an exit's egress and to a subnet router's LAN, since a tun read does not say whether it answers a flow                                                                                                                                                                                                                       |

## NAT traversal and ports

A node uses a private IKEv2 transport profile rather than general-purpose
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
- The `IKE_INTERMEDIATE` exchange of a joined kex entry stays on that path as
  well.
  [RFC 9242 section 3.2](https://www.rfc-editor.org/rfc/rfc9242.html#section-3.2)
  says "If the presence of NAT is detected in the IKE_SA_INIT exchange via
  NAT_DETECTION_SOURCE_IP and NAT_DETECTION_DESTINATION_IP notifications, then
  the peers switch to port 4500 in the first IKE_INTERMEDIATE exchange and use
  this port for all subsequent exchanges, as described in Section 2.23 of
  [RFC7296]."
- Received NAT-detection notifications are not used to select a transport: there
  is no port-500-to-4500 transition and no dedicated
  [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) NAT keepalive. The
  userspace transport accepts UDP-encapsulated ESP only, not raw IP ESP.

A strongSwan peer must therefore set `charon.port_nat_t` to the port the trust
document lists for it. Otherwise it moves to port 4500 once it detects the NAT
the mismatch reports, and nothing listens there. This profile remains usable
when a NAT changes the observed source port: replies follow the observed source,
and a fresh authenticated IKE request, or the authenticated answer to this
node's own request, can update the stored peer endpoint. It is deliberately not
interoperable with an otherwise generic peer expecting standard RFC 7296 port
selection or raw ESP.

A node sends no NAT keepalive, which
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

Once its IKE SA is established, every session moves the stored peer endpoint to
the address and port of an IKE message whose integrity protection validates and
that is new: a request at the Message ID the session expects next, or the answer
to the one request this node has outstanding, which the answer then settles. A
fragmented message moves it once whole, to where the fragment that completed it
came from. A replayed request, an answer that matches no outstanding request and
a message that does not validate move nothing. In the handshake, the responder
moves to where the `IKE_AUTH` request came from once it validates. The answers
the initiator reads move nothing, since the IKE SA they set up does not exist
yet, and a dial sends each of its requests to the endpoint it dials.
[RFC 7296 section 2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23)
asks a host that is not behind a NAT to follow "a packet whose integrity
protection validates", which takes in ESP packets as well, and asks a host
behind a NAT not to follow at all. A node departs from both. An ESP packet from
a new address moves nothing, and ESP following a validated packet too is
scheduled. A fresh request or answer moves the endpoint whether or not the node
is behind a NAT. A node never learns whether it is behind one, because it does
not compare the `NAT_DETECTION_DESTINATION_IP` it receives with its own address.

Behind a NAT, someone who captures a request or an answer and resends it from
another address before the original arrives can move a session's sends to that
address, and the original then moves nothing. The peer's next fresh request
moves them back. The peer sends one once it has heard nothing from this node for
its liveness interval, 10 seconds on a ranet3 peer. In exchange a session
follows a peer that moved, whichever end dialed, as soon as the peer either asks
or answers.

## Answer addresses

[RFC 7296 section 2.11](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.11)
says an implementation "MUST specify the address and port at which the request
was received as the source address and port in the response." On Linux and macOS
each answer names the address its request reached, and a session the peer opened
sends everything else from that address too, as
[moving hosts](../platforms.md#moving-hosts) describes. Once the host no longer
holds the address, or holds it with no route from it to the peer, the kernel
refuses a send from it, and the send goes again from the kernel's choice of
source. Without that resend the answer would not leave at all.

Each answer still tries the address first, so answers leave from it again as
soon as the kernel takes a send from it. The session's own sends stay on the
kernel's choice until a fresh request or answer moves them back, as
[moving hosts](../platforms.md#moving-hosts) gives, which a peer sends once that
traffic is lost. Where the session's ESP from the other address still reaches
the peer, the peer has no cause to probe, and the session stays there until a
fresh request or answer reaches the address.

On FreeBSD and OpenBSD the socket keeps no source, so every answer leaves from
the kernel's choice. Neither platform is supported beyond building.

## Rekeying

A node departs from a SHOULD of
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
algorithm. A peer's IKE SA rekey that does not offer the current PRF is refused
with `NO_PROPOSAL_CHOSEN`. Once a reload's `cap.crypto.ike.prf` leaves out the
PRF an IKE SA runs, no rekey of it is open, so the session deletes the IKE SA
and a new handshake under the new lists replaces it, as
[reloading](../reloading.md#capcrypto) describes.

An IKE SA rekey this node starts may run each `cap.crypto.ike.kex` entry that
keeps the ML-KEM method of the SA's entry while `kex` holds that entry, and any
`kex` entry once a reload left it out. An SA of `x25519+mlkem768` is then
rekeyed only by an entry joining `mlkem768`, and an SA of a classical entry may
move to a joined one. The rekey runs its key exchange in the SA's group while
one of those entries has that group, and in the group of the first of them
otherwise. A joined entry's ML-KEM method, ML-KEM-768 or ML-KEM-1024, then runs
in an `IKE_FOLLOWUP_KE` exchange after the `CREATE_CHILD_SA`, as
[RFC 9370 section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
describes. The `IKE_SA_INIT` offer holds 1 proposal for each `kex` entry, and
the offer of an IKE SA rekey 1 for each entry the rekey may run, in `kex` order,
with the first proposal in the group of its key exchange moved ahead of the
rest. A retry after `INVALID_KE_PAYLOAD` sends its key exchange in the group the
answer named and moves the first proposal in that group ahead.
[RFC 7296 section 3.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.4)
says the group of the key exchange "SHOULD match the Diffie-Hellman group in the
first group in the first proposal, if such exists."

As responder, ranet3 takes the first entry of its `kex` that a proposal holds,
among the proposals its lists meet in every other type, and answers the first
proposal in the offer's order holding that entry. A proposal holds an entry when
it offers the entry's group and its ML-KEM method, and `NONE` in any additional
key exchange type the entry does not use, as
[the configuration reference](../configuration-reference.md#how-the-lists-are-used)
gives it. In `IKE_SA_INIT`, a proposal that offers an additional key exchange
counts only when the request asked for `IKE_INTERMEDIATE`. A peer's IKE SA rekey
takes only an entry this node's own rekey of the SA may run, and is refused with
`NO_PROPOSAL_CHOSEN` when the offer holds none. While `kex` holds the entry of
an SA of `x25519+mlkem768`, a peer's rekey of it without ML-KEM-768 is refused
that way. A peer's Child SA creation or rekey may take any `kex` entry. After
either one's `CREATE_CHILD_SA`, a joined entry's ML-KEM method runs in an
`IKE_FOLLOWUP_KE` exchange. A key exchange in another group than the entry's is
answered with `INVALID_KE_PAYLOAD` naming the entry's group, in `IKE_SA_INIT`,
in an IKE SA rekey and in a Child SA rekey that carries a key exchange, as
[section 1.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3) lets a
responder "indicate its preferred Diffie-Hellman group". A peer whose key
exchange is in the group of an entry this node lists lower spends 1 round trip.
A peer's rekey whose key exchange is in the SA's group keeps the SA's entry
while `kex` holds it and the offer holds it, so a peer's scheduled rekey in the
SA's group costs no round trip. That holds for an IKE SA and for a Child SA the
peer keyed with key exchanges of its own.

A peer's Child SA creation or rekey can run key exchanges for PFS with any `kex`
entry. A Child SA rekey this node starts runs no key exchange and derives keys
from the IKE SA alone, and a Child SA the peer keyed with key exchanges of its
own loses them at this node's next rekey. That departs from section 2.8, which
says that "when rekeying, the new Child SA SHOULD NOT have different Traffic
Selectors and algorithms than the old one", since ranet3 starts no Child SA key
exchange of its own. The new Child SA's keys still come from the IKE SA's
`SK_d`, which an IKE SA of a joined entry derives with its ML-KEM method. A PFS
peer's rekey of a Child SA that ranet3's own rekey made has no entry to keep.
strongSwan sends it in the first group of its proposals, and ranet3 answers
`INVALID_KE_PAYLOAD` naming the group of the first entry of its own `kex` that a
proposal of the offer holds, where that is not the group of strongSwan's key
exchange. strongSwan tries again in that group and is taken. That costs 1
`CREATE_CHILD_SA` round trip for each such rekey over the session's life, since
each rekey of ranet3's in between drops the key exchanges again.

A Child SA rekey this node starts offers only the cipher of the SA it replaces
while `cap.crypto.esp.cipher` holds it, as
[RFC 7296 section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8)
asks. Answering a peer's Child SA rekey, ranet3 takes that cipher when the offer
and its list both hold it, and otherwise the first cipher of its list that the
offer holds. A peer whose own lists left the cipher out offers only the others,
and refusing them would keep its SA on a cipher it removed. A reload whose list
leaves the cipher out moves the SA to a listed cipher at the rekey it forces.
Both depart from the same SHOULD NOT. Section 3.3.4 says "The implementation
MUST reject SA proposals that are not authorized by these IKE suite controls",
which rules out keeping a cipher the lists left out.

When a peer refuses a rekey with `NO_ADDITIONAL_SAS`,
[RFC 7296 section 4](https://www.rfc-editor.org/rfc/rfc7296.html#section-4)
requires that the node can delete the old SA and create a new one instead. Where
the peer's own rekey of the same IKE SA crossed this node's and this node
answered it, its SA is held, and ranet3 takes that SA, as it does after any
error notify but `INVALID_SYNTAX`. Otherwise ranet3 keeps the old SA and retries
the rekey on its backoff, from 5 seconds up to 5 minutes at the defaults, until
the SA's lifetime ends and the IKE SA is deleted with it, or until a rekey the
peer starts replaces the SA. Only `CHILD_SA_NOT_FOUND` makes it create a new
Child SA from scratch. Deleting the old SA first would leave the session with no
SA for the round trip creating a new one takes, while the old SA carries traffic
until one of those replaces it.

[RFC 7296 section 2.25.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.2)
asks an end that receives a rekey of an IKE SA it is rekeying itself to reply as
usual. Past the IKE SA's lifetime, ranet3 answers every rekey on it with
`TEMPORARY_FAILURE` instead, whatever it is running itself.
[Section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8) says that
once its lifetime expires, an SA "MUST NOT be used", and a rekey answered on it
would use its keys for the exchange and for the new SA's keys. Before the
lifetime, such a rekey is answered as usual, except while this end's own rekey
of the IKE SA has had its `CREATE_CHILD_SA` answered and runs its
`IKE_FOLLOWUP_KE` exchange. This end then answers the peer's rekey with
`TEMPORARY_FAILURE`, as
[RFC 9370 section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
requires for a rekey that arrives while "the CREATE_CHILD_SA exchange initiated
by this peer has already been completed, and the series of IKE_FOLLOWUP_KE
exchanges is in progress": "a TEMPORARY_FAILURE notification MUST be sent in
response to such a request."

[RFC 9370 section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
has a responder delete the state of a rekey whose `IKE_FOLLOWUP_KE` request it
"does not receive ... after some reasonable period of time", and says "In
general, 5-20 seconds of waiting time should be appropriate in most cases." This
end waits 62 seconds, the time it resends 1 cut of a request to a silent peer
before it deems the IKE SA failed. A peer that resends as ranet3 does makes the
sends of that request within those 62 seconds through a step to its family's
floor and 1 or 2 falls of the path MTU, the last at most 40 seconds after the
answer before it where its schedule's own sends see the falls and at most 52
where probes see them, and finds the state kept. A chain of falls can carry its
last send past them, 4 falls that probes see or 13 that the schedule's sends
see. Such a peer's rekey then fails as late and is retried, with no SA lost. The
wait and what follows it are in [limits](limits.md#ike).

## Lifetimes

An SA past its lifetime is not used, as
[RFC 7296 section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8)
asks, with 2 exceptions.

An IKE SA past its lifetime still carries the exchange outstanding at its
lifetime, its answers to the peer's requests and then its own Delete.
[Section 2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1) has a
request retransmitted until it is answered or the IKE SA is deemed failed, and
[section 2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.3) has an
end wait for the answer to each request before it sends the next. The Delete
waits for the exchange already out, which takes its next send at the lifetime as
[limits](limits.md#ike) gives for an IKE SA that starts to close. That exchange
gets the sends of a silent peer whatever traffic the peer keeps up: 5 over about
62 seconds at the most for 1 cut, a request that fits its family's floor whole
and one whose path already sits at the floor included, 7 over 68 seconds at the
most for a request too large for the floor that the step to it from a larger
threshold cuts again, and more where the path MTU falls, at most 20 counted
sends, with a probe that cuts nothing adding sends it does not count. A Delete
of an IKE SA gets 2. The IKE SA is then deemed failed. The peer's rekeys are
answered `TEMPORARY_FAILURE`, and nothing else starts. A replaced IKE SA this
end deletes carries that Delete, which section 2.8 makes the last request on the
old SA, and takes its answer past the lifetime. When both of its sends go
unanswered, the replaced IKE SA alone is deemed failed, since the new one holds
its Child SAs.

An ESP batch that took a Child SA's keys before its lifetime finishes on them.
The keys leave the dataplane at the lifetime, and the batch holds the set of SAs
it started with, as every batch does across a rekey.

## Closing SAs

[RFC 7296 section 1.3.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3.1)
says "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA". A
node holds to that for a `CREATE_CHILD_SA` exchange. When the Child SA that
`IKE_AUTH` carries fails, both ends delete the IKE SA. A responder that refuses
it answers with its `AUTH` and the error, as
[section 1.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.2) asks, and
then sends a Delete for the IKE SA. An initiator that receives such an answer
deletes the IKE SA too, and so does an end whose own dataplane refuses the first
Child SA. An IKE SA carries nothing here without its Child SA, and keeping it
would hold state on both ends with no traffic to protect. The node that dialed
dials again.

Any error notify beside the responder's `AUTH` is such a refusal, a type ranet3
does not know included, since
[section 3.10.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.10.1)
says a recipient of one it does not recognize "MUST assume that the
corresponding request has failed entirely". The exceptions are
`AUTHENTICATION_FAILED`, `INVALID_SYNTAX` and `UNSUPPORTED_CRITICAL_PAYLOAD`,
after which
[section 2.21.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.2)
leaves the IKE SA uncreated without a Delete.

[RFC 7296 section 2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4)
asks an end that closes an IKE SA to send a Delete for it "unless the other
endpoint is no longer responding". A node does so wherever the peer may still
answer, except in 5 cases where it closes without one:

- This end's Message ID space is spent. A Delete is a request and needs one.
- A request or a response cannot be built. A Delete is encrypted the same way,
  so it could not be built either.
- A request from the peer takes the last Message ID this end can count.
  [Section 2.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.2) has the
  peer rekey or close the IKE SA long before.
- The peer's fragments of 1 message pass the reassembly limit.
  [RFC 7383 section 5](https://www.rfc-editor.org/rfc/rfc7383.html#section-5)
  says "the receiver can consider this situation to be either an attack or a
  broken sender implementation. In either case, the receiver SHOULD drop the
  connection and discard all the received fragments."
- A newer IKE SA of the session's path carries the peer's `INITIAL_CONTACT`.
  Section 2.4 allows an end to conclude that the peer has failed only on such a
  notice or a timeout, and lets it "delete any other IKE SAs it has to the same
  authenticated identity without waiting for a timeout". The notice is read per
  path: a node deletes the session it holds on the notice's path, with its Child
  SAs, where it took that session before the notice's IKE SA started, leaves a
  newer one there, from a dial that crossed the notice's, to the
  [`preferred`](../control-socket.md#requests-and-answers) rule, and leaves its
  sessions on the peer's other paths for dead peer detection or the peer's own
  new handshakes to end.

One close comes near these. An answer to this end's own request that does not
decode after its integrity check closes the IKE SA as
[section 2.21.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.3)
closes one after a malformed request, without a Delete, since the 2 ends'
encodings disagree and a Delete's answer would come from the same encoder.

[Section 2.21.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.3)
says "After the IKE SA is authenticated, all requests having errors MUST result
in a response notifying the other end of the error." A node answers a request
that does not parse with `INVALID_SYNTAX`, and an `INVALID_SYNTAX` sent or
received ends the IKE SA it came on without a Delete, since that section makes
the error fatal to both ends. A `CREATE_CHILD_SA` on an IKE SA that is busy, as
a replaced IKE SA still kept for its Delete always is, is answered
`TEMPORARY_FAILURE` before it is parsed, malformed or not, and the IKE SA stays.
A replaced IKE SA past its lifetime answers no request, malformed or not.
[Section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8) says
"When the lifetime of a Security Association expires, the Security Association
MUST NOT be used", and an answer would go out under its keys. Past its lifetime
such an IKE SA takes only the answer to this end's own Delete on it, as
[Lifetimes](#lifetimes) describes.

## IKE fragmentation

A node sends a message larger than the path in the fragments of
[RFC 7383](https://www.rfc-editor.org/rfc/rfc7383.html) where both ends sent
`IKEV2_FRAGMENTATION_SUPPORTED`, and reassembles the peer's, as
[limits](limits.md#paths-under-1280-bytes) describes. It departs from the RFCs
in these places.

[Section 2.5.1](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.5.1) says
"If the sender has information about the PMTU size, it SHOULD use it." A node
reads the path MTU the host holds at each send, but never cuts for less than
1280 bytes over IPv6 or 576 over IPv4, the values the same section recommends
where the path MTU is unknown, though the host knows a smaller one. IPv6 carries
1280 on every link, and the section says of 576 that "the value is large enough
for the presented solution and small enough to avoid IP fragmentation in most
situations".

[Section 5](https://www.rfc-editor.org/rfc/rfc7383.html#section-5) recommends
bounding the "sum of the sizes of Encrypted Fragment payload contents (after
decryption)" in a reassembly queue. A node bounds the stored fragments as the
IKE messages they arrived as instead, 16 KiB of them. Those hold more than their
content, and the bound covers what each fragment costs beside it. The bound
leaves the largest message a peer sends room at the IPv4 floor.

[Section 2.5.2](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.5.2) has
the initiator of an exchange probe smaller thresholds, coarse-grained. On Linux
and macOS ranet3 tries 2: the path MTU the host holds, read again at each send,
and the family's floor once the schedule's sends under a larger threshold went
unanswered twice, taken at the next send, the schedule's or a probe's, as
[paths under 1280 bytes](limits.md#paths-under-1280-bytes) gives. Where the
host's path MTU cannot be read, as on FreeBSD and OpenBSD, whose IKE leaves
without DF, only the floor is tried. Each exchange starts from the path MTU the
host reads, so a step carries nothing to the session's later exchanges, though
the section has "In subsequent exchanges, the node should start with the current
value of the fragmentation threshold", a sentence without a BCP 14 keyword. A
later exchange on a path narrower than the host reads, whose hop drops larger
datagrams and sends no ICMP message, steps down again after the same 2
unanswered sends. Each new cut is the original message cut again, with a larger
Total Fragments, as the section asks, so a retransmission after it is not
bitwise identical to the first send, which
[RFC 7296 section 2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
requires. Each new cut also starts the retransmission waits over, as section
2.5.2 requires ("the timers will start over"), where
[RFC 7296 section 2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4)
says "retransmission times MUST increase exponentially". The sends of a request
that ranet3 counts stay within 20 however it is cut, and a probe that cuts
nothing resends it without counting it. A close cuts a wait short too: once the
IKE SA starts to close, for any reason its lifetime included, the request
outstanding then takes its next counted send at once, from its own budget, as
[limits](limits.md#ike) gives. The RFC 7296 section 2.4 row on retransmission
times, in the table at the top of this page, gives the reason.

A responder takes section 2.5.1's "may use the maximum size of the received IKE
Fragment message IP datagrams as a threshold when constructing a fragmented
response", for the first answer to a request in fragments and for a kept answer
a repeat draws again, never under the floor, with Total Fragments grown as
section 2.5.2 asks. A repeat whole carries no size and leaves the answer as it
stands, unless the path MTU the host reads fell below the threshold the answer
was cut under, and the answer is then cut again for it with Total Fragments
grown. An answer cut for a wider path to a request that came whole thus never
shrinks for a repeat whole while that reading holds, and where a hop narrower
than the path the host reads drops its datagrams and sends no ICMP message, the
exchange runs to its budget. That stays because an answer no larger than a
request that came whole goes in datagrams no larger than that request, which the
hop carried, and with ML-KEM the request is at least as large as the answer in
every exchange ranet3 runs. Elsewhere an answer passes its request by a few
octets at most.

[RFC 7296 section 2.11](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.11)
says an implementation "MUST respond to the address and port from which the
request was received", and section 2.1 has a retransmitted request draw the
answer again. A node answers a repeat of a request it has answered under 1 rule,
in a half-open SA, an established session and the wait after `IKE_AUTH` alike,
as [limits](limits.md#ike) gives it in full. From the origin, the peer's own
address and port, it answers at most 20 repeats of each exchange, every counted
send of a peer that resends as ranet3 does. A peer asked to probe its path many
times in 1 exchange can send more, since a probe that cuts nothing resends a
request uncounted, and its repeats past the 20 draw nothing. A repeat from any
other address and port is answered only once the whole request has come from
there, and only within the bytes on the wire that address sent repeating it in
the exchange, which spends nothing of the origin's 20. The exchange keeps that
credit for at most 4 addresses, the one heard from least recently giving way to
a newcomer. Without the rule, a fragment 1 of tens of octets, which an initiator
in a half-open SA holds the keys for and anyone who captured one can replay past
`IKE_AUTH`, would aim an answer of up to 1820 octets in 4 datagrams at any
address. It leaves 2 residues. An observer sending from more than 3 fresh
addresses between every 2 of a moved initiator's datagrams can hold it until its
exchange times out. A replay in the origin's own address and port spends the
origin's count: up to 20 answers an exchange to a replayed fragment 1, 38,960
bytes on the wire for an ML-KEM-1024 answer at the IPv4 floor. When the path MTU
falls before every answer the 20 come to up to 78,020 bytes over IPv4 and up to
83,500 over IPv6. Such an answer is kept in at most 4 datagrams at or above the
IPv4 floor and in at most 2 at or above the IPv6 floor, and each fall cuts it
into 2 more. Over IPv6 the answers take fewer datagrams, 4 to 42 against 6 to
44, but each carries an IP header of 40 bytes against 20.

Fragments from a peer that sent no `IKEV2_FRAGMENTATION_SUPPORTED` are dropped
before anything of them is held.
[Section 2.4](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.4) puts its
"MUST NOT be used unless both peers have indicated their support for it" on the
sender alone, which makes this a choice rather than a departure.

A strongSwan responder that has answered a request takes a retransmission of it
only when the first datagram is the one it answered, fragment 1 of the same cut
or the same message whole. It ignores a retransmission ranet3 cut again, and
where strongSwan's answers are lost before ranet3's step to the floor or a fall
of the path MTU, the exchange runs to its budget.
[Section 2.6.1](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.6.1) has a
retransmitted fragment 1 draw the answer again. After a fall of the path MTU
ranet3 cannot send the old cut again, since DF holds and the host refuses a
datagram larger than the path MTU it knows.

## Authentication

Authentication is an Ed25519 signature
([RFC 7427](https://www.rfc-editor.org/rfc/rfc7427.html),
[RFC 8420](https://www.rfc-editor.org/rfc/rfc8420.html)) checked against the key
[the trust document](../trust.md) holds for the peer. There is no certificate,
shared key or EAP.
[RFC 7296 section 4](https://www.rfc-editor.org/rfc/rfc7296.html#section-4)
requires that every implementation can be configured to accept PKIX certificates
signed by RSA keys and shared key authentication. A node supports neither.

The minimal profile of [RFC 7815](https://www.rfc-editor.org/rfc/rfc7815.html)
does not cover this. It describes an initiator only (section 1), and it carries
a raw public key in a CERT payload (Appendix B.2). A node also answers as a
responder and sends no CERT payload. Refusing additional Child SAs with
`NO_ADDITIONAL_SAS` is within RFC 7296.

A node answers handshakes as a responder only when `link.listen` is set. A full
mesh needs every node to answer as well as dial.

A node sends `INITIAL_CONTACT` in its first `IKE_AUTH` request or response to a
peer while it holds no other IKE SA to that peer's node on any path, live or
with its `IKE_AUTH` under way, as after a restart, so of the handshakes it runs
to a peer at once only 1 carries it. The peer reads it as
[closing SAs](#closing-sas) describes.
[RFC 7296 section 2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4)
says the notice "MUST NOT be sent by an entity that may be replicated", and a
node's name runs on 1 host at a time, since the name and
[its key](../trust.md#key-files) running on a second host at once would have one
host's restart delete the other's IKE SAs on that path. A strongSwan responder
takes the notice to destroy without a Delete every IKE SA it holds with the same
2 IDs in that address family, unless its `unique` is `never`, a session it
dialed across the notice's among them
([`check_uniqueness`](https://github.com/strongswan/strongswan/blob/6.1.0/src/libcharon/sa/ike_sa_manager.c)),
so where the rule keeps that session here, this node holds it alone for the 72
seconds its liveness check takes to fail, 10 of silence and 62 of
retransmissions as [limits](limits.md#ike) gives.

Identities are compared by the endpoint they name rather than by their bytes. A
node writes `O` and `CN` as `UTF8String`, while strongSwan picks the string type
from the value. The same name therefore reaches the wire in 2 encodings, and an
endpoint `auth.aliases` names by other IDs reaches it in more. AUTH signs the
bytes as received either way, so the ID only selects which key must verify it. A
responder asked in IDr for an ID other than a DN answers with the ID type and
data it was asked for, in its own encoding with RESERVED zero. Asked for a DN,
it answers with its own encoding of the DN.

## Errors outside an exchange

[RFC 7296 section 2.21.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.4)
says "If an error occurs outside the context of an IKE request (e.g., the node
is getting ESP messages on a nonexistent SPI), the node SHOULD initiate an
INFORMATIONAL exchange with a Notify payload describing the problem."
[Section 1.5](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.5) says
which IKE SA carries it: "if the receiving node has an active IKE SA to the IP
address from whence the packet came, it MAY send an INVALID_SPI notification of
the wayward packet over that IKE SA in an INFORMATIONAL exchange. The
Notification Data contains the SPI of the invalid packet." A node counts ESP on
an SPI it does not hold in `ranet3_receive_refused_total` and drops it. Where
the ESP came from the address and port a session sends to, that session sends
its peer an `INFORMATIONAL` request carrying `INVALID_SPI`, with the SPI as its
data, and records `ike.notify.invalid_spi`. The port has to match as well as the
address, since ranet3 always encapsulates ESP in UDP, as for the suspicious
message of the next paragraph, "from an IP address (and port, if NAT traversal
is used)".

Section 2.21.4 also says "A node needs to limit the rate at which it will send
messages in response to unprotected messages." The node looks for the session an
unknown SPI came from at most once every 10 seconds, whoever sent the ESP. A
stranger's ESP on an unknown SPI therefore takes the look for every session
until the next, and a session's peer is told up to 10 seconds later than it
could be. The 10 seconds are the liveness interval, so the node looks at most as
often as a session sends a liveness check. An SPI a session let go of, by a
Delete, by the peer's `CHILD_SA_NOT_FOUND` for its SA, by an exchange that
installed nothing with it, or by ending, draws no report from any session for 10
seconds after, since the peer sends on it until it has read the Delete or
learned the session ended. A session sends no report for an SPI this node holds
by the time the report would go, nor while a request of its own is outstanding
or while its IKE SA's rekey holds every other request, and the next look that
finds it after the request ends sends one. Section 1.5 also allows "an
informational message without cryptographic protection to the source IP address"
where no IKE SA to it exists. A node sends none, since that would let anyone
make it send to any address. A peer's `INVALID_SPI` changes no SA here: the
request is answered empty, and the session logs the SPI it names at debug level,
as section 2.21.4 has the recipient do: "The recipient MUST NOT change the state
of any SAs as a result".

The same section says "A node receiving a suspicious message from an IP address
(and port, if NAT traversal is used) with which it has an IKE SA SHOULD send an
IKE Notify payload in an IKE INFORMATIONAL exchange over that SA." For ESP on an
unknown SPI from a session's exact address and port, that is the `INVALID_SPI`
above, at most once for each session from each look, and at most 1 look every 10
seconds for the whole node. This node drops any other suspicious message, such
as an IKE message that fails its integrity check, and sends nothing over the SA.
A node that answers every stray datagram from a peer's address can be made to
send over that SA by anyone able to spoof the address, which the 10 seconds
bound for ESP. The section warns of the same for the liveness checks such a
message prompts: "An implementation SHOULD limit the frequency of such tests to
avoid being tricked into participating in a DoS attack."

## Algorithms

A node offers and accepts only these algorithms:

| Use            | Algorithms                                                                |
| -------------- | ------------------------------------------------------------------------- |
| IKE encryption | AES-GCM with a 16-octet tag, 256 or 128-bit keys, ChaCha20-Poly1305       |
| IKE PRF        | HMAC-SHA2-384, HMAC-SHA2-256                                              |
| Key exchange   | X25519, P-384, P-256, each alone or followed by ML-KEM-768 or ML-KEM-1024 |
| Authentication | Ed25519                                                                   |
| ESP encryption | AES-GCM with a 16-octet tag, 256 or 128-bit keys, ChaCha20-Poly1305       |
| ESP integrity  | none, since every cipher is AEAD                                          |

[`cap.crypto`](../configuration-reference.md#capcryptoike) narrows the
encryption, PRF and key exchange rows of the table and orders them, and a node
takes, of each kind, the first transform of its own list that an offer holds.
The answering end's `esp.cipher` order decides a Child SA's cipher, so with the
default lists a strongSwan initiator that proposes ChaCha20-Poly1305 first, as a
host without AES instructions does, gets AES-GCM with a 256-bit key.

[RFC 7296 section 3.3.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.3.4)
says "all implementations of IKEv2 SHOULD include a management facility that
allows specification (by a user or system administrator) of Diffie-Hellman
parameters (the generator, modulus, and exponent lengths and values) for new
Diffie-Hellman groups", and "Implementations SHOULD provide a management
interface through which these parameters and the associated Transform IDs may be
entered". A node has neither. Its groups are elliptic curves fixed in code,
which no generator or modulus describes, and `cap.crypto.ike.kex` chooses among
them.

[Section 3.3.5](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.3.5) says
that an implementation offered a cipher "with a larger key length" than it is
configured for "SHOULD accept the offer if it supports use of the longer key". A
node refuses a key length its lists leave out, so one whose `cipher` names
`aes128gcm` alone refuses an offer of `aes256gcm` alone. Each name stands for 1
key length, and section 3.3.4 says "The implementation MUST reject SA proposals
that are not authorized by these IKE suite controls."

[RFC 8247](https://www.rfc-editor.org/rfc/rfc8247.html) makes `ENCR_AES_CBC`
(section 2.1), `AUTH_HMAC_SHA2_256_128` (section 2.3), MODP group 14 (section
2.4), and RSA and shared key authentication (section 3.1) MUST for IKEv2, and
`PRF_HMAC_SHA1` (section 2.2) and `AUTH_HMAC_SHA1_96` (section 2.3) MUST-.
[RFC 8221](https://www.rfc-editor.org/rfc/rfc8221.html) makes `ENCR_AES_CBC` and
`ENCR_NULL` (section 5) and `AUTH_HMAC_SHA2_256_128` (section 6) MUST for ESP,
and `AUTH_HMAC_SHA1_96` (section 6) MUST-. Both define the level the same way:
"MUST- This term means the same as MUST." RFC 8247 also makes
`PRF_HMAC_SHA2_512` (section 2.2) SHOULD+. A node implements none of them. A
peer has to support at least 1 algorithm in each row of the table.

## Traffic selectors

Every Child SA carries exactly 2 traffic selectors on each side, the full IPv4
range and the full IPv6 range. A node proposes those, and as an initiator takes
an answer of those alone. As a responder it takes a TSi and a TSr that each hold
both ranges among their selectors, whatever else they hold, such as a first
selector of the packet that started the request, and answers each with the 2
ranges. A request whose TSi or TSr lacks either range is refused with
`TS_UNACCEPTABLE`, beside the responder's `AUTH` in `IKE_AUTH` and alone in
`CREATE_CHILD_SA`. A `CREATE_CHILD_SA` request whose TS payload does not parse
or holds no selector is malformed instead, and is answered `INVALID_SYNTAX` on
an IKE SA that is not busy, as [Closing SAs](#closing-sas) describes.
[RFC 7296 section 2.9](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.9)
has a responder narrow the selectors to a subset its policy accepts, and refuse
with `TS_UNACCEPTABLE` only selectors it accepts no part of. A node never
narrows below the 2 ranges, so it refuses narrower selectors where section 2.9
has it accept them or narrow to a part of them. Babel picks the peer for each
packet after the kernel routes it to the tun, so every session carries all
traffic of both families.

## ESP

[RFC 4303 section 2.6](https://www.rfc-editor.org/rfc/rfc4303.html#section-2.6)
says a transmitter must be capable of generating dummy packets, with next header
59. A node generates none, and discards those it receives. It also sends no
traffic flow confidentiality padding
([section 2.7](https://www.rfc-editor.org/rfc/rfc4303.html#section-2.7)), which
the SA management protocol would have to negotiate. Both are a known gap rather
than a decision.

[RFC 4303 section 3.3.3](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.3.3)
asks that an attempt to send past the last sequence number be logged with the
SPI, the date and time, the source and destination addresses and, for IPv6, the
Flow ID, and [section 4](https://www.rfc-editor.org/rfc/rfc4303.html#section-4)
adds the sequence number. A node logs `ike Child SA ran out of sequence numbers`
once for each such SA, with both SPIs, both identities, the peer's address and
the sequence number, and the log line carries its own time. Its `src` names only
the local port. The socket is bound to the wildcard address. A session this node
dialed sends from the address the kernel picks for each datagram, which the
session never learns. A session the peer opened sends from the address its
request reached, and the log does not name that one either. No Flow ID is
logged. A node sets no flow label, so the label on each outer IPv6 header is the
kernel's.

[RFC 4303 section 3.4.2](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.4.2)
says that where "no valid Security Association exists for this packet, the
receiver MUST discard the packet", and that the entry it logs for the event
"SHOULD include the SPI value, date/time received, Source Address, Destination
Address, Sequence Number, and (in IPv6) the cleartext Flow ID."
[Section 4](https://www.rfc-editor.org/rfc/rfc4303.html#section-4) says the
same, and so does step 3a of
[RFC 4301 section 5.2](https://www.rfc-editor.org/rfc/rfc4301.html#section-5.2)
for traffic that matches no SA. A node discards such ESP. ESP on an SPI no
session holds is counted in `ranet3_receive_refused_total`, and a session
records an `ike.notify.invalid_spi`, with the SPI, the time and the session's
peer, only for the datagram it reports to its peer, as
[Errors outside an exchange](#errors-outside-an-exchange) describes. ESP on an
SPI a session holds with no SA installed for it, such as the responder's early
ESP on a Child SA rekey this node started, is counted in
`ranet3_esp_inbound_dropped_total`, and the `esp inbound packets dropped`
warning, at most once every 10 seconds for the whole node, can name it as
`no matching inbound ESP SA`. Neither draws a log line for each datagram. Anyone
able to reach the port can send ESP on an unknown SPI, and a log line for each
would let a flood fill the log.

Section 4 also says an implementation "MUST allow a system administrator to
enable or disable auditing for ESP". There is no such switch. Both counters and
`ike.notify.invalid_spi` are always on. The debug line a session logs for a
peer's `INVALID_SPI` follows `--log-level`, and so does the
`esp inbound packets dropped` warning, which `--log-level error` leaves out. The
record holds at most 1 report for each session from each look, and at most 1
look every 10 seconds for the whole node, so a switch would be a setting no
deployment needs.

## UDP checksums

[RFC 3948 section 2.1](https://www.rfc-editor.org/rfc/rfc3948.html#section-2.1)
says "the IPv4 UDP Checksum SHOULD be transmitted as a zero value". Every IPv4
datagram the transport sends carries a computed one, from the shared socket and
from the
[sockets connected to 1 peer](../platforms.md#sockets-connected-to-1-peer)
alike. On Linux a socket with `SO_NO_CHECK` gets `EINVAL` for every
`UDP_SEGMENT` send, so zero checksums would cost every IPv4 batch its segments.
macOS keeps the same checksum, for 1 behavior on both platforms. The same
section says "receivers MUST NOT depend on the UDP checksum being a zero value",
so nothing on the wire depends on a zero one.

## ECN

[RFC 7296 section 2.24](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.24)
says tunnel mode SAs "MUST support the ECN full-functionality option for
tunnels" and "MUST implement the tunnel encapsulation and decapsulation
processing" of RFC 4301, which
[RFC 6040 section 5.1](https://www.rfc-editor.org/rfc/rfc6040.html#section-5.1)
updates.

On Linux and macOS ranet3 reads the ECN field of each ESP datagram's outer IP
header, in both families, and before it delivers the inner packet sets that
packet's ECN field to the cell of
[RFC 6040 section 4.2](https://www.rfc-editor.org/rfc/rfc6040.html#section-4.2)'s
Figure 4 for the two, updating an IPv4 header's checksum with it. An inner
Not-ECT packet whose datagram arrived CE is dropped and counted in
`ranet3_esp_inbound_dropped_total`, and an inner ECT packet the outer mark set
to CE is counted in `ranet3_esp_inbound_ce_total`. The ESP line of
`ranet3 status` shows the drops, and the packets marked CE once there are any. A
packet whose two fields are a combination the figure marks currently unused, the
dropped one included, is counted in `ranet3_esp_inbound_ecn_unused_total`, which
the ESP line also shows once there are any. Each session records such packets at
most once every 10 seconds as an `esp.ecn.unused` event, with how many arrived
since its last record and the IP header of the first of them, and writes the
same record as a log line at the debug level. The section asks such a
combination logged with alarms rate-limited, and says "It MUST be possible to
suppress alarms or logging": `--log-level` at its default of `info` or above
leaves the line out, the event is held in the daemon's record that
[`ranet3 debug events`](../development/debug.md#events) reads and is pushed to
no log, and ranet3 raises no alarm. The dropped combination is also logged by
the warning line of dropped ESP packets, which names the last drop's reason at
most once every 10 seconds for the node, and `--log-level error` leaves that
line out.

On FreeBSD and OpenBSD the bind reads no control data, so the outer field is not
read and every packet is decapsulated as though its datagram arrived Not-ECT. A
CE mark a hop on the underlay set is lost there. Neither platform is supported
beyond building.

The outer header of every ESP datagram ranet3 sends is Not-ECT, which is RFC
6040's compatibility mode, the encapsulation of RFC 3168's limited functionality
mode, where
[RFC 6040 section 4.1](https://www.rfc-editor.org/rfc/rfc6040.html#section-4.1)
asks the normal mode, which copies the inner field to the outer header, and
[section 4.3](https://www.rfc-editor.org/rfc/rfc6040.html#section-4.3) says an
ingress "MUST at least implement normal mode" and "MUST NOT permanently disable
ECN processing across the tunnel". A Not-ECT outer header hides no congestion
signal, as
[RFC 3168 section 5](https://www.rfc-editor.org/rfc/rfc3168.html#section-5) has
it, so what the inner flow loses is ECN's lower latency rather than any signal.

A headend's outer header and an `End.DT46`'s decapsulation take the ECN field as
[steering](../segment-routing.md#steering) says. The record of the combinations
an `End.DT46` meets that the figure marks currently unused is suppressed as
ESP's is above: its line is written at the debug level, and its
`netstack.ecn.unused` event is pushed to no log.

## ICMP answers

[RFC 4443 section 2.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.2)
has a node answer a packet addressed elsewhere from a unicast address of its
own, and
[RFC 1812 section 4.3.2.4](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.4)
has a router answer from an address of the interface the answer leaves by, and
[section 4.2.2.11](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.2.2.11)
has it originate every datagram from an address of its own.
[Path MTU](../path-mtu.md#where-answers-come-from) says where each answer to a
packet larger than its session carries comes from. A tun read's answer departs
from them, coming from the packet's destination in both families. So does
`End`'s answer to this host or a network behind it, in both families, and its
IPv4 answer where the node holds no IPv4 router-id.
[Transit answers](#transit-answers) says where the forwarding decision's answers
depart.

A tun read's answer comes from the packet's destination because, where the host
routes that destination into the tun, that is the one source every check of the
sending host takes. The host's checks can refuse an arriving packet from one of
its own addresses. Over IPv4 the kernel drops it unless `accept_local` is set,
whatever `rp_filter` holds (`fib_validate_source`,
net/ipv4/fib_frontend.c:402-409 and 456-471 at Linux `940de590`). A reverse path
check on nftables' `fib` finds no interface for such a source in either family
(net/ipv6/netfilter/nft_fib_ipv6.c:244 and
net/ipv4/netfilter/nft_fib_ipv4.c:139-140), and xt_rpfilter refuses it unless
`--accept-local` is given (net/ipv6/netfilter/ip6t_rpfilter.c:70-71 and
net/ipv4/netfilter/ipt_rpfilter.c:42).

A node can also hold an address the host does not: its `End` SID, which
[segment routing](../segment-routing.md) keeps off the tun, or a router-id from
a host route it announces and the host routes elsewhere. A strict reverse path
check drops an answer from an address the host routes out of another link, since
it takes a source only where the route back to it leaves by the link the answer
arrived on (net/ipv6/netfilter/nft_fib_ipv6.c:244-252). The NixOS firewall
writes such a check, `fib saddr . mark . iif oif exists accept` under a policy
of drop, and its loose form, `fib saddr . mark oif exists accept`, takes an
address the host routes elsewhere. The `internal/netstack` root tests run both
chains, and under each the sender learns the path MTU from an answer from the
destination, in both families. With the IPv6 answer written from the tun's own
address instead, that test fails under both chains, since the sender never
learns the path MTU.

An IPv4 answer does not come from 192.0.0.8 either, the dummy address
[RFC 7600 section 4.8](https://www.rfc-editor.org/rfc/rfc7600.html#section-4.8)
has a translator answer from. `rp_filter` 1 drops an answer from it unless the
host routes 192.0.0.8 into the tun, and so does NixOS's strict chain.
`rp_filter` 2 takes it where the host's route to 192.0.0.8 is a unicast route, a
default route among them, and drops it where the host has none or where that
route refuses, such as a hold or an unreachable default
(net/ipv4/fib_frontend.c:400-406 and 425-438). Every setting takes an answer
from the destination where the host routes that destination into the tun. A
socket bound to the tun can send a packet past the kernel's hold into the tun,
as rows B3 and B4 of
[where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) give, and
there `rp_filter` 1 or 2 drops an IPv4 answer from the held destination wherever
the route back to it is the hold. `End`'s IPv4 answer with no IPv4 router-id
comes from the destination for the same reason, since the node of the carried
packet's source writes it into its own tun, and an IPv6 SID cannot be the source
of an ICMPv4 answer.

The sender's stack matches an ICMP error to its connection by the packet the
error quotes, whatever address the error comes from. Linux takes the smaller
path MTU to the destination from such an answer. The `internal/netstack` root
tests check this for both families, with and without a router-id, at the node
that read the packet and behind a waypoint.

A SID admits a packet only where its outer source lies inside `overlay`, and an
egress segment only where that source lies inside an entry of its allow list
inside the overlay as well. It drops any other packet with no answer before it
reads an extension header, as [Drops with no answer](#drops-with-no-answer)
lists, so each answer of a SID this section names is to a packet it admits, sent
through a session, or into the tun as below, and within the limits this section
gives below.

`End` answers a segment too large for its next session about the packet the
segment carries, to that packet's source, rather than about the segment it could
not forward, to the headend.
[RFC 4443 section 2.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
says an error "MUST include as much of the IPv6 offending (invoking) packet (the
packet that caused the error) as possible", section 3.2 sends a Packet Too Big
to the address "Copied from the Source Address field of the invoking packet",
and
[RFC 8754 section 5.4](https://www.rfc-editor.org/rfc/rfc8754.html#section-5.4)
says "For IP packets encapsulated in an outer IPv6 header, ICMP error handling
is as defined in [RFC2473]." The carried packet's source is the host whose path
MTU must shrink, and a ranet3 headend turns no Packet Too Big about its
encapsulation into one for the sender. The carried packet was going to an
address that is not this node's, so
[RFC 4443 section 2.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.2)
(b) governs the answer's source.

RFC 8754 section 5.4 also says "ICMP error packets generated within the SR
domain are sent to source nodes within the SR domain." The carried packet's
source can lie outside the mesh, behind the headend, and `End`'s answer about
that packet goes to it all the same.

The headend's half of RFC 2473's handling is a known gap. A ranet3 headend
writes an ICMPv6 error about its own encapsulation into its tun, and the sender
of the packet it carried never learns of it. So a waypoint that answers the
outer source, the headend, as RFC 2473 has a tunnel's node do, breaks path MTU
discovery through it. A Linux `seg6local` waypoint is one: its `End` forwards
the packet as the kernel forwards any IPv6 packet, and answers one too large for
the next link with a Packet Too Big to the outer source
(net/ipv6/seg6_local.c:405-416 and net/ipv6/ip6_output.c:669-672 at Linux
`940de590`). Under [`cap.exit.via`](../routing.md#mode-3-on-linux) the headend
encapsulates every packet of the host that only a default would carry, so the
gap covers all of them, as
[limits](limits.md#routes-that-carry-the-hosts-own-traffic) declare.

[RFC 8986 section 4.8](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.8)
says "The End.DT46 SID MUST be the last segment in an SR Policy". A headend
cannot check it, since it keeps no list of other nodes' SIDs and so cannot know
another node's behaviors, and the operator writes the egress segment last. The
exit holds its half: an `End.DT46` reached with segments left refuses the
packet, and so does an `End` last reached with none left, each with the
Parameter Problem below.

The Time Exceeded, Parameter Problem and Destination Unreachable a refused
segment gets quote the segment as it reached the refusal, go to its outer
source, the headend, as RFC 2473 has a tunnel's node answer, and come from the
segment's destination. That address is one of this node's SIDs, which is within
the RFC. An IPv4 answer quotes as much of the packet as fits 576 bytes
([RFC 1812 section 4.3.2.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.3)),
and an IPv6 answer as much as fits 1280 bytes
([RFC 4443 section 2.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)).

What an `End` and an `End.DT46` walk, deliver and answer is
[segment routing](../segment-routing.md#local-segments)'s. The departures below
remain.

Either SID drops a fragment of a larger packet with no answer.
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
says "At the destination, fragment packets are reassembled into their original,
unfragmented form", and
[section 5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5) says "A node
must be able to accept a fragmented packet that, after reassembly, is as large
as 1500 octets." The SID is the packet's destination, and a fragment of a larger
packet needs reassembly the SID does not do.

Either SID steps past at most 8 extension headers, and refuses a packet with a
ninth it would step past, with a Parameter Problem, code 8, pointing at that
header, as
[RFC 8883 section 2.5](https://www.rfc-editor.org/rfc/rfc8883.html#section-2.5)
answers a chain past a limit on the number of its headers.
[RFC 8200 section 4.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.1)
says "IPv6 nodes must accept and attempt to process extension headers in any
order and occurring any number of times in the same packet, except for the
Hop-by-Hop Options header, which is restricted to appear immediately after an
IPv6 header only." The bound on the walk is the node's own, so a sender cannot
choose how much of the node's time one packet costs. Linux bounds the same walk
at 12 extension headers, and its `End` drops a packet past them with no answer
(`IP6_MAX_EXT_HDRS_CNT`, include/net/ipv6.h:94, read at
net/ipv6/exthdrs_core.c:223-224, `seg6_get_srh`, net/ipv6/seg6.c:84-85, and
`input_action_end_core`, net/ipv6/seg6_local.c:410-412 and 418-420 at Linux
`940de590`).

A packet so refused is answered or dropped as
[local segments](../segment-routing.md#local-segments) gives. RFC 8883 section
2.5 says a code 8 Parameter Problem "SHOULD be sent when a node discards a
packet with an extension header chain that exceeds a limit on the number of
extension headers in the chain", and
[RFC 4443 section 2.4 (e.1)](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
lets no ICMPv6 error answer another, which such a packet may be.

An `End` refuses a segment routing header holding more than 16 segments with
segments left, past its check of the hop limit, with a Parameter Problem, code
6, pointing at its first octet, as
[RFC 8883 section 2.3](https://www.rfc-editor.org/rfc/rfc8883.html#section-2.3)
answers an extension header past a processing limit. RFC 8986 section 4.1
forwards such a packet (S12 to S15), and RFC 8754 section 4.3.1.1 ends "Resubmit
the packet to the IPv6 module for transmission to the new destination" (S22). A
waypoint carries every segment of a list on, 16 bytes in front of every packet,
so the cap keeps the length of the list it carries one the node chose rather
than the sender. Linux's `End` caps no list (`seg6_validate_srh`,
net/ipv6/seg6.c:26-77 at Linux `940de590`).

An `End` drops with no answer a packet whose next segment is no SID of this node
and lies inside a prefix this node originates that counts as no default, or at
an address `cap.table` assigns it with segments left 0. RFC 8986 section 4.1
submits it to the FIB lookup for its new destination (S15), and a prefix this
node originates is one the forwarding decision carries into the tun. An address
`cap.table` assigns this node is a local interface that is no SID, since the
loader refuses a SID there, and
[RFC 8754 section 4.3.2](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.3.2)
says, where the FIB entry "represents a local interface and is not locally
instantiated as an SRv6 SID", "If Segments Left is zero, the node must ignore
the routing header and proceed to process the next header in the packet, whose
type is identified by the Next Header field in the routing header." Linux's
`End`, outside a VRF, drops one at an address of its own host with no answer,
whatever its Segments Left (`input_action_end_finish`,
net/ipv6/seg6_local.c:400-402, and a local route's loopback device outside a
VRF, net/ipv6/route.c:1063-1073 at Linux `940de590`). No reason holds.

An `End` and an `End.DT46` read no option of the hop-by-hop and destination
options headers they walk past, only each header's Next Header and Hdr Ext Len.
So an `End` forwards, and an `End.DT46` decapsulates, whichever the SID delivers
to, a packet whose header there holds an option of a type the node does not
recognize, whatever its action, where the packet passes their other checks
above, and an `End` at hop limit 1 answers it with the Time Exceeded above.
[RFC 8200 section 4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4) says
"extension headers must be processed strictly in the order they appear in the
packet", and
[section 4.2](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.2) says the
Option Type's "highest-order 2 bits specify the action that must be taken if the
processing IPv6 node does not recognize the Option Type": 01 to "discard the
packet", and 10 to "discard the packet and, regardless of whether or not the
packet's Destination Address was a multicast address, send an ICMP Parameter
Problem, Code 2, message to the packet's Source Address, pointing to the
unrecognized Option Type", with 11 doing so "only if the packet's Destination
Address was not a multicast address". Linux reads a hop-by-hop header in the
first place on input, before the route lookup that hands the packet to
`seg6local`, and acts on an option it does not recognize as the option's type
says (`ip6_rcv_core`, net/ipv6/ip6_input.c:320-326, `ipv6_parse_hopopts`,
net/ipv6/exthdrs.c:1054-1087, `ip6_parse_tlv`, :190-194, and
`ip6_tlvopt_unknown`, :79-97 at Linux `940de590`). It processes no destination
options header on that path, and its `End` and `End.DT46` walk past such a
header by its length alone (`ipv6_find_hdr`, net/ipv6/exthdrs_core.c:278). No
reason holds.

Sending a segment on as above, an `End` cuts an IPv4 packet without DF that the
segment carries into fragments where the segment is larger than the session to
its next segment, as
[segment routing](../segment-routing.md#waypoints-and-packet-size) says. It
drops with no answer such a packet whose header fails RFC 1812 section 5.2.2's
checks, whose data runs past 65535 octets or for which the session leaves no
room for 8 octets of data behind its header.
[RFC 8200 section 4.4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.4)
says "If, after processing a Routing header of a received packet, an
intermediate node determines that the packet is to be forwarded onto a link
whose link MTU is less than the size of the packet, the node must discard the
packet and send an ICMP Packet Too Big message to the packet's Source Address",
and
[RFC 4443 section 3.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.2)
says "A Packet Too Big MUST be sent by a router in response to a packet that it
cannot forward because the packet is larger than the MTU of the outgoing link."
A router cuts such an IPv4 packet into fragments rather than answer it:
[RFC 1812 section 4.2.2.7](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.2.2.7)
says "Fragmentation, as described in [INTERNET:1], MUST be supported by a
router." That covers the cut. For a header failing RFC 1812 section 5.2.2's
checks, that section says "If the packet fails any of the following tests, it
MUST be silently discarded", which covers the silence too. No reason holds for
the rest of the silence.

Every answer of a SID goes back through the session the mesh routes the answered
source to, while that session is open and has room for it: the Time Exceeded,
Parameter Problem and Destination Unreachable a refused segment gets, and the
answer to a segment larger than its next session. The one exception is that
answer where the reply's lookup reaches the answered source by an entry of this
node's own that counts as no default. It goes into the tun within the limits it
draws on, as the forwarding decision answers this host or a network behind it,
as [Transit answers](#transit-answers) says, and it comes from the destination
of the packet it answers, in either family and whatever router-id the node
holds, for the reasons a tun read's answer does above. The answer about the
packet a segment carries comes from that packet's destination, and the one about
a segment that carries no packet from the segment's destination as `End` rewrote
it, its next segment. So a SID sends the Time Exceeded, Parameter Problem and
Destination Unreachable a refused segment gets to no source an entry of this
node's own reaches. Such a source is this node's own, as where a segment list it
steered comes back to it, or an overlay source a peer forged. RFC 4443 sends
each answer to the packet's source: the Packet Too Big of section 3.2, quoted
above, the Destination Unreachable of section 3.1, the Parameter Problem of
section 3.4, and the Time Exceeded of
[section 3.3](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3), where a
router that takes a hop limit to zero "MUST discard the packet and originate an
ICMPv6 Time Exceeded message with Code 0 to the source of the packet". The Time
Exceeded, Parameter Problem and Destination Unreachable come from the SID the
segment reached, which the host never routes into the tun, as above. Written
into the tun, such an answer would meet a host's strict reverse path check, such
as the NixOS firewall's, which drops it. For a source only this node's own
default reaches, the decision's reason holds for every answer of a SID: the mesh
routes no reply to it, and the host would send the answer out of its uplink.

No ICMPv4 answer carries a source route.
[RFC 1812 section 4.3.2.6](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.6)
says an error to a packet with one "SHOULD also contain a source route option of
the same type (strict or loose), created by reversing the portion before the
pointer", "unless the router is aware of policy that would prevent the delivery
of the ICMP error message". That exception covers every ICMPv4 answer ranet3
sends. Each reaches a host through a tun, this node's or that of the node the
mesh routes the answer to, and both hosts ranet3 runs on drop a packet with a
source route there by default. A Linux host drops one arriving on an interface
unless `accept_source_route` is set both there and under `all`, where it starts
at 0 (`ip_rcv_options`, net/ipv4/ip_input.c:295-306, net/ipv4/devinet.c:71-81
and include/linux/inetdevice.h:85-87 and 105-106 at Linux `940de590`). A macOS
host reads the options of every packet it receives, and drops one whose source
route ends at it unless `net.inet.ip.accept_sourceroute` is set, and one whose
route goes on unless `net.inet.ip.sourceroute` is set, both 0 by default
(`ip_dooptions`, bsd/netinet/ip_input.c:204-212, 1255, 2458-2528 and 2686-2689
at XNU `f6217f89`). An answer with no source route goes back by the mesh's
routes, as every other answer does. A sender that accepts source routes by those
settings and that only its source route reaches gets no answer.

[RFC 4443 section 3.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.2)
says:

> A Packet Too Big MUST be sent by a router in response to a packet that it
> cannot forward because the packet is larger than the MTU of the outgoing link.

It goes on: "Unlike other messages, it is sent in response to a packet received
with an IPv6 multicast destination address, or with a link-layer multicast or
link-layer broadcast address." The mesh routes no multicast: no kernel route it
installs names a group, since a group is delivered on a link rather than through
a tunnel. A read off the tun to a group is dropped before its route is looked up
or the packet steered, and the forwarding decision drops one a session delivers,
as [routing](../routing.md#transit) says. So the one packet to a group that can
meet a session too small for it is one a segment carries, which a ranet3 headend
never steers. `End` drops such a segment with no Packet Too Big, since no ICMPv6
error ranet3 builds answers a packet to a group.

An ICMPv6 error behind 9 extension headers or more is answered, but for the code
8 refusal above.
[RFC 4443 section 2.4 (e)](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
says "An ICMPv6 error message MUST NOT be originated as a result of receiving
the following", and the first of them, (e.1), is "An ICMPv6 error message". To
find a packet's ICMPv6 header, ranet3 steps over its extension headers as the
Linux kernel does, past at most 8 of them as a SID's walk does, and reads the
header behind them. A packet whose chain runs longer is answered as one that is
not an error. Refusing it would withhold the Time Exceeded and Packet Too Big
that sections 3.2 and 3.3 require from a packet nothing shows to be an error.
The kernel reads 13 headers, so it refuses an error behind 9 to 12 extension
headers that ranet3 answers. An error ranet3 builds carries its ICMPv6 header
right after the IPv6 header, so two ranet3 nodes never answer each other's
errors this way. The case needs a sender that puts its error behind 9 headers,
and the answers to it draw on the rate limits below like any other.

The rate limits on these answers are fixed in code.
[RFC 4443 section 2.4 (f)](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
says:

> The rate-limiting parameters SHOULD be configurable. In the case of a
> token-bucket implementation, the best defaults depend on where the
> implementation is expected to be deployed (e.g., a high-end router vs. an
> embedded host).

[RFC 1812 section 4.3.2.8](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.8)
says "The rate limit parameters SHOULD be settable as part of the configuration
of the router". A node takes the limits of the Linux kernel, which sent these
answers before ranet3 did: a bucket for each source of a packet answered and a
cap for the node, as [path MTU](../path-mtu.md#packets-that-do-not-fit) gives
them. Their intervals, burst and cap are the kernel's defaults, and the number
of sources a node keeps buckets for is ranet3's own. The defaults the RFC ties
to a deployment are a single bucket's. With a bucket per source, a node's budget
grows with the senders it answers, so a hub answering many gets more than a
leaf, and a sender's flood of expired or refused packets spends only its own
bucket. The cap bounds what a flood from many sources costs the smallest node.
No deployment has needed other values, and a setting comes with the first that
does.

Packet Too Big and fragmentation needed draw on neither limit, as the Linux
kernel leaves both out of its own (`icmpv4_mask_allow`, net/ipv4/icmp.c:277-291,
and `icmpv6_mask_allow`, net/ipv6/icmp.c:166-176, under the ratemask
net/ipv6/af_inet6.c:938-939 sets, at Linux `940de590`). That departs from the
same section, which says a node "MUST limit the rate of ICMPv6 error messages it
originates", and from RFC 1812 section 4.3.2.8, which says a router "SHOULD also
be able to limit the rate at which it sends other sorts of ICMP error messages
(Destination Unreachable, Redirect, Time Exceeded, Parameter Problem)".

### Transit answers

The [forwarding decision](../routing.md#transit) answers a session's packet it
does not forward from the router-id of the packet's family. A session is an
unnumbered link, which
[RFC 1812 section 4.3.2.4](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.4)
covers: "If the interface has no IP addresses associated with it, the router's
router-id (see Section [5.2.5]) is used instead". With no IPv4 router-id, Time
Exceeded, Destination Unreachable and Parameter Problem come from 192.0.0.8, the
address
[RFC 7600 section 4.8](https://www.rfc-editor.org/rfc/rfc7600.html#section-4.8)
names no host by. Record Route and Timestamp insert the same address, where
[RFC 1812 section 4.2.2.2](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.2.2.2)
asks for "its router-id", since a node with no IPv4 address has none to give.
With no IPv6 router-id they come from the node's first `End` SID that an
announced prefix covers, an address of the node the mesh routes to it, and with
no SID they are not sent and are counted unanswered.
[RFC 4443 section 3.3](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3)
says a router "MUST discard the packet and originate an ICMPv6 Time Exceeded
message", and nothing of such a node could be that message's source: IPv6 has no
dummy address, and an underlay address may not route back and would show where
the node is. A Packet Too Big with no IPv6 router-id comes from the node's first
`End` SID too, and with no IPv6 router-id and no SID from the packet's
destination. A Fragmentation Needed with no IPv4 router-id comes from the
packet's destination as well. Path MTU discovery needs the answer more than its
source.

An answer to a packet whose source the table answers as this node's own, through
an entry that does not count as a default, goes into the tun and comes from the
answered packet's destination. That holds whichever session delivered the
packet, a segment's inner packet among them. Such a source is this host or a
network behind it, and only they can receive the answer. A packet from this host
is answered so for the reasons a tun read's answer is above, and a router-id is
often an address of the host itself, which the host drops as a source. A packet
the host did not send, one a peer forged or a segment sent back with a source of
this host's, is answered the same way. The answer goes to the address the packet
names, which no one but this host or the network behind it holds. Linux,
forwarding such an IPv4 packet itself, drops it as a martian under
`fib_validate_source`, as above, and sends nothing.

A source that only an entry counting as a default reaches, an internet host
behind an exit's default for one, is no network behind this host. Its packet
gets no ICMP error of any kind, a Packet Too Big, a Fragmentation Needed and a
Parameter Problem among them, and the drop is counted under its reason alone, as
a drop whose answer finds no route back is. Answering would let any peer make
this node send errors carrying bytes the peer chose to any host past its uplink,
and the mesh routes no reply to such a source, so the host would send the answer
out of its uplink from another node's address. A traceroute from such a source,
from the internet toward an address behind an exit, so gets no answer from the
hop at this node. The one exception is the Destination Unreachable with code 2
that answers an IPv6 packet from a link-local source to a wider unicast
destination a router forwards, RFC 4443 section 3.1. It goes back on the session
the packet came by, never by a reply route, so it reaches the source's own link
and no stranger.

A session's packet to an address the host holds that no route of this node
covers, an underlay address for one, is decided as one to any address this node
holds no route of its own for. With no route at all it is answered no route, and
where it is answered, the answer comes from the router-id.
[RFC 4443 section 2.2](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.2)
(a) says "If the message is a response to a message sent to one of the node's
unicast addresses, the Source Address of the reply MUST be that same address".
The decision reads no host address list, only the routes this node holds, so it
cannot tell such an address from any other it has no route for.

A truncated IPv4 packet, one whose total length runs past what the session
delivered, is dropped and counted with no answer.
[RFC 1812 section 5.2.2](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.2)
says the router "SHOULD respond with an ICMP Parameter Problem message whose
pointer points at the IP total length field". Linux's `ip_rcv_core` drops it the
same way. The log line the section also asks for is written at most once every
30 seconds, with the count kept exact. The section's checks themselves hold on
every path: "Before a router can process any IP packet, it MUST perform a the
following basic validity checks". The decision runs them on each transit IPv4
header before it is answered, forwarded or cut into fragments, and the cut
copies only options the decision has already read.

An IPv6 packet a session delivers whose Payload Length runs past the octets the
session delivered, or is 0 with octets after its header, is dropped and counted
with no answer before any SID or the forwarding decision reads it. The decision
answers such an inner packet that an `End.DT46` hands it with a Parameter
Problem, code 0, pointing at the Payload Length, and counts it invalid.
[RFC 8200 section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3)
defines Payload Length as the "Length of the IPv6 payload, i.e., the rest of the
packet following this IPv6 header, in octets", and RFC 4443 section 3.4 answers
a header field that keeps a packet from being processed with a Parameter
Problem, as [ICMP answers](#icmp-answers) quotes. A Payload Length of 0 belongs
to a jumbogram, which no session carries, so the node refuses such a packet
rather than cut it to its header, where Linux's `ip6_rcv_core` cuts it to its
header unless a hop-by-hop header follows (net/ipv6/ip6_input.c:308-317 at Linux
`940de590`). That covers the drop at 0, and not the silence toward a session's
packet. Linux drops a packet whose Payload Length runs past its octets with no
answer too (:309-314). The session drops such a packet before the mesh reads it,
and the mesh's one entry for a session's packets hands a packet addressed to a
SID of this node to that SID before it answers any, so answering the session's
packet needs an entry of the mesh that answers one packet alone. An egress
segment hands such an inner packet that passes the checks of
[egress segments](../segment-routing.md#egress-segments) to the exit as it came.
On Linux the exit writes it into the tun, and the host's `ip6_rcv_core` then
drops one whose Payload Length runs past its octets and cuts one of length 0 to
its header, as above. On macOS the userspace exit drops and counts as
`malformed`, before its stack reads it, an IPv6 packet whose Payload Length does
not count exactly the octets after its header, one of length 0 with octets after
its header among them.

A transit IPv4 packet carrying a loose or strict source route is dropped and
counted.
[RFC 1812 section 5.3.13.4](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.13.4)
asks a router to support source routing with any discarding option off by
default, and its DISCUSSION gives the reason to discard: "source routing may be
used to bypass administrative and security controls within a network". The
mesh's separation is routing, and Linux discards source routes by default too.
The drop goes unanswered, where
[RFC 1812 section 5.2.2](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.2)
says a router "SHOULD respond with an ICMP Parameter Problem" to a strict source
route for another node. Linux drops either kind with no answer while
`accept_source_route` is off (`ip_rcv_options`, net/ipv4/ip_input.c:295-304 at
Linux `940de590`).

[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)
also says "For security reasons, it is recommended that implementations SHOULD
allow sending of ICMP destination unreachable messages to be disabled,
preferably on a per-interface basis". The forwarding decision's cannot be turned
off. Each answers a packet one of the node's sessions delivered, so its sender
is a peer that authenticated, and each goes only to that packet's source: the
code 2 answer back on the session the packet came by, as above, and any other
where the node's table routes it. It goes into the tun where the source is this
host or a network behind it, a source an entry of this node's own reaches that
does not count as a default. Those are the only receivers a tun-bound answer
has. Otherwise it goes through the peer the table routes the source to, so only
to an address some node announces a route for, another exit's default among
them. A source the table routes nowhere gets no answer, nor does one that only
this node's own default reaches, and neither does an exit's packet that
[Drops with no answer](#drops-with-no-answer) lists. The packets whose answer
would show the mesh to a sender outside it never reach the decision: the
antispoof filter and the SIDs drop them first, with no answer, as
[Drops with no answer](#drops-with-no-answer) lists.

The answer to a read off the tun with no route or inside a hold cannot be turned
off either. The host itself routed the packet into the tun, and the answer goes
only back into the tun, to the host that sent the packet, which delivers it or
forwards it toward its source, and never onto a session.

Every transit answer draws on the bucket of the answered packet's source and on
the node's cap, a Packet Too Big or Fragmentation Needed on neither, as
[path MTU](../path-mtu.md#packets-that-do-not-fit) gives them, and so does the
answer to a tun read. It draws once, where Linux draws twice for a packet with
no route, as that page says too.

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

| RFC 8966 section                | The RFC says                                                                                                          | ranet3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.5.3, and RFC 9079 section 5.1 | Create a route table entry for each finite update, and take an expired or retracted one to infinity before a flush    | Keeps it outside the route table as its neighbor's offer while its destination and source are a prefix this node announces or an address `cap.table` assigns, and drops the offer with no hold at its expiry or a retraction, and drops it when its destination is a host address of this node's from another source                                                                                                                                                                                                                                                                                                                        |
| 3.5.3                           | Create a route table entry for each finite update a neighbor sends                                                    | Drops it when the router-id it takes is all zeroes or all ones, and leaves a route already learned from that neighbor as it was until it expires                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 3.5.3                           | Create a route table entry for each finite update a neighbor sends                                                    | Takes one under this node's own router-id as a retraction of the route or offer that neighbor last sent, which keeps its origin                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 3.5.4                           | End the hold of a retracted prefix once every neighbor acknowledges a retraction sent with an acknowledgment request  | Keeps it until the route's expiry timer runs out and, once the prefix has lost its last route, until the latest time any update this node sent naming it reachable expires at a neighbor, if that is later                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 3.5.4                           | Forward no packet inside a held prefix by following a route for a shorter prefix                                      | Drops and answers each packet the tun hands it inside a hold, but one a steering policy takes or the checks at the mesh's edge drop, and each a peer sends, but the kernel keeps no hold that counts as a default, and a packet the host sends or forwards inside one takes the host's routes, while a packet inside any other hold ends where [where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux) and [on macOS](../routing.md#where-a-lookup-ends-on-macos) give, refused at a hold at rows L4, L9, D3 and D7, at 5410 where main's best default is a refusal at row L7, and for want of a route at rows B2 and B4 |
| 3.7.2                           | Make a reasonable attempt to reach every neighbor with a triggered update or retraction                               | Sends it once, with no acknowledgment and no repeat                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| 3.8.1.1                         | Send an update for a requested prefix that has a selected route                                                       | Sends a retraction when the selected route's next hop is the requester                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 3.8.1.2                         | Send an update for a seqno request the selected route satisfies                                                       | Forwards the request instead when the selected route's next hop is the requester                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 3.8.1.2                         | Forward a seqno request only while advertising the prefix                                                             | Forwards it whenever it has a route to the prefix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 3.8.1.2                         | Forward a seqno request it cannot satisfy to the next hop of a feasible route, or failing that of an unfeasible route | Forwards none whose router-id is all zeroes or all ones, and answers it as any other request                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 3.8.2.1                         | Set a starving node's seqno request to the router-id of the route it has just lost                                    | Asks each neighbor whose offer is unfeasible for that offer's router-id once a prefix of its own is given back with no offer selected                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 3.8.2.3                         | Send a route request to the neighbor shortly before a selected route expires                                          | Sends none                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Appendix A.3                    | Smooth the metric as an exponential average                                                                           | Follows an increase at once and smooths only improvements                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Appendix A.3                    | Switch to a route only when both its metric and its smoothed metric are lower                                         | Asks the smoothed metric to be lower by more than the margin [route selection](../routing.md#route-selection) gives                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Appendix B                      | Send an urgent TLV within 0.2 seconds                                                                                 | Sends an urgent update that follows another to the same neighbor at the end of the pace [route selection](../routing.md#route-selection) gives                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Appendix B                      | Resend a request after 2 seconds, doubling the delay, up to 3 times                                                   | Repeats a seqno request up to 4 times, 3, 3, 6 and 12 seconds apart                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

[RFC 8966 section 3.5.3](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.5.3)
has a node that holds no entry for an update's prefix and neighbor create one:
"a new entry is created in the route table, indexed by (prefix, plen, neigh),
with source equal to (prefix, plen, router-id), seqno equal to seqno, and an
advertised metric equal to the metric carried by the update". The sentence
carries no BCP 14 keyword.
[RFC 9079 section 5.1](https://www.rfc-editor.org/rfc/rfc9079.html#section-5.1)
has a node receiving a source-specific update behave "as described in [RFC8966],
Section 3.5.3, except that the entry under consideration is indexed by (prefix,
plen, sprefix, splen, neigh)". A node keeps an update whose destination and
source prefix are those of a prefix it announces, or of the host route of an
address `cap.table` assigns it, as its neighbor's offer outside the route table,
so while the key is its own a route a neighbor offers for it never enters the
route table. It treats each of them as directly attached, as the stub
implementation of
[Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E) does, which
"always prefers the direct route to a directly attached prefix to a route learnt
over the Babel protocol, even when the prefixes are the same". Where section
3.5.3 has an expired route's metric "set to infinity and the expiry timer is
reset", an offer has a route's expiry time and is dropped when it passes, with
no hold, and a retraction drops it the same way. A selected route's hold exists
to keep what this node told its neighbors, and an offer was never told.
[What a node announces](../routing.md#what-a-node-announces) gives the rest of
an offer's lifetime and its release. It drops an update whose destination is a
host address of its own, a `/32` or `/128` it announces or `cap.table` assigns,
from any other source prefix. The host's kernel delivers its own address
whatever the source, and a neighbor offering a route to it is misconfigured or
claiming this node's address. For a wider prefix, a source-specific route a
neighbor offers for the same destination has another source prefix, so it is
learned, and by the "destination-first ordering" of
[RFC 9079 section 4](https://www.rfc-editor.org/rfc/rfc9079.html#section-4) it
is preferred for packets from its source.

An update under this node's own router-id is its own route come back through a
neighbor that selected it, as split horizon's retraction or as a finite update
from a neighbor that keeps no split horizon. Section 3.5.3 would make it that
neighbor's entry. This node takes it as a retraction of whatever the neighbor
last sent for the prefix, a route or an offer, so it is never stored, selected
or advertised, and the entry keeps its origin, as every retraction does by
[section 4.6.9](https://www.rfc-editor.org/rfc/rfc8966.html#section-4.6.9): "the
router-id, next hop, and seqno are not used".

[RFC 8966 section 4.1.3](https://www.rfc-editor.org/rfc/rfc8966.html#section-4.1.3)
says "A router-id MUST NOT consist of either all binary zeroes (0000000000000000
hexadecimal) or all binary ones (FFFFFFFFFFFFFFFF hexadecimal)." A node takes no
route from a finite update whose router-id, from a Router-Id TLV or an Update's
Router-Id flag, is all zeroes or all ones, as it takes none from one with no
router-id at all, since it would relay the route under that id. A route already
learned from that neighbor stays as it was until it expires, and a retraction
after such an id still withdraws it.
[Appendix C](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-C) allows the
drop as route filtering, by which a node "either discards some of the routes
announced by its neighbours or learns them with a metric that is higher than
what would be expected". For a seqno request it cannot satisfy,
[section 3.8.1.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.8.1.2)
says "if the node has one or more feasible routes towards the requested prefix
with a next hop that is not the requesting node, then the node MUST forward the
request to the next hop of one such route", and "otherwise, if the node has one
or more (not feasible) routes to the requested prefix with a next hop that is
not the requesting node, then the node SHOULD forward the request to the next
hop of one such route". A node forwards no seqno request whose router-id is all
zeroes or all ones, through a feasible route or an unfeasible one, since the
forwarded request would carry it, and answers one as it answers any other.

[Section 3.8.2.1](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.8.2.1)
says "The router-id of the request is set to the router-id of the route that it
has just lost". The route a node loses when it gives back a prefix of its own is
its own, under its own router-id, so ranet3 asks each neighbor whose offer is
unfeasible for that offer's router-id, the only one whose newer seqno can make
the offer feasible.

[RFC 8966 section 3.5.4](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.5.4)
gives 2 ways to end the hold of a retracted prefix: "waiting until the route's
expiry timer has expired", or "sending a retraction with an acknowledgment
request (Section 3.3) to every reachable neighbour that has not explicitly
retracted prefix P, and waiting for all acknowledgments", of which "The latter
option is RECOMMENDED". A node takes the former, for the reason the section
gives: "The former option is simpler". It pays the cost the section names:
"since the expiry time can be as high as a few minutes, doing that prevents
automatic aggregation by creating spurious black-holes for aggregated routes". A
retracted prefix that a shorter route covers stays unreachable until the route's
expiry timer runs out, and a packet for it is dropped meanwhile rather than
following the shorter route. That holds for transit, and for this host's own
traffic where the kernel's copy of the hold refuses it, which the paragraphs
below bound, and the dropped packet is answered Destination Unreachable, for up
to 60 seconds at the defaults where this node told a neighbor the prefix is
reachable, and for the 56 second hold of a route it learned elsewhere.

The same section has a held prefix's packets dropped: "packets destined to an
address within P MUST NOT be forwarded by following a route for a shorter
prefix". Every packet inside a hold that the tun hands ranet3 is dropped and
answered Destination Unreachable into the tun, from the packet's destination,
unless a steering policy takes it or the checks at the mesh's edge drop it with
no answer, as [routing](../routing.md#transit) says. The
[forwarding decision](#transit-answers) drops every packet a peer sends inside a
hold and answers it, a hold that counts as a default among them, so no peer's
packet reaches the host's kernel. The kernel keeps no copy of a hold that
[counts as a default](../routing.md#routes-that-count-as-a-default), since an
`unreachable` route that wide would answer the host's own traffic it covers with
an error while other sessions stay live, and a retracted split internet would
cut the host off. A packet the host sends or forwards for an address inside such
a hold ends as [where a lookup ends](../routing.md#where-a-lookup-ends-on-linux)
gives for the routes left: by the host's own route, as it did before the mesh
carried the prefix, or by a shorter route back into the tun, where ranet3 drops
it and answers it as above. It pays the cost the section names for using the
shorter route, "running the risk of creating a routing loop (Section 2.8)":
until every neighbor has read the retraction, a packet the host forwards by its
own route can come back through a neighbor that still routes the prefix through
this node.

A hold the kernel keeps that does not count refuses a packet the host sends or
forwards only where the lookup ends at it, rows L4 and L9 of
[where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux) and
row D3 of
[where a lookup ends on macOS](../routing.md#where-a-lookup-ends-on-macos). Any
other lookup inside the held prefix ends where those tables give: outside
`overlay` at a route of main longer than /0 that covers it, row L6, refused at
5410 where main's best default is a refusal, row L7, from a socket carrying the
underlay's mark, row L2, from a socket bound to a device, rows B1 to B4, refused
there for want of a route at B2 and B4, and on macOS from a socket bound to no
interface and no address of the tun, rows D1 and D2. Where another program's
rule comes first, it ends as
[sharing a host](../coexistence.md#another-programs-rules) describes. A packet
that leaves by a route for a shorter prefix departs from the section, which says
"As long as this entry is maintained, packets destined to an address within P
MUST NOT be forwarded by following a route for a shorter prefix". The reason is
the design's, for a packet the host sends or forwards alike, since the rules
select on no input device: outside the overlay every route of main longer than
/0 answers ahead of the mesh's table, which keeps the host's LAN reachable, from
the mesh's sources too, ranet3's marked underlay stays out of the tun that
carries it, a bound socket asked for its device, an unscoped hold on macOS would
shadow every other way to its prefix, and ranet3 leaves alone the rules another
program puts ahead of its own, as
[sharing a host](../coexistence.md#another-programs-rules) describes.

A prefix that loses its last route, because its route was flushed at that
expiry, its neighbor's session went, or this node stopped announcing it while
`cap.table` did not assign it, or `cap.table` stopped assigning its address
while this node did not announce it, is held until the latest time any update
this node sent naming it reachable expires at a neighbor, if that is later,
whether or not a retraction followed, as
[the routing page](../routing.md#retracted-routes) says.

Each link is 1 ESP tunnel that delivers in order rather than lossy multicast.
The periodic update and the retraction hold cover a lost triggered update.

Forwarding a seqno request matters most when every route to a prefix has become
unfeasible. Nothing is advertised then, so the RFC's rule would forward nothing.

The smoothed metric is the worst the route has been over the last few time
constants. A route that has gone bad is left at once. A route still has to stay
good before it is switched to, as Appendix A.3 asks.

[Section 3.6](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.6) leaves
selection to local policy: "the route selection policy MUST only satisfy the
following properties", that a retracted route and an unfeasible route are never
selected.
[Appendix A.3](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-A.3)
switches "to a route R' only when both m(R') < m(R) and ms(R') < ms(R)". A node
also asks for the margin [route selection](../routing.md#route-selection) gives,
so 2 routes whose costs move around 1 value stop trading places.
[RFC 9616 section 4.3](https://www.rfc-editor.org/rfc/rfc9616.html#section-4.3)
asks for a hysteresis algorithm "such as the one described in Appendix A.3 of
[RFC8966]", which this is.

[Section 3.7.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.7.2) makes
the update for a changed router-id urgent,
[section 3.8.1.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.8.1.2)
the reply to a forwarded seqno request, and
[Appendix B](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-B) RECOMMENDS
"Urgent timeout: 0.2 seconds". Such an update that follows another to the same
neighbor waits out the pace [route selection](../routing.md#route-selection)
gives, as BIRD paces its triggered updates. A route that flaps then costs each
neighbor 1 update a pace, and the seqno raises that requests owe in it go out
together as 1 raise. Appendix B also RECOMMENDS a request timeout "initially 2
seconds, doubled every time a request is resent, up to a maximum of three
times". A node repeats a seqno request up to 4 times, 3, 3, 6 and 12 seconds
apart. A repeat after 2 seconds would fall inside the 2 seconds in which the
node holds back a second request for the same source and seqno as redundant, in
the sense of section 3.8.1.2.

### Sending and link cost

[Section 3.1](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.1) says
"outgoing TLVs are buffered and SHOULD be sent with a random delay", so that
speakers across a network do not fall into step and TLVs share packets, and "a
delay SHOULD be introduced between successive packets sent out on the same
interface". A node jitters no send, and the packets of 1 pass go back to back.
Each link is 1 ESP session to 1 neighbor, so no medium is shared with other
speakers whose sends could fall into step or collide, and the session's control
queue takes a pass's packets together. Triggered updates alone are paced, and
the pace is at most half the Hello interval, so a TLV that is not urgent still
leaves within the half Hello interval the section gives it.

[Section 3.4.2](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.4.2) says
IHUs "SHOULD be sent less often than Hellos", and Appendix B RECOMMENDS that
"the advertised IHU interval is always 3 times the Multicast Hello interval",
with IHUs sent "only with every third Multicast Hello on lossless links". A node
sends an IHU with every Hello, naming the Hello interval.
[RFC 9616 section 3.2](https://www.rfc-editor.org/rfc/rfc9616.html#section-3.2)
has both ends "produce one RTT sample for each received (Hello, IHU) pair", so
every Hello interval brings a round-trip sample of the link.

Appendix B RECOMMENDS a link cost "estimated using ETX on wireless links" and
"2-out-of-3 with C=96 on wired links". A node estimates ETX on every link unless
`cap.babel.quality` is `none`, which keeps the fixed cost. Every link is a
tunnel, wired or not underneath, and ETX measures the loss of whatever path it
crosses.
[RFC 9616 section 4.2](https://www.rfc-editor.org/rfc/rfc9616.html#section-4.2)
says "The default values rtt-min = 10 ms, rtt-max = 120 ms, and max-rtt-penalty
= 150 are RECOMMENDED". A node keeps rtt-min at 10 milliseconds and sets rtt-max
to 1024 milliseconds and the penalty to 1024. In a global mesh 120 milliseconds
saturates every intercontinental path, so the penalty stops ranking the links it
exists to rank, and a penalty of 150 against a wired cost of 96 makes a
satellite hop cost less than 3 wired ones.

[Section 6](https://www.rfc-editor.org/rfc/rfc8966.html#section-6) says "Every
implementation of Babel SHOULD implement BABEL-MAC", and RECOMMENDS "that all
Babel traffic be protected by an application-layer cryptographic protocol". A
node implements neither BABEL-MAC nor Babel over DTLS. Its Babel packets travel
only inside ESP sessions, each of which authenticated its neighbor and protects
what it carries against change and replay.

### Reassembly

A Babel packet a neighbor's stack cut into fragments is put back together before
the speaker reads it. Other speakers send packets of up to 1443 UDP octets,
which their stacks may fragment. A speaker on a kernel socket has the kernel
reassemble them. This node reads the inner packets of each session itself, so it
reassembles, as
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
describes, the fragments sent to its speaker: an IPv6 packet whose next header
is Fragment, from a link-local address, to `ff02::1:6` or to the speaker's own
link-local address. Such a fragment is the speaker's whether its packet
completes or not, and never reaches the tun. Any other fragment, ordinary
traffic to an address of the mesh among them, goes on as it arrived, to the tun
or by the forwarding decision to the next session, and the host's kernel
reassembles one the tun takes for its socket. The packet put back together goes
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

## Ingress filtering

The mesh is the segment routing domain of
[RFC 8754 section 5.1](https://www.rfc-editor.org/rfc/rfc8754.html#section-5.1),
and the tun is its edge: a packet the host routes into the tun enters the domain
there, and the forwarding decision drops a routing header and this node's own
SIDs, as [segment routing](../segment-routing.md#at-the-border-of-the-mesh)
describes. A routing header from a link outside the mesh is forwarded by its
destination, as RFC 7045 section 2.1 and RFC 5095 section 4.2 ask.

[Section 7](https://www.rfc-editor.org/rfc/rfc8754.html#section-7) says:

> Additionally, ingress filtering of IPv6 source addresses as recommended in BCP
> 38 [RFC2827] SHOULD be used.

The filter [RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html#section-3)
recommends admits an attached network's own prefixes and denies everything else:

```text
IF    packet's source address from within 204.69.207.0/24
THEN  forward as appropriate

IF    packet's source address is anything else
THEN  deny packet
```

The antispoof filter applies the other half. It drops a source inside `overlay`
arriving from outside the mesh, but what
[carve-outs](../antispoof.md#carve-outs) and
[exemptions](../antispoof.md#exemptions) pass. It passes every other source from
every interface outside it, since those links lead to the internet and no prefix
list describes them. That keeps a forged mesh source out of the mesh, and it is
not BCP 38's filter, so section 7 is met in part. The permit half, taking from
each peer only the prefixes it holds, needs first-hop source validation, which
this version does not have.

The tun is the domain's ingress for what a host forwards into the mesh, and the
forwarding decision filters its sources in part. It drops a source the table
routes to another node or holds unreachable, through a route that does not count
as a default, and an overlay source this node does not own, and toward a route
that counts as a default, or, under `cap.exit.via`, toward a destination outside
the overlay that no entry covers, it drops any source this node does not own. On
Linux a source this node does not own, outside the overlay and covered by no
route but one that counts as a default, passes toward a mesh destination. Owning
every source would drop the replies to an exit's egress and to a subnet router's
LAN, since a tun read does not say whether it answers a flow. On every other
platform the decision drops such a source toward any destination but an IPv6
link-local one, which is BCP 38's filter for the host's own side of the edge,
since no exit's replies cross the tun there: the userspace exit on macOS hands
its replies to the mesh through lanes of its own, and every other build carries
no exit. On Linux the chain `mesh_entry` reads that from conntrack before the
tun, and passes into it only this node's own sources, a reply, a destination a
`none` class takes and an IPv6 link-local or multicast destination, as
[the antispoof filter](../antispoof.md#the-entry-chain) gives, which is BCP 38's
filter in part for the host's own side of the edge.

## Exit translation

The departures below are those of the flows the exit translates: out of the mesh
under a class of `auto` or an address, and into it under `return`. A class of
`none` leaves a flow under the source it carries and is no NAT, so these
requirements do not apply to its flows.
[Each source's share of the flows](../exit-nodes.md#each-sources-share-of-the-flows)
covers the classes that translate alone, so a source under `none` is never
refused by it.

The kernel exit translates with the host's connection tracking, which maps each
connection on its own. A new connection from an inside address and port takes
the external port that endpoint already holds, so toward two destinations it
leaves from 1 port, until another inside host holds that port toward the
destination first. Leaf A holds port 4000 toward one server, leaf B then takes
port 4000 toward a second, and A's next connection from port 4000 to the second
server leaves from another port. No nf_tables statement pins 1 external port per
inside endpoint.
[RFC 4787 section 4.1](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.1)
says "A NAT MUST have an "Endpoint-Independent Mapping" behavior",
[RFC 5382 section 4.1](https://www.rfc-editor.org/rfc/rfc5382.html#section-4.1)
asks the same for TCP, and
[RFC 4787 section 8](https://www.rfc-editor.org/rfc/rfc4787.html#section-8)
says:

> A NAT MUST have deterministic behavior, i.e., it MUST NOT change the NAT
> translation (Section 4) or the Filtering (Section 5) Behavior at any point in
> time, or under any particular conditions.

The exit behavior suite checks the changed mapping for UDP and for TCP and
declares both as the kernel exit's limits, with the "RFC 4787 sections 4.1 and
8, RFC 5382 section 4.1" row.

An echo identifier is mapped as a port is, so the same clash departs from
[RFC 5508 section 3.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-3.1),
which says "NAT mapping of ICMP Query Identifiers SHOULD be external-host
independent".

The same mapping gives 2 inside endpoints 1 external endpoint at once. Leaf A's
port 4000 toward one server and leaf B's port 4000 toward a second both leave
from the exit's port 4000, since connection tracking keeps a translated
connection
[unique with its destination](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n682),
and toward 1 destination the second leaf takes another port.
[RFC 4787 section 4.2.1](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.2.1)
says "A NAT MUST NOT have a "Port assignment" behavior of "Port overloading"",
and
[RFC 5382 section 7.1](https://www.rfc-editor.org/rfc/rfc5382.html#section-7.1)
asks the same for TCP as its REQ-7. No nf_tables statement keeps an external
port for 1 inside endpoint, so an external endpoint names a leaf only together
with the destination it talks to. The exit behavior suite checks the overloading
for UDP and for TCP and declares both as the kernel exit's limits, with the "RFC
4787 section 4.2.1 (REQ-3), RFC 5382 section 7.1 (REQ-7)" row.

No external host whose address lies inside `overlay` is reachable through the
exit: a destination a node holds reaches that node, and
[the forwarding decision](../exit-nodes.md#what-an-exit-carries-out) refuses one
no node holds. The overlay is the mesh's own space, and a destination in it is
refused rather than carried to a stranger holding the same address. An exit
whose uplink lease overlaps the overlay carves the lease for its own host alone,
as [carve-outs](../antispoof.md#carve-outs) describe, so a node egressing
through it still reaches no address of the overlay that no node announces.
[RFC 4787 section 4.4](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.4)
says:

> REQ-7: A NAT device whose external IP interface can be configured dynamically
> MUST either (1) automatically ensure that its internal network uses IP
> addresses that do not conflict with its external network, or (2) be able to
> translate and forward traffic between all internal nodes and all external
> nodes whose IP addresses numerically conflict with the internal network.

The kernel exit translates the ICMP queries of the types the host's connection
tracking
[keeps a flow for](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n45)
([IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmpv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n50)).
A query of any other type, an RFC 8335 extended echo among them, would leave
under its own source, so the exit drops it out of the mesh under a class that
translates and into the mesh under `return`, as
[exit nodes](../exit-nodes.md#classes) describes.
[RFC 5508 section 3.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-3.1)
says in its REQ-1 that "a NAT device MUST permit ICMP Queries and their
associated responses, when the Query is initiated from a private host to the
external hosts". A class of `none` passes such a query as the host forwards it.

A query of such a type the exit sends itself from one of its mesh addresses
meets no drop and leaves untranslated under that mesh address. Whether an answer
reaches it depends on how the mesh routes that address, as
[an address that routes back to this exit](../exit-nodes.md#an-address-that-routes-back-to-this-exit)
describes. The drop sits at the forward hook, which only a packet the exit
forwards meets, and a drop for the exit's own packets would need a chain at the
output hook, which every packet the exit sends meets.

Under `auto` the kernel exit takes the address the kernel's masquerade picks for
each flow's route, for
[IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_masquerade.c?id=940de590b839f71d6dc846160534bf202401b8b7#n54)
and for
[IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_masquerade.c?id=940de590b839f71d6dc846160534bf202401b8b7#n237).
On an uplink holding several addresses of a family, one source's flows can so
leave under several addresses at once, the "IP address pooling" behavior
[RFC 4787 section 4.1](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.1)
calls "Arbitrary". It says:

> REQ-2: It is RECOMMENDED that a NAT have an "IP address pooling" behavior of
> "Paired". Note that this requirement is not applicable to NATs that do not
> support IP address pooling.

[RFC 6888 section 3](https://www.rfc-editor.org/rfc/rfc6888.html#section-3)
makes it a MUST on the default:

> REQ-2: A CGN MUST have a default "IP address pooling" behavior of "Paired" (as
> defined in Section 4.1 of [RFC4787]).

The exit's default class is `auto`, under which neither exit tracks the uplink's
addresses. The kernel exit's masquerade takes each flow's by its route. The
userspace exit takes each TCP connection's by its route too, with a mapping on
each address, since a source address belongs to its uplink, and another uplink's
network or a tunnel peer may drop it, as the filter of
[RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html#section-3) does. A UDP
mapping takes the address of the route to its first destination and keeps it
toward every later destination. Where the platform refuses that address on
another link
([`udp_connect`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/udp_usrreq.c),
[`in_pcbladdr`](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/netinet/in_pcb.c#L1610)),
or another uplink drops it, the datagram is lost. Once the host no longer holds
the address, a UDP mapping ends at the next destination it opens rather than
leave from another, and until then its sends fail. So a UDP mapping pairs, and a
source's TCP connections and UDP mappings do not. A class naming an address
pairs every flow of its sources under that address, and an uplink holding 1
address of a family pools none.

[RFC 5508 section 4.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-4.1)
says "If the IP checksum of the embedded packet fails to validate, the NAT
SHOULD silently drop the Error packet". The kernel exit translates such an error
and passes it on, since Linux checks only the outer ICMP checksum.

A connection whose inside port is free toward its destination leaves the kernel
exit from that port, so the port keeps its parity. On a clash the kernel exit
takes another port, starting at a random offset in the range the inside port
falls in, and that port has either parity. No nf_tables statement asks for a
port of the same parity. The userspace exit keeps a leaf's port where the host
carries it, a TCP one where no other mapping holds it on that address too, as
[the userspace exit](#the-userspace-exit) gives. In its place it binds the next
port it tries or any the host gives, of either parity.
[RFC 4787 section 4.2.2](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.2.2)
says:

> REQ-4: It is RECOMMENDED that a NAT have a "Port parity preservation" behavior
> of "Yes".

The section gives parity for RTP implementations that do not read an RTCP port
their peer names separately, and says "It is expected that this issue will fade
away with time, as implementations improve".

The kernel exit admits to a mapping only the replies of the flow that opened it.
A datagram or a SYN to a leaf's mapping from the server's address at another
port, or from another address, reaches the exit's own stack, which answers it as
it answers one to a port of its own, so a socket of the host's at that port
takes it, and the leaf never reads it.
[RFC 4787 section 5](https://www.rfc-editor.org/rfc/rfc4787.html#section-5)
says:

> REQ-8: If application transparency is most important, it is RECOMMENDED that a
> NAT have an "Endpoint-Independent Filtering" behavior. If a more stringent
> filtering behavior is most important, it is RECOMMENDED that a NAT have an
> "Address-Dependent Filtering" behavior.

[RFC 5382 section 4.3](https://www.rfc-editor.org/rfc/rfc5382.html#section-4.3)
recommends the same for TCP as its REQ-3, and
[RFC 6888 section 3](https://www.rfc-editor.org/rfc/rfc6888.html#section-3) says
in its REQ-7 "It is RECOMMENDED that a CGN use an "endpoint-independent
filtering" behavior (as defined in Section 5 of [RFC4787])". Either filtering
needs a destination translation for each external endpoint, and none holds: an
external endpoint can name several leaves at once, as the port overloading above
shows, and an entry of a map nf_tables updates from the packet path
[keeps the value it was made with](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nft_dynset.c?id=940de590b839f71d6dc846160534bf202401b8b7#n56),
so it can outlive its mapping and name the wrong leaf. A peer-to-peer
application's traversal through an exit can fail, and ranet3's own links never
cross an exit.

An unsolicited SYN to the exit's address reaches the exit's own stack as well,
which answers it as it answers one to a port of its own: with a reset at once
where nothing listens, in place of the silence and the Port Unreachable after it
that the same section asks for:

> REQ-4: A NAT MUST NOT respond to an unsolicited inbound SYN packet for at
> least 6 seconds after the packet is received. If during this interval the NAT
> receives and translates an outbound SYN for the connection the NAT MUST
> silently drop the original unsolicited inbound SYN packet. Otherwise, the NAT
> SHOULD send an ICMP Port Unreachable error (Type 3, Code 3) for the original
> SYN, unless REQ-4a applies.

The reset ends a TCP simultaneous open whose inbound SYN reaches the exit before
the leaf's SYN has made the mapping.
[RFC 5382 section 4.2](https://www.rfc-editor.org/rfc/rfc5382.html#section-4.2)
says in its REQ-2a "A NAT MUST handle the TCP simultaneous-open mode of
connection initiation", and section 4.3 says "If a NAT responds to the premature
inbound SYN with an error message that forces the external endpoint to abandon
the connection attempt, it hinders applications performing a TCP
simultaneous-open." A simultaneous open whose leaf's SYN reaches the exit first
crosses it both ways. The exit leaves the host's answer to a SYN as the host
gives it, since a rule dropping a SYN no socket takes would silence the host's
own closed ports too. A host firewall that drops inbound SYNs restores the
silence the requirement asks for.

A leaf's packet to another leaf's mapping on the exit's address is taken as the
exit's own, and its stack answers it as it answers one to a port of its own,
from the mapping's address, a datagram with Port Unreachable and a SYN with a
reset where nothing listens, so a socket of the host's at that port takes it.
The leaf holding the mapping never reads it.
[RFC 4787 section 6](https://www.rfc-editor.org/rfc/rfc4787.html#section-6) says
"A NAT MUST support "Hairpinning"",
[RFC 5382 section 7.2](https://www.rfc-editor.org/rfc/rfc5382.html#section-7.2)
asks the same for TCP, and
[RFC 5508 section 5](https://www.rfc-editor.org/rfc/rfc5508.html#section-5) says
"All NAT devices (i.e., Basic NAT as well as NAPT devices) MUST support the
traversal of hairpinned ICMP Error messages". A hairpin needs the same
destination translation for each external endpoint as the filtering above, which
holds for none, and leaves reach each other over the mesh at their overlay
addresses.

The kernel exit attaches timeouts of its own to each TCP, UDP, ICMP and ICMPv6
flow it translates, UDP to port 53 aside, one a class translates out of the mesh
and one an in rule translates into it under `return` alike, by a connection
tracking timeout object for each protocol, which its rules attach on the flow's
first packet. Every other connection the host tracks, a flow under `none` among
them, keeps the host's timeouts.
[RFC 5382 section 5](https://www.rfc-editor.org/rfc/rfc5382.html#section-5)
says:

> REQ-5: If a NAT cannot determine whether the endpoints of a TCP connection are
> active, it MAY abandon the session if it has been idle for some time. In such
> cases, the value of the "established connection idle-timeout" MUST NOT be less
> than 2 hours 4 minutes. The value of the "transitory connection idle-timeout"
> MUST NOT be less than 4 minutes.

The section counts a connection that one side alone has closed as established:
"ACKs in both directions mark the beginning of the established phase where
application data can be exchanged indefinitely (TCP states: ESTABLISHED,
FIN_WAIT_1, FIN_WAIT_2, and CLOSE_WAIT). The closing phase begins when both
endpoints have terminated their half of the connection by sending a FIN packet."
So an idle translated connection is kept 4 minutes while it opens, counted from
its first SYN, and 5 days once established. It is kept 2 hours 4 minutes while
one side alone has closed, and while data it carried is unacknowledged, a window
is closed or its retransmissions are spent, the states in which the host's
timeouts would drop it after 5 minutes. With a FIN seen each way it is kept 4
minutes. A connection in TIME_WAIT is kept 2 minutes and one closed by a reset
after a reply 10 seconds, the kernel's own, which the requirement leaves
unspecified. A reset before any reply ends the session at once.

The kernel does not renew an opening connection's timeout on a retransmitted
SYN, so an attempt whose SYNs go unanswered is forgotten 4 minutes after the
first, though each retransmission keeps it from being idle as the section counts
idleness. Linux gives the reason in
[its connection tracking](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_tcp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1357).

[RFC 7857 section 2.1](https://www.rfc-editor.org/rfc/rfc7857.html#section-2.1)
says "a NAT SHOULD provide different configurable parameters for configuring the
open and closing idle timeouts". The timeouts are fixed in code, since no
deployment was found needing other values, and they keep the "minimum default
transitory connection idle-timeout of 4 minutes" the section recommends.
[Section 2.2](https://www.rfc-editor.org/rfc/rfc7857.html#section-2.2) says of a
reset matching a mapping that "the NAT SHOULD wait for 4 minutes before deleting
the session and removing any state associated with it if no packets are received
during that 4-minute timeout". The kernel exit keeps the kernel's 10 seconds,
and none for a connection reset before any reply, which the kernel takes as
never opened. Each source's share of the exit's flows leaves a closed connection
uncounted, so a closed connection's timeout bounds the entries a source holds
past its share, and a source resetting its connections would hold each of them 4
minutes rather than 10 seconds.

[RFC 4787 section 4.3](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3)
says:

> REQ-5: A NAT UDP mapping timer MUST NOT expire in less than two minutes,
> unless REQ-5a applies.

Its item c says "A default value of five minutes or more for the NAT UDP mapping
timer is RECOMMENDED." The kernel exit keeps a translated UDP flow 2 minutes
after its last packet until it has a reply and a packet more than 2 seconds
after its first, and 5 minutes from then on. Before that it departs from item c:
a flow nobody answers carries nothing back, and the shorter timer bounds the
entries a source's unanswered flows hold in the table every source shares. A
flow to UDP port 53 keeps the host's timeouts, under item a: "For specific
destination ports in the well-known port range (ports 0-1023), a NAT MAY have
shorter UDP mapping timers that are specific to the IANA-registered application
running over that specific destination port." A resolver answers in one
exchange, and a busy exit sends many. The timers hold for as long as the host's
connection tracking keeps the flow, which a full table can cut short, as REQ-8's
paragraph below says.

The timers of this section, of RFC 5382 section 5 and of RFC 5508 section 3.2
also hold only while the timeout object a flow took on its first packet stands.
nf_tables changes no timeout object in place, and deleting one clears it from
every flow that took it, which then keeps the host's timeouts for the rest of
its life, since a flow takes an object only on its first packet. The kernel exit
deletes an object where a pass reads it back with values other than it writes,
as an earlier build may have left it, and makes it again in the same
transaction, withdraws its objects at a stop and at `ranet3 down`, and a
firewall reload's flush of the whole ruleset deletes them all. A pass deletes
each object that reads back with other values and leaves the rest. Both
families' objects of a protocol take the same values, so where an earlier build
wrote other values for a protocol, its object differs in each family that build
translated, and one pass detaches that protocol's flows in both, up to all 6
objects and every translated flow. A flow so left keeps the host's own timeouts,
the defaults of the kernel's tables for
[TCP](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_tcp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n61),
[UDP](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_udp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n27),
[ICMP](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n25)
and
[ICMPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmpv6.c?id=940de590b839f71d6dc846160534bf202401b8b7#n29)
unless a sysctl changed them. Among them, those of an unanswered UDP mapping, of
a TCP connection opening, closing or holding data unacknowledged, and of an ICMP
query fall short of RFC 4787 REQ-5, RFC 5382 REQ-5 and RFC 5508 REQ-2.

[RFC 5508 section 3.2](https://www.rfc-editor.org/rfc/rfc5508.html#section-3.2)
says:

> REQ-2: An ICMP Query session timer MUST NOT expire in less than 60 seconds.
>
> a) It is RECOMMENDED that the ICMP Query session timer be made configurable.

The kernel exit keeps a translated query session, an echo among them, 60 seconds
after its last request or reply, in ICMP and in ICMPv6, for as long as the
host's connection tracking keeps it, as for UDP. Item a departs: the timer is
fixed in code, since no deployment was found needing another value.

[RFC 5508 section 6](https://www.rfc-editor.org/rfc/rfc5508.html#section-6)
says:

> REQ-8: When a NAT device is unable to establish a NAT Session for a new
> transport-layer (TCP, UDP, ICMP, etc.) flow due to resource constraints or
> administrative restrictions, the NAT device SHOULD send an ICMP destination
> unreachable message, with a code of 13 (Communication administratively
> prohibited) to the sender, and drop the original packet.

Past a source's share of the flows, the kernel exit refuses the new flow by a
rule of its own and answers it: IPv6 with code 1, administratively prohibited,
as
[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)
has a filter answer, and IPv4 with code 1, Host Unreachable, where REQ-8 asks
code 13. A DCCP or UDP-Lite flow under a class that translates meets its
protocol's refusal, below, ahead of the share, so it draws that refusal's code
13 and never the share's code 1.
[RFC 6888 section 3](https://www.rfc-editor.org/rfc/rfc6888.html#section-3)
covers the same refusal at a NAT that subscribers who do not trust each other
share, and its REQ-11 says a NAT refusing a mapping under a quota "SHOULD send
an ICMP Destination Unreachable message with code 1 (Host Unreachable) to the
sender". It gives the reason: "Code 1 is preferred to code 13 because it is
listed as a "soft error" in [RFC1122], which is important because we don't want
TCP stacks to abort the connection attempt in this case."
[RFC 1122 section 4.2.3.9](https://www.rfc-editor.org/rfc/rfc1122.html#section-4.2.3.9)
lists codes 0, 1 and 5 as soft errors on which "TCP MUST NOT abort the
connection". What a leaf's TCP does with the answer is its stack's, as
[the share](../exit-nodes.md#each-sources-share-of-the-flows) says. The cost
falls on UDP: a connected UDP socket on a Linux leaf
[is told of code 13 and not of code 1](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/udp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n995),
unless its application asked for every error with `IP_RECVERR`, so such an
application no longer learns that its flow was refused.
[RFC 1812 section 5.2.7.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.7.1)
says "Routers SHOULD use the newly defined Code 13 (Communication
Administratively Prohibited) if they administratively filter packets". A refusal
under a quota is the case RFC 6888 REQ-11 answers, and the exit takes its code
there. RFC 6888's NAT shares IPv4 addresses alone, so IPv6 keeps RFC 4443's
code.

The kernel exit refuses a DCCP or UDP-Lite packet it would translate: out of the
mesh under a class that translates, and into it under `return`. Each protocol's
checksum covers the addresses
([RFC 4340 section 9.1](https://www.rfc-editor.org/rfc/rfc4340.html#section-9.1),
[RFC 3828 section 3.1](https://www.rfc-editor.org/rfc/rfc3828.html#section-3.1)),
and the host's source translation
[rewrites neither checksum](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_nat_proto.c?id=940de590b839f71d6dc846160534bf202401b8b7#n261),
so a translated packet would reach its receiver with a checksum that fails for
the addresses it carries.
[RFC 6888 section 3](https://www.rfc-editor.org/rfc/rfc6888.html#section-3) says
in its REQ-1 "If a CGN forwards packets containing a given transport protocol,
then it MUST fulfill that transport protocol's behavioral requirements", among
them RFC 5597's for DCCP, whose
[section 8.1](https://www.rfc-editor.org/rfc/rfc5597.html#section-8.1) says:

> REQ-11: If a NAT translates a DCCP packet with a valid DCCP checksum, it MUST
> ensure that the DCCP checksum is translated such that it is valid after the
> translation.

So the exit forwards neither under a translation. A rule ahead of the
translation takes such a packet in its flow's original direction and answers it
with Destination Unreachable, administratively prohibited: code 13 over IPv4, as
REQ-8 above asks, and code 1 over IPv6, as RFC 4443 section 3.1 has a filter
answer. A reply is left to cross, since a flow is translated only where its
first packet was, which the rule took. No quota is involved, so RFC 6888
REQ-11's code 1 does not reach it, and the protocol never crosses a class that
translates, so a stack trying again gains nothing. Under `none` the packet
leaves as the host forwards it. The refusal holds on every kernel, though
connection tracking translated DCCP before
[its removal](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fd72f265bb00d2dd2a3bbad7ec45520025e3a926)
and UDP-Lite before
[its own](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=84dee05d9d61884ee0986f5b4f3d69886f7dfeb0),
since an exit reading its kernel to decide would be a second way to decide it.

The kernel's reject
[answers only some](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/netfilter/nf_reject.h?id=940de590b839f71d6dc846160534bf202401b8b7#n8)
of these packets, so the exit refuses a valid IPv4 DCCP packet, and an IPv6 one
whose checksum covers part of it, with no answer. Over IPv4 that departs from
REQ-8 above, and over IPv6 from
[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1),
which says "A Destination Unreachable message SHOULD be generated by a router,
or by the IPv6 layer in the originating node, in response to a packet that
cannot be delivered to its destination address for reasons other than
congestion."

Before Linux 7.1, which carries UDP-Lite's removal, connection tracking
[checks a UDP-Lite checksum](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_udp.c?id=542be3fa5aff54210a02954c38f07e53ea9bdafd#n170)
against UDP's protocol number while `net.netfilter.nf_conntrack_checksum` is on,
its default, so it takes a valid UDP-Lite packet for one no flow is tracked for.
The exit's rules for such a packet then take it ahead of the refusal. Out of the
mesh they drop it, counted and with no answer, or pass it under `none`, and into
the mesh from a prefix `return` translates they drop it, the reply to a flow
under `none` among them.

Neither the answer to a flow past a source's share nor the answer to a refused
DCCP or UDP-Lite packet can be turned off.
[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)
says "For security reasons, it is recommended that implementations SHOULD allow
sending of ICMP destination unreachable messages to be disabled, preferably on a
per-interface basis." For IPv4,
[RFC 1812 section 5.2.7.1](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.2.7.1)
says "Routers MAY have a configuration option that causes Code 13 (Communication
Administratively Prohibited) messages not to be generated", and the exit has no
such option for its refusal.
[The host's rate limit on ICMP errors](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n311)
thins the answers to one source. The share's answer goes only to a mesh source,
through the tun, and under `return` a host outside the mesh draws the refusal's
answer only by sending into the mesh a protocol the exit refuses.

A DCCP or UDP-Lite packet the exit sends itself from a mesh address meets no
forward chain, so under a class that translates it leaves translated. From Linux
6.17 for DCCP and 7.1 for UDP-Lite, with the trackers above removed, nf_nat
rewrites neither checksum, so there it leaves with its checksum stale. Linux
retired
[its DCCP sockets](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=2a63dd0edf388802074f1d4d6b588a3b4c380688)
and its UDP-Lite sockets, over
[IPv4](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=56520b398e5e6ee129c6279d8649ca959765a0a0)
and
[IPv6](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=62554a51c5844feebe0466d8b31980e110b481de),
by those releases, so only a raw socket on the exit sends either there, and a
rule for the exit's own packets needs a chain at the output hook, which every
packet the exit sends meets, the dataplane's ESP among them, as for the query
above.

[RFC 5508 section 7](https://www.rfc-editor.org/rfc/rfc5508.html#section-7) says
in its REQ-10 that a NAT "SHOULD NOT support: 1. Source Quench Message ... 2.
Information Request/reply". Connection tracking
[takes Source Quench as an error](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/icmp.h?id=940de590b839f71d6dc846160534bf202401b8b7#n25)
of the flow it quotes and
[an Information Request as a query](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_proto_icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n82),
so each would cross translated. The kernel exit drops both and Information Reply
in IPv4, out of the mesh and into it, from any source and under every class,
`none` among them, and counts each drop. The rules come first in the forward
chain, and the exit writes them only while `cap.egress` translates IPv4 and
removes them when it stops.
[RFC 6633 section 1](https://www.rfc-editor.org/rfc/rfc6633.html#section-1)
"formally deprecates reaction to ICMP Source Quench messages by transport
protocols", and
[RFC 6918 section 3](https://www.rfc-editor.org/rfc/rfc6918.html#section-3)
"formally deprecates" Information Request and Information Reply among other
types.
[RFC 6633 section 8](https://www.rfc-editor.org/rfc/rfc6633.html#section-8) says
"Hosts, security gateways, and firewalls MUST silently discard received ICMP
Source Quench packets and SHOULD log such drops as a security fault with at
least minimal details (IP Source Address, IP Destination Address, ICMP message
type, and date/time the packet was seen)". The exit counts each drop in its
rule's counter and logs none, since any host can send the message and a log line
for each would let a sender fill the log. Outside that drop, on an exit stopped
or translating IPv6 alone and on a node that forwards IPv4 between its uplink
and the mesh with no kernel exit, a Source Quench crosses between the host and
the mesh in either direction. A known gap.

[RFC 5508 section 7.3](https://www.rfc-editor.org/rfc/rfc5508.html#section-7.3)
says "If a NAT device does not support forwarding packets with the source route
option, the NAT device SHOULD NOT forward outbound ICMP messages that contain
the source route option in the outer or inner IP header. This is because such
messages could reveal private IP addresses to the external realm." The host
[drops a packet carrying a source route](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/inetdevice.h?id=940de590b839f71d6dc846160534bf202401b8b7#n105)
unless it is set to accept one, and the mesh drops one in transit, as
[ICMP answers](#icmp-answers) says, so no packet carrying a source route enters
the mesh. The kernel exit translates and forwards a leaf's error whose quoted
header carries one, which quotes a packet the leaf made itself.

In IPv4 every ICMP error the kernel exit originates, its answer to a flow past a
source's share and to a protocol it refuses among them, sets precedence 6,
internet control, in its TOS octet, so it does not carry the refused packet's
diffserv class.
[Linux marks every ICMP error it originates so](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/icmp.c?id=940de590b839f71d6dc846160534bf202401b8b7#n944),
and the nf_tables reject statement has no option for another class.
[RFC 5508 section 7.7](https://www.rfc-editor.org/rfc/rfc5508.html#section-7.7)
says "When generating an ICMP message, a NAT device SHOULD copy the diffserv
class of the message that causes the sending of the ICMP error message."

When the host's connection table is full, connection tracking
[evicts a connection or drops the new one's packet](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1663)
with no answer, and what it evicts is the kernel's. A flow it evicts loses the
timeouts
[RFC 4787 section 4.3](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3),
[RFC 5382 section 5](https://www.rfc-editor.org/rfc/rfc5382.html#section-5) and
RFC 5508 section 3.2 set, since the table is the host's, as REQ-11's paragraph
below says. A new connection whose translated ports are still taken when it is
confirmed, in a clash the kernel cannot resolve, is dropped with no answer too.
Both drops happen inside connection tracking, so no rule of the exit's sees the
packet to answer it. The section says the requirement "is meant primarily for
future use. Current applications do not require this for them to work
correctly." The eviction is the design the same section discourages:

> Some NAT designers opt to never reject an outbound flow. When a NAT runs short
> of resources, they prefer to steal a resource from an existing NAT Session
> rather than reject the outbound flow. Such a design choice may appear
> conformant to REQ-8 below. However, the design choice is in violation of the
> spirit of both REQ-8 and REQ-2. Such a design choice is strongly discouraged.

RFC 6888 sets the requirements of a NAT that many subscribers share and none of
them manages, which each source's share of the exit's flows answers, for the
sources its family's set has room for, as
[a full set admits](../exit-nodes.md#each-sources-share-of-the-flows) says.
Section 3's REQ-4 asks a NAT to limit "the number of external ports (or,
equivalently, "identifiers" for ICMP) that are assigned per subscriber", and its
item a says "Per-subscriber limits MUST be configurable by the CGN
administrator", which `cap.egress.flows_per_source` is. Its item c says "it is
RECOMMENDED that the CGN include administrator-adjustable thresholds to prevent
a single subscriber from consuming excessive CPU resources from the CGN (e.g.,
rate-limit the subscriber's creation of new mappings)", and REQ-5's item b says
"it SHOULD be possible to limit the rate at which memory-consuming state
elements are allocated". The kernel exit bounds the flows a source holds open
and not the rate at which it opens them, so a source that keeps opening flows
past its share can cost the exit CPU in proportion to its share, as
[the kernel's count](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conncount.c?id=940de590b839f71d6dc846160534bf202401b8b7#n201)
walks the source's list of flows. And the share leaves out connections in
TIME_WAIT or closed, so a source closing short connections fast holds entries
its share does not count. A known gap: no rule bounds the rate at which one
source opens flows.

REQ-11 covers a NAT unable to create a mapping. Its item b says it "SHOULD send
an ICMP Destination Unreachable message with code 1 (Host Unreachable) to the
sender", its item c that it "SHOULD send a notification (e.g., SNMP trap)
towards a management system (if configured to do so)", and its item d that it
"MUST NOT delete existing mappings in order to "make room" for the new one". A
source at its share has its new flow refused, answered and counted, and its own
flows left as they are. Past the host's connection table, what the kernel
[evicts or drops](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1663)
is its own, and a drop happens before any rule of the exit's sees the packet, so
no answer is sent, the refused count does not move and no `egress.refused` event
is recorded. The host
[logs a rate-limited "table full" line](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_conntrack_core.c?id=940de590b839f71d6dc846160534bf202401b8b7#n1669).
The table is the host's, every connection of the host's in it, and ranet3 writes
no setting of it.

REQ-3 says "The CGN function SHOULD NOT have any limitations on the size or the
contiguity of the external address pool. In particular, the CGN function MUST be
configurable with contiguous or non-contiguous external IPv4 address ranges." A
class of `cap.egress translate` naming an address translates to it alone, and an
`auto` class to the address the host's route gives each flow, as the pooling
above says, and no class names a pool or a range. An exit carries the mesh's own
nodes, which split its addresses by class.

REQ-6 says "It MUST be possible to administratively turn off translation for
specific destination addresses and/or ports." The exit chooses whether to
translate a flow by the flow's source alone. In place of turning translation off
for a destination, a class of `none` in `cap.egress translate` leaves the flows
of the mesh sources its prefix covers under the source they carry. No field of
`cap.egress` names a destination address or port. A known gap.

REQ-9 says "A CGN MUST implement a protocol giving subscribers explicit control
over NAT mappings. That protocol SHOULD be the Port Control Protocol [RFC6887]."
The exit implements no protocol that gives a source control of its mappings, PCP
(RFC 6887) or another. Its mappings are the ones nf_nat makes for each flow
under the rules the capability gives. A known gap.

REQ-10 says "CGN implementers SHOULD make their equipment manageable.
Standards-based management using standards such as "Definitions of Managed
Objects for NAT" [RFC4008] is RECOMMENDED." The exit reports its state through
`ranet3 status`, its metrics and its events, as [exit nodes](../exit-nodes.md)
describes, and implements no MIB, since ranet3 speaks no SNMP.

### The userspace exit

On macOS `cap.egress` is the userspace exit, which ends each TCP connection a
leaf opens in a stack of its own and opens its own toward the server, and relays
UDP and echo through the host's sockets, as
[the exit on macOS](../exit-nodes.md#the-exit-on-macos) gives. Where a row above
names each exit, the userspace exit departs as the row says, for the reason it
gives.

RFC 5382 section 4.1 says "A NAT MUST have an "Endpoint-Independent Mapping"
behavior for TCP", and section 7.1 says "A NAT MUST NOT have a "Port assignment"
behavior of "Port overloading" for TCP." The userspace exit keeps a mapping for
each leaf address and port and each address its connections leave from, while a
connection is open: the address and port its connections from that address leave
from toward every server. The address is the one the leaf's class names, or
under `auto` the one the route to the server picks for the dial's socket. Under
`auto` a leaf port whose servers' routes pick two addresses, by two links or as
two sources on one, so keeps a mapping on each, on Linux and on macOS alike.
That departs from section 4.1, as the "RFC 4787 sections 4.1 and 8, RFC 5382
section 4.1" row declares: a source address belongs to its uplink, and another
uplink's network or a tunnel peer may drop it
([RFC 2827](https://www.rfc-editor.org/rfc/rfc2827.html#section-3)). Once the
host no longer holds a mapping's address, a connection under `auto` leaves from
the address the route then picks, under that address's mapping, and one under a
class naming the address fails, and its leaf is reset. The port is the leaf's
own where no other mapping holds it on that address and the host binds it, else
one the host gives. Every socket binds its mapping's address and port before its
connect, so no connection of another leaf address and port binds that endpoint,
and no mapping holding a connection is ended. The host gives no port a socket
holds on that address unless it shares ports among sockets that allow it, as
Linux does under
[`net.ipv4.ip_autobind_reuse`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/networking/ip-sysctl.rst?id=940de590b839f71d6dc846160534bf202401b8b7),
and such a port fails the dial. A mapping ends with its last connection, since
section 4.1 gives a mapping to the connections it serves, and section 5 and RFC
4787 section 4.3, whose timer is UDP's, ask nothing of it past them. A
connection the host refuses its mapping's endpoint while it holds the address
leaves from another port the host gives on that address, for that connection
alone, see the "RFC 4787 sections 4.1 and 8, RFC 5382 section 4.1" row: one
whose 4-tuple the host's TCP still holds, while an earlier connection on it is
open or closing and in TIME_WAIT after, unless the host's connect takes it over,
as Linux's may
([`tcp_twsk_unique`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp_ipv4.c?id=940de590b839f71d6dc846160534bf202401b8b7)),
and one whose port a listener of the host's holding `SO_REUSEADDR` took, which
Linux lets it bind beside the connected socket. The exit behavior suite checks
both requirements in TCP, and the userspace exit declares neither.

RFC 5382 section 4.3 REQ-3 recommends endpoint-independent or address-dependent
filtering for TCP, section 7.2 REQ-8 says "A NAT MUST support "hairpinning" for
TCP", and section 4.2 REQ-2a asks that a simultaneous open be handled. A
terminating exit has no inbound half: no connection from outside reaches a leaf.
A SYN from outside meets the host's own TCP, a leaf's connection to the exit's
own address is refused as one to any address the host holds, and a simultaneous
open opens through the host's socket in SYN-SENT. The exit behavior suite
declares it as the userspace exit's limit, with this row.

RFC 5382 section 7.3 REQ-9 says "If a NAT translates TCP, it SHOULD translate
ICMP Destination Unreachable (Type 3) messages." The userspace exit relays a
router's or a server's error about a dial that fails to the leaf, from the
address that raised it, and the leaf's TCP gives the connection up as it would
behind a NAT. An error about a connection that is open is about the host's own
socket, since the leaf's connection ends in the exit's stack: it reaches the
host's TCP, which acts on it as RFC 1122 section 4.2.3.9 gives, and never the
leaf. The other way, the exit's stack takes any quoted source as its own, so a
leaf's error reaches it only where the exit reads the quote down to a TCP
header. A Packet Too Big below RFC 8201 section 4's 1280 bytes or a
Fragmentation Needed below 552 bytes, see the RFC 1191 section 3 row, never
reaches it. One at that floor or above reaches it from any session, since a
waypoint's or a later hop's comes from an address the mesh may reach by another
first hop than the leaf, and dropping it would leave the connection sending
segments its path drops, against RFC 1191 section 3's and RFC 8201 section 4's
MUST to reduce the packet size. So a leaf behind another session can lower a
connection's segment size to the floor with a forged one, the blind
performance-degrading attack of RFC 5927 section 7.1, which slows the connection
and neither stalls nor ends it. gVisor at the pin checks neither the quoted
sequence number against the segments in flight (RFC 5927 section 4.1) nor the
connection's progress (section 7.2), so the forger needs only the connection's
addresses and ports, and either check would need the gVisor fork. The connection
then sends more, smaller segments for the same bytes, and they pass through the
pump and the link queue every leaf's connections share, so the cost reaches
other leaves too. Every other error reaches the stack only where the segment's
destination sits behind the same session as the error's source, each judged by
the session the mesh sends to it by, which for an address a steer entry covers
is its first segment's. Such an error from a node the mesh reaches by another
first hop than the leaf is dropped: the ones a router raises about an open IPv4
connection, net or host unreachable and time exceeded, are soft errors under RFC
1122 section 4.2.3.9, and a hard one, protocol or port unreachable, passes from
the leaf's own address or a router behind the leaf's session, while a filtering
router's own that the mesh reaches by another first hop is dropped like any
error from another session. Leaves behind one session share its trust and are
not told apart. An error in fragments is dropped as well, since its quote is
read whole.

RFC 5508 section 3.1 REQ-1 asks that ICMP queries and their responses pass. On
macOS the userspace exit sends a leaf's echo through the ICMP socket of its
family bound to the leaf's class's address, or to none under auto, with the
leaf's identifier where no other mapping holds it, and takes a reply for a leaf
where it carries the identifier that leaf's mapping holds and comes from one of
the last 16 destinations the mapping sent to. Nothing keeps another program off
an identifier, so a reply to another program's echo on that identifier from such
a destination reaches the leaf as well. A reply that matches no mapping reaches
no leaf and is counted.

RFC 6888 section 3 REQ-1, RFC 5508 section 6 REQ-8 and RFC 4443 section 3.1: the
userspace exit refuses every protocol but TCP, UDP and ICMP, DCCP and UDP-Lite
among them, with code 13 over IPv4 and code 1 over IPv6, on every fragment that
names it, since the host's ordinary sockets send no other protocol from its
address. The exit behavior suite declares it as the protocol limit.

RFC 5508 section 4.2.2 REQ-5 asks a NAT to revert and forward a leaf's ICMP
error about a mapping's datagram, and RFC 4787 section 4.2.1 REQ-3 (a)
recommends a source port below 1024 be mapped below 1024. An app on a phone
opens no raw socket and binds no port below 1024, so there the userspace exit
drops and counts a leaf's own error, which only a raw socket sends from the
mapping's address, and maps a low port to one the host gives. The exit behavior
suite declares both on the phone arm, with these rows.

The timers: a UDP mapping is kept 5 minutes past its last datagram out, and 30
seconds toward port 53, as RFC 4787 section 4.3 REQ-5a allows. An echo mapping
is kept 60 seconds, fixed. A leaf's closed connection lingers in TIME_WAIT 60
seconds under a cap past which the oldest is closed, below RFC 5382 section 5
REQ-5's 4 minutes for a closing connection. A leaf's bare SYN whose sequence
number comes after the one past its FIN, as gVisor's own TIME_WAIT takes a SYN,
closes the endpoint at once, so the leaf can open the four-tuple again: the
stack hands a SYN in TIME_WAIT to no forwarder, and the conditions RFC 1122
section 4.2.2.13 puts on that reopening are not checked, see its row. A
connection is freed at once after a reset, where RFC 7857 section 2.2 asks 4
minutes. A leaf's opening connection is held while the exit's dial to the server
runs, and answered once the host's TCP gives the dial up. An established
connection has no idle timer of the exit's: it is kept until an end closes or
resets it, or stops answering the keepalives the exit's stack sends the leaf and
the host's TCP the server.

A flow past its source's share or past the exit's totals, which the host's
memory and descriptors size, is answered with Host Unreachable over IPv4 and
administratively prohibited over IPv6, counted, and recorded in an
`egress.refused` event at most once every 30 seconds, and no open flow is closed
to make room (RFC 6888 section 3 REQ-11), but the oldest endpoint in TIME_WAIT
past the cap.

RFC 6888 section 3 REQ-8 says an external port "SHOULD NOT be reallocated to a
new mapping until at least 120 seconds have passed", with exceptions where "the
CGN tracks TCP sessions" (a) and where the ports "used address-dependent or
address-and-port-dependent filtering" (c). The userspace exit takes its ports
from the host's own sockets, which the host frees at once on close. Its TCP
ports meet (a), since the host's TCP tracks each connection of the exit's,
TIME_WAIT included, and its UDP ports (c), since each mapping filters by
address. The requirement is met through those exceptions, and the hold the RFC
asks be configurable does not arise.

RFC 7567 section 4.2 says "Network devices SHOULD use an AQM algorithm to
measure local congestion and to determine the packets to mark or drop so that
the congestion is managed." The userspace exit's link queue holds every packet
its stack sends toward the leaves until the pump writes it to a lane, and runs
RFC 8289's controlled delay, as a peer's sender does: once the delay has stayed
past 5 ms for 100 ms, with at least the leaf session's MTU queued behind the
head, the pump drops at the queue's head. Below the queue's bound of 4,096
packets that holds the delay to 5 ms. At full rate it does not. On the exit's
bench on Linux, 983 connections each copying both ways, one run at this code
read each second over the 7 seconds the queue stood at its bound: 92 to 97% of
the packets the pump took were the exit's own pure ACKs of the leaves' data. The
queue held 4,067 to 4,096 packets at its median but under 1.5 MB, and a packet's
median wait was 27 to 42 ms, about as long as 4,096 packets take at the 98,000
to 134,000 a second the pump took. The bound's tail drop took 54,000 to 173,000
packets a second, against the controlled delay's 68 to 368, and the check for an
MTU behind the head never held one back, since at least 369,000 bytes stood
queued in each of those seconds. In 3 runs with the controlled delay turned off,
alternated with 3 with it on, the leaves wrote 428 to 455 MB/s against 448 to
454 MB/s over each run's last 5 seconds, and the median wait was 34 to 38 ms in
both. A pure ACK is cumulative, so a dropped one slows no sender: the next
acknowledges everything it would have. The data toward the leaves, whose drops
would slow its senders, was 3 to 8% of the packets taken, and those senders held
windows of 1 to 5 segments at their median.
[The userspace exit's limits](limits.md#the-userspace-exit) give the bound.

**The gVisor fork.** The userspace exit's TCP is gVisor's netstack, which
`pkgs/ranet3/go.mod` replaces with a fork made from the upstream version it
requires. The fork carries 2 changes. A segment past a zero receive window whose
ACK is acceptable has its ACK taken, as RFC 9293 section 3.10.7.4 asks of "valid
ACKs" at a zero window, so a flow whose 2 directions both stand at a zero window
moves. And the send queue is counted in memory against the send buffer, each
segment's bytes with its structs, as the receive queue is, and each write is
read in pieces of a power of two so its chunks hold little more than that count,
so a server trickling toward a leaf whose window is closed holds one flow within
its send buffer.

The packets an exit drops before its translation sees them are under
[Drops with no answer](#drops-with-no-answer).

## Drops with no answer

[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)
says:

> A Destination Unreachable message SHOULD be generated by a router, or by the
> IPv6 layer in the originating node, in response to a packet that cannot be
> delivered to its destination address for reasons other than congestion.

It gives each failure to deliver a code, among them:

> If the reason for the failure to deliver is lack of a matching entry in the
> forwarding node's routing table, the Code field is set to 0.

> If the reason for the failure to deliver is administrative prohibition (e.g.,
> a "firewall filter"), the Code field is set to 1.

> If the reason for the failure to deliver is that the packet with this source
> address is not allowed due to ingress or egress filtering policies, the Code
> field is set to 5.

None of these drops answers, each for a reason that holds for every packet it
drops:

- For code 5, over IPv4 code 13 as
  [RFC 1812 section 5.3.9](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.9)
  gives it, the antispoof filter drops a source inside `overlay` arriving from
  outside the mesh, but what [carve-outs](../antispoof.md#carve-outs) and
  [exemptions](../antispoof.md#exemptions) pass. Each source lies in the mesh's
  own space, so an answer would be routed into the mesh, to the address's holder
  there or nowhere, rather than to the sender, which may have forged it.
- For code 5, over IPv4 code 13 as RFC 1812 section 5.3.9 gives it, on Linux the
  chain `mesh_entry` drops a packet the host would send into the tun from a
  source this node does not own, unless it is a reply, toward a `none` class or
  to an IPv6 link-local or multicast destination. The source may be the sender's
  own, as a LAN host's unannounced address is, but a forwarded packet's source
  may be forged, so an answer could reach a bystander, and a UDP send from the
  host fails with `EPERM` instead, as
  [the entry chain](../antispoof.md#the-entry-chain) says. Section 5.3.9 also
  says filtering SHOULD be configurable to forward all packets, and the chain
  has no such switch, since it keeps a host beside a forwarding node out of the
  mesh.
- For code 5, every SID refuses an outer source outside the overlay. Each packet
  is addressed to a SID, so an answer would tell its sender which addresses are
  SIDs.
- For code 5, an egress segment refuses an outer source outside its allow list's
  entries inside the overlay, or an inner source outside the list. The SID has
  already refused an outer source outside the overlay, so the outer source of
  each packet is an overlay address. A host beyond the mesh can forge one
  through a node that forwards without `overlay` or exempts it, and the segment
  cannot tell such a packet from a mesh node's, so an answer could reach the
  mesh node the source names rather than the host that sent the packet.
- For code 5, an egress segment past its allow list also refuses an inner source
  the mesh routes no reply to, of a packet to a destination other than a
  multicast destination or the limited broadcast, but a Not-ECT one that arrived
  under an outer CE, as the exit's check below does. No route would carry an
  answer back to that source either.
- For code 1, an egress segment past its reply check refuses an inner packet
  whose destination the mesh routes itself, by a route that does not
  [count as a default](../routing.md#routes-that-count-as-a-default), to another
  node, into a hold or to this node, since egress carries nothing for the mesh.
  For IPv4,
  [RFC 1812 section 5.3.9](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.9)
  says "The router MUST allow packets to be silently discarded" and "The router
  SHOULD allow an appropriate ICMP unreachable message to be sent when a packet
  is discarded", with code 13. The reason is the allow list's above. Each packet
  passed the SID's overlay check and the allow list, so its outer source is an
  overlay address and its inner one an overlay address or a LAN the list names,
  some of which a host beyond the mesh can forge through a node without
  `overlay` or one exempting it, and an answer could reach the mesh node the
  source names.
- For code 0, an egress segment past its reply check refuses an inner packet
  whose destination lies inside `overlay`, the mesh's own address space. No node
  that writes that `overlay` egresses such a destination through its
  [forwarding decision](#transit-answers) either. Where no node announces one,
  an exit with `overlay` whose table selects its own route that counts as a
  default answers it as no route, and a node whose table selects that exit's
  route routes it there. An exit without `overlay` has its decision egress such
  a destination as it egresses any other outside the mesh. The reason is the
  allow list's above, as for code 1.
- For code 5, the forwarding decision drops a tun read from a source the table
  routes to another node or holds unreachable, through a route that does not
  count as a default, or from an overlay source this node does not own. The
  source is forged, so an answer would reach the node it names rather than the
  host that sent the packet.
- For code 5, the forwarding decision drops a tun read from a source this node
  does not own toward a route that counts as a default, or, under
  `cap.exit.via`, toward a destination outside the overlay that no entry covers,
  and on every platform but Linux, where no entry chain runs, toward any
  destination but an IPv6 link-local one. Only this node's own traffic leaves
  the mesh through an exit, or enters it where no entry chain runs, and an
  unowned source may be forged, so an answer could reach a bystander.
- For code 1, the forwarding decision drops a tun read whose walk finds a
  routing header of type 0, 1 or 4, or a type the mesh does not recognize. An
  answer would tell the host that this node is the edge of the mesh's segment
  routing domain.
- For code 1, the forwarding decision drops a tun read addressed to one of this
  node's own SIDs. An answer would tell the host which addresses are SIDs.
- For code 1, the forwarding decision drops a tun read whose inner packet,
  opened one level deep, is itself IP-in-IP. An answer would tell the host that
  this node is the mesh's edge.
- For code 1 and for the Parameter Problem of
  [section 3.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.4), which
  a node SHOULD send for a header it cannot process, the forwarding decision
  drops as `invalid` a tun read whose chain runs past 16 hop-by-hop, destination
  options, routing and authentication headers and atomic fragments' headers or
  ends inside one, or whose inner packet, opened one level deep, has a header
  that cannot be read. The walk that finds a routing header or an inner packet
  must end, and an answer would tell the host that this node is the mesh's edge.
- For code 3, the forwarding decision writes a tun read back into the tun where
  the tun holds its destination. That address is one of this node's own, which
  the MUST NOT leaves out ("other than one of the receiving router's own
  addresses"). It drops as `looped` any other tun read the table answers as this
  node's own, which the mesh could only hand back to the host. That meets the
  MUST NOT that keeps such a packet off its arrival link, and the answer is a
  known gap.
- For code 5, an exit drops a packet it would egress through a route that
  [counts as a default](../routing.md#routes-that-count-as-a-default) where the
  mesh routes no reply to its source, as
  [exit nodes](../exit-nodes.md#what-an-exit-carries-out) describe. The answer
  would take the same route back, which reaches no node. The check is on for
  every exit, where
  [RFC 1812 section 5.3.8](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.8)
  has source address validation "disabled by default", for the DISCUSSION's
  reason: it "can erroneously discard valid packets in situations where paths
  are asymmetric". This one cannot, since it takes a route back through any
  session, a held prefix among them, or to this node's own networks and
  addresses, and drops only a source that no route but one counting as a default
  reaches. A LAN the exit shares with another mesh node is one such path: a LAN
  host's packet reaches the exit through the other node's session, and passes,
  since the exit's own entry for the LAN routes the reply.
- With no code named for it, an exit drops a packet it would egress through a
  prefix `cap.egress` advertises while it announces no prefix of the packet's
  family, or holds that family not [ready](../exit-nodes.md#readiness). From the
  moment the node takes the family's withdrawal, the drop lasts until the
  speaker retracts the prefix. From the moment the exit holds the family not
  ready, it lasts until a pass finds the family ready again or the speaker
  retracts the prefix. After the retraction the decision treats a packet for it
  as [the routing page](../routing.md#retracted-routes) says. A family whose
  translation another writer took is held not ready at once, and stays announced
  until the exit's next pass.

An egress segment drops with no answer, too, a packet its allow list and its
checks let through whose family is not [ready](../exit-nodes.md#readiness), and
counts it not ready. The node withdraws the SID's `/128` while a family the host
carries out is not ready, or no family is, as
[egress segments](../exit-nodes.md#egress-segments) gives for each platform, and
the mesh takes the readiness before the speaker retracts the route, so that drop
lasts from that moment until the retraction reaches the leaf, as the exit's
above does. Where the host does not carry the family out and the other family is
ready, the node keeps the `/128`, since a leaf reads it as the exit's liveness
and the exit still serves the other family, and the segment drops the family's
packets for as long as that holds. No reason holds for that silence.

The same section says:

> For security reasons, it is recommended that implementations SHOULD allow
> sending of ICMP destination unreachable messages to be disabled, preferably on
> a per-interface basis.

For the drops above these messages are always off, an exit's 2 among them. For
the drops the forwarding decision answers, no route, a hold, transit off and a
link-local source to a wider unicast destination a router forwards, they are
always on, and so they are for a read off the tun with no route or inside a
hold, which [routing](../routing.md#transit) describes.
[Transit answers](#transit-answers) gives the decision's drops that send none, a
truncated packet and a source route among them, and
[routing](../routing.md#transit) lists the rest, a malformed header and a source
or destination no router forwards. An egress segment drops with no answer every
inner packet whose source or destination no router forwards, and the decision
treats some of them otherwise. Both drop a packet to a multicast or limited
broadcast destination whatever its source. The decision writes a packet to an
IPv6 link-local destination to the tun whatever its source, and answers an IPv6
link-local source to a wider unicast destination a router forwards with code 2
on the session it came from. [The antispoof filter](../antispoof.md#watching-it)
counts each drop, [segment routing](../segment-routing.md#watching-it) counts
each refusal, and `ranet3 status` counts the decision's drops to a multicast or
limited broadcast destination, and an egress segment's of an inner packet to
such a destination that its allow list let through, but a Not-ECT one that
arrived under an outer CE, as `session multicast`, an exit's 2 as
`unrouted source` and `not ready`, and a tun read's as `invalid`, `forged`,
`routing header`, `SID`, `unowned source`, `nested` and `looped`, on its
`Transit` line.

[RFC 1812 section 5.3.9](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.9)
also says "The router SHOULD count and SHOULD allow selective logging of packets
not forwarded." The antispoof filter meets the first half and departs from the
second, on every platform it runs on. Each of its drops counts the packets it
refused by rule and family: on Linux each drop of chains `antispoof` and
`mesh_entry` in the nftables table `inet ranet3`, and on macOS each drop of
chain `antispoof` in the pf anchor `com.apple/ranet3`.
`ranet3_antispoof_dropped_packets_total` carries the counts by `reason` and
`family` as of the last pass, the `antispoof` line of `ranet3 status` gives
them, `ranet3 debug rules` reads each rule's counter at the moment it asks, and
each pass whose counters moved records `antispoof.dropped` with each kind's
packets since the pass before, which `ranet3 debug events` reads. No line is
logged for a dropped packet, and no setting logs one. A line for each refused
packet would let any sender that forges a source write the host's log at its own
rate, and the counters already name the rule and the family an operator tracing
a refused packet looks for.
