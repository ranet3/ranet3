---
# SPDX-FileCopyrightText: 2026 Nick Cao
# SPDX-FileCopyrightText: 2026 Yifei Sun
# SPDX-License-Identifier: MIT AND CC-BY-4.0
title: "Deliberate protocol deviations"
description: "Where ranet3 departs from the IKEv2, ESP, Babel, IPv6, ICMP and NAT specifications on purpose."
created: 2026-08-23
updated: 2026-10-27
order: 20
---

ranet3 departs from the specifications it implements in the places this page
lists. The table summarizes them, and the sections below give the details.

| RFC and section                                              | The RFC says                                                                                                                                     | ranet3                                                                                                                                                                                                                                                                                                                                                                                                      | Why                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 7296 section 2.23, RFC 9242 section 3.2                  | IKE starts on UDP port 500 and moves to 4500 behind a NAT, in the first `IKE_INTERMEDIATE` where one runs                                        | IKE and ESP share `link.port` from the first message                                                                                                                                                                                                                                                                                                                                                        | 1 port per node, with no transition to track                                                                                                                                                                                                                                                               |
| RFC 7296 section 2.23                                        | NAT detection hashes the real source address and port                                                                                            | The source hash covers a random address, so it never matches                                                                                                                                                                                                                                                                                                                                                | The peer always encapsulates ESP in UDP                                                                                                                                                                                                                                                                    |
| RFC 7296 section 2.23                                        | Follow any validated packet when not behind a NAT, and none behind one                                                                           | Every session follows a fresh authenticated request, and nothing else                                                                                                                                                                                                                                                                                                                                       | A session follows a peer that moved                                                                                                                                                                                                                                                                        |
| RFC 7296 section 2.11                                        | Answer from the address and port the request reached                                                                                             | The kernel's choice once that address is gone or has no route                                                                                                                                                                                                                                                                                                                                               | No answer otherwise, see Answer addresses                                                                                                                                                                                                                                                                  |
| RFC 7296 section 2.11                                        | Answer from the address and port the request reached                                                                                             | The kernel's choice on FreeBSD and OpenBSD                                                                                                                                                                                                                                                                                                                                                                  | No source kept, see Answer addresses                                                                                                                                                                                                                                                                       |
| RFC 7296 section 2.25.1                                      | Complete both colliding Child SA rekeys and keep 1                                                                                               | The peer's rekey is answered `TEMPORARY_FAILURE`                                                                                                                                                                                                                                                                                                                                                            | 1 Child SA per session                                                                                                                                                                                                                                                                                     |
| RFC 7296 section 2.8                                         | The responder may switch to the new SA once it sends its response                                                                                | It switches just before sending the response                                                                                                                                                                                                                                                                                                                                                                | The difference is the time to encrypt 1 message                                                                                                                                                                                                                                                            |
| RFC 7296 section 2.18                                        | An IKE SA rekey may choose a new PRF                                                                                                             | The PRF stays, and a reload that drops it replaces the IKE SA                                                                                                                                                                                                                                                                                                                                               | strongSwan expands keys with the old PRF                                                                                                                                                                                                                                                                   |
| RFC 7296 section 4                                           | After `NO_ADDITIONAL_SAS`, delete the old SA and create a new one                                                                                | Without a crossing peer rekey held, the old SA stays and the rekey is retried                                                                                                                                                                                                                                                                                                                               | Not implemented                                                                                                                                                                                                                                                                                            |
| RFC 7296 section 2.25.2                                      | Answer as usual a rekey of an IKE SA this end is rekeying too                                                                                    | Past the IKE SA's lifetime it is answered `TEMPORARY_FAILURE`                                                                                                                                                                                                                                                                                                                                               | Section 2.8: an SA past its lifetime is not used                                                                                                                                                                                                                                                           |
| RFC 7296 section 2.8                                         | An SA past its lifetime is not used                                                                                                              | It finishes its exchange, answers the peer and sends its Delete                                                                                                                                                                                                                                                                                                                                             | Sections 2.1 and 2.3 keep 1 request until it ends                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.8                                         | A rekeyed Child SA keeps the algorithms of the old one                                                                                           | A Child SA rekey may move to another listed cipher                                                                                                                                                                                                                                                                                                                                                          | Either end's lists left the old cipher out                                                                                                                                                                                                                                                                 |
| RFC 7296 section 2.8                                         | A rekeyed Child SA keeps the algorithms of the old one                                                                                           | This end's own Child SA rekey drops the key exchanges a peer's rekey ran                                                                                                                                                                                                                                                                                                                                    | No Child SA key exchange of its own, see Rekeying                                                                                                                                                                                                                                                          |
| RFC 7296 section 1.3.1                                       | A failed Child SA does not tear down the IKE SA                                                                                                  | When the Child SA in `IKE_AUTH` fails, both ends delete the IKE SA                                                                                                                                                                                                                                                                                                                                          | An IKE SA carries nothing without its Child SA                                                                                                                                                                                                                                                             |
| RFC 7296 section 2.4                                         | Send a Delete for an IKE SA closed while the peer still answers                                                                                  | None when a Message ID space is spent, a message cannot be built, or the peer's fragments of 1 message pass the reassembly limit                                                                                                                                                                                                                                                                            | A Delete needs a Message ID and the same encoding, and RFC 7383 section 5 drops the connection, see Closing SAs                                                                                                                                                                                            |
| RFC 7296 section 2.1                                         | A retransmission is bitwise identical to the original request                                                                                    | A request cut again for a smaller threshold is not                                                                                                                                                                                                                                                                                                                                                          | RFC 7383 section 2.5.2 has it refragmented, see IKE fragmentation                                                                                                                                                                                                                                          |
| RFC 7296 section 2.4                                         | Retransmission times increase exponentially                                                                                                      | Each new cut of a request starts them over                                                                                                                                                                                                                                                                                                                                                                  | RFC 7383 section 2.5.2 has the timers start over                                                                                                                                                                                                                                                           |
| RFC 7296 section 2.11                                        | Answer a request at the address and port it came from                                                                                            | A repeat from another address draws the answer only within the bytes it sent                                                                                                                                                                                                                                                                                                                                | A replayed fragment would aim answers at any address                                                                                                                                                                                                                                                       |
| RFC 7383 section 2.5.1                                       | Use the path MTU the sender knows for the fragments                                                                                              | Never less than 1280 bytes over IPv6 or 576 over IPv4                                                                                                                                                                                                                                                                                                                                                       | The values the section gives where the path MTU is unknown                                                                                                                                                                                                                                                 |
| RFC 7383 section 5                                           | Bound the decrypted content of the fragments held                                                                                                | The fragments are bounded as the IKE messages they came in                                                                                                                                                                                                                                                                                                                                                  | They hold more than their content                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.21.3                                      | Answer each erroneous request on an authenticated IKE SA with an error                                                                           | A replaced IKE SA past its lifetime answers no request                                                                                                                                                                                                                                                                                                                                                      | Section 2.8: an SA past its lifetime is not used                                                                                                                                                                                                                                                           |
| RFC 7296 section 4                                           | Accept configured RSA certificates and shared keys                                                                                               | Ed25519 signatures only, against the trust document                                                                                                                                                                                                                                                                                                                                                         | Keys come from the trust document                                                                                                                                                                                                                                                                          |
| RFC 7296 section 2.9                                         | Refuse unacceptable traffic selectors with `TS_UNACCEPTABLE`, or narrow them                                                                     | Only the full IPv4 and IPv6 ranges, anything else `NO_PROPOSAL_CHOSEN`                                                                                                                                                                                                                                                                                                                                      | Babel picks the peer for each packet                                                                                                                                                                                                                                                                       |
| RFC 7296 section 2.21.4                                      | Tell the peer of an error outside a request, such as ESP on an unknown SPI                                                                       | Such ESP is counted and dropped, and nothing is sent                                                                                                                                                                                                                                                                                                                                                        | A known gap                                                                                                                                                                                                                                                                                                |
| RFC 7296 section 2.21.4                                      | Answer a suspicious message from a peer's address over its IKE SA                                                                                | It is dropped, and nothing is sent over the SA                                                                                                                                                                                                                                                                                                                                                              | A spoofed address could make the node send                                                                                                                                                                                                                                                                 |
| RFC 7296 section 3.3.4                                       | Let an administrator enter new Diffie-Hellman groups and their parameters                                                                        | No such interface                                                                                                                                                                                                                                                                                                                                                                                           | Elliptic curve groups only, fixed in code                                                                                                                                                                                                                                                                  |
| RFC 7296 section 3.3.5                                       | Accept an offer of a longer key than the one configured                                                                                          | A key length the lists leave out is refused                                                                                                                                                                                                                                                                                                                                                                 | Section 3.3.4's suite controls are a MUST                                                                                                                                                                                                                                                                  |
| RFC 8247, RFC 8221                                           | Support AES-CBC, MODP 14, `PRF_HMAC_SHA1`, `AUTH_HMAC_SHA1_96`, HMAC integrity and RSA signatures                                                | AEAD ciphers and elliptic curve groups only                                                                                                                                                                                                                                                                                                                                                                 | Legacy transforms are left out                                                                                                                                                                                                                                                                             |
| RFC 4303 sections 2.6 and 2.7                                | Be able to generate dummy packets                                                                                                                | None are generated, and no traffic flow confidentiality padding is sent                                                                                                                                                                                                                                                                                                                                     | A known gap                                                                                                                                                                                                                                                                                                |
| RFC 4303 sections 3.3.3 and 4                                | Log a sequence number overflow with the source address and IPv6 Flow ID                                                                          | The log names the local port, not the source address, and no Flow ID                                                                                                                                                                                                                                                                                                                                        | A wildcard socket, and no flow label is set                                                                                                                                                                                                                                                                |
| RFC 3948 section 2.1                                         | Send the IPv4 UDP checksum as zero                                                                                                               | Every IPv4 datagram carries a computed checksum                                                                                                                                                                                                                                                                                                                                                             | Linux refuses segmented sends without one                                                                                                                                                                                                                                                                  |
| RFC 3948 section 4                                           | Send NAT keepalives                                                                                                                              | None are sent                                                                                                                                                                                                                                                                                                                                                                                               | Hellos and IKE liveness checks keep the mapping open                                                                                                                                                                                                                                                       |
| RFC 4443 section 2.2                                         | Answer from an address of the node's own                                                                                                         | A tun read's Packet Too Big and Destination Unreachable come from the packet's destination                                                                                                                                                                                                                                                                                                                  | Where the host routes the destination into the tun, only the destination passes every check, see ICMP answers                                                                                                                                                                                              |
| RFC 4443 sections 2.4 and 3.2                                | Answer the packet that could not be forwarded, to its source                                                                                     | `End` answers a segment it admits too large for its next session about the packet it carries, to that packet's source                                                                                                                                                                                                                                                                                       | The headend relays no answer to the sender, see ICMP answers                                                                                                                                                                                                                                               |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                       | Originate from an address of the router's own, of the interface the answer leaves by                                                             | An ICMPv4 answer to a tun read comes from the packet's destination                                                                                                                                                                                                                                                                                                                                          | Where the host routes the destination into the tun, only the destination passes `rp_filter` 1 and a strict chain, see ICMP answers                                                                                                                                                                         |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                       | Originate from an address of the router's own, of the interface the answer leaves by                                                             | With no IPv4 router-id, `End`'s IPv4 answer comes from the packet's destination                                                                                                                                                                                                                                                                                                                             | `rp_filter` 1 and a strict chain drop it from 192.0.0.8                                                                                                                                                                                                                                                    |
| RFC 1812 section 4.3.2.6                                     | Reverse a source route the packet carries into the error, unless a policy known to the router would keep the error from its sender               | No ICMPv4 answer carries a source route                                                                                                                                                                                                                                                                                                                                                                     | A Linux or macOS host drops a source-routed packet at its defaults, see ICMP answers                                                                                                                                                                                                                       |
| RFC 4443 section 3.2                                         | Send Packet Too Big for a packet larger than the next link, one to a multicast group included                                                    | `End` sends none for a segment carrying a packet to a multicast group                                                                                                                                                                                                                                                                                                                                       | The mesh routes no multicast, and a ranet3 headend steers no packet to a group                                                                                                                                                                                                                             |
| RFC 1812 section 5.3.5.1                                     | Limited broadcasts MUST NOT be discarded                                                                                                         | A read off the tun to 255.255.255.255 is dropped and counted with the multicast reads                                                                                                                                                                                                                                                                                                                       | No service of ranet3 takes a broadcast, and the same section forbids forwarding it                                                                                                                                                                                                                         |
| RFC 4443 section 2.4 (e.1)                                   | Originate no ICMPv6 error in answer to an ICMPv6 error                                                                                           | One behind 8 extension headers or more is answered where any other packet would be                                                                                                                                                                                                                                                                                                                          | Refusing at the bound would withhold the errors sections 3.2 and 3.3 require from a packet not shown to be an error                                                                                                                                                                                        |
| RFC 4443 section 2.4 (f)                                     | Make the rate limit's parameters configurable, since "the best defaults depend on where the implementation is expected to be deployed"           | Fixed in code, the Linux kernel's defaults but for the bound on sources kept                                                                                                                                                                                                                                                                                                                                | Buckets per source scale the node's budget with the senders it answers, and the cap bounds a flood's cost on the smallest node                                                                                                                                                                             |
| RFC 1812 section 4.3.2.8                                     | Make the rate limit's parameters settable in the router's configuration                                                                          | Fixed in code, the Linux kernel's defaults but for the bound on sources kept                                                                                                                                                                                                                                                                                                                                | Buckets per source scale the node's budget with the senders it answers, and the cap bounds a flood's cost on the smallest node                                                                                                                                                                             |
| RFC 4443 section 2.2, RFC 1812 sections 4.2.2.11 and 4.3.2.4 | Answer from an address of the node's own                                                                                                         | A transit answer to a packet whose source an entry of this node's not counting as a default reaches goes into the tun from the packet's destination, whichever session delivered it                                                                                                                                                                                                                         | Only this host or a network behind it receives it, and only the destination passes every check, see Transit answers                                                                                                                                                                                        |
| RFC 4443 section 2.2                                         | Answer from an address of the node's own                                                                                                         | With no IPv6 router-id and no SID, a transit Packet Too Big comes from the packet's destination                                                                                                                                                                                                                                                                                                             | Path MTU discovery needs the answer more than its source                                                                                                                                                                                                                                                   |
| RFC 4443 section 2.2 (a)                                     | Answer a packet sent to an address of the node's from that same address                                                                          | A session's packet to an address of the host that no route of this node covers is answered from the router-id                                                                                                                                                                                                                                                                                               | The decision reads no host address list, see Transit answers                                                                                                                                                                                                                                               |
| RFC 4443 sections 3.1, 3.2 and 3.3                           | Send Destination Unreachable (SHOULD), Packet Too Big and Time Exceeded (MUST)                                                                   | No ICMPv6 error of any kind is sent for transit from a source only this node's own default reaches, but for the beyond scope answer to a link-local source, which goes back on its session                                                                                                                                                                                                                  | The mesh routes no reply to it, and the host would send it out of its uplink, see Transit answers                                                                                                                                                                                                          |
| RFC 1812 sections 4.3.3.5 and 5.3.1                          | Send Parameter Problem and Time Exceeded (MUST)                                                                                                  | No ICMPv4 error of any kind, Destination Unreachable and Fragmentation Needed among them, is sent for transit from a source only this node's own default reaches                                                                                                                                                                                                                                            | The mesh routes no reply to it, and the host would send it out of its uplink, see Transit answers                                                                                                                                                                                                          |
| RFC 4443 sections 3.3 and 3.1                                | Send Time Exceeded (MUST) and Destination Unreachable (SHOULD)                                                                                   | Neither is sent for transit where the node holds no IPv6 router-id and no SID                                                                                                                                                                                                                                                                                                                               | No address of the node could be the source, see ICMP answers                                                                                                                                                                                                                                               |
| RFC 1812 sections 4.2.2.11 and 4.3.2.4                       | Originate from an address of the router's own, of the interface the answer leaves by                                                             | With no IPv4 router-id, a transit answer comes from 192.0.0.8, a Fragmentation Needed from the packet's destination                                                                                                                                                                                                                                                                                         | A session has no address, see ICMP answers                                                                                                                                                                                                                                                                 |
| RFC 1812 section 4.2.2.2                                     | Insert the router-id into an option where the interface has no address                                                                           | With no IPv4 router-id, Record Route and Timestamp insert 192.0.0.8                                                                                                                                                                                                                                                                                                                                         | The address its IPv4 answers come from                                                                                                                                                                                                                                                                     |
| RFC 1812 section 5.2.2                                       | Answer a truncated packet with Parameter Problem (SHOULD)                                                                                        | A truncated transit IPv4 packet is dropped and counted with no answer                                                                                                                                                                                                                                                                                                                                       | Linux's `ip_rcv_core` drops it the same way                                                                                                                                                                                                                                                                |
| RFC 1812 section 5.3.13.4                                    | Support source route options, with any discarding option off by default                                                                          | A transit IPv4 packet carrying a source route is dropped                                                                                                                                                                                                                                                                                                                                                    | Source routing bypasses controls, see ICMP answers                                                                                                                                                                                                                                                         |
| RFC 1812 section 5.2.2                                       | Answer a strict source route for another node with Parameter Problem (SHOULD)                                                                    | It is dropped and counted with no answer                                                                                                                                                                                                                                                                                                                                                                    | Linux's `ip_rcv_options` drops it the same way                                                                                                                                                                                                                                                             |
| RFC 4443 section 3.1                                         | Allow sending Destination Unreachable to be disabled, preferably per interface (SHOULD)                                                          | The forwarding decision's and a tun read's cannot be turned off, and each draws on its source's bucket and the node's cap                                                                                                                                                                                                                                                                                   | The decision's goes only to a source the node's table routes, or for code 2 back on its session, and a tun read's only back into the tun, see Transit answers                                                                                                                                              |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | The border filter drops a mesh source from outside the mesh with no answer                                                                                                                                                                                                                                                                                                                                  | The source is forged, so an answer would reach a bystander                                                                                                                                                                                                                                                 |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | A SID drops an outer source outside the overlay with no answer                                                                                                                                                                                                                                                                                                                                              | An answer tells the sender which addresses are SIDs                                                                                                                                                                                                                                                        |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | An egress segment drops a source outside its allow list with no answer                                                                                                                                                                                                                                                                                                                                      | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1, RFC 1812 section 5.2.7.1               | Answer a packet with no route with Destination Unreachable, code 0, over IPv4 Host Unreachable where other hosts of its network may be reachable | An egress segment drops an inner packet for a destination inside `cap.border.overlay` with no answer                                                                                                                                                                                                                                                                                                        | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1, RFC 1812 section 5.3.9                 | Answer a packet a firewall refuses with Destination Unreachable, code 1, over IPv4 code 13                                                       | An egress segment drops an inner packet for a destination the mesh routes itself with no answer                                                                                                                                                                                                                                                                                                             | A source may be forged, so an answer could reach a bystander                                                                                                                                                                                                                                               |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | An exit drops a packet it would egress, and the mesh routes no reply to, with no answer                                                                                                                                                                                                                                                                                                                     | No route would carry the answer back either                                                                                                                                                                                                                                                                |
| RFC 1812 section 5.3.8                                       | Have source address validation off by default (MUST)                                                                                             | An exit always drops a packet it would egress, and the mesh routes no reply to                                                                                                                                                                                                                                                                                                                              | The check is loose, so an asymmetric path passes it, a LAN the exit shares with another node among them                                                                                                                                                                                                    |
| RFC 4443 section 3.1                                         | Answer a packet that cannot be delivered with Destination Unreachable (SHOULD)                                                                   | An exit drops a packet for a family it stopped announcing or holds not ready with no answer, until the family is ready or it retracts the prefix                                                                                                                                                                                                                                                            | The retraction decides the packets after it                                                                                                                                                                                                                                                                |
| RFC 4443 section 3.1                                         | Answer a packet that cannot be delivered with Destination Unreachable (SHOULD)                                                                   | An egress segment drops a packet of a family not ready with no answer, until the node withdraws the SID's `/128`, or while the other family is ready if the host does not forward this one                                                                                                                                                                                                                  | The withdrawal decides the packets after it, and none holds while the `/128` stays, see Drops with no answer                                                                                                                                                                                               |
| RFC 4443 section 3.1                                         | Answer a packet that cannot be delivered with Destination Unreachable (SHOULD)                                                                   | A steered read off the tun whose first segment has no route is counted and dropped with no answer                                                                                                                                                                                                                                                                                                           | A known gap                                                                                                                                                                                                                                                                                                |
| RFC 4787 sections 4.1 and 8, RFC 5382 section 4.1            | Map 1 external port to each inside endpoint whatever the destination, and change that mapping under no conditions                                | The kernel exit takes another port once another inside host holds that port toward the same destination                                                                                                                                                                                                                                                                                                     | conntrack maps per connection, and no nf_tables statement pins 1 external port per inside endpoint, see Exit translation                                                                                                                                                                                   |
| RFC 5508 section 3.1                                         | Map an ICMP query identifier the same toward every external host (SHOULD)                                                                        | The kernel exit takes another identifier once another inside host holds that identifier toward the same host                                                                                                                                                                                                                                                                                                | conntrack maps an identifier as it maps a port, see Exit translation                                                                                                                                                                                                                                       |
| RFC 5508 section 4.1                                         | Drop an ICMP error whose embedded IP checksum fails to validate (SHOULD)                                                                         | The kernel exit translates the error and passes it on                                                                                                                                                                                                                                                                                                                                                       | Linux checks only the outer ICMP checksum, see Exit translation                                                                                                                                                                                                                                            |
| RFC 4787 section 4.2.2                                       | Map an even port to an even port and an odd port to an odd port (RECOMMENDED)                                                                    | The kernel exit keeps parity only while it keeps the port, and a port it takes on a clash has either parity                                                                                                                                                                                                                                                                                                 | No nf_tables statement keeps parity, see Exit translation                                                                                                                                                                                                                                                  |
| RFC 5382 section 5                                           | An idle TCP session is kept at least 2 hours 4 minutes once established, and at least 4 minutes while it opens or closes                         | The kernel exit keeps one at most 2 minutes while it opens or closes, and 5 minutes while data it carried is unacknowledged                                                                                                                                                                                                                                                                                 | A known gap, see Exit translation                                                                                                                                                                                                                                                                          |
| RFC 4787 section 4.3                                         | An idle UDP mapping is kept at least 2 minutes, and 5 minutes or more by default (RECOMMENDED)                                                   | The kernel exit keeps a UDP flow 30 seconds until it has a reply and a packet more than 2 seconds after its first, and 2 minutes from then on                                                                                                                                                                                                                                                               | A known gap, see Exit translation                                                                                                                                                                                                                                                                          |
| RFC 5508 section 3.2                                         | An idle ICMP query session is kept at least 60 seconds                                                                                           | The kernel exit keeps one 30 seconds after its last packet                                                                                                                                                                                                                                                                                                                                                  | A known gap, see Exit translation                                                                                                                                                                                                                                                                          |
| RFC 5508 section 6                                           | Answer a new flow the NAT cannot set up with an ICMP destination unreachable, code 13 (SHOULD)                                                   | The kernel exit drops the packet with no answer                                                                                                                                                                                                                                                                                                                                                             | The drop happens inside connection tracking, where no rule sees it, see Exit translation                                                                                                                                                                                                                   |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The border filter drops a routing header from outside the mesh with no answer                                                                                                                                                                                                                                                                                                                               | An answer tells the sender this node is the mesh's edge                                                                                                                                                                                                                                                    |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The border filter drops a SID of this node from outside the mesh with no answer                                                                                                                                                                                                                                                                                                                             | An answer tells the sender which addresses are SIDs                                                                                                                                                                                                                                                        |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | The forwarding decision drops a tun read from a source the table routes to another node or holds unreachable, through a route that does not count as a default, or from an overlay source this node does not own, with no answer                                                                                                                                                                            | The source is forged, so an answer would reach the node it names                                                                                                                                                                                                                                           |
| RFC 4443 section 3.1                                         | Answer a packet refused for its source with Destination Unreachable, code 5                                                                      | The forwarding decision drops a tun read toward a route that counts as a default from a source this node does not own, with no answer                                                                                                                                                                                                                                                                       | Only this node's own traffic leaves through an exit, and an unowned source may be forged                                                                                                                                                                                                                   |
| RFC 1812 section 5.3.8                                       | Have source address validation off by default (MUST)                                                                                             | The three source rules are always on, with no setting: an IPv4 tun read is dropped toward any destination from a source the table routes to another node or holds unreachable through a route that does not count as a default, or from an overlay source this node does not own, and toward a default from a source this node does not own                                                                 | The mesh keeps a source it does not own out at its edge, as RFC 8754 section 7 and BCP 38 ask of the domain's ingress. A path that is asymmetric costs what [the limits](limits.md#transit) say                                                                                                            |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The forwarding decision drops a tun read whose walk finds a routing header of type 0, 1 or 4, or a type it does not recognize, with no answer                                                                                                                                                                                                                                                               | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The forwarding decision drops a tun read addressed to one of this node's own SIDs, with no answer                                                                                                                                                                                                                                                                                                           | An answer tells the host which addresses are SIDs                                                                                                                                                                                                                                                          |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The forwarding decision drops a tun read whose inner packet, opened one level deep, is itself IP-in-IP, with no answer                                                                                                                                                                                                                                                                                      | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                         | Answer a packet a firewall refuses with Destination Unreachable, code 1                                                                          | The forwarding decision drops a tun read whose chain runs past 16 hop-by-hop, destination options and routing headers, with no answer                                                                                                                                                                                                                                                                       | The walk that finds a routing header or an inner packet must end, and no deployment sends such a chain                                                                                                                                                                                                     |
| RFC 4443 section 3.4                                         | Discard a packet whose header cannot be processed and answer it with Parameter Problem (SHOULD)                                                  | The forwarding decision drops a tun read whose chain ends inside a header the walk reads, with no answer                                                                                                                                                                                                                                                                                                    | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.4                                         | Discard a packet whose header cannot be processed and answer it with Parameter Problem (SHOULD)                                                  | The forwarding decision drops a tun read whose inner packet, opened one level deep, has a header that cannot be read, with no answer                                                                                                                                                                                                                                                                        | An answer tells the host this node is the mesh's edge                                                                                                                                                                                                                                                      |
| RFC 4443 section 3.1                                         | Answer a packet for a subnet of its own arrival link with Destination Unreachable, code 3, and never forward it back onto that link (MUST NOT)   | The forwarding decision drops a tun read the table answers as this node's own, with no answer, so it never goes back into the tun                                                                                                                                                                                                                                                                           | A known gap                                                                                                                                                                                                                                                                                                |
| RFC 8966 section 3.2.2                                       | Raise the node's own seqno only when asked                                                                                                       | The seqno rises at every start                                                                                                                                                                                                                                                                                                                                                                              | Peers take a restarted node's routes at once                                                                                                                                                                                                                                                               |
| RFC 8966 section 3.5.3, RFC 9079 section 5.1                 | Create a route table entry for each finite update a neighbor sends                                                                               | An update for the destination and source of this node's own prefix or assigned address is dropped, and one for its own host address whatever its source                                                                                                                                                                                                                                                     | Appendix E: the directly attached prefix is preferred, and the host's kernel delivers its own address whatever the source                                                                                                                                                                                  |
| RFC 8966 section 3.5.3                                       | Create a route table entry for each finite update a neighbor sends                                                                               | An update under a router-id of all zeroes or all ones is dropped                                                                                                                                                                                                                                                                                                                                            | Section 4.1.3 forbids that router-id, and Appendix C allows the filter                                                                                                                                                                                                                                     |
| RFC 8966 section 3.5.4                                       | End a hold once every neighbor acknowledges a retraction                                                                                         | The hold lasts until an expiry timer runs out, transit for the prefix answered unreachable meanwhile                                                                                                                                                                                                                                                                                                        | The RFC's own reason: "The former option is simpler"                                                                                                                                                                                                                                                       |
| RFC 8966 section 3.5.4                                       | Forward no packet inside a held prefix by a shorter route                                                                                        | The kernel keeps no hold that counts as a default, so the host's traffic there ends by the routes left, the host's own or a shorter route back into the tun, as [where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) gives                                                                                                                                                                     | That hold in the kernel would cut the host off                                                                                                                                                                                                                                                             |
| RFC 8966 section 3.5.4                                       | Forward no packet inside a held prefix by a shorter route                                                                                        | A packet inside a hold that does not count from a socket carrying the underlay's mark, from one bound to a device, or on macOS from one bound to no interface and no address of the tun ends where rows L2 and B1 to B4 of [where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux) and rows D1 and D2 of [where a lookup ends on macOS](../routing.md#where-a-lookup-ends-on-macos) give | ranet3's marked underlay stays out of the tun that carries it, a bound socket asked for its device, and on macOS an unscoped hold would shadow every other way to its prefix, see Updates and requests                                                                                                     |
| RFC 8966 section 3.5.4                                       | Forward no packet inside a held prefix by a shorter route                                                                                        | On Linux, a packet the host sends or forwards inside a hold that does not count ends outside `cap.border.overlay` at a route of main longer than /0 that covers it, as row L6 of [where a lookup ends](../routing.md#where-a-lookup-ends-on-linux) gives, and where another program's rule comes first as [sharing a host](../coexistence.md#another-programs-rules) describes                              | Outside the overlay every route of main longer than /0 answers ahead of the mesh's table, which keeps the host's LAN reachable, and ranet3 leaves another program's rules ahead of its own alone, see Updates and requests                                                                                 |
| RFC 8966 section 3.7.2                                       | Try to reach every neighbor with a triggered update                                                                                              | It is sent once                                                                                                                                                                                                                                                                                                                                                                                             | Each link is 1 ESP tunnel that delivers in order                                                                                                                                                                                                                                                           |
| RFC 8966 sections 3.8.1.1, 3.8.1.2                           | Answer a request when a selected route exists                                                                                                    | Split horizon applies to replies                                                                                                                                                                                                                                                                                                                                                                            | The requester is the route's next hop                                                                                                                                                                                                                                                                      |
| RFC 8966 section 3.8.1.2                                     | Forward a seqno request only while advertising the prefix                                                                                        | Forwarded whenever a route exists                                                                                                                                                                                                                                                                                                                                                                           | Starvation leaves nothing advertised                                                                                                                                                                                                                                                                       |
| RFC 8966 section 3.8.1.2                                     | Forward a seqno request to a feasible route's next hop, or failing that to an unfeasible route's                                                 | One under a router-id of all zeroes or all ones is not forwarded                                                                                                                                                                                                                                                                                                                                            | Section 4.1.3 forbids sending that router-id                                                                                                                                                                                                                                                               |
| RFC 8966 section 3.8.2.3                                     | Ask for a selected route shortly before it expires                                                                                               | No such request is sent                                                                                                                                                                                                                                                                                                                                                                                     | Not implemented                                                                                                                                                                                                                                                                                            |
| RFC 8966 section 4                                           | Make packets as large as the link's MTU allows                                                                                                   | At most 1232 octets of UDP payload                                                                                                                                                                                                                                                                                                                                                                          | Every session carries 1280 bytes                                                                                                                                                                                                                                                                           |
| RFC 8966 Appendix A.3                                        | Smooth the metric as an average                                                                                                                  | An increase takes effect at once                                                                                                                                                                                                                                                                                                                                                                            | A route that went bad is left at once                                                                                                                                                                                                                                                                      |
| RFC 8200 section 4.5                                         | Wait 60 seconds for fragments, and answer errors with ICMP                                                                                       | Wait 16 seconds, send no ICMP, drop more                                                                                                                                                                                                                                                                                                                                                                    | Fragments of 1 packet cross 1 session together                                                                                                                                                                                                                                                             |
| RFC 7045 section 2.1, RFC 5095 section 4.2                   | Discard a standard extension header only by a policy configurable per type, allow them by default, and forward routing types other than 0        | A tun read's routing header of type 0, 1 or 4, or of a type ranet3 does not recognize, is dropped by a policy fixed in code, and types 2, 3, 253 and 254 pass                                                                                                                                                                                                                                               | Types 0 and 1 are deprecated, and type 4 entering from a host is a packet entering the SR domain, which RFC 8754 section 5.1 drops at the edge. A type defined later can steer a packet as the SRH does, and the walk cannot tell one that does from one that does not. No deployment needs another policy |
| RFC 7045 section 2.1                                         | Forward a packet regardless of the extension headers present                                                                                     | A tun read whose chain runs past 16 hop-by-hop, destination options and routing headers is dropped                                                                                                                                                                                                                                                                                                          | The walk that finds a routing header or an inner packet must end, and no deployment sends such a chain                                                                                                                                                                                                     |
| RFC 5095 section 4.2                                         | A firewall forwards by default every routing header but type 0                                                                                   | The border filter drops a routing header of any type arriving from outside                                                                                                                                                                                                                                                                                                                                  | A first header of type 0 or 2 hides an SRH from nf_tables                                                                                                                                                                                                                                                  |
| RFC 8754 section 4.2                                         | A transit node forwards an SRH it is not the destination of                                                                                      | The border filter drops a routing header of any type arriving from outside, and the tun read's walk drops an SRH whatever its destination                                                                                                                                                                                                                                                                   | The mesh is the SR domain and this node its edge, section 5.1                                                                                                                                                                                                                                              |
| RFC 8754 section 5.4                                         | Handle errors as RFC 2473 does, and send them to sources in the SR domain                                                                        | `End` answers a segment it admits too large for its next session about the packet it carries, to that packet's source, in the mesh or not                                                                                                                                                                                                                                                                   | The headend relays no answer to the sender, see ICMP answers                                                                                                                                                                                                                                               |
| RFC 8754 section 5.4                                         | Handle the errors an encapsulated packet meets as RFC 2473 does                                                                                  | A headend writes an ICMPv6 error about its encapsulation into its tun                                                                                                                                                                                                                                                                                                                                       | A known gap, see ICMP answers                                                                                                                                                                                                                                                                              |
| RFC 8986 section 4.8                                         | Answer an `End.DT46` reached with segments left with Parameter Problem, code 0, pointing at Segments Left                                        | Such a packet is dropped with no answer, whichever the SID delivers to                                                                                                                                                                                                                                                                                                                                      | None holds, since the SID answers the header refusals beside it, see ICMP answers                                                                                                                                                                                                                          |
| RFC 8986 sections 4.8 and 4.1.1                              | Answer an upper-layer header `End.DT46` does not process with Parameter Problem, code 4, wherever it sits                                        | Such a packet is dropped with no answer, whichever the SID delivers to                                                                                                                                                                                                                                                                                                                                      | None holds, since the SID answers the header refusals beside it, see ICMP answers                                                                                                                                                                                                                          |
| RFC 8200 section 4.4                                         | Answer a routing header of an unrecognized type with segments left with Parameter Problem, code 0, pointing at the Routing Type                  | `End` and `End.DT46` drop such a packet with no answer, whichever the SID delivers to                                                                                                                                                                                                                                                                                                                       | None holds, since the SID answers the header refusals beside it, see ICMP answers                                                                                                                                                                                                                          |
| RFC 8986 sections 4.1 and 4.1.1                              | Answer an upper-layer header an `End` does not process with Parameter Problem, code 4                                                            | An `End` at segments left 0 whose SRH describes itself, or reached with no SRH, drops the packet with no answer, whatever its upper-layer header                                                                                                                                                                                                                                                            | A waypoint SID terminates no traffic, which covers the drop but not the silence, see ICMP answers                                                                                                                                                                                                          |
| RFC 8986 section 4.8, RFC 8200 section 4.4                   | Deliver an IPv4 or IPv6 upper-layer header behind any extension header, ignoring a routing header of an unrecognized type with segments left 0   | Dropped with no answer, such as behind a hop-by-hop or destination options header with no SRH, a routing header of another type with segments left 0, or destination options after the SRH                                                                                                                                                                                                                  | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8754 section 4.3.1.1, RFC 8986 sections 4.1 and 4.8      | At segments left 0, proceed to the next header, checking Last Entry only with segments left                                                      | In a packet they admit, `End` and `End.DT46` answer an SRH whose last entry runs past its length with Parameter Problem, code 0, at segments left 0 too                                                                                                                                                                                                                                                     | None holds, since the SRH's length still says where the next header starts, see ICMP answers                                                                                                                                                                                                               |
| RFC 8986 section 4.1                                         | With segments left, answer a spent hop limit with Time Exceeded before checking Last Entry and Segments Left                                     | In a packet it admits, `End` answers an SRH whose last entry runs past its length, or Segments Left past a list of at most 16 segments, with Parameter Problem, code 0, at hop limit 1 too                                                                                                                                                                                                                  | None holds: every SID takes RFC 8754 section 4.3.1.1's order, and the two differ only for a packet malformed and out of hops                                                                                                                                                                               |
| RFC 8200 sections 4.5 and 5                                  | Reassemble fragments at the destination, and process an atomic fragment as a whole packet                                                        | `End.DT46` drops a fragment with no answer, an atomic fragment included, and `End` one whose Fragment header precedes the SRH                                                                                                                                                                                                                                                                               | None for an atomic fragment, and a larger packet's fragment needs reassembly the SID does not do, see ICMP answers                                                                                                                                                                                         |
| RFC 8200 section 4.1                                         | Accept and attempt to process extension headers in any order, occurring any number of times                                                      | `End` drops an SRH behind an authentication header with no answer                                                                                                                                                                                                                                                                                                                                           | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8200 section 4.1                                         | Accept and attempt to process extension headers in any order, occurring any number of times                                                      | `End` and `End.DT46` drop an SRH behind 8 or more hop-by-hop and destination options headers with no answer                                                                                                                                                                                                                                                                                                 | A sender cannot choose what one packet costs, which covers the drop at both SIDs but not the silence, see ICMP answers                                                                                                                                                                                     |
| RFC 8986 section 4.1, RFC 8754 section 4.3.1.1               | Forward a packet with segments left, answering a spent hop limit or a header that does not describe itself                                       | `End` drops an SRH holding more than 16 segments with no answer, with segments left, at hop limit 1 too and with Segments Left past its last entry                                                                                                                                                                                                                                                          | A sender cannot choose the list a waypoint carries on, which covers the drop but not the silence, see ICMP answers                                                                                                                                                                                         |
| RFC 8986 section 4.1, RFC 4443 section 3.1                   | Submit the packet to the FIB lookup for its new destination, and answer a packet with no route with Destination Unreachable, code 0              | `End` drops with no answer a packet whose next segment is no SID of this node and that the mesh routes to no other node: no route, a hold or this node's own                                                                                                                                                                                                                                                | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8754 section 4.3.2                                       | At a local interface that is no SID, process the next header at segments left 0, and answer Parameter Problem, code 0, with segments left        | `End` drops with no answer a packet whose next segment is an address assigned to this node, whatever its Segments Left                                                                                                                                                                                                                                                                                      | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 4443 section 3.4                                         | Answer a header field that keeps a packet from being processed with Parameter Problem, naming its type and location (SHOULD)                     | `End` and `End.DT46` drop with no answer a packet ending inside its routing header or one ahead of it, and `End.DT46` one whose inner packet is shorter than its fixed header or not IP                                                                                                                                                                                                                     | None holds, since the SID answers the header refusals beside it, see ICMP answers                                                                                                                                                                                                                          |
| RFC 8200 sections 4 and 4.1                                  | Discard a packet that carries Next Header 0 in a header other than the IPv6 header, and answer Parameter Problem, code 1                         | `End` forwards and `End.DT46` decapsulates a packet whose hop-by-hop header follows a destination options or another hop-by-hop header ahead of the SRH                                                                                                                                                                                                                                                     | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8200 sections 4 and 4.2                                  | Process extension headers in order, and an unrecognized option by its type's 2 high bits: skip it, discard the packet, or discard and answer     | `End` and `End.DT46` read no option of a hop-by-hop or destination options header ahead of the SRH, so `End` forwards and `End.DT46` decapsulates a packet such an option says to discard                                                                                                                                                                                                                   | None holds: Linux acts on the options of a hop-by-hop header in the first place, see ICMP answers                                                                                                                                                                                                          |
| RFC 8200 section 4                                           | Answer an unrecognized Next Header value, and Next Header 0 outside the IPv6 header, with Parameter Problem, code 1 (SHOULD)                     | `End` and `End.DT46` drop with no answer a packet whose walk to the SRH meets a header of a kind they do not recognize, and `End.DT46` one whose SRH names a hop-by-hop header next                                                                                                                                                                                                                         | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8200 section 4.4, RFC 8986 section 4.1                   | At segments left 0, ignore a routing header of an unrecognized type, or stop processing the SRH, and proceed to the next header                  | `End` drops with no answer a packet whose SRH with segments left follows a routing header at segments left 0, an SRH or one of another type                                                                                                                                                                                                                                                                 | None holds, see ICMP answers                                                                                                                                                                                                                                                                               |
| RFC 8200 section 4.4, RFC 4443 section 3.2                   | Discard a packet larger than the link its routing header sends it onto, and answer it with Packet Too Big (MUST)                                 | `End` cuts a carried IPv4 packet without DF, drops with no answer one it cannot cut but for its options, and a segment whose SRH names anything but the IP packet behind it                                                                                                                                                                                                                                 | RFC 1812 has a router cut IPv4 and silently discard a bad header, and none holds for the rest, see ICMP answers                                                                                                                                                                                            |
| RFC 4443 sections 3.2, 3.3 and 3.4                           | Send Packet Too Big and Time Exceeded (MUST) and Parameter Problem (SHOULD) to the packet's source                                               | A SID's answers go only through a session, so none goes to a source an entry of this node's own reaches, this host or a network behind it among them                                                                                                                                                                                                                                                        | None holds but for a source only this node's own default reaches, which the mesh routes no reply to, see ICMP answers                                                                                                                                                                                      |
| RFC 8986 section 4.8, RFC 4443 section 3.4                   | Submit the inner packet to the FIB its upper-layer header type names, and answer a field that keeps a packet from being processed (SHOULD)       | Delivering to the mesh, `End.DT46` takes the inner packet's family from its version, not its Next Header, and an egress segment drops with no answer one where the two disagree                                                                                                                                                                                                                             | None holds, since the SID answers the header refusals beside it, see ICMP answers                                                                                                                                                                                                                          |
| RFC 8200 section 3, RFC 4443 section 3.4                     | Payload Length counts the octets after the IPv6 header, and a field keeping a packet from being processed gets Parameter Problem (SHOULD)        | An IPv6 packet whose Payload Length runs past its octets, or is 0 with octets after its header, is dropped with no answer, as a session delivers it or as `End.DT46` hands it to the mesh                                                                                                                                                                                                                   | A jumbogram fits no session, which covers the drop at 0 but not the silence, see Transit answers                                                                                                                                                                                                           |
| RFC 8754 section 7                                           | Admit at ingress only the sources of the attached networks, as BCP 38 does                                                                       | The border filter denies the mesh's own space from outside and admits the rest                                                                                                                                                                                                                                                                                                                              | The permit half needs first-hop source validation                                                                                                                                                                                                                                                          |
| RFC 8754 section 7                                           | Admit at ingress only the sources of the attached networks, as BCP 38 does                                                                       | A tun read from a source this node does not own, outside the overlay and covered by no route but one that counts as a default, passes toward a mesh destination                                                                                                                                                                                                                                             | Owning every source would drop the replies to an exit's egress and to a subnet router's LAN, since a tun read does not say whether it answers a flow                                                                                                                                                       |

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

Where the address has no route, each answer still tries it first, so answers
leave from it again as soon as a route returns. The session's own sends stay on
the kernel's choice until a fresh request after 1 minute, which a peer sends
once that traffic is lost. Where the session's ESP from the other address still
reaches the peer, the peer has no cause to probe, and the session stays there
until the peer's next request, such as a rekey.

On FreeBSD and OpenBSD the socket keeps no source, so every answer leaves from
the kernel's choice. Neither platform is supported beyond building.

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
algorithm. A peer's IKE SA rekey that does not offer the current PRF is refused
with `NO_PROPOSAL_CHOSEN`. Once a reload's `cap.crypto.ike.prf` leaves out the
PRF an IKE SA runs, no rekey of it is open, so the session deletes the IKE SA
and a new handshake under the new lists replaces it, as
[reloading](../reloading.md#capcrypto) describes.

An IKE SA rekey this node starts may run each `cap.crypto.ike.kex` entry that
keeps every ML-KEM method of the SA's entry while `kex` holds that entry, and
any `kex` entry once a reload left it out. An SA of `x25519+mlkem768` is then
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
holds it, and otherwise the first other cipher of its list that the offer holds.
A peer whose own lists left the cipher out offers only the others, and refusing
them would keep its SA on a cipher it removed. A reload whose list leaves the
cipher out moves the SA to a listed cipher at the rekey it forces. Both depart
from the same SHOULD NOT. Section 3.3.4 says "The implementation MUST reject SA
proposals that are not authorized by these IKE suite controls", which rules out
keeping a cipher the lists left out.

When a peer refuses a rekey with `NO_ADDITIONAL_SAS`,
[RFC 7296 section 4](https://www.rfc-editor.org/rfc/rfc7296.html#section-4)
requires that the node can delete the old SA and create a new one instead. Where
the peer's own rekey of the same IKE SA crossed this node's and this node
answered it, its SA is held, and ranet3 takes that SA, as it does after any
error notify but `INVALID_SYNTAX`. Otherwise ranet3 keeps the old SA and retries
the rekey on its backoff, from 5 seconds up to 5 minutes at the defaults, until
the SA's lifetime ends and the IKE SA is deleted with it, or until a rekey the
peer starts replaces the SA. Only `CHILD_SA_NOT_FOUND` makes it create a new
Child SA from scratch.

[RFC 7296 section 2.25.2](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.2)
asks an end that receives a rekey of an IKE SA it is rekeying itself to reply as
usual. Past the IKE SA's lifetime, ranet3 answers every rekey on it with
`TEMPORARY_FAILURE` instead, whatever it is running itself.
[Section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8) says that
once its lifetime expires, an SA "MUST NOT be used", and a rekey answered on it
would use its keys for the exchange and for the new SA's keys. Before the
lifetime, such a rekey is answered as usual, except while this end's own rekey
of the IKE SA has had its `CREATE_CHILD_SA` answered and runs its
`IKE_FOLLOWUP_KE` exchanges. ranet3 then answers the peer's rekey with
`TEMPORARY_FAILURE`, as
[RFC 9370 section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
requires for a rekey that arrives while "the CREATE_CHILD_SA exchange initiated
by this peer has already been completed, and the series of IKE_FOLLOWUP_KE
exchanges is in progress": "a TEMPORARY_FAILURE notification MUST be sent in
response to such a request."

[RFC 9370 section 2.2.4](https://www.rfc-editor.org/rfc/rfc9370.html#section-2.2.4)
has a responder delete the state of a rekey whose next `IKE_FOLLOWUP_KE` request
it "does not receive ... after some reasonable period of time", and says "In
general, 5-20 seconds of waiting time should be appropriate in most cases."
ranet3 waits 62 seconds, the time it resends 1 cut of a request to a silent peer
before it deems the IKE SA failed. A peer that resends as ranet3 does makes the
sends of its next request within those 62 seconds through a step to its family's
floor and 1 or 2 falls of the path MTU, the last at most 40 seconds after the
answer before it where its schedule's own sends see the falls and at most 52
where probes see them, and finds the state kept. A chain of falls can carry its
last send past them, 4 falls that probes see or 13 that the schedule's sends
see. ranet3's own rekey then fails as late and is retried, with no SA lost. The
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
waits for the exchange already out. That exchange gets the sends of a silent
peer whatever traffic the peer keeps up: 5 over about 62 seconds for 1 cut, a
request that fits its family's floor whole and one whose path already sits at
the floor included, 7 over 68 seconds for a request too large for the floor that
the step to it from a larger threshold cuts again, and more where the path MTU
falls, at most 20 counted sends, with a probe that cuts nothing adding sends it
does not count. A Delete of an IKE SA gets 2. The IKE SA is then deemed failed.
The peer's rekeys are answered `TEMPORARY_FAILURE`, and nothing else starts. A
replaced IKE SA this end deletes carries that Delete, which section 2.8 makes
the last request on the old SA, and takes its answer past the lifetime. When
both of its sends go unanswered, the replaced IKE SA alone is deemed failed,
since the new one holds its Child SAs.

An ESP batch that took a Child SA's keys before its lifetime finishes on them.
The keys leave the dataplane at the lifetime, and the batch holds the set of SAs
it started with, as every batch does across a rekey.

## Closing SAs

[RFC 7296 section 1.3.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.3.1)
says "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA".
ranet3 holds to that for a `CREATE_CHILD_SA` exchange. When the Child SA that
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
endpoint is no longer responding". ranet3 does so wherever the peer may still
answer, except in 4 cases where it closes without one:

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

Two closes come near these. A loaded configuration never reaches the close of
the session settings applied after `IKE_AUTH`, which refuse only what the
configuration's validation refuses. An answer to this end's own request that
does not decode after its integrity check closes the IKE SA as
[section 2.21.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.3)
closes one after a malformed request, without a Delete, since the 2 ends'
encodings disagree and a Delete's answer would come from the same encoder.

[Section 2.21.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.3)
says "After the IKE SA is authenticated, all requests having errors MUST result
in a response notifying the other end of the error." ranet3 answers a request
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

ranet3 sends a message larger than the path in the fragments of
[RFC 7383](https://www.rfc-editor.org/rfc/rfc7383.html) where both ends sent
`IKEV2_FRAGMENTATION_SUPPORTED`, and reassembles the peer's, as
[limits](limits.md#paths-under-1280-bytes) describes. It departs from the RFCs
in these places.

[Section 2.5.1](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.5.1) says
"If the sender has information about the PMTU size, it SHOULD use it." ranet3
reads the path MTU the host holds at each send, but never cuts for less than
1280 bytes over IPv6 or 576 over IPv4, the values the same section recommends
where the path MTU is unknown, though the host knows a smaller one. IPv6 carries
1280 on every link, and the section says of 576 that "the value is large enough
for the presented solution and small enough to avoid IP fragmentation in most
situations".

[Section 5](https://www.rfc-editor.org/rfc/rfc7383.html#section-5) recommends
bounding the "sum of the sizes of Encrypted Fragment payload contents (after
decryption)" in a reassembly queue. ranet3 bounds the stored fragments as the
IKE messages they arrived as instead, 16 KiB of them. Those hold more than their
content, and the bound covers what each fragment costs beside it. The bound
leaves the largest message a peer sends room at the IPv4 floor.

[Section 2.5.2](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.5.2) has
the initiator of an exchange probe smaller thresholds, coarse-grained. On Linux
and macOS ranet3 tries 2: the path MTU the host holds, read again at each send,
and the family's floor once the schedule's sends under a larger threshold went
unanswered twice, taken at the next send, the schedule's or a probe's. Where the
host's path MTU cannot be read, as on FreeBSD and OpenBSD, whose IKE leaves
without DF, only the floor is tried. After a step that cuts a request down to
the floor, taken on the path the request was readied or last cut on, which every
send of it went on since, the step's own included, the session's later
exchanges, its answers included, start at the floor, as the section's "In
subsequent exchanges, the node should start with the current value of the
fragmentation threshold" asks, across rekeys of the IKE SA. They start from the
path MTU the host reads again once a send or a status read finds the peer's
address or port or that reading changed since the step, or once the session is
asked to probe its path, as a network change or `ranet3 debug probe` asks. A
step carries nothing to later exchanges where a send of the request since its
readying or its last cut, the step's own included, found that the peer moved,
that the reading changed or that the session probed, even where the step finds
the path as it was then. Nor does a request that fits the floor whole, which
only moves its threshold at the step and keeps its schedule, since its lost
sends say nothing of larger datagrams and
[section 2.4](https://www.rfc-editor.org/rfc/rfc7383.html#section-2.4) finds "no
point in fragmenting liveness check messages". A path that widens where the host
sees no change keeps the floor until one of those comes or the session ends,
which the section's search, "performed downward", accepts: "Using these values
could lead to suboptimal fragmentation, but it is acceptable given the amount of
traffic IKE produces." Each new cut is the original message cut again, with a
larger Total Fragments, as the section asks, so a retransmission after it is not
bitwise identical to the first send, which
[RFC 7296 section 2.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1)
requires. Each new cut also starts the retransmission waits over, as section
2.5.2 requires ("the timers will start over"), where
[RFC 7296 section 2.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.4)
says "retransmission times MUST increase exponentially". The sends of a request
that ranet3 counts stay within 20 however it is cut, and a probe that cuts
nothing resends it without counting it.

A responder takes section 2.5.1's "may use the maximum size of the received IKE
Fragment message IP datagrams as a threshold when constructing a fragmented
response", for the first answer to a request in fragments and for a kept answer
a repeat draws again, never under the floor, with Total Fragments grown as
section 2.5.2 asks. A repeat whole carries no size and leaves the answer as it
stands, unless the session's threshold fell since the answer's cut, by a fall of
the path MTU or a request of ranet3's own stepping down to the floor, and the
answer is then cut again for that threshold with Total Fragments grown. An
answer cut for a wider path to a request that came whole thus never shrinks for
a repeat whole while the session's threshold holds, and where a hop narrower
than the path the host reads drops its datagrams and sends no ICMP message, the
exchange runs to its budget, unless an earlier step of a request of ranet3's own
holds the session at the floor, as above, after which its answers start at the
floor too. That stays because an answer no larger than a request that came whole
goes in datagrams no larger than that request, which the hop carried, and with
ML-KEM the request is at least as large as the answer in every exchange ranet3
runs. Elsewhere an answer passes its request by a few octets at most.

[RFC 7296 section 2.11](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.11)
says an implementation "MUST respond to the address and port from which the
request was received", and section 2.1 has a retransmitted request draw the
answer again. ranet3 answers a repeat of a request it has answered under 1 rule,
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
signed by RSA keys and shared key authentication. ranet3 supports neither.

The minimal profile of [RFC 7815](https://www.rfc-editor.org/rfc/rfc7815.html)
does not cover this. It describes an initiator only (section 1), and it carries
a raw public key in a CERT payload (Appendix B.2). ranet3 also answers as a
responder and sends no CERT payload. Refusing additional Child SAs with
`NO_ADDITIONAL_SAS` is within RFC 7296.

A node answers handshakes as a responder only when `link.listen` is set. A full
mesh needs every node to answer as well as dial.

Identities are compared by the endpoint they name rather than by their bytes.
ranet3 writes `O` and `CN` as `UTF8String`, while strongSwan picks the string
type from the value. The same name therefore reaches the wire in 2 encodings,
and an endpoint `auth.aliases` names by other IDs reaches it in more. AUTH signs
the bytes as received either way, so the ID only selects which key must verify
it. A responder asked in IDr for an ID other than a DN answers with the ID type
and data it was asked for, in its own encoding with RESERVED zero. Asked for a
DN, it answers with its own encoding of the DN.

## Errors outside an exchange

[RFC 7296 section 2.21.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.21.4)
says "If an error occurs outside the context of an IKE request (e.g., the node
is getting ESP messages on a nonexistent SPI), the node SHOULD initiate an
INFORMATIONAL exchange with a Notify payload describing the problem." ranet3
counts ESP on an SPI it does not hold in `ranet3_receive_refused_total`, drops
it and tells the peer nothing. ranet3 treats this as a known gap.

The same section says "A node receiving a suspicious message from an IP address
(and port, if NAT traversal is used) with which it has an IKE SA SHOULD send an
IKE Notify payload in an IKE INFORMATIONAL exchange over that SA." ranet3 drops
such a message and sends nothing over the SA. A node that answers every stray
datagram from a peer's address can be made to send over that SA by anyone able
to spoof the address, and liveness checks already find a dead SA. The section
warns of the same for the liveness checks such a message prompts: "An
implementation SHOULD limit the frequency of such tests to avoid being tricked
into participating in a DoS attack."

## Algorithms

ranet3 offers and accepts only these algorithms:

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
entered". ranet3 has neither. Its groups are elliptic curves fixed in code,
which no generator or modulus describes, and `cap.crypto.ike.kex` chooses among
them.

[Section 3.3.5](https://www.rfc-editor.org/rfc/rfc7296.html#section-3.3.5) says
that an implementation offered a cipher "with a larger key length" than it is
configured for "SHOULD accept the offer if it supports use of the longer key".
ranet3 refuses a key length its lists leave out, so a node whose `cipher` names
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
`PRF_HMAC_SHA2_512` (section 2.2) SHOULD+. ranet3 implements none of them. A
peer has to support at least 1 algorithm in each row of the table.

## Traffic selectors

Every Child SA carries exactly 2 traffic selectors on each side, the full IPv4
range and the full IPv6 range. ranet3 proposes those and accepts nothing else. A
request with any other selectors is refused with `NO_PROPOSAL_CHOSEN`. A
`CREATE_CHILD_SA` request whose TS payload does not parse or holds no selector
is malformed instead, and is answered `INVALID_SYNTAX` on an IKE SA that is not
busy, as [Closing SAs](#closing-sas) describes.
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

[RFC 4303 section 3.3.3](https://www.rfc-editor.org/rfc/rfc4303.html#section-3.3.3)
asks that an attempt to send past the last sequence number be logged with the
SPI, the date and time, the source and destination addresses and, for IPv6, the
Flow ID, and [section 4](https://www.rfc-editor.org/rfc/rfc4303.html#section-4)
adds the sequence number. ranet3 logs `ike Child SA ran out of sequence numbers`
once for each such SA, with both SPIs, both identities, the peer's address and
the sequence number, and the log line carries its own time. Its `src` names only
the local port. The socket is bound to the wildcard address. A session this node
dialed sends from the address the kernel picks for each datagram, which the
session never learns. A session the peer opened sends from the address its
request reached, and the log does not name that one either. No Flow ID is
logged. ranet3 sets no flow label, so the label on each outer IPv6 header is the
kernel's.

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
from them, coming from the packet's destination in both families, and so does
`End`'s IPv4 answer where the node holds no IPv4 router-id.
[Transit answers](#transit-answers) says where the forwarding decision's answers
depart.

A tun read's answer comes from the packet's destination because, where the host
routes that destination into the tun, that is the one source every check of the
sending host takes. The host drops an arriving packet from one of its own
addresses. Over IPv4 the kernel drops it unless `accept_local` is set, whatever
`rp_filter` holds (`fib_validate_source`, net/ipv4/fib_frontend.c:402-409 and
456-471 at Linux `940de590`). A reverse path check on nftables' `fib` finds no
interface for such a source in either family
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
`rp_filter` 2 takes it where the host has any route to 192.0.0.8, a default
route among them, and drops it where the host has none
(net/ipv4/fib_frontend.c:400-401 and 425-438). Every setting takes an answer
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

A SID admits a packet only where its outer source lies inside
`cap.border.overlay`, and an egress segment only where that source lies inside
its allow list as well. It drops any other packet with no answer before it reads
an extension header, as [Drops with no answer](#drops-with-no-answer) lists, so
each answer of a SID this section names is to a packet it admits, sent through a
session and within the limits this section gives below.

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
`940de590`).

The Time Exceeded and Parameter Problem a refused segment gets quote the
segment, go to its outer source, the headend, as RFC 2473 has a tunnel's node
answer, and come from the segment's destination. That address is one of this
node's SIDs, which is within the RFC. An IPv4 answer quotes as much of the
packet as fits 576 bytes
([RFC 1812 section 4.3.2.3](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.3)),
and an IPv6 answer as much as fits 1280 bytes
([RFC 4443 section 2.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)).

From a packet it admits, an `End.DT46`, whichever the SID delivers to, delivers
an IPv4 or IPv6 packet that follows the outer IPv6 header directly, or follows a
segment routing header at segments left 0 that the node reads, as
[segment routing](../segment-routing.md#local-segments) says, and an egress
segment only one that also passes the checks of
[egress segments](../segment-routing.md#egress-segments). In a packet it admits,
it answers a segment routing header behind at most 7 hop-by-hop and destination
options headers that fits in the packet but does not describe itself, whose last
entry runs past its length or, holding at most 16 segments, whose Segments Left
runs past its last entry, with a Parameter Problem, code 0, pointing at its
Segments Left field. That answer is RFC 8754's for a header with segments left,
and at segments left 0 it departs, as below. It drops every other packet with no
answer, among them a fragment and a packet whose segment routing header holds
more than 16 segments, whatever its Segments Left. That drop departs from each
requirement below. No reason holds for any of them but the drop of a fragment of
a larger packet, since the SID answers the header refusals beside them with a
Parameter Problem from the segment's destination, within the same limits. For a
segment routing header behind 8 or more hop-by-hop and destination options
headers, the bound on the headers the SID walks covers the drop and not the
silence, as below.

Three of the requirements are answers.
[RFC 8986 section 4.8](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.8)
has the node "Send an ICMP Parameter Problem to the Source Address with Code 0
(Erroneous header field encountered) and Pointer set to the Segments Left field"
for a segment routing header with segments left (S02 and S03). Its upper-layer
steps apply "When processing the Upper-Layer header of a packet matching a FIB
entry locally instantiated as an End.DT46 SID", and process an upper-layer
header other than IPv4 or IPv6 "as per Section 4.1.1" (S09 and S10), whose S04
is to "Send an ICMP Parameter Problem to the Source Address with Code 4 (SR
Upper-layer Header Error) and Pointer set to the offset of the Upper-Layer
header". That holds wherever the upper-layer header sits: right behind the IPv6
header, behind the segment routing header, or behind a hop-by-hop or destination
options header, with a segment routing header first or none.
[RFC 8200 section 4.4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.4)
says of a routing header whose type the node does not recognize, "If Segments
Left is non-zero, the node must discard the packet and send an ICMP Parameter
Problem, Code 0, message to the packet's Source Address, pointing to the
unrecognized Routing Type", such as a routing header of type 0, 2 or 200 at
segments left 1, alone or behind a hop-by-hop header.

Two are deliveries, past the extension headers a node passes. Section 4.8's
steps "When an SRH is processed" (S01) end "Proceed to process the next header
in the packet" (S05), and for an IPv4 or IPv6 upper-layer header it has the node
"Remove the outer IPv6 header with all its extension headers" (S02 and S06). RFC
8200 section 4.4 says of a routing header whose type the node does not
recognize, "If Segments Left is zero, the node must ignore the Routing header
and proceed to process the next header in the packet". The IPv4 or IPv6 packets
the SID drops include one behind a hop-by-hop or destination options header with
no segment routing header, one behind a routing header of another type with
segments left 0, one behind a destination options header after the segment
routing header, one behind an authentication header ahead of or behind the
segment routing header, one behind a segment routing header of 17 segments at
segments left 0, and one whose segment routing header sits behind 8 or more
hop-by-hop and destination options headers.

At segments left 0 the SID answers a segment routing header whose last entry
runs past its length, where the RFCs deliver the packet behind it.
[RFC 8754 section 4.3.1.1](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.3.1.1)
checks Last Entry only for a header with segments left (S05 to S13), and "If
Segments Left is equal to zero" has the node "Proceed to process the next header
in the packet, whose type is identified by the Next Header field in the routing
header" (S02 and S03). RFC 8986 section 4.8 answers only "If (Segments Left !=
0)" (S02) and otherwise has the node "Proceed to process the next header in the
packet" (S05), and section 4.1 has an `End` "Stop processing the SRH, and
proceed to process the next header in the packet" there (S02 and S03). The node
checks Last Entry against the header's length before it reads Segments Left, so
it answers such a header at segments left 0 as it does with segments left, at an
`End` too. No reason holds. At segments left 0 the node needs only the header's
Next Header and Hdr Ext Len, which it checks against the packet before Last
Entry, so a header whose last entry runs past its length still says where the
packet behind it starts. Linux's `End.DT46` takes such a header for none and
delivers the packet behind it (`seg6_validate_srh`, net/ipv6/seg6.c:44-47,
through `seg6_get_srh`, :102-103, and `decap_and_validate`,
net/ipv6/seg6_local.c:237-247 at Linux `940de590`).

The SID drops a fragment with no answer, wherever its Fragment header sits, an
atomic fragment included: one whose Fragment Offset and M flag are both zero.
[RFC 8200 section 4.5](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.5)
says "At the destination, fragment packets are reassembled into their original,
unfragmented form", and "If the fragment is a whole datagram (that is, both the
Fragment Offset field and the M flag are zero), then it does not need any
further reassembly and should be processed as a fully reassembled packet".
[Section 5](https://www.rfc-editor.org/rfc/rfc8200.html#section-5) says "A node
must be able to accept a fragmented packet that, after reassembly, is as large
as 1500 octets." The SID is the packet's destination. For an atomic fragment no
reason holds: it is the whole packet, and reading past its Fragment header costs
what reading past a destination options header costs. Linux's `End.DT46`
delivers one, since its header walk passes over a Fragment header at offset 0
(`input_action_end_dt46`, net/ipv6/seg6_local.c:1329, `decap_and_validate`,
:246, and `ipv6_find_hdr`, net/ipv6/exthdrs_core.c:243-272 at Linux `940de590`).
A fragment of a larger packet needs reassembly the SID does not do. Linux's
`End.DT46` puts none together either: it decapsulates a first fragment as it
stands, and drops a later one with no answer (net/ipv6/exthdrs_core.c:257 and
266-267, and net/ipv6/seg6_local.c:1199-1200 and 1277-1278).

An `End` sends a packet on to its next segment, as
[segment routing](../segment-routing.md#local-segments) says, where its outer
source lies in the overlay, the node reaches its segment routing header with
segments left as an `End.DT46` does, the header describes itself and holds at
most 16 segments, the hop limit is above 1, and the mesh routes the next segment
to another node. Where the next segment is a SID of this node, the node acts on
that SID in turn, as [segment routing](../segment-routing.md#local-segments)
says of a list naming several SIDs of one node in a row. Where the segment is
larger than the session to that node carries, it answers or cuts the packet the
segment carries, or drops the segment with no answer, as
[segment routing](../segment-routing.md#waypoints-and-packet-size) says. It
drops a segment, counted, where that session's budget has no room for it, as the
[dataplane](limits.md#dataplane) drops a tun read's packets, or where the
session has closed. Where its outer source lies in the overlay, it answers the
two refusals
[RFC 8986 section 4.1](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.1)
answers: a hop limit of 1 or less with a Time Exceeded (S06), and a segment
routing header that does not describe itself with the Parameter Problem, code 0,
above (S10), within the same bounds. It drops every other packet with no answer:
among them one at segments left 0 or with no segment routing header, one with a
routing header of another type, one whose Fragment header precedes its segment
routing header, one whose segment routing header sits behind an authentication
header or behind 8 or more hop-by-hop and destination options headers, one that
ends inside its routing header or a header ahead of it, one whose segment
routing header holds more than 16 segments, with segments left and at hop limit
1 too, and one whose next segment is no SID of this node and that the mesh
routes to no other node. That drop departs from the requirements below, and so
does the Parameter Problem where it comes at segments left 0, or in place of a
Time Exceeded at hop limit 1.

An `End` drops with no answer a routing header of another type with segments
left, such as one of type 0, 2 or 200 at segments left 1, alone or behind a
hop-by-hop header, since it acts on a segment routing header alone. RFC 8200
section 4.4 answers such a packet with the Parameter Problem above, and no
reason holds for this drop either.

An `End` reached at segments left 0 whose segment routing header describes
itself, or with no segment routing header, drops the packet with no answer too,
whatever its upper-layer header, an ICMPv6 echo request among them.
[RFC 8986 section 4.1](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.1)
has the node "Stop processing the SRH, and proceed to process the next header in
the packet" at segments left 0 (S02 and S03). Section 4.1.1 processes an
upper-layer header "If (Upper-Layer header type is allowed by local
configuration)" (S01), and otherwise has the node "Send an ICMP Parameter
Problem to the Source Address with Code 4 (SR Upper-layer Header Error) and
Pointer set to the offset of the Upper-Layer header" (S04). A waypoint SID is
not an address this node terminates traffic on, so `End` processes no
upper-layer header, as Linux's `End` processes none. Linux looks the segment
routing header up with `IP6_FH_F_SKIP_RH`, which passes over one at segments
left 0, and drops a packet in which it finds none with no answer
(`get_and_validate_srh`, net/ipv6/seg6_local.c:216-230, which passes the flag at
:220, `input_action_end_core`, :405-421, `seg6_get_srh`, net/ipv6/seg6.c:84-85,
and `ipv6_find_hdr`, net/ipv6/exthdrs_core.c:238-240 at Linux `940de590`). That
reason covers the drop, which section 4.1.1 allows, and not the silence, which
it does not, since `End` answers a spent hop limit (S06) and a header that does
not describe itself (S10) beside it, as above. No reason holds for the silence.

At segments left 0 an `End` answers a segment routing header whose last entry
runs past its length with the Parameter Problem RFC 8754 gives such a header
with segments left, which departs there as above. Linux's `End` drops it with no
answer, since its lookup passes over a header at segments left 0. An `End` also
drops with no answer a packet whose Fragment header comes ahead of its segment
routing header, an atomic fragment included, which departs from RFC 8200 as the
fragments above do, for the same reasons. Linux's `End` finds the segment
routing header past a Fragment header at offset 0 and acts on it
(`ipv6_find_hdr`, net/ipv6/exthdrs_core.c:243-272). With segments left, an `End`
checks Last Entry, the cap of 16 segments and Segments Left before the hop
limit, so at hop limit 1 it answers a segment routing header it reaches as above
and that fits in the packet, whose last entry runs past its length or, holding
at most 16 segments, whose Segments Left runs past its last entry, with the
Parameter Problem, code 0, rather than a Time Exceeded. RFC 8986 section 4.1
checks "If (IPv6 Hop Limit <= 1)" first and has the node "Send an ICMP Time
Exceeded message to the Source Address with Code 0 (Hop limit exceeded in
transit)" (S05 and S06), and only then "If ((Last Entry > max_LE) or (Segments
Left > Last Entry+1))" (S09). The node follows RFC 8754 section 4.3.1.1's order
for every SID, which checks "If ((Last Entry > max_last_entry) or" (S10) before
"If the IPv6 Hop Limit is less than or equal to 1" (S17). The two answers differ
only for a packet both malformed and out of hops. No reason holds, since section
4.1 is `End`'s own.

An `End` drops with no answer a packet whose segment routing header sits behind
an authentication header, since its walk to the routing header passes over
hop-by-hop and destination options headers alone, and one whose segment routing
header sits behind 8 or more of those, at hop limit 1 too, since the walk reads
at most 8 headers, the routing header the last of them. An `End.DT46` drops
both, among the deliveries above.
[RFC 8200 section 4.1](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.1)
says "IPv6 nodes must accept and attempt to process extension headers in any
order and occurring any number of times in the same packet, except for the
Hop-by-Hop Options header, which is restricted to appear immediately after an
IPv6 header only." RFC 8986 section 4.1 answers such a packet's spent hop limit
with the Time Exceeded above (S05 and S06), and otherwise has the node
"Decrement IPv6 Hop Limit by 1" through "Submit the packet to the egress IPv6
FIB lookup for transmission to the new destination" (S12 to S15). No reason
holds for the authentication header, which Linux's `End` walks past to act on
the segment routing header behind it (`ipv6_find_hdr`,
net/ipv6/exthdrs_core.c:273-276 at Linux `940de590`). The bound on the walk is
the node's own, so a sender cannot choose how much of the node's time one packet
costs. Linux bounds the same walk at 12 extension headers, so its `End` acts on
a segment routing header behind as many as 11 of them, and drops one behind more
with no answer (`IP6_MAX_EXT_HDRS_CNT`, include/net/ipv6.h:94, read at
net/ipv6/exthdrs_core.c:223-224, `seg6_get_srh`, net/ipv6/seg6.c:84-85, and
`input_action_end_core`, net/ipv6/seg6_local.c:410-412 and 418-420). That reason
covers the drop at both SIDs, and not the silence at either, since each answers
a header that does not describe itself beside it, and an `End` a spent hop limit
too, as above. No reason holds for that silence.

An `End` drops with no answer a packet whose segment routing header holds more
than 16 segments, with segments left, at hop limit 1 too, and with a Segments
Left past its last entry, since the node refuses such a list before it reads
Segments Left or the hop limit. RFC 8986 section 4.1 answers the spent hop limit
with the Time Exceeded above (S05 and S06) and the Segments Left past its last
entry with the Parameter Problem (S09 and S10), and otherwise forwards the
packet (S12 to S15).
[RFC 8754 section 4.3.1.1](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.3.1.1)
does the same in its own order, and ends "Resubmit the packet to the IPv6 module
for transmission to the new destination" (S22). A waypoint carries every segment
of a list on, 16 bytes in front of every packet, so the cap keeps the length of
the list it carries one the node chose rather than the sender. Linux's `End`
caps no list (`seg6_validate_srh`, net/ipv6/seg6.c:26-77), and answers a spent
hop limit after it moves the packet to its next segment (`advance_nextseg`,
net/ipv6/seg6_local.c:278-285, and `ip6_forward`,
net/ipv6/ip6_output.c:576-582). That reason covers the drop and not the silence,
since `End` answers both refusals for a shorter list. No reason holds for the
silence.

An `End` drops with no answer, too, a packet whose next segment is no SID of
this node and that the mesh routes to no other node: one no route covers, one
inside a held prefix, and one inside a prefix this node originates or at an
address assigned to it. RFC 8986 section 4.1 submits it to the FIB lookup for
its new destination (S15, above), and
[RFC 4443 section 3.1](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.1)
answers a packet no route carries with the Destination Unreachable, code 0,
[Drops with no answer](#drops-with-no-answer) quotes. The
[forwarding decision](../routing.md#transit) answers a destination no entry
holds, and one inside a held prefix, that way. An address `cap.table` assigns
this node is a local interface that is no SID, since the loader refuses a SID
there, and
[RFC 8754 section 4.3.2](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.3.2)
says, where the FIB entry "represents a local interface and is not locally
instantiated as an SRv6 SID", "If Segments Left is zero, the node must ignore
the routing header and proceed to process the next header in the packet, whose
type is identified by the Next Header field in the routing header." and "If
Segments Left is non-zero, the node must discard the packet and send an ICMP
Parameter Problem, Code 0, message to the packet's Source Address, pointing to
the unrecognized Routing Type." `End` drops such a next segment with no answer,
whatever its Segments Left. Linux's `End` answers a next segment no route covers
with that Destination Unreachable, and, outside a VRF, drops one at an address
of its own host with no answer, whatever its Segments Left
(`input_action_end_finish`, net/ipv6/seg6_local.c:400-402,
`seg6_lookup_nexthop`, :352, `seg6_lookup_any_nexthop`, :311-346, the null
route's `ip6_pkt_discard`, net/ipv6/route.c:298-299 and 4656-4663, a local
route's loopback device outside a VRF, :1063-1073, and the blackhole route,
:319-326). No reason holds, since `End` answers a spent hop limit and a header
that does not describe itself beside it, as above.

An `End` and an `End.DT46` drop with no answer a packet that ends inside its
routing header or a header ahead of it: one whose hop-by-hop or destination
options header runs past its end, one whose routing header is shorter than its 8
octet fixed part, and one whose segment routing header is shorter than its Hdr
Ext Len says. An `End.DT46` also drops one that ends where its inner packet
should start, and, whichever the SID delivers to, one whose inner packet is
shorter than the fixed header of its version, 20 octets for IPv4 and 40 for
IPv6, or is of neither version. From a packet it admits, the SID delivering to
the mesh hands such an inner packet to the
[forwarding decision](../routing.md#transit), which drops it as invalid, and an
egress segment refuses it.
[RFC 4443 section 3.4](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.4)
says "If an IPv6 node processing a packet finds a problem with a field in the
IPv6 header or extension headers such that it cannot complete processing the
packet, it MUST discard the packet and SHOULD originate an ICMPv6 Parameter
Problem message to the packet's source, indicating the type and location of the
problem." In each of these packets a field of the IPv6 header or an extension
header names what the packet does not hold: a length that runs past its end, a
Next Header naming a header or an inner packet that the packet ends inside or
before, or one naming an IPv4 or IPv6 packet where there is none. Linux drops
each with no answer too, but for the inner packet of neither version. Its `End`
drops a packet in which `seg6_get_srh` finds no segment routing header that fits
(net/ipv6/seg6.c:84-95, and `input_action_end_core`,
net/ipv6/seg6_local.c:410-412 and 418-420 at Linux `940de590`), its header walk
failing where the packet ends before a header's first octets (`ipv6_find_hdr`,
net/ipv6/exthdrs_core.c:226-228 and 233-236). Its `End.DT46` drops one whose
headers it cannot walk or pull past, or whose inner packet is shorter than its
header (`input_action_end_dt46`, net/ipv6/seg6_local.c:1329-1331,
`decap_and_validate`, :246-250, and `input_action_end_dt4` and
`input_action_end_dt6`, :1199-1203 and 1277-1281), and reads an inner packet of
neither version as the family its Next Header names, checking no version
(`input_action_end_dt46`, :1333-1338, `input_action_end_dt4`, :1213-1215, and
`input_action_end_dt6`, :1288-1299). A hop-by-hop header right behind the IPv6
header is read on input ahead of both, and one that runs past the packet is
dropped there (`ipv6_parse_hopopts`, net/ipv6/exthdrs.c:1066-1071, from
`ip6_rcv_core`, net/ipv6/ip6_input.c:320-325). No reason holds, since the SID
answers the header refusals beside them with a Parameter Problem from the
segment's destination, within the same limits, as above.

An `End` and an `End.DT46` walk hop-by-hop and destination options headers in
any order to reach the segment routing header, a hop-by-hop header after the
first place among them, so an `End` forwards a packet whose hop-by-hop header
follows a destination options header, and an `End.DT46` decapsulates it,
whichever the SID delivers to, where the packet passes their other checks above.
[RFC 8200 section 4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4) has
a destination node that meets a Next Header value it does not recognize "discard
the packet and send an ICMP Parameter Problem message to the source of the
packet, with an ICMP Code value of 1", and says "The same action should be taken
if a node encounters a Next Header value of zero in any header other than an
IPv6 header." Section 4.1, quoted above, restricts the hop-by-hop header "to
appear immediately after an IPv6 header only". Linux's `End` and `End.DT46` pass
it the same way, since `ipv6_find_hdr` takes a hop-by-hop header wherever it
sits (net/ipv6/exthdrs_core.c:18 and 212-284 at Linux `940de590`), from
`seg6_get_srh` (net/ipv6/seg6.c:84) and from `input_action_end_dt46` and
`decap_and_validate` (net/ipv6/seg6_local.c:1329 and 246). No reason holds.

An `End` and an `End.DT46` read no option of the hop-by-hop and destination
options headers they walk past to the segment routing header, only each header's
Next Header and Hdr Ext Len. So an `End` forwards, and an `End.DT46`
decapsulates, whichever the SID delivers to, a packet whose header there holds
an option of a type the node does not recognize, whatever its action, where the
packet passes their other checks above, and an `End` at hop limit 1 answers it
with the Time Exceeded above.
[RFC 8200 section 4](https://www.rfc-editor.org/rfc/rfc8200.html#section-4) says
"extension headers must be processed strictly in the order they appear in the
packet" and "a receiver must not, for example, scan through a packet looking for
a particular kind of extension header and process that header prior to
processing all preceding ones", and
[section 4.2](https://www.rfc-editor.org/rfc/rfc8200.html#section-4.2) says the
Option Type's "highest-order 2 bits specify the action that must be taken if the
processing IPv6 node does not recognize the Option Type": 01 to "discard the
packet", and 10 to "discard the packet and, regardless of whether or not the
packet's Destination Address was a multicast address, send an ICMP Parameter
Problem, Code 2, message to the packet's Source Address, pointing to the
unrecognized Option Type", with 11 doing so "only if the packet's Destination
Address was not a multicast address".
[RFC 8986 section 4](https://www.rfc-editor.org/rfc/rfc8986.html#section-4)
processes the header chain of a packet to a SID "as defined in Section 4 of
[RFC8200]". Linux reads a hop-by-hop header in the first place on input, before
the route lookup that hands the packet to `seg6local`, and acts on an option it
does not recognize as the option's type says (`ip6_rcv_core`,
net/ipv6/ip6_input.c:320-326, `ipv6_parse_hopopts`,
net/ipv6/exthdrs.c:1054-1087, `ip6_parse_tlv`, :190-194, and
`ip6_tlvopt_unknown`, :79-97 at Linux `940de590`). It processes no destination
options header on that path: their handler runs on local delivery alone
(`ipv6_destopt_rcv`, net/ipv6/exthdrs.c:296-340, registered at :863 and called
from `ip6_protocol_deliver_rcu`, net/ipv6/ip6_input.c:479), which a `seg6local`
route's input takes the place of (net/ipv6/route.c:1148-1159 and
include/net/lwtunnel.h:144-146), and its `End` and `End.DT46` walk past such a
header by its length alone (`ipv6_find_hdr`, net/ipv6/exthdrs_core.c:278). No
reason holds.

An `End` and an `End.DT46` drop with no answer a packet whose walk to the
segment routing header meets a header of a kind the node does not recognize,
such as a Mobility header (135) or an experimental one (253), with a segment
routing header behind it or none, since the walk passes hop-by-hop and
destination options headers alone. An `End.DT46` also drops with no answer one
whose segment routing header names a hop-by-hop header next. RFC 8200 section 4
answers both with the Parameter Problem, code 1, quoted above. Linux's `End` and
`End.DT46` drop the first with no answer too, since `ipv6_find_hdr` stops at a
kind `ipv6_ext_hdr` does not list (net/ipv6/exthdrs_core.c:13-24 and 217-221 at
Linux `940de590`): its `End` finds no segment routing header there
(`input_action_end_core`, net/ipv6/seg6_local.c:410-412), and its `End.DT46` an
upper-layer header it does not deliver (:1333-1342). Its `End.DT46` delivers the
second, since that walk takes a hop-by-hop header wherever it sits, as above. No
reason holds, since the SID answers the header refusals beside them, as above.

An `End` drops with no answer a packet whose segment routing header with
segments left follows a routing header at segments left 0, a segment routing
header or one of another type, since its walk ends at the first routing header.
RFC 8200 section 4.4, quoted above, has a node that meets a routing header of an
unrecognized type at segments left 0 "ignore the Routing header and proceed to
process the next header in the packet", and RFC 8986 section 4.1 has an `End` at
segments left 0 "Stop processing the SRH, and proceed to process the next header
in the packet" (S02 and S03), so the segment routing header behind it would move
the packet on. Linux's `End` does, since its lookup passes over every routing
header at segments left 0 (`get_and_validate_srh`, net/ipv6/seg6_local.c:220,
through `seg6_get_srh`, net/ipv6/seg6.c:84, and `ipv6_find_hdr`,
net/ipv6/exthdrs_core.c:238-240 at Linux `940de590`). An `End.DT46` drops such a
packet with no answer too, where RFC 8986 section 4.8 answers the segment
routing header with segments left, as above. No reason holds.

Sending a segment on as above, an `End` cuts an IPv4 packet without DF that the
segment carries into fragments where the segment is larger than the session to
its next segment, as
[segment routing](../segment-routing.md#waypoints-and-packet-size) says. It
drops with no answer such a packet whose header fails RFC 1812 section 5.2.2's
checks, whose data runs past 65535 octets or for which the session leaves no
room for 8 octets of data behind its header, and a segment whose routing header
names anything but the IP packet behind it, such as one a sender put into its
own packet ahead of its transport header.
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
the rest of the silence. A segment whose routing header names its own transport
comes from the sender of that packet, and `End` answers that same source's spent
hop limit beside it. Linux's `End` answers every such segment with a Packet Too
Big to its source, as above.

Every answer of a SID goes back through the session the mesh routes the answered
source to, while that session is open and has room for it: the Time Exceeded and
Parameter Problem a refused segment gets, and the answer to a segment larger
than its next session. So a SID sends none to a source an entry of this node's
own reaches, where the forwarding decision answers this host or a network behind
it into the tun, as [Transit answers](#transit-answers) says. Such a source is
this node's own, as where a segment list it steered comes back to it, or an
overlay source a peer forged. RFC 4443 sends each answer to the packet's source:
the Packet Too Big of section 3.2 and the Parameter Problem of section 3.4, both
quoted above, and the Time Exceeded of
[section 3.3](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.3), where a
router that takes a hop limit to zero "MUST discard the packet and originate an
ICMPv6 Time Exceeded message with Code 0 to the source of the packet". For a
source only this node's own default reaches, the decision's reason holds here
too: the mesh routes no reply to it, and the host would send the answer out of
its uplink. No reason holds for the rest.

From a packet it admits, an `End.DT46` delivering to the mesh hands the
forwarding decision an inner packet whose version and the Next Header in front
of it disagree, and the decision takes it as a packet of its version's family,
an IPv4 packet behind a Next Header of 41 as IPv4. An egress segment refuses
such a packet with no answer, counted refused.
[RFC 8986 section 4.8](https://www.rfc-editor.org/rfc/rfc8986.html#section-4.8)
has the node, "If (Upper-Layer header type == 4(IPv4) )", "Submit the packet to
the egress IPv4 FIB lookup for transmission to the new destination" (S01 to
S04), and use the IPv6 lookup for type 41 (S05 to S08), and RFC 4443 section 3.4
has a node discard a packet a header field keeps it from processing and answer
it with a Parameter Problem, as quoted above. Linux's `End.DT46` takes the
family its Next Header names (`input_action_end_dt46`,
net/ipv6/seg6_local.c:1329-1338, and `end_dt_vrf_core`, :1159-1179 at Linux
`940de590`). No reason holds, since the SID answers the header refusals beside
it, as above.

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
or the packet steered, and the forwarding decision hands one a session delivers
to the tun, as [routing](../routing.md#transit) says. So the one packet to a
group that can meet a session too small for it is one a segment carries, which a
ranet3 headend never steers. `End` drops such a segment with no Packet Too Big,
since no ICMPv6 error ranet3 builds answers a packet to a group.

An ICMPv6 error behind 8 extension headers or more is answered.
[RFC 4443 section 2.4 (e)](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
says "An ICMPv6 error message MUST NOT be originated as a result of receiving
the following", and the first of them, (e.1), is "An ICMPv6 error message". To
find a packet's ICMPv6 header, ranet3 steps over its extension headers as the
Linux kernel does, and reads at most 8 headers, the upper-layer header the last
of them. A packet whose chain runs longer is answered as one that is not an
error. Refusing it would withhold the Time Exceeded and Packet Too Big that
sections 3.2 and 3.3 require from a packet nothing shows to be an error. The
kernel reads 13 headers, so it refuses an error behind 8 to 12 extension headers
that ranet3 answers. An error ranet3 builds carries its ICMPv6 header right
after the IPv6 header, so two ranet3 nodes never answer each other's errors this
way. The case needs a sender that puts its error behind 8 headers, and the
answers to it draw on the rate limits below like any other.

The rate limits on these answers are fixed in code.
[RFC 4443 section 2.4 (f)](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.4)
says:

> The rate-limiting parameters SHOULD be configurable. In the case of a
> token-bucket implementation, the best defaults depend on where the
> implementation is expected to be deployed (e.g., a high-end router vs. an
> embedded host).

[RFC 1812 section 4.3.2.8](https://www.rfc-editor.org/rfc/rfc1812.html#section-4.3.2.8)
says "The rate limit parameters SHOULD be settable as part of the configuration
of the router". ranet3 takes the limits of the Linux kernel, which sent these
answers before ranet3 did: a bucket for each source of a packet answered and a
cap for the node, as [path MTU](../path-mtu.md#packets-that-do-not-fit) gives
them. Their intervals, burst and cap are the kernel's defaults, and the number
of sources a node keeps buckets for is ranet3's own. The defaults the RFC ties
to a deployment are a single bucket's. With a bucket per source, a node's budget
grows with the senders it answers, so a hub answering many gets more than a
leaf, and a sender's flood of expired or refused packets spends only its own
bucket. The cap bounds what a flood from many sources costs the smallest node.
No deployment has needed other values, and a setting comes with the first that
does. The kernel leaves Packet Too Big and fragmentation needed out of both its
limits. ranet3 leaves them out of the buckets only, since the same section says
a node "MUST limit the rate of ICMPv6 error messages it originates". One address
can stand for many hosts behind a NAT, and a bucket would hold back path MTU
discovery for all of them. Under the cap alone, one sender's packets past their
session at the cap's rate hold back every answer.

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
a drop whose answer finds no route back is. The mesh routes no reply to such a
source, and the host would send the answer out of its uplink from another node's
address. The one exception is the Destination Unreachable with code 2 that
answers an IPv6 packet from a link-local source to a wider unicast destination a
router forwards, RFC 4443 section 3.1. It goes back on the session the packet
came by, never by a reply route, so it reaches the source's own link and no
stranger.

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
drops and counts such an inner packet that an `End.DT46` hands it the same way,
as invalid.
[RFC 8200 section 3](https://www.rfc-editor.org/rfc/rfc8200.html#section-3)
defines Payload Length as the "Length of the IPv6 payload, i.e., the rest of the
packet following this IPv6 header, in octets", and RFC 4443 section 3.4 answers
a header field that keeps a packet from being processed with a Parameter
Problem, as [ICMP answers](#icmp-answers) quotes. A Payload Length of 0 belongs
to a jumbogram, which no session carries, so the node refuses such a packet
rather than cut it to its header, where Linux's `ip6_rcv_core` cuts it to its
header unless a hop-by-hop header follows (net/ipv6/ip6_input.c:308-317 at Linux
`940de590`). That covers the drop at 0, and not the silence. Linux drops a
packet whose Payload Length runs past its octets with no answer too (:309-314).
No reason holds for the silence. An egress segment hands such an inner packet
that passes the checks of
[egress segments](../segment-routing.md#egress-segments) to the exit as it came.
The exit writes it into the tun, and the host's `ip6_rcv_core` then drops one
whose Payload Length runs past its octets and cuts one of length 0 to its
header, as above.

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
would show the mesh to a sender outside it never reach the decision: the border
filter and the SIDs drop them first, with no answer, as
[Drops with no answer](#drops-with-no-answer) lists.

The answer to a read off the tun with no route or inside a hold cannot be turned
off either. The host itself routed the packet into the tun, and the answer goes
only back into the tun, to the host that sent the packet, which delivers it or
forwards it toward its source, and never onto a session.

Every transit answer draws on the bucket of the answered packet's source and on
the node's cap, a Packet Too Big or Fragmentation Needed on the cap alone, as
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

| RFC 8966 section                | The RFC says                                                                                                          | ranet3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3.5.3, and RFC 9079 section 5.1 | Create a route table entry for each finite update a neighbor sends                                                    | Drops it when its destination and source are a prefix this node announces or an address `cap.table` assigns, and when its destination is a host address of this node's, whatever its source                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| 3.5.3                           | Create a route table entry for each finite update a neighbor sends                                                    | Drops it when the router-id it takes is all zeroes or all ones, and leaves a route already learned from that neighbor as it was until it expires                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 3.5.4                           | End the hold of a retracted prefix once every neighbor acknowledges a retraction sent with an acknowledgment request  | Keeps it until the route's expiry timer runs out and, once the prefix has lost its last route, until the latest time any update this node sent naming it reachable expires at a neighbor, if that is later                                                                                                                                                                                                                                                                                                                                                                                                                              |
| 3.5.4                           | Forward no packet inside a held prefix by following a route for a shorter prefix                                      | Drops and answers each packet the tun hands it inside a hold, but one a steering policy takes or the checks at the mesh's edge drop, and each a peer sends, but the kernel keeps no hold that counts as a default, and a packet the host sends or forwards inside one takes the host's routes, while a packet inside any other hold ends where [where a lookup ends on Linux](../routing.md#where-a-lookup-ends-on-linux) and [on macOS](../routing.md#where-a-lookup-ends-on-macos) give, refused at a hold at rows L4, L9 and D3, at 5410 where main's best default is a refusal at row L7, and for want of a route at rows B2 and B4 |
| 3.7.2                           | Make a reasonable attempt to reach every neighbor with a triggered update or retraction                               | Sends it once, with no acknowledgment and no repeat                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| 3.8.1.1                         | Send an update for a requested prefix that has a selected route                                                       | Sends a retraction when the selected route's next hop is the requester                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 3.8.1.2                         | Send an update for a seqno request the selected route satisfies                                                       | Forwards the request instead when the selected route's next hop is the requester                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| 3.8.1.2                         | Forward a seqno request only while advertising the prefix                                                             | Forwards it whenever it has a route to the prefix                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| 3.8.1.2                         | Forward a seqno request it cannot satisfy to the next hop of a feasible route, or failing that of an unfeasible route | Forwards none whose router-id is all zeroes or all ones, and answers it as any other request                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| 3.8.2.3                         | Send a route request to the neighbor shortly before a selected route expires                                          | Sends none                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Appendix A.3                    | Smooth the metric as an exponential average                                                                           | Follows an increase at once and smooths only improvements                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |

[RFC 8966 section 3.5.3](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.5.3)
has a node that holds no entry for an update's prefix and neighbor create one:
"a new entry is created in the route table, indexed by (prefix, plen, neigh),
with source equal to (prefix, plen, router-id), seqno equal to seqno, and an
advertised metric equal to the metric carried by the update". The sentence
carries no BCP 14 keyword.
[RFC 9079 section 5.1](https://www.rfc-editor.org/rfc/rfc9079.html#section-5.1)
has a node receiving a source-specific update behave "as described in [RFC8966],
Section 3.5.3, except that the entry under consideration is indexed by (prefix,
plen, sprefix, splen, neigh)". ranet3 drops an update whose destination and
source prefix are those of a prefix it announces, or of the host route of an
address `cap.table` assigns it, so a route a neighbor offers for one never
enters the route table. It treats each of them as directly attached, as the stub
implementation of
[Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E) does, which
"always prefers the direct route to a directly attached prefix to a route learnt
over the Babel protocol, even when the prefixes are the same". It also drops an
update whose destination is a host address of its own, a `/32` or `/128` it
announces or `cap.table` assigns, whatever the update's source prefix. The
host's kernel delivers its own address whatever the source, and a neighbor
offering a route to it is misconfigured or claiming this node's address. For a
wider prefix, a source-specific route a neighbor offers for the same destination
has another source prefix, so it is learned, and by the "destination-first
ordering" of
[RFC 9079 section 4](https://www.rfc-editor.org/rfc/rfc9079.html#section-4) it
is preferred for packets from its source.

[RFC 8966 section 4.1.3](https://www.rfc-editor.org/rfc/rfc8966.html#section-4.1.3)
says "A router-id MUST NOT consist of either all binary zeroes (0000000000000000
hexadecimal) or all binary ones (FFFFFFFFFFFFFFFF hexadecimal)." ranet3 takes no
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
hop of one such route". ranet3 forwards no seqno request whose router-id is all
zeroes or all ones, through a feasible route or an unfeasible one, since the
forwarded request would carry it, and answers one as it answers any other.

[RFC 8966 section 3.5.4](https://www.rfc-editor.org/rfc/rfc8966.html#section-3.5.4)
gives 2 ways to end the hold of a retracted prefix: "waiting until the route's
expiry timer has expired", or "sending a retraction with an acknowledgment
request (Section 3.3) to every reachable neighbour that has not explicitly
retracted prefix P, and waiting for all acknowledgments", of which "The latter
option is RECOMMENDED". ranet3 takes the former, for the reason the section
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
`cap.border.overlay` at a route of main longer than /0 that covers it, row L6,
refused at 5410 where main's best default is a refusal, row L7, from a socket
carrying the underlay's mark, row L2, from a socket bound to a device, rows B1
to B4, refused there for want of a route at B2 and B4, and on macOS from a
socket bound to no interface and no address of the tun, rows D1 and D2. Where
another program's rule comes first, it ends as
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

## The border filter

[RFC 8754 section 4.2](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.2)
says of a node that is not the destination of a packet with a segment routing
header:

> Any other transit node MUST NOT inspect the underneath routing header and MUST
> forward the packet toward the DA according to its IPv6 routing table.

[The border filter](../border-filter.md) drops every IPv6 packet carrying a
routing header of any type that arrives on a link outside the mesh, whatever its
destination and its segments. The mesh is the segment routing domain and a node
with the filter is its edge, which
[section 5.1](https://www.rfc-editor.org/rfc/rfc8754.html#section-5.1) asks to
drop any packet entering the domain for a SID of the domain. Before typed SIDs a
node cannot tell which destinations are SIDs, and a header naming another node's
SID is the same forgery one hop later, so it drops the header whatever it names.
A node that is a transit router for another segment routing domain between 2
links outside the mesh loses that traffic. No deployment here is one. The drop
also takes another domain's packet routed from outside into the mesh, and a
packet from outside addressed to one of this node's own addresses that is not a
SID, which
[section 4.3.2](https://www.rfc-editor.org/rfc/rfc8754.html#section-4.3.2) has
the node process:

> If Segments Left is zero, the node must ignore the routing header and proceed
> to process the next header in the packet, whose type is identified by the Next
> Header field in the routing header.

The filter drops routing headers of types 0 and 2 too, since nf_tables finds
only the first routing header of a packet, and either would otherwise carry a
segment routing header past it.
[RFC 5095 section 3](https://www.rfc-editor.org/rfc/rfc5095.html#section-3) has
a node that receives a type 0 header treat it as an unrecognised type:

> If Segments Left is zero, the node must ignore the Routing header and proceed
> to process the next header in the packet, whose type is identified by the Next
> Header field in the Routing header.

So a node goes on to the segment routing header behind a type 0 header with no
segments left.
[Section 4.2](https://www.rfc-editor.org/rfc/rfc5095.html#section-4.2) says that

> Firewall policy intended to protect against packets containing RH0 MUST NOT
> simply filter all traffic with a Routing Header

and goes on:

> In addition, the default configuration MUST permit forwarding of traffic using
> a Routing Header other than 0.

The filter is off until a file writes `cap.border`, and with it on, Mobile IPv6
traffic carrying a type 2 header across 2 links outside the mesh is lost. No
deployment here carries any. From Linux 7.1 the kernel's search for a routing
header gives up at the 13th extension header, so the filter passes a routing
header behind 12 others. A Linux host from 7.1 with `seg6_enabled` set acts on a
segment routing header 13th in the chain and drops a packet whose routing header
sits further back. This node's own SIDs drop both with no answer, whatever the
outer source, since they look for the routing header behind at most 7 hop-by-hop
and destination options headers, as
[segment routing](../segment-routing.md#local-segments) describes. Before 7.1
neither search has a limit: the filter finds a routing header anywhere in the
chain, and the host acts on one anywhere.

The filter carries out section 5.1's first access list for this node's own SIDs.
Every local SID carries out the second, refusing a packet whose outer source
lies outside the IPv6 prefixes of `cap.border.overlay`, as
[segment routing](../segment-routing.md#local-segments) describes, so a host
beyond the mesh reaches no SID through a node with the filter. A node that
forwards without `cap.border` is only warned at load, and passes a forged
overlay source on to every SID.

Section 5.1's level 1, that a packet entering the domain addressed to a SID
within it is dropped, governs the tun as much as the links outside, since a
packet the host's own kernel routes into the tun enters the domain there. The
forwarding decision meets it in three places. It walks each IPv6 read and drops
one carrying a routing header of type 0, 1 or 4, the segment routing header, or
of a type it does not recognize. It drops a read addressed to one of this node's
own SIDs. And for another node's SID, which it cannot recognize by address since
the mesh keeps no registry of other nodes' SIDs, it opens every IPv6 read whose
chain ends at an inner IPv4 or IPv6 packet one level deep, whatever its
destination, and checks what ranet3's own SIDs would decapsulate, so a forged
inner source reaches no exit of the mesh. [The limits](limits.md#transit) say
what another implementation's `End.DT46` may decapsulate past the walk.
[Segment routing](../segment-routing.md#at-the-border-of-the-mesh) describes
these checks, and [Drops with no answer](#drops-with-no-answer) lists them.

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

The border filter applies the other half. It drops a source inside
`cap.border.overlay` arriving from outside the mesh, and passes every other
source from every link outside it, since those links lead to the internet and no
prefix list describes them. That keeps a forged mesh source out of the mesh, and
it is not BCP 38's filter, so section 7 is met in part. The permit half, taking
from each peer only the prefixes it holds, needs first-hop source validation,
which this version does not have.

The tun is the domain's ingress for what a host forwards into the mesh, and the
forwarding decision filters its sources in part. It drops a source the table
routes to another node or holds unreachable, through a route that does not count
as a default, and an overlay source this node does not own, and toward a route
that counts as a default it drops any source this node does not own. A source
this node does not own, outside the overlay and covered by no route but one that
counts as a default, passes toward a mesh destination. Owning every source would
drop the replies to an exit's egress and to a subnet router's LAN, since a tun
read does not say whether it answers a flow.

## Exit translation

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

An echo identifier is mapped as a port is, so the same clash departs from
[RFC 5508 section 3.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-3.1),
which says "NAT mapping of ICMP Query Identifiers SHOULD be external-host
independent".

[RFC 5508 section 4.1](https://www.rfc-editor.org/rfc/rfc5508.html#section-4.1)
says "If the IP checksum of the embedded packet fails to validate, the NAT
SHOULD silently drop the Error packet". The kernel exit translates such an error
and passes it on, since Linux checks only the outer ICMP checksum.

A connection whose inside port is free toward its destination leaves from that
port, so the port keeps its parity. On a clash the kernel exit takes another
port, starting at a random offset in the range the inside port falls in, and
that port has either parity. No nf_tables statement asks for a port of the same
parity.
[RFC 4787 section 4.2.2](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.2.2)
says:

> REQ-4: It is RECOMMENDED that a NAT have a "Port parity preservation" behavior
> of "Yes".

The section gives parity for RTP implementations that do not read an RTCP port
their peer names separately, and says "It is expected that this issue will fade
away with time, as implementations improve".

[RFC 5382 section 5](https://www.rfc-editor.org/rfc/rfc5382.html#section-5)
says:

> REQ-5: If a NAT cannot determine whether the endpoints of a TCP connection are
> active, it MAY abandon the session if it has been idle for some time. In such
> cases, the value of the "established connection idle-timeout" MUST NOT be less
> than 2 hours 4 minutes. The value of the "transitory connection idle-timeout"
> MUST NOT be less than 4 minutes.

The kernel exit keeps the host's connection tracking timeouts and sets none of
its own. An idle established connection is kept 5 days, but 5 minutes while data
it carried is unacknowledged or a window is closed. An opening connection is
kept 2 minutes after its SYN and 60 seconds after the answer, and a closing one
2 minutes, 60 seconds or 30 seconds, as far as the close has gone. A connection
in TIME_WAIT or reset is outside the requirement, which leaves both unspecified.
A known gap: a connection tracking timeout policy on the exit's own connections
could hold the requirement, and the exit installs none.

[RFC 4787 section 4.3](https://www.rfc-editor.org/rfc/rfc4787.html#section-4.3)
says:

> REQ-5: A NAT UDP mapping timer MUST NOT expire in less than two minutes,
> unless REQ-5a applies.

Its item c says "A default value of five minutes or more for the NAT UDP mapping
timer is RECOMMENDED." The kernel exit keeps the host's connection tracking
timeouts for UDP as for TCP, and sets none of its own. At the kernel's defaults,
a UDP flow with no reply yet is kept 30 seconds after its last packet, and so is
one whose packets all came within 2 seconds of its first. Once a reply has come,
a packet more than 2 seconds after the first keeps the flow 2 minutes, and so
does every packet after it. The timeouts are the same for every port, so
REQ-5a's shorter timers for well-known destination ports do not cover the 30
seconds. A known gap: a connection tracking timeout policy on the exit's own
connections could hold the requirement, and the exit installs none.

[RFC 5508 section 3.2](https://www.rfc-editor.org/rfc/rfc5508.html#section-3.2)
says:

> REQ-2: An ICMP Query session timer MUST NOT expire in less than 60 seconds.

The kernel exit keeps the host's ICMP and ICMPv6 timeouts and sets none of its
own. At the kernel's defaults, a query session, an echo among them, is kept 30
seconds after its last request or reply. A known gap: a connection tracking
timeout policy on the exit's own connections could hold the requirement, and the
exit installs none.

[RFC 5508 section 6](https://www.rfc-editor.org/rfc/rfc5508.html#section-6)
says:

> REQ-8: When a NAT device is unable to establish a NAT Session for a new
> transport-layer (TCP, UDP, ICMP, etc.) flow due to resource constraints or
> administrative restrictions, the NAT device SHOULD send an ICMP destination
> unreachable message, with a code of 13 (Communication administratively
> prohibited) to the sender, and drop the original packet.

When the host's connection table is full, connection tracking first evicts a
connection that is not yet assured, from the 8 hash buckets the new one starts
at, and with none to evict it drops the packet with no answer. A new connection
whose translated ports are still taken when it is confirmed, in a clash the
kernel cannot resolve, is dropped the same way. Both drops happen inside
connection tracking, so no rule of the exit's sees the packet to answer it. The
section says the requirement "is meant primarily for future use. Current
applications do not require this for them to work correctly." The eviction is
the design the same section discourages:

> Some NAT designers opt to never reject an outbound flow. When a NAT runs short
> of resources, they prefer to steal a resource from an existing NAT Session
> rather than reject the outbound flow. Such a design choice may appear
> conformant to REQ-8 below. However, the design choice is in violation of the
> spirit of both REQ-8 and REQ-2. Such a design choice is strongly discouraged.

The packets the exit refuses itself are under
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

- For code 5, the border filter drops a source inside `cap.border.overlay`
  arriving from outside the mesh. The source is forged, so an answer would go to
  the host it names rather than the one that sent the packet.
- For code 5, every SID refuses an outer source outside the overlay. Each packet
  is addressed to a SID, so an answer would tell its sender which addresses are
  SIDs.
- For code 5, an egress segment refuses an outer or inner source outside its
  allow list. The SID has already refused an outer source outside the overlay,
  so the outer source of each packet is an overlay address. A host beyond the
  mesh can forge one through a node that forwards without `cap.border`, and the
  segment cannot tell such a packet from a mesh node's, so an answer could reach
  the mesh node the source names rather than the host that sent the packet.
- For code 5, an egress segment past its allow list also refuses an inner source
  the mesh routes no reply to, as the exit's check below does. No route would
  carry an answer back to that source either.
- For code 1, an egress segment past its reply check refuses an inner packet
  whose destination the mesh routes itself, by a route that does not
  [count as a default](../routing.md#routes-that-count-as-a-default), to another
  node, into a hold or to this node, since egress carries nothing for the mesh.
  For IPv4,
  [RFC 1812 section 5.3.9](https://www.rfc-editor.org/rfc/rfc1812.html#section-5.3.9)
  says "The router MUST allow packets to be silently discarded" and "The router
  SHOULD allow an appropriate ICMP unreachable message to be sent when a packet
  is discarded", with code 13. The reason is the allow list's above. Each packet
  passed the SID's overlay check and the allow list, so its sources are overlay
  addresses, which a host beyond the mesh can forge through a node without
  `cap.border`, and an answer could reach the mesh node the source names.
- For code 0, an egress segment past its reply check refuses an inner packet
  whose destination lies inside `cap.border.overlay`, the mesh's own address
  space. No node whose `cap.border` sets that overlay egresses such a
  destination through its [forwarding decision](#transit-answers) either. Where
  no node announces one, an exit with `cap.border` whose table selects its own
  route that counts as a default answers it as no route, and a node whose table
  selects that exit's route routes it there. An exit without `cap.border` has no
  overlay, so its decision egresses such a destination as it egresses any other
  outside the mesh. The reason is the allow list's above, as for code 1.
- For code 1, the border filter drops a routing header arriving from outside the
  mesh. An answer would tell its sender that this node is the edge of the mesh's
  segment routing domain.
- For code 1, the border filter drops one of this node's SIDs as the destination
  of a packet arriving from outside the mesh. An answer would tell its sender
  which addresses are SIDs.
- For code 5, the forwarding decision drops a tun read from a source the table
  routes to another node or holds unreachable, through a route that does not
  count as a default, or from an overlay source this node does not own. The
  source is forged, so an answer would reach the node it names rather than the
  host that sent the packet.
- For code 5, the forwarding decision drops a tun read toward a route that
  counts as a default from a source this node does not own. Only this node's own
  traffic leaves the mesh through an exit, and an unowned source may be forged,
  so an answer could reach a bystander.
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
  options and routing headers or ends inside one, or whose inner packet, opened
  one level deep, has a header that cannot be read. The walk that finds a
  routing header or an inner packet must end, and an answer would tell the host
  that this node is the mesh's edge.
- For code 3, the forwarding decision drops as `looped` a tun read the table
  answers as this node's own, which the mesh could only hand back to the tun.
  That meets the MUST NOT that keeps such a packet off its arrival link, and the
  answer is a known gap.
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
- For code 0, a read off the tun that a segment list steers, whose first segment
  has no route, is counted and dropped with no answer, where every other read
  with no route that passes the checks at the mesh's edge is answered. That is a
  known gap.

An egress segment drops with no answer, too, a packet its allow list and its
checks let through whose family is not [ready](../exit-nodes.md#readiness), and
counts it not ready. The node withdraws the SID's `/128` while a family the host
forwards is not ready, or no family is, and the mesh takes the readiness before
the speaker retracts the route, so that drop lasts from that moment until the
retraction reaches the leaf, as the exit's above does. Where the host does not
forward the family and the other family is ready, the node keeps the `/128`,
since a leaf reads it as the exit's liveness and the exit still serves the other
family, and the segment drops the family's packets for as long as that holds. No
reason holds for that silence.

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
inner packet whose source no router forwards, and every one whose destination no
router forwards but the limited broadcast and multicast, and the decision treats
some of them otherwise. The decision writes a packet to a multicast, limited
broadcast or IPv6 link-local destination to the tun whatever its source, and
answers an IPv6 link-local source to a wider unicast destination a router
forwards with code 2 on the session it came from. Past its allow list, the
segment sends a packet from a source a router forwards to the limited broadcast
or a multicast destination on to its reply check.
[The border filter](../border-filter.md#watching-it) counts each drop,
[segment routing](../segment-routing.md#watching-it) counts each refusal, and
`ranet3 status` counts an exit's 2 as `unrouted source` and `not ready`, and a
tun read's as `invalid`, `forged`, `routing header`, `SID`, `unowned source`,
`nested` and `looped`, on its `Transit` line.
