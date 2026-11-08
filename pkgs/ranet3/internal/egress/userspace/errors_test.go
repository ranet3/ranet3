// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// An error about a leaf's datagram is answered to the leaf from its offender
// with its type and code, quoting the leaf's IP and UDP header as kept, then
// as much of the payload the error quoted as the leaf's datagram held: the
// quoted header keeps the leaf's lengths, and the error's own lengths claim
// exactly what it holds, within 576 bytes over IPv4 and 1280 over IPv6. A too
// big carries the MTU and a parameter problem its pointer, an IPv4 error the
// TTL it is given, and each error's checksums hold. A type the relay does not
// carry is answered with nothing.
func TestRelayedErrorQuotesNoMoreThanTheLeafsDatagram(t *testing.T) {
	router4, router6 := netip.MustParseAddr("198.51.100.1"), netip.MustParseAddr("2001:db8:2::1")
	for _, c := range []struct {
		name                 string
		leaf, server, router netip.Addr
		kind, code           byte
		info                 uint32
		payload, prefix      int
		// quoted is the payload the error quotes, and rest the word after its
		// checksum
		quoted int
		rest   uint32
	}{
		{"ipv4 prefix shorter", leaf4, server4, router4, 3, 1, 0, 100, 60, 60, 0},
		{"ipv4 prefix equal", leaf4, server4, router4, 3, 1, 0, 100, 100, 100, 0},
		{"ipv4 prefix longer", leaf4, server4, router4, 3, 1, 0, 100, 160, 100, 0},
		{"ipv4 port unreachable from the server", leaf4, server4, server4, 3, 3, 0, 100, 100, 100, 0},
		{"ipv4 time exceeded", leaf4, server4, router4, 11, 0, 0, 100, 100, 100, 0},
		{"ipv4 parameter problem", leaf4, server4, router4, 12, 0, 9, 100, 100, 100, 9 << 24},
		{"ipv4 too big cut at 576", leaf4, server4, router4, 3, 4, 1300, 1400, 1400, 576 - 20 - 8 - 28, 1300},
		{"ipv6 prefix shorter", leaf6, server6, router6, 1, 3, 0, 100, 60, 60, 0},
		{"ipv6 prefix equal", leaf6, server6, router6, 1, 3, 0, 100, 100, 100, 0},
		{"ipv6 prefix longer", leaf6, server6, router6, 1, 3, 0, 100, 160, 100, 0},
		{"ipv6 time exceeded", leaf6, server6, router6, 3, 0, 0, 100, 100, 100, 0},
		{"ipv6 parameter problem", leaf6, server6, router6, 4, 0, 42, 100, 100, 100, 42},
		{"ipv6 too big cut at 1280", leaf6, server6, router6, 2, 0, 1280, 1400, 1400, 1280 - 40 - 8 - 48, 1280},
	} {
		t.Run(c.name, func(t *testing.T) {
			payload := make([]byte, c.payload)
			for i := range payload {
				payload[i] = byte(i)
			}
			datagram := udpDatagram(netip.AddrPortFrom(c.leaf, 40000), netip.AddrPortFrom(c.server, 4000), payload)
			header, protocol := 20, byte(protoICMP)
			if c.leaf.Is6() {
				header, protocol = 40, protoICMPv6
			}
			kept := datagram[:header+8]
			prefix := append(bytes.Clone(payload[:min(c.prefix, c.payload)]), bytes.Repeat([]byte{0xee}, max(c.prefix-c.payload, 0))...)
			out := relayedError(kept, icmpError{offender: c.router, kind: c.kind, code: c.code, info: c.info}, prefix, hostTTL)
			p, ok := parse(out)
			if !ok || p.protocol != protocol || p.src != c.router || p.dst != c.leaf || p.kind != c.kind || p.code != c.code {
				t.Fatalf("relayed %s, want type %d code %d from %s to %s", p, c.kind, c.code, c.router, c.leaf)
			}
			if c.leaf.Is4() && out[8] != hostTTL {
				t.Errorf("relayed at the TTL %d, want the %d given", out[8], hostTTL)
			}
			message := out[header:]
			claimed := int(binary.BigEndian.Uint16(out[2:4]))
			if c.leaf.Is6() {
				claimed = 40 + int(binary.BigEndian.Uint16(out[4:6]))
			}
			if want := header + 8 + len(kept) + c.quoted; len(out) != want || claimed != len(out) {
				t.Errorf("the error holds %d bytes and claims %d, want %d", len(out), claimed, want)
			}
			if got := binary.BigEndian.Uint32(message[4:8]); got != c.rest {
				t.Errorf("the word after the checksum is %#x, want %#x", got, c.rest)
			}
			quote := message[8:]
			if !bytes.Equal(quote[:len(kept)], kept) || !bytes.Equal(quote[len(kept):], payload[:c.quoted]) {
				t.Errorf("quoted %x, want the leaf's header %x and its first %d bytes of payload", quote, kept, c.quoted)
			}
			running := sum(0, message)
			if c.leaf.Is6() {
				running += pseudo(c.router, c.leaf, protoICMPv6, len(message))
			} else if fold(sum(0, out[:20])) != 0 {
				t.Error("the IPv4 header's checksum fails")
			}
			if fold(running) != 0 {
				t.Error("the error's checksum fails")
			}
		})
	}
	datagram := udpDatagram(netip.AddrPortFrom(leaf4, 40000), netip.AddrPortFrom(server4, 4000), []byte("redirected"))
	if out := relayedError(datagram[:28], icmpError{offender: router4, kind: 5, code: 1}, []byte("redirected"), hostTTL); out != nil {
		t.Errorf("a redirect relayed as %x, want nothing", out)
	}
}

// A leaf's ICMP error about a datagram one of its mappings delivered reaches
// the datagram's server through the platform's raw socket, from the address
// the mapping sends to the server from, quoting the server's datagram as the
// mapping received it: to the mapping's port, its UDP checksum the server's,
// at the host's TTL or hop limit. It ends no mapping. With no raw socket it is
// dropped and counted, and the lane hands one about no mapping to the relay,
// which drops and counts it.
func TestLeafErrorReachesItsServerFromTheMapping(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
		kind, code   byte
	}{{"ipv4", leaf4, netip.MustParseAddr("127.0.0.1"), 3, 3}, {"ipv6", leaf6, netip.IPv6Loopback(), 1, 4}} {
		for _, rawless := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s rawless %t", family.name, rawless), func(t *testing.T) {
				server := loopbackServer(t, family.server)
				raw := &fakeRaw{}
				h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
					if !rawless {
						rt.Platform.Raw = raw
					}
				})
				h.x.SetHopLimits(hostTTL, hostHopLimit)
				leaf := netip.AddrPortFrom(family.leaf, freeUDPPort(t, family.leaf))
				h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
				outside := readDatagramFrom(t, server, []byte("request"))
				reply := []byte("a reply the leaf refuses")
				if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
					t.Fatal(err)
				}
				laid := h.waitLaid(t, "reply", func(pkt []byte) bool { return isDatagram(pkt, serverAt(server), leaf, reply) })
				refusal := leafRefusal(leaf.Addr(), family.server, family.kind, family.code, laid)
				if !fastLeafError(refusal) {
					t.Fatal("the lane would hand the leaf's error to the stack")
				}
				h.x.udp.leafError(refusal)
				sent := raw.sentSoFar()
				if rawless {
					if got := h.count(false, reasonLeafErrorUnsent); got != 1 || len(sent) != 0 {
						t.Errorf("dropped %d unsent and sent %d, want one dropped", got, len(sent))
					}
				} else {
					if len(sent) != 1 {
						t.Fatalf("sent %d through the raw socket, want 1", len(sent))
					}
					checkServerError(t, sent[0], outside, serverAt(server), family.kind, family.code, reply)
					if got := hopsOf(sent[0]); got != hostHops(family.server) {
						t.Errorf("sent the error at %d, want the host's %d", got, hostHops(family.server))
					}
				}
				if _, ok := h.mappingOf(leaf); !ok {
					t.Error("the leaf's error ended its mapping")
				}
			})
		}
	}
	h := newRelayHarness(t, nil)
	reply := udpDatagram(netip.AddrPortFrom(server4, 4000), netip.AddrPortFrom(leaf4, 40000), []byte("no mapping sent this"))
	h.x.handle(h.lane, leafRefusal(leaf4, server4, 3, 3, reply))
	if got := h.count(false, reasonLeafErrorUnmapped); got != 1 {
		t.Errorf("dropped %d as unmapped, want 1", got)
	}
}

// a leaf's error whose ICMP checksum or quoted IPv4 header's checksum fails is
// dropped and counted before the relay writes any checksum anew (RFC 5508
// REQ-3 (a) and (b)), and one that holds carries the leaf's diffserv class to
// the server (RFC 5508 section 7.7)
func TestLeafErrorIsCheckedAndCarriesItsDiffservClass(t *testing.T) {
	var class, ecn byte = 0xb8, 0x01
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
		kind, code   byte
	}{{"ipv4", leaf4, netip.MustParseAddr("127.0.0.1"), 3, 3}, {"ipv6", leaf6, netip.IPv6Loopback(), 1, 4}} {
		for _, damage := range []string{"none", "icmp checksum", "quoted checksum"} {
			if damage == "quoted checksum" && family.leaf.Is6() {
				continue
			}
			t.Run(family.name+" "+damage, func(t *testing.T) {
				server := loopbackServer(t, family.server)
				raw := &fakeRaw{}
				h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Raw = raw })
				leaf := netip.AddrPortFrom(family.leaf, freeUDPPort(t, family.leaf))
				h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
				outside := readDatagramFrom(t, server, []byte("request"))
				reply := []byte("a reply the leaf refuses")
				if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
					t.Fatal(err)
				}
				laid := h.waitLaid(t, "reply", func(pkt []byte) bool { return isDatagram(pkt, serverAt(server), leaf, reply) })
				refusal := leafRefusal(leaf.Addr(), family.server, family.kind, family.code, laid)
				header := 40
				if family.leaf.Is4() {
					header = 20
					refusal[1] = class | ecn
					binary.BigEndian.PutUint16(refusal[10:12], 0)
					binary.BigEndian.PutUint16(refusal[10:12], fold(sum(0, refusal[:20])))
				} else {
					refusal[0], refusal[1] = 6<<4|class>>4, (class|ecn)<<4|refusal[1]&0x0f
				}
				message := refusal[header:]
				switch damage {
				case "icmp checksum":
					message[2] ^= 0xff
				case "quoted checksum":
					message[8+10] ^= 0xff
					binary.BigEndian.PutUint16(message[2:4], 0)
					binary.BigEndian.PutUint16(message[2:4], fold(sum(0, message)))
				}
				h.x.udp.leafError(refusal)
				sent := raw.sentSoFar()
				if damage != "none" {
					if got := h.count(false, damage); got != 1 || len(sent) != 0 {
						t.Errorf("dropped %d under %q and sent %d, want one dropped and none sent", got, damage, len(sent))
					}
					return
				}
				if len(sent) != 1 {
					t.Fatalf("sent %d through the raw socket, want 1", len(sent))
				}
				checkServerError(t, sent[0], outside, serverAt(server), family.kind, family.code, reply)
				got := sent[0][1]
				if family.leaf.Is6() {
					got = sent[0][0]<<4 | sent[0][1]>>4
				}
				if got != class {
					t.Errorf("the error carries the DS field %#x, want the leaf's class %#x with its ECN bits clear", got, class)
				}
			})
		}
	}
}

// a leaf's error about a datagram another leaf's mapping hairpinned to it, once
// it sent to the host's address, sent to the address the datagram came from,
// reaches the sender's leaf
// through the lane and not the raw socket, quoting the datagram as the sender
// sent it, and comes from the address the sender sent to, the quote's
// destination after the translation, at the host's TTL and with an
// identification of its own (RFC 5508 REQ-7 and REQ-7 (a))
func TestLeafErrorAboutAHairpinnedDatagramReachesItsSender(t *testing.T) {
	host := netip.MustParseAddr("198.51.100.9")
	raw := &fakeRaw{}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		rt.Platform.Held = func(address netip.Addr) bool { return address == host }
		rt.Platform.Raw = raw
	})
	h.x.SetHopLimits(hostTTL, hostHopLimit)
	anchor := h.anchor(t)
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	port := h.unpaired(t, listener, host, anchor)
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	senderPort := h.unpaired(t, sender, host, anchor)
	h.x.handle(h.lane, udpDatagram(listener, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")))
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")))
	laid := h.waitLaid(t, "hairpinned datagram", func(pkt []byte) bool {
		return isDatagram(pkt, netip.AddrPortFrom(host, senderPort), listener, []byte("hairpinned"))
	})
	var class byte = 0x28
	refusal := leafRefusal(listener.Addr(), host, 3, 3, laid)
	refusal[1] = class
	binary.BigEndian.PutUint16(refusal[10:12], 0)
	binary.BigEndian.PutUint16(refusal[10:12], fold(sum(0, refusal[:20])))
	h.x.handle(h.lane, refusal)
	out := h.waitLaid(t, "error to the sender", func(pkt []byte) bool {
		p, ok := parse(pkt)
		return ok && p.protocol == icmpProtocol(host) && p.dst == sender.Addr()
	})
	checkServerError(t, out, netip.AddrPortFrom(host, port), sender, 3, 3, []byte("hairpinned"))
	if out[1] != class {
		t.Errorf("the error carries the DS field %#x, want the leaf's %#x", out[1], class)
	}
	if out[8] != hostTTL {
		t.Errorf("the error carries the TTL %d, want the host's %d", out[8], hostTTL)
	}
	if id, quoted := binary.BigEndian.Uint16(out[4:6]), binary.BigEndian.Uint16(laid[4:6]); id == 0 || id == quoted {
		t.Errorf("the error carries the identification %d, want one of its own past the hairpinned datagram's %d", id, quoted)
	}
	if sent, refused := raw.sentSoFar(), h.count(true, reasonDestination); len(sent) != 0 || refused != 0 {
		t.Errorf("sent %d through the raw socket and refused %d toward the host, want neither", len(sent), refused)
	}
}

// A leaf's error quoting a datagram from a mapping that hairpins, at an
// address of the host that mapping never sent to, is about no datagram that
// mapping hairpinned to it, and is dropped and counted rather than carried to
// that mapping's leaf. Each mapping is opened unpaired, so the forger's
// mapping sends from that address, and once the sender has sent there the same
// error reaches the sender's leaf: the drop comes from the sender's filter.
func TestLeafErrorAboutAnUnhairpinnedAddressIsDropped(t *testing.T) {
	host, other, spare := netip.MustParseAddr("198.51.100.9"), netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("198.51.100.11")
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host, other, spare)
		rt.Platform.Raw = &fakeRaw{}
	})
	anchor := h.anchor(t)
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	forger := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
	port, senderPort := h.unpaired(t, listener, spare, anchor), h.unpaired(t, sender, spare, anchor)
	forgerPort := h.unpaired(t, forger, spare, anchor)
	h.x.handle(h.lane, udpDatagram(listener, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")))
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")))
	h.waitLaid(t, "hairpinned datagram", func(pkt []byte) bool {
		return isDatagram(pkt, netip.AddrPortFrom(host, senderPort), listener, []byte("hairpinned"))
	})
	before := h.count(false, reasonLeafErrorUnmapped)
	quoted := udpDatagram(netip.AddrPortFrom(other, senderPort), forger, []byte("never sent"))
	h.x.handle(h.lane, leafRefusal(forger.Addr(), other, 3, 3, quoted))
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
		t.Errorf("dropped %d errors as about no datagram a mapping delivered, want the one about %s, which the sender never sent to", got, other)
	}
	time.Sleep(stackSettle)
	for _, pkt := range h.mesh.laidPackets() {
		if p, ok := parse(pkt); ok && p.protocol == protoICMP && p.dst == sender.Addr() {
			t.Fatalf("laid %s toward the sender's leaf, want nothing", p)
		}
	}
	h.x.handle(h.lane, udpDatagram(sender, netip.AddrPortFrom(other, forgerPort), []byte("lets the sender send to other")))
	h.x.handle(h.lane, leafRefusal(forger.Addr(), other, 3, 3, quoted))
	h.waitLaid(t, "error to the sender once it sent to "+other.String(), func(pkt []byte) bool {
		p, ok := parse(pkt)
		return ok && p.protocol == protoICMP && p.src == other && p.dst == sender.Addr()
	})
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
		t.Errorf("dropped %d errors as about no datagram a mapping delivered, want only the first", got)
	}
}

// leafRefusal is the ICMP error from leaf to server of kind and code quoting
// offending, its checksum set
func leafRefusal(leaf, server netip.Addr, kind, code byte, offending []byte) []byte {
	message := append([]byte{kind, code, 0, 0, 0, 0, 0, 0}, offending...)
	running := sum(0, message)
	if leaf.Is6() {
		running += pseudo(leaf, server, protoICMPv6, len(message))
	}
	binary.BigEndian.PutUint16(message[2:4], fold(running))
	return ipPacket(leaf, server, icmpProtocol(leaf), message)
}

// checkServerError fails t where out is not an error of kind and code from
// outside's address to server quoting server's datagram of payload to outside
// whole, with every checksum holding
func checkServerError(t *testing.T, out []byte, outside, server netip.AddrPort, kind, code byte, payload []byte) {
	t.Helper()
	p, ok := parse(out)
	if !ok || p.protocol != icmpProtocol(server.Addr()) || p.src != outside.Addr() || p.dst != server.Addr() || p.kind != kind || p.code != code {
		t.Fatalf("sent %s, want type %d code %d from %s to %s", p, kind, code, outside.Addr(), server.Addr())
	}
	header := 20
	if server.Addr().Is6() {
		header = 40
	}
	message := out[header:]
	running := sum(0, message)
	if server.Addr().Is6() {
		running += pseudo(outside.Addr(), server.Addr(), protoICMPv6, len(message))
	} else if fold(sum(0, out[:20])) != 0 || fold(sum(0, message[8:28])) != 0 {
		t.Error("an IPv4 header's checksum fails")
	}
	if fold(running) != 0 {
		t.Error("the error's checksum fails")
	}
	if !isDatagram(message[8:], server, outside, payload) {
		q, _ := parse(message[8:])
		t.Errorf("quoted %s, want the server's datagram of %d bytes to %s with its checksum", q, len(payload), outside)
	}
}
