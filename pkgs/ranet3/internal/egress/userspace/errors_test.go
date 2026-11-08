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

// destinationLive is whether leaf's mapping holds its socket toward to
func destinationLive(x *Exit, leaf, to netip.AddrPort) bool {
	x.udp.mu.RLock()
	m := x.udp.mappings[leaf]
	x.udp.mu.RUnlock()
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.destinations[to] != nil
}

// An error about a leaf's datagram is answered to the leaf from its offender
// with its type and code, quoting the leaf's IP and UDP header as kept, then
// as much of the payload the error quoted as the leaf's datagram held: the
// quoted header keeps the leaf's lengths, and the error's own lengths claim
// exactly what it holds, within 576 bytes over IPv4 and 1280 over IPv6. A too
// big carries the MTU and a parameter problem its pointer, each error the TTL
// or hop limit it is given, and each error's checksums hold. A type the relay does not
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
			out := relayedError(kept, icmpError{offender: c.router, kind: c.kind, code: c.code, info: c.info}, prefix, hostHops(c.leaf))
			p, ok := parse(out)
			if !ok || p.protocol != protocol || p.src != c.router || p.dst != c.leaf || p.kind != c.kind || p.code != c.code {
				t.Fatalf("relayed %s, want type %d code %d from %s to %s", p, c.kind, c.code, c.router, c.leaf)
			}
			if got := hopsOf(out); got != hostHops(c.leaf) {
				t.Errorf("relayed at %d, want the %d given", got, hostHops(c.leaf))
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

// tooBigFrom is a too big of kind and code from from to server carrying mtu
// and quoting offending
func tooBigFrom(from, server netip.Addr, kind, code byte, mtu uint32, offending []byte) []byte {
	message := append([]byte{kind, code, 0, 0, 0, 0, 0, 0}, offending...)
	binary.BigEndian.PutUint32(message[4:8], mtu)
	running := sum(0, message)
	if from.Is6() {
		running += pseudo(from, server, protoICMPv6, len(message))
	}
	binary.BigEndian.PutUint16(message[2:4], fold(running))
	return ipPacket(from, server, icmpProtocol(from), message)
}

// withOption4 is segment, an IPv4 packet, with four no-operation option bytes
// in its header, its lengths and checksum following
func withOption4(segment []byte) []byte {
	b := append(append(append([]byte(nil), segment[:20]...), 1, 1, 1, 1), segment[20:]...)
	b[0] = 4<<4 | 6
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	binary.BigEndian.PutUint16(b[10:12], 0)
	binary.BigEndian.PutUint16(b[10:12], fold(sum(0, b[:24])))
	return b
}

// sessionsApart has h's lanes reach forger through another session than every
// other address
func sessionsApart(h *relayHarness, forger netip.Addr) {
	h.mesh.session = func(address netip.Addr) int {
		if address == forger {
			return 2
		}
		return 1
	}
}

// checkReached fails t where the stack read other than one of what received
// counts with reason "", or read one or counted none as reason
func checkReached(t *testing.T, h *relayHarness, reached uint64, reason string) {
	t.Helper()
	if reason == "" {
		if reached != 1 {
			t.Errorf("the stack read %d errors, want the one", reached)
		}
		return
	}
	if reached != 0 || h.count(false, reason) != 1 {
		t.Errorf("the stack read %d errors and %d were counted as %q, want none read and one counted", reached, h.count(false, reason), reason)
	}
}

// A leaf's too big about a TCP segment toward a leaf reaches the stack from
// any session where it carries at least the family's least MTU, 552 bytes over
// IPv4 and 1280 over IPv6: from the leaf's own session, from a node the mesh
// reaches by another first hop than the leaf, as a waypoint or a later hop
// is, and quoting an IPv4 header with options. One carrying a smaller MTU,
// 100 bytes among them, is dropped and counted from any session, and the
// stack never reads it, so the endpoint it names keeps its segment size.
func TestLeafTooBigAboutTCPReachesTheStackFromAnySessionAtTheLeastMTU(t *testing.T) {
	for _, family := range []struct {
		name                 string
		leaf, server, forger netip.Addr
		kind, code           byte
		least                uint32
		received             func(*Exit) uint64
	}{
		{"ipv4", leaf4, server4, other4, 3, 4, 552, func(x *Exit) uint64 { return x.stack.Stats().ICMP.V4.PacketsReceived.DstUnreachable.Value() }},
		{"ipv6", leaf6, server6, other6, 2, 0, 1280, func(x *Exit) uint64 { return x.stack.Stats().ICMP.V6.PacketsReceived.PacketTooBig.Value() }},
	} {
		segment := tcpSegment(netip.AddrPortFrom(family.server, 443), netip.AddrPortFrom(family.leaf, 40000), 7000, 1000, tcpACK, make([]byte, 1000))
		type tooBig struct {
			name   string
			from   netip.Addr
			mtu    uint32
			quote  []byte
			reason string
		}
		cases := []tooBig{
			{"from the leaf's session", family.leaf, family.least, segment, ""},
			{"from behind another first hop", family.forger, family.least, segment, ""},
			{"below the least MTU from the leaf's session", family.leaf, family.least - 1, segment, reasonLeafErrorMTU},
			{"below the least MTU from behind another first hop", family.forger, family.least - 1, segment, reasonLeafErrorMTU},
			{"at 100 bytes", family.leaf, 100, segment, reasonLeafErrorMTU},
		}
		if family.leaf.Is4() {
			cases = append(cases, tooBig{"quoting a header with options", family.leaf, family.least, withOption4(segment), ""})
		}
		for _, c := range cases {
			t.Run(family.name+" "+c.name, func(t *testing.T) {
				h := newRelayHarness(t, nil)
				sessionsApart(h, family.forger)
				before := family.received(h.x)
				h.x.handle(h.lane, tooBigFrom(c.from, family.server, family.kind, family.code, c.mtu, c.quote))
				checkReached(t, h, family.received(h.x)-before, c.reason)
			})
		}
	}
}

// A leaf's ICMP error about a TCP segment toward a leaf other than a too big,
// a port unreachable or a time exceeded, reaches the stack only where it comes
// from the session the segment went to, and its unused bytes are never read as
// an MTU. One from another session, one leaf's forged error about another
// leaf's connection, is dropped and counted, and the stack never reads it.
func TestLeafErrorAboutTCPOtherThanTooBigReachesTheStackOnlyFromItsSession(t *testing.T) {
	for _, family := range []struct {
		name                 string
		leaf, server, forger netip.Addr
		unreachable, expired [2]byte
		reachedUnreachable   func(*Exit) uint64
		reachedExpired       func(*Exit) uint64
	}{
		{
			"ipv4", leaf4, server4, other4, [2]byte{3, 3}, [2]byte{11, 0},
			func(x *Exit) uint64 { return x.stack.Stats().ICMP.V4.PacketsReceived.DstUnreachable.Value() },
			func(x *Exit) uint64 { return x.stack.Stats().ICMP.V4.PacketsReceived.TimeExceeded.Value() },
		},
		{
			"ipv6", leaf6, server6, other6, [2]byte{1, 4}, [2]byte{3, 0},
			func(x *Exit) uint64 { return x.stack.Stats().ICMP.V6.PacketsReceived.DstUnreachable.Value() },
			func(x *Exit) uint64 { return x.stack.Stats().ICMP.V6.PacketsReceived.TimeExceeded.Value() },
		},
	} {
		segment := tcpSegment(netip.AddrPortFrom(family.server, 443), netip.AddrPortFrom(family.leaf, 40000), 7000, 1000, tcpACK, make([]byte, 1000))
		for _, c := range []struct {
			name     string
			from     netip.Addr
			kind     [2]byte
			received func(*Exit) uint64
			reason   string
		}{
			{"port unreachable from the leaf's session", family.leaf, family.unreachable, family.reachedUnreachable, ""},
			{"port unreachable from another session", family.forger, family.unreachable, family.reachedUnreachable, reasonLeafErrorElsewhere},
			{"time exceeded from the leaf's session", family.leaf, family.expired, family.reachedExpired, ""},
			{"time exceeded from another session", family.forger, family.expired, family.reachedExpired, reasonLeafErrorElsewhere},
		} {
			t.Run(family.name+" "+c.name, func(t *testing.T) {
				h := newRelayHarness(t, nil)
				sessionsApart(h, family.forger)
				before := c.received(h.x)
				h.x.handle(h.lane, leafRefusal(c.from, family.server, c.kind[0], c.kind[1], segment))
				checkReached(t, h, c.received(h.x)-before, c.reason)
			})
		}
	}
}

// A leaf's error reaches the stack only where its quote reads whole down to a
// TCP header, an IPv6 one past a fragment header at offset 0 among them, as
// gVisor steps over one to find the endpoint, so the session and MTU checks
// hold for every quote the stack acts on. A quote of IPv4 version 5, one
// behind an extension header the exit does not walk, one at a later fragment
// and one cut short of its TCP header are dropped and counted whatever their
// source, and the stack never reads them.
func TestLeafErrorReachesTheStackOnlyWithAQuoteReadToItsTCPHeader(t *testing.T) {
	tcp4 := tcpSegment(netip.AddrPortFrom(server4, 443), netip.AddrPortFrom(leaf4, 40000), 7000, 1000, tcpACK, make([]byte, 1000))
	tcp6 := tcpSegment(netip.AddrPortFrom(server6, 443), netip.AddrPortFrom(leaf6, 40000), 7000, 1000, tcpACK, make([]byte, 1000))
	behind := func(extension []byte) []byte {
		return ip6(server6, leaf6, extension[8], 64, append(append([]byte(nil), extension[:8]...), tcp6[40:]...))
	}
	// each extension header's 9th byte is the next header the IPv6 header
	// names, cut off before the header is laid
	firstFragment := behind([]byte{protoTCP, 0, 0, 0, 0, 0, 0, 9, ipv6Fragment})
	laterFragment := behind([]byte{protoTCP, 0, 0, 8, 0, 0, 0, 9, ipv6Fragment})
	authentication := behind([]byte{protoTCP, 0, 0, 0, 0, 0, 1, 0, 51})
	version5 := append([]byte(nil), tcp4...)
	version5[0] = 5<<4 | 5
	stack4 := func(x *Exit) uint64 { return x.stack.Stats().ICMP.V4.PacketsReceived.DstUnreachable.Value() }
	stack6 := func(x *Exit) uint64 { return x.stack.Stats().ICMP.V6.PacketsReceived.PacketTooBig.Value() }
	unreachable6 := func(x *Exit) uint64 { return x.stack.Stats().ICMP.V6.PacketsReceived.DstUnreachable.Value() }
	for _, c := range []struct {
		name     string
		from     netip.Addr
		mtu      uint32
		quote    []byte
		received func(*Exit) uint64
		reason   string
	}{
		{"ipv6 first fragment from the leaf's session", leaf6, 1280, firstFragment, stack6, ""},
		{"ipv6 first fragment from behind another first hop", other6, 1280, firstFragment, stack6, ""},
		// an mtu of 0 stands for a port unreachable, which meets the session check
		{"ipv6 first fragment port unreachable from another leaf's session", other6, 0, firstFragment, unreachable6, reasonLeafErrorElsewhere},
		{"ipv6 first fragment below the least MTU", leaf6, 1279, firstFragment, stack6, reasonLeafErrorMTU},
		{"ipv6 later fragment", other6, 1279, laterFragment, stack6, reasonLeafErrorQuote},
		{"ipv6 behind an authentication header", other6, 1279, authentication, stack6, reasonLeafErrorQuote},
		{"ipv6 cut inside the TCP header", other6, 1279, firstFragment[:40+8+4], stack6, reasonLeafErrorQuote},
		{"ipv4 version 5", other4, 67, version5, stack4, reasonLeafErrorQuote},
		{"ipv4 later fragment", other4, 67, ip4(server4, leaf4, protoTCP, 1, 1, 64, tcp4[20:]), stack4, reasonLeafErrorQuote},
		{"ipv4 cut inside the TCP header", other4, 67, tcp4[:20+4], stack4, reasonLeafErrorQuote},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newRelayHarness(t, nil)
			h.mesh.session = func(address netip.Addr) int {
				if address == other4 || address == other6 {
					return 2
				}
				return 1
			}
			kind, code, server := byte(2), byte(0), server6
			switch {
			case c.from.Is4():
				kind, code, server = 3, 4, server4
			case c.mtu == 0:
				kind, code = 1, 4
			}
			before := c.received(h.x)
			h.x.handle(h.lane, tooBigFrom(c.from, server, kind, code, c.mtu, c.quote))
			reached := c.received(h.x) - before
			if c.reason == "" {
				if reached != 1 {
					t.Errorf("the stack read %d too bigs, want the one", reached)
				}
				return
			}
			if reached != 0 || h.count(false, c.reason) != 1 {
				t.Errorf("the stack read %d too bigs and %d were counted as %q, want none read and one counted", reached, h.count(false, c.reason), c.reason)
			}
		})
	}
}

// The first fragment of a leaf's ICMP error is dropped and counted, since the
// quote its source and its MTU stand in is read only whole, so the stack
// never reassembles the error
func TestLeafErrorInFragmentsIsKeptFromTheStack(t *testing.T) {
	for _, family := range []struct {
		name         string
		leaf, server netip.Addr
		kind, code   byte
		mtu          uint32
		header       int
	}{
		{"ipv4", leaf4, server4, 3, 4, 576, 20},
		{"ipv6", leaf6, server6, 2, 0, 1280, 40},
	} {
		t.Run(family.name, func(t *testing.T) {
			segment := tcpSegment(netip.AddrPortFrom(family.server, 443), netip.AddrPortFrom(family.leaf, 40000), 7000, 1000, tcpACK, make([]byte, 1000))
			whole := tooBigFrom(family.leaf, family.server, family.kind, family.code, family.mtu, segment)
			h := newRelayHarness(t, nil)
			h.x.handle(h.lane, fragments(family.leaf, family.server, icmpProtocol(family.leaf), 9, whole[family.header:], 512)[0])
			if got := h.count(false, reasonLeafErrorFragment); got != 1 {
				t.Errorf("counted %d first fragments of an error as %q, want 1", got, reasonLeafErrorFragment)
			}
		})
	}
}
