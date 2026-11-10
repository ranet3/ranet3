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
	"ranet3.com/pkgs/ranet3/schema"
)

// destinationLive is whether a mapping of leaf's holds its socket toward to
func destinationLive(x *Exit, leaf, to netip.AddrPort) bool {
	_, dst := x.udp.opened(leaf, to)
	return dst != nil
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

// A leaf's error about a server's datagram leaves from the mapping holding the
// socket toward that server, by address and port, where the leaf's two
// mappings each hold a socket toward the server's address, as two classes in
// turn give them (RFC 5508 REQ-5 (a))
func TestLeafErrorLeavesFromTheMappingHoldingItsServer(t *testing.T) {
	first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	_, _ = loopbackServer(t, first), loopbackServer(t, second)
	host := netip.MustParseAddr("127.0.0.1")
	earlier, server := loopbackServer(t, host), loopbackServer(t, host)
	raw := &fakeRaw{}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Raw = raw })
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, first, second))
	h.x.cfg.Translate = classed(first).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(earlier), []byte("earlier")), false)
	readDatagramFrom(t, earlier, []byte("earlier"))
	h.x.cfg.Translate = classed(second).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
	outside := readDatagramFrom(t, server, []byte("request"))
	if mappings := h.mappingsOf(leaf); len(mappings) != 2 || outside.Addr() != second {
		t.Fatalf("%s holds %d mappings and reached the server from %s, want two and %s", leaf, len(mappings), outside, second)
	}
	reply := []byte("a reply the leaf refuses")
	if _, err := server.WriteToUDPAddrPort(reply, outside); err != nil {
		t.Fatal(err)
	}
	laid := h.waitLaid(t, "reply", func(pkt []byte) bool { return isDatagram(pkt, serverAt(server), leaf, reply) })
	h.x.udp.leafError(leafRefusal(leaf.Addr(), host, 3, 3, laid))
	sent := raw.sentSoFar()
	if len(sent) != 1 {
		t.Fatalf("sent %d through the raw socket, want 1", len(sent))
	}
	checkServerError(t, sent[0], outside, serverAt(server), 3, 3, reply)
}

// A leaf's error about a datagram from a port of a server's address no
// destination holds leaves from the one mapping of the leaf holding a socket
// toward that address, and where two do, as two classes in turn give them,
// is dropped and counted as about no mapping, since the quote holds the
// leaf's address and port and nothing of the mapping
func TestLeafErrorAboutAnotherPortOfItsServer(t *testing.T) {
	for _, mappings := range []int{1, 2} {
		t.Run(fmt.Sprintf("%d mappings", mappings), func(t *testing.T) {
			first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
			_, _ = loopbackServer(t, first), loopbackServer(t, second)
			host := netip.MustParseAddr("127.0.0.1")
			server, later, other := loopbackServer(t, host), loopbackServer(t, host), loopbackServer(t, host)
			raw := &fakeRaw{}
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Raw = raw })
			leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, first, second))
			h.x.cfg.Translate = classed(first).Translate
			h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("request")), false)
			outside := readDatagramFrom(t, server, []byte("request"))
			if mappings == 2 {
				h.x.cfg.Translate = classed(second).Translate
				h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("later")), false)
				readDatagramFrom(t, later, []byte("later"))
			}
			reply := []byte("from another port")
			if _, err := other.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			laid := h.waitLaid(t, "reply from another port", func(pkt []byte) bool { return isDatagram(pkt, serverAt(other), leaf, reply) })
			before := h.count(false, reasonLeafErrorUnmapped)
			h.x.udp.leafError(leafRefusal(leaf.Addr(), host, 3, 3, laid))
			sent := raw.sentSoFar()
			if mappings == 2 {
				if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 || len(sent) != 0 {
					t.Errorf("dropped %d errors as about no mapping and sent %d, want the one dropped and none sent", got, len(sent))
				}
				return
			}
			if len(sent) != 1 {
				t.Fatalf("sent %d through the raw socket, want 1", len(sent))
			}
			checkServerError(t, sent[0], outside, serverAt(other), 3, 3, reply)
		})
	}
}

// Where two of a leaf's mappings sent to one server's address, from two of
// its ports, a datagram from the port the first holds a socket toward that
// came in through the second still has the leaf's error about it leave from
// the first: the leaf sees one address and port for both, and its own
// datagrams to that port and its answer leave from the first
func TestLeafErrorAboutAServerPortLeavesFromItsHolder(t *testing.T) {
	first, second := netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.3")
	_, _ = loopbackServer(t, first), loopbackServer(t, second)
	host := netip.MustParseAddr("127.0.0.1")
	server, later := loopbackServer(t, host), loopbackServer(t, host)
	raw := &fakeRaw{}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) { rt.Platform.Raw = raw })
	leaf := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, first, second))
	h.x.cfg.Translate = classed(first).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("to the server")), false)
	atFirst := readDatagramFrom(t, server, []byte("to the server"))
	h.x.cfg.Translate = classed(second).Translate
	h.x.udp.take(udpDatagram(leaf, serverAt(later), []byte("to its other port")), false)
	atSecond := readDatagramFrom(t, later, []byte("to its other port"))
	if mappings := h.mappingsOf(leaf); len(mappings) != 2 || atFirst.Addr() != first || atSecond.Addr() != second {
		t.Fatalf("%s holds %d mappings and reached the server from %s and %s", leaf, len(mappings), atFirst, atSecond)
	}
	payload := []byte("the server's port to the second mapping")
	if _, err := server.WriteToUDPAddrPort(payload, atSecond); err != nil {
		t.Fatal(err)
	}
	laid := h.waitLaid(t, "the server's datagram through the second mapping", func(pkt []byte) bool {
		return isDatagram(pkt, serverAt(server), leaf, payload)
	})
	h.x.udp.leafError(leafRefusal(leaf.Addr(), host, 3, 3, laid))
	sent := raw.sentSoFar()
	if len(sent) != 1 {
		t.Fatalf("sent %d through the raw socket, want 1", len(sent))
	}
	checkServerError(t, sent[0], atFirst, serverAt(server), 3, 3, payload)
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
	host := netip.MustParseAddr("127.0.0.1")
	_ = loopbackServer(t, host)
	raw := &fakeRaw{}
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host)
		rt.Platform.Raw = raw
	})
	h.x.SetHopLimits(hostTTL, hostHopLimit)
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	port := h.hairpinning(t, listener, host)
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	senderPort := h.hairpinning(t, sender, host)
	h.x.udp.take(udpDatagram(listener, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")), false)
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")), false)
	laid := h.waitLaid(t, "hairpinned datagram", func(pkt []byte) bool {
		return isDatagram(pkt, netip.AddrPortFrom(host, senderPort), listener, []byte("hairpinned"))
	})
	var class byte = 0x28
	refusal := leafRefusal(listener.Addr(), host, 3, 3, laid)
	refusal[1] = class
	binary.BigEndian.PutUint16(refusal[10:12], 0)
	binary.BigEndian.PutUint16(refusal[10:12], fold(sum(0, refusal[:20])))
	h.x.udp.leafError(refusal)
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

// A leaf's error about a datagram a sender hairpinned to it, where the sender
// hairpinned to both of the leaf's mappings and only the one on the sender's
// address let it in, reaches the sender from that mapping's address and port,
// quoting the datagram as sent to it (RFC 5508 REQ-7, REQ-5 (a)). Once both
// mappings let the sender's address in, the quote names neither, and the
// error is dropped and counted.
func TestLeafErrorAboutAHairpinnedDatagramComesFromTheMappingItWentTo(t *testing.T) {
	one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, one), loopbackServer(t, two)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, one, two)
		rt.Platform.Raw = &fakeRaw{}
	})
	target := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, one, two))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	onOne := h.hairpinning(t, target, one)
	h.x.cfg.Translate = classed(two).Translate
	onTwo := h.hairpinning(t, target, two)
	h.x.cfg.Translate = nil
	senderPort := h.hairpinning(t, sender, one)
	atOne, atTwo, atSender := netip.AddrPortFrom(one, onOne), netip.AddrPortFrom(two, onTwo), netip.AddrPortFrom(one, senderPort)
	h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in")), false)
	h.x.udp.take(udpDatagram(sender, atOne, []byte("to one")), false)
	laid := h.waitLaid(t, "to one", func(raw []byte) bool { return isDatagram(raw, atSender, target, []byte("to one")) })
	filtered := h.count(false, reasonFiltered)
	h.x.udp.take(udpDatagram(sender, atTwo, []byte("to two")), false)
	if got := h.count(false, reasonFiltered) - filtered; got != 1 {
		t.Fatalf("filtered %d datagrams to the mapping on %s, which never sent to %s, want 1", got, two, one)
	}
	h.x.udp.leafError(leafRefusal(target.Addr(), one, 3, 3, laid))
	out := h.waitLaid(t, "the target's error to the sender", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMP && p.dst == sender.Addr()
	})
	checkServerError(t, out, atOne, sender, 3, 3, []byte("to one"))

	h.x.cfg.Translate = classed(two).Translate
	h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in on two")), false)
	h.x.cfg.Translate = nil
	h.waitLaid(t, "the target's datagram from two", func(raw []byte) bool {
		return isDatagram(raw, atTwo, sender, []byte("lets one in on two"))
	})
	h.x.udp.take(udpDatagram(sender, atTwo, []byte("to two again")), false)
	laid = h.waitLaid(t, "to two again", func(raw []byte) bool { return isDatagram(raw, atSender, target, []byte("to two again")) })
	h.drainLaid()
	before := h.count(false, reasonLeafErrorUnmapped)
	h.x.udp.leafError(leafRefusal(target.Addr(), one, 3, 3, laid))
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
		t.Errorf("dropped %d errors as about no mapping, want the one whose datagram either of two mappings could have let in", got)
	}
	time.Sleep(stackSettle)
	for pkt := h.x.link.poll(); pkt != nil; pkt = h.x.link.poll() {
		view := pkt.ToView()
		p, ok := parse(view.AsSlice())
		view.Release()
		h.x.link.release(pkt)
		if ok && p.protocol == protoICMP && p.dst == sender.Addr() {
			t.Errorf("laid %s toward the sender, want nothing", p)
		}
	}
}

// A leaf's error about a hairpinned datagram finds the mapping the datagram
// went to by the address and port the sender hairpinned to, not the address
// alone: where the sender also hairpinned to a third leaf's mapping on the
// address of the leaf's other mapping, and both of the leaf's mappings let the
// sender in, the error still reaches the sender from the one it hairpinned to
func TestLeafErrorAboutAHairpinnedDatagramMatchesItsAddressAndPort(t *testing.T) {
	one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, one), loopbackServer(t, two)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, one, two)
		rt.Platform.Raw = &fakeRaw{}
	})
	target := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, one, two))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	third := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
	h.hairpinning(t, target, one)
	h.x.cfg.Translate = classed(two).Translate
	onTwo := h.hairpinning(t, target, two)
	h.x.cfg.Translate = nil
	atSender := netip.AddrPortFrom(one, h.hairpinning(t, sender, one))
	atThird := netip.AddrPortFrom(one, h.hairpinning(t, third, one))
	atTwo := netip.AddrPortFrom(two, onTwo)
	h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in on one")), false)
	translate := classed(two).Translate
	translate[0].From = schema.PrefixFrom(netip.PrefixFrom(target.Addr(), 32))
	h.x.cfg.Translate = translate
	h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in on two")), false)
	h.x.cfg.Translate = nil
	h.x.udp.take(udpDatagram(sender, atThird, []byte("to the third leaf")), false)
	h.x.udp.take(udpDatagram(sender, atTwo, []byte("to two")), false)
	laid := h.waitLaid(t, "to two", func(raw []byte) bool { return isDatagram(raw, atSender, target, []byte("to two")) })
	for _, m := range h.mappingsOf(target) {
		if !m.admits(one) {
			t.Fatalf("the target's mapping %s does not let %s in", m.external(), one)
		}
	}
	h.x.udp.leafError(leafRefusal(target.Addr(), one, 3, 3, laid))
	out := h.waitLaid(t, "the target's error to the sender", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMP && p.dst == sender.Addr()
	})
	checkServerError(t, out, atTwo, sender, 3, 3, []byte("to two"))
}

// A leaf's error about a datagram a sender hairpinned to the first of the
// leaf's two mappings, both letting the sender in, goes by the sender's
// record: after hairpinRecord-2 other peers the record names both mappings,
// the quote neither, and the error is dropped and counted, and after one more
// the record no longer names the first, and the error leaves from the second,
// quoting its address and port. Both lead to the one leaf port that refused.
func TestLeafErrorAboutAHairpinnedDatagramGoesByTheMappingsTheRecordStillNames(t *testing.T) {
	for _, peers := range []int{hairpinRecord - 2, hairpinRecord - 1} {
		t.Run(fmt.Sprintf("%d peers", peers), func(t *testing.T) {
			one, two := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
			_, _ = loopbackServer(t, one), loopbackServer(t, two)
			h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
				holdOnly(rt, one, two)
				rt.Platform.Raw = &fakeRaw{}
			})
			target := netip.AddrPortFrom(leaf4, freeUDPPortOn(t, one, two))
			sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
			onOne := h.hairpinning(t, target, one)
			h.x.cfg.Translate = classed(two).Translate
			onTwo := h.hairpinning(t, target, two)
			h.x.cfg.Translate = nil
			atOne, atTwo := netip.AddrPortFrom(one, onOne), netip.AddrPortFrom(two, onTwo)
			atSender := netip.AddrPortFrom(one, h.hairpinning(t, sender, one))
			h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in on one")), false)
			h.x.cfg.Translate = classed(two).Translate
			h.x.udp.take(udpDatagram(target, atSender, []byte("lets one in on two")), false)
			h.x.cfg.Translate = nil
			h.x.udp.take(udpDatagram(sender, atOne, []byte("to one")), false)
			laid := h.waitLaid(t, "to one", func(raw []byte) bool { return isDatagram(raw, atSender, target, []byte("to one")) })
			h.x.udp.take(udpDatagram(sender, atTwo, []byte("to two")), false)
			h.waitLaid(t, "to two", func(raw []byte) bool { return isDatagram(raw, atSender, target, []byte("to two")) })
			for i := range peers {
				peer := netip.AddrPortFrom(netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + i)}), freeUDPPort(t, leaf4))
				at := netip.AddrPortFrom(one, h.hairpinning(t, peer, one))
				h.x.udp.take(udpDatagram(sender, at, []byte("to a peer")), false)
			}
			h.drainLaid()
			s := on(h.mappingsOf(sender), one)
			if named := s.hairpinnedToward(atOne); named != (peers < hairpinRecord-1) {
				t.Fatalf("the sender's record names %s %t after %d peers", atOne, named, peers)
			}
			before := h.count(false, reasonLeafErrorUnmapped)
			h.x.udp.leafError(leafRefusal(target.Addr(), one, 3, 3, laid))
			dropped := h.count(false, reasonLeafErrorUnmapped) - before
			if peers < hairpinRecord-1 {
				if dropped != 1 {
					t.Errorf("dropped %d errors as about no mapping, want the one the record names two mappings for", dropped)
				}
				time.Sleep(stackSettle)
				for pkt := h.x.link.poll(); pkt != nil; pkt = h.x.link.poll() {
					view := pkt.ToView()
					p, ok := parse(view.AsSlice())
					view.Release()
					h.x.link.release(pkt)
					if ok && p.protocol == protoICMP && p.dst == sender.Addr() {
						t.Errorf("laid %s toward the sender, want nothing", p)
					}
				}
				return
			}
			if dropped != 0 {
				t.Errorf("dropped %d errors as about no mapping, want none", dropped)
			}
			out := h.waitLaid(t, "the target's error to the sender", func(raw []byte) bool {
				p, ok := parse(raw)
				return ok && p.protocol == protoICMP && p.dst == sender.Addr()
			})
			checkServerError(t, out, atTwo, sender, 3, 3, []byte("to one"))
		})
	}
}

// A leaf's error quoting a datagram from a mapping that hairpins, sent by a
// leaf whose mapping the sender never hairpinned to, is about no datagram
// that mapping hairpinned to it, and is dropped and counted rather than
// carried to that mapping's leaf. So is the same error once the sender
// hairpinned to the leaf's mapping, which filtered it, never having sent to
// the sender's address. Once that mapping has, the error reaches the sender's
// leaf from it.
func TestLeafErrorAboutAnUnhairpinnedAddressIsDropped(t *testing.T) {
	host, other := netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")
	_, _ = loopbackServer(t, host), loopbackServer(t, other)
	h := newRelayHarness(t, func(rt *Runtime, _ *egress.Egress) {
		holdOnly(rt, host, other)
		rt.Platform.Raw = &fakeRaw{}
	})
	listener := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	sender := netip.AddrPortFrom(other4, freeUDPPort(t, other4))
	forger := netip.AddrPortFrom(leaf4.Next(), freeUDPPort(t, leaf4))
	port, senderPort := h.hairpinning(t, listener, host), h.hairpinning(t, sender, host)
	forgerPort := h.hairpinning(t, forger, other)
	h.x.udp.take(udpDatagram(listener, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")), false)
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(host, port), []byte("hairpinned")), false)
	h.waitLaid(t, "hairpinned datagram", func(pkt []byte) bool {
		return isDatagram(pkt, netip.AddrPortFrom(host, senderPort), listener, []byte("hairpinned"))
	})
	before := h.count(false, reasonLeafErrorUnmapped)
	quoted := udpDatagram(netip.AddrPortFrom(host, senderPort), forger, []byte("never sent"))
	h.x.udp.leafError(leafRefusal(forger.Addr(), host, 3, 3, quoted))
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 1 {
		t.Errorf("dropped %d errors as about no datagram a mapping delivered, want the one from %s, whose mapping's address %s the sender never sent to", got, forger, other)
	}
	time.Sleep(stackSettle)
	for _, pkt := range h.mesh.laidPackets() {
		if p, ok := parse(pkt); ok && p.protocol == protoICMP && p.dst == sender.Addr() {
			t.Fatalf("laid %s toward the sender's leaf, want nothing", p)
		}
	}
	h.x.udp.take(udpDatagram(sender, netip.AddrPortFrom(other, forgerPort), []byte("filtered at other")), false)
	h.x.udp.leafError(leafRefusal(forger.Addr(), host, 3, 3, quoted))
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 2 {
		t.Errorf("dropped %d errors as about no datagram a mapping delivered, want both, the forger's mapping having let in no datagram from %s", got, host)
	}
	h.x.udp.take(udpDatagram(forger, netip.AddrPortFrom(host, senderPort), []byte("lets the host's address in")), false)
	h.x.udp.leafError(leafRefusal(forger.Addr(), host, 3, 3, quoted))
	h.waitLaid(t, "error to the sender once the mapping on "+other.String()+" sent to "+host.String(), func(pkt []byte) bool {
		p, ok := parse(pkt)
		return ok && p.protocol == protoICMP && p.src == other && p.dst == sender.Addr()
	})
	if got := h.count(false, reasonLeafErrorUnmapped) - before; got != 2 {
		t.Errorf("dropped %d errors as about no datagram a mapping delivered, want only the first two", got)
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
