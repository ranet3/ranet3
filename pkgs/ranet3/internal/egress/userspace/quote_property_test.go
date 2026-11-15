// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// sentPacket is one datagram of a run a leaf sent one server: the packet,
// where its UDP header starts, and its payload
type sentPacket struct {
	raw     []byte
	at      int
	payload []byte
}

// field is a field of a leaf's IP header as the property reads it: the bytes
// it spans and the bits of each it holds
type field struct {
	at   int
	mask []byte
}

// for any run of datagrams a leaf sent one server through a destination, each
// field drawn so that the run carries it alike or not, and errors about any
// of them as the host hands them, with the quoted UDP length (macOS's ICMP
// socket) or with none (Linux's error queue), quoting any part of the payload,
// or the whole of it and then the zero padding of an RFC 4884 extension or the
// bytes of an extension with no length attribute, every error reaches the
// leaf, and the quote it gets is the datagram's own IP and UDP header in every
// field the run carried alike and zero in every other, with no options or
// extension headers where theirs differed, its lengths and IPv4 checksum its
// own, its UDP length the datagram's where the run or the error gives it and
// else the payload quoted held to the run's longest, which is the error's up
// to that length, the padding left out
func TestErrorQuotesWhatItKnowsOfItsDatagram(t *testing.T) {
	h := newRelayHarness(t, nil)
	pbt.Check(t, func(ht *hegel.T) {
		ipv4 := hegel.Draw(ht, hegel.Booleans())
		leaf := netip.AddrPortFrom(leaf6, hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		server := netip.AddrPortFrom(server6, hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		outside := netip.AddrPortFrom(other6, hegel.Draw(ht, pbt.Spanning[uint16](1, 65535)))
		router, kind, code := netip.MustParseAddr("2001:db8:2::1"), byte(1), byte(4)
		if ipv4 {
			leaf = netip.AddrPortFrom(leaf4, leaf.Port())
			server = netip.AddrPortFrom(server4, server.Port())
			outside = netip.AddrPortFrom(other4, outside.Port())
			router, kind, code = netip.MustParseAddr("198.51.100.1"), 3, 3
		}
		dst := &destination{to: server}
		defer h.mapped(leaf, outside, dst)()

		var run []sentPacket
		// a run whose layout is one carries options in every datagram or in
		// none, so that options of one layout with two contents are drawn
		// often, and the run's IPv6 flow labels are two, one of them the
		// run's own, which differs from the other in one of the label's
		// places alone, so that each place differing alone is drawn often
		oneLayout, options := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		flow := hegel.Draw(ht, hegel.SampledFrom([]uint32{0x02345, 0x12045, 0x12340}))
		for i := range hegel.Draw(ht, hegel.Integers(1, 20)) {
			payload := bytes.Repeat([]byte{hegel.Draw(ht, hegel.SampledFrom([]byte{0, 0x11, byte(i)}))}, hegel.Draw(ht, hegel.SampledFrom([]int{0, 1, 8, 31, 200})))
			if !oneLayout {
				options = hegel.Draw(ht, hegel.Booleans())
			}
			raw := drawnDatagram(ht, ipv4, leaf, server, payload, uint16(i), options, flow)
			d, ok := readDatagram(raw)
			if !ok {
				ht.Fatalf("the test's datagram %x does not read", raw)
			}
			dst.mu.Lock()
			dst.keep(raw, d)
			dst.mu.Unlock()
			run = append(run, sentPacket{raw, d.at, payload})
		}
		for range hegel.Draw(ht, hegel.Integers(1, 4)) {
			about := run[hegel.Draw(ht, hegel.Integers(0, len(run)-1))]
			prefix := about.payload[:hegel.Draw(ht, pbt.Spanning(0, len(about.payload)))]
			padded := hegel.Draw(ht, hegel.Booleans())
			if padded {
				prefix = append(bytes.Clone(about.payload), make([]byte, hegel.Draw(ht, hegel.Integers(0, 100)))...)
			} else if len(prefix) == len(about.payload) {
				prefix = append(bytes.Clone(prefix), bytes.Repeat([]byte{0xee}, hegel.Draw(ht, hegel.Integers(0, 40)))...)
			}
			quoted := hegel.Draw(ht, hegel.Booleans())
			e := icmpError{offender: router, kind: kind, code: code}
			h.drainLaid()
			if quoted {
				q := quotedError{icmpError: e, protocol: protoUDP, from: outside, to: server, length: uint16(8 + len(about.payload)), prefix: prefix}
				if !h.x.udp.relayQuoted(q) {
					ht.Fatal("the error was not taken as the mapping's")
				}
			} else {
				dst.mu.Lock()
				h.x.udp.relay(dst, e, 0, prefix, padded)
				dst.mu.Unlock()
			}
			laid := h.laid()
			if laid == nil {
				ht.Fatal("the error reached no leaf")
			}
			if want := knownQuote(run, about, prefix, quoted, padded); !bytes.Equal(quoteOf(laid), want) {
				ht.Fatalf("the error quotes %x, want %x", quoteOf(laid), want)
			}
		}
	})
}

// drawnDatagram is a leaf's datagram of payload from leaf to server, each
// field of its IP header drawn from values one of which is the same for every
// datagram: an IPv6 flow label 0x12345 or flow, an IPv4 one's identification
// as 1 or n, its UDP checksum left out or not, and where options holds its
// options or IPv6 destination options header, of one length and one next
// header with either of two contents
func drawnDatagram(ht *hegel.T, ipv4 bool, leaf, server netip.AddrPort, payload []byte, n uint16, options bool, flow uint32) []byte {
	message := udpMessage(leaf, server, payload)
	class := hegel.Draw(ht, hegel.SampledFrom([]byte{0, 0xb8}))
	hops := hegel.Draw(ht, hegel.SampledFrom([]byte{64, 1}))
	other := hegel.Draw(ht, hegel.Booleans())
	if !ipv4 {
		next := byte(protoUDP)
		if options {
			header := []byte{protoUDP, 0, 1, 4, 0, 0, 0, 0}
			if other {
				header[4] = 0x0d
			}
			next, message = ipv6DestinationOptions, append(header, message...)
		}
		raw := ip6(leaf.Addr(), server.Addr(), next, hops, message)
		label := hegel.Draw(ht, hegel.SampledFrom([]uint32{0x12345, flow}))
		binary.BigEndian.PutUint32(raw[0:4], 6<<28|uint32(class)<<20|label)
		return raw
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		message[6], message[7] = 0, 0
	}
	id := hegel.Draw(ht, hegel.SampledFrom([]uint16{1, n}))
	raw := ip4(leaf.Addr(), server.Addr(), protoUDP, id, hegel.Draw(ht, hegel.SampledFrom([]uint16{0, 0x4000})), hops, message)
	raw[1] = class
	if options {
		raw = withOptions(raw, 4)
		if other {
			// no operation three times, then the end of the options
			raw[23] = 0
		}
	}
	binary.BigEndian.PutUint16(raw[10:12], 0)
	binary.BigEndian.PutUint16(raw[10:12], fold(sum(0, raw[:int(raw[0]&0x0f)*4])))
	return raw
}

// knownQuote is the quote of the error about about, one of run, whose payload
// it quotes as prefix, with its UDP length where quoted, as the property reads
// what the exit knows of it: each field of about's that every datagram of run
// carries alike, zero where they do not
func knownQuote(run []sentPacket, about sentPacket, prefix []byte, quoted, padded bool) []byte {
	ipv4 := about.raw[0]>>4 == 4
	fixed, fieldsOf := 40, []field{{0, []byte{0x0f, 0xf0}}, {1, []byte{0x0f, 0xff, 0xff}}, {7, []byte{0xff}}}
	if ipv4 {
		fixed, fieldsOf = 20, []field{{1, []byte{0xff}}, {4, []byte{0xff, 0xff}}, {6, []byte{0xff, 0xff}}, {8, []byte{0xff}}}
	}
	alike := func(read func(sentPacket) []byte) bool {
		for _, other := range run {
			if !bytes.Equal(read(other), read(run[0])) {
				return false
			}
		}
		return true
	}
	ip := bytes.Clone(about.raw[:about.at])
	// IPv6's first next header names its extension headers
	layout := func(p sentPacket) []byte {
		if ipv4 {
			return p.raw[fixed:p.at]
		}
		return append([]byte{p.raw[6]}, p.raw[fixed:p.at]...)
	}
	if !alike(layout) {
		ip = ip[:fixed]
		if ipv4 {
			ip[0] = 4<<4 | 5
		} else {
			ip[6] = protoUDP
		}
	}
	for _, f := range fieldsOf {
		masked := func(p sentPacket) []byte {
			b := bytes.Clone(p.raw[f.at : f.at+len(f.mask)])
			for i := range b {
				b[i] &= f.mask[i]
			}
			return b
		}
		if !alike(masked) {
			for i := range f.mask {
				ip[f.at+i] &^= f.mask[i]
			}
		}
	}
	udp := bytes.Clone(about.raw[about.at : about.at+8])
	payload := prefix[:min(len(prefix), len(about.payload))]
	if !alike(func(p sentPacket) []byte { return p.raw[p.at+4 : p.at+6] }) && !quoted {
		if payload = prefix; padded {
			payload = bytes.TrimRight(prefix, "\x00")
		}
		longest := 0
		for _, p := range run {
			longest = max(longest, len(p.payload))
		}
		payload = payload[:min(len(payload), longest)]
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	}
	if !alike(func(p sentPacket) []byte { return p.raw[p.at+6 : p.at+8] }) {
		udp[6], udp[7] = 0, 0
	}
	size := len(ip) + int(binary.BigEndian.Uint16(udp[4:6]))
	if ipv4 {
		binary.BigEndian.PutUint16(ip[2:4], uint16(size))
		binary.BigEndian.PutUint16(ip[10:12], 0)
		binary.BigEndian.PutUint16(ip[10:12], fold(sum(0, ip)))
	} else {
		binary.BigEndian.PutUint16(ip[4:6], uint16(size-40))
	}
	return append(append(ip, udp...), payload...)
}
