// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// borderPacket is one packet as the border chain reads it at prerouting
type borderPacket struct {
	iif     string
	nfproto uint8
	// network is the network header and everything after it
	network []byte
}

// chainRun records the verdict an interpreted chain gave one packet
type chainRun struct {
	// rule is the index of the rule whose verdict the packet met, -1 for the policy
	rule    int
	accept  bool
	counted bool
}

// runChain evaluates the encoded rules in order against packet, as
// nf_tables does: the first rule to reach a verdict decides, and a packet no
// rule decides meets the chain's accept policy
func runChain(t testing.TB, rules []nftRequest, packet borderPacket) chainRun {
	t.Helper()
	for i, rule := range rules {
		code, counted, decided := runRule(t, rule.body, packet)
		if !decided {
			continue
		}
		if code != chainAccept && code != verdictDrop {
			t.Fatalf("rule %d ends with verdict %d, neither accept nor drop", i, code)
		}
		return chainRun{rule: i, accept: code == chainAccept, counted: counted}
	}
	return chainRun{rule: -1, accept: true}
}

// runRule executes one rule's expression bytes against packet over register
// 1, failing the test on any expression, attribute or register it does not
// model rather than guessing at it. A load or a comparison that fails ends
// the rule undecided, which is NFT_BREAK.
func runRule(t testing.TB, body []byte, packet borderPacket) (code uint32, counted, decided bool) {
	t.Helper()
	var register []byte
	for kind, value := range (nftMessage{Data: body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			var name string
			fields := map[uint16][]byte{}
			for _, field := range nested(element.value) {
				switch field.kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.value)
				case unix.NFTA_EXPR_DATA:
					for _, inner := range nested(field.value) {
						fields[inner.kind] = inner.value
					}
				}
			}
			for field := range fields {
				if !slices.Contains(modeled[name], field) {
					t.Fatalf("a %q expression carries attribute %d, which the interpreter does not model", name, field)
				}
			}
			switch name {
			case "meta":
				requireRegister(t, name, fields, unix.NFTA_META_DREG)
				switch be32(t, fields[unix.NFTA_META_KEY]) {
				case unix.NFT_META_IIFNAME:
					register = make([]byte, ifNameSize)
					copy(register, packet.iif)
				case unix.NFT_META_NFPROTO:
					register = []byte{packet.nfproto}
				default:
					t.Fatalf("meta loads key %d, which the interpreter does not model", be32(t, fields[unix.NFTA_META_KEY]))
				}
			case "payload":
				requireRegister(t, name, fields, unix.NFTA_PAYLOAD_DREG)
				if be32(t, fields[unix.NFTA_PAYLOAD_BASE]) != unix.NFT_PAYLOAD_NETWORK_HEADER {
					t.Fatalf("payload loads from base %d, not the network header", be32(t, fields[unix.NFTA_PAYLOAD_BASE]))
				}
				offset, length := int(be32(t, fields[unix.NFTA_PAYLOAD_OFFSET])), int(be32(t, fields[unix.NFTA_PAYLOAD_LEN]))
				if offset+length > len(packet.network) {
					return 0, false, false
				}
				register = slices.Clone(packet.network[offset : offset+length])
			case "bitwise":
				requireRegister(t, name, fields, unix.NFTA_BITWISE_SREG)
				requireRegister(t, name, fields, unix.NFTA_BITWISE_DREG)
				length := int(be32(t, fields[unix.NFTA_BITWISE_LEN]))
				mask, xor := dataValue(fields[unix.NFTA_BITWISE_MASK]), dataValue(fields[unix.NFTA_BITWISE_XOR])
				if len(mask) != length || len(xor) != length || len(register) < length {
					t.Fatalf("bitwise of %d bytes with a %d byte mask and a %d byte xor over a %d byte register", length, len(mask), len(xor), len(register))
				}
				for i := range length {
					register[i] = register[i]&mask[i] ^ xor[i]
				}
			case "cmp":
				requireRegister(t, name, fields, unix.NFTA_CMP_SREG)
				want := dataValue(fields[unix.NFTA_CMP_DATA])
				if len(want) == 0 || len(want) > len(register) {
					t.Fatalf("cmp of %d bytes against a %d byte register", len(want), len(register))
				}
				equal := bytes.Equal(register[:len(want)], want)
				switch be32(t, fields[unix.NFTA_CMP_OP]) {
				case unix.NFT_CMP_EQ:
					if !equal {
						return 0, false, false
					}
				case unix.NFT_CMP_NEQ:
					if equal {
						return 0, false, false
					}
				default:
					t.Fatalf("cmp with operator %d, which the interpreter does not model", be32(t, fields[unix.NFTA_CMP_OP]))
				}
			case "exthdr":
				requireRegister(t, name, fields, unix.NFTA_EXTHDR_DREG)
				if len(fields[unix.NFTA_EXTHDR_TYPE]) != 1 {
					t.Fatalf("exthdr names its header in %d bytes, not one", len(fields[unix.NFTA_EXTHDR_TYPE]))
				}
				if packet.nfproto != unix.NFPROTO_IPV6 {
					return 0, false, false
				}
				start, found := findExtension(packet.network, fields[unix.NFTA_EXTHDR_TYPE][0])
				offset, length := int(be32(t, fields[unix.NFTA_EXTHDR_OFFSET])), int(be32(t, fields[unix.NFTA_EXTHDR_LEN]))
				if flags, ok := fields[unix.NFTA_EXTHDR_FLAGS]; ok {
					if be32(t, flags) != unix.NFT_EXTHDR_F_PRESENT {
						t.Fatalf("exthdr carries flags %#x, of which the interpreter models only present", be32(t, flags))
					}
					// present stores one byte, whatever the offset and length
					register = []byte{0}
					if found {
						register[0] = 1
					}
					continue
				}
				if !found || start+offset+length > len(packet.network) {
					return 0, false, false
				}
				register = slices.Clone(packet.network[start+offset : start+offset+length])
			case "counter":
				counted = true
			case "immediate":
				if be32(t, fields[unix.NFTA_IMMEDIATE_DREG]) != unix.NFT_REG_VERDICT {
					t.Fatalf("immediate loads register %d rather than the verdict", be32(t, fields[unix.NFTA_IMMEDIATE_DREG]))
				}
				for _, data := range nested(fields[unix.NFTA_IMMEDIATE_DATA]) {
					if data.kind != unix.NFTA_DATA_VERDICT {
						continue
					}
					for _, field := range nested(data.value) {
						if field.kind == unix.NFTA_VERDICT_CODE {
							return be32(t, field.value), counted, true
						}
					}
				}
				t.Fatal("immediate carries no verdict code")
			default:
				t.Fatalf("the rule holds a %q expression, which the interpreter does not model", name)
			}
		}
	}
	return 0, false, false
}

// modeled is the attributes the interpreter reads of each expression. Any
// other, an exthdr operation, a bitwise operation, a payload checksum, changes
// what the expression does, so it fails the test.
var modeled = map[string][]uint16{
	"meta":      {unix.NFTA_META_KEY, unix.NFTA_META_DREG},
	"payload":   {unix.NFTA_PAYLOAD_DREG, unix.NFTA_PAYLOAD_BASE, unix.NFTA_PAYLOAD_OFFSET, unix.NFTA_PAYLOAD_LEN},
	"bitwise":   {unix.NFTA_BITWISE_SREG, unix.NFTA_BITWISE_DREG, unix.NFTA_BITWISE_LEN, unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR},
	"cmp":       {unix.NFTA_CMP_SREG, unix.NFTA_CMP_OP, unix.NFTA_CMP_DATA},
	"exthdr":    {unix.NFTA_EXTHDR_DREG, unix.NFTA_EXTHDR_TYPE, unix.NFTA_EXTHDR_OFFSET, unix.NFTA_EXTHDR_LEN, unix.NFTA_EXTHDR_FLAGS},
	"counter":   {},
	"immediate": {unix.NFTA_IMMEDIATE_DREG, unix.NFTA_IMMEDIATE_DATA},
}

func requireRegister(t testing.TB, name string, fields map[uint16][]byte, kind uint16) {
	t.Helper()
	if got := be32(t, fields[kind]); got != unix.NFT_REG_1 {
		t.Fatalf("%s names register %d where every expression here shares register 1", name, got)
	}
}

func be32(t testing.TB, value []byte) uint32 {
	t.Helper()
	if len(value) != 4 {
		t.Fatalf("a 32 bit attribute of %d bytes", len(value))
	}
	return binary.BigEndian.Uint32(value)
}

// dataValue is the bytes of an NFTA_DATA_VALUE nested in an attribute
func dataValue(attribute []byte) []byte {
	for _, inner := range nested(attribute) {
		if inner.kind == unix.NFTA_DATA_VALUE {
			return inner.value
		}
	}
	return nil
}

// kernelHeaderSearch is IP6_MAX_EXT_HDRS_CNT, the extension headers the
// kernel's ipv6_find_hdr walks before it gives up from Linux 7.1
const kernelHeaderSearch = 12

// findExtension walks the IPv6 extension header chain as the kernel's
// ipv6_find_hdr does with no flags: from the next header field at byte 6 and
// the end of a fixed header at byte 40, through hop-by-hop, routing,
// fragment, authentication and destination options headers, to the first
// header of the type asked for among the first kernelHeaderSearch. A fragment
// other than the first ends the walk, as does any other header.
func findExtension(network []byte, target uint8) (int, bool) {
	if len(network) < 40 {
		return 0, false
	}
	next, start := network[6], 40
	for walked := 0; ; walked++ {
		switch next {
		case unix.IPPROTO_HOPOPTS, unix.IPPROTO_ROUTING, unix.IPPROTO_FRAGMENT, unix.IPPROTO_AH, unix.IPPROTO_DSTOPTS:
		default:
			return 0, false
		}
		if walked == kernelHeaderSearch || start+2 > len(network) {
			return 0, false
		}
		if next == target {
			return start, true
		}
		header := network[start:]
		length := (int(header[1]) + 1) * 8
		switch next {
		case unix.IPPROTO_FRAGMENT:
			if start+4 > len(network) || binary.BigEndian.Uint16(header[2:])&^7 != 0 {
				return 0, false
			}
			length = 8
		case unix.IPPROTO_AH:
			length = (int(header[1]) + 2) * 4
		}
		next, start = header[0], start+length
	}
}

// drawnPacket is a packet the property sends at the chain, and the fields
// the model reads of it
type drawnPacket struct {
	iif                 string
	source, destination netip.Addr
	// headers is the IPv6 extension headers in order, each "hop", "dest",
	// "fragment" or "routing" followed by the routing type
	headers []string
}

// isRouting is whether header names a routing header
func isRouting(header string) bool { return strings.HasPrefix(header, "routing") }

// wire is the packet's bytes from its network header on, with eight bytes of
// UDP after the headers
func (p drawnPacket) wire() borderPacket {
	if p.source.Is4() {
		header := make([]byte, 20+8)
		header[0], header[8], header[9] = 0x45, 64, unix.IPPROTO_UDP
		binary.BigEndian.PutUint16(header[2:], uint16(len(header)))
		source, destination := p.source.As4(), p.destination.As4()
		copy(header[12:], source[:])
		copy(header[16:], destination[:])
		return borderPacket{iif: p.iif, nfproto: unix.NFPROTO_IPV4, network: header}
	}
	codes := map[string]uint8{"hop": unix.IPPROTO_HOPOPTS, "dest": unix.IPPROTO_DSTOPTS, "fragment": unix.IPPROTO_FRAGMENT}
	nexts := make([]uint8, 0, len(p.headers)+1)
	for _, header := range p.headers {
		if isRouting(header) {
			nexts = append(nexts, unix.IPPROTO_ROUTING)
		} else {
			nexts = append(nexts, codes[header])
		}
	}
	nexts = append(nexts, unix.IPPROTO_UDP)
	out := make([]byte, 40)
	out[0], out[6], out[7] = 0x60, nexts[0], 64
	source, destination := p.source.As16(), p.destination.As16()
	copy(out[8:], source[:])
	copy(out[24:], destination[:])
	for i, header := range p.headers {
		switch {
		case header == "hop" || header == "dest":
			// one PadN option filling the header to its eight bytes
			out = append(out, nexts[i+1], 0, 1, 4, 0, 0, 0, 0)
		case isRouting(header):
			// one segment of sixteen bytes, segments left one
			routing, err := strconv.ParseUint(strings.TrimPrefix(header, "routing"), 10, 8)
			if err != nil {
				panic("a routing header drawn without its type: " + header)
			}
			segment := destination
			out = append(out, nexts[i+1], 2, uint8(routing), 1, 0, 0, 0, 0)
			out = append(out, segment[:]...)
		case header == "fragment":
			// the first fragment, offset zero and more to come
			out = append(out, nexts[i+1], 0, 0, 1, 0, 0, 0x2a, 0x2a)
		}
	}
	out = append(out, make([]byte, 8)...)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return borderPacket{iif: p.iif, nfproto: unix.NFPROTO_IPV6, network: out}
}

// borderModel gives the verdict the chain means for a packet: whatever
// arrives on a device inside the mesh passes, and from outside it a source in
// the overlay, then a routing header of any type among the first
// kernelHeaderSearch extension headers, then one of this node's SIDs as the
// destination is dropped under that reason, and anything else passes
func borderModel(inside []string, cfg Border, sids []netip.Addr, p drawnPacket) (accept bool, reason string) {
	if slices.Contains(inside, p.iif) {
		return true, ""
	}
	for _, prefix := range cfg.Overlay {
		if prefix.Contains(p.source) {
			return false, "overlay_source"
		}
	}
	if routing := slices.IndexFunc(p.headers, isRouting); p.source.Is6() && routing >= 0 && routing < kernelHeaderSearch {
		return false, "routing_header"
	}
	if p.source.Is6() && slices.Contains(sids, p.destination) {
		return false, "sid_destination"
	}
	return true, ""
}

// lastAddress is the highest address prefix covers
func lastAddress(prefix netip.Prefix) netip.Addr {
	raw := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(raw)*8; bit++ {
		raw[bit/8] |= 0x80 >> (bit % 8)
	}
	last, _ := netip.AddrFromSlice(raw)
	return last
}

// unmappedIPv6 draws an IPv6 address that is not an IPv4 address written as
// one, which the overlay and the SIDs both refuse
func unmappedIPv6() hegel.Generator[netip.Addr] {
	return hegel.Filter(hegel.IPAddresses().IPv6(), func(a netip.Addr) bool { return !a.Is4In6() })
}

// overlayPrefixes draws one to four overlay prefixes of either family at
// lengths spanning each family's floor to full length, with the lengths the
// fleet and the documentation ranges use drawn by name
func overlayPrefixes() hegel.Generator[[]schema.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) []schema.Prefix {
		count := hegel.Draw(tc, pbt.Spanning(1, 4))
		var out []schema.Prefix
		for range count {
			var prefix netip.Prefix
			if hegel.Draw(tc, hegel.Booleans()) {
				bits := hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]int{8, 23, 24, 32}), pbt.Spanning(schema.MinSourceBits4, 32)))
				prefix = netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv4()), bits).Masked()
			} else {
				bits := hegel.Draw(tc, hegel.OneOf(hegel.SampledFrom([]int{12, 36, 48, 64, 128}), pbt.Spanning(schema.MinSourceBits6, 128)))
				prefix = netip.PrefixFrom(hegel.Draw(tc, unmappedIPv6()), bits).Masked()
			}
			if !slices.ContainsFunc(out, func(other schema.Prefix) bool { return other.Prefix == prefix }) {
				out = append(out, schema.PrefixFrom(prefix))
			}
		}
		return out
	})
}

// For a drawn configuration and a drawn packet, the encoded chain, executed
// byte by byte by the interpreter above, passes or drops the packet as the
// model does and counts a drop under the model's reason, never an accept.
// The inside names share prefixes with each other and with the devices a
// packet arrives on, and the sources sit on either side of each overlay
// prefix's edges, among them IPv6 sources whose bytes 4 to 7 spell an IPv4
// overlay address, which an IPv4 rule with no family test would read. The
// routing headers are of types 0, 2 and 4, one behind another, and behind
// options headers on either side of the kernel's search limit.
func TestBorderChainDropsWhatTheModelDrops(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		inside := []string{"ranet3"}
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			size := hegel.Draw(ht, pbt.Spanning(1, ifNameSize))
			inside = append(inside, hegel.Draw(ht, hegel.Text().Alphabet("ranet3").MinSize(size).MaxSize(size)))
		}
		cfg := Border{Overlay: hegel.Draw(ht, overlayPrefixes())}
		if err := cfg.Validate(); err != nil {
			ht.Fatalf("drew an overlay Validate refuses: %v", err)
		}
		var sids []netip.Addr
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			sids = append(sids, hegel.Draw(ht, unmappedIPv6()))
		}
		desired := newBorderFilter(cfg, BorderRuntime{Inside: inside, SIDs: sids}, &fakeBorder{}).desired()
		requests, err := borderBatch(desired, false)
		refused := slices.ContainsFunc(inside, func(name string) bool { return len(name) >= ifNameSize })
		if refused != (err != nil) {
			ht.Fatalf("the chain over inside %q encoded with %v, want refused %v", inside, err, refused)
		}
		if refused {
			return
		}
		rules := requests[3:]

		v4 := hegel.Draw(ht, hegel.Booleans())
		var edges []netip.Addr
		for _, prefix := range cfg.Overlay {
			if prefix.Addr().Is4() != v4 {
				continue
			}
			edges = append(edges, prefix.Masked().Addr(), lastAddress(prefix.Prefix), prefix.Masked().Addr().Prev(), lastAddress(prefix.Prefix).Next())
		}
		edges = slices.DeleteFunc(edges, func(a netip.Addr) bool { return !a.IsValid() })
		var p drawnPacket
		random := hegel.IPAddresses().IPv6()
		if v4 {
			random = hegel.IPAddresses().IPv4()
		}
		if len(edges) != 0 && hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
			p.source = hegel.Draw(ht, hegel.SampledFrom(edges))
		} else {
			p.source = hegel.Draw(ht, random)
		}
		if !v4 && hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
			for _, prefix := range cfg.Overlay {
				if prefix.Addr().Is4() {
					raw, inner := p.source.As16(), hegel.Draw(ht, hegel.SampledFrom([]netip.Addr{prefix.Masked().Addr(), lastAddress(prefix.Prefix)})).As4()
					copy(raw[4:8], inner[:])
					p.source = netip.AddrFrom16(raw)
					break
				}
			}
		}
		p.destination = hegel.Draw(ht, random)
		if !v4 && len(sids) != 0 && hegel.Draw(ht, hegel.WeightedBooleans(2.0/3)) {
			raw := hegel.Draw(ht, hegel.SampledFrom(sids)).As16()
			if hegel.Draw(ht, hegel.Booleans()) {
				bit := hegel.Draw(ht, pbt.Spanning(0, 127))
				raw[bit/8] ^= 0x80 >> (bit % 8)
			}
			p.destination = netip.AddrFrom16(raw)
		}
		if !v4 {
			routing := hegel.Draw(ht, hegel.SampledFrom([]string{"routing0", "routing2", "routing4"}))
			p.headers = hegel.Draw(ht, hegel.SampledFrom([][]string{
				nil, {routing}, {"hop", routing}, {"fragment", routing}, {routing, "fragment"}, {"hop"}, {"fragment"}, {"hop", "dest"},
				{"routing0", "routing4"}, {"routing2", "routing4"}, {"hop", "routing0", "dest", "routing4"},
			}))
			if hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
				options := hegel.Draw(ht, pbt.Spanning(kernelHeaderSearch-2, kernelHeaderSearch+1))
				p.headers = append(slices.Repeat([]string{"dest"}, options), routing)
			}
		}
		arrivals := []string{"eth0", "ranet3a1b2"}
		for _, name := range inside {
			arrivals = append(arrivals, name, name[:len(name)-1])
			if len(name) < ifNameSize-1 {
				arrivals = append(arrivals, name+"a")
			}
		}
		arrivals = slices.DeleteFunc(arrivals, func(name string) bool { return name == "" })
		p.iif = hegel.Draw(ht, hegel.SampledFrom(arrivals))

		// a quarter of the cases with SIDs aim at the last two rules: an IPv6
		// packet from outside the mesh and the overlay to one of the SIDs, with a
		// routing header or none, which the order of those two rules and the
		// address the SID rule loads decide
		if len(sids) != 0 && hegel.Draw(ht, hegel.WeightedBooleans(1.0/4)) {
			p = drawnPacket{iif: "eth0", destination: hegel.Draw(ht, hegel.SampledFrom(sids))}
			p.source = hegel.Draw(ht, hegel.Filter(unmappedIPv6(), func(a netip.Addr) bool {
				return !slices.ContainsFunc(cfg.Overlay, func(prefix schema.Prefix) bool { return prefix.Contains(a) })
			}))
			if hegel.Draw(ht, hegel.Booleans()) {
				p.headers = []string{"routing4"}
			}
		}

		run := runChain(ht, rules, p.wire())
		accept, reason := borderModel(inside, cfg, sids, p)
		where := fmt.Sprintf("a packet %+v through inside %q, overlay %v and SIDs %v", p, inside, cfg.Overlay, sids)
		switch {
		case run.accept != accept:
			ht.Fatalf("%s: the chain accepted %v at rule %d, the model %v for %q", where, run.accept, run.rule, accept, reason)
		case !accept && (!run.counted || desired[run.rule].Reason() != reason):
			ht.Fatalf("%s: dropped by %s, counted %v, want counted as %s", where, desired[run.rule], run.counted, reason)
		case accept && run.counted:
			ht.Fatalf("%s: accepted by a rule carrying a counter", where)
		case accept && run.rule != -1 && !strings.HasPrefix(desired[run.rule].String(), "accept via "):
			ht.Fatalf("%s: accepted by %s", where, desired[run.rule])
		}
	})
}
