// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	meshkernel "ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
)

// chainPacket is one packet as a chain reads it: the device it arrived on,
// empty for one this host sent, the one it leaves by, empty before routing,
// and its nf_tables family
type chainPacket struct {
	iif, oif string
	nfproto  uint8
	// network is the network header and everything after it, and transport
	// the header of l4proto, the protocol the kernel finds past the network
	// headers, and everything after it
	network   []byte
	l4proto   uint8
	transport []byte
	// ctState is the packet's state as ct state reads it, one NF_CT_STATE_ bit,
	// and reply whether it goes its connection's reply way, as ct direction
	// reads it
	ctState uint32
	reply   bool
	// sets is the named sets the chain's lookups read, by name, as
	// encodedSets reads them out of the batch that wrote them
	sets map[string][]nftables.Interval
}

// encodedSets reads each named set's keys out of the element requests of a
// batch, as the kernel holds them: an interval from each start to the key
// before the end that follows it, one with no end running to the last key. It
// is a decode of its own rather than nftables' decodeElements, so a fault of
// that one cannot hide here.
func encodedSets(t testing.TB, requests []nftables.Request) map[string][]nftables.Interval {
	t.Helper()
	type element struct {
		key []byte
		end bool
	}
	held := map[string][]element{}
	for _, request := range requests {
		if request.Kind == nftables.Command(unix.NFT_MSG_NEWSET) {
			name := nftables.DecodeSet(nftables.Message{Data: request.Body}).Name
			held[name] = append(held[name], []element{}...)
		}
		if request.Kind != nftables.Command(unix.NFT_MSG_NEWSETELEM) {
			continue
		}
		var name string
		var elements []element
		for kind, value := range (nftables.Message{Data: request.Body}).Attributes() {
			switch kind {
			case unix.NFTA_SET_ELEM_LIST_SET:
				name = unix.ByteSliceToString(value)
			case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
				for _, item := range nftables.Nested(value) {
					var e element
					for _, field := range nftables.Nested(item.Value) {
						switch field.Kind {
						case unix.NFTA_SET_ELEM_KEY:
							e.key = dataValue(field.Value)
						case unix.NFTA_SET_ELEM_FLAGS:
							e.end = be32(t, field.Value)&unix.NFT_SET_ELEM_INTERVAL_END != 0
						}
					}
					elements = append(elements, e)
				}
			}
		}
		held[name] = append(held[name], elements...)
	}
	out := map[string][]nftables.Interval{}
	for name, elements := range held {
		out[name] = []nftables.Interval{}
		slices.SortStableFunc(elements, func(a, b element) int { return bytes.Compare(a.key, b.key) })
		var start []byte
		for _, e := range elements {
			switch {
			case !e.end:
				start = e.key
			case start != nil:
				last := slices.Clone(e.key)
				for i := len(last) - 1; i >= 0; i-- {
					if last[i]--; last[i] != 0xff {
						break
					}
				}
				out[name] = append(out[name], nftables.Interval{First: start, Last: last})
				start = nil
			}
		}
		if start != nil {
			out[name] = append(out[name], nftables.Interval{First: start, Last: bytes.Repeat([]byte{0xff}, len(start))})
		}
	}
	return out
}

// chainRun records the verdict an interpreted chain gave one packet
type chainRun struct {
	// rule is the index of the rule whose verdict the packet met, -1 for the policy
	rule    int
	accept  bool
	counted bool
	// translation records the nat statement ending the rule, the zero value
	// where none did
	translation translation
	// timeouts names the last timeout object a rule on the way attached, empty
	// where none did
	timeouts string
	// rejected is the code of the destination unreachable a reject answered
	// with, 0 where none did
	rejected uint8
}

// translation is a nat statement's work on a packet's source: masquerade, or
// a source nat to the address to
type translation struct {
	masquerade bool
	to         netip.Addr
}

// ruleRun records one interpreted rule's work on a packet: the verdict of one
// it decided, and the timeout object one attached, decided or not
type ruleRun struct {
	code        uint32
	counted     bool
	translation translation
	timeouts    string
	rejected    uint8
}

// runChain evaluates the encoded rules in order against packet, as
// nf_tables does: the first rule to reach a verdict decides, and a packet no
// rule decides meets the chain's accept policy. A rule attaching a timeout
// object attaches it on the way, the last one to attach overriding those
// before it.
func runChain(t testing.TB, rules []nftables.Request, packet chainPacket) chainRun {
	t.Helper()
	var timeouts string
	for i, rule := range rules {
		run, decided := runRule(t, rule.Body, packet)
		if run.timeouts != "" {
			timeouts = run.timeouts
		}
		if !decided {
			continue
		}
		if run.code != nftables.Accept && run.code != nftables.Drop && run.code != nftables.Return {
			t.Fatalf("rule %d ends with verdict %d, neither accept, drop nor return", i, run.code)
		}
		// a return from a base chain meets the chain's accept policy
		return chainRun{rule: i, accept: run.code != nftables.Drop, counted: run.counted, translation: run.translation, timeouts: timeouts, rejected: run.rejected}
	}
	return chainRun{rule: -1, accept: true, timeouts: timeouts}
}

// runRule executes one rule's expression bytes against packet over register
// 1, failing the test on any expression, attribute or register it does not
// model rather than guessing at it. A load or a comparison that fails ends
// the rule undecided, which is NFT_BREAK, and a nat statement ends it with
// the packet accepted as translated. An objref of a timeout object attaches it
// and goes on, and a rule ending past its last expression is undecided, which
// is NFT_CONTINUE.
func runRule(t testing.TB, body []byte, packet chainPacket) (run ruleRun, decided bool) {
	t.Helper()
	// what a rule ending undecided leaves is the timeout object it attached
	undecided := func() (ruleRun, bool) { return ruleRun{timeouts: run.timeouts}, false }
	var register []byte
	for kind, value := range (nftables.Message{Data: body}).Attributes() {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nftables.Nested(value) {
			var name string
			fields := map[uint16][]byte{}
			for _, field := range nftables.Nested(element.Value) {
				switch field.Kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.Value)
				case unix.NFTA_EXPR_DATA:
					for _, inner := range nftables.Nested(field.Value) {
						fields[inner.Kind] = inner.Value
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
					register = make([]byte, unix.IFNAMSIZ)
					copy(register, packet.iif)
				case unix.NFT_META_OIFNAME:
					register = make([]byte, unix.IFNAMSIZ)
					copy(register, packet.oif)
				case unix.NFT_META_IIF:
					// a device's index is above zero, any device's alike to a
					// rule comparing it with zero
					var index uint32
					if packet.iif != "" {
						index = 7
					}
					register = binary.NativeEndian.AppendUint32(nil, index)
				case unix.NFT_META_NFPROTO:
					register = []byte{packet.nfproto}
				case unix.NFT_META_L4PROTO:
					// one byte, in a register the kernel zeroes whole
					register = []byte{packet.l4proto, 0, 0, 0}
				default:
					t.Fatalf("meta loads key %d, which the interpreter does not model", be32(t, fields[unix.NFTA_META_KEY]))
				}
			case "ct":
				requireRegister(t, name, fields, unix.NFTA_CT_DREG)
				switch key := be32(t, fields[unix.NFTA_CT_KEY]); key {
				case unix.NFT_CT_STATE:
					register = binary.NativeEndian.AppendUint32(nil, packet.ctState)
				case unix.NFT_CT_DIRECTION:
					// a packet with no connection has no direction, which ends the
					// rule, and one with a connection loads IP_CT_DIR_ORIGINAL or
					// IP_CT_DIR_REPLY into one byte of a register the kernel zeroes
					// whole
					if packet.ctState == nftables.CTStateInvalid || packet.ctState == nftables.CTStateUntracked {
						return undecided()
					}
					register = []byte{0, 0, 0, 0}
					if packet.reply {
						register[0] = 1
					}
				default:
					t.Fatalf("ct loads key %d, where the interpreter models ct state and direction", key)
				}
			case "payload":
				requireRegister(t, name, fields, unix.NFTA_PAYLOAD_DREG)
				from := packet.network
				switch base := be32(t, fields[unix.NFTA_PAYLOAD_BASE]); base {
				case unix.NFT_PAYLOAD_NETWORK_HEADER:
				case unix.NFT_PAYLOAD_TRANSPORT_HEADER:
					from = packet.transport
				default:
					t.Fatalf("payload loads from base %d, neither the network header nor the transport one", base)
				}
				offset, length := int(be32(t, fields[unix.NFTA_PAYLOAD_OFFSET])), int(be32(t, fields[unix.NFTA_PAYLOAD_LEN]))
				if offset+length > len(from) {
					return undecided()
				}
				register = slices.Clone(from[offset : offset+length])
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
				switch order := bytes.Compare(register[:len(want)], want); be32(t, fields[unix.NFTA_CMP_OP]) {
				case unix.NFT_CMP_GTE:
					if order < 0 {
						return undecided()
					}
				case unix.NFT_CMP_LTE:
					if order > 0 {
						return undecided()
					}
				case unix.NFT_CMP_EQ:
					if !equal {
						return undecided()
					}
				case unix.NFT_CMP_NEQ:
					if equal {
						return undecided()
					}
				default:
					t.Fatalf("cmp with operator %d, which the interpreter does not model", be32(t, fields[unix.NFTA_CMP_OP]))
				}
			case "lookup":
				requireRegister(t, name, fields, unix.NFTA_LOOKUP_SREG)
				set, ok := packet.sets[unix.ByteSliceToString(fields[unix.NFTA_LOOKUP_SET])]
				if !ok {
					t.Fatalf("a lookup reads set %s, which no request of the batch fills", fields[unix.NFTA_LOOKUP_SET])
				}
				held := slices.ContainsFunc(set, func(interval nftables.Interval) bool {
					key := register[:min(len(register), len(interval.First))]
					return bytes.Compare(interval.First, key) <= 0 && bytes.Compare(key, interval.Last) <= 0
				})
				var inverted bool
				if flags, ok := fields[unix.NFTA_LOOKUP_FLAGS]; ok {
					inverted = be32(t, flags)&unix.NFT_LOOKUP_F_INV != 0
				}
				if held == inverted {
					return undecided()
				}
			case "counter":
				run.counted = true
			case "immediate":
				switch be32(t, fields[unix.NFTA_IMMEDIATE_DREG]) {
				case unix.NFT_REG_1:
					register = slices.Clone(dataValue(fields[unix.NFTA_IMMEDIATE_DATA]))
					continue
				case unix.NFT_REG_VERDICT:
				default:
					t.Fatalf("immediate loads register %d, neither register 1 nor the verdict", be32(t, fields[unix.NFTA_IMMEDIATE_DREG]))
				}
				for _, data := range nftables.Nested(fields[unix.NFTA_IMMEDIATE_DATA]) {
					if data.Kind != unix.NFTA_DATA_VERDICT {
						continue
					}
					for _, field := range nftables.Nested(data.Value) {
						if field.Kind == unix.NFTA_VERDICT_CODE {
							run.code = be32(t, field.Value)
							return run, true
						}
					}
				}
				t.Fatal("immediate carries no verdict code")
			case "masq":
				run.code, run.translation = nftables.Accept, translation{masquerade: true}
				return run, true
			case "nat":
				requireRegister(t, name, fields, unix.NFTA_NAT_REG_ADDR_MIN)
				if kind, family := be32(t, fields[unix.NFTA_NAT_TYPE]), be32(t, fields[unix.NFTA_NAT_FAMILY]); kind != unix.NFT_NAT_SNAT || family != uint32(packet.nfproto) {
					t.Fatalf("nat of type %d in family %d, where the interpreter models a source nat of the packet's family %d", kind, family, packet.nfproto)
				}
				size := 4
				if packet.nfproto == unix.NFPROTO_IPV6 {
					size = 16
				}
				if len(register) < size {
					t.Fatalf("nat reads a %d byte address from a %d byte register", size, len(register))
				}
				to, _ := netip.AddrFromSlice(register[:size])
				run.code, run.translation = nftables.Accept, translation{to: to}
				return run, true
			case "objref":
				if kind := be32(t, fields[unix.NFTA_OBJREF_IMM_TYPE]); kind != unix.NFT_OBJECT_CT_TIMEOUT {
					t.Fatalf("objref names an object of type %d, where the interpreter models a ct timeout's", kind)
				}
				run.timeouts = unix.ByteSliceToString(fields[unix.NFTA_OBJREF_IMM_NAME])
			case "reject":
				// the answer goes back to the source, and the packet is dropped
				if kind := be32(t, fields[unix.NFTA_REJECT_TYPE]); kind != unix.NFT_REJECT_ICMP_UNREACH || len(fields[unix.NFTA_REJECT_ICMP_CODE]) != 1 {
					t.Fatalf("reject of type %d with a code of %d bytes, where the interpreter models a destination unreachable", kind, len(fields[unix.NFTA_REJECT_ICMP_CODE]))
				}
				run.code, run.rejected = nftables.Drop, fields[unix.NFTA_REJECT_ICMP_CODE][0]
				return run, true
			default:
				t.Fatalf("the rule holds a %q expression, which the interpreter does not model", name)
			}
		}
	}
	return undecided()
}

// modeled is the attributes the interpreter reads of each expression. Any
// other, a bitwise operation, a payload checksum, a nat
// range's maximum or flags, changes what the expression does, so it fails the
// test.
var modeled = map[string][]uint16{
	"meta":      {unix.NFTA_META_KEY, unix.NFTA_META_DREG},
	"ct":        {unix.NFTA_CT_KEY, unix.NFTA_CT_DREG},
	"payload":   {unix.NFTA_PAYLOAD_DREG, unix.NFTA_PAYLOAD_BASE, unix.NFTA_PAYLOAD_OFFSET, unix.NFTA_PAYLOAD_LEN},
	"bitwise":   {unix.NFTA_BITWISE_SREG, unix.NFTA_BITWISE_DREG, unix.NFTA_BITWISE_LEN, unix.NFTA_BITWISE_MASK, unix.NFTA_BITWISE_XOR},
	"cmp":       {unix.NFTA_CMP_SREG, unix.NFTA_CMP_OP, unix.NFTA_CMP_DATA},
	"lookup":    {unix.NFTA_LOOKUP_SET, unix.NFTA_LOOKUP_SREG, unix.NFTA_LOOKUP_SET_ID, unix.NFTA_LOOKUP_FLAGS},
	"counter":   {},
	"immediate": {unix.NFTA_IMMEDIATE_DREG, unix.NFTA_IMMEDIATE_DATA},
	"masq":      {},
	"nat":       {unix.NFTA_NAT_TYPE, unix.NFTA_NAT_FAMILY, unix.NFTA_NAT_REG_ADDR_MIN},
	"objref":    {unix.NFTA_OBJREF_IMM_TYPE, unix.NFTA_OBJREF_IMM_NAME},
	"reject":    {unix.NFTA_REJECT_TYPE, unix.NFTA_REJECT_ICMP_CODE},
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
	for _, inner := range nftables.Nested(attribute) {
		if inner.Kind == unix.NFTA_DATA_VALUE {
			return inner.Value
		}
	}
	return nil
}

// drawnPacket is a packet the property sends at the chain, and the fields
// the model reads of it
type drawnPacket struct {
	iif                 string
	source, destination netip.Addr
}

// wire is the packet's bytes from its network header on, with eight bytes of
// UDP to port 0 after the header
func (p drawnPacket) wire() chainPacket { return p.carrying(unix.IPPROTO_UDP, 0) }

// carrying is the packet's bytes from its network header on, with eight bytes
// of protocol after the header whose destination port, the third and fourth
// of UDP's and TCP's, is port
func (p drawnPacket) carrying(protocol uint8, port uint16) chainPacket {
	transport := binary.BigEndian.AppendUint16(make([]byte, 2, 8), port)
	transport = append(transport, make([]byte, 4)...)
	if p.source.Is4() {
		header := make([]byte, 20, 20+len(transport))
		header[0], header[8], header[9] = 0x45, 64, protocol
		header = append(header, transport...)
		binary.BigEndian.PutUint16(header[2:], uint16(len(header)))
		source, destination := p.source.As4(), p.destination.As4()
		copy(header[12:], source[:])
		copy(header[16:], destination[:])
		return chainPacket{iif: p.iif, nfproto: unix.NFPROTO_IPV4, network: header, l4proto: protocol, transport: header[20:]}
	}
	out := make([]byte, 40, 40+len(transport))
	out[0], out[6], out[7] = 0x60, protocol, 64
	source, destination := p.source.As16(), p.destination.As16()
	copy(out[8:], source[:])
	copy(out[24:], destination[:])
	out = append(out, transport...)
	binary.BigEndian.PutUint16(out[4:], uint16(len(out)-40))
	return chainPacket{iif: p.iif, nfproto: unix.NFPROTO_IPV6, network: out, l4proto: protocol, transport: out[40:]}
}

// drawnSets is the carve-outs and the sets' prefixes a property draws, which
// the models read as prefixes and the filter takes as ranges
type drawnSets struct {
	CarveOuts           []egress.CarveOut
	Carved, Owned, None []netip.Prefix
}

func (d drawnSets) borderSets() egress.BorderSets {
	return egress.BorderSets{CarveOuts: d.CarveOuts, Carved: meshkernel.Ranges(d.Carved), Owned: meshkernel.Ranges(d.Owned), None: meshkernel.Ranges(d.None)}
}

// borderModel gives the verdict the chain means for a packet, as 2.2 and 2.6
// write it: whatever arrives on a device inside the mesh passes, and from
// outside it a source the mesh's table holds inside a carve-out is dropped, a
// source in a carve-out passes on that carve-out's link alone, any other
// source in the overlay is dropped, each drop under its reason, and anything
// else passes
func borderModel(inside []string, cfg egress.Border, sets drawnSets, p drawnPacket) (accept bool, reason string) {
	if slices.Contains(inside, p.iif) {
		return true, ""
	}
	if slices.ContainsFunc(sets.Carved, func(prefix netip.Prefix) bool { return prefix.Contains(p.source) }) {
		return false, "carved_source"
	}
	if slices.ContainsFunc(sets.CarveOuts, func(c egress.CarveOut) bool { return c.Link == p.iif && c.Prefix.Contains(p.source) }) {
		return true, ""
	}
	for _, prefix := range cfg.Overlay {
		if prefix.Contains(p.source) {
			return false, "overlay_source"
		}
	}
	return true, ""
}

// within is address with its leading bits replaced by prefix's, an address
// prefix covers
func within(prefix netip.Prefix, address netip.Addr) netip.Addr {
	raw, base := address.AsSlice(), prefix.Masked().Addr().AsSlice()
	for bit := range prefix.Bits() {
		mask := byte(0x80 >> (bit % 8))
		raw[bit/8] = raw[bit/8]&^mask | base[bit/8]&mask
	}
	out, _ := netip.AddrFromSlice(raw)
	return out
}

// insidePrefix draws a prefix prefix covers, at a length from prefix's own to the
// family's full length
func insidePrefix(prefix netip.Prefix) hegel.Generator[netip.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) netip.Prefix {
		random := hegel.IPAddresses().IPv6()
		if prefix.Addr().Is4() {
			random = hegel.IPAddresses().IPv4()
		}
		bits := hegel.Draw(tc, pbt.Spanning(prefix.Bits(), prefix.Addr().BitLen()))
		return netip.PrefixFrom(within(prefix, hegel.Draw(tc, random)), bits).Masked()
	})
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

// edgesOf is each prefix's first and last address and the one on either side
// of them, in family v4 or IPv6
func edgesOf(v4 bool, prefixes ...netip.Prefix) []netip.Addr {
	var out []netip.Addr
	for _, prefix := range prefixes {
		if prefix.Addr().Is4() == v4 {
			out = append(out, prefix.Masked().Addr(), lastAddress(prefix), prefix.Masked().Addr().Prev(), lastAddress(prefix).Next())
		}
	}
	return slices.DeleteFunc(out, func(a netip.Addr) bool { return !a.IsValid() })
}

// schemaPrefixesOf is each prefix of an overlay list
func schemaPrefixesOf(prefixes []schema.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.Prefix)
	}
	return out
}

// unmappedIPv6 draws an IPv6 address that is not an IPv4 address written as
// one, which the overlay refuses
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
// overlay address, which an IPv4 rule with no family test would read.
func TestBorderChainDropsWhatTheModelDrops(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		inside := []string{"ranet3"}
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			size := hegel.Draw(ht, pbt.Spanning(1, unix.IFNAMSIZ))
			inside = append(inside, hegel.Draw(ht, hegel.Text().Alphabet("ranet3").MinSize(size).MaxSize(size)))
		}
		cfg := egress.Border{Overlay: hegel.Draw(ht, overlayPrefixes())}
		if err := cfg.Validate(); err != nil {
			ht.Fatalf("drew an overlay Validate refuses: %v", err)
		}
		// carve-outs on two links, each inside an overlay prefix, and the mesh's
		// prefixes inside each
		var drawn drawnSets
		for _, prefix := range cfg.Overlay {
			if !hegel.Draw(ht, hegel.Booleans()) {
				continue
			}
			carveOut := egress.CarveOut{Link: hegel.Draw(ht, hegel.SampledFrom([]string{"eth0", "eth1"})), Prefix: hegel.Draw(ht, insidePrefix(prefix.Prefix))}
			drawn.CarveOuts = append(drawn.CarveOuts, carveOut)
			for range hegel.Draw(ht, pbt.Spanning(0, 2)) {
				drawn.Carved = append(drawn.Carved, hegel.Draw(ht, insidePrefix(carveOut.Prefix)))
			}
		}
		all, sets, _ := newBorderFilter(&cfg, egress.BorderRuntime{Tun: "ranet3", Inside: inside, Sets: drawn.borderSets}, &fakeBorder{}).desired()
		requests, err := borderBatch(all, sets, false)
		refused := slices.ContainsFunc(inside, func(name string) bool { return len(name) >= unix.IFNAMSIZ })
		if refused != (err != nil) {
			ht.Fatalf("the chain over inside %q encoded with %v, want refused %v", inside, err, refused)
		}
		if refused {
			return
		}
		desired, rules := chainRules(all, requests, BorderChain)
		held := encodedSets(ht, requests)

		v4 := hegel.Draw(ht, hegel.Booleans())
		edges := edgesOf(v4, schemaPrefixesOf(cfg.Overlay)...)
		for _, carveOut := range drawn.CarveOuts {
			edges = append(edges, edgesOf(v4, carveOut.Prefix)...)
		}
		edges = append(edges, edgesOf(v4, drawn.Carved...)...)
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
		// an IPv6 source whose bytes 4 to 7 spell an IPv4 overlay or carved edge
		if spelled := edgesOf(true, append(schemaPrefixesOf(cfg.Overlay), drawn.Carved...)...); !v4 && len(spelled) != 0 && hegel.Draw(ht, hegel.WeightedBooleans(1.0/3)) {
			raw, inner := p.source.As16(), hegel.Draw(ht, hegel.SampledFrom(spelled)).As4()
			copy(raw[4:8], inner[:])
			p.source = netip.AddrFrom16(raw)
		}
		p.destination = hegel.Draw(ht, random)
		arrivals := []string{"eth0", "eth1", "eth", "ranet3a1b2"}
		for _, name := range inside {
			arrivals = append(arrivals, name, name[:len(name)-1])
			if len(name) < unix.IFNAMSIZ-1 {
				arrivals = append(arrivals, name+"a")
			}
		}
		arrivals = slices.DeleteFunc(arrivals, func(name string) bool { return name == "" })
		p.iif = hegel.Draw(ht, hegel.SampledFrom(arrivals))

		wire := p.wire()
		wire.sets = held
		run := runChain(ht, rules, wire)
		accept, reason := borderModel(inside, cfg, drawn, p)
		where := fmt.Sprintf("a packet %+v through inside %q, overlay %v and carve-outs %+v", p, inside, cfg.Overlay, drawn)
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

// entryPacket is a packet the entry property sends at the chain: the device
// it leaves by, its flow's direction, original, reply or untracked, and its
// addresses
type entryPacket struct {
	oif                 string
	direction           string
	source, destination netip.Addr
}

// entryModel gives the verdict the entry chain means for a packet, as 2.8
// writes it: one leaving by another device than the tun, one of a flow's reply
// direction, one to an IPv6 link-local or multicast address, one from a source
// this node owns and one to a destination translated none pass, and anything
// else is dropped
func entryModel(tun string, sets drawnSets, p entryPacket) bool {
	holds := func(prefixes []netip.Prefix, address netip.Addr) bool {
		return slices.ContainsFunc(prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
	}
	return p.oif != tun || p.direction == "reply" ||
		holds([]netip.Prefix{netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8")}, p.destination) ||
		holds(sets.Owned, p.source) || holds(sets.None, p.destination)
}

// entryPrefixes draws up to three prefixes of either family, at lengths
// spanning each family's
func entryPrefixes() hegel.Generator[[]netip.Prefix] {
	return hegel.Composite(func(tc hegel.TestCase) []netip.Prefix {
		var out []netip.Prefix
		for range hegel.Draw(tc, pbt.Spanning(0, 3)) {
			if hegel.Draw(tc, hegel.Booleans()) {
				out = append(out, netip.PrefixFrom(hegel.Draw(tc, hegel.IPAddresses().IPv4()), hegel.Draw(tc, pbt.Spanning(1, 32))).Masked())
			} else {
				out = append(out, netip.PrefixFrom(hegel.Draw(tc, unmappedIPv6()), hegel.Draw(tc, pbt.Spanning(1, 128))).Masked())
			}
		}
		return out
	})
}

// For drawn owned and none sets and a drawn packet, the encoded entry chain,
// executed byte by byte by the interpreter, passes or drops the packet as
// entryModel does and counts a drop as mesh_entry, never a pass. The output
// devices share the tun's prefix, the addresses sit on either side of each
// set's edges and of the IPv6 link-local and multicast prefixes, and an IPv6
// packet's address bytes now and then spell an IPv4 set's edge where an IPv4
// rule with no family test would read it.
func TestEntryChainReturnsWhatTheModelReturns(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		const tun = "ranet3"
		drawn := drawnSets{Owned: hegel.Draw(ht, entryPrefixes()), None: hegel.Draw(ht, entryPrefixes())}
		var cfg *egress.Border
		if hegel.Draw(ht, hegel.Booleans()) {
			cfg = &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.0/15"), schema.MustPrefix("3fff::/20")}}
		}
		all, sets, _ := newBorderFilter(cfg, egress.BorderRuntime{Tun: tun, Inside: []string{tun, "lo"}, Sets: drawn.borderSets}, &fakeBorder{}).desired()
		requests, err := borderBatch(all, sets, false)
		if err != nil {
			ht.Fatalf("encode the table: %v", err)
		}
		desired, rules := chainRules(all, requests, EntryChain)

		v4 := hegel.Draw(ht, hegel.Booleans())
		random := hegel.IPAddresses().IPv6()
		if v4 {
			random = hegel.IPAddresses().IPv4()
		}
		address := func(edges []netip.Addr) netip.Addr {
			if len(edges) != 0 && hegel.Draw(ht, hegel.WeightedBooleans(3.0/4)) {
				return hegel.Draw(ht, hegel.SampledFrom(edges))
			}
			return hegel.Draw(ht, random)
		}
		p := entryPacket{
			oif:       hegel.Draw(ht, hegel.SampledFrom([]string{tun, tun, tun, tun[:len(tun)-1], tun + "a", "eth0"})),
			direction: hegel.Draw(ht, hegel.SampledFrom([]string{"original", "reply", "untracked"})),
			source:    address(edgesOf(v4, drawn.Owned...)),
			destination: address(edgesOf(v4, append(slices.Clone(drawn.None),
				netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"))...)),
		}
		// an IPv6 source's bytes 4 to 7 sit where an IPv4 source is read, and its
		// bytes 8 to 11 where an IPv4 destination is
		if !v4 {
			raw := p.source.As16()
			if spelled := edgesOf(true, drawn.Owned...); len(spelled) != 0 && hegel.Draw(ht, hegel.Booleans()) {
				inner := hegel.Draw(ht, hegel.SampledFrom(spelled)).As4()
				copy(raw[4:8], inner[:])
			}
			if spelled := edgesOf(true, drawn.None...); len(spelled) != 0 && hegel.Draw(ht, hegel.Booleans()) {
				inner := hegel.Draw(ht, hegel.SampledFrom(spelled)).As4()
				copy(raw[8:12], inner[:])
			}
			p.source = netip.AddrFrom16(raw)
		}

		wire := drawnPacket{iif: "eth0", source: p.source, destination: p.destination}.wire()
		wire.oif, wire.sets = p.oif, encodedSets(ht, requests)
		switch p.direction {
		case "untracked":
			wire.ctState = nftables.CTStateUntracked
		case "reply":
			wire.reply = true
		}
		run := runChain(ht, rules, wire)
		accept := entryModel(tun, drawn, p)
		where := fmt.Sprintf("a packet %+v over owned %v and none %v", p, drawn.Owned, drawn.None)
		switch {
		case run.accept != accept:
			ht.Fatalf("%s: the chain passed %v at rule %d, the model %v", where, run.accept, run.rule, accept)
		case !accept && (!run.counted || desired[run.rule].Reason() != "mesh_entry"):
			ht.Fatalf("%s: dropped by %s, counted %v, want counted as mesh_entry", where, desired[run.rule], run.counted)
		case accept && run.counted:
			ht.Fatalf("%s: passed by a rule carrying a counter", where)
		}
	})
}
