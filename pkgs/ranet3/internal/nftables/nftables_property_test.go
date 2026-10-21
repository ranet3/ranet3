// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// matches runs expressions as nf_tables does over a packet whose network
// header is header: payload loads into register 1, bitwise masks and xors it,
// and cmp ends the rule unless the register holds its value
func matches(t *hegel.T, expressions []byte, header []byte) bool {
	var register []byte
	for _, element := range Nested(expressions) {
		var name string
		fields := map[uint16][]byte{}
		for _, field := range Nested(element.Value) {
			switch field.Kind {
			case unix.NFTA_EXPR_NAME:
				name = unix.ByteSliceToString(field.Value)
			case unix.NFTA_EXPR_DATA:
				for _, inner := range Nested(field.Value) {
					fields[inner.Kind] = inner.Value
				}
			}
		}
		switch name {
		case "payload":
			if binary.BigEndian.Uint32(fields[unix.NFTA_PAYLOAD_BASE]) != unix.NFT_PAYLOAD_NETWORK_HEADER {
				t.Fatalf("a load from base %x", fields[unix.NFTA_PAYLOAD_BASE])
			}
			offset := binary.BigEndian.Uint32(fields[unix.NFTA_PAYLOAD_OFFSET])
			length := binary.BigEndian.Uint32(fields[unix.NFTA_PAYLOAD_LEN])
			register = bytes.Clone(header[offset : offset+length])
		case "bitwise":
			mask, xor := value(fields[unix.NFTA_BITWISE_MASK]), value(fields[unix.NFTA_BITWISE_XOR])
			if len(mask) != len(register) || len(xor) != len(register) {
				t.Fatalf("a bitwise of %d and %d bytes over a register of %d", len(mask), len(xor), len(register))
			}
			for i := range register {
				register[i] = register[i]&mask[i] ^ xor[i]
			}
		case "cmp":
			want := value(fields[unix.NFTA_CMP_DATA])
			equal := len(register) >= len(want) && bytes.Equal(register[:len(want)], want)
			switch binary.BigEndian.Uint32(fields[unix.NFTA_CMP_OP]) {
			case unix.NFT_CMP_EQ:
				if !equal {
					return false
				}
			case unix.NFT_CMP_NEQ:
				if equal {
					return false
				}
			default:
				t.Fatalf("a cmp of op %x", fields[unix.NFTA_CMP_OP])
			}
		default:
			t.Fatalf("an expression %q", name)
		}
	}
	return true
}

// value is the NFTA_DATA_VALUE an attribute nests
func value(attribute []byte) []byte {
	for _, inner := range Nested(attribute) {
		if inner.Kind == unix.NFTA_DATA_VALUE {
			return inner.Value
		}
	}
	return nil
}

// A source prefix's expressions take exactly the packets whose source the
// prefix holds, in either family and at every length, over sources drawn
// inside the prefix, a bit away from it and anywhere
func TestSourcePrefixTakesExactlyTheSourcesItsPrefixHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		size, offset := 4, 12
		if hegel.Draw(ht, hegel.Booleans()) {
			size, offset = 16, 8
		}
		prefix, err := addressOf(hegel.Draw(ht, hegel.Binary(size, size))).Prefix(hegel.Draw(ht, pbt.Spanning(0, size*8)))
		if err != nil {
			ht.Fatal(err)
		}
		raw := AddressBytes(prefix.Addr())
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			raw = hegel.Draw(ht, hegel.Binary(size, size))
		case 1:
			bit := hegel.Draw(ht, hegel.Integers(0, size*8-1))
			raw[bit/8] ^= 0x80 >> (bit % 8)
		}
		source := addressOf(raw)
		header := make([]byte, offset+size)
		copy(header[offset:], raw)
		var expressions []byte
		for _, expression := range SourcePrefix(prefix) {
			expressions = append(expressions, expression...)
		}
		if got, want := matches(ht, expressions, header), prefix.Contains(source); got != want {
			ht.Fatalf("%s takes a packet from %s: %v, want %v", prefix, source, got, want)
		}
	})
}

func addressOf(raw []byte) netip.Addr {
	address, _ := netip.AddrFromSlice(raw)
	return address
}

// Every table, chain and rule request reads back as written: a chain decodes
// to its table, name, type, hook and priority and carries no fault against
// itself, a chain written otherwise carries one exactly where a field differs,
// remade where the type, hook or priority does, a flush names the chain and no
// handle, and a rule decodes to its table, chain, comment and counter, each
// message framed and parsed back whole
func TestRequestsReadBackAsWritten(t *testing.T) {
	names := func() hegel.Generator[string] {
		return hegel.Text().Alphabet("ranet3_-").MinSize(1).MaxSize(unix.IFNAMSIZ)
	}
	chains := func(table, name string) hegel.Generator[Chain] {
		return hegel.Composite(func(tc hegel.TestCase) Chain {
			return Chain{
				Table:    table,
				Name:     name,
				Type:     hegel.Draw(tc, hegel.SampledFrom([]string{"filter", "nat", "route"})),
				Hook:     hegel.Draw(tc, pbt.Spanning[uint32](unix.NF_INET_PRE_ROUTING, unix.NF_INET_POST_ROUTING)),
				Priority: hegel.Draw(tc, pbt.Spanning[int32](math.MinInt32, math.MaxInt32)),
			}
		})
	}
	pbt.Check(t, func(ht *hegel.T) {
		proto := hegel.Draw(ht, hegel.SampledFrom([]uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6, unix.NFPROTO_INET}))
		table, name := hegel.Draw(ht, names()), hegel.Draw(ht, names())
		c := hegel.Draw(ht, chains(table, name))
		conn := &Conn{pid: hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32))}
		seq := hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32))
		framed := func(request Request) Message {
			messages, err := parseMessages(conn.appendMessage(nil, request.Kind, request.Flags, seq, request.Body))
			if err != nil || len(messages) != 1 {
				ht.Fatalf("a request framed reads back as %d messages: %v", len(messages), err)
			}
			got := messages[0]
			if got.Kind != request.Kind || got.Seq != seq || got.Pid != conn.pid || !bytes.Equal(got.Data, request.Body) || got.Data[0] != proto {
				ht.Fatalf("a request of kind %#x reads back as %+v", request.Kind, got)
			}
			return got
		}

		created := framed(c.Create(proto))
		if gotTable, gotName, kind, hook, priority := DecodeChain(created); gotTable != table || gotName != name || kind != c.Type || hook != c.Hook || priority != c.Priority {
			ht.Fatalf("%+v reads back as %s %s %s %d %d", c, gotTable, gotName, kind, hook, priority)
		}
		if fault, remake := c.Fault(created); fault != "" || remake {
			ht.Fatalf("%+v reads back against itself with the fault %q, remade %v", c, fault, remake)
		}
		other := hegel.Draw(ht, chains(table, name))
		differs := other.Type != c.Type || other.Hook != c.Hook || other.Priority != c.Priority
		if fault, remake := c.Fault(framed(other.Create(proto))); (fault != "") != differs || remake != differs {
			ht.Fatalf("%+v reads back against %+v with the fault %q, remade %v", other, c, fault, remake)
		}
		if fault, _ := (Chain{Table: table + "x", Name: name}).Fault(created); fault != "" {
			ht.Fatalf("a chain of another table reads back with the fault %q", fault)
		}

		flushed := map[uint16]string{}
		for kind, field := range framed(c.Flush(proto)).Attributes() {
			flushed[kind] = unix.ByteSliceToString(field)
		}
		if len(flushed) != 2 || flushed[unix.NFTA_RULE_TABLE] != table || flushed[unix.NFTA_RULE_CHAIN] != name {
			ht.Fatalf("a flush of %s %s names %v, want the table and the chain alone", table, name, flushed)
		}

		spec := hegel.Draw(ht, hegel.Text().Alphabet("ipv46 outvia-ranet3.:/0123456789").MaxSize(udataCommentMax))
		packets, octets := hegel.Draw(ht, hegel.Integers[uint64](0, math.MaxUint64)), hegel.Draw(ht, hegel.Integers[uint64](0, math.MaxUint64))
		counter := PutAttr(nil, unix.NFTA_COUNTER_BYTES, binary.BigEndian.AppendUint64(nil, octets))
		counter = PutAttr(counter, unix.NFTA_COUNTER_PACKETS, binary.BigEndian.AppendUint64(nil, packets))
		written, err := c.Rule(proto, spec, append(MetaCompare(unix.NFT_META_IIFNAME, unix.NFT_CMP_EQ, name), Expression("counter", counter)))
		if err != nil {
			ht.Fatal(err)
		}
		rule := framed(written)
		if gotTable, gotName, gotSpec, gotPackets, gotBytes := DecodeRule(rule); gotTable != table || gotName != name || gotSpec != spec || gotPackets != packets || gotBytes != octets {
			ht.Fatalf("a rule %q of %s %s with %d packets and %d bytes reads back as %q of %s %s with %d and %d", spec, table, name, packets, octets, gotSpec, gotTable, gotName, gotPackets, gotBytes)
		}
	})
}
