// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
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

// A set and a ct timeout object read back as written: each decodes to its
// fields, carries no fault against itself, carries one against another of its
// name exactly where a field differs, remade where nf_tables would not change
// it in place, and passes one of another name or type
func TestSetsAndTimeoutsReadBackAsWritten(t *testing.T) {
	names := hegel.Text().Alphabet("ranet3-flows46").MinSize(1).MaxSize(unix.NFT_NAME_MAXLEN - 1)
	sets := func(table, name string) hegel.Generator[Set] {
		return hegel.Composite(func(tc hegel.TestCase) Set {
			return Set{
				Table:   table,
				Name:    name,
				ID:      hegel.Draw(tc, hegel.Integers[uint32](0, math.MaxUint32)),
				KeyType: hegel.Draw(tc, hegel.SampledFrom([]uint32{TypeIPv4Addr, TypeIPv6Addr})),
				KeyLen:  hegel.Draw(tc, hegel.SampledFrom([]uint32{4, 16})),
				Flags:   hegel.Draw(tc, hegel.SampledFrom([]uint32{0, unix.NFT_SET_EVAL, unix.NFT_SET_EVAL | unix.NFT_SET_TIMEOUT})),
				Size:    hegel.Draw(tc, pbt.Spanning[uint32](0, math.MaxUint32)),
				Comment: hegel.Draw(tc, hegel.Text().Alphabet("limit 0123456789").MaxSize(udataCommentMax)),
			}
		})
	}
	timeouts := func(table, name string) hegel.Generator[Timeout] {
		return hegel.Composite(func(tc hegel.TestCase) Timeout {
			policy := make([]uint32, hegel.Draw(tc, hegel.Integers(1, 11)))
			for i := range policy {
				policy[i] = hegel.Draw(tc, pbt.Spanning[uint32](0, math.MaxUint32))
			}
			return Timeout{
				Table:   table,
				Name:    name,
				L3Proto: hegel.Draw(tc, hegel.SampledFrom([]uint16{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6})),
				L4Proto: hegel.Draw(tc, hegel.SampledFrom([]uint8{unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6})),
				Policy:  policy,
			}
		})
	}
	pbt.Check(t, func(ht *hegel.T) {
		proto := hegel.Draw(ht, hegel.SampledFrom([]uint8{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6}))
		table, name := hegel.Draw(ht, names), hegel.Draw(ht, names)
		conn := &Conn{pid: hegel.Draw(ht, hegel.Integers[uint32](0, math.MaxUint32))}
		framed := func(request Request) Message {
			messages, err := parseMessages(conn.appendMessage(nil, request.Kind, request.Flags, 1, request.Body))
			if err != nil || len(messages) != 1 || !bytes.Equal(messages[0].Data, request.Body) || messages[0].Data[0] != proto {
				ht.Fatalf("a request of kind %#x reads back as %d messages: %v", request.Kind, len(messages), err)
			}
			return messages[0]
		}

		madeSet := func(s Set) Message {
			request, err := s.Create(proto)
			if err != nil {
				ht.Fatalf("%+v was refused: %v", s, err)
			}
			return framed(request)
		}
		s := hegel.Draw(ht, sets(table, name))
		created := madeSet(s)
		if got := DecodeSet(created); got != (Set{Table: s.Table, Name: s.Name, KeyType: s.KeyType, KeyLen: s.KeyLen, Flags: s.Flags, Size: s.Size, Comment: s.Comment}) {
			ht.Fatalf("%+v reads back as %+v", s, got)
		}
		if fault, remake := s.Fault(created); fault != "" || remake {
			ht.Fatalf("%+v reads back against itself with the fault %q, remade %v", s, fault, remake)
		}
		other := hegel.Draw(ht, sets(table, name))
		kept := other.KeyType != s.KeyType || other.KeyLen != s.KeyLen || other.Flags != s.Flags || other.Comment != s.Comment
		if fault, remake := s.Fault(madeSet(other)); (fault != "") != (kept || other.Size != s.Size) || remake != kept {
			ht.Fatalf("%+v reads back against %+v with the fault %q, remade %v", other, s, fault, remake)
		}
		// a set drawn whole rarely differs in its size alone, the one difference
		// Fault leaves to the next Create
		resized := s
		resized.Size = hegel.Draw(ht, pbt.Spanning[uint32](0, math.MaxUint32))
		if fault, remake := s.Fault(madeSet(resized)); (fault != "") != (resized.Size != s.Size) || remake {
			ht.Fatalf("%+v reads back against %+v with the fault %q, remade %v", resized, s, fault, remake)
		}
		if fault, _ := (Set{Table: table, Name: name + "x"}).Fault(created); fault != "" {
			ht.Fatalf("a set of another name reads back with the fault %q", fault)
		}

		o := hegel.Draw(ht, timeouts(table, name))
		made := framed(o.Create(proto))
		if got, ok := DecodeTimeout(made); !ok || got.Table != o.Table || got.Name != o.Name || got.L3Proto != o.L3Proto || got.L4Proto != o.L4Proto || !slices.Equal(got.Policy, o.Policy) {
			ht.Fatalf("%+v reads back as %+v, a ct timeout %v", o, got, ok)
		}
		if fault, remake := o.Fault(made); fault != "" || remake {
			ht.Fatalf("%+v reads back against itself with the fault %q, remade %v", o, fault, remake)
		}
		differ := hegel.Draw(ht, timeouts(table, name))
		differs := differ.L3Proto != o.L3Proto || differ.L4Proto != o.L4Proto || !slices.Equal(differ.Policy, o.Policy)
		if fault, remake := o.Fault(framed(differ.Create(proto))); (fault != "") != differs || remake != differs {
			ht.Fatalf("%+v reads back against %+v with the fault %q, remade %v", differ, o, fault, remake)
		}
		counter := made
		counter.Data = PutAttrString(PutAttrString(PutNfgenmsg(nil, proto), unix.NFTA_OBJ_TABLE, table), unix.NFTA_OBJ_NAME, name)
		counter.Data = PutAttrBE32(counter.Data, unix.NFTA_OBJ_TYPE, unix.NFT_OBJECT_COUNTER)
		if _, ok := DecodeTimeout(counter); ok {
			ht.Fatal("a counter of its name decodes as a ct timeout")
		}
		if fault, _ := o.Fault(counter); fault != "" {
			ht.Fatalf("a counter of its name reads back with the fault %q", fault)
		}
	})
}
