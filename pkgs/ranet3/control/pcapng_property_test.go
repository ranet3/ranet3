// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// pcapngBlockRead is one block as draft-ietf-opsawg-pcapng-06 section 3.1 frames it
type pcapngBlockRead struct {
	kind uint32
	body []byte
}

// pcapngOptionRead is one option of a block's list, section 3.5
type pcapngOptionRead struct {
	code  uint16
	value []byte
}

// readPcapng reads file as a pcapng file of one section, its byte order the one its section header's magic names, section 4.1
// it refuses a file that does not begin with a section header, a block whose two lengths differ or are not a multiple of 4, and one that runs past the file
func readPcapng(file []byte) (binary.ByteOrder, []pcapngBlockRead, error) {
	if len(file) < 12 || !bytes.Equal(file[:4], []byte{0x0A, 0x0D, 0x0D, 0x0A}) {
		return nil, nil, errors.New("the file does not begin with a section header block")
	}
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(file[8:]) == 0x1A2B3C4D:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(file[8:]) == 0x1A2B3C4D:
		order = binary.BigEndian
	default:
		return nil, nil, fmt.Errorf("the section header's byte-order magic is %x", file[8:12])
	}
	var blocks []pcapngBlockRead
	for rest := file; len(rest) != 0; {
		if len(rest) < 12 {
			return nil, nil, fmt.Errorf("%d bytes trail the last block", len(rest))
		}
		length := order.Uint32(rest[4:])
		if length < 12 || length%4 != 0 || int(length) > len(rest) {
			return nil, nil, fmt.Errorf("a block of type %#x gives the length %d with %d bytes left", order.Uint32(rest), length, len(rest))
		}
		if trailing := order.Uint32(rest[length-4:]); trailing != length {
			return nil, nil, fmt.Errorf("a block of type %#x gives the length %d before its body and %d after it", order.Uint32(rest), length, trailing)
		}
		blocks = append(blocks, pcapngBlockRead{kind: order.Uint32(rest), body: rest[8 : length-4]})
		rest = rest[length:]
	}
	return order, blocks, nil
}

// readPcapngOptions reads an option list, each value padded with zeros to 32 bits, which a writer ends with opt_endofopt
func readPcapngOptions(order binary.ByteOrder, list []byte) ([]pcapngOptionRead, error) {
	var options []pcapngOptionRead
	for len(list) != 0 {
		if len(list) < 4 {
			return nil, fmt.Errorf("%d bytes trail the options", len(list))
		}
		code, length := order.Uint16(list), int(order.Uint16(list[2:]))
		padded := (length + 3) &^ 3
		if 4+padded > len(list) {
			return nil, fmt.Errorf("option %d of %d bytes runs past its block", code, length)
		}
		if slices.ContainsFunc(list[4+length:4+padded], func(b byte) bool { return b != 0 }) {
			return nil, fmt.Errorf("option %d is padded with %x", code, list[4+length:4+padded])
		}
		if code == 0 {
			if length != 0 || len(list) != 4 {
				return nil, fmt.Errorf("opt_endofopt of length %d is followed by %d bytes", length, len(list)-4)
			}
			return options, nil
		}
		options = append(options, pcapngOptionRead{code: code, value: list[4 : 4+length]})
		list = list[4+padded:]
	}
	return nil, errors.New("the option list does not end with opt_endofopt")
}

// pcapngPacketRead is an enhanced packet block, section 4.3, its time read under the resolution of its interface
type pcapngPacketRead struct {
	time       time.Time
	data       []byte
	original   uint32
	comments   []string
	linkType   uint16
	snapLength uint32
}

// readPcapngPackets reads file's section header, interfaces and enhanced packet blocks, refusing any other block
func readPcapngPackets(file []byte) ([]pcapngPacketRead, error) {
	order, blocks, err := readPcapng(file)
	if err != nil {
		return nil, err
	}
	shb := blocks[0].body
	if len(shb) < 16 || order.Uint16(shb[4:]) != 1 || order.Uint16(shb[6:]) != 0 {
		return nil, fmt.Errorf("the section header %x is not one of version 1.0", shb)
	}
	if length := int64(order.Uint64(shb[8:])); length != -1 && (length < 0 || length%4 != 0) {
		return nil, fmt.Errorf("the section length is %d", length)
	}
	if len(shb) > 16 {
		if _, err := readPcapngOptions(order, shb[16:]); err != nil {
			return nil, err
		}
	}
	type iface struct {
		linkType   uint16
		snapLength uint32
		// unit is the length of a timestamp's unit, 10^-6 seconds where if_tsresol is absent, section 4.2
		unit time.Duration
	}
	var interfaces []iface
	var packets []pcapngPacketRead
	for _, block := range blocks[1:] {
		body := block.body
		switch block.kind {
		case 1:
			if len(body) < 8 || order.Uint16(body[2:]) != 0 {
				return nil, fmt.Errorf("the interface description block %x holds no link type or a reserved field other than 0", body)
			}
			options, err := readPcapngOptions(order, body[8:])
			if err != nil {
				return nil, err
			}
			in := iface{linkType: order.Uint16(body), snapLength: order.Uint32(body[4:]), unit: time.Microsecond}
			for _, option := range options {
				if option.code != 9 {
					continue
				}
				if len(option.value) != 1 || option.value[0]&0x80 != 0 || option.value[0] > 9 {
					return nil, fmt.Errorf("if_tsresol is %x, which this reader takes only as a power of 10 down to nanoseconds", option.value)
				}
				in.unit = time.Second
				for range option.value[0] {
					in.unit /= 10
				}
			}
			interfaces = append(interfaces, in)
		case 6:
			if len(body) < 20 {
				return nil, fmt.Errorf("the enhanced packet block %x is too short", body)
			}
			id := order.Uint32(body)
			if int(id) >= len(interfaces) {
				return nil, fmt.Errorf("a packet names interface %d of %d", id, len(interfaces))
			}
			in := interfaces[id]
			units := uint64(order.Uint32(body[4:]))<<32 | uint64(order.Uint32(body[8:]))
			captured, original := int(order.Uint32(body[12:])), order.Uint32(body[16:])
			padded := (captured + 3) &^ 3
			if 20+padded > len(body) {
				return nil, fmt.Errorf("a packet of %d bytes runs past its block", captured)
			}
			if slices.ContainsFunc(body[20+captured:20+padded], func(b byte) bool { return b != 0 }) {
				return nil, fmt.Errorf("a packet's data is padded with %x", body[20+captured:20+padded])
			}
			options, err := readPcapngOptions(order, body[20+padded:])
			if err != nil {
				return nil, err
			}
			packet := pcapngPacketRead{
				time: time.Unix(0, 0).Add(time.Duration(units) * in.unit), data: body[20 : 20+captured], original: original,
				linkType: in.linkType, snapLength: in.snapLength,
			}
			for _, option := range options {
				if option.code == 1 {
					packet.comments = append(packet.comments, string(option.value))
				}
			}
			packets = append(packets, packet)
		default:
			return nil, fmt.Errorf("a block of type %#x", block.kind)
		}
	}
	return packets, nil
}

// lineComment is the line RenderTracePacket writes for p without its payload
func lineComment(p TracePacket) string {
	var line strings.Builder
	RenderTracePacket(&line, p)
	words := strings.Fields(line.String())
	return strings.Join(slices.DeleteFunc(words, func(word string) bool { return strings.HasPrefix(word, "payload=") }), " ")
}

// drawTracePacket draws a record the writer takes, its payload length drawn by its residue mod 4 and up to TracePayloadMax
// its comment's length by its residue mod 4, and its time on both sides of 2^32 nanoseconds after the epoch
func drawTracePacket(ht *hegel.T) TracePacket {
	family := hegel.Draw(ht, hegel.SampledFrom([]int{4, 6}))
	addresses := hegel.IPAddresses().IPv4()
	if family == 6 {
		addresses = hegel.IPAddresses().IPv6()
	}
	p := TracePacket{
		Arrival:     hegel.Draw(ht, hegel.SampledFrom([]string{"session", "tun", "none"})),
		Decision:    hegel.Draw(ht, hegel.SampledFrom(TraceDecisions)),
		Reason:      hegel.Draw(ht, hegel.SampledFrom([]string{"", "expired", "budget", "forged"})),
		Next:        hegel.Draw(ht, hegel.SampledFrom([]string{"", "example/relay:1@0"})),
		Source:      hegel.Draw(ht, addresses),
		Destination: hegel.Draw(ht, addresses),
		Protocol:    hegel.Draw(ht, hegel.SampledFrom([]uint8{1, 6, 17, 58, 132, 47, 253})),
		Headers:     pbt.Subset(ht, []string{"hop-by-hop", "routing", "fragment"}, 0, 3),
		Transport:   hegel.Draw(ht, hegel.Booleans()),
		HopLimit:    hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8)),
		Fragments:   hegel.Draw(ht, pbt.Spanning(0, 3)),
		Answer:      hegel.Draw(ht, hegel.SampledFrom([]string{"", "expired", "too_big"})),
		Outcome:     hegel.Draw(ht, hegel.SampledFrom([]string{"", "sent", "withheld"})),
	}
	if hegel.Draw(ht, hegel.Booleans()) {
		p.Segment = hegel.Draw(ht, hegel.IPAddresses().IPv6())
	}
	p.SourcePort, p.DestinationPort = hegel.Draw(ht, pbt.Spanning[uint16](0, math.MaxUint16)), hegel.Draw(ht, pbt.Spanning[uint16](0, math.MaxUint16))
	p.TCPFlags, p.ICMPType, p.ICMPCode = hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8)), hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8)), hegel.Draw(ht, pbt.Spanning[uint8](0, math.MaxUint8))
	// TracePayloadMax is 4*16383 + 3, so the payload spans 0 to it
	payload := 4*hegel.Draw(ht, pbt.Spanning(0, TracePayloadMax/4)) + hegel.Draw(ht, pbt.Spanning(0, 3))
	p.Payload = make([]byte, payload)
	seed := hegel.Draw(ht, pbt.Spanning[uint8](1, math.MaxUint8))
	for i := range p.Payload {
		p.Payload[i] = byte(i) * seed
	}
	p.Length = payload + hegel.Draw(ht, pbt.Spanning(0, 1<<17))
	if hegel.Draw(ht, hegel.Booleans()) {
		p.Time = time.Unix(0, hegel.Draw(ht, pbt.Spanning[int64](1<<32, math.MaxInt64)))
	} else {
		p.Time = time.Unix(0, hegel.Draw(ht, pbt.Spanning[int64](0, 1<<32-1)))
	}
	// from= is the field the residue of the comment's length is set by
	residue := hegel.Draw(ht, pbt.Spanning(0, 3))
	from := "example/a"
	p.From = from + strings.Repeat("a", (residue-len(lineComment(p))-len(" from=")-len(from))&3)
	return p
}

// a file the writer wrote reads back under the draft's layout as one section of one raw IP interface at nanosecond resolution
// each record one packet whose data, original length, time and comment are the record's, every block framed and padded as section 3 says
func TestTracePcapReadsBackUnderTheDraftsLayout(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var records []TracePacket
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			records = append(records, drawTracePacket(ht))
		}
		var file bytes.Buffer
		w, err := NewTracePcap(&file)
		if err != nil {
			ht.Fatal(err)
		}
		for _, p := range records {
			if err := w.Write(p); err != nil {
				ht.Fatalf("the writer refused %+v: %v", p, err)
			}
		}
		packets, err := readPcapngPackets(file.Bytes())
		if err != nil {
			ht.Fatalf("the file does not read back: %v", err)
		}
		if len(packets) != len(records) {
			ht.Fatalf("%d records read back as %d packets", len(records), len(packets))
		}
		for i, p := range records {
			got := packets[i]
			switch {
			case got.linkType != 101 || got.snapLength != TracePayloadMax:
				ht.Fatalf("packet %d lies on an interface of link type %d and snap length %d", i, got.linkType, got.snapLength)
			case !bytes.Equal(got.data, p.Payload) || got.original != uint32(p.Length):
				ht.Fatalf("packet %d reads back as %d bytes of %d, from %d of %d", i, len(got.data), got.original, len(p.Payload), p.Length)
			case !got.time.Equal(p.Time):
				ht.Fatalf("packet %d reads back at %v, recorded at %v", i, got.time, p.Time)
			case len(got.comments) != 1 || got.comments[0] != lineComment(p):
				ht.Fatalf("packet %d reads back with the comments %q, want %q", i, got.comments, lineComment(p))
			}
		}
	})
}

// the writer refuses a record a block cannot hold as it is, and writes nothing of it
func TestTracePcapRefusesWhatABlockCannotHold(t *testing.T) {
	ok := TracePacket{Time: time.Unix(1, 0), Decision: "forward", Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.3"), Length: 20, Payload: make([]byte, 20)}
	for _, c := range []struct {
		name   string
		change func(*TracePacket)
	}{
		{"a payload past the snap length", func(p *TracePacket) { p.Payload, p.Length = make([]byte, TracePayloadMax+1), TracePayloadMax+1 }},
		{"a length short of the payload", func(p *TracePacket) { p.Length = 19 }},
		{"a length past 32 bits", func(p *TracePacket) { p.Length = math.MaxUint32 + 1 }},
		{"a time before the epoch", func(p *TracePacket) { p.Time = time.Unix(0, -1) }},
		{"no time", func(p *TracePacket) { p.Time = time.Time{} }},
		{"a comment past 65535 bytes", func(p *TracePacket) { p.From = strings.Repeat("a", math.MaxUint16) }},
		{"a comment of invalid UTF-8", func(p *TracePacket) { p.From = "\xff" }},
	} {
		var file bytes.Buffer
		w, err := NewTracePcap(&file)
		if err != nil {
			t.Fatal(err)
		}
		header := file.Len()
		if err := w.Write(ok); err != nil {
			t.Fatalf("the writer refused %+v: %v", ok, err)
		}
		p := ok
		c.change(&p)
		written := file.Len()
		if err := w.Write(p); err == nil || file.Len() != written {
			t.Errorf("%s: the writer answered %v and wrote %d bytes", c.name, err, file.Len()-written)
		}
		if written == header {
			t.Errorf("%s: the record before it wrote nothing", c.name)
		}
	}
}
