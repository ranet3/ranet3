// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package registry

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// object, array and literal are a JSON value as a document's text writes it, members in the order written
// a Go string is written as a JSON string holding its bytes as they are, so a test can write one that is not UTF-8
type (
	object struct {
		members []member
		// remarks is an object inside remarks, whose names are any the writer chose
		remarks bool
	}
	member struct {
		name  string
		value any
	}
	array   []any
	literal string
)

var (
	poolFamilies  = []string{"ip4", "ip6"}
	poolAddresses = []string{"", "192.0.2.1", "2001:db8::1", "gateway.example.org"}
	poolRemarks   = []string{"site", "since", "contact"}
)

func write(b *bytes.Buffer, v any) {
	switch v := v.(type) {
	case *object:
		b.WriteByte('{')
		for i, m := range v.members {
			if i > 0 {
				b.WriteByte(',')
			}
			quote(b, m.name)
			b.WriteByte(':')
			write(b, m.value)
		}
		b.WriteByte('}')
	case array:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			write(b, item)
		}
		b.WriteByte(']')
	case literal:
		b.WriteString(string(v))
	case string:
		quote(b, v)
	default:
		panic(fmt.Sprintf("no text for %T", v))
	}
}

// quote writes s as a JSON string, escaping what RFC 8259 section 7 requires and leaving every other byte as it is
func quote(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for i := range len(s) {
		switch c := s[i]; {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20:
			fmt.Fprintf(b, `\u%04x`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
}

// drawRemarks draws a node's remarks: null, or an object of a few members, one of which may hold an object of its own
func drawRemarks(tc hegel.TestCase) any {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		return literal("null")
	}
	remarks := &object{remarks: true}
	for _, name := range pbt.Subset(tc, poolRemarks, 0, len(poolRemarks)) {
		var value any = drawFrom(tc, poolNames)
		if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
			value = &object{remarks: true, members: []member{{"by", drawFrom(tc, poolNames)}}}
		}
		remarks.members = append(remarks.members, member{name, value})
	}
	return remarks
}

// drawLoadable draws a document Validate accepts with at least least blocks, as the value and as the text that writes it
func drawLoadable(tc hegel.TestCase, least int) (Registry, array) {
	var document Registry
	var text array
	listed := map[string][]string{}
	for range hegel.Draw(tc, pbt.Spanning(least, 3)) {
		block := Organization{Organization: drawFrom(tc, poolOrganizations), PublicKey: drawFrom(tc, poolPEMs)}
		free := slices.DeleteFunc(slices.Clone(poolNames), func(name string) bool { return slices.Contains(listed[block.Organization], name) })
		var nodes array
		for _, name := range pbt.Subset(tc, free, 0, 3) {
			listed[block.Organization] = append(listed[block.Organization], name)
			node := Node{CommonName: name}
			var endpoints array
			for _, serial := range pbt.Subset(tc, poolSerials, 0, 2) {
				endpoint := Endpoint{SerialNumber: serial, AddressFamily: drawFrom(tc, poolFamilies), Port: hegel.Draw(tc, pbt.Spanning[uint16](1, 65535))}
				var address any = literal("null")
				if at := hegel.Draw(tc, pbt.Spanning(0, len(poolAddresses))); at < len(poolAddresses) {
					endpoint.Address = &poolAddresses[at]
					address = poolAddresses[at]
				}
				node.Endpoints = append(node.Endpoints, endpoint)
				endpoints = append(endpoints, &object{members: []member{
					{"serial_number", endpoint.SerialNumber},
					{"address_family", endpoint.AddressFamily},
					{"address", address},
					{"port", literal(strconv.Itoa(int(endpoint.Port)))},
				}})
			}
			block.Nodes = append(block.Nodes, node)
			nodes = append(nodes, &object{members: []member{
				{"common_name", node.CommonName},
				{"endpoints", endpoints},
				{"remarks", drawRemarks(tc)},
			}})
		}
		document = append(document, block)
		text = append(text, &object{members: []member{
			{"organization", block.Organization},
			{"public_key", block.PublicKey},
			{"nodes", nodes},
		}})
	}
	return document, text
}

// levels lists the objects of v by depth: the blocks at 0, their nodes at 1, endpoints and remarks at 2, an object inside remarks at 3
func levels(v any, depth int, out [][]*object) [][]*object {
	switch v := v.(type) {
	case *object:
		for len(out) <= depth {
			out = append(out, nil)
		}
		out[depth] = append(out[depth], v)
		for _, m := range v.members {
			out = levels(m.value, depth+1, out)
		}
	case array:
		for _, item := range v {
			out = levels(item, depth, out)
		}
	}
	return out
}

// drawMember draws a depth, then one of the members keep takes among the objects at that depth
// a document of at least one block always holds one, since every keep below takes a block's organization
func drawMember(ht *hegel.T, text array, keep func(*object, member) bool) (*object, int) {
	type slot struct {
		o *object
		i int
	}
	var depths [][]slot
	for _, level := range levels(text, 0, nil) {
		var slots []slot
		for _, o := range level {
			for i, m := range o.members {
				if keep(o, m) {
					slots = append(slots, slot{o, i})
				}
			}
		}
		if len(slots) > 0 {
			depths = append(depths, slots)
		}
	}
	if len(depths) == 0 {
		ht.Fatalf("the draw made a document with no member to change")
	}
	slots := depths[hegel.Draw(ht, pbt.Spanning(0, len(depths)-1))]
	drawn := slots[hegel.Draw(ht, pbt.Spanning(0, len(slots)-1))]
	return drawn.o, drawn.i
}

// drawSpelling draws another spelling of a lowercase name that Unicode case folding matches to it, with one letter in upper case, a k as the Kelvin sign U+212A or an s as the long s U+017F
func drawSpelling(tc hegel.TestCase, name string) string {
	folds := map[byte]string{'k': string(rune(0x212A)), 's': string(rune(0x017F))}
	var spellings []string
	for i := range len(name) {
		if c := name[i]; c >= 'a' && c <= 'z' {
			spellings = append(spellings, name[:i]+string(c-'a'+'A')+name[i+1:])
		}
		if fold, ok := folds[name[i]]; ok {
			spellings = append(spellings, name[:i]+fold+name[i+1:])
		}
	}
	return drawFrom(tc, spellings)
}

func loadDrawn(ht *hegel.T, text array) (*Index, string, error) {
	var b bytes.Buffer
	write(&b, text)
	x, err := loadText(ht, b.String())
	return x, b.String(), err
}

func refusedByTheParse(ht *hegel.T, what, text string, err error) {
	if err == nil {
		ht.Fatalf("a document with %s was loaded: %q", what, text)
	}
	if !strings.HasPrefix(err.Error(), "registry: parse ") {
		ht.Fatalf("a document with %s was refused as %q, want the parse to refuse it: %q", what, err, text)
	}
}

// the text of a document Validate accepts loads as the index of that document
func TestLoadReadsADocumentAsItsTextWritesIt(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		document, text := drawLoadable(ht, 0)
		want, err := New(document)
		if err != nil {
			ht.Fatalf("the draw made a document Validate refuses: %v", err)
		}
		got, written, err := loadDrawn(ht, text)
		if err != nil || !reflect.DeepEqual(got, want) {
			ht.Fatalf("%q loaded as %+v, %v, want %+v", written, got, err, want)
		}
	})
}

func TestLoadRefusesAMemberNamedTwice(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		_, text := drawLoadable(ht, 1)
		o, i := drawMember(ht, text, func(*object, member) bool { return true })
		at := hegel.Draw(ht, pbt.Spanning(0, len(o.members)))
		o.members = slices.Insert(o.members, at, o.members[i])
		_, written, err := loadDrawn(ht, text)
		refusedByTheParse(ht, o.members[at].name+" twice", written, err)
	})
}

func TestLoadRefusesAMemberInAnotherSpelling(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		_, text := drawLoadable(ht, 1)
		o, i := drawMember(ht, text, func(o *object, _ member) bool { return !o.remarks })
		name := o.members[i].name
		o.members[i].name = drawSpelling(ht, name)
		_, written, err := loadDrawn(ht, text)
		refusedByTheParse(ht, name+" spelled "+strconv.Quote(o.members[i].name), written, err)
	})
}

func TestLoadRefusesInvalidUTF8(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		_, text := drawLoadable(ht, 1)
		o, i := drawMember(ht, text, func(_ *object, m member) bool { _, ok := m.value.(string); return ok })
		s := o.members[i].value.(string)
		at := hegel.Draw(ht, pbt.Spanning(0, len(s)))
		bad := hegel.Draw(ht, pbt.Spanning[byte](0x80, 0xff))
		o.members[i].value = s[:at] + string([]byte{bad}) + s[at:]
		_, written, err := loadDrawn(ht, text)
		refusedByTheParse(ht, fmt.Sprintf("byte %#x in %s", bad, o.members[i].name), written, err)
	})
}
