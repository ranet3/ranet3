// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package identity

import (
	"bytes"
	"strings"
	"testing"
)

// a second spelling of one length would let two byte sequences read as one name
func TestDERLengthMustBeMinimal(t *testing.T) {
	content := bytes.Repeat([]byte{0x41}, 200)
	for name, header := range map[string][]byte{
		"long form for a length the short form holds": {0x04, 0x81, 0x05},
		"one leading zero octet":                      {0x04, 0x82, 0x00, 0xc8},
		"three leading zero octets":                   {0x04, 0x84, 0x00, 0x00, 0x00, 0xc8},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := derElement(append(header, content...)); err == nil {
				t.Error("a non-minimal length was accepted, so one name has more than one encoding")
			}
		})
	}
	if _, body, _, err := derElement(append([]byte{0x04, 0x05}, content[:5]...)); err != nil || len(body) != 5 {
		t.Errorf("the short form was refused: body %d bytes, err %v", len(body), err)
	}
	if _, body, _, err := derElement(append([]byte{0x04, 0x81, 0xc8}, content...)); err != nil || len(body) != 200 {
		t.Errorf("the minimal long form was refused: body %d bytes, err %v", len(body), err)
	}
}

// four length octets spell values no int on a 32 bit build holds, and the refusal must name the same reason on every word size
func TestDERLengthBeyondTheBufferIsRefusedNotSliced(t *testing.T) {
	for name, raw := range map[string][]byte{
		"four octets, all ones": {0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 1, 2, 3},
		"four octets, high bit": {0x04, 0x84, 0x80, 0, 0, 0, 1, 2, 3},
		"three octets":          {0x04, 0x83, 0xff, 0xff, 0xff, 1, 2, 3},
		"one octet":             {0x04, 0x81, 0xff, 1, 2, 3},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := derElement(raw)
			if err == nil {
				t.Fatal("a length larger than the element was accepted")
			}
			if !strings.Contains(err.Error(), "truncated DER content") {
				t.Errorf("the refusal reads %q, which is a different reason on a different word size", err)
			}
		})
	}
	body := make([]byte, 1<<16)
	raw := append([]byte{0x04, 0x84, 0x00, 0x01, 0x00, 0x00}, body...)
	if _, _, _, err := derElement(raw); err == nil {
		t.Error("a non-minimal four octet length was accepted")
	}
	raw = append([]byte{0x04, 0x83, 0x01, 0x00, 0x00}, body...)
	tag, content, rest, err := derElement(raw)
	if err != nil || tag != 0x04 || len(content) != 1<<16 || len(rest) != 0 {
		t.Errorf("a three octet length that fits read tag %#x, %d bytes, %d left, err %v", tag, len(content), len(rest), err)
	}
}

func TestEndpointRoundTripsThroughItsDN(t *testing.T) {
	for _, id := range []Identity{
		MustParse("testorg/server:1"),
		{"an organization long enough to need a two octet DER length, padded out to be sure", "node", "42"},
	} {
		der, err := id.DN()
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if decoded, err := FromDN(der); err != nil || decoded != id {
			t.Fatalf("round trip produced %#v, %v, want %#v", decoded, err, id)
		}
	}
}

// strongSwan picks the string type from the value's characters, so it writes a printable organization as a PrintableString where ranet writes a UTF8String
func TestDNAcceptsEitherDERStringType(t *testing.T) {
	id := MustParse("testorg/server:1")
	der, err := id.DN()
	if err != nil {
		t.Fatal(err)
	}
	printable := bytes.Replace(der, []byte{0x0c, 0x07, 't', 'e', 's', 't', 'o', 'r', 'g'}, []byte{0x13, 0x07, 't', 'e', 's', 't', 'o', 'r', 'g'}, 1)
	if bytes.Equal(printable, der) {
		t.Fatal("test did not alter the encoding")
	}
	decoded, err := FromDN(printable)
	if err != nil {
		t.Fatalf("a PrintableString organization was rejected: %v", err)
	}
	if decoded != id {
		t.Fatalf("decoded %s, want %s", decoded, id)
	}
}

// a country or a second common name names a peer this profile cannot reason about, so the name is refused rather than reduced to the attributes it recognizes
func TestDNRejectsAttributesThisProfileDoesNotUse(t *testing.T) {
	extra := derSequence(
		derSet(derSequence(oidOrganizationName, derUTF8String("testorg"))),
		derSet(derSequence(oidCommonName, derUTF8String("server"))),
		derSet(derSequence(oidSerialNumber, derPrintableString("1"))),
		derSet(derSequence([]byte{0x06, 0x03, 0x55, 0x04, 0x06}, derPrintableString("FR"))),
	)
	if _, err := FromDN(extra); err == nil {
		t.Fatal("a name with a fourth attribute was accepted")
	}
}

func TestDNAcceptsAttributesInAnyOrder(t *testing.T) {
	reordered := derSequence(
		derSet(derSequence(oidCommonName, derUTF8String("server"))),
		derSet(derSequence(oidSerialNumber, derPrintableString("1"))),
		derSet(derSequence(oidOrganizationName, derUTF8String("testorg"))),
	)
	decoded, err := FromDN(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != MustParse("testorg/server:1") {
		t.Fatalf("decoded %s", decoded)
	}
}

// a name on the wire carries an endpoint, so an empty part is refused when it is read and a node is never written
func TestDNRefusesAnEmptyPart(t *testing.T) {
	name := func(organization, commonName, serial string) []byte {
		return derSequence(
			derSet(derSequence(oidOrganizationName, derUTF8String(organization))),
			derSet(derSequence(oidCommonName, derUTF8String(commonName))),
			derSet(derSequence(oidSerialNumber, derPrintableString(serial))),
		)
	}
	for part, der := range map[string][]byte{
		"organization": name("", "server", "1"),
		"common name":  name("testorg", "", "1"),
		"serial":       name("testorg", "server", ""),
	} {
		if id, err := FromDN(der); err == nil {
			t.Errorf("a name with an empty %s read as %#v", part, id)
		}
	}
	if der, err := MustParse("testorg/server").DN(); err == nil {
		t.Errorf("the node testorg/server was written as %x", der)
	}
}
