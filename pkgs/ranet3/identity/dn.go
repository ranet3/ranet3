// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package identity

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// X.501 attribute types, RFC 4519, each as its whole DER element
var (
	oidOrganizationName = []byte{0x06, 0x03, 0x55, 0x04, 0x0a} // 2.5.4.10
	oidCommonName       = []byte{0x06, 0x03, 0x55, 0x04, 0x03} // 2.5.4.3
	oidSerialNumber     = []byte{0x06, 0x03, 0x55, 0x04, 0x05} // 2.5.4.5
)

// DN is the RDNSequence ranet and strongSwan carry as a raw public key identity
// the RDNs are O, CN and serialNumber in that order, O and CN as UTF8String and the serial as PrintableString, as ranet's src/asn.rs writes them
func (id Identity) DN() ([]byte, error) {
	if id.serial == "" {
		return nil, fmt.Errorf("identity: %q names no endpoint, and only an endpoint goes on the wire", id.String())
	}
	atv := func(oid, value []byte) []byte { return derSequence(oid, value) }
	rdn := func(a []byte) []byte { return derSet(a) }
	return derSequence(
		rdn(atv(oidOrganizationName, derUTF8String(id.organization))),
		rdn(atv(oidCommonName, derUTF8String(id.name))),
		rdn(atv(oidSerialNumber, derPrintableString(id.serial))),
	), nil
}

// FromDN reads an endpoint from an RDNSequence of exactly the three single-valued RDNs O, CN and serialNumber, in any order, each once
// anything else is refused rather than read, because the name decides which key verifies AUTH
func FromDN(der []byte) (Identity, error) {
	tag, seq, rest, err := derElement(der)
	if err != nil {
		return Identity{}, err
	}
	if tag != 0x30 || len(rest) != 0 {
		return Identity{}, errors.New("identity: not a single RDNSequence")
	}
	var organization, commonName, serialNumber string
	targets := []struct {
		oid   []byte
		value *string
		seen  bool
	}{
		{oid: oidOrganizationName, value: &organization},
		{oid: oidCommonName, value: &commonName},
		{oid: oidSerialNumber, value: &serialNumber},
	}
	count := 0
	for len(seq) != 0 {
		_, _, next, err := derElement(seq)
		if err != nil {
			return Identity{}, err
		}
		oid, value, err := derAttribute(seq[:len(seq)-len(next)])
		if err != nil {
			return Identity{}, err
		}
		matched := false
		for i := range targets {
			if !bytes.Equal(oid, targets[i].oid) {
				continue
			}
			if targets[i].seen {
				return Identity{}, errors.New("identity: the name repeats an attribute")
			}
			targets[i].seen, matched = true, true
			*targets[i].value = value
		}
		if !matched {
			return Identity{}, errors.New("identity: the name carries an attribute type this profile does not use")
		}
		count++
		seq = next
	}
	if count != len(targets) {
		return Identity{}, fmt.Errorf("identity: the name has %d attributes, want %d", count, len(targets))
	}
	if serialNumber == "" {
		return Identity{}, errors.New("identity: the serial is empty")
	}
	return From(organization, commonName, serialNumber)
}

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func derTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	out = append(out, content...)
	return out
}

func derUTF8String(s string) []byte      { return derTLV(0x0c, []byte(s)) }
func derPrintableString(s string) []byte { return derTLV(0x13, []byte(s)) }
func derSequence(parts ...[]byte) []byte { return derTLV(0x30, slices.Concat(parts...)) }
func derSet(parts ...[]byte) []byte      { return derTLV(0x31, slices.Concat(parts...)) }

// derElement splits one DER TLV off the front of b
// an indefinite length is refused, since no structure read here has one
func derElement(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("identity: truncated DER element")
	}
	tag, b = b[0], b[1:]
	length := int(b[0])
	b = b[1:]
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(b) < count {
			return 0, nil, nil, errors.New("identity: unsupported DER length")
		}
		// DER requires the shortest length, or two byte sequences would read as one name
		if b[0] == 0 {
			return 0, nil, nil, errors.New("identity: non-minimal DER length")
		}
		var value uint64
		for _, octet := range b[:count] {
			value = value<<8 | uint64(octet)
		}
		b = b[count:]
		if value < 128 {
			return 0, nil, nil, errors.New("identity: non-minimal DER length")
		}
		// bounded by the bytes present before it becomes an int, which four length octets turn negative on a 32 bit build
		if value > uint64(len(b)) {
			return 0, nil, nil, errors.New("identity: truncated DER content")
		}
		length = int(value)
	}
	if len(b) < length {
		return 0, nil, nil, errors.New("identity: truncated DER content")
	}
	return tag, b[:length], b[length:], nil
}

// derAttribute reads one single-valued RDN, SET{SEQUENCE{OID, value}}, and returns the attribute's whole OID element and its string
// UTF8String and PrintableString are both read for any attribute, since strongSwan picks the type from the value's characters
// AUTH signs the bytes received, so a name read from either spelling still needs that peer's key
func derAttribute(rdn []byte) (oid []byte, value string, err error) {
	setTag, set, rest, err := derElement(rdn)
	if err != nil {
		return nil, "", err
	}
	if setTag != 0x31 || len(rest) != 0 {
		return nil, "", errors.New("identity: an RDN is not a single SET")
	}
	seqTag, seq, rest, err := derElement(set)
	if err != nil {
		return nil, "", err
	}
	if seqTag != 0x30 || len(rest) != 0 {
		return nil, "", errors.New("identity: an RDN does not hold exactly one attribute")
	}
	_, _, afterOID, err := derElement(seq)
	if err != nil {
		return nil, "", err
	}
	oid, seq = seq[:len(seq)-len(afterOID)], afterOID
	valueTag, content, rest, err := derElement(seq)
	if err != nil {
		return nil, "", err
	}
	if len(rest) != 0 {
		return nil, "", errors.New("identity: an attribute has trailing data")
	}
	switch valueTag {
	case 0x0c, 0x13:
		return oid, string(content), nil
	default:
		return nil, "", fmt.Errorf("identity: an attribute has string type %#x", valueTag)
	}
}
