// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package identity

import (
	"bytes"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// drawWirePart draws a part of any bytes, its length drawn outright where a DER length moves to the long form and to a second length octet
func drawWirePart(tc hegel.TestCase) string {
	size := hegel.Draw(tc, hegel.OneOf(pbt.Spanning(1, 300), hegel.SampledFrom([]int{127, 128, 255, 256})))
	return string(hegel.Draw(tc, hegel.Binary(size, size)))
}

func drawEndpoint(tc hegel.TestCase) Identity {
	id, err := From(drawWirePart(tc), drawWirePart(tc), drawWirePart(tc))
	if err != nil {
		panic(err)
	}
	return id
}

func TestEndpointReadsBackFromItsDN(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		id := drawEndpoint(ht)
		der, err := id.DN()
		if err != nil {
			ht.Fatalf("DN refused %#v: %v", id, err)
		}
		if got, err := FromDN(der); err != nil || got != id {
			ht.Fatalf("FromDN read %#v back as %#v, %v", id, got, err)
		}
		if der, err := id.Node().DN(); err == nil {
			ht.Fatalf("the node of %#v was written as %x", id, der)
		}
	})
}

// strongSwan picks each attribute's string type from its characters and may order the RDNs its own way, and every such spelling names one endpoint
func TestEachStringTypeAndOrderOfTheRDNsReadsAsOneEndpoint(t *testing.T) {
	orders := [][3]int{{0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0}}
	oids := [3][]byte{oidOrganizationName, oidCommonName, oidSerialNumber}
	pbt.Check(t, func(ht *hegel.T) {
		id := drawEndpoint(ht)
		values := [3]string{id.organization, id.name, id.serial}
		for printable := range 8 {
			for _, order := range orders {
				var rdns [][]byte
				for _, i := range order {
					value := derUTF8String(values[i])
					if printable>>i&1 == 1 {
						value = derPrintableString(values[i])
					}
					rdns = append(rdns, derSet(derSequence(oids[i], value)))
				}
				if got, err := FromDN(derSequence(rdns...)); err != nil || got != id {
					ht.Fatalf("PrintableString at %03b in order %v read %#v, %v, want %#v", printable, order, got, err, id)
				}
			}
		}
	})
}

// the decoders return on any bytes a peer sends, a damaged name and every cut of one included, and a name cut short is refused
func TestDNDecodersReturnOnArbitraryBytes(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		arbitrary := hegel.Draw(ht, hegel.Binary(0, 600))
		_, _ = FromDN(arbitrary)
		_, _, _ = derAttribute(arbitrary)
		der, err := drawEndpoint(ht).DN()
		if err != nil {
			panic(err)
		}
		damaged := bytes.Clone(der)
		damaged[hegel.Draw(ht, pbt.Spanning(0, len(der)-1))] = hegel.Draw(ht, pbt.Spanning[byte](0, 0xff))
		_, _ = FromDN(damaged)
		for n := range len(der) {
			if id, err := FromDN(der[:n:n]); err == nil {
				ht.Fatalf("%x cut to %d bytes read as %#v", der, n, id)
			}
		}
		_, rdns, _, err := derElement(der)
		if err != nil {
			panic(err)
		}
		for n := range len(rdns) + 1 {
			_, _, _ = derAttribute(rdns[:n:n])
		}
	})
}
