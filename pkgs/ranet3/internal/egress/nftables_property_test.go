// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package egress

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// crossing holds the two devices a rule's interface tests read of a packet at
// postrouting: the one it arrived on, empty for one this host sent, and the
// one it leaves by.
type crossing struct {
	arrival, departure string
}

// interfaceTest is one cmp made against a meta load.
type interfaceTest struct {
	key   uint32
	op    uint32
	value []byte
}

// interfaceTests reads a rule's expressions as nf_tables runs them, register 1
// holding what the last meta or payload expression loaded, and keeps every cmp
// made against a meta load.
func interfaceTests(body []byte) []interfaceTest {
	var out []interfaceTest
	var key uint32
	meta := false
	for kind, value := range (nftMessage{Data: body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			var name string
			var data []byte
			for _, field := range nested(element.value) {
				switch field.kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.value)
				case unix.NFTA_EXPR_DATA:
					data = field.value
				}
			}
			switch name {
			case "meta":
				meta = false
				for _, field := range nested(data) {
					if field.kind == unix.NFTA_META_KEY && len(field.value) == 4 {
						key, meta = binary.BigEndian.Uint32(field.value), true
					}
				}
			case "cmp":
				if !meta {
					continue
				}
				test := interfaceTest{key: key}
				for _, field := range nested(data) {
					switch field.kind {
					case unix.NFTA_CMP_OP:
						test.op = binary.BigEndian.Uint32(field.value)
					case unix.NFTA_CMP_DATA:
						for _, inner := range nested(field.value) {
							if inner.kind == unix.NFTA_DATA_VALUE {
								test.value = inner.value
							}
						}
					}
				}
				out = append(out, test)
			default:
				meta = false
			}
		}
	}
	return out
}

// holds evaluates the test as the kernel does: meta iifname and oifname load
// the name NUL-padded to IFNAMSIZ, meta iif loads the arrival index, zero for
// a packet this host sent, and cmp compares the leading bytes of the register
// its value covers.
func (test interfaceTest) holds(packet crossing) bool {
	register := make([]byte, ifNameSize)
	switch test.key {
	case unix.NFT_META_IIFNAME:
		copy(register, packet.arrival)
	case unix.NFT_META_OIFNAME:
		copy(register, packet.departure)
	case unix.NFT_META_IIF:
		var index uint32
		if packet.arrival != "" {
			index = 7
		}
		register = binary.NativeEndian.AppendUint32(nil, index)
	default:
		return false
	}
	if len(test.value) > len(register) {
		return false
	}
	equal := bytes.Equal(register[:len(test.value)], test.value)
	switch test.op {
	case unix.NFT_CMP_EQ:
		return equal
	case unix.NFT_CMP_NEQ:
		return !equal
	}
	return false
}

// meant is which packets a rule translates by its definition: out of the mesh
// what arrives on the mesh device and leaves by another, out of the egress
// device what arrives on it and leaves by anything but the mesh device, and
// into the mesh what arrives from elsewhere, not from this host, and leaves by
// the mesh device. For a rule keyed on the egress device, arrival tested
// against the mesh device would translate the mesh's own traffic out of this
// node, which an exit advertising nothing offers to nobody, and departure
// tested against the egress device would translate a steered packet the main
// table routes back into the mesh.
func meant(rule Rule, packet crossing) bool {
	switch {
	case rule.Direction == Out && rule.Egress != "":
		return packet.arrival == rule.Egress && packet.departure != rule.Interface
	case rule.Direction == Out:
		return packet.arrival == rule.Interface && packet.departure != rule.Interface
	default:
		return packet.arrival != "" && packet.arrival != rule.Interface && packet.departure == rule.Interface
	}
}

// deviceNames draws a device name from one to IFNAMSIZ bytes, one past the
// longest a device carries, over few letters so that two draws often agree or
// share a prefix.
func deviceNames() hegel.Generator[string] {
	return hegel.Composite(func(tc hegel.TestCase) string {
		size := hegel.Draw(tc, pbt.Spanning(1, ifNameSize))
		return hegel.Draw(tc, hegel.Text().Alphabet("ran0e").MinSize(size).MaxSize(size))
	})
}

// Every rule encodes to interface tests that take exactly the packets the rule
// is meant for, evaluated over the mesh device, the egress device, a device
// whose name starts like each, another link and this host itself. A rule is
// refused exactly when a name is too long for a device or an inbound rule is
// keyed on the egress device.
func TestEncodedRuleTakesThePacketsItIsMeantFor(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := Rule{
			Family:    hegel.Draw(ht, hegel.SampledFrom([]uint8{FamilyIPv4, FamilyIPv6})),
			Direction: Direction(hegel.Draw(ht, pbt.Spanning(uint8(Out), uint8(In)))),
			Interface: hegel.Draw(ht, deviceNames()),
		}
		if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			rule.Egress = hegel.Draw(ht, deviceNames())
		}
		source, from := netip.MustParseAddr("198.51.100.7"), netip.MustParsePrefix("198.51.100.0/24")
		if rule.Family == FamilyIPv6 {
			source, from = netip.MustParseAddr("2001:db8::7"), netip.MustParsePrefix("2001:db8:1::/48")
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			rule.Source = source
		}
		if rule.Direction == In && hegel.Draw(ht, hegel.Booleans()) {
			rule.From = from
		}

		request, err := newRule(rule)
		refused := len(rule.Interface) >= ifNameSize || len(rule.Egress) >= ifNameSize || (rule.Direction == In && rule.Egress != "")
		if refused != (err != nil) {
			ht.Fatalf("%s encoded with %v, want refused %v", rule, err, refused)
		}
		if refused {
			return
		}
		tests := interfaceTests(request.body)
		devices := []string{rule.Interface, rule.Interface + "1", "eth0"}
		if rule.Egress != "" {
			devices = append(devices, rule.Egress, rule.Egress+"1")
		}
		for _, arrival := range append([]string{""}, devices...) {
			for _, departure := range devices {
				packet := crossing{arrival, departure}
				took := true
				for _, test := range tests {
					took = took && test.holds(packet)
				}
				if want := meant(rule, packet); took != want {
					ht.Fatalf("%s takes a packet arriving on %q and leaving by %q: %v, want %v, from tests %+v", rule, arrival, departure, took, want, tests)
				}
			}
		}
	})
}
