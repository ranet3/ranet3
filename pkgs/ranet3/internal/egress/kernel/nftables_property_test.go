// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
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
	for kind, value := range (nftables.Message{Data: body}).Attributes() {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nftables.Nested(value) {
			var name string
			var data []byte
			for _, field := range nftables.Nested(element.Value) {
				switch field.Kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.Value)
				case unix.NFTA_EXPR_DATA:
					data = field.Value
				}
			}
			switch name {
			case "meta":
				meta = false
				for _, field := range nftables.Nested(data) {
					if field.Kind == unix.NFTA_META_KEY && len(field.Value) == 4 {
						key, meta = binary.BigEndian.Uint32(field.Value), true
					}
				}
			case "cmp":
				if !meta {
					continue
				}
				test := interfaceTest{key: key}
				for _, field := range nftables.Nested(data) {
					switch field.Kind {
					case unix.NFTA_CMP_OP:
						test.op = binary.BigEndian.Uint32(field.Value)
					case unix.NFTA_CMP_DATA:
						for _, inner := range nftables.Nested(field.Value) {
							if inner.Kind == unix.NFTA_DATA_VALUE {
								test.value = inner.Value
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
	register := make([]byte, unix.IFNAMSIZ)
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
// what arrives on the mesh device and leaves by another, and into the mesh what
// arrives from elsewhere, not from this host, and leaves by the mesh device
func meant(rule Rule, packet crossing) bool {
	if rule.Direction == Out {
		return packet.arrival == rule.Interface && packet.departure != rule.Interface
	}
	return packet.arrival != "" && packet.arrival != rule.Interface && packet.departure == rule.Interface
}

// deviceNames draws a device name from one to IFNAMSIZ bytes, one past the
// longest a device carries, over few letters so that two draws often agree or
// share a prefix.
func deviceNames() hegel.Generator[string] {
	return hegel.Composite(func(tc hegel.TestCase) string {
		size := hegel.Draw(tc, pbt.Spanning(1, unix.IFNAMSIZ))
		return hegel.Draw(tc, hegel.Text().Alphabet("ran0e").MinSize(size).MaxSize(size))
	})
}

// Every rule encodes to interface tests that take exactly the packets the rule
// is meant for, evaluated over the mesh device, two devices whose names start
// like it, a drawn link whose name often shares a prefix with it, another
// link and this host itself. A rule is refused exactly when its name is too
// long for a device.
func TestEncodedRuleTakesThePacketsItIsMeantFor(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		rule := Rule{
			Family:    hegel.Draw(ht, hegel.SampledFrom([]uint8{egress.FamilyIPv4, egress.FamilyIPv6})),
			Direction: Direction(hegel.Draw(ht, pbt.Spanning(uint8(Out), uint8(In)))),
			Interface: hegel.Draw(ht, deviceNames()),
		}
		other := hegel.Draw(ht, deviceNames())
		source, from := netip.MustParseAddr("198.51.100.7"), netip.MustParsePrefix("198.51.100.0/24")
		if rule.Family == egress.FamilyIPv6 {
			source, from = netip.MustParseAddr("2001:db8::7"), netip.MustParsePrefix("2001:db8:1::/48")
		}
		if hegel.Draw(ht, hegel.Booleans()) {
			rule.Source = source
		}
		if rule.Direction == In && hegel.Draw(ht, hegel.Booleans()) {
			rule.From = from
		}

		request, err := newRule(rule)
		refused := len(rule.Interface) >= unix.IFNAMSIZ
		if refused != (err != nil) {
			ht.Fatalf("%s encoded with %v, want refused %v", rule, err, refused)
		}
		if refused {
			return
		}
		tests := interfaceTests(request.Body)
		devices := []string{rule.Interface, rule.Interface + "1", rule.Interface + "e", other, "eth0"}
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
