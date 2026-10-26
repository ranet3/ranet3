// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	_ "embed"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

var update = flag.Bool("update", false, "rewrite testdata/messages.golden from what the translator and the border build now")

// golden is embedded, so a test binary run from any directory reads it
//
//go:embed testdata/messages.golden
var golden []byte

// every shape of translation rule in both families: out of the mesh under the
// host's address and a configured one, from a class under an address and
// under none, into the mesh from a prefix, from one host and from anywhere,
// and from this node's own address under the host's address and under none
func everyTranslation() []Rule {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	return []Rule{
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3"},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.7/32"), Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3"},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.128/25"), None: true},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Source: netip.MustParseAddr("198.51.100.7")},
		{Family: egress.FamilyIPv4, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("192.0.2.1/32")},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3"},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("2001:db8:1::/48"), Source: v6},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("2001:db8:1::7/128")},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("3fff::/20"), Source: v6},
		{Family: egress.FamilyIPv6, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("3fff::1/128"), None: true},
	}
}

// Every request the translator and the border send, in the order each
// transaction sends it, keeps the kind, flags and body testdata/messages.golden
// holds
func TestTranslatorAndBorderMessagesKeepTheirBytes(t *testing.T) {
	var out bytes.Buffer
	write := func(name string, requests []nftables.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fmt.Fprintf(&out, "%s\n", name)
		for _, request := range requests {
			fmt.Fprintf(&out, "  kind %#06x flags %#06x body %x\n", request.Kind, request.Flags, request.Body)
		}
	}
	both, rules := []uint8{egress.FamilyIPv4, egress.FamilyIPv6}, everyTranslation()
	requests, err := translatorBatch(both, rules, nil)
	write("translator in both families", requests, err)
	requests, err = translatorBatch(both, rules, both)
	write("translator remaking both families", requests, err)
	requests, err = translatorBatch([]uint8{egress.FamilyIPv6}, rules, []uint8{egress.FamilyIPv6})
	write("translator remaking ipv6 alone", requests, err)
	requests, err = translatorBatch([]uint8{egress.FamilyIPv4}, nil, nil)
	write("translator in ipv4 with no rule", requests, err)
	write("translator withdrawal", []nftables.Request{delTable(egress.FamilyIPv4), delTable(egress.FamilyIPv6)}, nil)

	rt := egress.BorderRuntime{Inside: []string{"ranet3", "lo"}, SIDs: []netip.Addr{netip.MustParseAddr("2001:db8:a::1")}}
	desired := newBorderFilter(overlay(t, "192.0.2.0/24", "2001:db8:1::7/128"), rt, &fakeBorder{}).desired()
	requests, err = borderBatch(desired, false)
	write("border", requests, err)
	requests, err = borderBatch(desired, true)
	write("border remaking its table", requests, err)
	requests, err = borderBatch(nil, false)
	write("border with no rule", requests, err)
	write("border withdrawal", []nftables.Request{delBorderTable()}, nil)

	path := filepath.Join("testdata", "messages.golden")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(out.Bytes(), golden) {
		t.Errorf("%s no longer matches\n--- golden\n%s\n--- now\n%s", path, golden, out.Bytes())
	}
}
