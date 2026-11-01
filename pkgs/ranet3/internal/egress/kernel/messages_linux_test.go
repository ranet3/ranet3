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
	"ranet3.com/pkgs/ranet3/schema"
)

var update = flag.Bool("update", false, "rewrite testdata/messages.golden from what the translator and the antispoof filter build now")

// golden is embedded, so a test binary run from any directory reads it
//
//go:embed testdata/messages.golden
var golden []byte

// every shape of translation rule in both families: out of the mesh under the
// host's address and a configured one, from a class under an address and
// under none, into the mesh from a prefix with a timeout rule, from one host and from anywhere,
// and from this node's own address under the host's address and under none,
// with a timeout rule of each protocol keyed out of the mesh and from this
// node's own address, each family's limit from every source and in the chain of
// a class of none from the classes inside it as one set, a class of none's pass
// to its chain ahead of the limit and one inside it in that chain, the rules
// taking what no flow is tracked for, out of the mesh a drop from a class, from
// the classes inside a class of none and from every source, and
// into it a drop from a prefix and from every source, the ICMP drops of each
// message out of the mesh and into it, and the refusals of each protocol out of
// the mesh, from a class and from every source, and into it from a prefix and
// from every source
func everyTranslation() []Rule {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	return []Rule{
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.128/26"), Passes: true,
			Under: netip.MustParsePrefix("198.51.100.128/25")},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("198.51.100.192/27"), netip.MustParsePrefix("198.51.100.224/27")}),
			Limit: egress.DefaultFlowsPerSource, Under: netip.MustParsePrefix("198.51.100.128/25")},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("198.51.100.192/27")}),
			Untracked: true, Under: netip.MustParsePrefix("198.51.100.128/25")},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.128/25"), Passes: true},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Untracked: true},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Untracked: true},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Drops: SourceQuench},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", Drops: Information},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Limit: egress.DefaultFlowsPerSource},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Protocol: dccp},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Protocol: udpLite},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3"},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.7/32"), Source: v4},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3"},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.128/25"), None: true},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Source: netip.MustParseAddr("198.51.100.7")},
		{Family: egress.FamilyIPv4, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("192.0.2.1/32")},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Timeouts: UDPTimeouts},
		{Family: egress.FamilyIPv4, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("198.51.100.0/24"), Timeouts: UDPTimeouts},
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Timeouts: TCPTimeouts},
		{Family: egress.FamilyIPv4, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("192.0.2.1/32"), Timeouts: ICMPTimeouts},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("3fff::/20"), Untracked: true},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", Untracked: true},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", Limit: egress.DefaultFlowsPerSource},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("3fff::/20"), Protocol: udpLite},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", Protocol: dccp},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3"},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("2001:db8:1::/48"), Source: v6},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("2001:db8:1::7/128")},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("3fff::/20"), Source: v6},
		{Family: egress.FamilyIPv6, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("3fff::1/128"), None: true},
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", From: netip.MustParsePrefix("3fff::/20"), Timeouts: ICMPv6Timeouts},
		{Family: egress.FamilyIPv6, Direction: In, Interface: "ranet3", From: netip.MustParsePrefix("2001:db8:1::/48"), Timeouts: TCPTimeouts},
		{Family: egress.FamilyIPv6, Direction: Local, Interface: "ranet3", From: netip.MustParsePrefix("3fff::1/128"), Timeouts: UDPTimeouts},
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
	both, rules, limit := []uint8{egress.FamilyIPv4, egress.FamilyIPv6}, everyTranslation(), egress.DefaultFlowsPerSource
	requests, err := translatorBatch(both, limit, rules, nil, nil)
	write("translator in both families", requests, err)
	requests, err = translatorBatch(both, limit, rules, both, nil)
	write("translator remaking both families", requests, err)
	requests, err = translatorBatch([]uint8{egress.FamilyIPv6}, limit, rules, []uint8{egress.FamilyIPv6}, nil)
	write("translator remaking ipv6 alone", requests, err)
	requests, err = translatorBatch([]uint8{egress.FamilyIPv4}, limit, nil, nil, nil)
	write("translator in ipv4 with no rule", requests, err)
	// a table holding three chains of classes of none no rule names, one of
	// which a goto of another names and one a rule of another writer's chain
	// goes to, which stays
	stray := map[uint8][]noneStray{egress.FamilyIPv4: {{name: "none_198_51_100_0_24"}, {name: "none_198_51_100_0_25"}, {name: "none_203_0_113_0_24", heldBy: "chain other"}}}
	requests, err = translatorBatch([]uint8{egress.FamilyIPv4}, limit, nil, nil, stray)
	write("translator in ipv4 deleting the chains of classes of none it no longer writes", requests, err)
	write("translator withdrawal", []nftables.Request{delTable(egress.FamilyIPv4), delTable(egress.FamilyIPv6)}, nil)
	// what a pass writes for the default capability and for one of each kind of
	// class, one that translates inside one of none among them, without return
	// and under it
	node := Runtime{Interface: "ranet3", MeshAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("3fff::2")}}
	classes := egress.Egress{
		Advertise: prefixes(t, "198.51.100.0/24", "::/0"),
		Translate: []egress.Class{
			{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}},
			{From: schema.MustPrefix("192.0.2.0/24"), To: egress.Translation{None: true}},
			{From: schema.MustPrefix("192.0.2.0/26"), To: egress.Translation{Auto: true}},
			{From: schema.MustPrefix("3fff::/20"), To: egress.Translation{Auto: true}},
		},
	}
	returned := classes
	returned.Return = true
	for _, c := range []struct {
		name string
		cfg  egress.Egress
	}{
		{"translator of the default capability", egress.Egress{Advertise: prefixes(t, "0.0.0.0/0", "::/0")}},
		{"translator of a capability of classes", classes},
		{"translator of that capability under return", returned},
	} {
		requests, err = translatorBatch(both, limit, newTranslator(c.cfg, node, &fakeBackend{}).desired(), nil, nil)
		write(c.name, requests, err)
	}

	sets := egress.BorderSets{
		CarveOuts: []egress.CarveOut{{Link: "eth0", Prefix: netip.MustParsePrefix("192.0.2.0/25")}},
		Carved:    ranges("192.0.2.5/32"),
		Owned:     ranges("192.0.2.200/32", "2001:db8:1::7/128"),
		None:      ranges("203.0.113.0/24", "2001:db8:2::/48"),
	}
	rt := egress.BorderRuntime{Tun: "ranet3", Inside: []string{"ranet3", "lo"}, Sets: func(*egress.Border) egress.BorderSets { return sets }}
	exempted := overlay(t, "192.0.2.0/24", "2001:db8:1::7/128")
	exempted.Antispoof = egress.Antispoof{Exempt: prefixes(t, "192.0.2.192/26"), Interface: map[string]egress.AntispoofInterface{
		"eth1": {Exempt: prefixes(t, "2001:db8:1::7/128")}, "wl*": {Exempt: prefixes(t, "192.0.2.128/26")},
	}}
	desired, written, _ := newBorderFilter(exempted, rt, &fakeBorder{}).desired()
	requests, err = borderBatch(desired, written, false)
	write("antispoof filter", requests, err)
	requests, err = borderBatch(desired, written, true)
	write("antispoof filter remaking its table", requests, err)
	// none4 gains a range below its own and grows its own downward, and owned6 empties
	moved := borderSets{noneSet + "4": ranges("198.51.100.0/24", "203.0.112.0/23"), ownedSet + "6": nil}
	requests, err = fillBatch(written, moved)
	write("antispoof filter moving two sets", requests, err)
	desired, written, _ = newBorderFilter(nil, rt, &fakeBorder{}).desired()
	requests, err = borderBatch(desired, written, true)
	write("entry chain with no antispoof chain", requests, err)
	write("antispoof filter withdrawal", []nftables.Request{delBorderTable()}, nil)

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
