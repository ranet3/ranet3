// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

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

// The count a limit rule's line holds each source to is the rule's limit, in
// each family
func TestLimitLineCountsToItsRulesLimit(t *testing.T) {
	for _, family := range []uint8{egress.FamilyIPv4, egress.FamilyIPv6} {
		for _, limit := range []int{1, 300, egress.DefaultFlowsPerSource} {
			line, err := translatorLine(Rule{Family: family, Direction: Out, Interface: "ranet3", Limit: limit}, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got := connlimitCounts(line.Expressions); !slices.Equal(got, []uint32{uint32(limit)}) {
				t.Errorf("the %s line of a limit of %d holds each source to the counts %v, want [%d]", egress.FamilyName(family), limit, got, limit)
			}
		}
	}
}

// connlimitCounts reads the count of each connlimit a dynset among expressions
// attaches to its keys, NFTA_CONNLIMIT_COUNT being attribute 1 of its data
func connlimitCounts(expressions [][]byte) []uint32 {
	var counts []uint32
	for _, expression := range expressions {
		for _, element := range nftables.Nested(expression) {
			if name, data := expressionParts(element.Value); name == "dynset" {
				for _, attr := range nftables.Nested(data) {
					if name, data := expressionParts(attr.Value); attr.Kind == unix.NFTA_DYNSET_EXPR && name == "connlimit" {
						for _, field := range nftables.Nested(data) {
							if field.Kind == 1 && len(field.Value) == 4 {
								counts = append(counts, binary.BigEndian.Uint32(field.Value))
							}
						}
					}
				}
			}
		}
	}
	return counts
}

// expressionParts is an expression's name and data
func expressionParts(body []byte) (name string, data []byte) {
	for _, attr := range nftables.Nested(body) {
		switch attr.Kind {
		case unix.NFTA_EXPR_NAME:
			name = strings.TrimRight(string(attr.Value), "\x00")
		case unix.NFTA_EXPR_DATA:
			data = attr.Value
		}
	}
	return name, data
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
	contents := translatorContents(both, limit, rules)
	requests, err := translatorBatch(contents, rules, nftables.Contents{}, nil)
	write("translator in both families", requests, err)
	requests, err = translatorBatch(contents, rules, nftables.Contents{Chains: []nftables.Chain{forward}, Sets: contents.Sets, Timeouts: contents.Timeouts}, nil)
	write("translator remaking its forward chain and both families' sets and timeout objects", requests, err)
	ipv6 := translatorContents([]uint8{egress.FamilyIPv6}, limit, nil)
	requests, err = translatorBatch(contents, rules, nftables.Contents{Sets: ipv6.Sets, Timeouts: ipv6.Timeouts[:1]}, nil)
	write("translator remaking the ipv6 set and one ipv6 timeout object alone", requests, err)
	ipv4 := translatorContents([]uint8{egress.FamilyIPv4}, limit, nil)
	requests, err = translatorBatch(ipv4, nil, nftables.Contents{}, nil)
	write("translator in ipv4 with no rule", requests, err)
	// a table holding three chains of classes of none no rule names, one of
	// which a goto of another names and one a rule of another writer's chain
	// goes to, which stays
	stray := []noneStray{{name: "none_198_51_100_0_24"}, {name: "none_198_51_100_0_25"}, {name: "none_203_0_113_0_24", heldBy: "chain other"}}
	requests, err = translatorBatch(ipv4, nil, nftables.Contents{}, stray)
	write("translator in ipv4 deleting the chains of classes of none it no longer writes", requests, err)
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
		desired := newTranslator(c.cfg, node, &fakeBackend{}).desired()
		requests, err = translatorBatch(translatorContents(both, limit, desired), desired, nftables.Contents{}, nil)
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
	requests, err = borderBatch(desired, written, nftables.Contents{}, nil)
	write("antispoof filter", requests, err)
	requests, err = borderBatch(desired, written, nftables.Contents{Chains: []nftables.Chain{prerouting}, Sets: borderNamed[2:3]}, []string{BorderChain, EntryChain})
	write("antispoof filter remaking its antispoof chain and one set", requests, err)
	// none4 gains a range below its own and grows its own downward, and owned6 empties
	moved := borderSets{noneSet + "4": ranges("198.51.100.0/24", "203.0.112.0/23"), ownedSet + "6": nil}
	requests, err = fillBatch(written, moved)
	write("antispoof filter moving two sets", requests, err)
	desired, written, _ = newBorderFilter(nil, rt, &fakeBorder{}).desired()
	requests, err = borderBatch(desired, written, nftables.Contents{}, []string{BorderChain, EntryChain})
	write("entry chain deleting the antispoof chain it no longer writes", requests, err)

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
