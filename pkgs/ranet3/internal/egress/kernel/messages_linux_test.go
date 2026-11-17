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
// node's own address, each family's limit from every source, each family's
// pass of the sources whose class is none, the rules taking what no flow is
// tracked for, out of the mesh a drop from a class and from every source, and
// into it a drop from a prefix and from every source, the ICMP drops of each
// message out of the mesh and into it, and the refusals of each protocol out of
// the mesh, from a class and from every source, and into it from a prefix and
// from every source
func everyTranslation() []Rule {
	v4, v6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	return []Rule{
		{Family: egress.FamilyIPv4, Direction: Out, Interface: "ranet3", Passes: true,
			Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("198.51.100.128/26"), netip.MustParsePrefix("198.51.100.224/27")})},
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
		{Family: egress.FamilyIPv6, Direction: Out, Interface: "ranet3", Passes: true, Sources: prefixSet([]netip.Prefix{netip.MustParsePrefix("3fff:800::/21")})},
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
			line, err := translatorLine(Rule{Family: family, Direction: Out, Interface: "ranet3", Limit: limit}, unix.NFT_CT_LABELS)
			if err != nil {
				t.Fatal(err)
			}
			if got := connlimitCounts(line.Expressions); !slices.Equal(got, []uint32{uint32(limit)}) {
				t.Errorf("the %s line of a limit of %d holds each source to the counts %v, want [%d]", egress.FamilyName(family), limit, got, limit)
			}
		}
	}
}

// The probe of the label carries it by the key it is given in one request
// alone, the rule at the index labelTaken reads a refusal of the label at, in
// a chain none of the translator's, and ends in that chain made again under
// NLM_F_EXCL, which the kernel refuses whatever it made of the label, so a
// refusal of the rule is told from the refusal that ends the probe
func TestLabelProbeIsRefusedWhateverTheKernelMakesOfTheLabel(t *testing.T) {
	for _, key := range []uint32{unix.NFT_CT_LABELS, 255} {
		requests, at, err := labelProbe(key)
		if err != nil {
			t.Fatal(err)
		}
		var carrying []int
		for i, request := range requests {
			if readsKey(request, key) {
				carrying = append(carrying, i)
			}
		}
		if !slices.Equal(carrying, []int{at}) || at == len(requests)-1 {
			t.Errorf("the probe under the key %d carries it in the requests %v of %d, want its rule at %d alone, ahead of the last", key, carrying, len(requests), at)
		}
		made, again := requests[1], requests[len(requests)-1]
		if made.Kind&0xff != unix.NFT_MSG_NEWCHAIN || again.Kind != made.Kind || !bytes.Equal(again.Body, made.Body) || again.Flags != made.Flags|unix.NLM_F_EXCL {
			t.Errorf("the probe makes the chain %+v and ends in %+v, want the same chain made again under NLM_F_EXCL", made, again)
		}
		if scope := translatorScope; slices.Contains(scope.Chains, probeChain) || strings.HasPrefix(probeChain, scope.Prefix) {
			t.Errorf("the probe's chain %s is named as one of the translator's", probeChain)
		}
	}
}

// labelTaken reads the label taken from the refusal of the probe's last
// request with EEXIST alone, and refused from a refusal of its rule with
// EOPNOTSUPP alone. Every other answer, of the probe's own requests or of the
// socket, is an error that says neither.
func TestLabelTakenReadsTheProbesAnswer(t *testing.T) {
	requests, at, err := labelProbe(unix.NFT_CT_LABELS)
	if err != nil {
		t.Fatal(err)
	}
	last := len(requests) - 1
	for _, c := range []struct {
		answer error
		takes  bool
		err    bool
	}{
		{&nftables.Refused{Request: last, Err: unix.EEXIST}, true, false},
		{&nftables.Refused{Request: at, Err: unix.EOPNOTSUPP}, false, false},
		{&nftables.Refused{Request: 0, Err: unix.EOPNOTSUPP}, false, true},
		{&nftables.Refused{Request: last, Err: unix.EOPNOTSUPP}, false, true},
		{&nftables.Refused{Request: at, Err: unix.EINVAL}, false, true},
		{&nftables.Refused{Request: 1, Err: unix.EEXIST}, false, true},
		{&nftables.Refused{Request: 0, Err: unix.EPERM}, false, true},
		{&nftables.Refused{Request: -1, Err: unix.EOPNOTSUPP}, false, true},
		{unix.ENOBUFS, false, true},
		{fmt.Errorf("wrapped: %w", unix.EOPNOTSUPP), false, true},
		{nil, false, true},
	} {
		takes, err := labelTaken(c.answer, at, len(requests))
		if takes != c.takes || (err != nil) != c.err {
			t.Errorf("the answer %v reads the label taken %v with the error %v, want taken %v and an error %v", c.answer, takes, err, c.takes, c.err)
		}
	}
}

// readsKey is whether request writes a rule holding a ct expression of key
func readsKey(request nftables.Request, key uint32) bool {
	if request.Kind&0xff != unix.NFT_MSG_NEWRULE || len(request.Body) < 4 {
		return false
	}
	for _, attr := range nftables.Nested(request.Body[4:]) {
		if attr.Kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nftables.Nested(attr.Value) {
			if name, data := expressionParts(element.Value); name == "ct" {
				for _, field := range nftables.Nested(data) {
					if field.Kind == unix.NFTA_CT_KEY && len(field.Value) == 4 && binary.BigEndian.Uint32(field.Value) == key {
						return true
					}
				}
			}
		}
	}
	return false
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
	requests, err := translatorBatch(contents, rules, nftables.Contents{}, nil, nil, unix.NFT_CT_LABELS)
	write("translator in both families", requests, err)
	requests, err = translatorBatch(contents, rules, nftables.Contents{}, nil, nil, 0)
	write("translator in both families on a kernel that refuses connection labels", requests, err)
	requests, err = translatorBatch(contents, rules, nftables.Contents{Chains: []nftables.Chain{forward}, Sets: contents.Sets, Timeouts: contents.Timeouts}, nil, nil, unix.NFT_CT_LABELS)
	write("translator remaking its forward chain and both families' sets and timeout objects", requests, err)
	ipv6 := translatorContents([]uint8{egress.FamilyIPv6}, limit, nil)
	requests, err = translatorBatch(contents, rules, nftables.Contents{Sets: ipv6.Sets, Timeouts: ipv6.Timeouts[:1]}, nil, nil, unix.NFT_CT_LABELS)
	write("translator remaking the ipv6 set and one ipv6 timeout object alone", requests, err)
	ipv4 := translatorContents([]uint8{egress.FamilyIPv4}, limit, nil)
	requests, err = translatorBatch(ipv4, nil, nftables.Contents{}, nil, nil, unix.NFT_CT_LABELS)
	write("translator in ipv4 with no rule", requests, err)
	// a table holding three chains an earlier translator wrote for classes of
	// none, one of which a goto of another names and one a rule of another
	// writer's chain goes to, which stays
	stray := []noneStray{{name: "none_198_51_100_0_24"}, {name: "none_198_51_100_0_25"}, {name: "none_203_0_113_0_24", heldBy: "chain other"}}
	requests, err = translatorBatch(ipv4, nil, nftables.Contents{}, stray, nil, unix.NFT_CT_LABELS)
	write("translator in ipv4 deleting the chains an earlier translator wrote", requests, err)
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
		requests, err = translatorBatch(translatorContents(both, limit, desired), desired, nftables.Contents{}, nil, nil, unix.NFT_CT_LABELS)
		write(c.name, requests, err)
	}
	stopped := newTranslator(returned, node, &fakeBackend{}).stopped()
	requests, err = translatorBatch(translatorContents(both, limit, stopped), stopped, nftables.Contents{}, nil, nil, unix.NFT_CT_LABELS)
	write("stopped translator of that capability under return", requests, err)
	requests, _, err = labelProbe(unix.NFT_CT_LABELS)
	write("translator's probe of the connection label", requests, err)

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
	requests, err = borderBatch(desired, written, nftables.Contents{}, nil, nil)
	write("antispoof filter", requests, err)
	requests, err = borderBatch(desired, written, nftables.Contents{Chains: []nftables.Chain{prerouting}, Sets: borderNamed[2:3]}, []string{BorderChain, EntryChain}, nil)
	write("antispoof filter remaking its antispoof chain and one set", requests, err)
	// none4 gains a range below its own and grows its own downward, and owned6 empties
	moved := borderSets{noneSet + "4": ranges("198.51.100.0/24", "203.0.112.0/23"), ownedSet + "6": nil}
	requests, err = fillBatch(written, moved)
	write("antispoof filter moving two sets", requests, err)
	desired, written, _ = newBorderFilter(nil, rt, &fakeBorder{}).desired()
	requests, err = borderBatch(desired, written, nftables.Contents{}, []string{BorderChain, EntryChain}, nil)
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
