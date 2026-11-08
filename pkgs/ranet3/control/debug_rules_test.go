// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// rulesFixture is a node's derived rules beside networkd's, a VRF's and one of
// its own protocol it does not derive, one derived rule missing, its last
// pass's lookups with wg-quick's table taking the IPv4 overlay and another
// program's table 300 taking a send pinned to eth0 but not one from a pair's
// bound source, and its antispoof chain read three seconds after its last pass
// with one forged source dropped
func rulesFixture() RulesInfo {
	lookup := func(family string, priority uint32, table uint32, protocol uint8, owned bool) PolicyRule {
		return PolicyRule{Family: family, Priority: priority, Action: "lookup", Table: table, Protocol: protocol, Owned: owned, Wanted: owned}
	}
	to := lookup("ipv4", 100, 200, 4, false)
	to.To = netip.MustParsePrefix("198.51.100.0/24")
	iif := lookup("ipv4", 120, 254, 155, true)
	iif.IIF, iif.Wanted = "eth1", false
	from := lookup("ipv4", 150, 254, 4, false)
	from.From = netip.MustParsePrefix("198.51.100.0/24")
	l3mdev := lookup("ipv4", 1000, 0, 2, false)
	l3mdev.L3mdev = true
	mark := PolicyRule{Family: "ipv4", Priority: 5100, FWMark: 0x72, FWMask: ^uint32(0), Action: "goto", Goto: 5190, Protocol: 155, Owned: true, Wanted: true}
	overlay := lookup("ipv4", 5110, 200, 155, true)
	overlay.To = netip.MustParsePrefix("192.0.2.0/24")
	nop := PolicyRule{Family: "ipv4", Priority: 5190, Action: "nop", Protocol: 155, Owned: true, Wanted: true}
	none, floor := 0, 15
	inMain := lookup("ipv4", 5410, 254, 155, true)
	inMain.Suppress = &none
	unreachable := PolicyRule{Family: "ipv6", Priority: 200, Invert: true, IIF: "eth0", Action: "unreachable", Protocol: 4}
	wanted := lookup("ipv6", 5420, 200, 155, true)
	wanted.Suppress = &floor
	return RulesInfo{
		Policy: []PolicyRule{
			lookup("ipv4", 0, 255, 2, false), to, iif, from, l3mdev, mark, overlay, nop, inMain,
			lookup("ipv4", 32766, 254, 2, false), lookup("ipv4", 32767, 253, 2, false),
			lookup("ipv6", 0, 255, 2, false), unreachable, lookup("ipv6", 32766, 254, 2, false),
		},
		Missing: []PolicyRule{wanted},
		Lookups: []RuleLookup{
			{Lookup: "overlay", Family: "ipv4", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Address: netip.MustParseAddr("192.0.2.2"), Answer: "table 51820 dev wg0", Taken: true},
			{Lookup: "overlay", Family: "ipv6", Prefix: netip.MustParsePrefix("3fff::/20"), Address: netip.MustParseAddr("3fff::2"), Answer: "a refusal (no route to host)"},
			{Lookup: "underlay", Family: "ipv4", Address: netip.MustParseAddr("198.51.100.77"), Answer: "table 51820 dev wg0"},
			{Lookup: "underlay", Family: "ipv4", Address: netip.MustParseAddr("203.0.113.70"), Answer: "table 51820 dev wg0"},
			{Lookup: "underlay", Family: "ipv6", Address: netip.MustParseAddr("2001:db8:400::7"), Source: netip.MustParseAddr("2001:db8:a::10"), Interface: "eth0", Answer: "table 300 dev ranet0", Taken: true},
			{Lookup: "underlay", Family: "ipv6", Address: netip.MustParseAddr("2001:db8:400::7"), Source: netip.MustParseAddr("2001:db8:b::10"), Answer: "table main dev eth0"},
		},
		Border: &BorderTable{
			Where:   "nftables table inet ranet3 chains antispoof and mesh_entry",
			ReadAt:  time.Date(2026, 10, 19, 9, 14, 2, 0, time.UTC),
			ReadAgo: Duration(3 * time.Second),
			Ready:   true,
			Chains: []BorderChain{
				{Name: "antispoof", Hook: "prerouting", Priority: new(-300), Rules: []BorderChainRule{
					{Spec: "accept via ranet3", Verdict: "accept", Reason: "inside", Held: true},
					{Spec: "accept via lo", Verdict: "accept", Reason: "inside", Held: true},
					{Spec: "drop ipv4 source @carved4", Verdict: "drop", Reason: "carved_source", Family: "ipv4", Held: true, Packets: 2, Bytes: 120},
					{Spec: "drop ipv6 source @carved6", Verdict: "drop", Reason: "carved_source", Family: "ipv6", Held: true},
					{Spec: "accept via eth0 source 203.0.113.0/26", Verdict: "accept", Reason: "carve_out", Family: "ipv4", Held: true},
					{Spec: "drop ipv4 source 203.0.113.0/24", Verdict: "drop", Reason: "overlay_source", Family: "ipv4", Held: true, Packets: 12, Bytes: 720},
					{Spec: "drop ipv6 source 3fff:a::/36", Verdict: "drop", Reason: "overlay_source", Family: "ipv6", Held: true},
					{Spec: "drop ipv6 source 3fff:b::/48", Verdict: "drop", Reason: "overlay_source", Family: "ipv6"},
				}},
				{Name: "mesh_entry", Hook: "postrouting", Priority: new(110), Rules: []BorderChainRule{
					{Spec: "return via other than ranet3", Verdict: "return", Reason: "outside", Held: true},
					{Spec: "return a reply", Verdict: "return", Reason: "reply", Held: true},
					{Spec: "return ipv4 source @owned4", Verdict: "return", Reason: "owned", Family: "ipv4", Held: true},
					{Spec: "drop ipv4 entering the mesh", Verdict: "drop", Reason: "mesh_entry", Family: "ipv4", Held: true, Packets: 4, Bytes: 336},
				}},
				{Rules: []BorderChainRule{{Spec: "a rule with no comment", Held: true}}},
			},
			Sets: []BorderSet{
				{Kind: "set", Name: "carved4", Elements: []string{"203.0.113.5"}},
				{Kind: "set", Name: "owned4", Elements: []string{"203.0.113.0/26", "198.51.100.7-198.51.100.9"}},
				{Kind: "set", Name: "none4"},
			},
		},
	}
}

func TestRulesRenderAsTheGoldenFiles(t *testing.T) {
	info := rulesFixture()
	var out strings.Builder
	RenderRules(&out, info)
	golden(t, "rules.txt", []byte(out.String()))
	goldenJSON(t, "rules.json", info)

	// darwin has no policy rules, runs no antispoof filter where overlay is not
	// written, and lists the
	// interface each live session's datagrams name, or the interface of the pin
	// they carry: the route the selection matched, one address no route holds, a pin
	// of a session the peer opened, and a link-local zone's
	out.Reset()
	darwin := RulesInfo{
		Policy:    []PolicyRule{},
		PolicyErr: "this platform has no policy rules",
		Missing:   []PolicyRule{},
		Lookups: []RuleLookup{
			{Lookup: "underlay", Family: "ipv4", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Address: netip.MustParseAddr("198.51.100.77"), Answer: "dev en0"},
			{Lookup: "underlay", Family: "ipv4", Address: netip.MustParseAddr("203.0.113.10"), Answer: "dev en1"},
			{Lookup: "underlay", Family: "ipv4", Address: netip.MustParseAddr("203.0.113.70"), Answer: "no route"},
			{Lookup: "underlay", Family: "ipv6", Prefix: netip.MustParsePrefix("::/0"), Address: netip.MustParseAddr("2001:db8:400::7"), Answer: "dev en0"},
			{Lookup: "underlay", Family: "ipv6", Address: netip.MustParseAddr("fe80::9%en0"), Answer: "dev en0"},
		},
	}
	RenderRules(&out, darwin)
	golden(t, "rules-darwin.txt", []byte(out.String()))
	goldenJSON(t, "rules-darwin.json", darwin)

	// where overlay is written darwin's filter runs over pf: the anchor's
	// rules with their counters, an exemption under en* one rule per link and
	// one whose label pf holds shortened by its whole text, its table, this
	// daemon's reference and the main ruleset's call, and every reference pf
	// lists
	out.Reset()
	darwin.Border = &BorderTable{
		Where:   "pf anchor com.apple/ranet3",
		ReadAt:  time.Date(2026, 11, 3, 23, 40, 5, 0, time.UTC),
		ReadAgo: Duration(2 * time.Second),
		Ready:   true,
		Chains: []BorderChain{
			{Name: "antispoof", Hook: "in", Rules: []BorderChainRule{
				{Spec: "accept via lo0", Verdict: "accept", Reason: "inside", Held: true},
				{Spec: "drop ipv4 source @carved4", Verdict: "drop", Reason: "carved_source", Family: "ipv4", Held: true, Packets: 1, Bytes: 84},
				{Spec: "drop ipv6 source @carved6", Verdict: "drop", Reason: "carved_source", Family: "ipv6", Held: true},
				{Spec: "accept via en0 source 192.0.2.128/25", Verdict: "accept", Reason: "carve_out", Family: "ipv4", Held: true},
				{Spec: "accept exempt source 192.0.2.32/27", Verdict: "accept", Reason: "exempt", Family: "ipv4", Held: true},
				{Spec: "accept exempt via bridge100 source 3fff:10:2222:3333:4444:5555:6666:7777/128", Verdict: "accept", Reason: "exempt", Family: "ipv6", Held: true},
				{Spec: "accept exempt via en0 source 3fff:10:1::/48", Verdict: "accept", Reason: "exempt", Family: "ipv6", Held: true},
				{Spec: "accept exempt via en1 source 3fff:10:1::/48", Verdict: "accept", Reason: "exempt", Family: "ipv6", Held: true},
				{Spec: "accept exempt via en1 source 192.0.2.64/26", Verdict: "accept", Reason: "exempt", Family: "ipv4", Held: true},
				{Spec: "drop ipv4 source 192.0.2.0/24", Verdict: "drop", Reason: "overlay_source", Family: "ipv4", Held: true, Packets: 2, Bytes: 168},
				{Spec: "drop ipv6 source 3fff:10::/32", Verdict: "drop", Reason: "overlay_source", Family: "ipv6", Held: true, Packets: 9, Bytes: 936},
			}},
		},
		Sets: []BorderSet{
			{Kind: "table", Name: "ranet3_carved", Elements: []string{"192.0.2.200", "3fff:10::/48"}},
		},
		PF:       &BorderPF{Anchor: "com.apple/ranet3", Token: 9223372036854775809, PID: 4242, Listed: true, Called: true},
		Enablers: []BorderEnabler{{PID: 4242, Name: "ranet3"}, {PID: 377, Name: "othervpn"}},
	}
	RenderRules(&out, darwin)
	golden(t, "rules-darwin-pf.txt", []byte(out.String()))
	goldenJSON(t, "rules-darwin-pf.json", darwin)

	// a pass that asked nothing, and a dump that failed beside the lookups
	out.Reset()
	RenderRules(&out, RulesInfo{Policy: info.Policy[:1]})
	golden(t, "rules-unasked.txt", []byte(out.String()))
	out.Reset()
	RenderRules(&out, RulesInfo{PolicyErr: "kernel: dump rules: permission denied", Lookups: info.Lookups})
	golden(t, "rules-undumped.txt", []byte(out.String()))

	// a platform that runs no filter, where overlay is written, says so in one line
	out.Reset()
	RenderRules(&out, RulesInfo{PolicyErr: "this platform has no policy rules", Border: &BorderTable{UnenforcedOn: "freebsd"}})
	if want := "\nAntispoof filter, not enforced on freebsd\n"; !strings.HasSuffix(out.String(), want) {
		t.Errorf("a platform with no filter renders\n%s\nwant it to end %q", out.String(), want)
	}
}

// a set is headed by the word its reading carries, whatever else the table
// holds, so the renderer learns no backend from the pf block
func TestBorderSetIsHeadedByTheWordItsBackendCallsItBy(t *testing.T) {
	for _, c := range []struct {
		kind string
		pf   *BorderPF
	}{{"table", nil}, {"set", &BorderPF{Anchor: "com.apple/ranet3"}}} {
		var out strings.Builder
		RenderRules(&out, RulesInfo{Border: &BorderTable{Where: "a backend", PF: c.pf, Sets: []BorderSet{{Kind: c.kind, Name: "owned"}}}})
		if !strings.Contains(out.String(), c.kind+" owned") {
			t.Errorf("a %s read with pf block %v renders\n%s", c.kind, c.pf, out.String())
		}
	}
}

// fallbackFixture is a table of one chain, holding, its drop having counted
// twelve packets, nothing forwarded and no own prefix of IPv6
func fallbackFixture() *FallbackTable {
	return &FallbackTable{
		Where: "nftables table inet ranet3 chains fallback and output", Hook: "postrouting", Priority: 2147483646,
		State: "holding", Held: true,
		Rules: []FallbackTableRule{
			{Spec: "oifname { lo, ranet3 } accept"},
			{Spec: "meta mark 0x00000072 accept"},
			{Spec: "meta iif != 0 iifname != @forwarded accept"},
			{Spec: "ip daddr @lan4 accept"},
			{Spec: "ip6 daddr @lan6 accept"},
			{Spec: "ip daddr { 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept"},
			{Spec: "ip6 daddr { fe80::/10, ff00::/8 } accept"},
			{Spec: "ip daddr @own4 accept"},
			{Spec: "ip6 daddr @own6 accept"},
			{Spec: "ct direction reply ct protocol tcp ct original proto-dst @tcp_ports accept"},
			{Spec: "counter drop", Packets: 12, Bytes: 720},
		},
		Sets: []FallbackTableSet{
			{Name: "forwarded"},
			{Name: "lan4", Elements: []string{"198.51.100.0/25", "203.0.113.64-203.0.113.70"}},
			{Name: "lan6", Elements: []string{"2001:db8:a::/64"}},
			{Name: "own4", Elements: []string{"203.0.113.0/26"}},
			{Name: "own6"},
			{Name: "tcp_ports", Elements: []string{"22", "60000-61000"}},
			{Name: "udp_ports"},
		},
	}
}

// The switch's chains render after the border's, holding with their lines and
// sets, not held, and unread
func TestRulesRenderTheFallbackTable(t *testing.T) {
	info := rulesFixture()
	info.Fallback = fallbackFixture()
	var out strings.Builder
	RenderRules(&out, info)
	golden(t, "rules-fallback.txt", []byte(out.String()))
	goldenJSON(t, "rules-fallback.json", info.Fallback)

	gone := fallbackFixture()
	gone.State, gone.Reason, gone.Held, gone.Rules, gone.Sets = "not holding", "its chains are missing", false, nil, nil
	unread := fallbackFixture()
	unread.Err, unread.Rules, unread.Sets = "nftables: dump tables: operation not permitted", nil, nil
	out.Reset()
	RenderRules(&out, RulesInfo{Policy: info.Policy[:1], Fallback: gone})
	RenderRules(&out, RulesInfo{Policy: info.Policy[:1], Fallback: unread})
	golden(t, "rules-fallback-unheld.txt", []byte(out.String()))
}

// On macOS the switch renders as its rejects on lo0 beside the platform's
// lack of policy rules, with neither hook nor priority nor a count, and the
// overlay's lookups name the route each ends at
func TestRulesRenderTheDarwinSwitch(t *testing.T) {
	var rejects []FallbackTableRule
	for _, key := range []string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"} {
		rejects = append(rejects, FallbackTableRule{Spec: key + " via 127.0.0.1 reject"})
	}
	for _, key := range []string{"100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1"} {
		rejects = append(rejects, FallbackTableRule{Spec: key + " via ::1 reject"})
	}
	darwin := RulesInfo{
		Policy:    []PolicyRule{},
		PolicyErr: "this platform has no policy rules",
		Missing:   []PolicyRule{},
		Border:    &BorderTable{UnenforcedOn: "darwin"},
		Lookups: []RuleLookup{
			{Lookup: "overlay", Family: "ipv4", Prefix: netip.MustParsePrefix("192.0.2.0/24"), Address: netip.MustParseAddr("192.0.2.2"), Answer: "192.0.2.0/24 via 127.0.0.1 on lo0 reject"},
			{Lookup: "overlay", Family: "ipv6", Prefix: netip.MustParsePrefix("3fff::/20"), Address: netip.MustParseAddr("3fff::2"), Answer: "3fff::/21 on utun5", Taken: true},
			{Lookup: "underlay", Family: "ipv4", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Address: netip.MustParseAddr("203.0.113.70"), Answer: "dev en0"},
		},
		Fallback: &FallbackTable{Where: "rejects on lo0", State: "holding", Held: true, Rules: rejects, Sets: []FallbackTableSet{}},
	}
	var out strings.Builder
	RenderRules(&out, darwin)
	golden(t, "rules-darwin-switch.txt", []byte(out.String()))
	goldenJSON(t, "rules-darwin-switch.json", darwin)
}

// in mode 3 the view lists the two steered defaults of the reconciler's table
// after the lookups and before the antispoof filter's chains, which every Linux
// node writes, installed while the path is up and the mesh holds a live
// session, and withdrawn with the SID that took the path down and the table's
// answer for it
func TestRulesListTheSteeredDefaults(t *testing.T) {
	info := rulesFixture()
	routes := func(v4, v6 bool) []SteeredDefault {
		return []SteeredDefault{
			{Family: "ipv4", To: netip.MustParsePrefix("0.0.0.0/0"), Installed: v4},
			{Family: "ipv6", To: netip.MustParsePrefix("::/0"), Installed: v6},
		}
	}
	for name, steered := range map[string]*SteeredDefaults{
		"rules-path-up":   {Table: 200, State: "up", Routes: routes(true, true)},
		"rules-path-down": {Table: 200, State: "down", Down: "3fff:b:0:306::3", Verdict: "held", Routes: routes(false, false)},
	} {
		info.Steered = steered
		var out strings.Builder
		RenderRules(&out, info)
		golden(t, name+".txt", []byte(out.String()))
		goldenJSON(t, name+".json", info.Steered)
	}
}

// rulesSource serves the rules view
type rulesSource struct{ fakeSource }

func (*rulesSource) DebugRules() RulesInfo { return rulesFixture() }

// the rules view reads the host's rules and the border's counters
func TestRulesReadTheRulesAndTheBorder(t *testing.T) {
	server := served(t, &rulesSource{})
	if status, body := get(t, server.Client(), server.URL+PathDebugRules); status != http.StatusOK || !strings.Contains(body, `"drop ipv4 source 203.0.113.0/24"`) {
		t.Errorf("the rules view was answered %d %q", status, body)
	}
}
