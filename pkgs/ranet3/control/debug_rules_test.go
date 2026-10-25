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
// its own protocol it does not derive, one derived rule missing, and its border
// chain read three seconds after its last pass with one forged source dropped
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
		Border: &BorderChain{
			Where:    "nftables table inet ranet3 chain border",
			Hook:     "prerouting",
			Priority: -300,
			ReadAt:   time.Date(2026, 10, 19, 9, 14, 2, 0, time.UTC),
			ReadAgo:  Duration(3 * time.Second),
			Ready:    true,
			Rules: []BorderChainRule{
				{Spec: "accept via ranet3", Verdict: "accept", Reason: "inside", Held: true},
				{Spec: "accept via lo", Verdict: "accept", Reason: "inside", Held: true},
				{Spec: "drop ipv4 source 23.161.104.0/24", Verdict: "drop", Reason: "overlay_source", Family: "ipv4", Held: true, Packets: 12, Bytes: 720},
				{Spec: "drop ipv6 source 2602:f590::/36", Verdict: "drop", Reason: "overlay_source", Family: "ipv6", Held: true},
				{Spec: "drop ipv6 routing header", Verdict: "drop", Reason: "routing_header", Family: "ipv6", Held: true},
				{Spec: "drop ipv6 destination 2a0c:b641:69c:5d26::3", Verdict: "drop", Reason: "sid_destination", Family: "ipv6"},
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

	// darwin has no policy rules and refuses cap.border
	out.Reset()
	RenderRules(&out, RulesInfo{PolicyErr: "this platform has no policy rules"})
	golden(t, "rules-darwin.txt", []byte(out.String()))
}

// rulesSource serves the rules view
type rulesSource struct{ fakeSource }

func (*rulesSource) DebugRules() RulesInfo { return rulesFixture() }

// the rules view discloses rules and counters, which status already discloses
// to the socket's group, so a caller the root class refuses still reads it
func TestRulesAreReadByACallerTheRootClassRefuses(t *testing.T) {
	server := injected(t, &rulesSource{}, Caller{UID: 4242})
	if status, body := get(t, server.Client(), server.URL+PathDebugRules); status != http.StatusOK || !strings.Contains(body, `"drop ipv6 routing header"`) {
		t.Errorf("uid 4242 asking for the rules view was answered %d %q", status, body)
	}
}
