// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"reflect"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// an exit whose only service is one egress segment, beside the node of the
// other tests, in each format a file is written in
const (
	egressTableTOML = `
[cap.table]
rules = [
  { to = "10.66.0.0/16", table = 200, priority = 100 },
  { iif = "ranet3e", table = "main", priority = 120, family = "both" },
  { from = "10.66.0.0/16", table = 200, priority = 150 },
]
`
	egressSegmentTOML = `
[[cap.segment.local]]
sid = "2a0c:b641:69c:5d26::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["23.161.104.0/24", "2602:f590::/36"]
`
	egressBorderTOML = `
[cap.border]
overlay = ["23.161.104.0/24", "2602:f590::/36"]
`
	egressExitTOML = "\n[cap.egress]\n" + egressBorderTOML + egressTableTOML + egressSegmentTOML
	egressExitYAML = `
cap:
  egress: {}
  border:
    overlay: [23.161.104.0/24, 2602:f590::/36]
  table:
    rules:
      - { to: 10.66.0.0/16, table: 200, priority: 100 }
      - { iif: ranet3e, table: main, priority: 120, family: both }
      - { from: 10.66.0.0/16, table: 200, priority: 150 }
  segment:
    local:
      - sid: 2a0c:b641:69c:5d26::3
        behavior: End.DT46
        deliver: egress
        allow: [23.161.104.0/24, 2602:f590::/36]
`
	egressExitJSON = `{
  "node": "example/laptop",
  "auth": {"key": "key.pem", "trust": "trust.json"},
  "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]},
  "dial": {"to": ["example/gateway"]},
  "cap": {
    "egress": {},
    "border": {"overlay": ["23.161.104.0/24", "2602:f590::/36"]},
    "table": {"rules": [
      {"to": "10.66.0.0/16", "table": 200, "priority": 100},
      {"iif": "ranet3e", "table": "main", "priority": 120, "family": "both"},
      {"from": "10.66.0.0/16", "table": 200, "priority": 150}
    ]},
    "segment": {"local": [{"sid": "2a0c:b641:69c:5d26::3", "behavior": "End.DT46", "deliver": "egress", "allow": ["23.161.104.0/24", "2602:f590::/36"]}]}
  }
}`
)

// An egress segment is an End.DT46 entry with deliver = "egress" and its allow
// list, written alike in each format, and a file writing deliver = "mesh"
// loads as one leaving it out
func TestEgressSegmentReadsAlikeInEveryFormat(t *testing.T) {
	want := srv6.Segment{
		SID:      schema.MustAddr("2a0c:b641:69c:5d26::3"),
		Behavior: srv6.BehaviorEndDT46,
		Deliver:  srv6.DeliverEgress,
		Allow:    []schema.Prefix{schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("2602:f590::/36")},
	}
	for name, body := range map[string]struct{ extension, text string }{
		"toml": {".toml", nodeTOML + egressExitTOML},
		"yaml": {".yaml", nodeYAML + egressExitYAML},
		"json": {".json", egressExitJSON},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, body.extension, body.text)
			if err != nil {
				t.Fatalf("an exit serving one egress segment was refused: %v", err)
			}
			if got := cfg.Segments().Local; len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Errorf("the segment read as %+v, want %+v", got, want)
			}
		})
	}
	written, err := loadTOML(t, nodeTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\ndeliver = \"mesh\"\n")
	if err != nil {
		t.Fatal(err)
	}
	omitted, err := loadTOML(t, nodeTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(written.Segments().Normalized(), omitted.Segments().Normalized()) {
		t.Errorf("deliver = \"mesh\" read as %+v and its omission as %+v", written.Segments(), omitted.Segments())
	}
}

// An egress segment loads only beside what carries its traffic: cap.egress to
// translate it, cap.table to hold the rule sending the egress device to the
// main table, that rule in each family and in its place, a mesh tun name the
// device's own name fits beside, and its /128 left to readiness
func TestEgressSegmentIsRefusedWithoutWhatCarriesIt(t *testing.T) {
	exit := nodeTOML + egressExitTOML
	rules := func(lines ...string) string {
		return strings.Replace(exit, `rules = [
  { to = "10.66.0.0/16", table = 200, priority = 100 },
  { iif = "ranet3e", table = "main", priority = 120, family = "both" },
  { from = "10.66.0.0/16", table = 200, priority = 150 },
]`, "rules = [\n"+strings.Join(lines, ",\n")+",\n]", 1)
	}
	for name, c := range map[string]struct{ body, says string }{
		"no cap.egress": {
			nodeTOML + egressTableTOML + egressSegmentTOML,
			"cap.segment local 2a0c:b641:69c:5d26::3 delivers to egress and cap.egress is absent, so nothing translates what leaves the egress device",
		},
		"no cap.table": {
			nodeTOML + "\n[cap.egress]\n" + egressSegmentTOML,
			"delivers to egress and cap.table is absent, so no reconciler holds the iif rule",
		},
		"no iif rule": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 100 }`, `{ from = "10.66.0.0/16", table = 200, priority = 150 }`),
			`cap.table rules holds no rule sending what arrives on ranet3e to the main table for ipv4: add { iif = "ranet3e", table = "main", priority = 120, family = "both" }, after every "to" rule into table 200 and before every "from" rule into it`,
		},
		"an iif rule of one family": {
			rules(`{ iif = "ranet3e", table = "main", priority = 120, family = "ipv4" }`),
			"holds no rule sending what arrives on ranet3e to the main table for ipv6",
		},
		"an iif rule into another table": {
			rules(`{ iif = "ranet3e", table = 300, priority = 120, family = "both" }`),
			"holds no rule sending what arrives on ranet3e to the main table for ipv4",
		},
		"an iif rule with a mark beside": {
			rules(`{ iif = "ranet3e", fwmark = 7, table = "main", priority = 120, family = "both" }`),
			"holds no rule sending what arrives on ranet3e to the main table for ipv4",
		},
		"an iif rule naming another device": {
			rules(`{ iif = "ranet3", table = "main", priority = 120, family = "both" }`),
			"holds no rule sending what arrives on ranet3e to the main table for ipv4",
		},
		"an iif rule after a from rule": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 100 }`, `{ from = "10.66.0.0/16", table = 200, priority = 150 }`, `{ iif = "ranet3e", table = "main", priority = 160, family = "both" }`),
			`cap.table rules priority 160 iif ranet3e family ipv4 lookup main comes after the "from" rule at priority 150 into table 200, which takes steered packets to the mesh table first: move it between 100 and 150`,
		},
		"an iif rule before a to rule": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 100 }`, `{ iif = "ranet3e", table = "main", priority = 90, family = "both" }`),
			`cap.table rules priority 90 iif ranet3e family ipv4 lookup main comes before the "to" rule at priority 100 into table 200, which sends steered packets for mesh destinations out of the uplink: move it after 100`,
		},
		"an iif rule below the higher of two to rules listed lower first": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 100 }`, `{ to = "10.67.0.0/16", table = 200, priority = 130 }`, `{ iif = "ranet3e", table = "main", priority = 120, family = "both" }`),
			`priority 120 iif ranet3e family ipv4 lookup main comes before the "to" rule at priority 130 into table 200, which sends steered packets for mesh destinations out of the uplink: move it after 130`,
		},
		"an iif rule above the lower of two from rules listed higher first": {
			rules(`{ from = "10.66.0.0/16", table = 200, priority = 200 }`, `{ from = "10.67.0.0/16", table = 200, priority = 150 }`, `{ iif = "ranet3e", table = "main", priority = 160, family = "both" }`),
			`priority 160 iif ranet3e family ipv4 lookup main comes after the "from" rule at priority 150 into table 200, which takes steered packets to the mesh table first: move it before 150`,
		},
		"an iif rule at a to rule's priority": {
			rules(`{ to = "2001:db8::/32", table = 200, priority = 120 }`, `{ iif = "ranet3e", table = "main", priority = 120, family = "both" }`),
			`priority 120 iif ranet3e family ipv6 lookup main comes before the "to" rule at priority 120`,
		},
		"no room between the bounds": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 100 }`, `{ from = "10.66.0.0/16", table = 200, priority = 101 }`),
			"no priority lies after 100 and before 101, so move one of those rules",
		},
		"a from rule below a to rule": {
			rules(`{ from = "10.66.0.0/16", table = 200, priority = 100 }`, `{ to = "10.66.0.0/16", table = 200, priority = 150 }`),
			"no priority lies after 150 and before 100, so move one of those rules",
		},
		"an iif rule between a from rule and a to rule above it": {
			rules(`{ from = "10.66.0.0/16", table = 200, priority = 100 }`, `{ iif = "ranet3e", table = "main", priority = 120, family = "both" }`, `{ to = "10.66.0.0/16", table = 200, priority = 150 }`),
			"no priority lies after 150 and before 100, so move one of those rules",
		},
		"an iif rule above a to rule above a from rule": {
			rules(`{ from = "10.66.0.0/16", table = 200, priority = 100 }`, `{ to = "10.66.0.0/16", table = 200, priority = 150 }`, `{ iif = "ranet3e", table = "main", priority = 151, family = "both" }`),
			"no priority lies after 150 and before 100, so move one of those rules",
		},
		"a lone to rule just below the last priority": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 4294967294 }`),
			`add { iif = "ranet3e", table = "main", priority = 4294967295, family = "both" }`,
		},
		"a lone to rule at the last priority": {
			rules(`{ to = "10.66.0.0/16", table = 200, priority = 4294967295 }`),
			"no priority lies after 4294967295, so move that rule",
		},
		"a lone from rule at the first priority": {
			rules(`{ from = "10.66.0.0/16", table = 200, priority = 1 }`),
			"no priority lies before 1, so move that rule",
		},
		"a mesh tun of 15 bytes": {
			strings.Replace(exit, "[link]\n", "[link]\ntun = \"fifteen-bytes-x\"\n", 1),
			`config: link.tun "fifteen-bytes-x" is 15 bytes, and the egress device is named link.tun plus e, which the kernel caps at 15 bytes`,
		},
		"a mesh tun the kernel numbers": {
			strings.Replace(exit, "[link]\n", "[link]\ntun = \"ranet%d\"\n", 1),
			`config: link.tun "ranet%d" is a template the kernel numbers, so the egress device's name is not known before the daemon starts`,
		},
		"its /128 announced by cap.route": {
			exit + "[cap.route]\nannounce = [\"2a0c:b641:69c:5d26::3/128\"]\n",
			"config: cap.route announces 2a0c:b641:69c:5d26::3/128, the egress segment's own route, which would announce it whether or not the segment is ready",
		},
		"a second egress segment's /128 announced by cap.route": {
			exit + strings.Replace(egressSegmentTOML, "5d26::3", "5d26::4", 1) + "[cap.route]\nannounce = [\"2a0c:b641:69c:5d26::4/128\"]\n",
			"config: cap.route announces 2a0c:b641:69c:5d26::4/128, the egress segment's own route, which would announce it whether or not the segment is ready",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	// a rule into the mesh table with neither selector bounds nothing, and a covering route may be announced
	for name, body := range map[string]string{
		"a mark rule into the mesh table": rules(`{ fwmark = 7, table = 200, priority = 130, family = "both" }`, `{ iif = "ranet3e", table = "main", priority = 120, family = "both" }`),
		"a covering prefix announced":     exit + "[cap.route]\nannounce = [\"2a0c:b641:69c:5d20::/60\"]\n",
		"the device named after link.tun": strings.Replace(strings.ReplaceAll(exit, `iif = "ranet3e"`, `iif = "ranet0e"`), "[link]\n", "[link]\ntun = \"ranet0\"\n", 1),
	} {
		if _, err := loadTOML(t, body); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	// a segment that delivers to the mesh asks for none of it
	if _, err := loadTOML(t, nodeTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\n"); err != nil {
		t.Errorf("a segment delivering to the mesh was refused: %v", err)
	}
}
