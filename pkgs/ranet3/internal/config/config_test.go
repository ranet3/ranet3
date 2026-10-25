// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package config

import (
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
	"ranet3.com/pkgs/ranet3/transport"
)

// The node a test starts from, in both spellings. Everything below adds one
// capability to it, so a refusal is about the capability rather than about
// what the node forgot to say.
const (
	nodeYAML = `
node: example/laptop
auth:
  key: key.pem
  trust: trust.json
link:
  port: 13000
  endpoints:
    - serial: "0"
      family: ip4
dial:
  to:
    - example/gateway
`
	nodeTOML = `
node = "example/laptop"
[auth]
key = "key.pem"
trust = "trust.json"
[link]
port = 13000
endpoints = [{ serial = "0", family = "ip4" }]
[dial]
to = ["example/gateway"]
`
)

// load writes a body under the extension it is written in and reads it back
// the way the daemon does, through the loader rather than through a decoder,
// so the test covers the dispatch and the validation as well as the parse.
func load(t testing.TB, extension, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config"+extension)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return load(t, ".yaml", body)
}

func loadTOML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return load(t, ".toml", body)
}

// A configuration is read by its extension, and one the loader does not know
// is refused by name rather than sniffed: a file whose contents and whose name
// disagree is one somebody has to debug.
func TestLoaderPicksTheDecoderByExtension(t *testing.T) {
	for _, extension := range []string{".yaml", ".yml", ".json"} {
		if _, err := load(t, extension, nodeYAML); err != nil {
			t.Errorf("%s was refused: %v", extension, err)
		}
	}
	if _, err := loadTOML(t, nodeTOML); err != nil {
		t.Errorf("toml was refused: %v", err)
	}
	// The body is valid YAML, so only the name decides.
	_, err := load(t, ".conf", nodeYAML)
	if err == nil {
		t.Fatal("an extension the loader does not know was sniffed rather than refused")
	}
	if !strings.Contains(err.Error(), ".conf") {
		t.Errorf("the refusal reads %q and does not name the extension", err)
	}
}

// One node written twice reaches one struct. This is the property the second
// decoder exists for: a deployment that writes toml and a control plane that
// speaks json describe the same node.
func TestBothDecodersReadOneNode(t *testing.T) {
	const capabilitiesYAML = `
cap:
  route:
    announce: ["10.66.0.5/32", { prefix: "::/0", from: "2001:db8:1::/48" }]
  transit:
    enable: false
  babel:
    hello: 4s
    quality: none
    cost:
      rx: 96
      rtt: { weight: 1024, min: 10ms, max: 1024ms }
  table:
    id: 200
    addresses: ["10.66.0.5/32"]
    rules:
      - { fwmark: 0x726c, table: main, priority: 40, family: both }
  segment:
    source: "3fff:1:69c:8c0::1"
    local:
      - { sid: "3fff:1:69c:8c6::1", behavior: "End.DT46" }
  border:
    overlay: ["3fff::/20"]
  crypto:
    replay: 4096
    rekey: { child: 1h, retry: { first: 5s, max: 5m } }
`
	const capabilitiesTOML = `
[cap.route]
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8:1::/48" }]
[cap.transit]
enable = false
[cap.babel]
hello = "4s"
quality = "none"
[cap.babel.cost]
rx = 96
[cap.babel.cost.rtt]
weight = 1024
min = "10ms"
max = "1024ms"
[cap.table]
id = 200
addresses = ["10.66.0.5/32"]
rules = [{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }]
[cap.segment]
source = "3fff:1:69c:8c0::1"
local = [{ sid = "3fff:1:69c:8c6::1", behavior = "End.DT46" }]
[cap.border]
overlay = ["3fff::/20"]
[cap.crypto]
replay = 4096
rekey = { child = "1h", retry = { first = "5s", max = "5m" } }
`
	fromYAML, err := loadYAML(t, nodeYAML+capabilitiesYAML)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fromTOML, err := loadTOML(t, nodeTOML+capabilitiesTOML)
	if err != nil {
		t.Fatalf("toml: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromTOML) {
		t.Errorf("yaml read\n%+v\nand toml read\n%+v", fromYAML, fromTOML)
	}
	// And the capabilities are actually there, so two empty structs cannot
	// pass the comparison above.
	if fromYAML.Cap.Route == nil || fromYAML.Cap.Transit == nil || fromYAML.Cap.Babel == nil || fromYAML.Cap.Table == nil ||
		fromYAML.Cap.Segment == nil || fromYAML.Cap.Crypto == nil {
		t.Fatalf("a capability was dropped: %+v", fromYAML.Cap)
	}
	if fromYAML.Transits() || fromYAML.Babel().Quality != babel.LinkQualityNone {
		t.Error("the capability values did not reach the struct")
	}
}

// Every refusal below is a configuration that loads into a node doing
// something other than what its file says, and both decoders have to make the
// same one: an operator who picks the other extension gets the same answer.
func TestBothDecodersRefuseTheSameConfigurations(t *testing.T) {
	for name, pair := range map[string]struct{ asYAML, asTOML string }{
		"an unknown field": {
			asYAML: "unknown: true\n",
			asTOML: "unknown = true\n",
		},
		"an unknown capability": {
			asYAML: "cap:\n  egres:\n    source4: auto\n",
			asTOML: "[cap.egres]\nsource4 = \"auto\"\n",
		},
		"a negative hello interval": {
			asYAML: "cap:\n  babel:\n    hello: -1s\n",
			asTOML: "[cap.babel]\nhello = \"-1s\"\n",
		},
		"an unrepresentable update interval": {
			asYAML: "cap:\n  babel:\n    update: 11m\n",
			asTOML: "[cap.babel]\nupdate = \"11m\"\n",
		},
		"a link quality that is neither": {
			asYAML: "cap:\n  babel:\n    quality: best\n",
			asTOML: "[cap.babel]\nquality = \"best\"\n",
		},
		"an oversized replay window": {
			asYAML: "cap:\n  crypto:\n    replay: 1048577\n",
			asTOML: "[cap.crypto]\nreplay = 1048577\n",
		},
		"an announcement that is not a prefix": {
			asYAML: "cap:\n  route:\n    announce: [not-a-prefix]\n",
			asTOML: "[cap.route]\nannounce = [\"not-a-prefix\"]\n",
		},
		"a segment source that is not an address": {
			asYAML: "cap:\n  segment:\n    source: \"not an address\"\n",
			asTOML: "[cap.segment]\nsource = \"not an address\"\n",
		},
		"a v4 segment source": {
			asYAML: "cap:\n  segment:\n    source: 10.0.0.1\n",
			asTOML: "[cap.segment]\nsource = \"10.0.0.1\"\n",
		},
		"a multicast segment source": {
			asYAML: "cap:\n  segment:\n    source: ff02::1\n",
			asTOML: "[cap.segment]\nsource = \"ff02::1\"\n",
		},
		"an address no interface can carry": {
			asYAML: "cap:\n  table:\n    addresses: [\"::/0\"]\n",
			asTOML: "[cap.table]\naddresses = [\"::/0\"]\n",
		},
		"an address with no prefix length": {
			asYAML: "cap:\n  table:\n    addresses: [\"2001:db8::1/0\"]\n",
			asTOML: "[cap.table]\naddresses = [\"2001:db8::1/0\"]\n",
		},
		// RTA_PREFSRC is stamped on IPv4 routes alone, and IPv6 carries no
		// preferred source at all, so an address of the other family is a
		// setting the reconciler would take and never apply.
		"a preferred source of the other family": {
			asYAML: "cap:\n  table:\n    prefsrc4: \"2001:db8::1\"\n",
			asTOML: "[cap.table]\nprefsrc4 = \"2001:db8::1\"\n",
		},
		// An interface cannot carry the unspecified address, and Assigned
		// skips it, so taking the entry is the one outcome that leaves the
		// operator an address they wrote and this node never assigned. The
		// length is there because the zero-length spelling is refused by a
		// check of its own, and this one has to hold without it.
		"an address under a length no interface can carry": {
			asYAML: "cap:\n  table:\n    addresses: [\"::/64\"]\n",
			asTOML: "[cap.table]\naddresses = [\"::/64\"]\n",
		},
		// Both intervals normalize a value at or below zero to their default,
		// so a negative one loads into a node running on a number nobody
		// wrote and says nothing.
		"a negative reconcile interval": {
			asYAML: "cap:\n  table:\n    reconcile: -1s\n",
			asTOML: "[cap.table]\nreconcile = \"-1s\"\n",
		},
		"a negative capture grace": {
			asYAML: "cap:\n  table:\n    capture_grace: -1s\n",
			asTOML: "[cap.table]\ncapture_grace = \"-1s\"\n",
		},
		// A mask with no mark reaches the kernel as a rule matching every
		// packet whose mark is zero under it, which on this fleet is the
		// unmarked traffic the rule was written to leave alone.
		"a rule carrying a mark mask and no mark": {
			asYAML: "cap:\n  table:\n    rules: [{ fwmask: 0xffffffff, to: \"10.0.0.0/8\", table: 200, priority: 40 }]\n",
			asTOML: "[cap.table]\nrules = [{ fwmask = 0xffffffff, to = \"10.0.0.0/8\", table = 200, priority = 40 }]\n",
		},
		"a rule selecting on a mark with no family": {
			asYAML: "cap:\n  table:\n    rules: [{ fwmark: 0x726c, table: main, priority: 40 }]\n",
			asTOML: "[cap.table]\nrules = [{ fwmark = 0x726c, table = \"main\", priority = 40 }]\n",
		},
		"a rule naming a family and an address": {
			asYAML: "cap:\n  table:\n    rules: [{ to: \"10.0.0.0/8\", table: 200, priority: 40, family: ipv6 }]\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 40, family = \"ipv6\" }]\n",
		},
		"a rule at the local table's priority": {
			asYAML: "cap:\n  table:\n    rules: [{ to: \"10.0.0.0/8\", table: 200, priority: 0 }]\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 0 }]\n",
		},
		"two rules that are one rule": {
			asYAML: "cap:\n  table:\n    rules:\n      - { to: \"10.0.0.0/8\", table: 200, priority: 40 }\n      - { to: \"10.0.0.0/8\", table: 200, priority: 40 }\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 40 }, { to = \"10.0.0.0/8\", table = 200, priority = 40 }]\n",
		},
		// The kernel reads an all-ones mask and an absent one alike, so these
		// two entries install one rule. Compared as written they looked
		// different, and every pass reported EEXIST on the second and retried.
		"two rules one mask apart": {
			asYAML: "cap:\n  table:\n    rules:\n      - { fwmark: 0x726c, table: main, priority: 40, family: both }\n      - { fwmark: 0x726c, fwmask: 0xffffffff, table: main, priority: 40, family: both }\n",
			asTOML: "[cap.table]\nrules = [{ fwmark = 0x726c, table = \"main\", priority = 40, family = \"both\" }, { fwmark = 0x726c, fwmask = 0xffffffff, table = \"main\", priority = 40, family = \"both\" }]\n",
		},
		// And one entry written for both families expanded into two that are
		// one rule each, which the comparison also has to see.
		"one family written twice": {
			asYAML: "cap:\n  table:\n    rules:\n      - { fwmark: 0x726c, table: main, priority: 40, family: both }\n      - { fwmark: 0x726c, table: main, priority: 40, family: ipv6 }\n",
			asTOML: "[cap.table]\nrules = [{ fwmark = 0x726c, table = \"main\", priority = 40, family = \"both\" }, { fwmark = 0x726c, table = \"main\", priority = 40, family = \"ipv6\" }]\n",
		},
		"a negative rekey interval": {
			asYAML: "cap:\n  crypto:\n    rekey: { child: -1s }\n",
			asTOML: "[cap.crypto.rekey]\nchild = \"-1s\"\n",
		},
		"a zero retry delay": {
			asYAML: "cap:\n  crypto:\n    rekey: { retry: { first: 0 } }\n",
			asTOML: "[cap.crypto.rekey.retry]\nfirst = \"0\"\n",
		},
		"a first retry past the maximum": {
			asYAML: "cap:\n  crypto:\n    rekey: { retry: { first: 1m, max: 5s } }\n",
			asTOML: "[cap.crypto.rekey.retry]\nfirst = \"1m\"\nmax = \"5s\"\n",
		},
		"a rekey with no room for its margin": {
			asYAML: "cap:\n  crypto:\n    rekey: { child: 5m }\n",
			asTOML: "[cap.crypto.rekey]\nchild = \"5m\"\n",
		},
		"a segment this node also carries as an address": {
			asYAML: "cap:\n  table:\n    addresses: [\"3fff:1:69c:8c6::1/128\"]\n  segment:\n    local: [{ sid: \"3fff:1:69c:8c6::1\", behavior: End }]\n  border:\n    overlay: [\"3fff::/20\"]\n",
			asTOML: "[cap.table]\naddresses = [\"3fff:1:69c:8c6::1/128\"]\n[cap.segment]\nlocal = [{ sid = \"3fff:1:69c:8c6::1\", behavior = \"End\" }]\n[cap.border]\noverlay = [\"3fff::/20\"]\n",
		},
		"an exit that advertises nothing": {
			asYAML: "cap:\n  egress:\n    source4: auto\n",
			asTOML: "[cap.egress]\nsource4 = \"auto\"\n",
		},
		"an advertised prefix with host bits": {
			asYAML: "cap:\n  egress:\n    advertise: [\"198.51.100.7/24\"]\n",
			asTOML: "[cap.egress]\nadvertise = [\"198.51.100.7/24\"]\n",
		},
		"an egress source of the other family": {
			asYAML: "cap:\n  egress:\n    advertise: [\"0.0.0.0/0\"]\n    source4: \"2001:db8::1\"\n",
			asTOML: "[cap.egress]\nadvertise = [\"0.0.0.0/0\"]\nsource4 = \"2001:db8::1\"\n",
		},
		// The device comes down by the longest segment list, and a list long
		// enough to take it under the 1280 RFC 8200 requires of every link is
		// one the daemon refuses at startup. Refusing it here too makes a
		// configuration check and the daemon agree: lists of five and more
		// loaded clean and then would not start.
		"a segment list the device cannot carry": {
			asYAML: "cap:\n  segment:\n    source: \"3fff:1:69c:8c0::1\"\n    steer:\n      - from: \"3fff:a::1/128\"\n        via: [\"3fff:1:69c::1\", \"3fff:1:69c::2\", \"3fff:1:69c::3\", \"3fff:1:69c::4\", \"3fff:1:69c::5\"]\n",
			asTOML: "[cap.segment]\nsource = \"3fff:1:69c:8c0::1\"\nsteer = [{ from = \"3fff:a::1/128\", via = [\"3fff:1:69c::1\", \"3fff:1:69c::2\", \"3fff:1:69c::3\", \"3fff:1:69c::4\", \"3fff:1:69c::5\"] }]\n",
		},
		"a steering selector that claims every address": {
			asYAML: "cap:\n  segment:\n    source: \"3fff:1:69c:8c0::1\"\n    steer: [{ from: \"::/0\", via: [\"3fff:1:69c::1\"] }]\n",
			asTOML: "[cap.segment]\nsource = \"3fff:1:69c:8c0::1\"\nsteer = [{ from = \"::/0\", via = [\"3fff:1:69c::1\"] }]\n",
		},
		"an egress source nothing can reply to": {
			asYAML: "cap:\n  egress:\n    advertise: [\"0.0.0.0/0\"]\n    source4: 127.0.0.1\n",
			asTOML: "[cap.egress]\nadvertise = [\"0.0.0.0/0\"]\nsource4 = \"127.0.0.1\"\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+pair.asYAML); err == nil {
				t.Errorf("yaml took %q", pair.asYAML)
			}
			if _, err := loadTOML(t, nodeTOML+pair.asTOML); err == nil {
				t.Errorf("toml took %q", pair.asTOML)
			}
		})
	}
}

// a file writing link.underlay mark is refused as an unknown key under every
// decoder, since on linux every underlay socket carries, where the process
// may set it, one mark that no key sets
// the same block without the key loads, so the refusal is the key's
func TestLoaderRefusesTheUnderlayMarkAsUnknown(t *testing.T) {
	const asJSON = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}],"underlay":{%s}},"dial":{"to":["example/gateway"]}}`
	underlaidYAML := func(block string) string {
		return strings.Replace(nodeYAML, "  endpoints:", "  underlay: "+block+"\n  endpoints:", 1)
	}
	for name, test := range map[string]struct{ extension, with, without, refusal string }{
		"toml": {".toml",
			nodeTOML + "[link.underlay]\nmark = 0x726c\n",
			nodeTOML + "[link.underlay]\n",
			`unknown field "link.underlay.mark"`},
		"yaml": {".yaml",
			underlaidYAML("{ mark: 0x726c }"),
			underlaidYAML("{}"),
			"field mark not found in type transport.Underlay"},
		"json": {".json",
			fmt.Sprintf(asJSON, `"mark":29292`),
			fmt.Sprintf(asJSON, ""),
			"field mark not found in type transport.Underlay"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, test.extension, test.without); err != nil {
				t.Fatalf("link.underlay without mark was refused: %v", err)
			}
			if _, err := load(t, test.extension, test.with); err == nil || !strings.Contains(err.Error(), test.refusal) {
				t.Errorf("link.underlay with mark loaded with %v, want it refused as %s", err, test.refusal)
			}
		})
	}
}

// a file writing cap.table vrf is refused as an unknown key under every decoder
// the same block without the key loads, so the refusal is the key's
func TestLoaderRefusesTheVRFKeyAsUnknown(t *testing.T) {
	const asJSON = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"to":["example/gateway"]},` +
		`"cap":{"table":{"id":200%s}}}`
	for name, test := range map[string]struct{ extension, with, without, refusal string }{
		"toml": {".toml",
			nodeTOML + "[cap.table]\nid = 200\n[cap.table.vrf]\nname = \"gravity\"\n",
			nodeTOML + "[cap.table]\nid = 200\n",
			`unknown field "cap.table.vrf"`},
		"yaml": {".yaml",
			nodeYAML + "cap:\n  table:\n    id: 200\n    vrf: { name: gravity }\n",
			nodeYAML + "cap:\n  table:\n    id: 200\n",
			"field vrf not found in type kernel.Table"},
		"json": {".json",
			fmt.Sprintf(asJSON, `,"vrf":{"name":"gravity"}`),
			fmt.Sprintf(asJSON, ""),
			"field vrf not found in type kernel.Table"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, test.extension, test.without); err != nil {
				t.Fatalf("cap.table without vrf was refused: %v", err)
			}
			if _, err := load(t, test.extension, test.with); err == nil || !strings.Contains(err.Error(), test.refusal) {
				t.Errorf("cap.table with vrf loaded with %v, want it refused as %s", err, test.refusal)
			}
		})
	}
}

// What the node itself has to say, and what it may not say twice.
func TestNodeFactsAreRefusedWhenTheyCannotBeActedOn(t *testing.T) {
	for name, body := range map[string]string{
		"no node":                  strings.Replace(nodeYAML, "node: example/laptop\n", "", 1),
		"a node with no org":       strings.Replace(nodeYAML, "node: example/laptop", "node: laptop", 1),
		"a node of two org levels": strings.Replace(nodeYAML, "node: example/laptop", "node: example/lab/laptop", 1),
		// the endpoints are link.endpoints, and a node written as one of them would be a second place to name them
		"an endpoint as the node": strings.Replace(nodeYAML, "node: example/laptop", "node: example/laptop:0", 1),
		"no port":                 strings.Replace(nodeYAML, "  port: 13000\n", "", 1),
		"no key":                  strings.Replace(nodeYAML, "  key: key.pem\n", "", 1),
		"no trust":                strings.Replace(nodeYAML, "  trust: trust.json\n", "", 1),
		// Every IKE datagram here carries the non-ESP marker, and RFC 7296
		// section 2.23 forbids UDP encapsulation on port 500, so a node naming
		// it is one no conformant peer can talk to.
		"port 500":                  strings.Replace(nodeYAML, "port: 13000", "port: 500", 1),
		"no endpoints":              strings.Replace(nodeYAML, "  endpoints:\n    - serial: \"0\"\n      family: ip4\n", "  endpoints: []\n", 1),
		"a peer with no org":        strings.Replace(nodeYAML, "    - example/gateway\n", "    - gateway\n", 1),
		"a peer as a table":         strings.Replace(nodeYAML, "    - example/gateway\n", "    - { org: example, name: gateway }\n", 1),
		"a peer as a selector":      strings.Replace(nodeYAML, "    - example/gateway\n", "    - tag:router\n", 1),
		"a duplicate endpoint peer": strings.Replace(nodeYAML, "    - example/gateway\n", "    - example/gateway:1\n    - example/gateway:1\n", 1),
		"a duplicate endpoint": strings.Replace(nodeYAML, "    - serial: \"0\"\n      family: ip4\n",
			"    - serial: \"0\"\n      family: ip4\n    - serial: \"0\"\n      family: ip4\n", 1),
		"a duplicate peer":                   strings.Replace(nodeYAML, "    - example/gateway\n", "    - example/gateway\n    - example/gateway\n", 1),
		"an endpoint family that is neither": strings.Replace(nodeYAML, "family: ip4", "family: ipv4", 1),
		// A listener needs no peers, and a node with neither does nothing at
		// all.
		"nothing to dial and nothing listening": strings.Replace(nodeYAML, "dial:\n  to:\n    - example/gateway\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil {
				t.Error("a node that could not run was accepted")
			}
		})
	}
	// The two that make a node with no peers legitimate.
	alone := strings.Replace(nodeYAML, "dial:\n  to:\n    - example/gateway\n", "", 1)
	for name, body := range map[string]string{
		"a listener": strings.Replace(alone, "  port: 13000\n", "  port: 13000\n  listen: true\n", 1),
		"dial.all":   alone + "dial:\n  all: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err != nil {
				t.Errorf("a node that answers or dials everybody was refused: %v", err)
			}
		})
	}
}

// node and each dial.to entry are written as their text under either decoder, and dial.to takes a node and an endpoint of another
func TestNodeAndPeersReadAsIdentities(t *testing.T) {
	want := []identity.Identity{identity.MustParse("example/gateway"), identity.MustParse("other/relay:1")}
	for name, body := range map[string]string{
		".yaml": strings.Replace(nodeYAML, "    - example/gateway\n", "    - example/gateway\n    - other/relay:1\n", 1),
		".toml": strings.Replace(nodeTOML, `to = ["example/gateway"]`, `to = ["example/gateway", "other/relay:1"]`, 1),
	} {
		cfg, err := load(t, name, body)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cfg.Node != identity.MustParse("example/laptop") || !slices.Equal(cfg.Dial.To, want) {
			t.Errorf("%s read node %s and dial.to %v, want example/laptop and %v", name, cfg.Node, cfg.Dial.To, want)
		}
	}
}

// a null dial.to entry names nobody, where yaml.v3 would drop it from the list and encoding/json reads it as the zero identity
// a null after a named peer is refused as one before it is
func TestDialToRefusesAnEntryThatNamesNobody(t *testing.T) {
	const asJSON = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"to":[null,"other/relay"]}}`
	for name, file := range map[string]struct{ extension, body string }{
		"yaml, null first":        {".yaml", strings.Replace(nodeYAML, "    - example/gateway\n", "    - ~\n    - other/relay\n", 1)},
		"yaml, null after a peer": {".yaml", strings.Replace(nodeYAML, "    - example/gateway\n", "    - other/relay\n    - ~\n", 1)},
		"json, null first":        {".json", asJSON},
		"json, null after a peer": {".json", strings.Replace(asJSON, `[null,"other/relay"]`, `["other/relay",null]`, 1)},
	} {
		if _, err := load(t, file.extension, file.body); err == nil || !strings.Contains(err.Error(), "a dial.to entry names nobody") {
			t.Errorf("%s: a file whose dial.to holds a null entry was answered with %v", name, err)
		}
	}
	var cfg Config
	if err := json.Unmarshal([]byte(asJSON), &cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "a dial.to entry names nobody") {
		t.Errorf("a null dial.to entry read by encoding/json was answered with %v", err)
	}
}

// a link.mtu under 1280, under 1280 plus what the longest steering list puts in front of a packet, or past 65470 is refused under either decoder
// and the refusal names the field, the value written and the bound it misses
func TestLinkMTURefusalsNameTheFieldUnderEitherDecoder(t *testing.T) {
	const (
		twoSegmentsYAML = "cap:\n  segment:\n    source: \"3fff:1:69c:8c0::1\"\n    steer: [{ from: \"3fff:a::1/128\", via: [\"3fff:1:69c::1\", \"3fff:1:69c::2\"] }]\n"
		twoSegmentsTOML = "[cap.segment]\nsource = \"3fff:1:69c:8c0::1\"\nsteer = [{ from = \"3fff:a::1/128\", via = [\"3fff:1:69c::1\", \"3fff:1:69c::2\"] }]\n"
	)
	for name, refusal := range map[string]struct {
		mtu        string
		yaml, toml string
		names      []string
	}{
		"under what IPv6 requires of every link":            {"1279", "", "", []string{"link.mtu", "1279", "1280"}},
		"past what one ESP-in-UDP datagram carries":         {"65471", "", "", []string{"link.mtu", "65471", "65470"}},
		"under what a list of two segments leaves room for": {"1359", twoSegmentsYAML, twoSegmentsTOML, []string{"link.mtu", "1359", "cap.segment steer", "80 bytes"}},
	} {
		t.Run(name, func(t *testing.T) {
			for extension, body := range map[string]string{
				".yaml": strings.Replace(nodeYAML, "  port: 13000\n", "  port: 13000\n  mtu: "+refusal.mtu+"\n", 1) + refusal.yaml,
				".toml": strings.Replace(nodeTOML, "port = 13000\n", "port = 13000\nmtu = "+refusal.mtu+"\n", 1) + refusal.toml,
			} {
				_, err := load(t, extension, body)
				if err == nil {
					t.Fatalf("%s took link.mtu %s", extension, refusal.mtu)
				}
				for _, named := range refusal.names {
					if !strings.Contains(err.Error(), named) {
						t.Errorf("%s refused link.mtu %s with %q, which does not name %s", extension, refusal.mtu, err, named)
					}
				}
			}
		})
	}
}

// An announcement that cannot mean what it looks like. Each of these loads
// into a node announcing something other than what its file says, and the
// mapping spelling is the one an exit actually uses.
func TestAnnouncementsRefuseWhatTheyCannotMean(t *testing.T) {
	for name, entry := range map[string]string{
		// originatedKey masks, so this announces "::/0" and claims the exit.
		"a masked default":        `"2001:db8::1/0"`,
		"a masked default, v4":    `"198.51.100.1/0"`,
		"a masked default source": `{ prefix: "2001:db8::/48", from: "2001:db8::1/0" }`,
		// A source covering every address is kept by nothing: originatedKey
		// drops it and the entry becomes an ordinary announcement.
		"a source covering everything": `{ prefix: "2001:db8::/48", from: "::/0" }`,
		// Neither family has a lookup that could express this, and installing
		// it as an ordinary route would steal traffic from every other source.
		"mismatched families": `{ prefix: "::/0", from: "10.0.0.0/8" }`,
		// BIRD drops the whole Update without an IPv4 SADR channel, and the
		// IPv4 FIB has no source-specific lookup for the reconciler to install
		// into, so this reaches nobody.
		"an IPv4 source-specific announcement": `{ prefix: "0.0.0.0/0", from: "198.51.100.0/24" }`,
		// A key nobody reads is a prefix nobody announces, and the operator
		// has no way to tell from the outside.
		"an unknown field":  `{ prefix: "::/0", form: "2001:db8::/48" }`,
		"no prefix at all":  `{ from: "2001:db8::/48" }`,
		"not a prefix":      `"2001:db8::1"`,
		"a sequence inside": `[2001:db8::/48]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+"cap:\n  route:\n    announce:\n      - "+entry+"\n"); err == nil {
				t.Error("the config loaded, so nothing says this cannot mean what it looks like")
			}
		})
	}
	// The spellings that do mean what they say stay accepted.
	for name, entry := range map[string]string{
		"a real default":                   `"::/0"`,
		"a plain announcement":             `"2001:db8::/48"`,
		"a source-specific default":        `{ prefix: "::/0", from: "2001:db8::/48" }`,
		"an address written as a /128":     `"2001:db8::1/128"`,
		"a v4 address written as a /32":    `"10.66.0.5/32"`,
		"a source shorter than the prefix": `{ prefix: "2001:db8::/48", from: "2001:db8:1::/64" }`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+"cap:\n  route:\n    announce:\n      - "+entry+"\n"); err != nil {
				t.Errorf("a well-formed announcement was refused: %v", err)
			}
		})
	}
}

// An address is assigned to a device and never announced, so the refusal for
// one written with no prefix length must not tell the operator to write a
// default instead: that is the advice for an announcement, and the check above
// it refuses exactly what it would produce.
func TestAssignedAddressRefusalDoesNotAdviseADefault(t *testing.T) {
	_, err := loadYAML(t, nodeYAML+"cap:\n  table:\n    addresses: [\"2001:db8::1/0\"]\n")
	if err == nil {
		t.Fatal("a masked default was accepted as an address")
	}
	if strings.Contains(err.Error(), "announces a default route") {
		t.Errorf("the refusal tells the operator to write a default: %v", err)
	}
	if !strings.Contains(err.Error(), "cap.table addresses") {
		t.Errorf("the refusal reads %q and does not name the field", err)
	}
}

// Both fields of one entry can be wrong, and which one the refusal names has
// to be the same on every load: iterating a map named a random one, so an
// operator fixing what the message pointed at got a different message next
// time, and any test asserting the text would flake.
func TestAnnouncementRefusalNamesTheSameFieldEveryTime(t *testing.T) {
	body := nodeYAML + "cap:\n  route:\n    announce:\n      - { prefix: \"2001:db8::1/0\", from: \"2001:db8::2/0\" }\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var first string
	for attempt := range 40 {
		_, err := Load(path)
		if err == nil {
			t.Fatal("an entry whose prefix and from are both masked defaults was accepted")
		}
		if attempt == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("load %d said %q, where the first said %q", attempt, err, first)
		}
	}
}

// A file assembled by concatenation ends in a separator, and the document
// after it carries nothing. Refusing it refuses a configuration that is whole,
// and every later SIGHUP with it.
func TestConfigurationEndingInASeparatorIsTaken(t *testing.T) {
	for name, tail := range map[string]string{
		"a bare separator":          "---\n",
		"a separator and a comment": "---\n# nothing here\n",
		"an end of document marker": "...\n",
		"trailing blank lines":      "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+tail); err != nil {
				t.Errorf("a configuration ending in %q was refused: %v", tail, err)
			}
		})
	}
	// A second document is not, however many empty ones stand between it and
	// the first. A file half pasted below a stray separator would otherwise
	// start on the first half alone and validate cleanly, so the node comes up
	// with the listener off or the wrong peer set and nothing says so, and
	// reading exactly one document past the first let an empty one hide the
	// half behind it: cat of two configurations, which is the case this
	// refuses, is where that empty document comes from.
	for name, between := range map[string]string{
		"a separator":                      "---\n",
		"an empty document between them":   "---\n---\n",
		"two empty documents between them": "---\n---\n---\n",
		"an end marker and a separator":    "...\n---\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+between+"link:\n  listen: false\n"); err == nil {
				t.Error("a second document was accepted")
			}
		})
	}
}

// A refusal names the block and the field an operator wrote, and the value
// they wrote there. Each of these used to name none of the three: "intervals
// must be between 10ms and 10m55.35s" says nothing about which line to change,
// and "rule priority 40 ... lookup 254" answers an operator who wrote "main"
// with a number and leaves out the family that tells two expanded rules apart.
func TestRefusalsNameTheBlockTheOperatorWrote(t *testing.T) {
	for name, refusal := range map[string]struct {
		body  string
		names []string
	}{
		"an interval past what the protocol can carry": {
			body:  "cap:\n  babel:\n    hello: 11m\n",
			names: []string{"cap.babel hello", "11m0s"},
		},
		"the other interval, which defaults off the first": {
			body:  "cap:\n  babel:\n    update: 11m\n",
			names: []string{"cap.babel update", "11m0s"},
		},
		"a cost that saturates": {
			body:  "cap:\n  babel:\n    cost: { rx: 65000, rtt: { weight: 1024 } }\n",
			names: []string{"cap.babel cost rx", "65000", "1024"},
		},
		"an rtt window written backwards": {
			body:  "cap:\n  babel:\n    cost: { rtt: { min: 2s, max: 1s } }\n",
			names: []string{"cap.babel cost rtt min", "2s", "1s"},
		},
		"a steering selector with host bits": {
			body:  "cap:\n  segment:\n    source: \"3fff:1:69c:8c0::1\"\n    steer: [{ from: \"3fff:a::1/128\", to: \"2001:db8::1/32\", via: [\"3fff:1:69c::1\"] }]\n",
			names: []string{"cap.segment steer to", "2001:db8::1/32"},
		},
		"a local segment written twice": {
			body:  "cap:\n  segment:\n    local:\n      - { sid: \"3fff:1:69c:8c6::1\", behavior: End }\n      - { sid: \"3fff:1:69c:8c6::1\", behavior: \"End.DT46\" }\n",
			names: []string{"cap.segment local", "3fff:1:69c:8c6::1"},
		},
		"a rule at the local table's priority": {
			body:  "cap:\n  table:\n    rules: [{ fwmark: 0x726c, table: main, priority: 0, family: both }]\n",
			names: []string{"cap.table rules", "lookup main", "family ipv4", "0x726c"},
		},
		"two rules the kernel reads as one": {
			body:  "cap:\n  table:\n    rules:\n      - { fwmark: 0x726c, table: main, priority: 40, family: both }\n      - { fwmark: 0x726c, fwmask: 0xffffffff, table: main, priority: 40, family: both }\n",
			names: []string{"cap.table rules", "lookup main", "family ipv4"},
		},
		// The entry's own source or the block's, and the refusal says so:
		// without the check the path check below answers instead, and it
		// describes the segment list rather than the field that is missing.
		"a steering entry with no source anywhere": {
			body:  "cap:\n  segment:\n    steer: [{ from: \"3fff:a::1/128\", via: [\"3fff:1:69c::1\"] }]\n",
			names: []string{"cap.segment steer", "names no source", "3fff:a::1/128"},
		},
		// The word, not the shape: a family the decoder took and expansion
		// then refused answers an operator who wrote "ipv7" by telling them
		// to name a family, which they did.
		"a family that is none of the three": {
			body:  "cap:\n  table:\n    rules: [{ fwmark: 0x726c, table: main, priority: 40, family: ipv7 }]\n",
			names: []string{"ipv7", "ipv4, ipv6 or both"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadYAML(t, nodeYAML+refusal.body)
			if err == nil {
				t.Fatalf("%q was taken", refusal.body)
			}
			for _, named := range refusal.names {
				if !strings.Contains(err.Error(), named) {
					t.Errorf("the refusal reads %q and does not name %s", err, named)
				}
			}
		})
	}
}

// a number that is not whole is refused with its line, where the yaml decoder cut it to a whole one
// 13000.5, 1.3e4 and 13000.0 became 13000 and -0 became 0, and encoding/json refuses all four
// the field is found by its position in a list, behind a pointer and in a block of its own, since the walk takes each differently
// the number is also found through an anchor and its alias, and under a key written as an alias or as !!binary, which the decoder reads through
// a merge key is refused whatever it merges, since the walk does not follow it and toml and json cannot spell it
func TestIntegerFieldRefusesANumberThatIsNotWhole(t *testing.T) {
	const asJSON = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":%s,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"to":["example/gateway"]}}`
	type row struct{ extension, body, field string }
	// refuses wants the file refused with an error reading "line N: " and then text, N being the line field is written on
	refuses := func(t *testing.T, test row, text string) {
		t.Helper()
		_, err := load(t, test.extension, test.body)
		if err == nil {
			t.Fatalf("%s was taken", text)
		}
		line := 1 + strings.Count(test.body[:strings.Index(test.body, test.field)], "\n")
		if want := fmt.Sprintf("line %d: %s", line, text); !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal reads %q, want it to name %q", err, want)
		}
	}
	for _, written := range []string{"13000.5", "1.3e4", "13000.0", "-0"} {
		for name, test := range map[string]row{
			"a port in a yaml file": {".yaml", strings.Replace(nodeYAML, "port: 13000", "port: "+written, 1), "port:"},
			"a port in a json file": {".json", fmt.Sprintf(asJSON, written), `"port"`},
			"a replay window, behind a pointer": {
				".yaml", nodeYAML + "cap:\n  crypto:\n    replay: " + written + "\n", "replay:"},
			"a rule priority, in a list": {
				".yaml", nodeYAML + "cap:\n  table:\n    rules:\n      - to: 10.0.0.0/8\n        table: 200\n        priority: " + written + "\n", "priority:"},
			// the anchor sits on a field that takes any text, and the alias carries the number into one that takes a whole one
			"a port read through an alias": {
				".yaml", strings.NewReplacer("key: key.pem", "key: &n "+written, "port: 13000", "port: *n").Replace(nodeYAML), "&n"},
			// the anchor holds the word port, which is the key the number is written under
			"a port under a key written as an alias": {
				".yaml", strings.NewReplacer("key: key.pem", "key: &k port", "port: 13000", "*k : "+written).Replace(nodeYAML), "*k"},
			// cG9ydA== is the word port in base64, which the decoder reads a !!binary key as
			"a port under a key written as !!binary": {
				".yaml", strings.Replace(nodeYAML, "port: 13000", "!!binary cG9ydA==: "+written, 1), "!!binary"},
		} {
			t.Run(name+" written "+written, func(t *testing.T) { refuses(t, test, written) })
		}
	}
	// the refusal is of the key that brings the number in, and a whole number is refused with it
	for name, test := range map[string]row{
		"a merge key in a block": {
			".yaml", strings.Replace(nodeYAML, "port: 13000", "<<: { port: 13000.5 }", 1), "<<"},
		// the mapping begins on the line of port, so only the key's own line is right
		"a merge key after another key of its mapping": {
			".yaml", strings.Replace(nodeYAML, "port: 13000", "port: 13000\n  <<: { listen: false }", 1), "<<"},
		"a merge key holding a whole number": {
			".yaml", strings.Replace(nodeYAML, "port: 13000", "<<: { port: 13000 }", 1), "<<"},
		"a merge key holding a sequence of mappings": {
			".yaml", strings.Replace(nodeYAML, "port: 13000", "<<: [ { port: 1.3e4 } ]", 1), "<<"},
		"a merge key inside a merged mapping": {
			".yaml", strings.Replace(nodeYAML, "port: 13000", "<<: { <<: { port: 13000.5 } }", 1), "<<"},
		"a merge key in a nested block": {
			".yaml", nodeYAML + "cap:\n  crypto:\n    <<: { replay: 4096.7 }\n", "<<"},
		"a merge key in a list": {
			".yaml", nodeYAML + "cap:\n  table:\n    rules:\n      - <<: { priority: 100.5 }\n        to: 10.0.0.0/8\n        table: 200\n", "<<"},
		"a merge key at the top of the file": {
			".yaml", "<<: { dial: { all: true } }\n" + nodeYAML, "<<"},
	} {
		t.Run(name, func(t *testing.T) { refuses(t, test, "a merge key is refused") })
	}
}

// A key whose spelling differs from the tag in case alone is refused by name,
// under the decoder that would otherwise fold it. BurntSushi matches a field
// case-insensitively when the exact spelling misses and records the key as
// decoded, so Undecoded reports nothing: "ANNOUNCE" loaded as "announce", and
// a document carrying both spellings took whichever one a map walk reached
// last, 176 times out of 200 the typo. The other decoder refuses it, and
// Load's own doc says both run strict so that a typo cannot silently do
// something.
func TestTOMLRefusesAKeyThatDiffersOnlyInCase(t *testing.T) {
	for name, body := range map[string]string{
		"a capability's field":          "[cap.route]\nANNOUNCE = [\"10.66.0.5/32\"]\n",
		"a nested block":                "[cap.crypto.REKEY]\nchild = \"1h\"\n",
		"a field inside a list":         "[cap.table]\nrules = [{ FWMARK = 0x726c, table = \"main\", priority = 40, family = \"both\" }]\n",
		"a field in an array of tables": "[[cap.table.rules]]\nFWMARK = 0x726c\ntable = \"main\"\npriority = 40\nfamily = \"both\"\n",
		// Both spellings in one document, where the folded one used to win or
		// lose depending on the run.
		"one written twice": "[cap.route]\nannounce = [\"10.66.0.5/32\"]\nANNOUNCE = [\"10.66.0.6/32\"]\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := loadTOML(t, nodeTOML+body)
			if err == nil {
				t.Fatalf("toml folded the case of %q", body)
			}
			if !strings.Contains(err.Error(), "unknown field") {
				t.Errorf("the refusal reads %q and does not name the key", err)
			}
		})
	}
	// The same keys spelled right are still taken, so the check refuses the
	// case rather than the key.
	if _, err := loadTOML(t, nodeTOML+"[cap.table]\nrules = [{ fwmark = 0x726c, table = \"main\", priority = 40, family = \"both\" }]\n[cap.crypto.rekey]\nchild = \"1h\"\n"); err != nil {
		t.Errorf("the keys as the tags spell them were refused: %v", err)
	}
}

// A rule keyed on the device a packet arrives on, written under the key the
// configuration reference names, reaches the reconciler as that device. The
// encoder round trip cannot pin the spelling, since it writes and reads by one
// tag.
func TestRuleInputDeviceLoadsUnderItsDocumentedKey(t *testing.T) {
	for extension, body := range map[string]string{
		".toml": nodeTOML + "[cap.table]\nrules = [{ iif = \"eth1\", table = \"main\", priority = 60, family = \"both\" }]\n",
		".yaml": nodeYAML + "cap:\n  table:\n    rules: [{ iif: eth1, table: main, priority: 60, family: both }]\n",
	} {
		cfg, err := load(t, extension, body)
		if err != nil {
			t.Errorf("%s: the rule was refused: %v", extension, err)
			continue
		}
		if rules := cfg.Cap.Table.Rules; len(rules) != 1 || rules[0].IIF != "eth1" {
			t.Errorf("%s: the rules loaded as %v", extension, rules)
		}
	}
}

// A capability is on because its block is there. There is no enabled field to
// forget, which is the failure the old one had: a node that configured the
// reconciler and left it off came up with a working mesh, no rules and no
// message.
func TestCapabilityIsOnBecauseItsBlockIsThere(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cap.Table != nil || cfg.Cap.Segment != nil || cfg.Cap.Crypto != nil {
		t.Fatalf("a node that asked for nothing got %+v", cfg.Cap)
	}
	// And the defaults an absent block stands for are the ones a subsystem
	// documents, rather than a zero that means something else.
	if cfg.Transits() {
		t.Error("a node with no cap.transit relays the routes it learns")
	}
	if cfg.Babel().HelloInterval() != 4*time.Second {
		t.Errorf("a node with no cap.babel runs a %s hello interval", cfg.Babel().HelloInterval())
	}
	if cfg.Crypto().ReplayWindow() != esp.DefaultReplayWindow {
		t.Errorf("a node with no cap.crypto runs a %d packet replay window", cfg.Crypto().ReplayWindow())
	}
	// An empty block is still the capability turned on.
	cfg, err = loadYAML(t, nodeYAML+"cap:\n  table: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cap.Table == nil {
		t.Error("an empty cap.table left the reconciler off")
	}
}

// Every spelling of "this block is written" says the same thing, under both
// decoders and for every capability there is. The capabilities are read off
// Caps rather than listed here, so one added later is covered without anybody
// remembering to, and the spellings cover the empty block each decoder allows:
// a bare key, an empty mapping and an explicit null under yaml, a table header
// and an inline table under toml. The spelling this was found through is the
// bare key, which decoded to the same nil as a capability nobody asked for, so
// uncommenting "table:" and leaving its fields commented gave a mesh with no
// routes, no rules and no message.
func TestBlockPresenceAgreesAcrossDecoders(t *testing.T) {
	caps := reflect.TypeFor[Caps]()
	for i := range caps.NumField() {
		key := yamlKey(caps.Field(i))
		// Either the block is on, or the capability refused the empty block by
		// name. Never off, which is the outcome an operator cannot see.
		outcome := func(t *testing.T, extension, body string) string {
			t.Helper()
			cfg, err := load(t, extension, body)
			switch {
			case err != nil && !strings.Contains(err.Error(), "cap."+key):
				t.Errorf("cap.%s was refused without naming itself: %v", key, err)
				return "refused: " + err.Error()
			case err != nil:
				return "refused: " + err.Error()
			case reflect.ValueOf(cfg.Cap).Field(i).IsNil():
				return "off, with nothing said"
			}
			return "on"
		}
		t.Run(key, func(t *testing.T) {
			spellings := map[string]string{
				"yaml bare key":       ".yaml\x00" + nodeYAML + "cap:\n  " + key + ":\n",
				"yaml empty mapping":  ".yaml\x00" + nodeYAML + "cap:\n  " + key + ": {}\n",
				"yaml explicit null":  ".yaml\x00" + nodeYAML + "cap:\n  " + key + ": null\n",
				"toml table header":   ".toml\x00" + nodeTOML + "[cap." + key + "]\n",
				"toml inline mapping": ".toml\x00" + nodeTOML + "[cap]\n" + key + " = {}\n",
			}
			want, wanted := "", ""
			for _, how := range slices.Sorted(maps.Keys(spellings)) {
				extension, body, _ := strings.Cut(spellings[how], "\x00")
				got := outcome(t, extension, body)
				if got == "off, with nothing said" {
					t.Errorf("cap.%s written as a %s is %s", key, how, got)
				}
				if wanted == "" {
					want, wanted = got, how
					continue
				}
				if got != want {
					t.Errorf("cap.%s is %q written as a %s and %q written as a %s", key, got, how, want, wanted)
				}
			}
		})
	}
}

// Every format a configuration is written in is text, and a string that is not
// UTF-8 survives none of them alike: toml refuses it, json rewrites it and
// yaml carries it only as binary. A configuration built with one, in a name, a
// path or a device, is refused by the path a file writes it under, rather than
// taken and rendered into a file that does not load or loads as another node.
func TestValidateRefusesAStringThatIsNotText(t *testing.T) {
	for path, change := range map[string]func(*Config){
		"auth.key":              func(c *Config) { c.Auth.Key = "key\xfe.pem" },
		"link.tun":              func(c *Config) { c.Link.TUN = "ranet\xff" },
		"link.endpoints.serial": func(c *Config) { c.Link.Endpoints[0].Serial = "\xc3" },
		"cap.table.rules.iif":   func(c *Config) { c.Cap.Table.Rules[0].IIF = "ranet0\xff" },
	} {
		t.Run(path, func(t *testing.T) {
			cfg := fullConfig()
			change(&cfg)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), path) {
				t.Errorf("refused with %v, want it refused by the path %s", err, path)
			}
		})
	}
}

// The link cost surface exists so a node can look as expensive as the speaker
// it replaces. Nothing else reads these four fields, so without this they
// could all be dropped with every other check still green, and a node
// configured to match its peers would silently run on defaults.
func TestBabelCostFieldsReachTheSpeaker(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML+`cap:
  babel:
    hello: 3s
    update: 9s
    quality: none
    cost:
      rx: 42
      rtt: { weight: 4242, min: 7ms, max: 77ms }
`)
	if err != nil {
		t.Fatal(err)
	}
	speaker := cfg.Babel()
	cost := speaker.CostEffective()
	// the estimator rides in the cost the speaker runs, and a file writing none ran etx without it
	if cost.Quality != babel.LinkQualityNone {
		t.Errorf("the quality reached the speaker as %s, want none", cost.Quality)
	}
	if cost.RxCost != 42 || cost.RTT.Weight != 4242 {
		t.Errorf("the costs reached the speaker as %d and %d, want 42 and 4242", cost.RxCost, cost.RTT.Weight)
	}
	if cost.RTT.Min.Duration() != 7*time.Millisecond || cost.RTT.Max.Duration() != 77*time.Millisecond {
		t.Errorf("the rtt window reached the speaker as %s..%s, want 7ms..77ms", cost.RTT.Min, cost.RTT.Max)
	}
	if speaker.HelloInterval() != 3*time.Second || speaker.UpdateInterval() != 9*time.Second {
		t.Errorf("the intervals reached the speaker as %s/%s, want 3s/9s",
			speaker.HelloInterval(), speaker.UpdateInterval())
	}
	// Omitted, the speaker's own defaults stand, matching BIRD.
	if bare := (babel.Config{}).CostEffective(); bare != babel.DefaultCostParams() {
		t.Errorf("an empty block changed the defaults to %+v", bare)
	}
}

// One cost line written leaves the other three at the speaker's default, the
// promise internal/babel's doc comment makes and the one examples/config.toml
// invites by documenting each on its own line. Writing "rx = 96", the default
// spelled out, used to replace the block whole and take the round-trip term
// down to zero with it, so a 10 ms link and a 1 s link cost the same and the
// round-trip ranking a fleet run had measured was gone.
func TestOneCostLineLeavesTheRestAtTheDefault(t *testing.T) {
	defaults := babel.DefaultCostParams()
	for _, written := range []struct {
		yaml, toml string
		want       babel.CostParams
	}{
		{"rx: 96", "rx = 96", defaults},
		{"rtt: { weight: 1024 }", "rtt = { weight = 1024 }", defaults},
		{"rtt: { min: 10ms }", "rtt = { min = \"10ms\" }", defaults},
		{"rtt: { max: 1024ms }", "rtt = { max = \"1024ms\" }", defaults},
		// A weight written out as zero is taken as written, which is the half
		// a plain value cannot spell: it turns the round-trip term off rather
		// than asking for the default.
		{"rtt: { weight: 0 }", "rtt = { weight = 0 }",
			babel.CostParams{RxCost: defaults.RxCost, RTT: babel.RTTCost{Min: defaults.RTT.Min, Max: defaults.RTT.Max}}},
	} {
		t.Run(written.toml, func(t *testing.T) {
			fromYAML, err := loadYAML(t, nodeYAML+"cap:\n  babel:\n    cost:\n      "+written.yaml+"\n")
			if err != nil {
				t.Fatalf("yaml: %v", err)
			}
			fromTOML, err := loadTOML(t, nodeTOML+"[cap.babel.cost]\n"+written.toml+"\n")
			if err != nil {
				t.Fatalf("toml: %v", err)
			}
			for name, cfg := range map[string]*Config{"yaml": fromYAML, "toml": fromTOML} {
				if got := cfg.Babel().CostEffective(); got != written.want {
					t.Errorf("%s: %q gives %+v, want %+v", name, written.yaml, got, written.want)
				}
			}
		})
	}
}

// A timer written as a bare zero disables it, which is the one spelling an
// operator uses for that and the one every other duration in the file takes.
func TestZeroRekeyIntervalDisablesIt(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML+"cap:\n  crypto:\n    rekey: { child: 0, ike: 0 }\n")
	if err != nil {
		t.Fatalf("a disabled rekey was refused: %v", err)
	}
	if cfg.Crypto().ChildInterval() != 0 || cfg.Crypto().IKEInterval() != 0 {
		t.Errorf("the rekeys are %s and %s, want both off",
			cfg.Crypto().ChildInterval(), cfg.Crypto().IKEInterval())
	}
	// And a disabled interval has no schedule for the margin to fit inside,
	// so a margin longer than the interval is no longer a contradiction.
	if _, err := loadYAML(t, nodeYAML+"cap:\n  crypto:\n    rekey: { child: 0, margin: 1h, jitter: 1h }\n"); err != nil {
		t.Errorf("a margin beside a disabled rekey was refused: %v", err)
	}
}

// A key written with nothing under it turns a block on and leaves a scalar
// alone, and fillBlocks is where the two rules meet: it allocates the first
// and must not touch the second. Every pointer-to-scalar field in this schema
// spells an omitted field as nil and reads a written zero as written, so
// filling one in turns a bare "replay:" into anti-replay disabled, the
// opposite of what leaving the key out means, and a bare "enable:" under
// cap.transit into transit off where the block is refused for stating nothing.
// Neither has a second spelling to agree with either, because toml cannot
// write a key with no value at all.
//
// The fields are found by reflection rather than listed, so one added later is
// covered without anybody remembering to, and the two whose zero is a safety
// property are asked again below in the terms their subsystem reads them in.
func TestBareScalarKeyIsNotAWrittenZero(t *testing.T) {
	for _, path := range pointerScalars(reflect.TypeFor[Config](), "") {
		t.Run(path, func(t *testing.T) {
			var body strings.Builder
			body.WriteString(nodeYAML)
			for depth, key := range strings.Split(path, ".") {
				body.WriteString(strings.Repeat("  ", depth) + key + ":\n")
			}
			cfg, err := loadYAML(t, body.String())
			if err != nil {
				// Refused is an answer an operator can see. Silently taking
				// the zero is the one that is not.
				return
			}
			field := reflect.ValueOf(cfg).Elem()
			for key := range strings.SplitSeq(path, ".") {
				if field.Kind() == reflect.Pointer {
					field = field.Elem()
				}
				field = fieldByKey(field, key)
			}
			if !field.IsNil() {
				t.Errorf("%s written with nothing under it reads as %v, want the default it stands for",
					path, field.Elem())
			}
		})
	}

	// The same two facts as their subsystems ask them, because a nil pointer
	// is only interesting for what it means downstream.
	cfg, err := loadYAML(t, nodeYAML+"cap:\n  crypto:\n    replay:\n")
	if err != nil {
		t.Fatalf("a bare replay key was refused: %v", err)
	}
	if got := cfg.Crypto().ReplayWindow(); got != esp.DefaultReplayWindow {
		t.Errorf("a bare replay key runs a %d packet window, want %d: zero is anti-replay off",
			got, esp.DefaultReplayWindow)
	}
	if _, err := loadYAML(t, nodeYAML+"cap:\n  transit:\n    enable:\n"); err == nil || !strings.Contains(err.Error(), "cap.transit states no enable") {
		t.Errorf("a bare enable key under cap.transit was answered with %v, want the block refused for stating nothing", err)
	}
}

// pointerScalars names every field under ty that spells absence as a nil
// pointer to something other than a block, in the yaml path a file writes. A
// field reached through a list is skipped: an empty list has no element for a
// key to sit under.
func pointerScalars(ty reflect.Type, prefix string) []string {
	if ty.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for field := range ty.Fields() {
		if !field.IsExported() {
			continue
		}
		path := strings.TrimPrefix(prefix+"."+yamlKey(field), ".")
		under := field.Type
		if under.Kind() == reflect.Pointer {
			if under.Elem().Kind() != reflect.Struct {
				out = append(out, path)
				continue
			}
			under = under.Elem()
		}
		out = append(out, pointerScalars(under, path)...)
	}
	return out
}

// fullConfig writes every capability block and sets every field of every one of them to a value of its own
// a field that arrives holding its neighbor's value then reads back wrong rather than equal
// the values satisfy every check Load makes
// the round trip below goes through the loader rather than through a decoder alone
func fullConfig() Config {
	transits := false
	rxcost, weight := uint16(96), uint16(1024)
	rttMin, rttMax := schema.Duration(10*time.Millisecond), schema.Duration(1024*time.Millisecond)
	replay := uint32(2048)
	child, rekeyIKE := schema.Duration(90*time.Minute), schema.Duration(150*time.Minute)
	margin, jitter := schema.Duration(3*time.Minute), schema.Duration(30*time.Second)
	retryFirst, retryMax := schema.Duration(7*time.Second), schema.Duration(11*time.Minute)
	return Config{
		Node: identity.MustParse("example/laptop"),
		Auth: Auth{Key: "key.pem", Trust: "trust.json", Aliases: ike.Aliases{
			Remote: ike.RemoteAliases{
				IP: map[string]identity.Identity{
					"192.0.2.10":   identity.MustParse("example/gateway:1"),
					"2001:db8::10": identity.MustParse("example/gateway:2"),
				},
				FQDN:  map[string]identity.Identity{"gw.example.net": identity.MustParse("example/gateway:1")},
				Email: map[string]identity.Identity{"ops@example.net": identity.MustParse("example/relay:1")},
				KeyID: map[string]identity.Identity{"0a1b2c3d": identity.MustParse("other/relay:1")},
			},
			// an entry for each field one writes, under a node and under an endpoint
			Local: map[string]ike.LocalAlias{
				"example/gateway":   {FQDN: "laptop.example.net"},
				"example/gateway:2": {IP: "2001:db8::5"},
				"example/relay":     {Email: "laptop@example.net"},
				"other/relay":       {KeyID: "6c6170746f70"},
			},
		}},
		Link: Link{
			Port:      13000,
			Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}},
			Listen:    true,
			TUN:       "ranet0",
			MTU:       8918,
			Underlay:  transport.Underlay{Bind: true},
		},
		Dial: Dial{All: true, To: []identity.Identity{identity.MustParse("example/gateway:1")}},
		Cap: Caps{
			Route: &babel.Routes{
				Announce: []schema.Announce{
					{Prefix: schema.MustPrefix("10.66.0.5/32")},
					{Prefix: schema.MustPrefix("::/0"), From: schema.MustPrefix("2001:db8:1::/48")},
				},
			},
			Transit: &babel.Transit{Enable: &transits},
			Babel: &babel.Config{
				Hello:   schema.Duration(4 * time.Second),
				Update:  schema.Duration(16 * time.Second),
				Quality: babel.LinkQualityNone,
				Cost: babel.CostOptions{Rx: &rxcost, RTT: babel.RTTOptions{
					Weight: &weight,
					Min:    &rttMin,
					Max:    &rttMax,
				}, Extra: babel.ExtraCost{
					Foreign: 1024,
					Org:     map[string]uint16{"gravity": 2048, "example": 5},
					Node:    map[string]uint16{"example/gateway": 300},
				}},
			},
			Table: &kernel.Table{
				ID:              200,
				Proto:           155,
				Metric:          64,
				PrefSrc4:        schema.MustAddr("10.66.0.5"),
				Addresses:       []schema.Prefix{schema.MustPrefix("10.66.0.5/32")},
				AssignAnnounced: true,
				Reconcile:       schema.Duration(30 * time.Second),
				CaptureGrace:    schema.Duration(10 * time.Second),
				// a rule naming an address is refused for also naming the family the address says
				// so no one rule carries every field
				Rules: []kernel.Rule{{
					To:       schema.MustPrefix("3fff:1:69c::/48"),
					From:     schema.MustPrefix("3fff:a::/32"),
					FWMark:   0x726c,
					FWMask:   0xffff,
					IIF:      "eth1",
					Table:    schema.TableMain,
					Priority: 40,
				}, {
					FWMark:   0x726c,
					FWMask:   0xffff,
					Table:    schema.TableMain,
					Priority: 41,
					Family:   kernel.FamilyIPv6,
				}, {
					// family both and a table by number, spellings the two above leave out
					FWMark:   0x726c,
					Table:    100,
					Priority: 42,
					Family:   kernel.FamilyBoth,
				}},
			},
			Segment: &srv6.Segments{
				Source: schema.MustAddr("3fff:1:69c:8c0::1"),
				Local: []srv6.Segment{
					{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEndDT46},
					{SID: schema.MustAddr("3fff:1:69c:8c6::2"), Behavior: srv6.BehaviorEnd},
					{
						SID:      schema.MustAddr("3fff:1:69c:8c6::3"),
						Behavior: srv6.BehaviorEndDT46,
						Deliver:  srv6.DeliverEgress,
						Allow:    []schema.Prefix{schema.MustPrefix("3fff:a::/32"), schema.MustPrefix("198.18.104.0/24")},
					},
				},
				Steer: []srv6.Steer{{
					From:   schema.MustPrefix("3fff:a::198:18:104:117/128"),
					To:     schema.MustPrefix("3fff:1:69c:8c9::/64"),
					Source: schema.MustAddr("3fff:1:69c:8c0::2"),
					Via: []schema.Addr{
						schema.MustAddr("3fff:1:69c:98d6::1"),
						schema.MustAddr("3fff:1:69c:98d6::2"),
					},
				}, {
					// a source selector and next hops alone
					// whose unset destination and source json has to leave out rather than refuse to spell
					From: schema.MustPrefix("3fff:a::198:18:104:118/128"),
					Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
				}},
			},
			Crypto: &ike.Crypto{
				Replay: &replay,
				Rekey: ike.Rekey{
					Child:  &child,
					IKE:    &rekeyIKE,
					Margin: &margin,
					Jitter: &jitter,
					Retry:  ike.Retry{First: &retryFirst, Max: &retryMax},
				},
				// each list in an order of its own, the two cipher lists apart
				// so one read into another's place reads back wrong
				IKE: ike.IKESuites{
					Cipher: []string{"chacha20poly1305", "aes128gcm"},
					PRF:    []string{"sha256", "sha384"},
					Kex:    []string{"p384", "x25519"},
				},
				ESP: ike.ESPSuites{Cipher: []string{"aes128gcm", "chacha20poly1305", "aes256gcm"}},
			},
			Egress: &egress.Egress{
				Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0"), schema.MustPrefix("::/0")},
				// one of each spelling a source takes
				// so the address form and the word both cross every encoder in this one case
				Source4: egress.Source{Addr: netip.MustParseAddr("198.51.100.7")},
				Source6: egress.Source{Auto: true},
				Return:  true,
				Sweep:   schema.Duration(45 * time.Second),
			},
			// covering the egress segment's allow list, which the loader asks of it
			Border: &egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("3fff::/20"), schema.MustPrefix("198.18.0.0/15")}},
		},
	}
}

// A file an operator wrote reaches the daemon whole, whichever of the three
// encoders carried it. Each decides an absent field on its own terms, so each
// is asked the same question separately rather than one standing for the
// others: a field dropped on the way out is a setting the node never applies
// and nothing reports.
//
// The case is checked against the schema before it is rendered, so a
// capability that grows a field fails here until fullConfig writes one, rather
// than passing a round trip that never carried it.
func TestEveryWrittenFieldSurvivesEachEncoder(t *testing.T) {
	want := fullConfig()
	if missing := unwritten(reflect.ValueOf(want), ""); len(missing) > 0 {
		t.Fatalf("fullConfig leaves %d field(s) at zero, so no encoder below is asked to carry them: %s",
			len(missing), strings.Join(missing, ", "))
	}
	sameAfterEachEncoder(t, want)
}

// << names an FQDN alias and a cost.extra organization in every file, so the yaml rendering has to quote it
func TestMergeKeySpelledMapKeysSurviveEachEncoder(t *testing.T) {
	want := fullConfig()
	want.Auth.Aliases.Remote.FQDN["<<"] = identity.MustParse("example/gateway:1")
	want.Cap.Babel.Cost.Extra.Org["<<"] = 7
	sameAfterEachEncoder(t, want)
}

// difference names the first field at which got parts from want, in the path
// a file writes it under, so a failure reads as one setting rather than as two
// renderings that may share the fault being looked for.
func difference(want, got reflect.Value, path string) string {
	switch {
	case want.Kind() == reflect.Pointer && !want.IsNil() && !got.IsNil():
		return difference(want.Elem(), got.Elem(), path)
	case want.Kind() == reflect.Struct && !spellsItself(want.Type()):
		for i := range want.NumField() {
			field := want.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			if !reflect.DeepEqual(want.Field(i).Interface(), got.Field(i).Interface()) {
				return difference(want.Field(i), got.Field(i), strings.TrimPrefix(path+"."+yamlKey(field), "."))
			}
		}
	case want.Kind() == reflect.Slice && want.Len() == got.Len():
		for i := range want.Len() {
			if !reflect.DeepEqual(want.Index(i).Interface(), got.Index(i).Interface()) {
				return difference(want.Index(i), got.Index(i), fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	gotShown, wantShown := shown(got, "%v"), shown(want, "%v")
	if gotShown == wantShown {
		gotShown, wantShown = shown(got, "%#v"), shown(want, "%#v")
	}
	return fmt.Sprintf("%s is %s, want %s", path, gotShown, wantShown)
}

// shown spells one side of a difference, through the pointer where there is
// one, since an address says nothing about what it points at. verb is %v, or
// %#v where the two sides would print alike under it.
func shown(value reflect.Value, verb string) string {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return "absent"
		}
		value = value.Elem()
	}
	return fmt.Sprintf(verb, value.Interface())
}

// sameAfterEachEncoder renders drawn under each file encoder, loads each
// rendering the way the daemon loads its file and fails at the first one that
// reads back anything but drawn, naming the setting it changed. The json
// rendering is read by the control plane's own decoder as well, since the file
// and the wire form are one schema.
func sameAfterEachEncoder(tb testing.TB, drawn Config) {
	tb.Helper()
	for _, encoder := range encoders {
		body, err := encoder.render(&drawn)
		if err != nil {
			tb.Fatalf("render %s: %v", encoder.extension, err)
		}
		got, err := load(tb, encoder.extension, string(body))
		if err != nil {
			tb.Fatalf("%s refused the configuration it rendered:\n%s\n%v", encoder.extension, body, err)
		}
		if !reflect.DeepEqual(*got, drawn) {
			tb.Fatalf("%s read back %s, from\n%s", encoder.extension, difference(reflect.ValueOf(drawn), reflect.ValueOf(*got), ""), body)
		}
		if encoder.extension != ".json" {
			continue
		}
		var overWire Config
		if err := json.Unmarshal(body, &overWire); err != nil {
			tb.Fatalf("the control plane refused\n%s\n%v", body, err)
		}
		if !reflect.DeepEqual(overWire, drawn) {
			tb.Fatalf("the control plane read back %s, from\n%s", difference(reflect.ValueOf(drawn), reflect.ValueOf(overWire), ""), body)
		}
	}
}

// unwritten names every field left at its zero value, in the yaml path a file
// writes it under. The walk stops at a type spelling itself as one scalar,
// since what stands behind that spelling is the type's own business, and a
// net/netip value exports no field to look at in any case.
//
// A pointer to a scalar counts as written the moment it is not nil, because
// that is the whole reason those fields are pointers: an explicit zero of
// cap.crypto replay asks for something other than the default an absent field
// takes, and one of cap.transit enable is valid where an absent field is
// refused.
func unwritten(value reflect.Value, path string) []string {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return []string{path}
		}
		if value.Type().Elem().Kind() != reflect.Struct {
			return nil
		}
		return unwritten(value.Elem(), path)
	}
	if value.Kind() == reflect.Slice && value.Len() == 0 {
		return []string{path}
	}
	if value.IsZero() {
		return []string{path}
	}
	if spellsItself(value.Type()) {
		return nil
	}
	var out []string
	switch value.Kind() {
	case reflect.Struct:
		structure := value.Type()
		for i := range structure.NumField() {
			field := structure.Field(i)
			if !field.IsExported() {
				continue
			}
			out = append(out, unwritten(value.Field(i), strings.TrimPrefix(path+"."+yamlKey(field), "."))...)
		}
	case reflect.Slice:
		// A list carries a set of entries rather than one entry holding one of
		// every field, so a field any entry writes is a field this case
		// covers. cap.table rules is why: a rule naming an address may not
		// also name a family, and demanding both of one entry would demand a
		// rule the loader refuses.
		missing := unwritten(value.Index(0), path)
		for i := 1; i < value.Len() && len(missing) > 0; i++ {
			next := unwritten(value.Index(i), path)
			missing = slices.DeleteFunc(missing, func(p string) bool { return !slices.Contains(next, p) })
		}
		out = append(out, missing...)
	}
	return out
}

// oneEndpoint is a link writing the one endpoint the schema requires and
// nothing else, which the two checks below start from: an endpoint list is the
// only required field here that is a list, and yaml writes a nil one as an
// empty sequence and reads that back as an empty list, so a case leaving it out
// reports a difference no block it was probing had caused.
func oneEndpoint() Link { return Link{Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}}} }

// laptop is the node a probe of another block names, since the zero identity has no text to render
var laptop = identity.MustParse("example/laptop")

// spellsItself reports a type writing itself as one value rather than as the
// fields behind it, by either of the two marshalers this tree's encoders
// consult.
func spellsItself(ty reflect.Type) bool {
	if ty.Kind() != reflect.Pointer {
		ty = reflect.PointerTo(ty)
	}
	return ty.Implements(reflect.TypeFor[yaml.Marshaler]()) ||
		ty.Implements(reflect.TypeFor[encoding.TextMarshaler]())
}

// encoders is each way a configuration is written, named by its extension
// parse reads a block back at its own type, for the checks that stop short of the loader
var encoders = []struct {
	extension string
	render    func(any) ([]byte, error)
	parse     func([]byte, any) error
}{
	{".yaml", marshalYAML, yaml.Unmarshal},
	{".toml", toml.Marshal, toml.Unmarshal},
	{".json", json.Marshal, json.Unmarshal},
}

// marshalYAML writes what yaml.Marshal writes with every << quoted, since the
// decoder takes a plain, untagged << key for a merge key
func marshalYAML(value any) ([]byte, error) {
	var document yaml.Node
	if err := document.Encode(value); err != nil {
		return nil, err
	}
	quoteMergeKeys(&document)
	return yaml.Marshal(&document)
}

func quoteMergeKeys(node *yaml.Node) {
	if node.Value == "<<" {
		node.Tag, node.Style = "!!str", yaml.DoubleQuotedStyle
	}
	for _, child := range node.Content {
		quoteMergeKeys(child)
	}
}

// a block holding one written field and nothing else still reaches the daemon
// yaml.v3 decides omitempty for a struct by asking for IsZero and otherwise walking the exported fields
// so a block whose one written field the walk cannot see is dropped with the operator's value in it
// and a full configuration hides that
// each case is one nested block, rendered and read back at its own type so no validation stands between the two
func TestOneWrittenFieldKeepsItsBlock(t *testing.T) {
	rx := uint16(96)
	rttMin := schema.Duration(10 * time.Millisecond)
	replay := uint32(2048)
	child, retryFirst := schema.Duration(90*time.Minute), schema.Duration(7*time.Second)
	for name, want := range map[string]any{
		"cap.crypto rekey":       ike.Crypto{Rekey: ike.Rekey{Child: &child}},
		"cap.crypto rekey retry": ike.Rekey{Retry: ike.Retry{First: &retryFirst}},
		"cap.crypto ike":         ike.Crypto{IKE: ike.IKESuites{Kex: []string{"p256"}}},
		"cap.crypto esp":         ike.Crypto{ESP: ike.ESPSuites{Cipher: []string{"aes128gcm"}}},
		"cap.babel cost":         babel.Config{Cost: babel.CostOptions{Rx: &rx}},
		"cap.babel cost rtt":     babel.CostOptions{RTT: babel.RTTOptions{Min: &rttMin}},
		"dial":                   Config{Node: laptop, Link: oneEndpoint(), Dial: Dial{All: true}},
		"cap":                    Config{Node: laptop, Link: oneEndpoint(), Cap: Caps{Crypto: &ike.Crypto{Replay: &replay}}},
		"link underlay": Config{Node: laptop, Link: Link{
			Endpoints: oneEndpoint().Endpoints,
			Underlay:  transport.Underlay{Bind: true},
		}},
		"cap.route announce from": babel.Routes{Announce: []schema.Announce{
			{Prefix: schema.MustPrefix("::/0"), From: schema.MustPrefix("2001:db8:1::/48")},
		}},
		"cap.segment source": srv6.Segments{Source: schema.MustAddr("3fff:1:69c:8c0::1")},
		"cap.segment steer": srv6.Segments{Steer: []srv6.Steer{{
			From:   schema.MustPrefix("3fff:a::198:18:104:117/128"),
			To:     schema.MustPrefix("3fff:1:69c:8c9::/64"),
			Source: schema.MustAddr("3fff:1:69c:8c0::2"),
			Via:    []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
		}}},
		"cap.egress source": egress.Egress{
			Source4: egress.Source{Addr: netip.MustParseAddr("198.51.100.7")},
			Source6: egress.Source{Auto: true},
		},
		"cap.table prefsrc4": kernel.Table{PrefSrc4: schema.MustAddr("10.66.0.5")},
		"cap.table rule selectors": kernel.Table{Rules: []kernel.Rule{{
			To:       schema.MustPrefix("3fff:1:69c::/48"),
			From:     schema.MustPrefix("3fff:a::/32"),
			Table:    schema.TableMain,
			Priority: 40,
		}}},
		"auth aliases": Auth{Aliases: ike.Aliases{Local: map[string]ike.LocalAlias{"example/gateway": {Email: "laptop@example.net"}}}},
		"auth aliases remote": ike.Aliases{Remote: ike.RemoteAliases{
			KeyID: map[string]identity.Identity{"0a1b2c3d": identity.MustParse("example/gateway:1")},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, encoder := range encoders {
				body, err := encoder.render(want)
				if err != nil {
					t.Fatalf("render as %s: %v", encoder.extension, err)
				}
				got := reflect.New(reflect.TypeOf(want))
				if err := encoder.parse(body, got.Interface()); err != nil {
					t.Fatalf("parse the %s\n%s\n%v", encoder.extension, body, err)
				}
				if !reflect.DeepEqual(got.Elem().Interface(), want) {
					t.Errorf("%s dropped it: wrote\n%s\nand read back %+v", encoder.extension, body, got.Elem().Interface())
				}
			}
		})
	}
}

// a block nobody wrote leaves no key behind and reads back as the zero value the capability documents
// writing a block turns that capability on
// so a block rendered as an empty mapping writes down a decision the file never made
// and a block dropped on the way out that does not read back zero loses the defaults it stood for
// yaml decides this by walking a struct's exported fields and json by asking for omitzero
// so each is asked separately
// the toml encoder writes the empty table
// that costs nothing while it reads back zero
// so it is asked for the round trip alone
func TestUnwrittenBlockLeavesNoKey(t *testing.T) {
	for name, probe := range map[string]struct {
		value  any
		absent []string
	}{
		"cap.crypto": {ike.Crypto{}, []string{"rekey", "retry", "ike", "esp"}},
		"cap.babel":  {babel.Config{}, []string{"cost", "rtt"}},
		"cap.table":  {kernel.Table{}, []string{"rules"}},
		// the blocks inside rekey and cost are asked on their own
		// because cap.crypto and cap.babel drop those two whole
		"cap.crypto rekey": {ike.Rekey{}, []string{"retry"}},
		"cap.babel cost":   {babel.CostOptions{}, []string{"rtt"}},
		"link":             {oneEndpoint(), []string{"underlay"}},
		"config":           {Config{Node: laptop, Link: oneEndpoint()}, []string{"dial", "cap", "underlay", "aliases"}},
		// the tables inside auth.aliases are asked on their own as well, since auth drops the block whole
		"auth":                {Auth{Key: "key.pem", Trust: "trust.json"}, []string{"aliases"}},
		"auth aliases":        {ike.Aliases{}, []string{"remote", "local"}},
		"auth aliases remote": {ike.RemoteAliases{}, []string{"ip", "fqdn", "email", "keyid"}},
	} {
		t.Run(name, func(t *testing.T) {
			for _, encoder := range encoders {
				body, err := encoder.render(probe.value)
				if err != nil {
					t.Fatalf("render as %s: %v", encoder.extension, err)
				}
				if encoder.extension != ".toml" {
					for _, key := range probe.absent {
						if strings.Contains(string(body), key) {
							t.Errorf("%s writes %q for a block nobody wrote:\n%s", encoder.extension, key, body)
						}
					}
				}
				got := reflect.New(reflect.TypeOf(probe.value))
				if err := encoder.parse(body, got.Interface()); err != nil {
					t.Fatalf("parse the %s\n%s\n%v", encoder.extension, body, err)
				}
				if !reflect.DeepEqual(got.Elem().Interface(), probe.value) {
					t.Errorf("%s read %s back as %+v rather than as the zero it was written from", encoder.extension, body, got.Elem().Interface())
				}
			}
		})
	}
}
