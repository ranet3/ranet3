// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/ike"
)

// aliasesYAML is nodeYAML with body written under auth.aliases, inside the auth block it already writes
func aliasesYAML(body string) string {
	return strings.Replace(nodeYAML, "  trust: trust.json\n", "  trust: trust.json\n  aliases:\n"+body, 1)
}

// auth.aliases is one shape under each decoder, every table of remote and an entry of local with it
func TestAliasesReadAlikeUnderEachDecoder(t *testing.T) {
	gateway := identity.MustParse("acme/gw:1")
	want := ike.Aliases{
		Remote: ike.RemoteAliases{
			IP:    map[string]identity.Identity{"192.0.2.10": gateway, "2001:db8::10": gateway},
			FQDN:  map[string]identity.Identity{"gw.acme.example": gateway},
			Email: map[string]identity.Identity{"ops@acme.example": gateway},
			KeyID: map[string]identity.Identity{"0a1b2c3d": gateway},
		},
		Local: map[string]ike.LocalAlias{"acme/gw": {FQDN: "laptop.example.net"}},
	}
	for name, file := range map[string]struct{ extension, body string }{
		"toml": {".toml", nodeTOML + `
[auth.aliases.remote.ip]
"192.0.2.10" = "acme/gw:1"
"2001:db8::10" = "acme/gw:1"

[auth.aliases.remote.fqdn]
"gw.acme.example" = "acme/gw:1"

[auth.aliases.remote.email]
"ops@acme.example" = "acme/gw:1"

[auth.aliases.remote.keyid]
"0a1b2c3d" = "acme/gw:1"

[auth.aliases.local]
"acme/gw" = { fqdn = "laptop.example.net" }
`},
		"yaml": {".yaml", aliasesYAML("    remote:\n" +
			"      ip: {192.0.2.10: acme/gw:1, \"2001:db8::10\": acme/gw:1}\n" +
			"      fqdn: {gw.acme.example: acme/gw:1}\n" +
			"      email: {ops@acme.example: acme/gw:1}\n" +
			"      keyid: {\"0a1b2c3d\": acme/gw:1}\n" +
			"    local: {acme/gw: {fqdn: laptop.example.net}}\n")},
		"json": {".json", `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json","aliases":{"remote":{` +
			`"ip":{"192.0.2.10":"acme/gw:1","2001:db8::10":"acme/gw:1"},"fqdn":{"gw.acme.example":"acme/gw:1"},` +
			`"email":{"ops@acme.example":"acme/gw:1"},"keyid":{"0a1b2c3d":"acme/gw:1"}},"local":{"acme/gw":{"fqdn":"laptop.example.net"}}}},` +
			`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, file.extension, file.body)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.Auth.Aliases, want) {
				t.Errorf("auth.aliases reads as %+v, want %+v", cfg.Auth.Aliases, want)
			}
		})
	}
}

// a key or a value no handshake could use, a value of another kind and a spelling one decoder would read apart from the others are refused, naming what was written
func TestAliasesRefusals(t *testing.T) {
	remote := func(body string) string { return aliasesYAML("    remote:\n" + body) }
	for name, file := range map[string]struct{ extension, body, names string }{
		"a remote entry naming a node": {".yaml", remote("      fqdn: {gw.acme.example: acme/gw}\n"),
			`ike: auth.aliases.remote.fqdn "gw.acme.example" names the node acme/gw`},
		"a remote entry naming nobody": {".yaml", remote("      fqdn: {gw.acme.example: gw}\n"), `"gw" is not organization/name`},
		"an address of no family": {".yaml", remote("      ip: {192.0.2: acme/gw:1}\n"),
			`ike: auth.aliases.remote.ip "192.0.2" is not an address`},
		"octets not in hex": {".yaml", remote("      keyid: {0a1: acme/gw:1}\n"),
			`ike: auth.aliases.remote.keyid "0a1" is not octets in hex`},
		"two keys naming one ID": {".yaml", remote("      fqdn: {gw.acme.example: acme/gw:1, GW.ACME.example: acme/gw:2}\n"),
			`ike: auth.aliases.remote.fqdn "gw.acme.example" and "GW.ACME.example" name one ID`},
		"an FQDN holding a terminator": {".toml", nodeTOML + "[auth.aliases.remote.fqdn]\n\"gw.acme.example\\r\" = \"acme/gw:1\"\n",
			`ike: auth.aliases.remote.fqdn "gw.acme.example\r" holds the terminator '\r'`},
		// \L is the line separator in a yaml double quoted string
		"an email address holding a line separator": {".yaml", remote("      email: {\"ops@acme.example\\L\": acme/gw:1}\n"),
			`ike: auth.aliases.remote.email "ops@acme.example`},
		"an FQDN beyond ASCII": {".yaml", remote("      fqdn: {\"gw.ac\\xe9me.example\": acme/gw:1}\n"), "and an FQDN is ASCII"},
		"an email address with no domain": {".yaml", remote("      email: {ops@: acme/gw:1}\n"),
			`ike: auth.aliases.remote.email "ops@" is not an address of the form local@domain`},
		"a local ID holding a terminator": {".yaml", aliasesYAML("    local: {acme/gw: {fqdn: \"laptop\\texample.net\"}}\n"),
			`ike: auth.aliases.local "acme/gw" fqdn "laptop\texample.net" holds the terminator '\t'`},
		"a local entry writing no ID": {".yaml", aliasesYAML("    local: {acme/gw: {}}\n"),
			`ike: auth.aliases.local "acme/gw" writes 0 of ip, fqdn, email and keyid`},
		"a local entry writing two IDs": {".toml", nodeTOML + "[auth.aliases.local]\n\"acme/gw\" = { fqdn = \"laptop.example.net\", email = \"ops@example.net\" }\n",
			`ike: auth.aliases.local "acme/gw" writes 2 of ip, fqdn, email and keyid`},
		"a local key naming nobody": {".yaml", aliasesYAML("    local: {gw: {fqdn: laptop.example.net}}\n"),
			`ike: auth.aliases.local "gw": identity: "gw" is not organization/name`},
		// the toml decoder reads a value that is not a table as an empty table and says nothing
		"a remote table that is not a table": {".toml", nodeTOML + "[auth.aliases.remote]\nip = true\n", `"auth.aliases.remote.ip" takes a table`},
		"a local table that is not a table":  {".toml", nodeTOML + "[auth.aliases]\nlocal = \"acme/gw\"\n", `"auth.aliases.local" takes a table`},
		// and it folds the case of a key it finds no field for
		"a table in another case": {".toml", nodeTOML + "[auth.aliases.remote.FQDN]\n\"gw.acme.example\" = \"acme/gw:1\"\n",
			`unknown field "auth.aliases.remote.FQDN"`},
		"a field of a local entry in another case": {".toml", nodeTOML + "[auth.aliases.local]\n\"acme/gw\" = { FQDN = \"laptop.example.net\" }\n",
			`unknown field "auth.aliases.local.\"acme/gw\".FQDN"`},
		"an unknown field of a local entry": {".yaml", aliasesYAML("    local: {acme/gw: {fqdm: laptop.example.net}}\n"), "fqdm"},
		// the yaml decoder follows a merge key into a map, and toml and json have no spelling for one
		"a merge key in a remote table": {".yaml", remote("      fqdn: {<<: {gw.acme.example: acme/gw:1}}\n"), "a merge key is refused"},
		"a merge key in a local entry":  {".yaml", aliasesYAML("    local: {acme/gw: {<<: {fqdn: laptop.example.net}}}\n"), "a merge key is refused"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, file.extension, file.body)
			if err == nil || !strings.Contains(err.Error(), file.names) {
				t.Errorf("the file was answered with %v, want a refusal naming %s", err, file.names)
			}
		})
	}
}

// auth.aliases.local is refused on a node whose link.endpoints holds two endpoints of one family, which a peer could not tell apart by an alias
// a node with one endpoint in each family takes it, and one with two in a family takes a table that presents nothing
func TestLocalAliasesNeedOneEndpointInAFamily(t *testing.T) {
	local := aliasesYAML("    local: {example/gateway: {fqdn: laptop.example.net}}\n")
	remote := aliasesYAML("    remote: {fqdn: {gw.example.net: example/gateway:1}}\n")
	withEndpoints := func(body string, families ...string) string {
		var endpoints strings.Builder
		for serial, family := range families {
			fmt.Fprintf(&endpoints, "    - serial: \"%d\"\n      family: %s\n", serial, family)
		}
		return strings.Replace(body, "    - serial: \"0\"\n      family: ip4\n", endpoints.String(), 1)
	}
	for name, test := range map[string]struct {
		body string
		want string // the refusal, empty where the file is taken
	}{
		"two ip4 endpoints": {withEndpoints(local, "ip4", "ip6", "ip4"),
			"config: auth.aliases.local is refused on a node whose link.endpoints holds 2 endpoints of the ip4 family, since a peer could not tell them apart by an alias"},
		"three ip6 endpoints": {withEndpoints(local, "ip6", "ip6", "ip6"),
			"link.endpoints holds 3 endpoints of the ip6 family"},
		"one endpoint in each family":          {withEndpoints(local, "ip4", "ip6"), ""},
		"two ip4 endpoints presenting nothing": {withEndpoints(remote, "ip4", "ip4"), ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, ".yaml", test.body)
			if test.want == "" && err != nil {
				t.Fatalf("the file was refused with %v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("the file was answered with %v, want a refusal naming %q", err, test.want)
			}
		})
	}
}

// an auth.aliases.local KEY_ID spelling another node's endpoint is refused, since every peer resolves it to that endpoint with no table and verifies AUTH with that node's key
// one spelling an endpoint of this node is taken
func TestLocalKeyIDSpellingAnotherNodeIsRefused(t *testing.T) {
	keyid := func(spelled string) string {
		return aliasesYAML(fmt.Sprintf("    local: {example/gateway: {keyid: %q}}\n", hex.EncodeToString([]byte(spelled))))
	}
	_, err := load(t, ".yaml", keyid("example/gateway:1"))
	if want := `ike: auth.aliases.local "example/gateway" keyid "` + hex.EncodeToString([]byte("example/gateway:1")) +
		`" spells example/gateway:1, an endpoint of another node`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("a KEY_ID spelling another node's endpoint was answered with %v, want a refusal naming %q", err, want)
	}
	if _, err := load(t, ".yaml", keyid("example/laptop:0")); err != nil {
		t.Errorf("a KEY_ID spelling this node's own endpoint was refused: %v", err)
	}
}

// of two keys of one table that are not text, the refusal names the same one on every load, where the order of a map would pick one at random
func TestAliasRefusalNamesTheSameKeyEveryTime(t *testing.T) {
	cfg := fullConfig()
	gateway := identity.MustParse("example/gateway:1")
	cfg.Auth.Aliases.Remote.FQDN = map[string]identity.Identity{"a\xff": gateway, "b\xff": gateway, "c\xff": gateway}
	first := cfg.Validate()
	if first == nil {
		t.Fatal("keys that are not text were taken")
	}
	for attempt := range 40 {
		if err := cfg.Validate(); err == nil || err.Error() != first.Error() {
			t.Fatalf("validation %d said %v, where the first said %v", attempt+1, err, first)
		}
	}
}

// a key or a value of auth.aliases that is not text is refused by its path, as every other string of a configuration is, since no file can write it
func TestAliasStringThatIsNotTextIsRefused(t *testing.T) {
	gateway := identity.MustParse("example/gateway:1")
	for path, change := range map[string]func(*ike.Aliases){
		"auth.aliases.remote.fqdn": func(a *ike.Aliases) { a.Remote.FQDN = map[string]identity.Identity{"gw\xff": gateway} },
		"auth.aliases.local": func(a *ike.Aliases) {
			a.Local = map[string]ike.LocalAlias{"example/gateway\xff": {FQDN: "laptop.example.net"}}
		},
		`auth.aliases.local."example/gateway".fqdn`: func(a *ike.Aliases) {
			a.Local = map[string]ike.LocalAlias{"example/gateway": {FQDN: "laptop\xff"}}
		},
	} {
		t.Run(path, func(t *testing.T) {
			cfg := fullConfig()
			change(&cfg.Auth.Aliases)
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "config: "+path+" ") {
				t.Errorf("refused with %v, want it refused by the path %s", err, path)
			}
		})
	}
}
