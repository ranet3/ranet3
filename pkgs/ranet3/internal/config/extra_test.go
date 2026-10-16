// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
)

// the block reads alike under each decoder, the three keys with it
func TestExtraCostReadsAlikeUnderEachDecoder(t *testing.T) {
	want := babel.ExtraCost{Foreign: 1024, Org: map[string]uint16{"gravity": 2048}, Node: map[string]uint16{"ysun/lagern": 300}}
	for name, file := range map[string]struct{ extension, body string }{
		"toml": {".toml", nodeTOML + "[cap.babel.cost.extra]\nforeign = 1024\norg = { gravity = 2048 }\nnode = { \"ysun/lagern\" = 300 }\n"},
		"yaml": {".yaml", nodeYAML + "cap:\n  babel:\n    cost:\n      extra:\n        foreign: 1024\n        org: {gravity: 2048}\n        node: {ysun/lagern: 300}\n"},
		"json": {".json", `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
			`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true},` +
			`"cap":{"babel":{"cost":{"extra":{"foreign":1024,"org":{"gravity":2048},"node":{"ysun/lagern":300}}}}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, file.extension, file.body)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Babel().Cost.Extra; !got.Equal(want) {
				t.Errorf("the block reads as %+v, want %+v", got, want)
			}
		})
	}
}

// this node's own identity, an amount of infinity, a node key that is not a node, a number the decoder would change, a merge key and a value that is not a table are refused
func TestExtraCostRefusals(t *testing.T) {
	block := func(body string) string { return nodeYAML + "cap:\n  babel:\n    cost:\n      extra:\n" + body }
	for name, file := range map[string]struct{ extension, body, names string }{
		"this node":          {".yaml", block("        node: {example/laptop: 300}\n"), "is this node"},
		"infinity":           {".yaml", block("        foreign: 65535\n"), "foreign is 65535"},
		"an endpoint":        {".yaml", block("        node: {example/gateway:0: 300}\n"), "names an endpoint"},
		"a float":            {".yaml", block("        org: {gravity: 2048.0}\n"), "written as a float"},
		"a minus sign":       {".yaml", block("        org: {gravity: -0}\n"), "minus sign"},
		"a merge key":        {".yaml", block("        org: {<<: {gravity: 2048}}\n"), "a merge key is refused"},
		"too large":          {".toml", nodeTOML + "[cap.babel.cost.extra]\norg = { gravity = 70000 }\n", "out of range"},
		"not a table":        {".toml", nodeTOML + "[cap.babel.cost.extra]\norg = true\n", "takes a table"},
		"an unknown key":     {".toml", nodeTOML + "[cap.babel.cost.extra]\nforiegn = 1\n", "foriegn"},
		"an unknown in yaml": {".yaml", block("        orgs: {gravity: 1}\n"), "orgs"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, file.extension, file.body)
			if err == nil || !strings.Contains(err.Error(), file.names) {
				t.Errorf("the file was answered with %v, want a refusal naming %q", err, file.names)
			}
		})
	}
}

// a key of the block that is not text is refused by its path, as every other string of a configuration is, since no file can write it
func TestExtraCostKeyThatIsNotTextIsRefused(t *testing.T) {
	cfg := fullConfig()
	cfg.Cap.Babel.Cost.Extra.Org = map[string]uint16{"\xff": 1}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cap.babel.cost.extra.org") {
		t.Errorf("an organization key that is not UTF-8 was answered with %v, want a refusal naming cap.babel.cost.extra.org", err)
	}
}
