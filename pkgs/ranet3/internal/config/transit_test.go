// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

// cap.transit left out is off, on a listener as on a leaf, and written it is on, an empty block included, under each decoder
func TestTransitIsOnWhereTheFileWritesTheBlock(t *testing.T) {
	listener := strings.Replace(nodeYAML, "  port: 13000\n", "  port: 13000\n  listen: true\n", 1)
	const json = `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
		`"link":{"port":13000,"listen":true,"endpoints":[{"serial":"0","family":"ip4"}]}%s}`
	for name, file := range map[string]struct {
		extension, body string
		on              bool
	}{
		"a listener leaving it out":         {".yaml", listener, false},
		"a leaf leaving it out":             {".yaml", nodeYAML, false},
		"a leaf writing an empty block":     {".yaml", nodeYAML + "cap:\n  transit: {}\n", true},
		"a leaf writing the bare key":       {".yaml", nodeYAML + "cap:\n  transit:\n", true},
		"a leaf writing it in toml":         {".toml", nodeTOML + "[cap.transit]\n", true},
		"a listener leaving it out in json": {".json", strings.Replace(json, "%s", "", 1), false},
		"a listener writing it in json":     {".json", strings.Replace(json, "%s", `,"cap":{"transit":{}}`, 1), true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, file.extension, file.body)
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Transits(); got != file.on {
				t.Errorf("transit is %t, want %t", got, file.on)
			}
		})
	}
}

// enable is no key of cap.transit, which the block's presence alone turns on, so each decoder refuses it as unknown
func TestTransitRefusesEnable(t *testing.T) {
	for name, file := range map[string]struct{ extension, body string }{
		"yaml": {".yaml", nodeYAML + "cap:\n  transit:\n    enable: true\n"},
		"toml": {".toml", nodeTOML + "[cap.transit]\nenable = true\n"},
		"json": {".json", `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
			`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"cap":{"transit":{"enable":false}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, file.extension, file.body)
			if err == nil || !strings.Contains(err.Error(), "enable") {
				t.Errorf("cap.transit enable was answered with %v, want it refused as unknown", err)
			}
		})
	}
}
