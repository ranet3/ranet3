// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"strings"
	"testing"
)

// cap.transit left out is off, on a listener as on a leaf, and a written block follows its enable, under each decoder
func TestTransitIsOnOnlyWhereTheFileWritesEnableTrue(t *testing.T) {
	listener := strings.Replace(nodeYAML, "  port: 13000\n", "  port: 13000\n  listen: true\n", 1)
	for name, file := range map[string]struct {
		extension, body string
		on              bool
	}{
		"a listener leaving it out": {".yaml", listener, false},
		"a leaf leaving it out":     {".yaml", nodeYAML, false},
		"a listener writing it off": {".yaml", listener + "cap:\n  transit:\n    enable: false\n", false},
		"a leaf writing it on":      {".yaml", nodeYAML + "cap:\n  transit:\n    enable: true\n", true},
		"a leaf writing it in toml": {".toml", nodeTOML + "[cap.transit]\nenable = true\n", true},
		"a listener writing it in json": {".json", `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
			`"link":{"port":13000,"listen":true,"endpoints":[{"serial":"0","family":"ip4"}]},"cap":{"transit":{"enable":false}}}`, false},
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
