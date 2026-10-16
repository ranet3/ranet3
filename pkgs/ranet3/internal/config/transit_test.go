// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"
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

// the old key under cap.route is refused naming the block that holds the setting, under every decoder and spelling
func TestRouteTransitIsRefusedNamingCapTransit(t *testing.T) {
	line := strings.Count(nodeYAML, "\n") + 3
	for name, file := range map[string]struct{ extension, body, line string }{
		"yaml":                 {".yaml", nodeYAML + "cap:\n  route:\n    transit: false\n", fmt.Sprintf("line %d:", line)},
		"yaml beside announce": {".yaml", nodeYAML + "cap:\n  route:\n    announce: [\"10.66.0.5/32\"]\n    transit: true\n", fmt.Sprintf("line %d:", line+1)},
		"yaml bare":            {".yaml", nodeYAML + "cap:\n  route:\n    transit:\n", fmt.Sprintf("line %d:", line)},
		"json": {".json", `{"node":"example/laptop","auth":{"key":"key.pem","trust":"trust.json"},` +
			`"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true},"cap":{"route":{"transit":true}}}`, "line 1:"},
		"toml":        {".toml", nodeTOML + "[cap.route]\ntransit = true\n", ""},
		"toml inline": {".toml", nodeTOML + "[cap]\nroute = { announce = [\"10.66.0.5/32\"], transit = false }\n", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, file.extension, file.body)
			if err == nil || !strings.Contains(err.Error(), "cap.transit with enable") || !strings.Contains(err.Error(), file.line) {
				t.Errorf("cap.route transit was answered with %v, want a refusal naming cap.transit on %q", err, file.line)
			}
		})
	}
}
