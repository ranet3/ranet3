// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"
	"testing"
)

// a cap.segment steer whose to counts as a default is refused in each format, a zero-length one, a /1 half, 2000::/3 and a ULA wider than the floor among them
// with or without a from beside it, while a to at the floors, a /8 and a /16, and one inside the overlay load
func TestSteerToCountingAsADefaultIsRefused(t *testing.T) {
	body := func(format, from, to string) (string, string) {
		selector := map[string]string{
			"toml": fmt.Sprintf(`to = "%s"`, to),
			"yaml": fmt.Sprintf(`to: "%s"`, to),
			"json": fmt.Sprintf(`"to": "%s"`, to),
		}[format]
		if from != "" {
			selector += map[string]string{"toml": fmt.Sprintf(`, from = "%s"`, from), "yaml": fmt.Sprintf(`, from: "%s"`, from), "json": fmt.Sprintf(`, "from": "%s"`, from)}[format]
		}
		switch format {
		case "toml":
			return ".toml", nodeTOML + "[cap.border]\noverlay = [\"192.0.2.0/24\", \"3fff::/20\"]\n[cap.segment]\nsource = \"3fff::2\"\nsteer = [{ " + selector + `, via = ["3fff:b:0:206::1"] }]` + "\n"
		case "yaml":
			return ".yaml", nodeYAML + "cap:\n  border: {overlay: [192.0.2.0/24, 3fff::/20]}\n  segment:\n    source: 3fff::2\n    steer: [{" + selector + ", via: [3fff:b:0:206::1]}]\n"
		}
		return ".json", fmt.Sprintf(`{
  "node": "example/laptop",
  "auth": {"key": "key.pem", "trust": "trust.json"},
  "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]},
  "dial": {"to": ["example/gateway"]},
  "cap": {"border": {"overlay": ["192.0.2.0/24", "3fff::/20"]}, "segment": {"source": "3fff::2", "steer": [{%s, "via": ["3fff:b:0:206::1"]}]}}
}`, selector)
	}
	for _, format := range formats {
		for _, c := range []struct{ from, to string }{
			{"", "0.0.0.0/0"}, {"", "::/0"}, {"", "0.0.0.0/1"}, {"", "128.0.0.0/1"}, {"", "2000::/3"}, {"", "fd00::/8"},
			{"192.0.2.2/32", "0.0.0.0/0"}, {"3fff::2/128", "::/0"}, {"3fff::2/128", "8000::/1"},
		} {
			extension, text := body(format, c.from, c.to)
			want := fmt.Sprintf("config: cap.segment steer to %s counts as a default, which is cap.exit via: write the path there", c.to)
			if _, err := load(t, extension, text); err == nil || err.Error() != want {
				t.Errorf("in %s a steer from %q to %s was refused with %v, want %q", format, c.from, c.to, err, want)
			}
		}
		for _, to := range []string{"203.0.0.0/8", "2001::/16", "192.0.2.0/24", "3fff::/20", "3fff:b::/32"} {
			extension, text := body(format, "", to)
			if _, err := load(t, extension, text); err != nil {
				t.Errorf("in %s a steer to %s was refused: %v", format, to, err)
			}
		}
	}
}
