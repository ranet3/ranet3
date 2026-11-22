// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import "testing"

// ::1 in each role cap.segment and cap.exit via give an outer header is refused at load in each format, with the loader's message whole
// a block source no entry uses, a steering entry's own source, a local SID no packet reaches, a segment of an entry and a segment of cap.exit via
// yaml quotes the address, since a plain scalar may not open with a colon
func TestLoopbackInAnOuterHeaderIsRefusedAtLoad(t *testing.T) {
	overlayTOML, overlayYAML, overlayJSON := "overlay = [\"192.0.2.0/24\", \"3fff::/20\"]\n", "overlay: [192.0.2.0/24, 3fff::/20]\n", `"overlay": ["192.0.2.0/24", "3fff::/20"]`
	for _, c := range []struct {
		name                   string
		asTOML, asYAML, asJSON string
		says                   string
	}{
		{
			"a block source no entry uses",
			"[cap.segment]\nsource = \"::1\"\n",
			"cap:\n  segment:\n    source: \"::1\"\n",
			`"segment": {"source": "::1"}`,
			"srv6: cap.segment source ::1 cannot address a segment routed packet",
		},
		{
			"a steering entry's own source",
			"[cap.segment]\nsource = \"3fff:1::1\"\n[[cap.segment.steer]]\nto = \"3fff:9::/64\"\nvia = [\"3fff:1::2\"]\nsource = \"::1\"\n",
			"cap:\n  segment:\n    source: 3fff:1::1\n    steer:\n      - {to: 3fff:9::/64, via: [3fff:1::2], source: \"::1\"}\n",
			`"segment": {"source": "3fff:1::1", "steer": [{"to": "3fff:9::/64", "via": ["3fff:1::2"], "source": "::1"}]}`,
			"srv6: tunnel source ::1 cannot address a segment routed packet",
		},
		{
			"a local SID no packet reaches",
			"[[cap.segment.local]]\nsid = \"::1\"\nbehavior = \"End\"\n",
			"cap:\n  segment:\n    local:\n      - {sid: \"::1\", behavior: End}\n",
			`"segment": {"local": [{"sid": "::1", "behavior": "End"}]}`,
			"srv6: cap.segment local ::1 cannot address a segment routed packet",
		},
		{
			"a segment of an entry",
			"[cap.segment]\nsource = \"3fff:1::1\"\n[[cap.segment.steer]]\nto = \"3fff:9::/64\"\nvia = [\"::1\"]\n",
			"cap:\n  segment:\n    source: 3fff:1::1\n    steer:\n      - {to: 3fff:9::/64, via: [\"::1\"]}\n",
			`"segment": {"source": "3fff:1::1", "steer": [{"to": "3fff:9::/64", "via": ["::1"]}]}`,
			"srv6: segment ::1 cannot address a segment routed packet",
		},
	} {
		bodies := map[string]string{
			".toml": overlayTOML + nodeTOML + c.asTOML,
			".yaml": nodeYAML + overlayYAML + c.asYAML,
			".json": `{"node": "example/laptop", "auth": {"key": "key.pem", "trust": "trust.json"}, "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]}, "dial": {"to": ["example/gateway"]}, ` + overlayJSON + `, "cap": {` + c.asJSON + `}}`,
		}
		for extension, body := range bodies {
			t.Run(c.name+" in "+extension, func(t *testing.T) {
				_, err := load(t, extension, body)
				if err == nil || err.Error() != c.says {
					t.Errorf("the load says %v, want %q", err, c.says)
				}
			})
		}
	}
	for _, format := range formats {
		t.Run("a segment of cap.exit via in "+format, func(t *testing.T) {
			via := "::1"
			if format == "yaml" {
				via = `"::1"`
			}
			_, err := loadNode(t, viaFixture(via), format)
			if want := "cap.exit via: srv6: segment ::1 cannot address a segment routed packet"; err == nil || err.Error() != want {
				t.Errorf("the load says %v, want %q", err, want)
			}
		})
	}
}
