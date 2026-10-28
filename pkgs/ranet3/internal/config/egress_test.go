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
// other tests, in each format a file is written in, with no cap.table
const (
	egressSegmentTOML = `
[[cap.segment.local]]
sid = "3fff:b:0:306::3"
behavior = "End.DT46"
deliver = "egress"
allow = ["203.0.113.0/24", "3fff:a::/36"]
`
	egressBorderTOML = `
[cap.border]
overlay = ["203.0.113.0/24", "3fff:a::/36"]
`
	egressExitTOML = "\n[cap.egress]\n" + egressBorderTOML + egressSegmentTOML
	egressExitYAML = `
cap:
  egress: {}
  border:
    overlay: [203.0.113.0/24, 3fff:a::/36]
  segment:
    local:
      - sid: 3fff:b:0:306::3
        behavior: End.DT46
        deliver: egress
        allow: [203.0.113.0/24, 3fff:a::/36]
`
	egressExitJSON = `{
  "node": "example/laptop",
  "auth": {"key": "key.pem", "trust": "trust.json"},
  "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]},
  "dial": {"to": ["example/gateway"]},
  "cap": {
    "egress": {},
    "border": {"overlay": ["203.0.113.0/24", "3fff:a::/36"]},
    "segment": {"local": [{"sid": "3fff:b:0:306::3", "behavior": "End.DT46", "deliver": "egress", "allow": ["203.0.113.0/24", "3fff:a::/36"]}]}
  }
}`
)

// egressExits is the exit in each format, by its file's extension
func egressExits() map[string]struct{ extension, text string } {
	return map[string]struct{ extension, text string }{
		"toml": {".toml", nodeTOML + egressExitTOML},
		"yaml": {".yaml", nodeYAML + egressExitYAML},
		"json": {".json", egressExitJSON},
	}
}

// An egress segment is an End.DT46 entry with deliver = "egress" and its allow
// list, written alike in each format, which loads beside cap.egress with no
// cap.table, since its inner packets leave through the mesh tun and no rule
// has to route them, and a file writing deliver = "mesh" loads as one leaving
// it out
func TestEgressSegmentReadsAlikeInEveryFormat(t *testing.T) {
	want := srv6.Segment{
		SID:      schema.MustAddr("3fff:b:0:306::3"),
		Behavior: srv6.BehaviorEndDT46,
		Deliver:  srv6.DeliverEgress,
		Allow:    []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff:a::/36")},
	}
	for name, body := range egressExits() {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, body.extension, body.text)
			if err != nil {
				t.Fatalf("an exit serving one egress segment with no cap.table was refused: %v", err)
			}
			if cfg.Cap.Table != nil {
				t.Errorf("the exit read a cap.table %+v that no file wrote", cfg.Cap.Table)
			}
			if got := cfg.Segments().Local; len(got) != 1 || !reflect.DeepEqual(got[0], want) {
				t.Errorf("the segment read as %+v, want %+v", got, want)
			}
		})
	}
	written, err := loadTOML(t, nodeTOML+egressBorderTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\ndeliver = \"mesh\"\n")
	if err != nil {
		t.Fatal(err)
	}
	omitted, err := loadTOML(t, nodeTOML+egressBorderTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(written.Segments().Normalized(), omitted.Segments().Normalized()) {
		t.Errorf("deliver = \"mesh\" read as %+v and its omission as %+v", written.Segments(), omitted.Segments())
	}
}

// An egress segment loads only beside cap.egress, which translates what it
// carries, and with its /128 left to readiness, in each format
func TestEgressSegmentIsRefusedWithoutWhatCarriesIt(t *testing.T) {
	exits := egressExits()
	withoutEgress := map[string]string{
		"toml": nodeTOML + egressBorderTOML + egressSegmentTOML,
		"yaml": strings.Replace(exits["yaml"].text, "  egress: {}\n", "", 1),
		"json": strings.Replace(exits["json"].text, `"egress": {},`, "", 1),
	}
	announcing := map[string]string{
		"toml": exits["toml"].text + "[cap.route]\nannounce = [\"3fff:b:0:306::3/128\"]\n",
		"yaml": strings.Replace(exits["yaml"].text, "cap:\n", "cap:\n  route:\n    announce: [3fff:b:0:306::3/128]\n", 1),
		"json": strings.Replace(exits["json"].text, `"cap": {`, `"cap": {"route": {"announce": ["3fff:b:0:306::3/128"]},`, 1),
	}
	for format, body := range exits {
		for name, c := range map[string]struct{ text, says string }{
			"no cap.egress": {
				withoutEgress[format],
				"cap.segment local 3fff:b:0:306::3 delivers to egress and cap.egress is absent, so nothing translates what leaves the mesh tun",
			},
			"its /128 announced by cap.route": {
				announcing[format],
				"config: cap.route announces 3fff:b:0:306::3/128, the egress segment's own route, which would announce it whether or not the segment is ready",
			},
		} {
			t.Run(format+" "+name, func(t *testing.T) {
				if _, err := load(t, body.extension, c.text); err == nil || !strings.Contains(err.Error(), c.says) {
					t.Errorf("refused with %v, want %q", err, c.says)
				}
			})
		}
	}
	exit := exits["toml"].text
	second := exit + strings.Replace(egressSegmentTOML, "306::3", "306::4", 1) + "[cap.route]\nannounce = [\"3fff:b:0:306::4/128\"]\n"
	if _, err := loadTOML(t, second); err == nil || !strings.Contains(err.Error(), "config: cap.route announces 3fff:b:0:306::4/128, the egress segment's own route") {
		t.Errorf("a second egress segment's /128 announced by cap.route was refused with %v", err)
	}
	// a covering route may be announced, and the mesh tun may take any name the platform does
	for name, body := range map[string]string{
		"a covering prefix announced":   exit + "[cap.route]\nannounce = [\"3fff:b:0:300::/60\"]\n",
		"a mesh tun of 15 bytes":        strings.Replace(exit, "[link]\n", "[link]\ntun = \"fifteen-bytes-x\"\n", 1),
		"a mesh tun the kernel numbers": strings.Replace(exit, "[link]\n", "[link]\ntun = \"ranet%d\"\n", 1),
	} {
		if _, err := loadTOML(t, body); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
	// a segment that delivers to the mesh asks for none of it but cap.border
	if _, err := loadTOML(t, nodeTOML+egressBorderTOML+"[[cap.segment.local]]\nsid = \"2001:db8::1\"\nbehavior = \"End.DT46\"\n"); err != nil {
		t.Errorf("a segment delivering to the mesh was refused: %v", err)
	}
}
