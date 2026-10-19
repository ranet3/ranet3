// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/schema"
)

// cap.border is one list, written alike in each format
func TestBorderReadsAlikeInEveryFormat(t *testing.T) {
	want := []schema.Prefix{schema.MustPrefix("23.161.104.0/24"), schema.MustPrefix("2602:f590::/36")}
	for name, body := range map[string]struct{ extension, text string }{
		"toml": {".toml", nodeTOML + egressExitTOML},
		"yaml": {".yaml", nodeYAML + egressExitYAML},
		"json": {".json", egressExitJSON},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, body.extension, body.text)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Cap.Border == nil || !slices.Equal(cfg.Cap.Border.Overlay, want) {
				t.Errorf("cap.border read as %+v, want overlay %v", cfg.Cap.Border, want)
			}
		})
	}
}

// The block refuses what its own package refuses, by name, through the loader
func TestBorderRefusalsReachTheLoader(t *testing.T) {
	for name, c := range map[string]struct{ overlay, says string }{
		"an empty overlay": {`[]`, "egress: cap.border overlay is empty, so the filter would pass every forged mesh source"},
		"a zero length": {
			`["23.161.104.0/24", "2602:f590::/36", "0.0.0.0/0"]`,
			"egress: cap.border overlay 0.0.0.0/0 covers every address of its family",
		},
		"under the floor": {
			`["23.161.104.0/24", "2602:f590::/36", "2000::/11"]`,
			"egress: cap.border overlay 2000::/11 is shorter than /8 for IPv4 or /12 for IPv6",
		},
		"an IPv4 prefix written as IPv6": {
			`["23.161.104.0/24", "2602:f590::/36", "::ffff:198.18.0.0/111"]`,
			"egress: cap.border overlay ::ffff:198.18.0.0/111 is an IPv4 prefix written as IPv6, so write it as 198.18.0.0/15",
		},
		"host bits": {
			`["23.161.104.0/24", "2602:f590::/36", "198.18.0.1/15"]`,
			"egress: cap.border overlay 198.18.0.1/15 has bits set below its prefix length",
		},
		"written twice": {
			`["23.161.104.0/24", "2602:f590::/36", "23.161.104.0/24"]`,
			"egress: cap.border overlay 23.161.104.0/24 is written twice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(nodeTOML+egressExitTOML, `overlay = ["23.161.104.0/24", "2602:f590::/36"]`, "overlay = "+c.overlay, 1)
			if _, err := loadTOML(t, body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
}

// An egress segment loads only beside the filter guarding it, and only with
// an allow list the filter's overlay covers, since a forged allowed source
// reaches the segment through any forwarding node whose filter passes it
func TestEgressSegmentIsRefusedOutsideTheBorder(t *testing.T) {
	exit := nodeTOML + egressExitTOML
	overlay := func(list string) string {
		return strings.Replace(exit, `overlay = ["23.161.104.0/24", "2602:f590::/36"]`, "overlay = "+list, 1)
	}
	// second is exit with an egress segment after the first, allowing list
	second := func(list string) string {
		return exit + "\n[[cap.segment.local]]\nsid = \"2a0c:b641:69c:5d26::4\"\nbehavior = \"End.DT46\"\ndeliver = \"egress\"\nallow = " + list + "\n"
	}
	for name, c := range map[string]struct{ body, says string }{
		"no cap.border": {
			strings.Replace(exit, egressBorderTOML, "", 1),
			"config: cap.segment local 2a0c:b641:69c:5d26::3 is written and cap.border is absent",
		},
		"an allow entry of another family's overlay": {
			overlay(`["23.161.104.0/24", "3fff::/20"]`),
			"config: cap.segment local 2a0c:b641:69c:5d26::3 allow 2602:f590::/36 lies outside cap.border overlay, so every forwarding node's filter lets a forged 2602:f590::/36 source through to it",
		},
		"an allow entry wider than its overlay entry": {
			overlay(`["23.161.104.0/25", "2602:f590::/36"]`),
			"allow 23.161.104.0/24 lies outside cap.border overlay",
		},
		"an allow entry beside its overlay entry": {
			overlay(`["23.161.105.0/24", "2602:f590::/36"]`),
			"allow 23.161.104.0/24 lies outside cap.border overlay",
		},
		"an allow entry of a second egress segment outside the overlay": {
			second(`["23.161.104.0/24", "3fff:a::/32"]`),
			"config: cap.segment local 2a0c:b641:69c:5d26::4 allow 3fff:a::/32 lies outside cap.border overlay",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	// an overlay entry covering an allow entry from a shorter prefix covers it
	if _, err := loadTOML(t, overlay(`["23.161.0.0/16", "2602:f590::/32"]`)); err != nil {
		t.Errorf("an overlay covering the allow list from shorter prefixes was refused: %v", err)
	}
	if _, err := loadTOML(t, second(`["23.161.104.128/25", "2602:f590:1::/48"]`)); err != nil {
		t.Errorf("a second egress segment the overlay covers was refused: %v", err)
	}
	// a node with no egress segment writes the filter on its own
	if _, err := loadTOML(t, nodeTOML+egressBorderTOML); err != nil {
		t.Errorf("a node with cap.border alone was refused: %v", err)
	}
}

// Every local segment loads only beside cap.border, whose overlay's IPv6
// prefixes are the only outer sources a local SID acts on, so a segment
// delivering to the mesh is refused without the block, and with an overlay
// holding no IPv6 prefix, which would refuse every packet. A segment cap.segment
// refuses for itself is refused for that first, with or without the block.
func TestEveryLocalSegmentNeedsTheBorder(t *testing.T) {
	const mesh = "[[cap.segment.local]]\nsid = \"2a0c:b641:69c:5d26::1\"\nbehavior = \"End\"\n"
	for name, c := range map[string]struct{ body, says string }{
		"a segment cap.segment refuses, and no cap.border": {
			nodeTOML + mesh + "deliver = \"egress\"\n",
			"srv6: cap.segment local 2a0c:b641:69c:5d26::1: deliver egress belongs to End.DT46, and End hands the packet to its next segment",
		},
		"no cap.border": {
			nodeTOML + mesh,
			"config: cap.segment local 2a0c:b641:69c:5d26::1 is written and cap.border is absent, so nothing bounds the outer sources it acts on and a forged mesh source reaches it through this node's own links: add cap.border",
		},
		"an overlay of IPv4 alone": {
			nodeTOML + mesh + "[cap.border]\noverlay = [\"23.161.104.0/24\", \"198.18.0.0/15\"]\n",
			"config: cap.border overlay holds no IPv6 prefix, so cap.segment local 2a0c:b641:69c:5d26::1 would refuse every packet, whose outer source is always IPv6",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || err.Error() != c.says {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	if _, err := loadTOML(t, nodeTOML+mesh+"[cap.border]\noverlay = [\"23.161.104.0/24\", \"2602:f590::/36\"]\n"); err != nil {
		t.Errorf("a segment beside an overlay holding an IPv6 prefix was refused: %v", err)
	}
	// with no local segment the overlay may hold one family alone
	if _, err := loadTOML(t, nodeTOML+"[cap.border]\noverlay = [\"23.161.104.0/24\"]\n"); err != nil {
		t.Errorf("an overlay of IPv4 alone on a node with no segment was refused: %v", err)
	}
}

// A prefix this node advertises out of cap.egress lies outside the overlay,
// since the hosts behind it would arrive on a link outside the mesh with a
// mesh source and the filter would drop them, while the exit default
// overlaps everything and is left out
func TestAdvertiseOverlappingTheOverlayIsRefused(t *testing.T) {
	advertise := func(list string) string {
		return strings.Replace(nodeTOML+egressExitTOML, "\n[cap.egress]\n", "\n[cap.egress]\nadvertise = "+list+"\n", 1)
	}
	for list, says := range map[string]string{
		`["23.161.104.128/25"]`: "config: cap.egress advertise 23.161.104.128/25 overlaps cap.border overlay 23.161.104.0/24, so the hosts behind this node arrive on a link outside the mesh with a mesh source and the filter drops them",
		`["23.161.0.0/16"]`:     "config: cap.egress advertise 23.161.0.0/16 overlaps cap.border overlay 23.161.104.0/24",
		`["2602:f590:1::/48"]`:  "config: cap.egress advertise 2602:f590:1::/48 overlaps cap.border overlay 2602:f590::/36",
	} {
		if _, err := loadTOML(t, advertise(list)); err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("advertise %s was refused with %v, want %q", list, err, says)
		}
	}
	for _, list := range []string{`["0.0.0.0/0", "::/0"]`, `["192.0.2.0/24", "2001:db8::/32"]`} {
		if _, err := loadTOML(t, advertise(list)); err != nil {
			t.Errorf("advertise %s was refused: %v", list, err)
		}
	}
}
