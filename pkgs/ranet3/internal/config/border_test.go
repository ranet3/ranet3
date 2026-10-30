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
	want := []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff:a::/36")}
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
			`["203.0.113.0/24", "3fff:a::/36", "0.0.0.0/0"]`,
			"egress: cap.border overlay 0.0.0.0/0 covers every address of its family",
		},
		"under the floor": {
			`["203.0.113.0/24", "3fff:a::/36", "2000::/11"]`,
			"egress: cap.border overlay 2000::/11 is shorter than /8 for IPv4 or /12 for IPv6",
		},
		"an IPv4 prefix written as IPv6": {
			`["203.0.113.0/24", "3fff:a::/36", "::ffff:198.18.0.0/111"]`,
			"egress: cap.border overlay ::ffff:198.18.0.0/111 is an IPv4 prefix written as IPv6, so write it as 198.18.0.0/15",
		},
		"host bits": {
			`["203.0.113.0/24", "3fff:a::/36", "198.18.0.1/15"]`,
			"egress: cap.border overlay 198.18.0.1/15 has bits set below its prefix length",
		},
		"written twice": {
			`["203.0.113.0/24", "3fff:a::/36", "203.0.113.0/24"]`,
			"egress: cap.border overlay 203.0.113.0/24 is written twice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			body := strings.Replace(nodeTOML+egressExitTOML, `overlay = ["203.0.113.0/24", "3fff:a::/36"]`, "overlay = "+c.overlay, 1)
			if _, err := loadTOML(t, body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
}

// An egress segment loads only beside the filter guarding it, and an allow
// entry outside the filter's overlay, which admits an inner source alone, loads
// only beside an IPv6 entry inside it to admit the outer source, which is
// always IPv6, and is refused for every other reason an entry inside is
func TestEgressSegmentIsRefusedOutsideTheBorder(t *testing.T) {
	exit := nodeTOML + egressExitTOML
	overlay := func(list string) string {
		return strings.Replace(exit, `overlay = ["203.0.113.0/24", "3fff:a::/36"]`, "overlay = "+list, 1)
	}
	// second is exit with an egress segment after the first, allowing list
	second := func(list string) string {
		return exit + "\n[[cap.segment.local]]\nsid = \"3fff:b:0:306::4\"\nbehavior = \"End.DT46\"\ndeliver = \"egress\"\nallow = " + list + "\n"
	}
	const alone = "lies outside cap.border overlay, which admits it as an inner source alone, and no IPv6 entry of the list lies inside the overlay to admit an outer source, which is always IPv6"
	for name, c := range map[string]struct{ body, says string }{
		"no cap.border": {
			strings.Replace(exit, egressBorderTOML, "", 1),
			"config: cap.segment local 3fff:b:0:306::3 is written and cap.border is absent",
		},
		"an IPv6 entry of another family's overlay alone": {
			overlay(`["203.0.113.0/24", "3fff:c::/30"]`),
			"config: cap.segment local 3fff:b:0:306::3 allow 3fff:a::/36 " + alone,
		},
		"entries outside beside an IPv4 entry inside alone": {
			second(`["203.0.113.0/24", "2001:db8:f3::/64", "3fff:c::/32"]`),
			"config: cap.segment local 3fff:b:0:306::4 allow 2001:db8:f3::/64 " + alone,
		},
		"an IPv6 entry reaching past the overlay alone": {
			second(`["3fff::/20"]`),
			"config: cap.segment local 3fff:b:0:306::4 allow 3fff::/20 " + alone,
		},
		"an IPv4 entry outside with no IPv6 entry": {
			second(`["198.51.100.0/24"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow holds no IPv6 prefix",
		},
		"an entry outside of length zero": {
			second(`["3fff:a::/36", "0.0.0.0/0"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow 0.0.0.0/0 admits every address of its family",
		},
		"an entry outside under the floor": {
			second(`["3fff:a::/36", "2000::/11"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow 2000::/11 is shorter than /8 for IPv4 or /12 for IPv6",
		},
		"an entry outside written as IPv6": {
			second(`["3fff:a::/36", "::ffff:198.51.100.0/120"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow ::ffff:198.51.100.0/120 is an IPv4 prefix written as IPv6",
		},
		"an entry outside with host bits": {
			second(`["3fff:a::/36", "198.51.100.1/24"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow 198.51.100.1/24 has bits set below its prefix length",
		},
		"an entry outside written twice": {
			second(`["3fff:a::/36", "198.51.100.0/24", "198.51.100.0/24"]`),
			"srv6: cap.segment local 3fff:b:0:306::4 allow 198.51.100.0/24 is written twice",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	for name, body := range map[string]string{
		// an overlay entry covering an allow entry from a shorter prefix covers it
		"an overlay covering the list from shorter prefixes": overlay(`["203.0.0.0/8", "3fff:a::/32"]`),
		"a second egress segment the overlay covers":         second(`["203.0.113.128/25", "3fff:a:1::/48"]`),
		"an IPv4 entry wider than its overlay entry":         overlay(`["203.0.113.0/25", "3fff:a::/36"]`),
		"an IPv4 entry beside the overlay":                   overlay(`["198.51.100.0/24", "3fff:a::/36"]`),
		"a LAN of each family beside an IPv6 entry inside":   second(`["3fff:a:1::/48", "2001:db8:f3::/64", "198.51.100.64/28"]`),
		// a node with no egress segment writes the filter on its own
		"cap.border alone": nodeTOML + egressBorderTOML,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, body); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// Every local segment loads only beside cap.border, whose overlay's IPv6
// prefixes are the only outer sources a local SID acts on, so a segment
// delivering to the mesh is refused without the block, and with an overlay
// holding no IPv6 prefix, which would refuse every packet. A segment cap.segment
// refuses for itself is refused for that first, with or without the block.
func TestEveryLocalSegmentNeedsTheBorder(t *testing.T) {
	const mesh = "[[cap.segment.local]]\nsid = \"3fff:b:0:306::1\"\nbehavior = \"End\"\n"
	for name, c := range map[string]struct{ body, says string }{
		"a segment cap.segment refuses, and no cap.border": {
			nodeTOML + mesh + "deliver = \"egress\"\n",
			"srv6: cap.segment local 3fff:b:0:306::1: deliver egress belongs to End.DT46, and End hands the packet to its next segment",
		},
		"no cap.border": {
			nodeTOML + mesh,
			"config: cap.segment local 3fff:b:0:306::1 is written and cap.border is absent, so nothing bounds the outer sources it acts on and a forged mesh source reaches it through this node's own links: add cap.border",
		},
		"an overlay of IPv4 alone": {
			nodeTOML + mesh + "[cap.border]\noverlay = [\"203.0.113.0/24\", \"198.18.0.0/15\"]\n",
			"config: cap.border overlay holds no IPv6 prefix, so cap.segment local 3fff:b:0:306::1 would refuse every packet, whose outer source is always IPv6",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || err.Error() != c.says {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	if _, err := loadTOML(t, nodeTOML+mesh+"[cap.border]\noverlay = [\"203.0.113.0/24\", \"3fff:a::/36\"]\n"); err != nil {
		t.Errorf("a segment beside an overlay holding an IPv6 prefix was refused: %v", err)
	}
	// with no local segment the overlay may hold one family alone
	if _, err := loadTOML(t, nodeTOML+"[cap.border]\noverlay = [\"203.0.113.0/24\"]\n"); err != nil {
		t.Errorf("an overlay of IPv4 alone on a node with no segment was refused: %v", err)
	}
}

// A class translating none loads only beside cap.border, since a learned route
// reads alike for a node's own address and for a LAN another node advertises,
// and only the overlay tells the entry chain's none sets which to keep. A class
// translating auto loads without it.
func TestNoneClassNeedsTheBorder(t *testing.T) {
	const exit = "\n[cap.egress]\nadvertise = [\"0.0.0.0/0\", \"::/0\"]\ntranslate = [\n  { from = \"3fff:a::/36\", to = \"%s\" },\n]\n"
	body := func(to string) string { return nodeTOML + strings.Replace(exit, "%s", to, 1) }
	const says = "config: cap.egress translate class 3fff:a::/36 is none and cap.border is absent, so the entry chain cannot tell the mesh's node addresses from the LANs other nodes advertise, and would refuse every inbound connection to that class's hosts: add cap.border with the prefixes the mesh numbers its nodes from"
	if _, err := loadTOML(t, body("none")); err == nil || err.Error() != says {
		t.Errorf("a none class without cap.border was refused with %v, want %q", err, says)
	}
	if _, err := loadTOML(t, body("none")+"\n[cap.border]\noverlay = [\"203.0.113.0/24\", \"3fff:a::/36\"]\n"); err != nil {
		t.Errorf("a none class beside cap.border was refused: %v", err)
	}
	if _, err := loadTOML(t, body("auto")); err != nil {
		t.Errorf("an auto class without cap.border was refused: %v", err)
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
		`["203.0.113.128/25"]`: "config: cap.egress advertise 203.0.113.128/25 overlaps cap.border overlay 203.0.113.0/24, so the hosts behind this node arrive on a link outside the mesh with a mesh source and the filter drops them",
		`["203.0.0.0/8"]`:      "config: cap.egress advertise 203.0.0.0/8 overlaps cap.border overlay 203.0.113.0/24",
		`["3fff:a:1::/48"]`:    "config: cap.egress advertise 3fff:a:1::/48 overlaps cap.border overlay 3fff:a::/36",
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
