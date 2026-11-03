// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// cap.antispoof's exemptions in each format, the overlay written beside them
// by egressExits
const (
	antispoofTOML = `
[cap.antispoof]
exempt = ["203.0.113.192/26"]
[cap.antispoof.interface.eth1]
exempt = ["3fff:a:1::/48"]
[cap.antispoof.interface."wl*"]
exempt = ["203.0.113.128/26"]
`
	antispoofYAML = `  antispoof:
    exempt: [203.0.113.192/26]
    interface:
      eth1: {exempt: [3fff:a:1::/48]}
      "wl*": {exempt: [203.0.113.128/26]}
`
	antispoofJSON = `"antispoof": {"exempt": ["203.0.113.192/26"], "interface": {"eth1": {"exempt": ["3fff:a:1::/48"]}, "wl*": {"exempt": ["203.0.113.128/26"]}}},`
)

// exempting is each of egressExits with antispoofTOML, antispoofYAML or
// antispoofJSON written in, by format
func exempting() map[string]struct{ extension, text string } {
	exits := egressExits()
	return map[string]struct{ extension, text string }{
		"toml": {".toml", exits["toml"].text + antispoofTOML},
		"yaml": {".yaml", strings.Replace(exits["yaml"].text, "cap:\n", "cap:\n"+antispoofYAML, 1)},
		"json": {".json", strings.Replace(exits["json"].text, `"cap": {`, `"cap": {`+antispoofJSON, 1)},
	}
}

// overlay is one top-level list and cap.antispoof its exemptions, each written
// alike in each format, and the filter's configuration is both with this
// node's own prefixes, absent where overlay is
func TestOverlayAndAntispoofReadAlikeInEveryFormat(t *testing.T) {
	overlay := []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff:a::/36")}
	want := egress.Border{Overlay: overlay, Antispoof: egress.Antispoof{
		Exempt: []schema.Prefix{schema.MustPrefix("203.0.113.192/26")},
		Interface: map[string]egress.AntispoofInterface{
			"eth1": {Exempt: []schema.Prefix{schema.MustPrefix("3fff:a:1::/48")}},
			"wl*":  {Exempt: []schema.Prefix{schema.MustPrefix("203.0.113.128/26")}},
		},
	}}
	for format, body := range exempting() {
		t.Run(format, func(t *testing.T) {
			cfg, err := load(t, body.extension, body.text)
			if err != nil {
				t.Fatal(err)
			}
			want := want
			want.Own, want.Addresses = cfg.OwnPrefixes()
			if border := cfg.Border(); border == nil || !reflect.DeepEqual(*border, want) {
				t.Errorf("the filter's configuration read as %+v, want %+v", border, want)
			}
		})
	}
	for format, body := range egressExits() {
		t.Run(format+" with no exemption", func(t *testing.T) {
			cfg, err := load(t, body.extension, body.text)
			if err != nil {
				t.Fatal(err)
			}
			if border := cfg.Border(); border == nil || !slices.Equal(border.Overlay, overlay) || border.Antispoof.Exempt != nil || border.Antispoof.Interface != nil {
				t.Errorf("the filter's configuration read as %+v, want overlay %v alone", border, overlay)
			}
		})
	}
	cfg, err := loadTOML(t, nodeTOML)
	if err != nil {
		t.Fatal(err)
	}
	if border := cfg.Border(); border != nil {
		t.Errorf("a node writing no overlay read the filter's configuration %+v", border)
	}
}

// overlay refuses what the filter's package refuses of it, and cap.antispoof
// what it refuses of an exemption, by name, through the loader
func TestOverlayAndAntispoofRefusalsReachTheLoader(t *testing.T) {
	exit := overlayTOML + nodeTOML + egressExitTOML
	overlay := func(list string) string {
		return strings.Replace(exit, `overlay = ["203.0.113.0/24", "3fff:a::/36"]`, "overlay = "+list, 1)
	}
	for name, c := range map[string]struct{ body, says string }{
		"an empty overlay": {overlay(`[]`), "egress: overlay is empty, so the antispoof filter would pass every forged mesh source"},
		"a zero length": {
			overlay(`["203.0.113.0/24", "3fff:a::/36", "0.0.0.0/0"]`),
			"egress: overlay 0.0.0.0/0 covers every address of its family",
		},
		"under the floor": {
			overlay(`["203.0.113.0/24", "3fff:a::/36", "2000::/11"]`),
			"egress: overlay 2000::/11 is shorter than /8 for IPv4 or /12 for IPv6",
		},
		"an IPv4 prefix written as IPv6": {
			overlay(`["203.0.113.0/24", "3fff:a::/36", "::ffff:198.18.0.0/111"]`),
			"egress: overlay ::ffff:198.18.0.0/111 is an IPv4 prefix written as IPv6, so write it as 198.18.0.0/15",
		},
		"host bits": {
			overlay(`["203.0.113.0/24", "3fff:a::/36", "198.18.0.1/15"]`),
			"egress: overlay 198.18.0.1/15 has bits set below its prefix length",
		},
		"written twice": {
			overlay(`["203.0.113.0/24", "3fff:a::/36", "203.0.113.0/24"]`),
			"egress: overlay 203.0.113.0/24 is written twice",
		},
		"cap.antispoof with no overlay": {
			nodeTOML + "[cap.antispoof]\nexempt = [\"203.0.113.0/24\"]\n",
			"config: cap.antispoof is written and overlay is absent, so no filter runs for it to exempt from: write overlay with the prefixes the mesh numbers its nodes from",
		},
		"an empty block": {
			exit + "[cap.antispoof]\n",
			"config: cap.antispoof exempts nothing, and the filter runs wherever overlay is written: write exempt or cap.antispoof.interface, or leave the block out",
		},
		"an exemption outside the overlay": {
			exit + "[cap.antispoof]\nexempt = [\"198.51.100.0/24\"]\n",
			"egress: cap.antispoof exempt 198.51.100.0/24 lies outside overlay, and the filter drops only an overlay source, so it would exempt nothing",
		},
		"an exemption reaching past the overlay": {
			exit + "[cap.antispoof]\nexempt = [\"203.0.112.0/23\"]\n",
			"egress: cap.antispoof exempt 203.0.112.0/23 lies outside overlay",
		},
		"an exemption written twice": {
			exit + "[cap.antispoof]\nexempt = [\"203.0.113.0/25\", \"203.0.113.0/25\"]\n",
			"egress: cap.antispoof exempt 203.0.113.0/25 is written twice",
		},
		"an interface's exemption outside the overlay": {
			exit + "[cap.antispoof.interface.eth1]\nexempt = [\"2001:db8::/32\"]\n",
			"egress: cap.antispoof.interface.\"eth1\" exempt 2001:db8::/32 lies outside overlay",
		},
		"an interface exempting nothing": {
			exit + "[cap.antispoof.interface.eth1]\nexempt = []\n",
			"egress: cap.antispoof.interface.\"eth1\" exempts nothing: write its exempt, or leave the entry out",
		},
		"a * before the end": {
			exit + "[cap.antispoof.interface.\"w*0\"]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"w*0\" is not an interface name, nor one followed by a single trailing *, the only wildcard",
		},
		"two trailing *": {
			exit + "[cap.antispoof.interface.\"wl**\"]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"wl**\" is not an interface name, nor one followed by a single trailing *, the only wildcard",
		},
		"a * alone": {
			exit + "[cap.antispoof.interface.\"*\"]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"*\" names every interface, which is cap.antispoof exempt",
		},
		"an empty name": {
			exit + "[cap.antispoof.interface.\"\"]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"\" is not an interface name",
		},
		"a name past the kernel's": {
			exit + "[cap.antispoof.interface.sixteen-bytes-xy]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"sixteen-bytes-xy\" is 16 bytes before any *, and an interface name is at most 15",
		},
		"a prefix past the kernel's": {
			exit + "[cap.antispoof.interface.\"sixteen-bytes-xy*\"]\nexempt = [\"203.0.113.0/25\"]\n",
			"egress: cap.antispoof.interface.\"sixteen-bytes-xy*\" is 16 bytes before any *, and an interface name is at most 15",
		},
		"an unknown key": {
			exit + "[cap.antispoof]\nexempt = [\"203.0.113.0/25\"]\noff = true\n",
			"cap.antispoof.off",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	for name, body := range map[string]string{
		"an exemption covering the overlay":      exit + "[cap.antispoof]\nexempt = [\"203.0.113.0/24\", \"3fff:a::/36\"]\n",
		"an interface's exemption alone":         exit + "[cap.antispoof.interface.eth1]\nexempt = [\"3fff:a::/48\"]\n",
		"a name of 15 bytes":                     exit + "[cap.antispoof.interface.fifteen-bytes-x]\nexempt = [\"203.0.113.0/25\"]\n",
		"a prefix of 15 bytes with its *":        exit + "[cap.antispoof.interface.\"fifteen-bytes-x*\"]\nexempt = [\"203.0.113.0/25\"]\n",
		"an exemption shared and an interface's": exit + antispoofTOML,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, body); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// A gateway announcing a range for the site behind it exempts the range from
// the interface its site is on: the shared list, which takes every interface
// outside the mesh, the uplink among them, is refused where it overlaps a
// range cap.route announces inside the overlay, by a message naming the
// interface form, while one overlapping only a host prefix it announces, one
// overlapping a range outside the overlay and one beside the range load
func TestSharedExemptionOverlappingAnAnnouncedRangeIsRefused(t *testing.T) {
	gateway := overlayTOML + nodeTOML + "[cap.route]\nannounce = [\"203.0.113.0/25\", \"203.0.113.200/32\", \"198.51.100.0/24\"]\n"
	for list, says := range map[string]string{
		`["203.0.113.0/26"]`: "config: cap.antispoof exempt 203.0.113.0/26 overlaps 203.0.113.0/25, which cap.route announces, and the shared list passes its sources from every interface outside the mesh, the uplink among them: write it under cap.antispoof.interface.<name>.exempt for the interface its hosts are on",
		`["203.0.113.0/24"]`: "config: cap.antispoof exempt 203.0.113.0/24 overlaps 203.0.113.0/25",
	} {
		if _, err := loadTOML(t, gateway+"[cap.antispoof]\nexempt = "+list+"\n"); err == nil || !strings.Contains(err.Error(), says) {
			t.Errorf("exempt %s was refused with %v, want %q", list, err, says)
		}
	}
	for name, block := range map[string]string{
		"the range under its site's interface": "[cap.antispoof.interface.eth1]\nexempt = [\"203.0.113.0/25\"]\n",
		"a shared entry beside the range":      "[cap.antispoof]\nexempt = [\"203.0.113.192/27\"]\n",
		"a shared entry over a host prefix":    "[cap.antispoof]\nexempt = [\"203.0.113.200/29\"]\n",
	} {
		if _, err := loadTOML(t, gateway+block); err != nil {
			t.Errorf("%s was refused: %v", name, err)
		}
	}
}

// An egress segment loads only beside the overlay bounding it, and an allow
// entry outside the overlay, which admits an inner source alone, loads only
// beside an IPv6 entry inside it to admit the outer source, which is always
// IPv6, and is refused for every other reason an entry inside is
func TestEgressSegmentIsRefusedOutsideTheOverlay(t *testing.T) {
	exit := overlayTOML + nodeTOML + egressExitTOML
	overlay := func(list string) string {
		return strings.Replace(exit, `overlay = ["203.0.113.0/24", "3fff:a::/36"]`, "overlay = "+list, 1)
	}
	// second is exit with an egress segment after the first, allowing list
	second := func(list string) string {
		return exit + "\n[[cap.segment.local]]\nsid = \"3fff:b:0:306::4\"\nbehavior = \"End.DT46\"\ndeliver = \"egress\"\nallow = " + list + "\n"
	}
	const alone = "lies outside overlay, which admits it as an inner source alone, and no IPv6 entry of the list lies inside the overlay to admit an outer source, which is always IPv6"
	for name, c := range map[string]struct{ body, says string }{
		"no overlay": {
			strings.Replace(exit, overlayTOML, "", 1),
			"config: cap.segment local 3fff:b:0:306::3 is written and overlay is absent",
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
		// a node with no egress segment writes the overlay on its own
		"overlay alone": overlayTOML + nodeTOML,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, body); err != nil {
				t.Errorf("refused: %v", err)
			}
		})
	}
}

// Every local segment loads only beside overlay, whose IPv6 prefixes are the
// only outer sources a local SID acts on, so a segment delivering to the mesh
// is refused without it, and with an overlay holding no IPv6 prefix, which
// would refuse every packet. A segment cap.segment refuses for itself is
// refused for that first, with or without the overlay. The loader decides
// alike on every platform, so a node with End segments and the overlay loads
// where no filter runs.
func TestEveryLocalSegmentNeedsTheOverlay(t *testing.T) {
	const mesh = "[[cap.segment.local]]\nsid = \"3fff:b:0:306::1\"\nbehavior = \"End\"\n"
	for name, c := range map[string]struct{ body, says string }{
		"a segment cap.segment refuses, and no overlay": {
			nodeTOML + mesh + "deliver = \"egress\"\n",
			"srv6: cap.segment local 3fff:b:0:306::1: deliver egress belongs to End.DT46, and End hands the packet to its next segment",
		},
		"no overlay": {
			nodeTOML + mesh,
			"config: cap.segment local 3fff:b:0:306::1 is written and overlay is absent, so nothing bounds the outer sources it acts on: write overlay with the prefixes the mesh numbers its nodes from",
		},
		"an overlay of IPv4 alone": {
			"overlay = [\"203.0.113.0/24\", \"198.18.0.0/15\"]\n" + nodeTOML + mesh,
			"config: overlay holds no IPv6 prefix, so cap.segment local 3fff:b:0:306::1 would refuse every packet, whose outer source is always IPv6",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadTOML(t, c.body); err == nil || err.Error() != c.says {
				t.Errorf("refused with %v, want %q", err, c.says)
			}
		})
	}
	const dt46 = "[[cap.segment.local]]\nsid = \"3fff:b:0:306::2\"\nbehavior = \"End.DT46\"\n"
	for name, c := range map[string]struct{ extension, text string }{
		"a segment beside an overlay holding an IPv6 prefix": {".toml", overlayTOML + nodeTOML + mesh},
		"End and End.DT46 with exemptions":                   {".toml", overlayTOML + nodeTOML + mesh + dt46 + antispoofTOML},
		"End and End.DT46 in yaml": {".yaml", nodeYAML + "overlay: [203.0.113.0/24, 3fff:a::/36]\ncap:\n  segment:\n    local:\n" +
			"      - {sid: 3fff:b:0:306::1, behavior: End}\n      - {sid: 3fff:b:0:306::2, behavior: End.DT46}\n"},
		// with no local segment the overlay may hold one family alone
		"an overlay of IPv4 alone on a node with no segment": {".toml", "overlay = [\"203.0.113.0/24\"]\n" + nodeTOML},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := load(t, c.extension, c.text)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if cfg.Border() == nil {
				t.Errorf("loaded with no filter configuration")
			}
		})
	}
}

// A class translating none loads only beside overlay, since a learned route
// reads alike for a node's own address and for a LAN another node advertises,
// and only the overlay tells the entry chain's none sets which to keep. A class
// translating auto loads without it.
func TestNoneClassNeedsTheOverlay(t *testing.T) {
	const exit = "\n[cap.egress]\nadvertise = [\"0.0.0.0/0\", \"::/0\"]\ntranslate = [\n  { from = \"3fff:a::/36\", to = \"%s\" },\n]\n"
	body := func(to string) string { return nodeTOML + strings.Replace(exit, "%s", to, 1) }
	const says = "config: cap.egress translate class 3fff:a::/36 is none and overlay is absent, so the entry chain cannot tell the mesh's node addresses from the LANs other nodes advertise, and would refuse every inbound connection to that class's hosts: write overlay with the prefixes the mesh numbers its nodes from"
	if _, err := loadTOML(t, body("none")); err == nil || err.Error() != says {
		t.Errorf("a none class without overlay was refused with %v, want %q", err, says)
	}
	if _, err := loadTOML(t, overlayTOML+body("none")); err != nil {
		t.Errorf("a none class beside overlay was refused: %v", err)
	}
	if _, err := loadTOML(t, body("auto")); err != nil {
		t.Errorf("an auto class without overlay was refused: %v", err)
	}
}

// A prefix this node advertises out of cap.egress lies outside the overlay,
// since the hosts behind it would arrive on a link outside the mesh with a
// mesh source and the filter would drop them, while the exit default
// overlaps everything and is left out
func TestAdvertiseOverlappingTheOverlayIsRefused(t *testing.T) {
	advertise := func(list string) string {
		return strings.Replace(overlayTOML+nodeTOML+egressExitTOML, "\n[cap.egress]\n", "\n[cap.egress]\nadvertise = "+list+"\n", 1)
	}
	for list, says := range map[string]string{
		`["203.0.113.128/25"]`: "config: cap.egress advertise 203.0.113.128/25 overlaps overlay 203.0.113.0/24, so the hosts behind this node arrive on a link outside the mesh with a mesh source and the antispoof filter drops them",
		`["203.0.0.0/8"]`:      "config: cap.egress advertise 203.0.0.0/8 overlaps overlay 203.0.113.0/24",
		`["3fff:a:1::/48"]`:    "config: cap.egress advertise 3fff:a:1::/48 overlaps overlay 3fff:a::/36",
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
