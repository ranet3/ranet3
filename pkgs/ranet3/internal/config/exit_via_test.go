// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/srv6"
)

// viaNode is a node writing cap.table's addresses, cap.border's overlay, cap.segment's source and End segments where given, and cap.exit via
type viaNode struct {
	addresses, overlay []string
	source             string
	local, via         []string
}

// viaFixture is a node in mode 3 whose outer source comes from its IPv6 overlay address, past an IPv4 one and an IPv6 one outside the overlay
func viaFixture(via ...string) viaNode {
	return viaNode{
		addresses: []string{"192.0.2.2/24", "2001:db8::2/64", "3fff::2/20"},
		overlay:   []string{"192.0.2.0/24", "3fff::/20"},
		via:       via,
	}
}

// file is n as format spells it, with the extension it is written under
func (n viaNode) file(format string) (string, string) {
	list := func(entries []string, quote string) string {
		quoted := make([]string, len(entries))
		for i, entry := range entries {
			quoted[i] = quote + entry + quote
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	}
	switch format {
	case "toml":
		body := nodeTOML + "[cap.table]\naddresses = " + list(n.addresses, `"`) + "\n[cap.border]\noverlay = " + list(n.overlay, `"`) + "\n"
		if n.source != "" || len(n.local) != 0 {
			body += "[cap.segment]\n"
			if n.source != "" {
				body += "source = \"" + n.source + "\"\n"
			}
			for _, sid := range n.local {
				body += "[[cap.segment.local]]\nsid = \"" + sid + "\"\nbehavior = \"End\"\n"
			}
		}
		return ".toml", body + "[cap.exit]\nvia = " + list(n.via, `"`) + "\n"
	case "yaml":
		body := nodeYAML + "cap:\n  table: {addresses: " + list(n.addresses, "") + "}\n  border: {overlay: " + list(n.overlay, "") + "}\n"
		if n.source != "" || len(n.local) != 0 {
			body += "  segment:\n"
			if n.source != "" {
				body += "    source: " + n.source + "\n"
			}
			if len(n.local) != 0 {
				body += "    local:\n"
			}
			for _, sid := range n.local {
				body += "      - {sid: " + sid + ", behavior: End}\n"
			}
		}
		return ".yaml", body + "  exit: {via: " + list(n.via, "") + "}\n"
	}
	var segment []string
	if n.source != "" {
		segment = append(segment, `"source": "`+n.source+`"`)
	}
	if len(n.local) != 0 {
		var local []string
		for _, sid := range n.local {
			local = append(local, `{"sid": "`+sid+`", "behavior": "End"}`)
		}
		segment = append(segment, `"local": [`+strings.Join(local, ", ")+`]`)
	}
	segmentBlock := ""
	if len(segment) != 0 {
		segmentBlock = `"segment": {` + strings.Join(segment, ", ") + `}, `
	}
	return ".json", fmt.Sprintf(`{
  "node": "example/laptop",
  "auth": {"key": "key.pem", "trust": "trust.json"},
  "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]},
  "dial": {"to": ["example/gateway"]},
  "cap": {"table": {"addresses": %s}, "border": {"overlay": %s}, %s"exit": {"via": %s}}
}`, list(n.addresses, `"`), list(n.overlay, `"`), segmentBlock, list(n.via, `"`))
}

var formats = []string{"toml", "yaml", "json"}

// loadNode loads n as format spells it
func loadNode(t testing.TB, n viaNode, format string) (*Config, error) {
	t.Helper()
	extension, body := n.file(format)
	return load(t, extension, body)
}

// cap.exit via reads alike in each format, reaches the reconciler in the order written, and becomes the steering table's default policy
// sent from the first IPv6 cap.table address inside the overlay, past an IPv4 one and an IPv6 one outside it, or from cap.segment source where written
// the device MTU takes the path's overhead off, and the trie claims nothing for it
func TestExitViaReadsAlikeInEveryFormat(t *testing.T) {
	via := []string{"3fff:b:0:306::3", "3fff:b:0:206::1"}
	want := []netip.Addr{netip.MustParseAddr(via[0]), netip.MustParseAddr(via[1])}
	for _, format := range formats {
		for source, node := range map[string]viaNode{
			"3fff::2":         viaFixture(via...),
			"3fff:b:0:100::1": func() viaNode { n := viaFixture(via...); n.source = "3fff:b:0:100::1"; return n }(),
		} {
			cfg, err := loadNode(t, node, format)
			if err != nil {
				t.Fatalf("%s with source %s: %v", format, source, err)
			}
			mode := cfg.ReconcilerTable().Mode()
			if mode == nil || len(mode.Via) != 2 || mode.Via[0].Addr != want[0] || mode.Via[1].Addr != want[1] {
				t.Errorf("%s: cap.exit via reaches the reconciler as %+v", format, mode)
			}
			_, steering, err := cfg.SegmentTables()
			if err != nil {
				t.Fatal(err)
			}
			policy := steering.Default()
			if policy == nil || policy.Source != netip.MustParseAddr(source) || !slices.Equal(policy.Path, want) {
				t.Errorf("%s: the default policy is %+v, want %v from %s", format, policy, want, source)
			}
			if got := steering.Lookup(netip.MustParseAddr("3fff::2"), netip.MustParseAddr("2001:db8::9")); got != nil {
				t.Errorf("%s: the trie claimed a packet for %v", format, got)
			}
			if mtu, err := steering.CheckMTU(cfg.Link.SessionMTU()); err != nil || mtu != cfg.Link.SessionMTU()-srv6.Overhead(2) {
				t.Errorf("%s: the device runs at %d (%v), want link.mtu %d less %d", format, mtu, err, cfg.Link.SessionMTU(), srv6.Overhead(2))
			}
		}
	}
}

// each refusal of cap.exit via reaches the loader in each format
// a SID no packet can be addressed to, more than 16, one written twice, one of this node's own first or last, no IPv6 prefix in the overlay
// no outer source, and a cap.segment source outside the overlay
// while a SID of this node's own between the first and the last, and seventeen less one, load
func TestExitViaRefusalsReachTheLoader(t *testing.T) {
	sixteen := make([]string, 17)
	for i := range sixteen {
		sixteen[i] = fmt.Sprintf("3fff:b:0:%x::1", 0x300+i)
	}
	for name, c := range map[string]struct {
		node viaNode
		says string
	}{
		"an IPv4 SID":     {viaFixture("192.0.2.9"), "cap.exit via: srv6: segment 192.0.2.9 cannot address a segment routed packet"},
		"a multicast SID": {viaFixture("ff02::1"), "cap.exit via: srv6: segment ff02::1 cannot address a segment routed packet"},
		"17 SIDs":         {viaFixture(sixteen...), "cap.exit via: srv6: 17 segments is more than the 16 this node will build"},
		"a SID twice":     {viaFixture("3fff:b:0:306::3", "3fff:b:0:206::1", "3fff:b:0:306::3"), "kernel: cap.exit via names 3fff:b:0:306::3 twice, which sends the packet around a loop"},
		"its own first SID": {
			func() viaNode {
				n := viaFixture("3fff:b:0:106::1", "3fff:b:0:306::3")
				n.local = []string{"3fff:b:0:106::1"}
				return n
			}(),
			"config: cap.exit via starts or ends at 3fff:b:0:106::1, a segment of this node's own cap.segment local, which acts only on a packet another node sends it",
		},
		"its own last SID": {
			func() viaNode {
				n := viaFixture("3fff:b:0:306::3", "3fff:b:0:106::1")
				n.local = []string{"3fff:b:0:106::1"}
				return n
			}(),
			"config: cap.exit via starts or ends at 3fff:b:0:106::1, a segment of this node's own cap.segment local, which acts only on a packet another node sends it",
		},
		"no IPv6 overlay": {
			func() viaNode { n := viaFixture("3fff:b:0:306::3"); n.overlay = []string{"192.0.2.0/24"}; return n }(),
			"config: cap.exit via is written and cap.border overlay holds no IPv6 prefix, so every segment refuses the path's outer source, which is always IPv6",
		},
		"no outer source": {
			func() viaNode {
				n := viaFixture("3fff:b:0:306::3")
				n.addresses = []string{"192.0.2.2/24", "2001:db8::2/64"}
				return n
			}(),
			"config: cap.exit via is written and neither cap.segment source nor an IPv6 cap.table address inside cap.border overlay gives the path an outer source: write cap.segment source",
		},
		"a source outside the overlay": {
			func() viaNode { n := viaFixture("3fff:b:0:306::3"); n.source = "2001:db8::2"; return n }(),
			"config: cap.segment source 2001:db8::2 lies outside cap.border overlay, so every segment of cap.exit via refuses the path's packets by their outer source",
		},
	} {
		for _, format := range formats {
			if _, err := loadNode(t, c.node, format); err == nil || err.Error() != c.says {
				t.Errorf("%s in %s was refused with %v, want %q", name, format, err, c.says)
			}
		}
	}
	middle := viaFixture("3fff:b:0:306::3", "3fff:b:0:106::1", "3fff:b:0:206::1")
	middle.local = []string{"3fff:b:0:106::1"}
	for _, format := range formats {
		if _, err := loadNode(t, middle, format); err != nil {
			t.Errorf("its own SID in the middle in %s was refused: %v", format, err)
		}
	}
	// 16 segments take 304 bytes, which a 1400 byte link leaves under 1280
	extension, body := viaFixture(sixteen[:16]...).file("toml")
	if _, err := load(t, extension, strings.Replace(body, "port = 13000\n", "port = 13000\nmtu = 1584\n", 1)); err != nil {
		t.Errorf("16 SIDs were refused: %v", err)
	}
}

// besideVia is n's file in format with fallback, where it is not empty, and inbound written beside cap.exit via
func besideVia(n viaNode, format, fallback string, inbound []string) (string, string) {
	extension, body := n.file(format)
	var toml, yaml, json []string
	if fallback != "" {
		toml, yaml, json = append(toml, `fallback = "`+fallback+`"`+"\n"), append(yaml, "fallback: "+fallback+", "), append(json, `"fallback": "`+fallback+`", `)
	}
	if len(inbound) != 0 {
		toml = append(toml, `inbound = ["`+strings.Join(inbound, `", "`)+`"]`+"\n")
		yaml = append(yaml, "inbound: ["+strings.Join(inbound, ", ")+"], ")
		json = append(json, `"inbound": ["`+strings.Join(inbound, `", "`)+`"], `)
	}
	switch format {
	case "toml":
		return extension, strings.Replace(body, "[cap.exit]\n", "[cap.exit]\n"+strings.Join(toml, ""), 1)
	case "yaml":
		return extension, strings.Replace(body, "  exit: {", "  exit: {"+strings.Join(yaml, ""), 1)
	}
	return extension, strings.Replace(body, `"exit": {`, `"exit": {`+strings.Join(json, ""), 1)
}

// cap.exit via with fallback unwritten runs fallback = "none" in each format, the switch mode 3 defaults to, and takes inbound
// beside it, where fallback = "uplink" written lets the host's traffic leave by its own default and refuses inbound as mode 2 does
func TestExitViaRefusesUnlessFallbackSaysUplink(t *testing.T) {
	const inboundRefused = "kernel: cap.exit inbound lists the services that answer beyond the LAN while fallback = \"none\" refuses the rest, and fallback is not \"none\": write fallback = \"none\" or remove inbound"
	node := viaFixture("3fff:b:0:306::3")
	for _, format := range formats {
		for _, c := range []struct {
			fallback string
			inbound  []string
			refuses  bool
			says     string
		}{
			{"", nil, true, ""},
			{"", []string{"22/tcp"}, true, ""},
			{"none", nil, true, ""},
			{"uplink", nil, false, ""},
			{"uplink", []string{"22/tcp"}, false, inboundRefused},
		} {
			extension, body := besideVia(node, format, c.fallback, c.inbound)
			cfg, err := load(t, extension, body)
			if c.says != "" {
				if err == nil || err.Error() != c.says {
					t.Errorf("%s with fallback %q and inbound %v was refused with %v, want %q", format, c.fallback, c.inbound, err, c.says)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s with fallback %q and inbound %v: %v", format, c.fallback, c.inbound, err)
			}
			if mode := cfg.ReconcilerTable().Mode(); mode == nil || mode.Refuses() != c.refuses {
				t.Errorf("%s with fallback %q runs %+v, which refuses %v, want %v", format, c.fallback, mode, mode != nil && mode.Refuses(), c.refuses)
			}
		}
	}
}

// a path long enough to take the device under 1280 bytes is refused by the MTU's arithmetic, which counts via beside cap.segment steer
func TestExitViaCountsInTheDeviceMTU(t *testing.T) {
	node := viaFixture("3fff:b:0:306::3", "3fff:b:0:206::1")
	extension, body := node.file("toml")
	// two segments take 80 bytes, so 1359 leaves 1279
	body = strings.Replace(body, "port = 13000\n", "port = 13000\nmtu = 1359\n", 1)
	if _, err := load(t, extension, body); err == nil || !strings.Contains(err.Error(), "cap.exit via takes 80 bytes, leaving a 1279 byte device") {
		t.Errorf("a path leaving a 1279 byte device was refused with %v", err)
	}
	body = strings.Replace(body, "mtu = 1359\n", "mtu = 1360\n", 1)
	if _, err := load(t, extension, body); err != nil {
		t.Errorf("a path leaving a 1280 byte device was refused: %v", err)
	}
}
