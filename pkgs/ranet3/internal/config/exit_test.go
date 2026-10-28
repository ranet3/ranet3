// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// exitLeaf is a node writing cap.table, cap.border and cap.exit in each format, cap.exit's body given as each format spells it
func exitLeaf(format, exit string) (string, string) {
	switch format {
	case "toml":
		return ".toml", nodeTOML + "[cap.table]\n[cap.border]\noverlay = [\"192.0.2.0/24\", \"3fff::/20\"]\n[cap.exit]\n" + exit
	case "yaml":
		return ".yaml", nodeYAML + "cap:\n  table: {}\n  border:\n    overlay: [192.0.2.0/24, 3fff::/20]\n  exit: " + exit + "\n"
	}
	return ".json", fmt.Sprintf(`{
  "node": "example/laptop",
  "auth": {"key": "key.pem", "trust": "trust.json"},
  "link": {"port": 13000, "endpoints": [{"serial": "0", "family": "ip4"}]},
  "dial": {"to": ["example/gateway"]},
  "cap": {"table": {}, "border": {"overlay": ["192.0.2.0/24", "3fff::/20"]}, "exit": %s}
}`, exit)
}

// cap.exit written with no key turns the mode on, and forward reads alike in each format
// the reconciler's table carries the block as written, and without cap.exit it carries none
func TestExitReadsAlikeInEveryFormat(t *testing.T) {
	for _, c := range []struct {
		format, bare, forwarding string
	}{
		{"toml", "", "forward = [\"docker0\", \"br-*\"]\n"},
		{"yaml", "{}", "{forward: [docker0, \"br-*\"]}"},
		{"json", "{}", `{"forward": ["docker0", "br-*"]}`},
	} {
		t.Run(c.format, func(t *testing.T) {
			for body, want := range map[string][]string{c.bare: nil, c.forwarding: {"docker0", "br-*"}} {
				extension, text := exitLeaf(c.format, body)
				cfg, err := load(t, extension, text)
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Cap.Exit == nil || !slices.Equal(cfg.Cap.Exit.Forward, want) {
					t.Errorf("cap.exit %q read as %+v, want forward %v", body, cfg.Cap.Exit, want)
				}
				if mode := cfg.ReconcilerTable().Mode(); mode == nil || !slices.Equal(mode.Forward, want) {
					t.Errorf("cap.exit %q reaches the reconciler as %+v", body, mode)
				}
			}
		})
	}
	cfg, err := loadTOML(t, nodeTOML+"[cap.table]\n")
	if err != nil {
		t.Fatal(err)
	}
	if mode := cfg.ReconcilerTable().Mode(); mode != nil {
		t.Errorf("a node with no cap.exit runs the mode %+v", mode)
	}
}

// exitLeafBody is exitLeaf's file alone
func exitLeafBody(format, exit string) string {
	_, body := exitLeaf(format, exit)
	return body
}

// cap.exit is refused with no cap.table, whose reconciler writes the mode's
// rules, and with no cap.border, whose overlay those rules keep off the uplink,
// in each format. via is refused by name, and fallback by its value when it is
// neither "uplink" nor "none".
func TestExitRefusalsReachTheLoader(t *testing.T) {
	const (
		noTable  = "config: cap.exit is written and cap.table is absent, so no reconciler writes the rules the mode is made of: add cap.table"
		noBorder = "config: cap.exit is written and cap.border is absent, so the mode's rules cannot keep the overlay's sources off the uplink: add cap.border with the prefixes the mesh numbers its nodes from"
		via      = "cap.exit via names a path to one exit, which this version does not take: write cap.exit without via, which follows the mesh's default of lowest metric"
	)
	for _, c := range []struct {
		format, via, fallback string
		dropTable, dropBorder func(string) string
	}{
		{
			"toml", "via = [\"3fff:b:0:306::3\"]\n", "fallback = \"lan\"\n",
			func(body string) string { return strings.Replace(body, "[cap.table]\n", "", 1) },
			func(body string) string {
				return strings.Replace(body, "[cap.border]\noverlay = [\"192.0.2.0/24\", \"3fff::/20\"]\n", "", 1)
			},
		},
		{
			"yaml", `{via: ["3fff:b:0:306::3"]}`, "{fallback: lan}",
			func(body string) string { return strings.Replace(body, "  table: {}\n", "", 1) },
			func(body string) string {
				return strings.Replace(body, "  border:\n    overlay: [192.0.2.0/24, 3fff::/20]\n", "", 1)
			},
		},
		{
			"json", `{"via": ["3fff:b:0:306::3"]}`, `{"fallback": "lan"}`,
			func(body string) string { return strings.Replace(body, `"table": {}, `, "", 1) },
			func(body string) string {
				return strings.Replace(body, `"border": {"overlay": ["192.0.2.0/24", "3fff::/20"]}, `, "", 1)
			},
		},
	} {
		t.Run(c.format, func(t *testing.T) {
			bare := map[string]string{"toml": "", "yaml": "{}", "json": "{}"}[c.format]
			extension, body := exitLeaf(c.format, bare)
			for name, refused := range map[string]struct{ body, says string }{
				"no cap.table":  {c.dropTable(body), noTable},
				"no cap.border": {c.dropBorder(body), noBorder},
				"via":           {exitLeafBody(c.format, c.via), via},
				"fallback":      {exitLeafBody(c.format, c.fallback), `kernel: cap.exit fallback "lan" is neither "uplink" nor "none"`},
			} {
				if _, err := load(t, extension, refused.body); err == nil || !strings.Contains(err.Error(), refused.says) {
					t.Errorf("%s was refused with %v, want %q", name, err, refused.says)
				}
			}
		})
	}
}

// cap.exit is refused on an exit in each format, each reason a node is one by
// its own clause of the refusal's message
func TestExitIsRefusedOnAnExit(t *testing.T) {
	const refusal = "config: cap.exit sends this node's own traffic out through another exit, and this node is an exit (%s), whose own traffic and whose egress leave by its own uplink: remove cap.exit, or stop offering the exit"
	for _, c := range []struct {
		reason, clause      string
		toml, yaml, jsonish string
	}{
		{
			"an advertised default", "cap.egress advertises 0.0.0.0/0",
			"\n[cap.egress]\nadvertise = [\"0.0.0.0/0\"]\n",
			"{}\n  egress: {advertise: [0.0.0.0/0]}",
			`{}, "egress": {"advertise": ["0.0.0.0/0"]}`,
		},
		{
			"an announcement that counts as a default", "cap.route announces 2000::/3, which counts as a default",
			"\n[cap.route]\nannounce = [\"2000::/3\"]\n",
			"{}\n  route: {announce: [\"2000::/3\"]}",
			`{}, "route": {"announce": ["2000::/3"]}`,
		},
		{
			"an egress segment", "cap.segment local 3fff:b:0:306::3 delivers to egress",
			"\n[cap.egress]\n[[cap.segment.local]]\nsid = \"3fff:b:0:306::3\"\nbehavior = \"End.DT46\"\ndeliver = \"egress\"\nallow = [\"192.0.2.0/24\", \"3fff:a::/36\"]\n",
			"{}\n  egress: {}\n  segment:\n    local:\n      - {sid: \"3fff:b:0:306::3\", behavior: End.DT46, deliver: egress, allow: [192.0.2.0/24, \"3fff:a::/36\"]}",
			`{}, "egress": {}, "segment": {"local": [{"sid": "3fff:b:0:306::3", "behavior": "End.DT46", "deliver": "egress", "allow": ["192.0.2.0/24", "3fff:a::/36"]}]}`,
		},
	} {
		for format, body := range map[string]string{"toml": c.toml, "yaml": c.yaml, "json": c.jsonish} {
			extension, text := exitLeaf(format, body)
			want := fmt.Sprintf(refusal, c.clause)
			if _, err := load(t, extension, text); err == nil || err.Error() != want {
				t.Errorf("cap.exit beside %s in %s was refused with %v, want %q", c.reason, format, err, want)
			}
		}
	}
}

// forward refuses an entry that can name no link, a malformed pattern with
// path.ErrBadPattern among them, and lo by name, and takes every other pattern
// and name, a pattern matching lo among them
func TestExitForwardRefusesWhatNamesNoLink(t *testing.T) {
	forward := func(entry string) string {
		return exitLeafBody("toml", "forward = ['docker0', '"+entry+"']\n")
	}
	for entry, says := range map[string]string{
		"":      "kernel: cap.exit forward holds an empty entry, which names no link",
		"br-[a": `kernel: cap.exit forward "br-[a": syntax error in pattern`,
		`eth\`:  `kernel: cap.exit forward "eth\\": syntax error in pattern`,
		"[]":    `kernel: cap.exit forward "[]": syntax error in pattern`,
		"[a-]":  `kernel: cap.exit forward "[a-]": syntax error in pattern`,
		"lo":    "kernel: cap.exit forward lo is the loopback link, whose traffic is the host's own and follows the mode already",
	} {
		_, err := loadTOML(t, forward(entry))
		if err == nil || err.Error() != says {
			t.Errorf("forward %q was refused with %v, want %q", entry, err, says)
		}
		if strings.Contains(says, "syntax error") && !errors.Is(err, path.ErrBadPattern) {
			t.Errorf("forward %q was refused with %v, which is not path.ErrBadPattern", entry, err)
		}
	}
	for _, entry := range []string{"abcdefghijklmno", "docker*", "br-?", "[a-c]x", "[^a]*", "lo*", `eth\0`, "veth.1"} {
		if _, err := loadTOML(t, forward(entry)); err != nil {
			t.Errorf("forward %q was refused: %v", entry, err)
		}
	}
}

// fallback and inbound read alike in each format, and the reconciler's mode
// carries them. fallback unwritten is "uplink" and refuses nothing.
func TestFallbackAndInboundReadAlikeInEveryFormat(t *testing.T) {
	for format, body := range map[string]string{
		"toml": "fallback = \"none\"\ninbound = [\"60000-61000/udp\", \"22/tcp\"]\n",
		"yaml": `{fallback: none, inbound: [60000-61000/udp, 22/tcp]}`,
		"json": `{"fallback": "none", "inbound": ["60000-61000/udp", "22/tcp"]}`,
	} {
		extension, text := exitLeaf(format, body)
		cfg, err := load(t, extension, text)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		mode := cfg.ReconcilerTable().Mode()
		if mode == nil || mode.Fallback != kernel.FallbackNone || !mode.Refuses() || !slices.Equal(mode.Inbound, []string{"60000-61000/udp", "22/tcp"}) {
			t.Errorf("%s: cap.exit %s reaches the reconciler as %+v", format, body, mode)
		}
		if normal := mode.Normalized().Inbound; !slices.Equal(normal, []string{"22/tcp", "60000-61000/udp"}) {
			t.Errorf("%s: inbound normalized to %q", format, normal)
		}
	}
	cfg, err := loadTOML(t, exitLeafBody("toml", ""))
	if err != nil {
		t.Fatal(err)
	}
	if mode := cfg.ReconcilerTable().Mode(); mode == nil || mode.Fallback != "" || mode.Refuses() || mode.Inbound != nil {
		t.Errorf("cap.exit with neither key reaches the reconciler as %+v", mode)
	}
	cfg, err = loadTOML(t, exitLeafBody("toml", "fallback = \"uplink\"\n"))
	if err != nil || cfg.Cap.Exit.Refuses() {
		t.Errorf("fallback = \"uplink\" read as %+v, %v", cfg, err)
	}
}

// fallback takes "uplink" and "none" alone. inbound is refused unless
// fallback is "none", and an entry is refused when it is malformed, names
// port 0, a port past 65535 or a protocol other than tcp and udp, runs
// downward, or names the ports of an earlier entry again. Ranges that overlap
// or touch are taken, and normalization joins them.
func TestFallbackAndInboundRefusals(t *testing.T) {
	inbound := func(fallback string, entries ...string) string {
		body := "inbound = ['" + strings.Join(entries, "', '") + "']\n"
		if fallback != "" {
			body = "fallback = \"" + fallback + "\"\n" + body
		}
		return exitLeafBody("toml", body)
	}
	const notNone = `kernel: cap.exit inbound lists the services that answer beyond the LAN while fallback = "none" refuses the rest, and fallback is not "none": write fallback = "none" or remove inbound`
	for name, refused := range map[string]struct{ body, says string }{
		"fallback off its values": {exitLeafBody("toml", "fallback = \"None\"\n"), `kernel: cap.exit fallback "None" is neither "uplink" nor "none"`},
		"fallback empty":          {exitLeafBody("toml", "fallback = \"\"\ninbound = ['22/tcp']\n"), notNone},
		"under uplink":            {inbound("uplink", "22/tcp"), notNone},
		"under no fallback":       {inbound("", "22/tcp"), notNone},
		"no protocol":             {inbound("none", "22"), `kernel: cap.exit inbound "22" is not <port>/<protocol> or <first>-<last>/<protocol>`},
		"icmp":                    {inbound("none", "8/icmp"), `kernel: cap.exit inbound "8/icmp" names the protocol "icmp", where inbound takes tcp or udp`},
		"protocol in capitals":    {inbound("none", "22/TCP"), `kernel: cap.exit inbound "22/TCP" names the protocol "TCP", where inbound takes tcp or udp`},
		"empty protocol":          {inbound("none", "22/"), `kernel: cap.exit inbound "22/" names the protocol "", where inbound takes tcp or udp`},
		"port 0":                  {inbound("none", "0/udp"), `kernel: cap.exit inbound "0/udp" names port 0, which no service listens on`},
		"range from port 0":       {inbound("none", "0-10/tcp"), `kernel: cap.exit inbound "0-10/tcp" names port 0, which no service listens on`},
		"past 65535":              {inbound("none", "65536/tcp"), `kernel: cap.exit inbound "65536/tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"no port":                 {inbound("none", "/tcp"), `kernel: cap.exit inbound "/tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"open range":              {inbound("none", "22-/tcp"), `kernel: cap.exit inbound "22-/tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"signed":                  {inbound("none", "+22/tcp"), `kernel: cap.exit inbound "+22/tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"spaced":                  {inbound("none", "22 /tcp"), `kernel: cap.exit inbound "22 /tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"a name":                  {inbound("none", "ssh/tcp"), `kernel: cap.exit inbound "ssh/tcp" is not <port>/<protocol> or <first>-<last>/<protocol>, each port from 1 to 65535`},
		"downward":                {inbound("none", "61000-60000/udp"), `kernel: cap.exit inbound "61000-60000/udp" runs from 61000 down to 60000: write the lower port first`},
		"twice":                   {inbound("none", "22/tcp", "53/udp", "22/tcp"), `kernel: cap.exit inbound "22/tcp" is written twice, the second time as "22/tcp"`},
		"twice as a range":        {inbound("none", "22/tcp", "22-22/tcp"), `kernel: cap.exit inbound "22/tcp" is written twice, the second time as "22-22/tcp"`},
	} {
		if _, err := loadTOML(t, refused.body); err == nil || err.Error() != refused.says {
			t.Errorf("%s was refused with %v, want %q", name, err, refused.says)
		}
	}
	for _, entries := range [][]string{
		{"1/tcp", "65535/udp", "1-65535/udp"},
		{"22/tcp", "22/udp"},
		{"20-30/tcp", "25/tcp", "31-40/tcp"},
	} {
		if _, err := loadTOML(t, inbound("none", entries...)); err != nil {
			t.Errorf("inbound %q was refused: %v", entries, err)
		}
	}
}
