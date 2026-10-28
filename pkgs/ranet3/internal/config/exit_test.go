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
// in each format. via is refused by name, and fallback is a key the decoder
// does not know.
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
			"toml", "via = [\"3fff:b:0:306::3\"]\n", "fallback = \"uplink\"\n",
			func(body string) string { return strings.Replace(body, "[cap.table]\n", "", 1) },
			func(body string) string {
				return strings.Replace(body, "[cap.border]\noverlay = [\"192.0.2.0/24\", \"3fff::/20\"]\n", "", 1)
			},
		},
		{
			"yaml", `{via: ["3fff:b:0:306::3"]}`, "{fallback: uplink}",
			func(body string) string { return strings.Replace(body, "  table: {}\n", "", 1) },
			func(body string) string {
				return strings.Replace(body, "  border:\n    overlay: [192.0.2.0/24, 3fff::/20]\n", "", 1)
			},
		},
		{
			"json", `{"via": ["3fff:b:0:306::3"]}`, `{"fallback": "uplink"}`,
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
				"fallback":      {exitLeafBody(c.format, c.fallback), "fallback"},
			} {
				if _, err := load(t, extension, refused.body); err == nil || !strings.Contains(err.Error(), refused.says) {
					t.Errorf("%s was refused with %v, want %q", name, err, refused.says)
				}
			}
		})
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
