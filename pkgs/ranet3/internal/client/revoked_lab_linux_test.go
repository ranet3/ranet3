// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package client

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

func TestStartAndReloadWithoutRevokedKeys(t *testing.T) {
	for _, format := range []struct {
		name, extension string
		values          []string
		body            func(string, string, string) string
	}{
		{"toml", ".toml", []string{"", "revoked = []\n"}, func(key, trust, revoked string) string {
			return fmt.Sprintf("node = \"example/local\"\n[auth]\nkey = %q\ntrust = %q\n%s[link]\nport = 13000\nendpoints = [{serial = \"0\", family = \"ip4\"}]\n[dial]\nall = true\n", key, trust, revoked)
		}},
		{"yaml", ".yaml", []string{"", "  revoked: []\n", "  revoked: null\n"}, func(key, trust, revoked string) string {
			return fmt.Sprintf("node: example/local\nauth:\n  key: %q\n  trust: %q\n%slink:\n  port: 13000\n  endpoints: [{serial: \"0\", family: ip4}]\ndial:\n  all: true\n", key, trust, revoked)
		}},
		{"json", ".json", []string{"", `,"revoked":[]`, `,"revoked":null`}, func(key, trust, revoked string) string {
			return fmt.Sprintf(`{"node":"example/local","auth":{"key":%q,"trust":%q%s},"link":{"port":13000,"endpoints":[{"serial":"0","family":"ip4"}]},"dial":{"all":true}}`, key, trust, revoked)
		}},
	} {
		for i, value := range format.values {
			t.Run(fmt.Sprintf("%s/%d", format.name, i), func(t *testing.T) {
				_, privateKey, reg := runtimeFixture(t)
				directory := t.TempDir()
				key := filepath.Join(directory, "key.pem")
				store := filepath.Join(directory, "registry.json")
				path := filepath.Join(directory, "config"+format.extension)
				writeKey(t, key, privateKey)
				writeRegistry(t, store, reg)
				if err := os.WriteFile(path, []byte(format.body(key, store, value)), 0600); err != nil {
					t.Fatal(err)
				}
				cfg, err := config.Load(path)
				if err != nil || len(cfg.Auth.Revoked) != 0 {
					t.Fatalf("start configuration: %+v, %v", cfg, err)
				}
				var c *Client
				if os.Geteuid() == 0 {
					netnstest.EnterEmpty(t)
					c, err = New(cfg, events.New())
					if err != nil {
						t.Fatalf("start: %v", err)
					}
					t.Cleanup(func() { c.Close(); c.peers.Wait() })
				} else {
					c = testClientOf(t, cfg, privateKey, reg)
				}
				if err := c.ReloadFrom(path); err != nil {
					t.Fatalf("reload: %v", err)
				}
				if got := c.config().Auth.Revoked; len(got) != 0 {
					t.Fatalf("reloaded revoked keys: %d", len(got))
				}
			})
		}
	}
}
