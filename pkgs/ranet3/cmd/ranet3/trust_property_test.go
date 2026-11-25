// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestTrustSigningRoundTripProperty(t *testing.T) {
	keyPath, _, public := trustSigningFixture(t)
	pbt.Check(t, func(ht *hegel.T) {
		count := hegel.Draw(ht, pbt.Spanning(0, 2))
		port := hegel.Draw(ht, pbt.Spanning(1, 65535))
		id := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		address := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		keyed := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
		endpoint := "{"
		if address {
			endpoint += `"address":"192.0.2.1",`
		}
		endpoint += `"family":"ip4",`
		if id {
			endpoint += `"id":"a",`
		}
		endpoint += fmt.Sprintf(`"port":%d}`, port)
		document := `{"nodes":[]}`
		if count > 0 {
			document = `{"nodes":[{"endpoints":[` + endpoint + `]`
			if keyed {
				document += `,"key":"` + public + `"`
			}
			document += `,"name":"example/gateway"}`
			if count > 1 {
				document += `,{"endpoints":[],"name":"example/relay"}`
			}
			document += `]}`
		}
		dir := t.TempDir()
		input := filepath.Join(dir, "document.json")
		if err := os.WriteFile(input, []byte(document), 0600); err != nil {
			ht.Fatal(err)
		}
		first := filepath.Join(dir, "first.cose")
		if _, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", first, input); err != nil {
			ht.Fatalf("init %s: %s: %v", document, stderr, err)
		}
		shown, stderr, err := runTrustCommand("trust", "show", "--authority", public, first)
		if err != nil || shown != document {
			ht.Fatalf("show(init(J)) = %q, want %q: %s, %v", shown, document, stderr, err)
		}
		second := filepath.Join(dir, "second.cose")
		if _, stderr, err := runTrustCommand("trust", "sign", "--key", keyPath, "--previous", first, "--authority", public, "--out", second, input); err != nil {
			ht.Fatalf("sign %s: %s: %v", document, stderr, err)
		}
		shown, stderr, err = runTrustCommand("trust", "show", "--authority", public, second)
		if err != nil || shown != document {
			ht.Fatalf("show(sign(J, parent)) = %q, want %q: %s, %v", shown, document, stderr, err)
		}
	})
}
