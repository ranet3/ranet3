// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func TestTrustStoredLExcludesAuthorityAfterEntryRemoval(t *testing.T) {
	f := localTrustFixtureOf(t)
	f.cfg.Auth.Authority = []string{base64.StdEncoding.EncodeToString(f.newKey.DER)}
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(f.oldKey.DER), Height: 1}}
	f.writeStore(t, f.oldKey, f.first, f.firstProof, nil)
	if err := os.WriteFile(f.cfg.Auth.Trust, f.replacement, 0600); err != nil {
		t.Fatal(err)
	}
	first, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
	if err != nil || first.Row != trustdoc.D9 || first.Prepared == nil || len(first.Record.List) != 1 || first.Record.List[0].Floor != 1 {
		t.Fatalf("record initial E and recover: %+v, %v", first, err)
	}
	path := filepath.Join(f.dir, trustStoreName)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.cfg.Auth.Revoked = nil
	f.cfg.Auth.Authority = append(f.cfg.Auth.Authority, base64.StdEncoding.EncodeToString(f.oldKey.DER))
	if err := os.WriteFile(f.cfg.Auth.Trust, f.first, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := LoadTrust(f.cfg, f.dir, first.Record, first.Prepared, nil)
	if err != nil || result.Row != trustdoc.D13 || result.Offered != nil || result.Prepared != nil || result.Held != first.Prepared || len(result.Record.List) != 1 || result.Record.List[0].Floor != 1 || result.Refused == nil || result.Refused.Reason != "not verified" {
		t.Fatalf("stored L must outlive removed E and exclude reintroduced K: %+v, %v", result, err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("excluded signer changed store: %x, %v", after, err)
	}
}

func TestTrustUnreadableStorePrecedesSixtyFifthKey(t *testing.T) {
	f := localTrustFixtureOf(t)
	keys := make([]trustdoc.CompromisedKey, 64)
	for i := range keys {
		_, key := localAuthority(t, byte(i))
		keys[i] = trustdoc.CompromisedKey{Key: key}
	}
	slices.SortFunc(keys, func(a, b trustdoc.CompromisedKey) int { return bytes.Compare(a.Key.DER, b.Key.DER) })
	valid, err := trustdoc.EncodeStore(trustdoc.StoreImage{Compromised: keys})
	if err != nil {
		t.Fatal(err)
	}
	_, extra := localAuthority(t, 0x90)
	f.cfg.Auth.Revoked = []config.RevokedKey{{Key: base64.StdEncoding.EncodeToString(extra.DER), Height: 1}}
	path := filepath.Join(f.dir, trustStoreName)
	for _, tc := range []struct {
		name string
		body []byte
		row  trustdoc.Row
	}{
		{"readable 64", valid, trustdoc.C1},
		{"unreadable before cap", []byte{0xa0}, trustdoc.D14},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.body, 0600); err != nil {
				t.Fatal(err)
			}
			result, err := LoadTrust(f.cfg, f.dir, nil, nil, nil)
			if err != nil || result.Row != tc.row || result.Prepared != nil || result.Status(f.cfg) != nil {
				t.Fatalf("step 3a then 3b: %+v, %v", result, err)
			}
			if tc.row == trustdoc.D14 && result.Record != nil || tc.row == trustdoc.C1 && (result.Record == nil || result.Failure != "config: compromised key list has 65 entries, at most 64 allowed") {
				t.Fatalf("bad store precedes cap, readable store reaches cap: %+v", result)
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, tc.body) {
				t.Fatalf("prewrite row changed bytes: %x, %v", after, err)
			}
		})
	}
}
