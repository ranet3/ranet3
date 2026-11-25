// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustCurveFacts(t *testing.T) {
	_, input, _ := trustSigningFixture(t)
	for _, test := range []struct{ keyType, algorithm string }{
		{"p256", "ESP256 (-9)"},
		{"p384", "ESP384 (-51)"},
	} {
		t.Run(test.keyType, func(t *testing.T) {
			keyPath := filepath.Join(t.TempDir(), "authority.pem")
			public, stderr, err := runTrustCommand("key", "generate", "--type", test.keyType, "--out", keyPath)
			if err != nil || stderr != "" {
				t.Fatalf("generate %s: %q, %v", test.keyType, stderr, err)
			}
			key, err := trust.ParseAuthorityKey(strings.TrimSpace(public))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "trust.cose")
			if out, stderr, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", path, input); err != nil || out != "" {
				t.Fatalf("init %s: stdout %q, stderr %q, error %v", test.keyType, out, stderr, err)
			}
			verified, err := trust.ReadSignedFile(path, []trust.AuthorityKey{key})
			if err != nil {
				t.Fatal(err)
			}
			fingerprint := sha256.Sum256(key.DER)
			want := fmt.Sprintf("height 1\nprevious none\ndigest %x\nalgorithm %s\nkey SHA256:%s\n", verified.Digest, test.algorithm, base64.RawStdEncoding.EncodeToString(fingerprint[:]))
			out, stderr, err := runTrustCommand("trust", "show", "--authority", strings.TrimSpace(public), path)
			if err != nil || out != `{"nodes":[]}` || stderr != want {
				t.Fatalf("show %s: stdout %q, stderr %q, error %v", test.keyType, out, stderr, err)
			}
			out, stderr, err = runTrustCommand("trust", "verify", "--authority", strings.TrimSpace(public), path)
			if err != nil || out != "" || stderr != want {
				t.Fatalf("verify %s: stdout %q, stderr %q, error %v", test.keyType, out, stderr, err)
			}
		})
	}
}

func TestTrustRepeatedAuthorityKeys(t *testing.T) {
	keyPath, input, public := trustSigningFixture(t)
	otherPath := filepath.Join(t.TempDir(), "other.pem")
	_, other := writeTrustTestKey(t, otherPath, 0x43)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	key, err := trust.ParseAuthorityKey(public)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := trust.ReadSignedFile(parent, []trust.AuthorityKey{key})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(key.DER)
	facts := fmt.Sprintf("height 1\nprevious none\ndigest %x\nalgorithm Ed25519 (-19)\nkey SHA256:%s\n", verified.Digest, base64.RawStdEncoding.EncodeToString(fingerprint[:]))
	for _, pair := range [][2]string{{public, other}, {other, public}} {
		for _, verb := range []string{"show", "verify"} {
			out, stderr, err := runTrustCommand("trust", verb, "--authority", pair[0], "--authority", pair[1], parent)
			if err != nil || stderr != facts || (verb == "show" && out != `{"nodes":[]}`) || (verb == "verify" && out != "") {
				t.Fatalf("%s keys in order %v: stdout %q, stderr %q, error %v", verb, pair[0] == public, out, stderr, err)
			}
		}
		output := filepath.Join(t.TempDir(), "successor.cose")
		out, stderr, err := runTrustCommand("trust", "sign", "--key", keyPath, "--previous", parent, "--authority", pair[0], "--authority", pair[1], "--out", output, input)
		if err != nil || out != "" || !strings.HasPrefix(stderr, "height 2\nprevious ") {
			t.Fatalf("sign keys in order %v: stdout %q, stderr %q, error %v", pair[0] == public, out, stderr, err)
		}
		successor, err := trust.ReadSignedFile(output, []trust.AuthorityKey{key})
		if err != nil || successor.Payload.Previous == nil || *successor.Payload.Previous != verified.Digest {
			t.Fatalf("successor signed under repeated keys: %+v, %v", successor, err)
		}
	}
}
