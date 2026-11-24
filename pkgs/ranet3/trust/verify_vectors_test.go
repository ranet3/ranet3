// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// OpenSSL 3.5.9 generated the signatures over independently assembled
// protected headers, Sig_structures and outer CBOR bytes.
var independentVectors = []struct {
	name string
	key  string
	file string
}{
	{
		"ed25519",
		"MCowBQYDK2VwAyEA7vRDY0q9Dah4orYnH+P9+VDDuev6ghmNsdhocuu9duc=",
		"d2845827a201320378216170706c69636174696f6e2f766e642e72616e6574332e74727573742b63626f72a05819a3010103a101800450018e8cf033207abc8def0123456789ab5840c9a17ad94a1bc1d5ea0836fce6e7f72c70dbba426e9d09b2bf4bc3c300762ed642883afd53aca59543d31ed21d87c30b38118e46c550770e9eb6134df5dae708",
	},
	{
		"p256",
		"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEp6N8aV0w0bZ5SfkQ1VIjuIWbBHfH12iBkHmrv63AjTkEjV/tZNw6MPKblolwbm3LtffK80JjC5fpR4HhNKw2yg==",
		"d2845827a201280378216170706c69636174696f6e2f766e642e72616e6574332e74727573742b63626f72a05819a3010103a101800450018e8cf033207abc8def0123456789ab5840d5256da12afe220886acc5aba3b19183bff1354853d1a4663a9b0323b3eedb30a60441583dd7b3a436a629c91fb66d37488c55894aa266113fe18f05be9d5557",
	},
	{
		"p384",
		"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEtXZ65+wkT0SgEPwkPOe0WzvvMLjgwwONjXQ2hDTPnURdB0fGwojETc5ocxV1lezjKj4LyxEq4lJz6E2bi8vgKNSk6S1GG81v7JI5Wv7wXQ17u2UkK1T6tjDZZxaocYDY",
		"d2845828a20138320378216170706c69636174696f6e2f766e642e72616e6574332e74727573742b63626f72a05819a3010103a101800450018e8cf033207abc8def0123456789ab5860554fd017ef2269b569704ec34cc0499c614a13c756f5c3913bda5be55213d9557577de798f8339515b89d03b3f6206cdaae44579674ab3d9fde71d5738704f8e4504f3db4624f45ea4c9127b38cabecc4ba57073d5501161c33875b1be7b88a6",
	},
}

func vectorBytes(t *testing.T, text string) []byte {
	t.Helper()
	body, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type aliasedCurve struct{ elliptic.Curve }

func TestVerifyIndependentVectors(t *testing.T) {
	_, body := payloadExample(t)
	wantDigest := sha256.Sum256(body)
	keys := make([]AuthorityKey, len(independentVectors))
	files := make([][]byte, len(independentVectors))
	for i, vector := range independentVectors {
		var err error
		keys[i], err = ParseAuthorityKey(vector.key)
		if err != nil {
			t.Fatal(err)
		}
		files[i] = vectorBytes(t, vector.file)
	}
	for i, vector := range independentVectors {
		t.Run(vector.name, func(t *testing.T) {
			verified, err := VerifySignedFile(files[i], keys)
			if err != nil {
				t.Fatal(err)
			}
			if verified.Digest != wantDigest || !bytes.Equal(verified.Key.DER, keys[i].DER) || verified.Payload.Height != 1 || verified.Payload.Mesh.Validate() != nil || len(verified.Payload.Document.Nodes) != 0 {
				t.Fatalf("wrong verified snapshot %+v", verified)
			}
			if _, err := VerifySignedFile(files[i], keys[(i+1)%len(keys):(i+1)%len(keys)+1]); err == nil {
				t.Fatal("accepted a signature under another key")
			}
			bad := bytes.Clone(files[i])
			bad[len(bad)-1] ^= 0x01
			if _, err := VerifySignedFile(bad, keys); err == nil {
				t.Fatal("accepted a modified signature")
			}
			wrongAlgorithm := keys[i]
			wrongAlgorithm.Algorithm = 0
			if _, err := VerifySignedFile(files[i], []AuthorityKey{wrongAlgorithm}); err == nil {
				t.Fatal("accepted a mismatched algorithm and key")
			}
		})
	}
	ec := *keys[1].Public.(*ecdsa.PublicKey)
	ec.Curve = aliasedCurve{ec.Curve}
	alias := keys[1]
	alias.Public = &ec
	if _, err := VerifySignedFile(files[1], []AuthorityKey{alias}); err == nil {
		t.Fatal("accepted an unrecognized curve with the same bit size")
	}
	path := filepath.Join(t.TempDir(), "snapshot.cbor")
	if err := os.WriteFile(path, files[0], 0o600); err != nil {
		t.Fatal(err)
	}
	if verified, err := ReadSignedFile(path, keys); err != nil || verified.Digest != wantDigest {
		t.Fatalf("read configured signed file %+v: %v", verified, err)
	}
	if err := os.Truncate(path, MaxSignedBytes+1); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSignedFile(path, keys); err == nil || !strings.Contains(err.Error(), "stat") {
		t.Fatalf("oversized stat: %v", err)
	}
}
