// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

// signTestFile constructs signed test data without a production signing API.
func signTestFile(t *testing.T, body []byte, signer crypto.Signer, algorithm int) ([]byte, AuthorityKey) {
	t.Helper()
	var header []byte
	var width int
	switch algorithm {
	case algorithmEd25519:
		header, width = protectedEd, 32
	case algorithmESP256:
		header, width = protectedP256, 32
	case algorithmESP384:
		header, width = protectedP384, 48
	default:
		t.Fatalf("unsupported test algorithm %d", algorithm)
	}
	structure := signatureStructure(header, body)
	message := structure
	var opts crypto.SignerOpts = crypto.Hash(0)
	switch algorithm {
	case algorithmESP256:
		sum := sha256.Sum256(structure)
		message, opts = sum[:], crypto.SHA256
	case algorithmESP384:
		sum := sha512.Sum384(structure)
		message, opts = sum[:], crypto.SHA384
	}
	signature, err := signer.Sign(rand.Reader, message, opts)
	if err != nil {
		t.Fatal(err)
	}
	if algorithm != algorithmEd25519 {
		var pair struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &pair)
		if err != nil || len(rest) != 0 {
			t.Fatalf("test signer returned malformed ECDSA signature: %v", err)
		}
		signature = append(pair.R.FillBytes(make([]byte, width)), pair.S.FillBytes(make([]byte, width))...)
	}
	file := []byte{0xd2, 0x84}
	file = appendBstr(file, header)
	file = append(file, 0xa0)
	file = appendBstr(file, body)
	file = appendBstr(file, signature)
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	return file, key
}

func TestVerifiedPayloadOrderAndTwinSignatures(t *testing.T) {
	payload, body := payloadExample(t)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	for _, malformed := range [][]byte{{0xff}, {0xf6}, append([]byte{0xa3, 0x01, 0x00}, body[3:]...)} {
		file, key := signTestFile(t, malformed, private, algorithmEd25519)
		if _, err := VerifySignedFile(file, []AuthorityKey{key}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("signed payload")) {
			t.Fatalf("authenticated malformed payload: %v", err)
		}
		file[len(file)-1] ^= 0x01
		if _, err := VerifySignedFile(file, []AuthorityKey{key}); err == nil || !bytes.Contains([]byte(err.Error()), []byte("signature")) {
			t.Fatalf("decoded payload before rejecting signature: %v", err)
		}
	}
	for _, test := range []struct {
		name      string
		algorithm int
		curve     func() (*ecdsa.PrivateKey, error)
	}{
		{"p256", algorithmESP256, func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }},
		{"p384", algorithmESP384, func() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			private, err := test.curve()
			if err != nil {
				t.Fatal(err)
			}
			file, key := signTestFile(t, body, private, test.algorithm)
			verified, err := VerifySignedFile(file, []AuthorityKey{key})
			if err != nil || verified.Payload.Mesh != payload.Mesh {
				t.Fatalf("signed snapshot %+v: %v", verified, err)
			}
			width := (private.Curve.Params().BitSize + 7) / 8
			twin := bytes.Clone(file)
			originalS := new(big.Int).SetBytes(twin[len(twin)-width:])
			twinS := new(big.Int).Sub(private.Curve.Params().N, originalS)
			twinS.FillBytes(twin[len(twin)-width:])
			if bytes.Equal(file, twin) {
				t.Fatal("identical ECDSA twin")
			}
			second, err := VerifySignedFile(twin, []AuthorityKey{key})
			if err != nil || second.Digest != verified.Digest {
				t.Fatalf("ECDSA twin not authenticated on same payload digest: %v", err)
			}
		})
	}
}
