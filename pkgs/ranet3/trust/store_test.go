// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func storeTestKey(t *testing.T, seed byte) AuthorityKey {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	der, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// This oracle writes the small CBOR map directly, independent of EncodeStore.
func TestStoreClosedCanonicalLOnlyImage(t *testing.T) {
	key := storeTestKey(t, 0x41)
	raw := append([]byte{0xa1, 0x03, 0x81, 0xa2, 0x01, 0x58, byte(len(key.DER))}, key.DER...)
	raw = append(raw, 0x02, 0x05)
	image, err := DecodeStore(raw)
	if err != nil {
		t.Fatal(err)
	}
	if image.Verified != nil || len(image.Compromised) != 1 || image.Compromised[0].Floor != 5 || !bytes.Equal(image.Compromised[0].Key.DER, key.DER) {
		t.Fatalf("decoded image: %+v", image)
	}
	encoded, err := EncodeStore(image)
	if err != nil || !bytes.Equal(encoded, raw) {
		t.Fatalf("encoded %x, want %x: %v", encoded, raw, err)
	}
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"unknown label", append([]byte{0xa1, 0x04}, raw[2:]...)},
		{"nonminimal map length", append([]byte{0xb8, 0x01}, raw[1:]...)},
		{"missing list", []byte{0xa0}},
		{"unknown list label", append([]byte{0xa1, 0x03, 0x81, 0xa1, 0x04, 0x58, byte(len(key.DER))}, key.DER...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeStore(test.raw); err == nil {
				t.Errorf("accepted %x", test.raw)
			}
		})
	}
}

func TestStoreRefusesUnsortedAndDuplicateKeys(t *testing.T) {
	first := storeTestKey(t, 0x42)
	second := storeTestKey(t, 0x43)
	keys := []AuthorityKey{first, second}
	slices.SortFunc(keys, func(a, b AuthorityKey) int { return bytes.Compare(a.DER, b.DER) })
	encode := func(a, b AuthorityKey) []byte {
		wire := []byte{0xa1, 0x03, 0x82, 0xa1, 0x01, 0x58, byte(len(a.DER))}
		wire = append(wire, a.DER...)
		wire = append(wire, 0xa1, 0x01, 0x58, byte(len(b.DER)))
		return append(wire, b.DER...)
	}
	for _, raw := range [][]byte{encode(keys[1], keys[0]), encode(keys[0], keys[0])} {
		if _, err := DecodeStore(raw); err == nil {
			t.Fatalf("accepted unordered or duplicate keys: %x", raw)
		}
	}
	if _, err := DecodeStore(make([]byte, MaxStoreBytes+1)); err == nil {
		t.Fatal("accepted a store above the size cap")
	}
}

func TestStoreFullImageIndependentMapAndRecordedSigner(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, ed25519.SeedSize))
	key := storeTestKey(t, 0x47)
	signed, err := SignPayload(Payload{Height: 1, Mesh: MeshID{6: 0x70, 8: 0x80}, Document: Document{Nodes: []Node{}}}, private)
	if err != nil {
		t.Fatal(err)
	}
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	independent := map[uint64]any{
		1: signed,
		2: key.DER,
		3: []any{map[uint64]any{1: key.DER, 2: uint64(2)}},
	}
	body, err := mode.Marshal(independent)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeStore(body)
	if err != nil || decoded.Verified == nil || decoded.Verified.Payload.Height != 1 || decoded.Compromised[0].Floor != 2 {
		t.Fatalf("full map: %+v, %v", decoded, err)
	}
	encoded, err := EncodeStore(decoded)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatalf("full image round trip: %x, want %x: %v", encoded, body, err)
	}
	other := storeTestKey(t, 0x48)
	independent[2] = other.DER
	wrong, err := mode.Marshal(independent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeStore(wrong); err == nil {
		t.Fatal("accepted a stored snapshot under a different recorded signer")
	}
}
