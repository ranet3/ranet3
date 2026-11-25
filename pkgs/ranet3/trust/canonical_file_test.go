// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

type nonminimalHead struct {
	name string
	file []byte
}

func signedNonminimalHeads(t *testing.T) ([]nonminimalHead, signedEnvelope, AuthorityKey) {
	t.Helper()
	mesh := MeshID{6: 0x70, 8: 0x80}
	body, err := encodePayload(Payload{Height: 1, Document: Document{Nodes: []Node{}}, Mesh: mesh})
	if err != nil {
		t.Fatal(err)
	}
	file, key := signTestFile(t, body, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519)
	envelope, err := parseEnvelope(file)
	if err != nil {
		t.Fatal(err)
	}
	positions := []struct {
		name   string
		start  int
		length int
	}{
		{"protected", 2, len(envelope.Protected)},
		{"payload", 2 + 2 + len(envelope.Protected) + 1, len(envelope.Payload)},
		{"signature", 2 + 2 + len(envelope.Protected) + 1 + 2 + len(envelope.Payload), len(envelope.Signature)},
	}
	results := make([]nonminimalHead, 0, len(positions))
	for _, position := range positions {
		if position.length < 24 || position.length > 255 || file[position.start] != 0x58 || int(file[position.start+1]) != position.length {
			t.Fatalf("expected a one-byte-length byte string at %d, length %d", position.start, position.length)
		}
		bad := make([]byte, 0, len(file)+1)
		bad = append(bad, file[:position.start]...)
		bad = append(bad, 0x59, 0x00, file[position.start+1])
		bad = append(bad, file[position.start+2:]...)
		results = append(results, nonminimalHead{position.name, bad})
	}
	return results, envelope, key
}

func TestSignedFileWholeEncodingIsCanonical(t *testing.T) {
	cases, envelope, key := signedNonminimalHeads(t)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := authenticateParsedEnvelope(test.file, envelope, []AuthorityKey{key}); err == nil || err.Error() != "trust: signed file is not canonical" {
				t.Fatalf("accepted signed %s head that changes file encoding: %v", test.name, err)
			}
		})
	}
}

func TestSignedFileNonminimalHeadsRejected(t *testing.T) {
	cases, _, key := signedNonminimalHeads(t)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AuthenticateSignedFile(test.file, []AuthorityKey{key}); err == nil || !strings.Contains(err.Error(), "nonminimal byte string length") {
				t.Fatalf("accepted signed %s nonminimal head: %v", test.name, err)
			}
		})
	}
}

func TestSignedFileRejectsNoncanonicalPayload(t *testing.T) {
	_, canonical := payloadExample(t)
	nonminimal := append([]byte{canonical[0], canonical[1], 0x18, canonical[2]}, canonical[3:]...)
	duplicate := append([]byte{0xa4, 0x01, 0x01, 0x01, 0x01}, canonical[3:]...)
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	for _, test := range []struct {
		name string
		body []byte
		want string
	}{
		{"nonminimal height", nonminimal, "trust: signed payload: trust: CBOR is not deterministic"},
		{"duplicate height", duplicate, "trust: signed payload: trust: decode CBOR"},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, key := signTestFile(t, test.body, private, algorithmEd25519)
			if _, err := AuthenticateSignedFile(file, []AuthorityKey{key}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("accepted %s in authenticated payload: %v", test.name, err)
			}
		})
	}
}

func TestSignedFileEnvelopeRefusalsBeforeComparison(t *testing.T) {
	_, body := payloadExample(t)
	file, key := signTestFile(t, body, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), algorithmEd25519)
	badTag := bytes.Clone(file)
	badTag[0] = 0xd0
	badArray := bytes.Clone(file)
	badArray[1] = 0x83
	badHeader := bytes.Clone(file)
	badHeader[6] = 0x27
	badUnprotected := bytes.Clone(file)
	badUnprotected[2+2+len(protectedEd)] = 0xa1
	for _, test := range []struct {
		name string
		file []byte
		want string
	}{
		{"tag", badTag, "trust: signed file is not tagged COSE_Sign1"},
		{"array", badArray, "trust: signed file is not tagged COSE_Sign1"},
		{"protected", badHeader, "trust: unknown protected header"},
		{"unprotected", badUnprotected, "trust: unprotected header must be empty"},
		{"trailing", append(bytes.Clone(file), 0), "trust: bytes after signed file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AuthenticateSignedFile(test.file, []AuthorityKey{key}); err == nil || err.Error() != test.want {
				t.Fatalf("accepted signed file with %s before comparison: %v", test.name, err)
			}
		})
	}
}
