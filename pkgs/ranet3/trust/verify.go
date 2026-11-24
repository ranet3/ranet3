// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
)

// Verified contains only a payload authenticated by one supplied authority key.
type Verified struct {
	Payload Payload
	Digest  [32]byte
	Key     AuthorityKey
}

// VerifySignedFile authenticates before decoding any payload member.
func VerifySignedFile(file []byte, keys []AuthorityKey) (Verified, error) {
	envelope, err := parseEnvelope(file)
	if err != nil {
		return Verified{}, err
	}
	key, ok := verifySignature(envelope, keys)
	if !ok {
		return Verified{}, errors.New("trust: no authority key verifies the signature")
	}
	payload, err := decodePayload(envelope.Payload)
	if err != nil {
		return Verified{}, fmt.Errorf("trust: signed payload: %w", err)
	}
	canonical := make([]byte, 0, len(file))
	canonical = append(canonical, 0xd2, 0x84)
	canonical = appendBstr(canonical, envelope.Protected)
	canonical = append(canonical, 0xa0)
	canonical = appendBstr(canonical, envelope.Payload)
	canonical = appendBstr(canonical, envelope.Signature)
	if !bytes.Equal(canonical, file) {
		return Verified{}, errors.New("trust: signed file is not canonical")
	}
	return Verified{Payload: payload, Digest: sha256.Sum256(envelope.Payload), Key: key}, nil
}

func verifySignature(envelope signedEnvelope, keys []AuthorityKey) (AuthorityKey, bool) {
	structure := signatureStructure(envelope.Protected, envelope.Payload)
	var digest []byte
	if envelope.Algorithm == algorithmESP256 {
		sum := sha256.Sum256(structure)
		digest = sum[:]
	} else if envelope.Algorithm == algorithmESP384 {
		sum := sha512.Sum384(structure)
		digest = sum[:]
	}
	var r, s big.Int
	if digest != nil {
		half := len(envelope.Signature) / 2
		r.SetBytes(envelope.Signature[:half])
		s.SetBytes(envelope.Signature[half:])
	}
	for _, key := range keys {
		if key.Algorithm != envelope.Algorithm {
			continue
		}
		switch public := key.Public.(type) {
		case ed25519.PublicKey:
			if envelope.Algorithm == algorithmEd25519 && ed25519.Verify(public, structure, envelope.Signature) {
				return key, true
			}
		case *ecdsa.PublicKey:
			if (envelope.Algorithm == algorithmESP256 && public.Curve == elliptic.P256() ||
				envelope.Algorithm == algorithmESP384 && public.Curve == elliptic.P384()) &&
				ecdsa.Verify(public, digest, &r, &s) {
				return key, true
			}
		}
	}
	return AuthorityKey{}, false
}

// ReadSignedFile caps the read even if a file grows after stat or is a FIFO.
func ReadSignedFile(path string, keys []AuthorityKey) (Verified, error) {
	file, err := os.Open(path)
	if err != nil {
		return Verified{}, fmt.Errorf("trust: open signed file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Verified{}, fmt.Errorf("trust: stat signed file: %w", err)
	}
	if info.Size() > MaxSignedBytes {
		return Verified{}, errors.New("trust: signed file exceeds 64 MiB at stat")
	}
	body, err := io.ReadAll(io.LimitReader(file, MaxSignedBytes+1))
	if err != nil {
		return Verified{}, fmt.Errorf("trust: read signed file: %w", err)
	}
	if len(body) > MaxSignedBytes {
		return Verified{}, errors.New("trust: signed file exceeds 64 MiB at read")
	}
	return VerifySignedFile(body, keys)
}
