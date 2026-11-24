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
	"math/big"
	"os"
)

// Authenticated is an intact, strictly decoded file whose signature verified.
// Its document profile is checked separately after the authority overlap check.
type Authenticated struct {
	payload Payload
	digest  [32]byte
	key     AuthorityKey
}

func (a Authenticated) Payload() Payload { return a.payload }

// Verified contains only a fully validated payload authenticated by a supplied key.
type Verified struct {
	Payload Payload
	Digest  [32]byte
	Key     AuthorityKey
}

func (a Authenticated) Validate() (Verified, error) {
	if err := a.payload.Validate(); err != nil {
		return Verified{}, fmt.Errorf("trust: signed payload: %w", err)
	}
	return Verified{Payload: a.payload, Digest: a.digest, Key: a.key}, nil
}

// VerifySignedFile authenticates before decoding any payload member.
func VerifySignedFile(file []byte, keys []AuthorityKey) (Verified, error) {
	authenticated, err := AuthenticateSignedFile(file, keys)
	if err != nil {
		return Verified{}, err
	}
	return authenticated.Validate()
}

// AuthenticateSignedFile performs load steps 5a and 5b, before the overlap
// check and the field validation of step 7.
func AuthenticateSignedFile(file []byte, keys []AuthorityKey) (Authenticated, error) {
	envelope, err := parseEnvelope(file)
	if err != nil {
		return Authenticated{}, err
	}
	return authenticateParsedEnvelope(file, envelope, keys)
}

func authenticateParsedEnvelope(file []byte, envelope signedEnvelope, keys []AuthorityKey) (Authenticated, error) {
	key, ok := verifySignature(envelope, keys)
	if !ok {
		return Authenticated{}, errors.New("trust: no authority key verifies the signature")
	}
	payload, err := decodePayloadUnvalidated(envelope.Payload)
	if err != nil {
		return Authenticated{}, fmt.Errorf("trust: signed payload: %w", err)
	}
	canonical := make([]byte, 0, len(file))
	canonical = append(canonical, 0xd2, 0x84)
	canonical = appendBstr(canonical, envelope.Protected)
	canonical = append(canonical, 0xa0)
	canonical = appendBstr(canonical, envelope.Payload)
	canonical = appendBstr(canonical, envelope.Signature)
	if !bytes.Equal(canonical, file) {
		return Authenticated{}, errors.New("trust: signed file is not canonical")
	}
	return Authenticated{payload: payload, digest: sha256.Sum256(envelope.Payload), key: key}, nil
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

// ReadSignedFile reads and fully validates a signed file under supplied keys.
func ReadSignedFile(path string, keys []AuthorityKey) (Verified, error) {
	authenticated, err := ReadAuthenticatedFile(path, keys)
	if err != nil {
		return Verified{}, err
	}
	return authenticated.Validate()
}

// ReadAuthenticatedFile caps the read even if a file grows after stat or is a FIFO.
func ReadAuthenticatedFile(path string, keys []AuthorityKey) (Authenticated, error) {
	file, err := os.Open(path)
	if err != nil {
		return Authenticated{}, fmt.Errorf("trust: open signed file: %w", err)
	}
	defer file.Close()
	body, err := readBounded(file, MaxSignedBytes, "signed file", "64 MiB", false)
	if err != nil {
		return Authenticated{}, err
	}
	return AuthenticateSignedFile(body, keys)
}
