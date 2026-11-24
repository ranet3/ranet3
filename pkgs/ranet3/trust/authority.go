// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// AuthorityKey is a validated public key and its canonical DER representation.
type AuthorityKey struct {
	DER       []byte
	Public    crypto.PublicKey
	Algorithm int
}

func ParseAuthorityKey(text string) (AuthorityKey, error) {
	der, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || base64.StdEncoding.EncodeToString(der) != text {
		return AuthorityKey{}, errors.New("trust: authority key is not canonical padded base64")
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return AuthorityKey{}, fmt.Errorf("trust: parse authority key: %w", err)
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || !bytes.Equal(canonical, der) {
		return AuthorityKey{}, errors.New("trust: authority key is not canonical DER SubjectPublicKeyInfo")
	}
	algorithm, err := authorityAlgorithm(public)
	if err != nil {
		return AuthorityKey{}, err
	}
	return AuthorityKey{DER: der, Public: public, Algorithm: algorithm}, nil
}

func authorityAlgorithm(public crypto.PublicKey) (int, error) {
	switch key := public.(type) {
	case ed25519.PublicKey:
		if err := ValidatePublicKey(key); err != nil {
			return 0, fmt.Errorf("trust: invalid Ed25519 authority key: %w", err)
		}
		return algorithmEd25519, nil
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return algorithmESP256, nil
		case elliptic.P384():
			return algorithmESP384, nil
		}
	}
	return 0, errors.New("trust: authority key must be Ed25519, P-256 or P-384")
}

func LoadAuthorityPrivateKey(path string) (crypto.Signer, AuthorityKey, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, AuthorityKey{}, fmt.Errorf("trust: open authority private key %s: %w", path, err)
	}
	defer file.Close()
	body, err := readBounded(file, maxAuthorityPEMBytes, "authority private key", "65536 bytes", true)
	if err != nil {
		return nil, AuthorityKey{}, fmt.Errorf("trust: read authority private key %s: %w", path, err)
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, AuthorityKey{}, errors.New("trust: authority private key must be one PKCS8 PEM block")
	}
	private, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, AuthorityKey{}, fmt.Errorf("trust: parse authority private key: %w", err)
	}
	signer, ok := private.(crypto.Signer)
	if !ok {
		return nil, AuthorityKey{}, errors.New("trust: authority private key has an unsupported type")
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, AuthorityKey{}, fmt.Errorf("trust: encode authority public key: %w", err)
	}
	key, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		return nil, AuthorityKey{}, err
	}
	return signer, key, nil
}

func readBounded(file *os.File, limit int, kind, sizeLabel string, regular bool) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("trust: stat %s: %w", kind, err)
	}
	if regular && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("trust: %s is not a regular file", kind)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("trust: %s exceeds %s at stat", kind, sizeLabel)
	}
	size := max(4096, min(int(info.Size())+1, limit+1))
	body := make([]byte, size)
	n := 0
	for {
		if n == len(body) {
			if n > limit {
				return nil, fmt.Errorf("trust: %s exceeds %s at read", kind, sizeLabel)
			}
			larger := make([]byte, min(2*len(body), limit+1))
			copy(larger, body)
			body = larger
		}
		count, readErr := file.Read(body[n:])
		n += count
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("trust: read %s: %w", kind, readErr)
		}
	}
	if n > limit {
		return nil, fmt.Errorf("trust: %s exceeds %s at read", kind, sizeLabel)
	}
	return body[:n], nil
}
