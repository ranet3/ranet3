// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// SignPayload signs a validated snapshot. Nil randomness gives ECDSA's RFC 6979
// deterministic signatures in Go 1.27, while Ed25519 is deterministic by design.
func SignPayload(payload Payload, signer crypto.Signer) ([]byte, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	algorithm, err := authorityAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	body, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	var protected []byte
	var width int
	var opts crypto.SignerOpts = crypto.Hash(0)
	switch algorithm {
	case algorithmEd25519:
		protected, width = protectedEd, 32
	case algorithmESP256:
		protected, width, opts = protectedP256, 32, crypto.SHA256
	case algorithmESP384:
		protected, width, opts = protectedP384, 48, crypto.SHA384
	}
	file := make([]byte, 0, len(body)+len(protected)+2*width+16)
	file = append(file, 0xd2, 0x84)
	file = appendBstr(file, protected)
	file = append(file, 0xa0)
	file = appendBstr(file, body)
	if len(file)+2+2*width > MaxSignedBytes {
		return nil, errors.New("trust: signed file exceeds 64 MiB")
	}
	structure := signatureStructure(protected, body)
	message := structure
	switch algorithm {
	case algorithmESP256:
		sum := sha256.Sum256(structure)
		message = sum[:]
	case algorithmESP384:
		sum := sha512.Sum384(structure)
		message = sum[:]
	}
	signature, err := signer.Sign(nil, message, opts)
	if err != nil {
		return nil, fmt.Errorf("trust: sign payload: %w", err)
	}
	if algorithm != algorithmEd25519 {
		var pair struct{ R, S *big.Int }
		rest, err := asn1.Unmarshal(signature, &pair)
		if err != nil || len(rest) != 0 || pair.R == nil || pair.S == nil || pair.R.Sign() <= 0 || pair.S.Sign() <= 0 || pair.R.BitLen() > width*8 || pair.S.BitLen() > width*8 {
			return nil, errors.New("trust: invalid ECDSA signature")
		}
		signature = make([]byte, 2*width)
		pair.R.FillBytes(signature[:width])
		pair.S.FillBytes(signature[width:])
	}
	if len(signature) != 2*width {
		return nil, errors.New("trust: invalid signature length")
	}
	return appendBstr(file, signature), nil
}
