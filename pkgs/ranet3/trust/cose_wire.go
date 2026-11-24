// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrNotSign1 means the signed file does not begin with a tag 18 COSE_Sign1 array.
var ErrNotSign1 = errors.New("trust: signed file is not tagged COSE_Sign1")

const mediaType = "application/vnd.ranet3.trust+cbor"

var protectedEd = append([]byte{0xa2, 0x01, 0x32, 0x03, 0x78, 0x21}, mediaType...)
var protectedP256 = append([]byte{0xa2, 0x01, 0x28, 0x03, 0x78, 0x21}, mediaType...)
var protectedP384 = append([]byte{0xa2, 0x01, 0x38, 0x32, 0x03, 0x78, 0x21}, mediaType...)

type signedEnvelope struct {
	Algorithm int
	Protected []byte
	Payload   []byte
	Signature []byte
}

func parseEnvelope(file []byte) (signedEnvelope, error) {
	if len(file) > MaxSignedBytes {
		return signedEnvelope{}, errors.New("trust: signed file exceeds 64 MiB")
	}
	if len(file) < 2 || file[0] != 0xd2 || file[1] != 0x84 {
		return signedEnvelope{}, ErrNotSign1
	}
	at := 2
	protected, err := takeBstr(file, &at)
	if err != nil {
		return signedEnvelope{}, fmt.Errorf("trust: protected header: %w", err)
	}
	var algorithm, signatureSize int
	switch {
	case bytes.Equal(protected, protectedEd):
		algorithm, signatureSize = algorithmEd25519, 64
	case bytes.Equal(protected, protectedP256):
		algorithm, signatureSize = algorithmESP256, 64
	case bytes.Equal(protected, protectedP384):
		algorithm, signatureSize = algorithmESP384, 96
	default:
		return signedEnvelope{}, errors.New("trust: unknown protected header")
	}
	if at >= len(file) || file[at] != 0xa0 {
		return signedEnvelope{}, errors.New("trust: unprotected header must be empty")
	}
	at++
	payload, err := takeBstr(file, &at)
	if err != nil {
		return signedEnvelope{}, fmt.Errorf("trust: payload: %w", err)
	}
	signature, err := takeBstr(file, &at)
	if err != nil {
		return signedEnvelope{}, fmt.Errorf("trust: signature: %w", err)
	}
	if at != len(file) {
		return signedEnvelope{}, errors.New("trust: bytes after signed file")
	}
	if len(signature) != signatureSize {
		return signedEnvelope{}, fmt.Errorf("trust: signature has %d bytes, want %d", len(signature), signatureSize)
	}
	return signedEnvelope{Algorithm: algorithm, Protected: protected, Payload: payload, Signature: signature}, nil
}

// takeBstr borrows a definite canonical byte string directly from file.
func takeBstr(file []byte, at *int) ([]byte, error) {
	if *at >= len(file) || file[*at]>>5 != 2 {
		return nil, errors.New("expected byte string")
	}
	length := uint64(file[*at] & 0x1f)
	*at++
	switch length {
	case 24, 25, 26, 27:
		count := 1 << (length - 24)
		if count > len(file)-*at {
			return nil, errors.New("truncated length")
		}
		length = 0
		for i := range count {
			length = length<<8 | uint64(file[*at+i])
		}
		*at += count
		minimum := uint64(24)
		switch count {
		case 2:
			minimum = 256
		case 4:
			minimum = 65536
		case 8:
			minimum = 4294967296
		}
		if length < minimum {
			return nil, errors.New("nonminimal byte string length")
		}
	case 28, 29, 30, 31:
		return nil, errors.New("indefinite or reserved byte string length")
	}
	if length > uint64(len(file)-*at) {
		return nil, errors.New("truncated byte string")
	}
	data := file[*at : *at+int(length)]
	*at += int(length)
	return data, nil
}

func appendBstr(dst, data []byte) []byte {
	length := len(data)
	switch {
	case length < 24:
		dst = append(dst, 0x40|byte(length))
	case length < 256:
		dst = append(dst, 0x58, byte(length))
	case length < 65536:
		dst = append(dst, 0x59, byte(length>>8), byte(length))
	default:
		dst = append(dst, 0x5a, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	return append(dst, data...)
}

func signatureStructure(protected, payload []byte) []byte {
	structure := make([]byte, 0, len(payload)+len(protected)+32)
	structure = append(structure, 0x84, 0x6a)
	structure = append(structure, "Signature1"...)
	structure = appendBstr(structure, protected)
	structure = append(structure, 0x40)
	return appendBstr(structure, payload)
}
