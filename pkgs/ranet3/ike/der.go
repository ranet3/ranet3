// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Ed25519AlgorithmIdentifier is the DER SEQUENCE{OID 1.3.101.112} of RFC 8410, without parameters
// it is both the RFC 7427 signature AlgorithmIdentifier and the one inside a SubjectPublicKeyInfo
func Ed25519AlgorithmIdentifier() []byte {
	return []byte{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70}
}
