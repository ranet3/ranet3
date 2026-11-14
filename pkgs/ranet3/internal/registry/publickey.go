// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// fieldPrime and edwardsD are p and d of RFC 8032 section 5.1
var (
	fieldPrime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edwardsD   = func() *big.Int {
		d, _ := new(big.Int).SetString("37095705934669439343138083508754565189542113879843219016388785533085940283555", 10)
		return d
	}()
)

// smallOrderOrdinates are the ordinates of the eight points whose order divides 8, little endian
// the two points with x = 0 have ordinates 1 and p-1, so their encodings with the sign bit set are refused here too
var smallOrderOrdinates = [...][ed25519.PublicKeySize]byte{
	{0x01},
	{
		0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
	},
	{},
	{
		0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
	},
	{
		0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
	},
}

// ValidatePublicKey refuses a key other than the canonical encoding of a point outside the small order subgroup,
// since ed25519.Verify accepts under a small order point signatures made without any private key
func ValidatePublicKey(key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("length is %d octets, want %d", len(key), ed25519.PublicKeySize)
	}
	encoded := [ed25519.PublicKeySize]byte(key)
	encoded[31] &^= 0x80
	bigEndian := encoded
	slices.Reverse(bigEndian[:])
	y := new(big.Int).SetBytes(bigEndian[:])
	if y.Cmp(fieldPrime) >= 0 {
		return errors.New("encoding is not canonical")
	}
	// x^2 = u / v with u = y^2 - 1 and v = d y^2 + 1, and u v is a square exactly when u / v is, as v is never 0
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	v := y2.Add(y2.Mul(y2, edwardsD), big.NewInt(1))
	if big.Jacobi(u.Mod(u.Mul(u, v), fieldPrime), fieldPrime) < 0 {
		return errors.New("encoding is on no point of the curve")
	}
	if slices.Contains(smallOrderOrdinates[:], encoded) {
		return errors.New("point has small order")
	}
	return nil
}
