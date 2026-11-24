// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"crypto/sha512"
	"fmt"
	"math/big"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// curveRefuses decodes as RFC 8032 section 5.1.3 does, then asks whether [8]P is the neutral point
func curveRefuses(y *big.Int, sign uint) bool {
	if y.Cmp(curveP) >= 0 {
		return true
	}
	P, ok := pointAt(y, sign)
	if !ok {
		return true
	}
	if P.x.Sign() == 0 && sign == 1 {
		return true
	}
	return scale(big.NewInt(8), P).equal(neutral)
}

func TestValidatePublicKeyRefusesWhatTheCurveCallsNonCanonicalOrSmallOrder(t *testing.T) {
	points := smallOrderPoints(t)
	// ordinates from just below p through every non-canonical one, where the canonical test decides
	// p - 1, p and p + 1 are drawn by name, since the canonical test branches at p
	low := new(big.Int).Sub(curveP, big.NewInt(32))
	boundary := hegel.OneOf(pbt.Spanning(0, 50), hegel.SampledFrom([]int{31, 32, 33}))
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	pbt.Check(t, func(ht *hegel.T) {
		var y *big.Int
		switch hegel.Draw(ht, pbt.Spanning(0, 2)) {
		case 0:
			y = points[hegel.Draw(ht, pbt.Spanning(0, len(points)-1))].y
		case 1:
			y = new(big.Int).Add(low, big.NewInt(int64(hegel.Draw(ht, boundary))))
		default:
			digest := sha512.Sum512(fmt.Appendf(nil, "ordinate %d", hegel.Draw(ht, pbt.Spanning(0, 1<<30))))
			y = fromLittleEndian(digest[:32])
			y.And(y, mask)
		}
		sign := uint(hegel.Draw(ht, pbt.Spanning(0, 1)))
		key := encodeAt(y, sign)
		if refused, want := ValidatePublicKey(key[:]) != nil, curveRefuses(y, sign); refused != want {
			ht.Fatalf("%x refused %v, the curve says %v", key, refused, want)
		}
	})
}
