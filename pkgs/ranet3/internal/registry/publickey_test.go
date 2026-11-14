// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"
)

// edwards25519 of RFC 8032 section 5.1, -x^2 + y^2 = 1 + d x^2 y^2 over GF(p), a math/big model checked against crypto/ed25519's [s]B
var (
	curveP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	curveD = fmul(big.NewInt(-121665), finv(big.NewInt(121666)))
	curveL = func() *big.Int {
		l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
	neutral = point{big.NewInt(0), big.NewInt(1)}
)

type point struct{ x, y *big.Int }

func fadd(a, b *big.Int) *big.Int { r := new(big.Int).Add(a, b); return r.Mod(r, curveP) }
func fsub(a, b *big.Int) *big.Int { r := new(big.Int).Sub(a, b); return r.Mod(r, curveP) }
func fmul(a, b *big.Int) *big.Int { r := new(big.Int).Mul(a, b); return r.Mod(r, curveP) }
func finv(a *big.Int) *big.Int    { return new(big.Int).ModInverse(a, curveP) }
func fneg(a *big.Int) *big.Int    { return fsub(big.NewInt(0), a) }

// fsqrt is nil when a is not a square
func fsqrt(a *big.Int) *big.Int { return new(big.Int).ModSqrt(a, curveP) }

func (P point) onCurve() bool {
	x2, y2 := fmul(P.x, P.x), fmul(P.y, P.y)
	return fsub(y2, x2).Cmp(fadd(big.NewInt(1), fmul(curveD, fmul(x2, y2)))) == 0
}

func (P point) equal(Q point) bool { return P.x.Cmp(Q.x) == 0 && P.y.Cmp(Q.y) == 0 }

// add is the complete addition law, complete since d is not a square
func add(P, Q point) point {
	t := fmul(curveD, fmul(fmul(P.x, Q.x), fmul(P.y, Q.y)))
	return point{
		fmul(fadd(fmul(P.x, Q.y), fmul(P.y, Q.x)), finv(fadd(big.NewInt(1), t))),
		fmul(fadd(fmul(P.y, Q.y), fmul(P.x, Q.x)), finv(fsub(big.NewInt(1), t))),
	}
}

func scale(k *big.Int, P point) point {
	R := neutral
	for i := k.BitLen() - 1; i >= 0; i-- {
		R = add(R, R)
		if k.Bit(i) == 1 {
			R = add(R, P)
		}
	}
	return R
}

// pointAt solves the curve for x of parity sign at ordinate y, false when y is no point's ordinate
func pointAt(y *big.Int, sign uint) (point, bool) {
	y2 := fmul(y, y)
	x := fsqrt(fmul(fsub(y2, big.NewInt(1)), finv(fadd(big.NewInt(1), fmul(curveD, y2)))))
	if x == nil {
		return point{}, false
	}
	if x.Bit(0) != sign {
		x = fneg(x)
	}
	return point{x, y}, true
}

// encodeAt writes y below 2^255 little endian with the sign in bit 255, canonical or not
func encodeAt(y *big.Int, sign uint) [ed25519.PublicKeySize]byte {
	var b [ed25519.PublicKeySize]byte
	y.FillBytes(b[:])
	slices.Reverse(b[:])
	b[31] |= byte(sign) << 7
	return b
}

func encode(P point) [ed25519.PublicKeySize]byte { return encodeAt(P.y, P.x.Bit(0)) }

func fromLittleEndian(b []byte) *big.Int {
	reversed := bytes.Clone(b)
	slices.Reverse(reversed)
	return new(big.Int).SetBytes(reversed)
}

// smallOrderPoints solves the curve for every point whose order divides 8
// a point is its own negative (-x, y) exactly when x = 0, and the numerators of [2]P are 2xy and x^2 + y^2,
// so the order divides 4 exactly when x = 0 or y = 0, and divides 8 exactly when x = 0, y = 0 or x^2 + y^2 = 0
func smallOrderPoints(t testing.TB) []point {
	t.Helper()
	points := []point{
		{big.NewInt(0), big.NewInt(1)},
		{big.NewInt(0), fneg(big.NewInt(1))},
	}
	i := fsqrt(fneg(big.NewInt(1)))
	if i == nil {
		t.Fatal("-1 is not a square modulo p")
	}
	points = append(points, point{i, big.NewInt(0)}, point{fneg(i), big.NewInt(0)})
	// y^2 = -x^2 on the curve is d x^4 - 2 x^2 - 1 = 0, so x^2 = (1 +- sqrt(1 + d)) / d
	s := fsqrt(fadd(big.NewInt(1), curveD))
	if s == nil {
		t.Fatal("1 + d is not a square modulo p")
	}
	for _, root := range []*big.Int{s, fneg(s)} {
		x2 := fmul(fadd(big.NewInt(1), root), finv(curveD))
		x, y := fsqrt(x2), fsqrt(fneg(x2))
		if x == nil || y == nil {
			continue
		}
		for _, xs := range []*big.Int{x, fneg(x)} {
			for _, ys := range []*big.Int{y, fneg(y)} {
				points = append(points, point{xs, ys})
			}
		}
	}
	return points
}

// smallOrderEncodings is every 32 octet encoding Go's decoder takes for a point whose order divides 8,
// the canonical one, the sign bit set where x = 0, and y + p where it stays below 2^255
func smallOrderEncodings(t testing.TB) [][ed25519.PublicKeySize]byte {
	t.Helper()
	two255 := new(big.Int).Lsh(big.NewInt(1), 255)
	var encodings [][ed25519.PublicKeySize]byte
	for _, P := range smallOrderPoints(t) {
		ordinates := []*big.Int{P.y}
		if wrapped := new(big.Int).Add(P.y, curveP); wrapped.Cmp(two255) < 0 {
			ordinates = append(ordinates, wrapped)
		}
		for _, y := range ordinates {
			encodings = append(encodings, encodeAt(y, P.x.Bit(0)))
			if P.x.Sign() == 0 {
				encodings = append(encodings, encodeAt(y, 1))
			}
		}
	}
	return encodings
}

func publicKeyPEM(t testing.TB, key []byte) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func honestKey(label string, i int) ed25519.PrivateKey {
	seed := sha512.Sum512(fmt.Appendf(nil, "%s %d", label, i))
	return ed25519.NewKeyFromSeed(seed[:ed25519.SeedSize])
}

func TestSmallOrderConstantsAreTheCurves(t *testing.T) {
	if !curveP.ProbablyPrime(32) || !curveL.ProbablyPrime(32) {
		t.Fatal("p or L is not prime")
	}
	base, ok := pointAt(fmul(big.NewInt(4), finv(big.NewInt(5))), 0)
	if !ok || !base.onCurve() || base.equal(neutral) || !scale(curveL, base).equal(neutral) {
		t.Fatal("(x, 4/5) with x even is not a point of order L")
	}
	// the arithmetic here is crypto/ed25519's curve, whose public half of a seed is [clamp(SHA-512(seed)[:32])]B
	for i := range 4 {
		private := honestKey("curve check", i)
		digest := sha512.Sum512(private.Seed())
		digest[0] &= 248
		digest[31] &= 127
		digest[31] |= 64
		if got, want := encode(scale(fromLittleEndian(digest[:32]), base)), private.Public().(ed25519.PublicKey); !bytes.Equal(got[:], want) {
			t.Fatalf("[s]B encodes to %x, crypto/ed25519 gives %x", got, want)
		}
	}

	points := smallOrderPoints(t)
	ordinates := map[[ed25519.PublicKeySize]byte]bool{}
	for _, P := range points {
		if !P.onCurve() || !scale(big.NewInt(8), P).equal(neutral) {
			t.Fatalf("(%x, %x) is not a point whose order divides 8", P.x, P.y)
		}
		ordinates[encodeAt(P.y, 0)] = true
	}
	for i, P := range points {
		if slices.ContainsFunc(points[:i], P.equal) {
			t.Fatalf("(%x, %x) solved twice", P.x, P.y)
		}
	}
	if len(points) != 8 {
		t.Fatalf("%d points, want 8", len(points))
	}

	if fieldPrime.Cmp(curveP) != 0 || edwardsD.Cmp(curveD) != 0 {
		t.Errorf("fieldPrime is %x and edwardsD %x, the curve's p is %x and d %x", fieldPrime, edwardsD, curveP, curveD)
	}
	held := map[[ed25519.PublicKeySize]byte]bool{}
	for _, y := range smallOrderOrdinates {
		held[y] = true
	}
	if len(held) != len(smallOrderOrdinates) || len(held) != len(ordinates) {
		t.Errorf("smallOrderOrdinates holds %d ordinates, %d distinct, the curve's eight points have %d", len(smallOrderOrdinates), len(held), len(ordinates))
	}
	for y := range ordinates {
		if !held[y] {
			t.Errorf("smallOrderOrdinates lacks %x", y)
		}
	}
}

func TestValidatePublicKeyRefusesEveryEncodingOfASmallOrderPoint(t *testing.T) {
	encodings := smallOrderEncodings(t)
	if len(encodings) != 14 {
		t.Fatalf("%d encodings, want the 8 canonical, 4 with y + p and 2 with the sign bit of x = 0 alone", len(encodings))
	}
	for _, key := range encodings {
		if err := ValidatePublicKey(key[:]); err == nil {
			t.Errorf("%x was accepted", key)
		}
		checkDocumentRefused(t, key[:])
	}
}

func TestValidatePublicKeyRefusesKeyOnNoPoint(t *testing.T) {
	y := big.NewInt(2)
	for sign := range uint(2) {
		if _, ok := pointAt(y, sign); ok {
			t.Fatalf("the curve has a point at ordinate %v", y)
		}
		key := encodeAt(y, sign)
		if err := ValidatePublicKey(key[:]); err == nil {
			t.Errorf("%x was accepted", key)
		}
		checkDocumentRefused(t, key[:])
	}
}

// checkDocumentRefused wants New to refuse a document whose organization other holds key, naming other
func checkDocumentRefused(t *testing.T, key []byte) {
	t.Helper()
	document := Registry{
		{Organization: "example", PublicKey: publicKeyPEM(t, honestKey("registry", 0).Public().(ed25519.PublicKey)), Nodes: []Node{{CommonName: "gateway"}}},
		{Organization: "other", PublicKey: publicKeyPEM(t, key), Nodes: []Node{{CommonName: "laptop"}}},
	}
	if _, err := New(document); err == nil || !strings.HasPrefix(err.Error(), `registry: organization "other": not a usable public key: `) {
		t.Errorf("a document whose organization other holds %x was indexed or refused as %v", key, err)
	}
}

func TestValidatePublicKeyAcceptsGeneratedKeys(t *testing.T) {
	for i := range 1000 {
		key := honestKey("generated", i).Public().(ed25519.PublicKey)
		if err := ValidatePublicKey(key); err != nil {
			t.Fatalf("%x was refused: %v", key, err)
		}
	}
}

func TestValidatePublicKeyRefusesAnotherLength(t *testing.T) {
	for _, n := range []int{0, ed25519.PublicKeySize - 1, ed25519.PublicKeySize + 1} {
		if err := ValidatePublicKey(make(ed25519.PublicKey, n)); err == nil {
			t.Errorf("a key of %d octets was accepted", n)
		}
	}
}

// under the keys the registry refuses, ed25519.Verify accepts R = the neutral point and S = 0, which no private key made
func TestSmallOrderKeyVerifiesSignatureMadeWithoutPrivateKey(t *testing.T) {
	neutralEncoding := encode(neutral)
	forged := append(neutralEncoding[:], make([]byte, 32)...)
	honest := honestKey("control", 0).Public().(ed25519.PublicKey)

	// [k]O = O for every k, so every message verifies
	for _, message := range []string{"first message", "second message"} {
		if !ed25519.Verify(neutralEncoding[:], []byte(message), forged) {
			t.Errorf("the neutral key refused the forged signature over %q", message)
		}
	}

	// under the all-zero key, of order 4, a message verifies when its challenge is 0 modulo 4
	var zero [ed25519.PublicKeySize]byte
	verified := -1
	for i := range 128 {
		if ed25519.Verify(zero[:], fmt.Appendf(nil, "message %d", i), forged) {
			verified = i
			break
		}
	}
	if verified < 0 {
		t.Fatal("the all-zero key refused the forged signature over 128 messages")
	}
	if ed25519.Verify(honest, fmt.Appendf(nil, "message %d", verified), forged) {
		t.Errorf("a generated key accepted the forged signature")
	}
}
