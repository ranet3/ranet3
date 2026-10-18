// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"
)

// the tests run ML-KEM-1024 beside ML-KEM-768, which a session runs alone until it implements the IKE fragmentation of RFC 7383
func init() {
	kemMethods = append(kemMethods, kemMethod{ML_KEM_1024,
		func() (crypto.Decapsulator, error) { return mlkem.GenerateKey1024() },
		func(key []byte) (crypto.Encapsulator, error) { return mlkem.NewEncapsulationKey1024(key) }})
}

// kemSizes is the initiator's KE data and the responder's of each method, as crypto/mlkem gives them
var kemSizes = map[uint16][2]int{
	ML_KEM_768:  {mlkem.EncapsulationKeySize768, mlkem.CiphertextSize768},
	ML_KEM_1024: {mlkem.EncapsulationKeySize1024, mlkem.CiphertextSize1024},
}

// a responder takes no encapsulation key that fails the checks of FIPS 203 section 7.2, a coefficient of q or more, one octet short or one long
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "Responders MUST perform the checks on the initiator public key specified in section 7.2 of the Module-Lattice-Based KEM standard [FIPS203] before the Encaps(pk) operation."
func TestEncapsulationKeyFailingItsChecksIsRefused(t *testing.T) {
	for _, method := range kemMethods {
		pair, err := generateKEM(method.id)
		if err != nil {
			t.Fatal(err)
		}
		key := pair.PublicBytes()
		if len(key) != kemSizes[method.id][0] {
			t.Fatalf("method %d drew a key of %d octets, want %d", method.id, len(key), kemSizes[method.id][0])
		}
		// FIPS 203 ByteEncode12 puts the first coefficient in the first octet and the low half of the second
		overQ := slices.Clone(key)
		overQ[0], overQ[1] = 0xff, overQ[1]|0x0f
		for name, bad := range map[string][]byte{
			"a coefficient of 4095": overQ,
			"one octet short":       key[:len(key)-1],
			"one octet long":        append(slices.Clone(key), 0),
		} {
			if secret, ciphertext, err := encapsulateKEM(method.id, bad); err == nil || secret != nil || ciphertext != nil {
				t.Errorf("method %d with %s encapsulated %d octets, %v, want the key refused", method.id, name, len(ciphertext), err)
			}
		}
		if _, _, err := encapsulateKEM(method.id, key); err != nil {
			t.Errorf("method %d refused a key it drew: %v", method.id, err)
		}
	}
}

// an initiator takes no ciphertext of another length than its method's
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "Initiators MUST perform the Ciphertext type check specified in section 7.3 of the Module-Lattice-Based KEM standard [FIPS203] before the Decaps(sk, ct) operation."
func TestCiphertextOfAnotherLengthIsRefused(t *testing.T) {
	for _, method := range kemMethods {
		pair, err := generateKEM(method.id)
		if err != nil {
			t.Fatal(err)
		}
		secret, ciphertext, err := encapsulateKEM(method.id, pair.PublicBytes())
		if err != nil {
			t.Fatal(err)
		}
		if len(ciphertext) != kemSizes[method.id][1] {
			t.Fatalf("method %d encapsulated %d octets, want %d", method.id, len(ciphertext), kemSizes[method.id][1])
		}
		for name, bad := range map[string][]byte{
			"one octet short": ciphertext[:len(ciphertext)-1],
			"one octet long":  append(slices.Clone(ciphertext), 0),
		} {
			if got, err := pair.SharedSecret(bad); err == nil || got != nil {
				t.Errorf("method %d decapsulated a ciphertext %s into %x, %v, want it refused", method.id, name, got, err)
			}
		}
		if got, err := pair.SharedSecret(ciphertext); err != nil || !bytes.Equal(got, secret) || len(got) != mlkem.SharedKeySize {
			t.Errorf("method %d decapsulated %x, %v, want the responder's %x", method.id, got, err, secret)
		}
	}
}

// each exchange draws its own key and each encapsulation its own randomness
// draft-ietf-ipsecme-ikev2-mlkem-09 section 3: "Generating an ephemeral keypair and ciphertext for each ML-KEM key exchange is REQUIRED by this specification."
// draft-ietf-ipsecme-ikev2-mlkem-09 section 3: "Responders also MUST NOT reuse randomness in the generation of KEM ciphertexts."
func TestEveryExchangeDrawsItsOwnKeyAndCiphertext(t *testing.T) {
	for _, method := range kemMethods {
		first, err := generateKEM(method.id)
		if err != nil {
			t.Fatal(err)
		}
		second, err := generateKEM(method.id)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(first.PublicBytes(), second.PublicBytes()) {
			t.Errorf("method %d drew one key twice", method.id)
		}
		secretA, ciphertextA, errA := encapsulateKEM(method.id, first.PublicBytes())
		secretB, ciphertextB, errB := encapsulateKEM(method.id, first.PublicBytes())
		if errA != nil || errB != nil || bytes.Equal(ciphertextA, ciphertextB) || bytes.Equal(secretA, secretB) {
			t.Errorf("method %d encapsulated to one key twice alike: %v, %v", method.id, errA, errB)
		}
	}
}

// Go's ML-KEM from a fixed seed and fixed randomness gives the KE data and SK(1) pinned here, which both ends agree on
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2: "The 32-byte ML-KEM shared secret output, ss, is used without padding like the traditional shared g^ir value in the IKEv2 specification [RFC7296]."
func TestMLKEMKnownAnswers(t *testing.T) {
	seed := make([]byte, mlkem.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	random := bytes.Repeat([]byte{0x5a}, 32)
	for _, test := range []struct {
		method uint16
		// key is the decapsulation key from seed, and encapsulate the responder's side with random
		key         func() (crypto.Decapsulator, error)
		encapsulate func(key []byte) (secret, ciphertext []byte, err error)
		// keyPayload, ciphertextPayload and secret are the SHA-256 of the two KE payloads and of SK(1)
		keyPayload, ciphertextPayload, secret string
	}{
		{
			ML_KEM_768,
			func() (crypto.Decapsulator, error) { return mlkem.NewDecapsulationKey768(seed) },
			func(key []byte) ([]byte, []byte, error) {
				encapsulation, err := mlkem.NewEncapsulationKey768(key)
				if err != nil {
					return nil, nil, err
				}
				return mlkemtest.Encapsulate768(encapsulation, random)
			},
			"95022a1c8dda82a7c455ee059b4724d75d7c7c463ea5d2333fe42a544b8702dc",
			"f973fd1f7b70925173c46aecb884a67a323d9296765199a0f470530c943da5f1",
			"a1005d85111d68acbb7ec3191a274cfd7a0cd3ee5b0c3f5fd258a82c6b1211f8",
		},
		{
			ML_KEM_1024,
			func() (crypto.Decapsulator, error) { return mlkem.NewDecapsulationKey1024(seed) },
			func(key []byte) ([]byte, []byte, error) {
				encapsulation, err := mlkem.NewEncapsulationKey1024(key)
				if err != nil {
					return nil, nil, err
				}
				return mlkemtest.Encapsulate1024(encapsulation, random)
			},
			"c3123ab636c0b9f013f21e93eca9becd05ca944343cc90a90691dbdf96631c2e",
			"6588f3368f7e10909fc529d06875e8ee32a3c2d5467f22c4cb2605d446337f5b",
			"a6dd9afe7ca56b6834f7dc85052a954c607170e7be6f4fe40cc523163dced46f",
		},
	} {
		key, err := test.key()
		if err != nil {
			t.Fatal(err)
		}
		method, err := kemOf(test.method)
		if err != nil {
			t.Fatal(err)
		}
		pair := &kemKeyPair{method: method, key: key}
		secret, ciphertext, err := test.encapsulate(pair.PublicBytes())
		if err != nil {
			t.Fatal(err)
		}
		if got, err := pair.SharedSecret(ciphertext); err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("method %d: the initiator decapsulated %x, %v, the responder holds %x", test.method, got, err, secret)
		}
		digest := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
		for name, pinned := range map[string][2]string{
			"the initiator's KE payload": {digest(EncodeKE(test.method, pair.PublicBytes())), test.keyPayload},
			"the responder's KE payload": {digest(EncodeKE(test.method, ciphertext)), test.ciphertextPayload},
			"SK(1)":                      {digest(secret), test.secret},
		} {
			if pinned[0] != pinned[1] {
				t.Errorf("method %d: %s hashes to %s, want %s", test.method, name, pinned[0], pinned[1])
			}
		}
	}
}
