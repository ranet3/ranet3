// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"crypto"
	"crypto/mlkem"
	"fmt"
)

// kemMethod is an ML-KEM parameter set by the Transform Type 4 ID that names it
type kemMethod struct {
	id       uint16
	generate func() (crypto.Decapsulator, error)
	parse    func([]byte) (crypto.Encapsulator, error)
}

// ML-KEM-1024 waits for the IKE fragmentation of RFC 7383, which its messages need, and Go has no ML-KEM-512
var kemMethods = []kemMethod{
	{ML_KEM_768,
		func() (crypto.Decapsulator, error) { return mlkem.GenerateKey768() },
		func(key []byte) (crypto.Encapsulator, error) { return mlkem.NewEncapsulationKey768(key) }},
}

func kemOf(id uint16) (kemMethod, error) {
	for _, method := range kemMethods {
		if method.id == id {
			return method, nil
		}
	}
	return kemMethod{}, fmt.Errorf("ike: unsupported key exchange method %d", id)
}

// kemKeyPair is the decapsulation key the initiator of one ML-KEM exchange holds
type kemKeyPair struct {
	method kemMethod
	key    crypto.Decapsulator
}

// generateKEM draws a decapsulation key for one exchange, from randomness of its own
// draft-ietf-ipsecme-ikev2-mlkem-09 section 3: "Generating an ephemeral keypair and ciphertext for each ML-KEM key exchange is REQUIRED by this specification."
// draft-ietf-ipsecme-ikev2-mlkem-09 section 3: "For example, at the initiator, the ML-KEM and (EC)DH keypairs used in a PQ/T Hybrid key exchange MUST NOT be generated from the same seed."
func generateKEM(id uint16) (*kemKeyPair, error) {
	method, err := kemOf(id)
	if err != nil {
		return nil, err
	}
	key, err := method.generate()
	if err != nil {
		return nil, fmt.Errorf("ike: generate ML-KEM key: %w", err)
	}
	return &kemKeyPair{method: method, key: key}, nil
}

func (k *kemKeyPair) PublicBytes() []byte { return k.key.Encapsulator().Bytes() }

// SharedSecret is SK(n) from the responder's KE data
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "Initiators MUST perform the Ciphertext type check specified in section 7.3 of the Module-Lattice-Based KEM standard [FIPS203] before the Decaps(sk, ct) operation."
// Decapsulate checks the length first, which is all that check asks of a ciphertext
func (k *kemKeyPair) SharedSecret(ciphertext []byte) ([]byte, error) {
	secret, err := k.key.Decapsulate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("ike: ML-KEM ciphertext fails the type check of FIPS 203 section 7.3: %w", err)
	}
	return secret, nil
}

// encapsulateKEM is SK(n) and the responder's KE data from the initiator's encapsulation key
// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "Responders MUST perform the checks on the initiator public key specified in section 7.2 of the Module-Lattice-Based KEM standard [FIPS203] before the Encaps(pk) operation."
// NewEncapsulationKey768 and NewEncapsulationKey1024 run both checks of that section, the length and the modulus
// draft-ietf-ipsecme-ikev2-mlkem-09 section 3: "Responders also MUST NOT reuse randomness in the generation of KEM ciphertexts."
func encapsulateKEM(id uint16, key []byte) (secret, ciphertext []byte, err error) {
	method, err := kemOf(id)
	if err != nil {
		return nil, nil, err
	}
	encapsulator, err := method.parse(key)
	if err != nil {
		return nil, nil, fmt.Errorf("ike: ML-KEM encapsulation key fails the checks of FIPS 203 section 7.2: %w", err)
	}
	secret, ciphertext = encapsulator.Encapsulate()
	return secret, ciphertext, nil
}
