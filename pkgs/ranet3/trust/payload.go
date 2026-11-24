// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"errors"
	"fmt"
)

// Payload is the signed wrapper around a document. Digest is not a member here.
type Payload struct {
	Height   uint64
	Previous *[32]byte
	Document Document
	Mesh     MeshID
}

type payloadWire struct {
	Height   uint64       `cbor:"1,keyasint"`
	Previous []byte       `cbor:"2,keyasint,omitempty"`
	Document cborDocument `cbor:"3,keyasint"`
	Mesh     []byte       `cbor:"4,keyasint"`
}

func (p Payload) validateHeader() error {
	if p.Height == 0 || p.Height > MaxHeight {
		return fmt.Errorf("trust: invalid snapshot height %d", p.Height)
	}
	if (p.Height == 1) != (p.Previous == nil) {
		return errors.New("trust: previous is absent exactly at height 1")
	}
	return p.Mesh.Validate()
}

func encodePayload(payload Payload) ([]byte, error) {
	if err := payload.validateHeader(); err != nil {
		return nil, err
	}
	document, err := documentToWire(payload.Document)
	if err != nil {
		return nil, err
	}
	wire := payloadWire{Height: payload.Height, Document: document, Mesh: payload.Mesh[:]}
	if payload.Previous != nil {
		wire.Previous = payload.Previous[:]
	}
	return marshalCBOR(wire)
}

func decodePayload(body []byte) (Payload, error) {
	if len(body) > MaxSignedBytes {
		return Payload{}, errors.New("trust: payload exceeds signed file limit")
	}
	var wire payloadWire
	if err := unmarshalCBOR(body, &wire); err != nil {
		return Payload{}, err
	}
	// CDDL fixes mesh width before copying into MeshID, where Validate cannot recover it.
	if len(wire.Mesh) != len(MeshID{}) {
		return Payload{}, fmt.Errorf("trust: mesh has %d bytes, want 16", len(wire.Mesh))
	}
	payload := Payload{Height: wire.Height}
	copy(payload.Mesh[:], wire.Mesh)
	if wire.Previous != nil {
		// CDDL fixes previous width before copying into [32]byte, where Validate cannot recover it.
		if len(wire.Previous) != 32 {
			return Payload{}, fmt.Errorf("trust: previous has %d bytes, want 32", len(wire.Previous))
		}
		payload.Previous = new([32]byte)
		copy(payload.Previous[:], wire.Previous)
	}
	if err := payload.validateHeader(); err != nil {
		return Payload{}, err
	}
	document, err := documentFromWire(wire.Document)
	if err != nil {
		return Payload{}, err
	}
	payload.Document = document
	return payload, nil
}
