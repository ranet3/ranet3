// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package esp

import (
	"fmt"
	"slices"
)

// Authenticate is AuthenticateInPlace over a copy of pkt, which it leaves as it was
func (in *InboundSA) Authenticate(pkt []byte) (*AuthenticatedPacket, error) {
	return in.AuthenticateInPlace(slices.Clone(pkt))
}

// AuthenticateInPlace is AuthenticateBatchInPlace of pkt alone, answering its refusal
func (in *InboundSA) AuthenticateInPlace(pkt []byte) (*AuthenticatedPacket, error) {
	result := in.AuthenticateBatchInPlace([][]byte{pkt}, nil)[0]
	if result.Err != nil {
		return nil, result.Err
	}
	return &result, nil
}

// Commit is CommitBatch of p alone, then its Plaintext
func (p *AuthenticatedPacket) Commit() ([]byte, byte, error) {
	if p == nil {
		return nil, 0, errUnauthenticated
	}
	batch := []AuthenticatedPacket{*p}
	CommitBatch(batch)
	*p = batch[0]
	return p.Plaintext()
}

// Seal consumes the next sequence number of the range and encrypts one packet
func (r *SequenceRange) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	if r == nil || r.sa == nil || r.next > r.end {
		return nil, fmt.Errorf("esp: reserved sequence range exhausted")
	}
	seq := r.next
	r.next++
	nonceLen := r.sa.aead.NonceSize()
	storage := make([]byte, nonceLen, nonceLen+r.sa.sealedLen(len(innerIPPacket)))
	storage = r.sa.appendSealed(storage, storage[:nonceLen], innerIPPacket, nextHeader, seq)
	return storage[nonceLen:], nil
}

func (r *SequenceRange) SealBatch(innerIPPackets [][]byte, nextHeaders []byte) ([][]byte, error) {
	return r.SealBatchInto(innerIPPackets, nextHeaders, nil)
}
