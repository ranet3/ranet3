// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/srv6"
)

// egressReadiness is the families cap.egress carries out of the mesh, as the exit and the republish last named them, and the exit carrying them
type egressReadiness struct {
	// egressReady holds egressReady4 and egressReady6 for the families SetEgressReady last named ready, none at first
	egressReady atomic.Uint32
	// advertisedReady holds the same bits for the families SetAdvertisedReady last named ready, none at first
	advertisedReady atomic.Uint32
	// exit is the one SetExit handed over, nil before, and read only once a readiness word names a family ready, which the exit's hooks set after SetExit, so it needs no lock
	exit Exit
}

// Exit is where both egress verdicts hand their batches, the one method of internal/egress's Exit the mesh calls
// it is declared here so this package imports nothing of internal/egress
type Exit interface {
	// Egress takes frames of the families whose readiness the caller read, each TUNHeadroom bytes and then the packet, on the terms DeliverInboundBatch states
	Egress(frames [][]byte)
}

// SetExit hands the mesh the exit both egress verdicts hand their batches to, once and before the exit's hooks name a family ready, since the mesh reads it only once a readiness word does
func (m *Mesh) SetExit(exit Exit) { m.exit = exit }

// SetAdvertisedReady tells the mesh which families cap.egress translates for the prefixes it advertises, those the translator reports ready and lets this node announce
// a packet egressing through such a prefix of a family that is not ready is dropped and counted not ready
// the egress segments' word is not it, since that one also carries cap.border's hold, which holds no advertised prefix back
func (m *Mesh) SetAdvertisedReady(v4, v6 bool) { m.advertisedReady.Store(readyBits(v4, v6)) }

func readyBits(v4, v6 bool) uint32 {
	var ready uint32
	if v4 {
		ready |= egressReady4
	}
	if v6 {
		ready |= egressReady6
	}
	return ready
}

const (
	egressReady4 uint32 = 1 << iota
	egressReady6
)

// SetEgressReady tells the mesh which families the egress segments carry out
// translated, from the translator's last pass and, under cap.border, the
// border filter's, and an egress result of a family that is not ready is
// dropped and counted NotReady
func (m *Mesh) SetEgressReady(v4, v6 bool) { m.egressReady.Store(readyBits(v4, v6)) }

// EgressReady is the families SetEgressReady last named ready
func (m *Mesh) EgressReady() (v4, v6 bool) {
	ready := m.egressReady.Load()
	return ready&egressReady4 != 0, ready&egressReady6 != 0
}

// egressReadyFor is the bit of egressReady that family, an srv6 next header, needs
func egressReadyFor(family uint8) uint32 {
	if family == srv6.NextHeaderIPv4 {
		return egressReady4
	}
	return egressReady6
}

// each caller has read its own family's readiness first, so every frame here is of a family the exit reported ready
// a mesh with no exit holds both words at none, since only an exit's hooks move them, so no frame reaches here without one
// an empty batch, most of decide's and every one of a mesh with no exit, returns before the exit is called
func (m *Mesh) egress(frames [][]byte) {
	if len(frames) == 0 {
		return
	}
	m.exit.Egress(frames)
}
