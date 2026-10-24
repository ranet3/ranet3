// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"sync/atomic"

	"ranet3.com/pkgs/ranet3/srv6"
)

// egressReadiness is the families cap.egress carries out of the mesh, as the translator and the republish last named them
type egressReadiness struct {
	// egressReady holds egressReady4 and egressReady6 for the families SetEgressReady last named ready, none at first
	egressReady atomic.Uint32
	// advertisedReady holds the same bits for the families SetAdvertisedReady last named ready, none at first
	advertisedReady atomic.Uint32
}

// SetAdvertisedReady tells the mesh which families cap.egress translates for the prefixes it advertises, those the translator lets this node announce
// a packet egressing through such a prefix of a family that is not ready is dropped and counted not ready
// the egress segments' readiness is not it, since a node with no egress segment translates its advertised prefixes all the same
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

// egressReadyFor is the bit of egressReady that family, an srv6 next header, needs
func egressReadyFor(family uint8) uint32 {
	if family == srv6.NextHeaderIPv4 {
		return egressReady4
	}
	return egressReady6
}

// egress hands the host frames it carries out of the mesh, an egress segment's inner packets and the decision's through a prefix cap.egress advertises
// each caller has read its own family's readiness first, so every frame here is of a family the translator's rule keyed on the tun covers
func (m *Mesh) egress(frames [][]byte) { m.writeHost(frames) }
