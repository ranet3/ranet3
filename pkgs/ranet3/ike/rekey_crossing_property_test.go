// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// an IKE SA rekey of this end's that crosses the peer's rekey of the same SA, classical or chained, leaves this end current on the SA the model keeps
// the model is crossedRekeys.keeps'
func TestCrossingIKESARekeysKeepTheSATheModelKeeps(t *testing.T) {
	bubble.Run(testCrossingIKESARekeysKeepTheSATheModelKeeps)(t)
}

func testCrossingIKESARekeysKeepTheSATheModelKeeps(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	pbt.Check(t, func(ht *hegel.T) {
		c := crossedRekeys{answeredFirst: hegel.Draw(ht, hegel.Booleans()), chained: hegel.Draw(ht, hegel.Booleans())}
		answers := crossingAnswers
		if c.chained {
			// an SA answering this end's rekey of an SA of x25519+mlkem768 opens this end's own chain, which keeps does not play
			answers = crossingAnswers[1:]
			c.chainEndsFirst = hegel.Draw(ht, hegel.Booleans())
		}
		c.answer = answers[hegel.Draw(ht, pbt.Spanning(0, len(answers)-1))]
		c.lowest = hegel.Draw(ht, pbt.Spanning(0, 3))
		c.nonces = crossingNonces(ht, c.lowest)
		c.keeps(ht, mux)
	})
}
