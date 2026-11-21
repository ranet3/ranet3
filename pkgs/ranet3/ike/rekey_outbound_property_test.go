// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// maxOutboundDelayMS is the longest one-way delay the property draws, in milliseconds, and maxLostAnswers the most sends of the answer it loses
const maxOutboundDelayMS, maxLostAnswers = 50, 2

// RFC 7296 section 2.8: "The responder can be assured that the initiator is prepared to receive messages on an SA if either (1) it has received a cryptographically valid message on the other half of the SA pair, or (2) the new SA rekeys an existing SA and it receives an IKE request to close the replaced SA."
// every ESP packet either end seals across a Child SA rekey is opened at the other end, whichever end asks, whatever the relay's delay and the sends of the answer and of the Delete it loses, whichever ends carry traffic and whether the asking end's dataplane refuses the SA its rekey made, and neither end is ever without an outbound SA
// once the rekey has ended, the Delete that ends it answered, both ends hold one Child SA, the new one or with the refusal the old one, and neither awaits the retirement of another
func TestChildSARekeyLosesNoPacketAndNoOutboundSA(t *testing.T) {
	bubble.Run(testChildSARekeyLosesNoPacketAndNoOutboundSA)(t)
}

func testChildSARekeyLosesNoPacketAndNoOutboundSA(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		c := outboundCase{
			askerIsInitiator: hegel.Draw(ht, pbt.Spanning(0, 1)) == 1,
			delay:            time.Duration(hegel.Draw(ht, pbt.Spanning(0, maxOutboundDelayMS))) * time.Millisecond,
			lostAnswers:      hegel.Draw(ht, pbt.Spanning(0, maxLostAnswers)),
			lostDeletes:      hegel.Draw(ht, pbt.Spanning(0, 1)),
			refusals:         hegel.Draw(ht, pbt.Spanning(0, 1)),
		}
		// the ends that carry traffic: the answering end, the asking end, or both
		carried := hegel.Draw(ht, pbt.Spanning(1, 3))
		p := dialOutbound(t, c)
		defer p.close()
		p.carry(carried&1 != 0, carried&2 != 0)
		time.Sleep(flowSettle)
		err := p.rekeyChild(t)
		if refused := c.refusals > 0; refused != (err != nil) {
			ht.Fatalf("the Child SA rekey ended with %v where the asking end's dataplane refused it is %v", err, refused)
		}
		if lost := p.losses(); len(lost) > 0 {
			ht.Fatalf("%s", strings.Join(lost, ", "))
		}
		asked, answered := p.asker.Child(), p.answerer.Child()
		if asked.LocalSPI == 0 || asked.LocalSPI != answered.RemoteSPI || asked.RemoteSPI != answered.LocalSPI {
			ht.Fatalf("the asking end holds %08x/%08x and the answering end %08x/%08x, want one Child SA both hold", asked.LocalSPI, asked.RemoteSPI, answered.LocalSPI, answered.RemoteSPI)
		}
		if a, b := p.asker.retiringChild(), p.answerer.retiringChild(); a.LocalSPI != 0 || b.LocalSPI != 0 {
			ht.Fatalf("the asking end awaits the retirement of %08x and the answering end of %08x, want neither", a.LocalSPI, b.LocalSPI)
		}
	})
}
