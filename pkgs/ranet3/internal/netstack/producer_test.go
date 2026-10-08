// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package netstack

import (
	"fmt"
	"runtime"
)

// reserveBatch assigns the peer's transmission ticket and its ESP sequence
// range under one lock, waiting for room in the data budget
// rather than dropping. Nothing in the dataplane does that: Mesh reserves
// through reserveBatchNow so one backpressured peer cannot stall the readers
// feeding every other peer. This is the unthrottled producer the ordering
// tests and the benchmarks need, which is why it lives here rather than beside
// them.
func (p *Peer) reserveBatch(count, bytes int) *peerBatch {
	charge := dataCharge(count, bytes)
	for !p.dataBudget.take(charge) {
		select {
		case <-p.stop:
			return &peerBatch{peer: p, err: fmt.Errorf("netstack: peer %s closed", p.ID)}
		default:
			runtime.Gosched()
		}
	}
	return p.reserveTicket(count, charge, false)
}

// filled reserves count one-byte packets of the data budget without waiting and appends that many
// nil when the budget has no room for them
func filled(p *Peer, count int) *peerBatch {
	return filledSized(p, count, 1)
}

// filledSized reserves count packets of size bytes each of the data budget without waiting and appends that many
// nil when the budget has no room for them
func filledSized(p *Peer, count, size int) *peerBatch {
	b := p.reserveBatchNow(count, count*size)
	if b != nil {
		for range count {
			b.append(make([]byte, size), 0)
		}
	}
	return b
}

// sendOrDrop takes a place and sends it in one step, as a caller with
// nothing to decide under a lock does.
func sendOrDrop(p *Peer, raw []byte, nextHeader byte) error {
	place, err := p.ReserveRawOrDrop(raw, nextHeader)
	if err != nil {
		return err
	}
	return place.Send()
}
