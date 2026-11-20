// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"fmt"
	"log/slog"
)

// the reasons ike.sa.retired gives for the end of a retained IKE SA
const (
	// retiredDeleted is the peer's Delete of the SA
	retiredDeleted = "deleted"
	// retiredAnswered is this end's Delete of the SA, answered
	retiredAnswered = "answered"
	// retiredUnanswered is this end's Delete or other request on the SA, deemed failed or refused
	retiredUnanswered = "unanswered"
	// retiredDisplaced is a later rekey that took the SA's slot
	retiredDisplaced = "displaced"
	// retiredBound is the end of the hold, its record's or the retention's, short of the SA's lifetime
	retiredBound = "bound"
	// retiredLifetime is the SA's lifetime
	retiredLifetime = "lifetime"
	// retiredFailed is a request of the peer's on the SA that failed, of the kind ike.sa.retired gives as failure
	retiredFailed = "failed"
)

// the kinds of failure ike.sa.retired gives with retiredFailed
const (
	failedMessageID = "message id"
	failedRequest   = "request"
	failedAnswer    = "answer"
	failedFragments = "fragments"
	failedSyntax    = "syntax"
)

// ikeRetirement is the end of a retained IKE SA as ike.sa.retired tells it
type ikeRetirement struct {
	spi                       uint64
	replaced, reason, failure string
}

// retireLocked queues the end of ctx, a retained IKE SA still in its slot, for tellRetired, with stateMu held
func (s *Session) retireLocked(ctx *ikeContext, reason, failure string) {
	s.queueRetiredLocked(ctx, ctx == s.collision, reason, failure)
}

// queueRetiredLocked queues the end of ctx, which the collision slot held where collision says so, with stateMu held
// replaced is collision for an SA held as a simultaneous rekey's candidate, own for the SA this end's rekey replaced, and peer for one a peer's rekey replaced
func (s *Session) queueRetiredLocked(ctx *ikeContext, collision bool, reason, failure string) {
	replaced := "peer"
	switch {
	case collision:
		replaced = "collision"
	case ctx.ownDelete:
		replaced = "own"
	}
	s.retiredIKE = append(s.retiredIKE, ikeRetirement{spi: ctx.spiI, replaced: replaced, reason: reason, failure: failure})
}

// tellRetired records ike.sa.retired for each end retireLocked queued, once stateMu is released
// it writes no line of its own
func (s *Session) tellRetired() {
	s.stateMu.Lock()
	queued := s.retiredIKE
	s.retiredIKE = nil
	s.stateMu.Unlock()
	for _, r := range queued {
		attrs := []slog.Attr{slog.String("sa", "ike"), slog.String("spi", fmt.Sprintf("%016x", r.spi)), slog.String("replaced", r.replaced), slog.String("reason", r.reason)}
		if r.reason == retiredFailed {
			attrs = append(attrs, slog.String("failure", r.failure))
		}
		s.emit("ike.sa.retired", attrs...)
	}
}
