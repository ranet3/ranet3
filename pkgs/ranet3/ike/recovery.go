// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// recoveryRecord keeps this end's answer to a peer's rekey of an IKE SA for the peer's resends of that rekey, so a busy peer that lost the answer draws it again for as long as it resends
// replaced stays in Session.old while the record lives, its lastPeer holding the answer at mid, and replacement is the SA that replaced it, the one that answer made or, where this end's own rekey won a crossing with that rekey, its chain open or its SA held, or replaced it before or after that rekey was refused, this end's
// lastSent is the last time the answer went out and until the record's end, never past the replaced SA's lifetime
// told marks a record whose first answer past the retention ike.rekey.repeat_answered told
type recoveryRecord struct {
	replaced, replacement *ikeContext
	mid                   uint32
	lastSent, until       time.Time
	told                  bool
}

// recordLocked makes the record of replaced, whose answer at mid to the peer's rekey went out at sent and which replacement replaced, retained at at, with stateMu held
// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// the answer is kept for busyRequestBudget from its send, the sends of a peer that keeps traffic flowing, and no less than retainedContextDeadline from the retention, so the hold of replaced never ends before the one it had
func (s *Session) recordLocked(replaced, replacement *ikeContext, mid uint32, sent, at time.Time) {
	until := sent.Add(busyRequestBudget)
	if retained := at.Add(retainedContextDeadline); retained.After(until) {
		until = retained
	}
	if ends := replaced.established.Add(s.timing.IKERekeyInterval); s.timing.IKERekeyInterval > 0 && ends.Before(until) {
		until = ends
	}
	replaced.replacedAt, replaced.stateNotFoundKept = at, false
	s.recovery = recoveryRecord{replaced: replaced, replacement: replacement, mid: mid, lastSent: sent, until: until}
	if s.old == replaced && until.After(s.oldBy) {
		s.oldBy = until
	}
}

// liveRecordLocked is the record while it serves, nil once s.old no longer holds its SA or that SA's kept answer is another request's, with stateMu held
func (s *Session) liveRecordLocked() *recoveryRecord {
	r := &s.recovery
	if r.replaced == nil || r.replaced != s.old || r.replaced.lastPeerResponseID != r.mid {
		return nil
	}
	return r
}

// endRecordLocked ends the record and lowers the hold of its SA to the retention counted from from, with stateMu held
func (s *Session) endRecordLocked(from time.Time) {
	replaced := s.recovery.replaced
	s.recovery = recoveryRecord{}
	if replaced == nil || s.old != replaced {
		return
	}
	if by := from.Add(retainedContextDeadline); by.Before(s.oldBy) {
		s.oldBy = by
	}
}

// forgetRecordLocked ends the record where it names dropped, an SA a slot of the session no longer holds, so neither the SA nor its keys stay reachable through it, with stateMu held
func (s *Session) forgetRecordLocked(dropped *ikeContext) {
	if s.recovery.replaced == dropped {
		s.recovery = recoveryRecord{}
	}
}

// pastRetention reports whether ctx is an SA this end's rekey replaced or a record held, retained longer than retainedContextDeadline ago
// past it the SA takes the repeat the record serves and its IKE Delete alone
func (s *Session) pastRetention(ctx *ikeContext) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return !ctx.replacedAt.IsZero() && !time.Now().Before(ctx.replacedAt.Add(retainedContextDeadline))
}

// servesRepeat reports whether a repeat at mid on ctx, past its retention, draws the answer ctx keeps there: the record's, or the STATE_NOT_FOUND that took its place, which serves for as long as the record holds ctx
func (s *Session) servesRepeat(ctx *ikeContext, mid uint32) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if r := s.liveRecordLocked(); r != nil && r.replaced == ctx && r.mid == mid && time.Now().Before(r.until) {
		return true
	}
	return heldByStateNotFoundLocked(ctx, &s.recovery) && ctx.lastPeerResponseID == mid
}

// repeatAnswered notes that the answer ctx keeps at mid went out again, and records ike.rekey.repeat_answered at the record's first such answer past ctx's retention
// that tells a repeat was answered, and not that the peer took the answer
func (s *Session) repeatAnswered(ctx *ikeContext, mid uint32) {
	s.stateMu.Lock()
	tell := false
	if r := s.liveRecordLocked(); r != nil && r.replaced == ctx && r.mid == mid {
		r.lastSent = time.Now()
		if !r.told && !r.lastSent.Before(ctx.replacedAt.Add(retainedContextDeadline)) {
			r.told, tell = true, true
		}
	}
	s.stateMu.Unlock()
	if tell {
		slog.Info("ike answered a repeat of the peer's rekey past the replaced IKE SA's retention", "spi", ctx.spiI, "message_id", mid)
		s.emit("ike.rekey.repeat_answered", slog.String("sa", "ike"), slog.Uint64("message_id", uint64(mid)))
	}
}

// answeredOn ends the record of ctx where the answer just kept on ctx is another request's, back to the retention today's code holds it for, and leaves it where that answer is the STATE_NOT_FOUND that takes the kept answer's place
func (s *Session) answeredOn(ctx *ikeContext) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if r := &s.recovery; r.replaced == ctx && ctx.lastPeerResponseID != r.mid && !heldByStateNotFoundLocked(ctx, r) {
		s.endRecordLocked(ctx.replacedAt)
	}
}

// confirm takes a fresh authenticated request on ctx, the current IKE SA, as the peer's switch to it, records ike.rekey.confirmed where ctx was unconfirmed, and ends the record whose replacement ctx is
// the SA a peer's rekey replaced is then kept for the peer's Delete for the retention counted from the last send of the answer, and the SA this end's own rekey replaced, which this end deletes, for the retention counted from that rekey
func (s *Session) confirm(ctx *ikeContext) {
	// most fresh requests come on a confirmed SA no record names, which the read lock tells without holding off the slots' other readers
	s.stateMu.RLock()
	idle := ctx != s.current || !ctx.unconfirmed && s.recovery.replacement != ctx
	s.stateMu.RUnlock()
	if idle {
		return
	}
	s.stateMu.Lock()
	if ctx != s.current {
		s.stateMu.Unlock()
		return
	}
	confirmed := ctx.unconfirmed
	ctx.unconfirmed = false
	if r := s.recovery; r.replacement == ctx {
		if r.replaced != nil && r.replaced.lastPeerResponseID == r.mid {
			r.replaced.lastPeer = answeredRequest{}
		}
		from := r.lastSent
		if r.replaced != nil && r.replaced.ownDelete {
			from = r.replaced.replacedAt
		}
		s.endRecordLocked(from)
	}
	s.stateMu.Unlock()
	if confirmed {
		s.emit("ike.rekey.confirmed", slog.String("sa", "ike"), slog.String("spi", fmt.Sprintf("%016x", ctx.spiI)))
	}
}

// requestPastRetention takes message, a fresh request on ctx from source, where ctx is a replaced IKE SA past its retention and nextPeerMID the Message ID ctx expected
// an INFORMATIONAL carrying the IKE SA's Delete and no payload marked critical that this end does not support goes through handleRequest, which answers it and ends ctx and its record
// an IKE_FOLLOWUP_KE right after the answer ctx's record keeps is answered STATE_NOT_FOUND, as handleFollowup answers it inside the retention, which serves the request's repeats for as long as the record holds ctx, and every other request is dropped unanswered
// a failure there ends ctx alone, the answer counts no send toward the record of sends to the endpoint, and nothing moves the endpoint
func (s *Session) requestPastRetention(ctx *ikeContext, hdr *Header, outer *Message, message *opened, nextPeerMID uint32, source transport.Endpoint) {
	inner, err := decodeMessagePlaintext(message.innerFirst, message.plaintext)
	if err != nil {
		dropPastRetention(ctx, hdr.MessageID, "it does not decode")
		return
	}
	_, found := firstUnsupportedCritical(outer.Payloads, inner)
	// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
	// a peer that took the kept answer opening its rekey's chain sends that exchange next, and ctx holds no chain past its retention, so it draws that answer, which a peer holding the SA its own crossing rekey made takes it to
	if !found && hdr.ExchangeType == IKE_FOLLOWUP_KE && nextPeerMID != maxMessageID && s.keepsStateNotFound(ctx, hdr.MessageID) {
		response, err := s.responseNotify(ctx, hdr.MessageID, IKE_FOLLOWUP_KE, N_STATE_NOT_FOUND)
		if err != nil {
			s.retire(ctx, retiredFailed, failedRequest)
			return
		}
		if sent, err := s.keepAnswer(ctx, hdr.MessageID, response, message); err == nil {
			s.answeredOn(ctx)
			_ = s.sendTo(sent.datagrams, source)
		}
		return
	}
	if found || hdr.ExchangeType != INFORMATIONAL || !deletesIKE(inner) || nextPeerMID == maxMessageID {
		dropPastRetention(ctx, hdr.MessageID, "it is not the SA's Delete")
		return
	}
	response, err := s.handleRequest(ctx, hdr, outer.Payloads, inner)
	if err != nil {
		if response != nil {
			s.answer(response, message.form, source)
		}
		failure := failedRequest
		if _, refused := errors.AsType[invalidSyntaxSent](err); refused {
			failure = failedSyntax
		}
		s.retire(ctx, retiredFailed, failure)
		return
	}
	if sent, err := s.keepAnswer(ctx, hdr.MessageID, response, message); err == nil {
		_ = s.sendTo(sent.datagrams, source)
	}
}

// keepsStateNotFound reports whether mid on ctx is the Message ID right after the answer ctx's live record keeps, and where it is marks the STATE_NOT_FOUND ctx answers there as the answer that takes the kept answer's place, inside ctx's retention or past it
// RFC 7296 section 2.1: "The responder MUST remember each response until it receives a request whose sequence number is larger than or equal to the sequence number in the response plus its window size."
// so answeredOn leaves the record and the hold it gave ctx, which confirm and the peer's Delete still end, and past the retention a repeat of the request draws that answer until then
func (s *Session) keepsStateNotFound(ctx *ikeContext, mid uint32) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	r := s.liveRecordLocked()
	if r == nil || r.replaced != ctx || r.mid+1 != mid || !time.Now().Before(r.until) {
		return false
	}
	ctx.stateNotFoundKept = true
	return true
}

// heldByStateNotFoundLocked reports whether the answer ctx keeps is the STATE_NOT_FOUND keepsStateNotFound marked in place of the answer of r, the record of ctx, with stateMu held
func heldByStateNotFoundLocked(ctx *ikeContext, r *recoveryRecord) bool {
	return r.replaced == ctx && ctx.stateNotFoundKept && ctx.lastPeerResponseID == r.mid+1
}

// dropPastRetention drops the request at mid on ctx, a replaced IKE SA past its retention, for why
func dropPastRetention(ctx *ikeContext, mid uint32, why string) {
	slog.Debug("ike dropped a request on a replaced IKE SA past its retention", "spi", ctx.spiI, "message_id", mid, "why", why)
}
