// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"log/slog"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// recoveryRecord keeps the answer that replaced an IKE SA at a peer's rekey for the peer's resends of that rekey, so a busy peer that lost the answer draws it again for as long as it resends
// replaced stays in Session.old while the record lives, its lastPeer holding the answer at mid, and replacement is the SA that answer made
// lastSent is the last time the answer went out and until the record's end, never past the replaced SA's lifetime
type recoveryRecord struct {
	replaced, replacement *ikeContext
	mid                   uint32
	lastSent, until       time.Time
}

// recordLocked makes the record of replaced, which the answer at mid that went out at sent replaced with replacement, retained at at, with stateMu held
// RFC 7296 section 2.1: "In order to allow saving memory, responders are allowed to forget the response after a timeout of several minutes."
// the answer is kept for busyRequestBudget from the retention, the sends of a peer that keeps traffic flowing, while replacement waits unconfirmed for the peer's first fresh request on it
func (s *Session) recordLocked(replaced, replacement *ikeContext, mid uint32, sent, at time.Time) {
	until := at.Add(busyRequestBudget)
	if ends := replaced.established.Add(s.timing.IKERekeyInterval); s.timing.IKERekeyInterval > 0 && ends.Before(until) {
		until = ends
	}
	replaced.replacedAt = at
	s.recovery = recoveryRecord{replaced: replaced, replacement: replacement, mid: mid, lastSent: sent, until: until}
	if s.old == replaced {
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

// pastRetention reports whether ctx is an SA a peer's rekey replaced through this end's answer, retained longer than retainedContextDeadline ago
// past it the SA takes the repeat the record serves and its IKE Delete alone
func (s *Session) pastRetention(ctx *ikeContext) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return !ctx.replacedAt.IsZero() && !time.Now().Before(ctx.replacedAt.Add(retainedContextDeadline))
}

// servesRepeat reports whether a repeat at mid on ctx draws the record's answer
func (s *Session) servesRepeat(ctx *ikeContext, mid uint32) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	r := s.liveRecordLocked()
	return r != nil && r.replaced == ctx && r.mid == mid && time.Now().Before(r.until)
}

// repeatAnswered notes that the answer ctx keeps at mid went out again
func (s *Session) repeatAnswered(ctx *ikeContext, mid uint32) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if r := s.liveRecordLocked(); r != nil && r.replaced == ctx && r.mid == mid {
		r.lastSent = time.Now()
	}
}

// answeredOn ends the record of ctx where the answer just kept on ctx is another request's, back to the retention today's code holds it for
func (s *Session) answeredOn(ctx *ikeContext) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if r := &s.recovery; r.replaced == ctx && ctx.lastPeerResponseID != r.mid {
		s.endRecordLocked(ctx.replacedAt)
	}
}

// confirm takes a fresh authenticated request on ctx as the peer's switch to it where ctx is the current IKE SA and unconfirmed
// the record whose replacement ctx is then ends, its SA kept for the peer's Delete for the retention counted from the last send of the answer
func (s *Session) confirm(ctx *ikeContext) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if ctx != s.current || !ctx.unconfirmed {
		return
	}
	ctx.unconfirmed = false
	if r := s.recovery; r.replacement == ctx {
		if r.replaced != nil && r.replaced.lastPeerResponseID == r.mid {
			r.replaced.lastPeer = answeredRequest{}
		}
		s.endRecordLocked(r.lastSent)
	}
}

// requestPastRetention takes message, a fresh request on ctx from source, where ctx is a replaced IKE SA past its retention and nextPeerMID the Message ID ctx expected
// an INFORMATIONAL carrying the IKE SA's Delete and no payload marked critical that this end does not support goes through handleRequest, which answers it and ends ctx and its record, and every other request is dropped unanswered
// a failure there ends ctx alone, the answer counts no send toward the record of sends to the endpoint, and nothing moves the endpoint
func (s *Session) requestPastRetention(ctx *ikeContext, hdr *Header, outer *Message, message *opened, nextPeerMID uint32, source transport.Endpoint) {
	inner, err := decodeMessagePlaintext(message.innerFirst, message.plaintext)
	if err != nil {
		dropPastRetention(ctx, hdr.MessageID, "it does not decode")
		return
	}
	if _, found := firstUnsupportedCritical(outer.Payloads, inner); found || hdr.ExchangeType != INFORMATIONAL || !deletesIKE(inner) || nextPeerMID == maxMessageID {
		dropPastRetention(ctx, hdr.MessageID, "it is not the SA's Delete")
		return
	}
	response, err := s.handleRequest(ctx, hdr, outer.Payloads, inner)
	if err != nil {
		if response != nil {
			s.answer(response, message.form, source)
		}
		s.removeRetainedContext(ctx)
		return
	}
	if sent, err := s.keepAnswer(ctx, hdr.MessageID, response, message); err == nil {
		_ = s.sendTo(sent.datagrams, source)
	}
}

// dropPastRetention drops the request at mid on ctx, a replaced IKE SA past its retention, for why
func dropPastRetention(ctx *ikeContext, mid uint32, why string) {
	slog.Debug("ike dropped a request on a replaced IKE SA past its retention", "spi", ctx.spiI, "message_id", mid, "why", why)
}
