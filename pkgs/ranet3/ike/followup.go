// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// followupChain is a peer's rekey this end answered with additional key exchanges still to run, each in an IKE_FOLLOWUP_KE exchange of its own
// RFC 9370 section 2.2.4: "With multiple key exchanges, the SAs are not yet created when the CREATE_CHILD_SA is completed. Instead, they would be created only after the series of IKE_FOLLOWUP_KE exchanges is finished."
type followupChain struct {
	// ctx is the IKE SA the chain's exchanges run on
	ctx      *ikeContext
	link     [followupLinkLen]byte
	deadline time.Time
	// methods holds the additional key exchanges left, the next first
	methods []uint16
	// secrets holds SK(0) and the secret of each additional key exchange run so far
	secrets [][]byte
	ni, nr  []byte
	// ike is the IKE SA the rekey makes
	ike *followupIKE
	// done is closed when the chain ends, however it ends
	done chan struct{}
}

// followupIKE is the IKE SA a peer's rekey makes once its chain ends
type followupIKE struct {
	suite      SASuite
	spiI, spiR uint64
}

func newFollowupChain(ctx *ikeContext, methods []uint16, shared, ni, nr []byte, now time.Time) *followupChain {
	c := &followupChain{ctx: ctx, methods: slices.Clone(methods), secrets: [][]byte{shared}, ni: ni, nr: nr, done: make(chan struct{})}
	c.relink(now)
	return c
}

// relink draws the link of the next exchange and restarts the wait for it
// RFC 9370 section 2.2.4: "The responder MUST include this notification in a CREATE_CHILD_SA or IKE_FOLLOWUP_KE response message in case the next IKE_FOLLOWUP_KE exchange is expected, filling it with some data that would allow linking the current exchange to the next one."
func (c *followupChain) relink(now time.Time) {
	rand.Read(c.link[:])
	c.deadline = now.Add(followupWait)
}

// links reports whether data is the link of the next exchange, in a time that tells nothing of where the two differ
func (c *followupChain) links(data []byte) bool {
	return subtle.ConstantTimeCompare(c.link[:], data) == 1
}

func (c *followupChain) linkPayload() RawPayload {
	return linkPayload(c.link[:])
}

// kind names the SA the chain makes as the events' sa attribute does
func (c *followupChain) kind() string { return "ike" }

// linkPayload is the ADDITIONAL_KEY_EXCHANGE notify carrying data
// RFC 9370 section 2.2.4: "Its Notify Message Type value is 16441, and the Protocol ID and SPI Size are both set to 0."
func linkPayload(data []byte) RawPayload {
	return RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_ADDITIONAL_KEY_EXCHANGE, Data: data})}
}

// linkOf is the data of the first ADDITIONAL_KEY_EXCHANGE notify in payloads, non-nil and possibly empty, or nil where there is none
// it fails on a notify that does not decode
func linkOf(payloads []RawPayload) ([]byte, error) {
	for _, payload := range payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return nil, err
		}
		if notify.Type == N_ADDITIONAL_KEY_EXCHANGE {
			return append([]byte{}, notify.Data...), nil
		}
	}
	return nil, nil
}

// openChainLocked makes c the peer's chain, and returns the one it supersedes
// it must be called with stateMu held
func (s *Session) openChainLocked(c *followupChain) *followupChain {
	superseded := s.peerChain
	s.peerChain = c
	if superseded != nil {
		close(superseded.done)
	}
	return superseded
}

// takeChainLocked ends the peer's chain and returns it, nil where none is open
// it must be called with stateMu held
func (s *Session) takeChainLocked() *followupChain {
	c := s.peerChain
	if c != nil {
		s.peerChain = nil
		close(c.done)
	}
	return c
}

// dropped tells of a chain this end dropped before its last exchange, once
func (s *Session) dropped(c *followupChain, reason string) {
	if c == nil {
		return
	}
	slog.Info("ike dropped the peer's additional key exchanges", "sa", c.kind(), "reason", reason)
	s.emit("ike.followup.dropped", slog.String("sa", c.kind()), slog.String("reason", reason))
}

// expireChain drops the peer's chain once its wait ran out, or once the IKE SA it runs on is no longer current
func (s *Session) expireChain(now time.Time) {
	s.stateMu.Lock()
	var c *followupChain
	reason := "expired"
	if open := s.peerChain; open != nil && (!now.Before(open.deadline) || open.ctx != s.current) {
		if now.Before(open.deadline) {
			reason = "superseded"
		}
		c = s.takeChainLocked()
	}
	s.stateMu.Unlock()
	s.dropped(c, reason)
}

// nextChainExpiry is when the peer's chain runs out of time, for Run to wake at
func (s *Session) nextChainExpiry() (time.Time, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	if s.peerChain == nil {
		return time.Time{}, false
	}
	return s.peerChain.deadline, true
}

func (s *Session) chainOpen() bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.peerChain != nil
}

// handleFollowup answers a peer's IKE_FOLLOWUP_KE on ctx
func (s *Session) handleFollowup(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	link, err := linkOf(inner)
	if err != nil {
		return s.refuseRequest(ctx, msgID, IKE_FOLLOWUP_KE, err)
	}
	s.stateMu.RLock()
	c := s.peerChain
	linked := c != nil && c.ctx == ctx && ctx == s.current && link != nil && c.links(link)
	s.stateMu.RUnlock()
	// RFC 9370 section 2.2.4: "If the responder receives an IKE_FOLLOWUP_KE message for which it does not have a key exchange state, it MUST send back a new error type notification called "STATE_NOT_FOUND"."
	if !linked {
		return s.responseNotify(ctx, msgID, IKE_FOLLOWUP_KE, N_STATE_NOT_FOUND)
	}
	// RFC 7296 section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
	// an IKE SA past its lifetime is closing as well, and the chain is kept for a peer that asks again before the close
	if s.closing.Load() || s.ikeExpired(ctx) {
		return s.responseNotify(ctx, msgID, IKE_FOLLOWUP_KE, N_TEMPORARY_FAILURE)
	}
	method := c.methods[0]
	key, err := keData(inner, method)
	if err != nil {
		return s.refuseRequest(ctx, msgID, IKE_FOLLOWUP_KE, err)
	}
	secret, ciphertext, err := encapsulateKEM(method, key)
	if err != nil {
		// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the checks fail, the responder MUST reject the initiator's improper public key and SHOULD send a Notify payload of type INVALID_SYNTAX as a response to the request to prevent resource exhaustion or denial of service risks."
		rejected := &kexRejection{exchange: "IKE_FOLLOWUP_KE", method: method, side: "key", err: err}
		s.emit("ike.kex.rejected", rejected.attrs()...)
		return s.refuseRequest(ctx, msgID, IKE_FOLLOWUP_KE, rejected)
	}
	answer := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, ciphertext)}}
	s.stateMu.Lock()
	c.secrets, c.methods = append(c.secrets, secret), c.methods[1:]
	if len(c.methods) > 0 {
		c.relink(time.Now())
		answer = append(answer, c.linkPayload())
		s.stateMu.Unlock()
		return s.response(ctx, msgID, IKE_FOLLOWUP_KE, answer)
	}
	s.stateMu.Unlock()
	return s.finishIKEChain(ctx, msgID, c, answer)
}

// finishIKEChain makes the IKE SA of the peer's rekey whose last additional key exchange answer holds, and switches to it as handleIKERekey does
// RFC 9370 section 2.2.4: "SKEYSEED = prf(SK_d, SK(0) | Ni | Nr | SK(1) | ... SK(n))"
func (s *Session) finishIKEChain(ctx *ikeContext, msgID uint32, c *followupChain, answer []RawPayload) ([]byte, error) {
	made := c.ike
	newContext, err := rekeyedContext(ctx, made.suite, c.secrets, c.ni, c.nr, made.spiI, made.spiR, true)
	if err == nil {
		err = s.mux.RegisterIKE(made.spiI)
	}
	// the IKE SA the rekey would replace is kept, as handleIKERekey keeps it on a failure of this end's
	if err != nil {
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		s.stateMu.Lock()
		s.takeChainLocked()
		s.stateMu.Unlock()
		return s.responseNotify(ctx, msgID, IKE_FOLLOWUP_KE, N_TEMPORARY_FAILURE)
	}
	// the chain gives way to its SA under one lock, so this end's own rekey reads either as the rekey it collides with
	s.stateMu.Lock()
	s.takeChainLocked()
	placed := s.placePeerIKELocked(ctx, newContext, c.ni, c.nr)
	s.stateMu.Unlock()
	if !placed {
		// this end's own rekey won the simultaneous rekey, so the peer's chain was to stop before this exchange
		s.dropped(c, "superseded")
		return s.responseNotify(ctx, msgID, IKE_FOLLOWUP_KE, N_TEMPORARY_FAILURE)
	}
	return s.response(ctx, msgID, IKE_FOLLOWUP_KE, answer)
}

// awaitPeerRekey waits for the peer's chain on old, which won a simultaneous rekey this end's own lost, to replace old, and fails when the chain ends without replacing it or the IKE SA starts to close
func (s *Session) awaitPeerRekey(old *ikeContext, c *followupChain) error {
	select {
	case <-c.done:
	// a teardown's Delete waits for this rekey, and a closing IKE SA answers the chain's next exchange TEMPORARY_FAILURE, which would leave the chain open to its deadline
	case <-s.closingSignal():
		return errors.New("ike: IKE SA rekey: the IKE SA is closing")
	case <-s.mux.Done():
		return errors.New("ike: session closed")
	}
	if s.currentContext() == old {
		return fmt.Errorf("ike: IKE SA rekey: the peer's rekey that won the simultaneous rekey ended without replacing the IKE SA")
	}
	return nil
}
