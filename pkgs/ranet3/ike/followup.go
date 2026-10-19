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
	// made is the SA the chain makes
	made peerSA
	// done is closed when the chain ends, however it ends
	done chan struct{}
}

// peerSA is the SA a peer's rekey or creation makes, at the answer or once its chain's last exchange ends
type peerSA interface {
	// kind names the SA as the events' sa attribute does
	kind() string
	// install makes the SA under ctx from secrets, SK(0) and then those of the additional key exchanges in order, with the nonces ni and nr, puts it in place and ends the peer's chain
	// it reports false where this end's own rekey superseded the SA and nothing was put in place
	install(s *Session, ctx *ikeContext, secrets [][]byte, ni, nr []byte) (bool, error)
}

// peerIKE is the IKE SA a peer's rekey makes
type peerIKE struct {
	suite      SASuite
	spiI, spiR uint64
}

func (*peerIKE) kind() string { return "ike" }

// peerChild is the Child SA a peer's creation or rekey makes, keyed by the key exchanges of entry
type peerChild struct {
	encr                Transform
	localSPI, remoteSPI uint32
	entry               kexEntry
}

func (*peerChild) kind() string { return "child" }

func newFollowupChain(ctx *ikeContext, made peerSA, methods []uint16, shared, ni, nr []byte) *followupChain {
	c := &followupChain{ctx: ctx, methods: slices.Clone(methods), secrets: [][]byte{shared}, ni: ni, nr: nr, made: made, done: make(chan struct{})}
	c.relink()
	return c
}

// relink draws the link of the next exchange and restarts the wait for it
// RFC 9370 section 2.2.4: "The responder MUST include this notification in a CREATE_CHILD_SA or IKE_FOLLOWUP_KE response message in case the next IKE_FOLLOWUP_KE exchange is expected, filling it with some data that would allow linking the current exchange to the next one."
func (c *followupChain) relink() {
	rand.Read(c.link[:])
	c.deadline = time.Now().Add(followupWait)
}

// links reports whether data is the link of the next exchange, in a time that tells nothing of where the two differ
func (c *followupChain) links(data []byte) bool {
	return subtle.ConstantTimeCompare(c.link[:], data) == 1
}

func (c *followupChain) linkPayload() RawPayload {
	return linkPayload(c.link[:])
}

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
	slog.Info("ike dropped the peer's additional key exchanges", "sa", c.made.kind(), "reason", reason)
	s.emit("ike.followup.dropped", slog.String("sa", c.made.kind()), slog.String("reason", reason))
}

// dropChain ends the peer's chain where why gives a reason to, and tells of it
// why runs with stateMu held and gives "" to keep the chain
func (s *Session) dropChain(why func(c *followupChain) string) {
	s.stateMu.Lock()
	var c *followupChain
	reason := ""
	if open := s.peerChain; open != nil {
		if reason = why(open); reason != "" {
			c = s.takeChainLocked()
		}
	}
	s.stateMu.Unlock()
	if c != nil {
		s.dropped(c, reason)
	}
}

// superseded drops any chain, as a peer's new rekey or creation of an SA does, the peer running one at a time
func superseded(*followupChain) string { return "superseded" }

// expireChain drops the peer's chain once its wait ran out, or once the IKE SA it runs on is no longer current
func (s *Session) expireChain(now time.Time) {
	s.dropChain(func(c *followupChain) string {
		switch {
		case !now.Before(c.deadline):
			return "expired"
		case c.ctx != s.current:
			return "superseded"
		}
		return ""
	})
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

// chainKind names the SA the peer's open chain makes, "" where none is open
func (s *Session) chainKind() string {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.chainKindLocked()
}

// chainKindLocked is chainKind with stateMu held
func (s *Session) chainKindLocked() string {
	if s.peerChain == nil {
		return ""
	}
	return s.peerChain.made.kind()
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
	// section 2.25.1: "If a peer receives a request to rekey a Child SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
	// and a Child SA closes with its IKE SA
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
		c.relink()
		answer = append(answer, c.linkPayload())
		s.stateMu.Unlock()
		return s.response(ctx, msgID, IKE_FOLLOWUP_KE, answer)
	}
	s.stateMu.Unlock()
	return s.finishChain(ctx, msgID, c, answer)
}

// finishChain makes the SA of the peer's chain c, whose last exchange ctx carried at msgID, and answers that exchange with answer where the SA is in place
// a failure of this end's keeps the SA the chain would replace, as handleIKERekey and handleChildRekey keep it
func (s *Session) finishChain(ctx *ikeContext, msgID uint32, c *followupChain, answer []RawPayload) ([]byte, error) {
	placed, err := c.made.install(s, ctx, c.secrets, c.ni, c.nr)
	switch {
	case err != nil:
		slog.Warn("ike cannot answer a peer rekey", "sa", c.made.kind(), "err", err)
	case !placed:
		// this end's own rekey won the simultaneous rekey, so the peer's chain was to stop before this exchange
		s.dropped(c, "superseded")
	default:
		return s.response(ctx, msgID, IKE_FOLLOWUP_KE, answer)
	}
	return s.responseNotify(ctx, msgID, IKE_FOLLOWUP_KE, N_TEMPORARY_FAILURE)
}

// install makes the Child SA and puts it in place, replacing the one the peer rekeys where it rekeys one
// RFC 9370 section 2.2.4: "KEYMAT = prf+ (SK_d, SK(0) | Ni | Nr | SK(1) |  ... SK(n))"
func (made *peerChild) install(s *Session, ctx *ikeContext, secrets [][]byte, ni, nr []byte) (bool, error) {
	s.stateMu.Lock()
	s.takeChainLocked()
	s.stateMu.Unlock()
	initKey, respKey, err := childSAKeymat(ctx.suite.PRFID, ctx.skD, secrets[0], ni, nr, made.encr.ID, made.encr.KeyLengthBits, secrets[1:]...)
	if err == nil {
		err = s.replaceKeyedChild(ChildSA{EncrID: made.encr.ID, EncrKeyBits: made.encr.KeyLengthBits, LocalSPI: made.localSPI, RemoteSPI: made.remoteSPI, InboundKey: initKey, OutboundKey: respKey}, made.entry)
	}
	return err == nil, err
}

// install makes the IKE SA and switches to it, or holds it as the collision's candidate
// RFC 9370 section 2.2.4: "SKEYSEED = prf(SK_d, SK(0) | Ni | Nr | SK(1) | ... SK(n))"
func (made *peerIKE) install(s *Session, ctx *ikeContext, secrets [][]byte, ni, nr []byte) (bool, error) {
	newContext, err := rekeyedContext(ctx, made.suite, secrets, ni, nr, made.spiI, made.spiR, true)
	if err == nil {
		// the SPI map is shared by every mux on the hub
		// so a peer holding two sessions with this node can name an SPI already taken
		err = s.mux.RegisterIKE(made.spiI)
	}
	// the chain gives way to its SA under one lock, so this end's own rekey reads either as the rekey it collides with
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.takeChainLocked()
	if err != nil {
		return false, err
	}
	return s.placePeerIKELocked(ctx, newContext, ni, nr), nil
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
