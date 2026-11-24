// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"
)

// RekeyChild replaces the current Child SA without a new Diffie-Hellman exchange.
// Run must be active, and an error after installation names the failed retirement.
func (s *Session) RekeyChild() error {
	return s.rekeyChild(false, nil)
}

// RekeyChildProactively requests a packet-count-triggered Child SA rekey.
// A running rekey or a session admission wait does not start another exchange.
func (s *Session) RekeyChildProactively() error {
	return s.rekeyChild(true, nil)
}

// session admission survives every Child SA replacement
// only this end's installation clears its count of failed local rekeys
type childRetry struct {
	mu       sync.Mutex
	ended    []childOutcome
	until    time.Time
	failures uint
}

func (r *childRetry) failed(sent bool) uint {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sent {
		r.failures++
	}
	return r.failures
}

func (r *childRetry) installed() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
}

type childOutcome struct {
	rekeyed uint64
	err     error
}

func (r *childRetry) held(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return now.Before(r.until) || slices.ContainsFunc(r.ended, func(outcome childOutcome) bool {
		return outcome.err != nil && !errors.Is(outcome.err, errChildReplaced)
	})
}

func (r *childRetry) opens() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.until
}

func (r *childRetry) end(outcome childOutcome) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = append(r.ended, outcome)
}

// until Run settles this prefix, writers can only append beyond it
func (r *childRetry) unsettled() []childOutcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ended[:len(r.ended):len(r.ended)]
}

func (r *childRetry) settled(n int, until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = slices.Delete(r.ended, 0, n)
	if until.After(r.until) {
		r.until = until
	}
}

// rekeyEnded records how a rekey this end started came out
// sa names the SA it replaced
// the suite attribute names the replacement's transforms
func (s *Session) rekeyEnded(sa string, err error) {
	if err != nil {
		s.emit("ike.rekey.failed", slog.String("sa", sa), slog.String("err", err.Error()))
		return
	}
	suite := s.Suite()
	replacement := suite.ESP()
	if sa == "ike" {
		replacement = suite.IKE()
	}
	s.emit("ike.rekey.completed", slog.String("sa", sa), slog.String("suite", replacement))
}

type childRetirementError struct{ error }

func (e childRetirementError) Unwrap() error { return e.error }

// childUnsentError marks a CREATE_CHILD_SA refusal before the request takes a Message ID, including an IKE SA rekey request.
// The Child rekey path keeps or removes it before Child retry settlement decides whether to count the attempt.
type childUnsentError struct{ error }

func (e childUnsentError) Unwrap() error { return e.error }

func (s *Session) rekeyChild(alreadyRunningIsSuccess bool, target *uint64) (err error) {
	if !s.childRekeying.CompareAndSwap(false, true) {
		if alreadyRunningIsSuccess {
			return nil
		}
		return fmt.Errorf("ike: Child SA rekey already in progress")
	}
	defer func() {
		s.childRekeying.Store(false)
		select {
		case s.childRekeyEnded <- struct{}{}:
		default:
		}
	}()
	var old ChildSA
	var rekeyed uint64
	if target != nil {
		old, rekeyed = s.childWithGeneration()
		if rekeyed != *target {
			return errScheduledChildReplaced
		}
	}
	if s.childWithdrawn() {
		return errors.New("ike: the Child SA is past its lifetime")
	}
	if s.closing.Load() {
		return errors.New("ike: the IKE SA is closing")
	}
	// RFC 7296 section 2.25: "When a peer receives a TEMPORARY_FAILURE notification, it MUST NOT immediately retry the operation" and "it MUST wait so that the sender may complete whatever operation caused the temporary condition."
	if s.childRetry.held(time.Now()) {
		if alreadyRunningIsSuccess {
			return nil
		}
		return errors.New("ike: a Child SA rekey waits out the retry delay of the one that failed")
	}
	s.emit("ike.rekey.started", slog.String("sa", "child"))
	// a scheduled request keeps the snapshot read under the slot
	if target == nil {
		old, rekeyed = s.childWithGeneration()
	}
	defer func() {
		retire, retired := errors.AsType[childRetirementError](err)
		outcome := err
		if retired {
			outcome = nil
		}
		s.childRetry.end(childOutcome{rekeyed, outcome})
		s.rekeyEnded("child", outcome)
		if retired {
			s.emit("ike.rekey.retire_failed", slog.String("sa", "child"), slog.String("err", retire.Error()))
		}
	}()
	// a peer's open chain may replace the SA this request would rekey
	if s.chainKind() != "" {
		return childUnsentError{errors.New("ike: Child SA rekey: the peer's own rekey runs its additional key exchange")}
	}
	if old.LocalSPI == 0 && old.RemoteSPI == 0 {
		return s.negotiateChild(nil, rekeyed)
	}
	if old.LocalSPI == 0 || old.RemoteSPI == 0 {
		return childUnsentError{errors.New("ike: no Child SA to rekey")}
	}
	err = s.negotiateChild(&old, rekeyed)
	var rejected *rejectedError
	if !errors.As(err, &rejected) || rejected.notify.Type != N_CHILD_SA_NOT_FOUND {
		return err
	}
	if rejected.notify.Protocol != ProtoESP || len(rejected.notify.SPI) != 4 || binary.BigEndian.Uint32(rejected.notify.SPI) != old.LocalSPI {
		return fmt.Errorf("ike: invalid CHILD_SA_NOT_FOUND response")
	}
	// RFC 7296 section 2.25 recommends removing the stale half without a Delete
	if err := s.forgetChild(old); err != nil {
		return fmt.Errorf("ike: forget missing peer Child SA: %w", err)
	}
	// CHILD_SA_NOT_FOUND answered the first request, so this attempt sent even
	// if its second negotiation stops before taking another Message ID.
	err = s.negotiateChild(nil, rekeyed)
	if unsent, ok := errors.AsType[childUnsentError](err); ok {
		return unsent.error
	}
	return err
}

var errScheduledChildReplaced = errors.New("ike: the scheduled Child SA rekey target was replaced")

var errChildReplaced = errors.New("ike: the Child SA this exchange set out from was replaced before its request went out")

func (s *Session) negotiateChild(old *ChildSA, generation uint64) error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	context := s.currentContext()
	var replaced uint32
	if old != nil {
		replaced = old.LocalSPI
	}
	localSPI := newChildSPI(replaced)
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, localSPI)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return childUnsentError{fmt.Errorf("ike: generate Child SA rekey nonce: %w", err)}
	}
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	lists := s.lists()
	offer := lists.espProposal(spi)
	if old != nil {
		offer = lists.espRekeyProposal(spi, *old)
	}
	inner := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{offer})},
		{Type: PayloadNonce, Body: EncodeNonce(nonce)},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	var oldLocalSPI []byte
	if old != nil {
		oldLocalSPI = make([]byte, 4)
		binary.BigEndian.PutUint32(oldLocalSPI, old.LocalSPI)
		// RFC 7296 section 1.3.3: "The SA being rekeyed is identified by the SPI field in the Notify payload"
		// and of that SPI: "this is the SPI the exchange initiator would expect in inbound ESP or AH packets."
		inner = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: oldLocalSPI, Type: N_REKEY_SA})}}, inner...)
	}
	// RFC 7296 section 2.8: "the responder MAY begin sending on an SA as soon as it sends its response to the CREATE_CHILD_SA request"
	// so an SPI this end could not then install is refused before the request goes out
	if err := s.canReplaceChild(localSPI, generation); err != nil {
		return childUnsentError{err}
	}
	if err := s.mux.RegisterESP(localSPI); err != nil {
		return childUnsentError{err}
	}
	installed := false
	defer func() {
		if !installed {
			s.mux.UnregisterESP(localSPI)
		}
	}()
	response, err := s.requestOnLocked(context, CREATE_CHILD_SA, inner)
	if err != nil {
		if unsent, ok := errors.AsType[childUnsentError](err); ok {
			return childUnsentError{fmt.Errorf("ike: Child SA negotiation request: %w", unsent.error)}
		}
		return fmt.Errorf("ike: Child SA negotiation request: %w", err)
	}

	// RFC 7296 section 2.8: "The responder to a CREATE_CHILD_SA MUST be prepared to accept messages on an SA before sending its response to the creation request, so there is no ambiguity for the initiator."
	// section 1.4.1: "To delete an SA, an INFORMATIONAL exchange with one or more Delete payloads is sent listing the SPIs (as they would be expected in the headers of inbound packets) of the SAs to be deleted."
	orphaned := func(cause error) error {
		answer, delErr := s.requestLocked(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})}})
		if delErr != nil {
			slog.Warn("ike could not delete the Child SA a failed rekey left at the peer", "spi", localSPI, "err", delErr)
		} else {
			s.halfClosedBy(answer, localSPI)
		}
		return cause
	}

	payloads, err := decodeChildNegotiationResponse(response, context.suite.PRFID)
	if err != nil {
		if _, ok := errors.AsType[*rejectedError](err); ok {
			return err
		}
		return orphaned(err)
	}
	_, encr, remoteSPI, err := decodeChildProposal(payloads.sa.Body, offer.Transforms)
	if err != nil {
		return orphaned(fmt.Errorf("ike: invalid Child SA response proposal: %w", err))
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return orphaned(err)
	}
	initKey, respKey, err := ChildSAKeymat(context.suite.PRFID, context.skD, nonce, payloads.nonce.Body, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return orphaned(err)
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: localSPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return orphaned(err)
	}
	installed = true
	s.childRetry.installed()
	if old == nil {
		return nil
	}
	s.deletingRetiring(old.RemoteSPI)
	deleted, err := s.requestLocked(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{oldLocalSPI}})}})
	// RFC 7296 section 1.4.1 on a Delete that crosses the peer's own: "In that case, the responses MUST NOT include Delete payloads for the deleted SAs, since that would result in duplicate deletion and could in theory delete the wrong SA."
	retireErr := s.retireChild(old.RemoteSPI)
	if err != nil && retireErr != nil {
		return childRetirementError{fmt.Errorf("ike: retire replaced Child SA: %w, and its Delete failed: %w", retireErr, err)}
	}
	if err != nil {
		return childRetirementError{fmt.Errorf("ike: delete replaced Child SA: %w", err)}
	}
	if retireErr != nil {
		return childRetirementError{fmt.Errorf("ike: retire replaced Child SA: %w", retireErr)}
	}
	if s.halfClosedBy(deleted, old.LocalSPI) {
		return nil
	}
	for _, p := range deleted {
		if p.Type != PayloadD {
			continue
		}
		if _, err := DecodeDelete(p.Body); err != nil {
			return childRetirementError{fmt.Errorf("ike: invalid Child SA retire response: %w", err)}
		}
	}
	return nil
}

type rejectedError struct {
	exchange string
	notify   Notify
}

func (e *rejectedError) Error() string {
	return fmt.Sprintf("ike: %s rejected: notify type %d", e.exchange, e.notify.Type)
}

// decodeChildNegotiationResponse reads an error notify in the answer before the payloads of an answer that succeeds
func decodeChildNegotiationResponse(response []RawPayload, prfID uint16) (childExchangePayloads, error) {
	if err := refusal("Child SA negotiation", response); err != nil {
		return childExchangePayloads{}, err
	}
	payloads, err := parseChildExchangePayloads(response)
	if err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	if err := validateCompleteChildExchange(payloads, prfID); err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	if payloads.ke != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: Child SA response includes unrequested KE")
	}
	return payloads, nil
}

func (s *Session) handleChildRekey(ctx *ikeContext, msgID uint32, inner []RawPayload) (*outbound, error) {
	s.stateMu.RLock()
	// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
	// section 2.25.1: "If a peer receives a request to rekey a Child SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
	// section 2.25.2: "If a peer receives a request to create or rekey a Child SA when it is currently rekeying the IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
	// a peer's rekey of the IKE SA runs at this end until its chain ends
	ikeBusy := ctx != s.current || s.localRekey != nil || s.chainKindLocked() == "ike" || s.closing.Load() || s.ikeExpired(ctx)
	s.stateMu.RUnlock()
	if ikeBusy || s.retiringChild().LocalSPI != 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	malformed := func(err error) (*outbound, error) { return s.refuseRequest(ctx, msgID, CREATE_CHILD_SA, err) }
	payloads, err := decodeChildExchangePayloads(inner, ctx.suite.PRFID)
	if err != nil {
		return malformed(err)
	}
	var rekey Notify
	for _, notify := range payloads.notifies {
		if notify.Type == N_REKEY_SA {
			rekey = notify
		}
	}
	rekeying := rekey.Type == N_REKEY_SA
	// RFC 7296 section 3.10 on a notify's Protocol ID: "For notifications concerning Child SAs, this field MUST contain either (2) to indicate AH or (3) to indicate ESP."
	// and on its SPI Size: "Length in octets of the SPI as defined by the IPsec protocol ID or zero if no SPI is applicable."
	if rekeying && ((rekey.Protocol != ProtoESP && rekey.Protocol != ProtoAH) || len(rekey.SPI) != 4) {
		return malformed(fmt.Errorf("ike: REKEY_SA names protocol %d by a %d octet SPI", rekey.Protocol, len(rekey.SPI)))
	}
	if _, err := decodeRequestSA(payloads.sa.Body); err != nil {
		return malformed(err)
	}
	// RFC 7296 section 2.9: "Each TS payload contains one or more Traffic Selectors."
	for _, selectors := range []*RawPayload{payloads.tsi, payloads.tsr} {
		decoded, err := DecodeTS(selectors.Body)
		if err == nil && len(decoded) == 0 {
			err = errors.New("ike: TS payload carries no traffic selector")
		}
		if err != nil {
			return malformed(err)
		}
	}
	var group uint16
	var peerPublic []byte
	if payloads.ke != nil {
		if group, peerPublic, err = decodeRequestKE(payloads.ke.Body); err != nil {
			return malformed(err)
		}
	}
	s.childMu.RLock()
	child, childEntry := s.child, s.childEntryLocked()
	s.childMu.RUnlock()
	if !rekeying && (child.LocalSPI != 0 || child.RemoteSPI != 0) {
		// RFC 7296 section 2.25: "A peer that receives a CHILD_SA_NOT_FOUND notification SHOULD silently delete the Child SA (if it still exists) and send a request to create a new Child SA from scratch (if the Child SA does not yet exist)."
		// so a request without REKEY_SA makes the one Child SA this end keeps while it has none, and is refused while it has one
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_ADDITIONAL_SAS)
	}
	var expected *ChildSA
	if rekeying {
		if s.childRekeying.Load() {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
		}
		if rekey.Protocol != ProtoESP || child.LocalSPI == 0 || binary.BigEndian.Uint32(rekey.SPI) != child.RemoteSPI {
			// RFC 7296 section 2.25: "The SA that the initiator attempted to rekey is indicated by the SPI field in the Notify payload, which is copied from the SPI field in the REKEY_SA notification."
			return s.responseNotifySA(ctx, msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND, rekey.Protocol, rekey.SPI)
		}
		expected = &child
	}
	// the peer runs one creation or rekey of the Child SA at a time, so a new one ends the chain of the last
	s.dropChain(superseded)
	if err := acceptSelectors(payloads.tsi, payloads.tsr); err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TS_UNACCEPTABLE)
	}
	lists := s.lists()
	ciphers, entries := lists.espCiphers(), lists.kexEntries()
	if expected != nil && childEntry.group == group {
		// the answer keeps the cipher and the key exchanges of the Child SA it replaces where the offer and the lists hold them
		entries = promoted(entries, childEntry)
	}
	if expected != nil {
		ciphers = lists.rekeyChoice(*expected)
	}
	selected, err := selectChildRequestProposal(payloads.sa.Body, ciphers, entries, group)
	if err != nil {
		if invalidKE, ok := errors.AsType[*invalidKEError](err); ok {
			return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD,
				invalidKENotifyData(invalidKE.group))
		}
		// an offer refused over lists that left out a transform of the Child SA's suite rekeys it as a reload does
		s.SuitesChanged()
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	// checked once the offer is settled and before the key exchange and the keymat, the work minPeerChildRekeyInterval limits
	// so a rekey answered INVALID_KE_PAYLOAD leaves the limit to the retry it asks for
	// RFC 7296 section 1.3: "In the case of such a rejection, the CREATE_CHILD_SA exchange fails, and the initiator will probably retry the exchange with a Diffie-Hellman proposal and KEi in the group that the responder gave in the INVALID_KE_PAYLOAD Notify payload."
	if expected != nil && !s.allowPeerChildRekey() {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	// RFC 7296 section 1.3.1: "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA: there is no reason to lose the work done to set up the IKE SA."
	// an error returned from here would end the IKE SA, so a failure of this end's answers TEMPORARY_FAILURE
	fail := func(err error) (*outbound, error) {
		slog.Warn("ike cannot answer a peer Child SA rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	var sharedSecret, localPublic []byte
	if selected.dh.ID != 0 {
		dh, err := GenerateDH(selected.dh.ID)
		if err != nil {
			return fail(err)
		}
		sharedSecret, err = dh.SharedSecret(peerPublic)
		if err != nil {
			return malformed(err)
		}
		localPublic = dh.PublicBytes()
	}
	encr := selected.encryption
	var replaced uint32
	if expected != nil {
		replaced = expected.LocalSPI
	}
	localSPI := newChildSPI(replaced)
	spi := binary.BigEndian.AppendUint32(nil, localSPI)
	nr := make([]byte, nonceLen)
	if _, err := rand.Read(nr); err != nil {
		return fail(err)
	}
	ni := append([]byte(nil), payloads.nonce.Body...)
	responseEncr := encr
	if responseEncr.ID == ENCR_CHACHA20_POLY1305 {
		// RFC 7296 section 3.3.6: "Any attributes of a selected transform MUST be returned unmodified."
		// and ChaCha20-Poly1305 is offered with no Key Length, which canonicalEncryptionTransform fills in
		responseEncr.KeyLengthBits = 0
	}
	response := Proposal{Number: selected.proposal.Number, Protocol: ProtoESP, SPI: spi, Transforms: []Transform{responseEncr, {Type: TransESN, ID: ESN_NO}}}
	// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
	if selected.integ.Type != 0 {
		response.Transforms = append(response.Transforms, selected.integ)
	}
	if selected.dh.Type != 0 {
		response.Transforms = append(response.Transforms, selected.dh)
	}
	response.Transforms = append(response.Transforms, selected.additions...)
	responsePayloads := []RawPayload{{Type: PayloadSA, Body: EncodeSA([]Proposal{response})}, {Type: PayloadNonce, Body: EncodeNonce(nr)}}
	if localPublic != nil {
		responsePayloads = append(responsePayloads, RawPayload{Type: PayloadKE, Body: EncodeKE(selected.dh.ID, localPublic)})
	}
	responsePayloads = append(responsePayloads, RawPayload{Type: PayloadTSi, Body: fullRangeSelectors()}, RawPayload{Type: PayloadTSr, Body: fullRangeSelectors()})
	entry := kexChoice{dh: selected.dh, additions: selected.additions}.entry()
	made := &peerChild{encr: encr, localSPI: localSPI, remoteSPI: selected.remoteSPI, entry: entry}
	// RFC 9370 section 2.2.4: "With multiple key exchanges, the SAs are not yet created when the CREATE_CHILD_SA is completed. Instead, they would be created only after the series of IKE_FOLLOWUP_KE exchanges is finished."
	// so the Child SA waits for the one IKE_FOLLOWUP_KE of its additional key exchange, and nothing is installed until then
	if entry.addition != 0 {
		c := newFollowupChain(ctx, made, entry.addition, sharedSecret, ni, nr)
		s.stateMu.Lock()
		// the chain dropped above was the last one open, since only Run's goroutine opens one
		s.peerChain = c
		s.stateMu.Unlock()
		return s.response(ctx, msgID, CREATE_CHILD_SA, append(responsePayloads, c.linkPayload()))
	}
	if _, err := made.install(s, ctx, sharedSecret, nil, ni, nr); err != nil {
		return fail(err)
	}
	return s.response(ctx, msgID, CREATE_CHILD_SA, responsePayloads)
}

// decodeRequestSA reads the SA payload of a peer's request
// RFC 7296 section 2.7: "An SA payload consists of one or more proposals."
func decodeRequestSA(body []byte) ([]Proposal, error) {
	props, err := DecodeSA(body)
	if err == nil && len(props) == 0 {
		err = errors.New("ike: SA payload carries no proposal")
	}
	return props, err
}

// decodeRequestKE reads the KE payload of a peer's request, which names a group and carries a value in it
func decodeRequestKE(body []byte) (uint16, []byte, error) {
	group, public, err := DecodeKE(body)
	if err == nil && (group == 0 || len(public) == 0) {
		err = fmt.Errorf("ike: KE payload of group %d carries %d octets", group, len(public))
	}
	return group, public, err
}
