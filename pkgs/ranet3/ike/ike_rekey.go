// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"
)

// saEnding is a rekey failure after which the IKE SA goes with a Delete, the one Run's teardown sends, and reason names why as ike.sa.closed does
type saEnding struct {
	reason string
	err    error
}

func (e *saEnding) Error() string { return e.err.Error() }
func (e *saEnding) Unwrap() error { return e.err }

// RekeyIKE replaces the IKE SA while retaining the current Child SAs
// Run must be serving the IKE requests it sends
// a failure it returns as a *saEnding ends the IKE SA with a Delete
// it fails while the peer's rekey of either SA runs its additional key exchanges
func (s *Session) RekeyIKE() (err error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	s.emit("ike.rekey.started", slog.String("sa", "ike"))
	defer func() { s.rekeyEnded("ike", err) }()
	defer func() {
		if !rejectedWith(err, N_STATE_NOT_FOUND) {
			s.stateNotFounds = 0
		}
	}()
	// the peer refuses this end's rekey while its own rekey of either SA runs its chain, for the reasons handleIKERekey refuses the peer's, so this end starts none then and the schedule retries after its backoff
	if s.chainKind() != "" {
		return errors.New("ike: IKE SA rekey: the peer's own rekey runs its additional key exchanges")
	}
	ni := make([]byte, nonceLen)
	if err := s.fillIKERekeyNonce(ni); err != nil {
		return fmt.Errorf("ike: generate IKE SA rekey nonce: %w", err)
	}
	lists := s.lists()
	// the SA is read under the lock that records the rekey, so a peer's rekey answered before it made the SA this one replaces, and one answered after it collides with this one
	s.stateMu.Lock()
	old := s.current
	if !lists.holdsPRF(old.suite.PRFID) {
		s.stateMu.Unlock()
		return fmt.Errorf("ike: IKE SA rekey: %w", ErrPRFUnlisted)
	}
	// neither SPI of the SA being replaced
	// it stays routed by both until its Delete completes
	// and the Delete unregisters what it named
	spiI := randUint64Nonzero()
	for spiI == old.spiI || spiI == old.spiR {
		spiI = randUint64Nonzero()
	}
	local := &ikeRekey{old: old, spiI: spiI, nonce: ni}
	s.localRekey = local
	s.stateMu.Unlock()
	defer func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if s.localRekey == local {
			s.localRekey = nil
		}
	}()
	entries := lists.rekeyable(old.suite.entry())
	// RFC 7296 section 1.3: "The Diffie-Hellman group of the KEi MUST be an element of the group the initiator expects the responder to accept (additional Diffie-Hellman groups can be proposed)."
	// the peer took the IKE SA's group in the exchange that made the SA
	group := old.suite.DHGroup
	if !slices.ContainsFunc(entries, func(entry kexEntry) bool { return entry.group == group }) {
		group = entries[0].group
	}
	if slices.ContainsFunc(entries, func(entry kexEntry) bool { return !entry.classical() }) {
		s.quiet.Store(true)
	}
	defer s.quiet.Store(false)
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiI)
	var (
		offer    []Proposal
		dh       *DHKeyPair
		response []RawPayload
		// answered is when the answer came, which the peer's wait for a first IKE_FOLLOWUP_KE runs from
		answered time.Time
	)
	for attempt := range 2 {
		offer = lists.ikeRekeyProposals(spi, old.suite, group)
		dh, err = GenerateDH(group)
		if err != nil {
			return fmt.Errorf("ike: generate IKE SA rekey DH key: %w", err)
		}
		response, err = s.requestLocked(CREATE_CHILD_SA, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA(offer)},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
		})
		if err != nil {
			return fmt.Errorf("ike: IKE SA rekey request: %w", err)
		}
		answered = time.Now()

		var retryGroup uint16
		for i := range response {
			if response[i].Type != PayloadN {
				continue
			}
			notify, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid IKE SA rekey notify: %w", err)
			}
			if notify.Type != N_INVALID_KE_PAYLOAD {
				continue
			}
			if len(notify.Data) != 2 {
				return fmt.Errorf("ike: invalid IKE SA rekey INVALID_KE_PAYLOAD data")
			}
			retryGroup = binary.BigEndian.Uint16(notify.Data)
			break
		}
		if retryGroup == 0 {
			break
		}
		if attempt != 0 || !slices.Contains(transformsOf(offer), Transform{Type: TransDH, ID: retryGroup}) {
			return fmt.Errorf("ike: IKE SA rekey rejected: requested unoffered DH group %d", retryGroup)
		}
		// RFC 7296 section 1.3: "In the case of such a rejection, the CREATE_CHILD_SA exchange fails, and the initiator will probably retry the exchange with a Diffie-Hellman proposal and KEi in the group that the responder gave in the INVALID_KE_PAYLOAD Notify payload."
		group = retryGroup
	}

	answer, err := readIKERekeyAnswer(response, offer, group, dh)
	if err != nil {
		return s.refusedIKERekey(local, err)
	}
	chained := answer.link != nil
	// candidate is the SA this end's exchange made at the peer, which an answer running additional key exchanges makes only at the last of them
	var candidate *ikeContext
	if !chained {
		if candidate, err = rekeyedContext(old, answer.suite, [][]byte{answer.shared}, ni, answer.nonce, spiI, answer.spiR, false); err != nil {
			return fmt.Errorf("ike: derive IKE SA rekey keys: %w", err)
		}
	}
	// a peer's rekey collides with this one once this end answered it, with an SA made or with a chain still open, and the nonces of the exchange that made each settle it
	s.stateMu.Lock()
	// only adoptCollisionOnPeerDelete clears the rekey before its end
	if s.localRekey != local {
		s.stateMu.Unlock()
		// RFC 7296 section 2.8.2: "If the peer that did notice the simultaneous rekey gets the delete request from the other peer for the old IKE SA, it knows that the other peer did not detect the simultaneous rekey, and the first peer can forget its own rekey attempt."
		// the peer's SA is current already, and the SA this end's exchange made goes as a redundant one
		return s.yieldIKERekey(old, candidate, nil)
	}
	collision, chain := s.collision, s.peerChain
	// a peer's chain opened as this rekey started collides with it only where it rekeys the IKE SA
	if s.chainKindLocked() != "ike" {
		chain = nil
	}
	peerNi, peerNr := local.peerNonce, local.peerResponseNonce
	if chain != nil {
		peerNi, peerNr = chain.ni, chain.nr
	}
	lost := (collision != nil || chain != nil) && lowestNonceBelongsToFirst(ni, answer.nonce, peerNi, peerNr)
	local.lost, local.chain = lost, !lost && chained
	s.stateMu.Unlock()
	if lost {
		slog.Info("ike simultaneous rekey selected peer candidate")
		// the peer's SA is current from here where its exchange made it, so the rekey has taken effect whatever the Delete of this end's does
		if err := s.yieldIKERekey(old, candidate, collision); err != nil || collision != nil {
			return err
		}
		// RFC 9370 section 2.2.4: "if additional key exchanges are negotiated in the CREATE_CHILD_SA exchange in which the smallest nonce is used, then, because there is nothing to delete yet, the initiator of this exchange just stops the rekeying process, and it MUST NOT initiate the IKE_FOLLOWUP_KE exchange."
		// the winner is the peer's chain, which makes its SA at its last exchange, and Run starts nothing on old until then, since strongSwan destroys an IKE SA that takes any other request while it waits for IKE_FOLLOWUP_KE
		s.quiet.Store(true)
		return s.awaitPeerRekey(old, chain)
	}
	if collision != nil || chain != nil {
		// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
		// the peer created the redundant SA here, and a Delete of it from this end as well would cross the peer's, whose answer from this end retires the SA its own Delete runs on
		// it stays registered for the peer's Delete to be answered, and expireRetainedContexts gives up on a Delete that never comes
		// a peer's chain that lost stops before its first IKE_FOLLOWUP_KE, and Run drops it once this end's SA is current
		slog.Info("ike simultaneous rekey selected local candidate")
	}
	replacement := candidate
	if chained {
		additional, err := s.followups(answer.suite.entry().added(), answer.link, answered)
		if err != nil {
			return err
		}
		if replacement, err = rekeyedContext(old, answer.suite, append([][]byte{answer.shared}, additional...), ni, answer.nonce, spiI, answer.spiR, false); err != nil {
			return &saEnding{reason: "local failure", err: fmt.Errorf("ike: derive IKE SA rekey keys: %w", err)}
		}
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return fmt.Errorf("ike: register rekeyed IKE SA: %w", err)
	}
	s.stateMu.Lock()
	old.ownDelete = true
	s.retainOldLocked(old)
	s.current = replacement
	s.stateMu.Unlock()

	// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
	// the replacement is current from here, so the rekey has taken effect whatever this exchange does, a peer's own Delete of the old SA arriving first and a refusal among them
	deleted, deleteErr := s.requestOnLocked(old, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if deleteErr == nil {
		deleteErr = refusal("INFORMATIONAL", deleted)
	}
	if deleteErr != nil {
		slog.Info("ike replaced IKE SA was not deleted by this end", "spi", old.spiI, "err", deleteErr)
	}
	s.stateMu.Lock()
	if s.old == old {
		s.old = nil
	}
	s.releaseSPILocked(old.spiI)
	s.stateMu.Unlock()
	return nil
}

// yieldIKERekey ends this end's rekey of old in favor of a peer's rekey of it, making winner current where it is the SA the peer's exchange made
// candidate is the SA this end's exchange made at the peer, nil where its additional key exchanges never ran, and it goes with a Delete of its own
func (s *Session) yieldIKERekey(old, candidate, winner *ikeContext) error {
	if candidate != nil {
		if err := s.mux.RegisterIKE(candidate.spiI); err != nil {
			return fmt.Errorf("ike: register redundant IKE SA: %w", err)
		}
	}
	// the winner and the redundant context both stay visible to dispatch while the Delete is outstanding
	s.stateMu.Lock()
	if winner != nil {
		s.retainOldLocked(old)
		s.current, s.collision = winner, nil
	}
	if candidate != nil {
		candidate.ownDelete = true
		s.retainCollisionLocked(candidate)
	}
	s.stateMu.Unlock()
	if candidate == nil {
		return nil
	}
	// the redundant SA goes whether or not the peer answers
	// one left in s.collision refuses every later peer rekey
	// and the next rekey of this end's would collide with it, with no peer nonce to settle on
	answer, deleteErr := s.requestOnLocked(candidate, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if deleteErr == nil {
		deleteErr = refusal("INFORMATIONAL", answer)
	}
	if deleteErr != nil {
		slog.Info("ike redundant IKE SA was not deleted by this end", "spi", candidate.spiI, "err", deleteErr)
	}
	// released only while nothing else routes by it
	// unregistering the SA the session is current on leaves the control channel deaf while ESP flows
	s.stateMu.Lock()
	if s.collision == candidate {
		s.collision = nil
	}
	s.releaseSPILocked(candidate.spiI)
	s.stateMu.Unlock()
	return nil
}

// rekeyedContext is the IKE SA a rekey of old makes in suite between spiI and spiR, keyed by the secrets of its key exchanges in the order they ran, the responder's where responder holds
func rekeyedContext(old *ikeContext, suite SASuite, secrets [][]byte, ni, nr []byte, spiI, spiR uint64, responder bool) (*ikeContext, error) {
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, secrets[0], ni, nr, spiI, spiR, secrets[1:]...)
	if err != nil {
		return nil, err
	}
	return &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR, responder: responder, established: time.Now()}, nil
}

// followups runs an IKE_FOLLOWUP_KE exchange for each of methods, the first echoing link of the answer that came at answered, and returns their secrets in order
// RFC 9370 section 2.2.4: "Each additional key exchange method MUST be fully completed before the next one is started."
func (s *Session) followups(methods []uint16, link []byte, answered time.Time) ([][]byte, error) {
	var secrets [][]byte
	for n, method := range methods {
		pair, err := generateKEM(method)
		if err != nil {
			return nil, &saEnding{reason: "local failure", err: err}
		}
		// RFC 9370 section 2.2.4: "The initiator MUST send back this notification intact in the request message of the next IKE_FOLLOWUP_KE exchange."
		// the peer's wait runs from the answer before, and followupWait is scaled to the timeout Run resends on
		result := s.awaitLocked(&localRequest{exchange: IKE_FOLLOWUP_KE, inner: []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, pair.PublicBytes())}, linkPayload(link)},
			context: s.currentContext(), result: make(chan requestResult, 1), lateFrom: answered.Add(s.retransmitTimeout() * (followupWait / requestTimeout))})
		if result.err != nil {
			return nil, fmt.Errorf("ike: IKE_FOLLOWUP_KE %d: %w", n+1, result.err)
		}
		answered = time.Now()
		answer := result.inner
		if err := refusal("IKE_FOLLOWUP_KE", answer); err != nil {
			return nil, s.refusedFollowup(err, result.late)
		}
		ciphertext, err := keData(answer, method)
		var secret []byte
		if err == nil {
			secret, err = pair.SharedSecret(ciphertext)
		}
		if err != nil {
			// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the error occurs in the CREATE_CHILD_SA or IKE_FOLLOWUP_KE exchanges, the initiator MUST delete the existing IKE SA and send a Delete payload in a new INFORMATIONAL exchange for the responder to also remove it."
			// a missing KE and another method end it alike, since the two ends then hold different state
			rejected := &kexRejection{exchange: "IKE_FOLLOWUP_KE", method: method, side: "ciphertext", err: err}
			slog.Warn("ike rejected the responder's ML-KEM ciphertext", "err", rejected)
			s.emit("ike.kex.rejected", rejected.attrs()...)
			return nil, &saEnding{reason: "kex rejected", err: rejected}
		}
		secrets = append(secrets, secret)
		if n+1 == len(methods) {
			break
		}
		if link, _ = linkOf(answer); link == nil {
			return nil, &saEnding{reason: "rekey answer refused", err: fmt.Errorf("ike: IKE_FOLLOWUP_KE %d response links no next exchange", n+1)}
		}
	}
	return secrets, nil
}

// refusedFollowup is how a rekey ends whose IKE_FOLLOWUP_KE the peer refused with err, late where the refusal came after a send past the peer's wait
// RFC 9370 section 2.2.4: "If the initiator receives this notification in response to an IKE_FOLLOWUP_KE exchange performing an additional key exchange, it MUST cancel this exchange and MUST treat the whole series of exchanges started from the CREATE_CHILD_SA exchange as having failed."
// RFC 9370 section 2.2.4: "If the initiator continues to receive STATE_NOT_FOUND notifications after several retries, it MUST treat this situation as a fatal error and delete the IKE SA by sending a DELETE payload."
// a late STATE_NOT_FOUND may tell only that the peer's wait ran out while the path lost the sends, so it is no sign of lost state and is not counted
func (s *Session) refusedFollowup(err error, late bool) error {
	if !rejectedWith(err, N_STATE_NOT_FOUND) || late {
		return err
	}
	if s.stateNotFounds++; s.stateNotFounds >= stateNotFoundLimit {
		return &saEnding{reason: "state not found", err: fmt.Errorf("ike: %d IKE SA rekeys in a row were answered STATE_NOT_FOUND: %w", s.stateNotFounds, err)}
	}
	return err
}

// refusedIKERekey is how local, this end's IKE SA rekey, ends where the peer refused its CREATE_CHILD_SA with err, nil where it takes the peer's rekey of the same SA held for it in its place
// RFC 9370 section 2.2.4: "In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
// so a peer whose rekey of the SA this end answered may refuse this one, and it installs its own SA as it reads the answer, which makes the SA held here the one both ends keep
// the peer's nonces are recorded only where its rekey of the SA was held for this one, and a collision without them is the redundant SA of an earlier crossing
func (s *Session) refusedIKERekey(local *ikeRekey, err error) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	// the rekey ends with the decision, so a peer's rekey of the SA that ends after it is placed as one with no rekey of this end's in flight
	if s.localRekey == local {
		s.localRekey = nil
	}
	if s.collision == nil || local.peerNonce == nil || !rejectedWith(err, N_TEMPORARY_FAILURE) {
		return err
	}
	s.retainOldLocked(local.old)
	s.current, s.collision = s.collision, nil
	return nil
}

func rejectedWith(err error, notifyType NotifyType) bool {
	rejected, ok := errors.AsType[*rejectedError](err)
	return ok && rejected.notify.Type == notifyType
}

// ikeRekeyAnswer is the peer's answer to this end's IKE SA rekey
type ikeRekeyAnswer struct {
	suite  SASuite
	nonce  []byte
	spiR   uint64
	shared []byte
	// link is the data of the answer's ADDITIONAL_KEY_EXCHANGE notify, which the first IKE_FOLLOWUP_KE echoes, nil without one
	link []byte
}

// readIKERekeyAnswer reads the answer to an IKE SA rekey offering offer, with its KE payload of dh in group
// an answer refused after it selected an additional key exchange or carried a link fails as a *saEnding, since the peer may hold a chain that waits on this end
// RFC 9370 section 2.2.1: "If the responder's message contains one or more duplicated choices, the initiator should log the error and MUST treat the exchange as failed. The initiator MUST NOT initiate any IKE_INTERMEDIATE (or IKE_FOLLOWUP_KE) exchanges so that no new SA is created. If this happens in the CREATE_CHILD_SA exchange, then the initiator MAY delete the IKE SA over which the invalid message was received by sending a Delete payload."
func readIKERekeyAnswer(response []RawPayload, offer []Proposal, group uint16, dh *DHKeyPair) (ikeRekeyAnswer, error) {
	if err := refusal("IKE SA rekey", response); err != nil {
		return ikeRekeyAnswer{}, err
	}
	var sa, nonce, ke *RawPayload
	for i := range response {
		switch response[i].Type {
		case PayloadSA:
			sa = &response[i]
		case PayloadNonce:
			nonce = &response[i]
		case PayloadKE:
			ke = &response[i]
		}
	}
	// refusal decoded every notify
	link, _ := linkOf(response)
	chained := link != nil || sa != nil && selectsAddition(sa.Body)
	refuse := func(err error) (ikeRekeyAnswer, error) {
		if chained {
			return ikeRekeyAnswer{}, &saEnding{reason: "rekey answer refused", err: err}
		}
		return ikeRekeyAnswer{}, err
	}
	if sa == nil || nonce == nil || ke == nil {
		return refuse(fmt.Errorf("ike: incomplete IKE SA rekey response"))
	}
	props, err := DecodeSA(sa.Body)
	// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
	// suiteFromProposal holds the answer to the proposal of the offer it names
	if err != nil || len(props) != 1 || props[0].Protocol != ProtoIKE || len(props[0].SPI) != 8 {
		return refuse(fmt.Errorf("ike: invalid IKE SA rekey proposal"))
	}
	selectedProposal := props[0]
	selectedProposal.SPI = nil
	suite, err := suiteFromProposal(selectedProposal, offer, true)
	if err != nil {
		return refuse(fmt.Errorf("ike: invalid IKE SA rekey transforms: %w", err))
	}
	if suite.DHGroup != group {
		return refuse(fmt.Errorf("ike: IKE SA rekey chose DH group %d, want %d", suite.DHGroup, group))
	}
	// RFC 7296 section 2.10: "MUST be at least half the key size of the negotiated pseudorandom function (PRF)"
	if !validNonceFor(nonce.Body, suite.PRFID) {
		return refuse(fmt.Errorf("ike: IKE SA rekey nonce length %d is short for the negotiated PRF", len(nonce.Body)))
	}
	spiR := binary.BigEndian.Uint64(props[0].SPI)
	if spiR == 0 {
		return refuse(fmt.Errorf("ike: IKE SA rekey returned zero SPI"))
	}
	peerGroup, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || peerGroup != group {
		return refuse(fmt.Errorf("ike: IKE SA rekey KE group mismatch (got %d, used %d)", peerGroup, group))
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return refuse(fmt.Errorf("ike: IKE SA rekey shared secret: %w", err))
	}
	// RFC 9370 section 2.2.4: "The responder MUST include this notification in a CREATE_CHILD_SA or IKE_FOLLOWUP_KE response message in case the next IKE_FOLLOWUP_KE exchange is expected, filling it with some data that would allow linking the current exchange to the next one."
	// and after an answer with no additional key exchange none is expected
	added := !suite.entry().classical()
	if added && link == nil {
		return refuse(errors.New("ike: IKE SA rekey answer selected additional key exchanges and carried no ADDITIONAL_KEY_EXCHANGE"))
	}
	if !added && link != nil {
		return refuse(errors.New("ike: IKE SA rekey answer carried ADDITIONAL_KEY_EXCHANGE and selected no additional key exchange"))
	}
	return ikeRekeyAnswer{suite: suite, nonce: nonce.Body, spiR: spiR, shared: shared, link: link}, nil
}

// selectsAddition reports whether an SA payload selects a method in an ADDKE type
func selectsAddition(body []byte) bool {
	props, err := DecodeSA(body)
	return err == nil && slices.ContainsFunc(props, func(proposal Proposal) bool {
		return slices.ContainsFunc(proposal.Transforms, func(transform Transform) bool { return additional(transform.Type) && transform.ID != 0 })
	})
}

// handleIKERekey answers a peer's IKE SA rekey under ctx
// the new context is current from the answer on, or from the last IKE_FOLLOWUP_KE of a rekey with additional key exchanges
// ctx stays until the peer deletes it
func (s *Session) handleIKERekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	s.stateMu.RLock()
	accept := ctx == s.current && (s.old == nil || s.localRekey != nil) && s.collision == nil
	ownChain := s.localRekey != nil && s.localRekey.chain
	childChain := s.chainKindLocked() == "child"
	s.stateMu.RUnlock()
	// RFC 7296 section 2.25.1: "If a peer receives a request to rekey the IKE SA, and it is currently creating, rekeying, or closing a Child SA of that IKE SA, it SHOULD reply with TEMPORARY_FAILURE."
	// a peer's creation or rekey of the Child SA runs at this end until its chain ends
	// section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
	// RFC 9370 section 2.2.4: "a situation may occur when, due to packet loss, one of the peers receives the CREATE_CHILD_SA message requesting the rekey of an SA that is already being rekeyed by this peer (i.e., the CREATE_CHILD_SA exchange initiated by this peer has already been completed, and the series of IKE_FOLLOWUP_KE exchanges is in progress). In this case, a TEMPORARY_FAILURE notification MUST be sent in response to such a request."
	if !accept || ownChain || childChain || s.closing.Load() || s.childRekeying.Load() || s.retiringChild().LocalSPI != 0 || s.ikeExpired(ctx) {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	// the peer runs one rekey of the IKE SA at a time, so a new one ends the chain of the last
	s.dropChain(superseded)
	malformed := func(err error) ([]byte, error) { return s.refuseRequest(ctx, msgID, CREATE_CHILD_SA, err) }
	payloads, err := parseChildExchangePayloads(inner)
	if err != nil {
		return malformed(err)
	}
	// RFC 7296 section 1.3.2 gives the request as "HDR, SK {SA, Ni, KEi}", and section 2.10: "Nonces used in IKEv2 MUST be randomly chosen, MUST be at least 128 bits in size, and MUST be at least half the key size of the negotiated pseudorandom function (PRF)."
	// a rekey keeps the IKE SA's PRF, as ikeRekeyProposals offers it, so the nonce is held to that PRF before a proposal is chosen
	if payloads.tsi != nil || payloads.tsr != nil || payloads.sa == nil || payloads.nonce == nil || payloads.ke == nil || !validNonceFor(payloads.nonce.Body, ctx.suite.PRFID) {
		return malformed(errors.New("ike: IKE SA rekey request is not an SA, a nonce and a KE"))
	}
	props, err := decodeRequestSA(payloads.sa.Body)
	if err != nil {
		return malformed(err)
	}
	group, peerPublic, err := decodeRequestKE(payloads.ke.Body)
	if err != nil {
		return malformed(err)
	}
	props = slices.DeleteFunc(props, func(proposal Proposal) bool {
		// RFC 7296 section 2.18: "In other words, an initiator MUST NOT propose the value "NONE" for the Diffie-Hellman transform, and a responder MUST NOT accept such a proposal."
		// a proposal that lists NONE among its Diffie-Hellman transforms proposes it, whatever else it lists
		return proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 8 || binary.BigEndian.Uint64(proposal.SPI) == 0 ||
			slices.ContainsFunc(proposal.Transforms, func(transform Transform) bool { return transform.Type == TransDH && transform.ID == 0 })
	})
	lists := s.lists()
	// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
	// a rekey keeps the PRF
	// so no PRF is authorized once ike prf left out the one in use
	chosen, retry, ok := chooseIKE(props, lists.ikeCiphers(), lists.rekeyPRFs(ctx.suite.PRFID), lists.rekeyEntries(ctx.suite.entry(), group), group)
	if retry != 0 {
		// RFC 7296 section 1.3: "If the responder selects a proposal using a different Diffie-Hellman group (other than NONE), the responder MUST reject the request and indicate its preferred Diffie-Hellman group in the INVALID_KE_PAYLOAD Notify payload."
		return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD, invalidKENotifyData(retry))
	}
	if !ok {
		// an offer refused over lists that left out a transform of this SA's suite replaces or rekeys the SA as a reload does
		s.SuitesChanged()
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	suite := chosen.suite
	// checked once the offer is settled and before the key exchange and the derivation, the work minPeerIKERekeyInterval limits
	// so a rekey answered INVALID_KE_PAYLOAD leaves the limit to the retry it asks for
	if !s.allowPeerIKERekey() {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	spiI := binary.BigEndian.Uint64(chosen.offered.SPI)
	// RFC 7296 section 2.6: "Each endpoint chooses one of the two SPIs and MUST choose them so as to be unique identifiers of an IKE SA."
	// an SPI this session routes registers again on the same mux, and the Delete of the replaced SA would then unregister the SPI another SA is reached by
	// the SPI of a local rekey in flight is refused alike, since this end's request published it, and the losing branch of RekeyIKE would unregister it under the winner
	s.stateMu.RLock()
	taken := s.routedLocked(spiI) || (s.localRekey != nil && s.localRekey.spiI == spiI)
	s.stateMu.RUnlock()
	if taken || spiI == ctx.spiI || spiI == ctx.spiR {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	// RFC 7296 section 1.3.1: "A failed attempt to create a Child SA SHOULD NOT tear down the IKE SA: there is no reason to lose the work done to set up the IKE SA."
	// the IKE SA a rekey would replace is kept the same way, and an error returned from here would end it, so a failure of this end's answers TEMPORARY_FAILURE
	dh, err := GenerateDH(group)
	if err != nil {
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return malformed(err)
	}
	nr := make([]byte, nonceLen)
	if err := s.fillIKERekeyNonce(nr); err != nil {
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	ni := append([]byte(nil), payloads.nonce.Body...)
	spiR := randUint64Nonzero()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiR)
	answer := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: chosen.offered.Number, Protocol: ProtoIKE, SPI: spi, Transforms: chosen.transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	}
	made := &peerIKE{suite: suite, spiI: spiI, spiR: spiR}
	// RFC 9370 section 2.2.4: "If the initiator includes any ADDKE Transform Types in the SA payload (along with Transform Type 4), and if the responder agrees to perform additional key exchanges, then the additional key exchanges are performed in a series of new IKE_FOLLOWUP_KE exchanges that follow the CREATE_CHILD_SA exchange."
	// so the new SA waits for the last of them, and nothing is registered or switched until then
	if added := suite.entry().added(); len(added) > 0 {
		c := newFollowupChain(ctx, made, added, shared, ni, nr)
		s.stateMu.Lock()
		// this end's own rekey may have completed its CREATE_CHILD_SA while the answer was made
		if s.ownChainLocked(ctx) {
			s.stateMu.Unlock()
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
		}
		// the chain dropped above was the last one open, since only Run's goroutine opens one
		s.peerChain = c
		s.stateMu.Unlock()
		return s.response(ctx, msgID, CREATE_CHILD_SA, append(answer, c.linkPayload()))
	}
	placed, err := made.install(s, ctx, [][]byte{shared}, ni, nr)
	if err != nil {
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	if !placed {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	return s.response(ctx, msgID, CREATE_CHILD_SA, answer)
}

// ownChainLocked reports whether this end's own rekey of ctx runs its additional key exchanges, its CREATE_CHILD_SA completed, with stateMu held
func (s *Session) ownChainLocked(ctx *ikeContext) bool {
	return s.localRekey != nil && s.localRekey.old == ctx && s.localRekey.chain
}

// placePeerIKELocked makes made, the IKE SA a peer's rekey of ctx made with the nonces ni and nr, current, or holds it as the collision's candidate while this end's own rekey of ctx waits on its answer
// it reports false while this end's own rekey of ctx runs its additional key exchanges, and then places nothing and releases made's SPI
// it must be called with stateMu held
func (s *Session) placePeerIKELocked(ctx, made *ikeContext, ni, nr []byte) bool {
	switch local := s.localRekey; {
	case s.ownChainLocked(ctx):
		s.releaseSPILocked(made.spiI)
		return false
	case local != nil && local.old == ctx && !local.lost:
		local.peerNonce, local.peerResponseNonce = ni, nr
		s.retainCollisionLocked(made)
	// with no rekey of this end's on ctx, or one that lost a simultaneous rekey and stopped, the peer's replaces the SA as one with no collision does
	default:
		s.retainOldLocked(ctx)
		s.current = made
	}
	return true
}

func (s *Session) fillIKERekeyNonce(nonce []byte) error {
	if s.ikeRekeyNonce != nil {
		return s.ikeRekeyNonce(nonce)
	}
	_, err := rand.Read(nonce)
	return err
}

// compareIKENonces compares complete nonce octet strings as specified by RFC
// 7296 section 2.8.2. Leading zero octets remain significant.
func compareIKENonces(a, b []byte) int {
	return bytes.Compare(a, b)
}

// lowestNonceBelongsToFirst reports whether the lowest of the four nonces is
// from the first rekey exchange, whose candidate must therefore be deleted.
func lowestNonceBelongsToFirst(firstI, firstR, secondI, secondR []byte) bool {
	lowest := firstI
	first := true
	for _, candidate := range []struct {
		nonce []byte
		first bool
	}{{firstR, true}, {secondI, false}, {secondR, false}} {
		if bytes.Compare(candidate.nonce, lowest) < 0 {
			lowest, first = candidate.nonce, candidate.first
		}
	}
	return first
}
