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

// RekeyIKE replaces the IKE SA while retaining the current Child SAs. Run
// must be active to service the serialized IKE requests.
func (s *Session) RekeyIKE() (err error) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	s.emit("ike.rekey.started", slog.String("sa", "ike"))
	defer func() { s.rekeyEnded("ike", err) }()

	old := s.currentContext()
	// Neither SPI of the SA being replaced, for the reason handleIKERekey
	// gives about the peer's choice: the replaced SA stays routed by both
	// until its Delete completes, and the Delete unregisters what it named.
	spiI := randUint64Nonzero()
	for spiI == old.spiI || spiI == old.spiR {
		spiI = randUint64Nonzero()
	}
	group := uint16(DH_CURVE25519)
	ni := make([]byte, nonceLen)
	if err := s.fillIKERekeyNonce(ni); err != nil {
		return fmt.Errorf("ike: generate IKE SA rekey nonce: %w", err)
	}
	s.stateMu.Lock()
	s.localRekey = &ikeRekey{old: old, spiI: spiI, nonce: ni}
	s.stateMu.Unlock()
	defer func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if s.localRekey != nil && s.localRekey.old == old {
			s.localRekey = nil
		}
	}()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiI)
	proposal := ikeRekeyProposal(spi, old.suite.PRFID)
	var (
		dh       *DHKeyPair
		response []RawPayload
	)
	for attempt := range 2 {
		dh, err = GenerateDH(group)
		if err != nil {
			return fmt.Errorf("ike: generate IKE SA rekey DH key: %w", err)
		}
		response, err = s.requestLocked(CREATE_CHILD_SA, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{leadingGroup(proposal, group)})},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
		})
		if err != nil {
			return fmt.Errorf("ike: IKE SA rekey request: %w", err)
		}

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
		if attempt != 0 || !supportedIKEGroup(retryGroup) {
			return fmt.Errorf("ike: IKE SA rekey rejected: requested unsupported DH group %d", retryGroup)
		}
		// RFC 7296 section 1.3: "In the case of such a rejection, the CREATE_CHILD_SA exchange fails, and the initiator will probably retry the exchange with a Diffie-Hellman proposal and KEi in the group that the responder gave in the INVALID_KE_PAYLOAD Notify payload."
		group = retryGroup
	}

	if err := refusal("IKE SA rekey", response); err != nil {
		return err
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
	if sa == nil || nonce == nil || ke == nil {
		return fmt.Errorf("ike: incomplete IKE SA rekey response")
	}
	props, err := DecodeSA(sa.Body)
	// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
	// section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
	// this end's offer names three types, and suiteFromProposal and the loop below hold the answer to the rest
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoIKE ||
		len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		return fmt.Errorf("ike: invalid IKE SA rekey proposal")
	}
	selectedProposal := props[0]
	selectedProposal.SPI = nil
	suite, err := suiteFromProposal(selectedProposal)
	if err != nil {
		return fmt.Errorf("ike: invalid IKE SA rekey transforms: %w", err)
	}
	if suite.DHGroup != group {
		return fmt.Errorf("ike: IKE SA rekey chose DH group %d, want %d", suite.DHGroup, group)
	}
	// Checked here rather than with the other payloads, because half the rule
	// is the key size of the PRF this proposal just settled.
	if !validNonceFor(nonce.Body, suite.PRFID) {
		return fmt.Errorf("ike: IKE SA rekey nonce length %d is short for the negotiated PRF", len(nonce.Body))
	}
	for _, selected := range props[0].Transforms {
		if !slices.Contains(proposal.Transforms, selected) {
			return fmt.Errorf("ike: IKE SA rekey chose unsupported transform %d/%d", selected.Type, selected.ID)
		}
	}
	spiR := binary.BigEndian.Uint64(props[0].SPI)
	if spiR == 0 {
		return fmt.Errorf("ike: IKE SA rekey returned zero SPI")
	}
	peerGroup, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || peerGroup != group {
		return fmt.Errorf("ike: IKE SA rekey KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return fmt.Errorf("ike: IKE SA rekey shared secret: %w", err)
	}
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, shared, ni, nonce.Body, spiI, spiR)
	if err != nil {
		return fmt.Errorf("ike: derive IKE SA rekey keys: %w", err)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR, established: time.Now()}
	s.stateMu.RLock()
	collision := s.collision
	localRekey := s.localRekey
	s.stateMu.RUnlock()
	if collision != nil {
		localLoses := lowestNonceBelongsToFirst(ni, nonce.Body, localRekey.peerNonce, localRekey.peerResponseNonce)
		if localLoses {
			slog.Info("ike simultaneous rekey selected peer candidate")
			if err := s.mux.RegisterIKE(spiI); err != nil {
				return fmt.Errorf("ike: register redundant IKE SA: %w", err)
			}
			// Both the winner and the redundant context must remain visible
			// to dispatch while the Delete exchange is outstanding.
			s.stateMu.Lock()
			s.retainOldLocked(old)
			s.current = collision
			newContext.ownDelete = true
			s.retainCollisionLocked(newContext)
			s.stateMu.Unlock()
			// The redundant SA goes whether or not the peer answers. Leaving
			// it in s.collision refuses every later peer rekey, and the next
			// local one takes this branch again with no peer nonce, so the
			// failure would be permanent rather than one lost exchange.
			answer, deleteErr := s.requestOnLocked(newContext, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
			if deleteErr == nil {
				if refused := refusal("INFORMATIONAL", answer); refused != nil {
					slog.Info("ike redundant IKE SA was not deleted by this end", "spi", spiI, "err", refused)
				}
			}
			// Only if nothing else is routed by it, the rule the three sites
			// around removeRetainedContext and releaseDisplacedLocked already
			// follow. handleIKERekey refuses a peer that names this SPI back,
			// so the two contexts should never share one, but the guard is here
			// because being wrong about that unregisters the SA the session is
			// now current on and leaves the control channel deaf while ESP
			// keeps flowing, and because the peer chooses when to try.
			s.stateMu.Lock()
			if s.collision == newContext {
				s.collision = nil
			}
			s.releaseSPILocked(spiI)
			s.stateMu.Unlock()
			if deleteErr != nil {
				return fmt.Errorf("ike: delete redundant local IKE SA: %w", deleteErr)
			}
			return nil
		}
		// RFC 7296 section 2.8.2: "The new IKE SA containing the lowest nonce SHOULD be deleted by the node that created it, and the other surviving new IKE SA MUST inherit all the Child SAs."
		// the peer created the redundant SA here, and a Delete of it from this end as well would cross the peer's, whose answer from this end retires the SA its own Delete runs on
		// it stays registered for the peer's Delete to be answered, and expireRetainedContexts gives up on a Delete that never comes
		slog.Info("ike simultaneous rekey selected local candidate")
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return fmt.Errorf("ike: register rekeyed IKE SA: %w", err)
	}
	s.stateMu.Lock()
	old.ownDelete = true
	s.retainOldLocked(old)
	s.current = newContext
	s.stateMu.Unlock()

	// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
	// the replacement is current from here, so the rekey has taken effect whatever this exchange does, a peer's own Delete of the old SA arriving first and a refusal among them
	answer, deleteErr := s.requestOnLocked(old, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if deleteErr == nil {
		deleteErr = refusal("INFORMATIONAL", answer)
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

// handleIKERekey accepts a peer-initiated IKE SA rekey. Its response remains
// protected by ctx. The newly-derived context becomes current for subsequent
// exchanges while ctx stays available until the peer deletes it.
func (s *Session) handleIKERekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	s.stateMu.RLock()
	accept := ctx == s.current && (s.old == nil || s.localRekey != nil) && s.collision == nil
	s.stateMu.RUnlock()
	// RFC 7296 section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
	if !accept || s.closing.Load() || s.childRekeying.Load() || s.retiringChild().LocalSPI != 0 || s.ikeExpired(ctx) {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	// checked before the key exchange and the derivation, the work the peer is asking for, see minPeerIKERekeyInterval
	if !s.allowPeerIKERekey() {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	malformed := func(err error) ([]byte, error) { return s.refuseRequest(ctx, msgID, CREATE_CHILD_SA, err) }
	payloads, err := parseChildExchangePayloads(inner)
	if err != nil {
		return malformed(err)
	}
	// RFC 7296 section 1.3.2 gives the request as "HDR, SK {SA, Ni, KEi}", and section 2.10: "Nonces used in IKEv2 MUST be randomly chosen, MUST be at least 128 bits in size, and MUST be at least half the key size of the negotiated pseudorandom function (PRF)."
	// a rekey keeps the IKE SA's PRF, as ikeRekeyProposal offers it, so the nonce is held to that PRF before a proposal is chosen
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
	var (
		selected         []Transform
		suite            SASuite
		selectedProposal Proposal
		preferredGroup   uint16
	)
	for _, proposal := range props {
		if proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 8 || binary.BigEndian.Uint64(proposal.SPI) == 0 {
			continue
		}
		candidate, candidateSuite, candidatePreferred, ok := selectIKERekeyProposal(proposal, group, ctx.suite.PRFID)
		if ok {
			selected = candidate
			suite = candidateSuite
			selectedProposal = proposal
			break
		}
		if candidatePreferred != 0 && (preferredGroup == 0 || ikeGroupPreference(candidatePreferred) < ikeGroupPreference(preferredGroup)) {
			preferredGroup = candidatePreferred
		}
	}
	if selected == nil {
		if preferredGroup == 0 {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		// RFC 7296 section 1.3: "If the responder selects a proposal using a different Diffie-Hellman group (other than NONE), the responder MUST reject the request and indicate its preferred Diffie-Hellman group in the INVALID_KE_PAYLOAD Notify payload."
		return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD, invalidKENotifyData(preferredGroup))
	}
	spiI := binary.BigEndian.Uint64(selectedProposal.SPI)
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
	spiR := randUint64Nonzero()
	keys, err := DeriveRekeyedIKEKeys(ctx.suite.PRFID, ctx.skD, suite, shared, payloads.nonce.Body, nr, spiI, spiR)
	if err != nil {
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		// The SPI map is shared by every mux on the hub, so a peer that holds
		// two sessions with this node knows an SPI that is already taken.
		slog.Warn("ike cannot answer a peer IKE rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR, responder: true, established: time.Now()}
	s.stateMu.Lock()
	local := s.localRekey
	if local != nil && local.old == ctx {
		local.peerNonce = append([]byte(nil), payloads.nonce.Body...)
		local.peerResponseNonce = append([]byte(nil), nr...)
		s.retainCollisionLocked(newContext)
	} else {
		s.retainOldLocked(ctx)
		s.current = newContext
	}
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiR)
	response := Proposal{Number: selectedProposal.Number, Protocol: ProtoIKE, SPI: spi, Transforms: selected}
	return s.response(ctx, msgID, CREATE_CHILD_SA, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{response})},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	})
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

func supportedIKEGroup(group uint16) bool {
	for _, transform := range ikeProposal().Transforms {
		if transform.Type == TransDH && transform.ID == group {
			return true
		}
	}
	return false
}

func ikeGroupPreference(group uint16) int {
	preference := 0
	for _, transform := range ikeProposal().Transforms {
		if transform.Type != TransDH {
			continue
		}
		if transform.ID == group {
			return preference
		}
		preference++
	}
	return preference
}

// Keep the PRF across rekeys: strongSwan uses the old PRF for both SKEYSEED
// and expansion, while RFC 7296 section 2.18 specifies the new PRF for expansion.
// Negotiating the same PRF interoperates without changing either derivation.
func ikeRekeyProposal(spi []byte, prfID uint16) Proposal {
	p := ikeProposal()
	p.SPI = spi
	transforms := p.Transforms[:0]
	for _, transform := range p.Transforms {
		if transform.Type != TransPRF || transform.ID == prfID {
			transforms = append(transforms, transform)
		}
	}
	p.Transforms = transforms
	return p
}

func selectIKERekeyProposal(proposal Proposal, keGroup, prfID uint16) ([]Transform, SASuite, uint16, bool) {
	// RFC 7296 section 3.3.6: "If the responder receives a proposal that contains a Transform Type it does not understand, or a proposal that is missing a mandatory Transform Type, it MUST consider this proposal unacceptable"
	// and of a transform with a Transform Attribute it does not understand: "other transforms with the same Transform Type are processed as usual."
	// DecodeSA marks such a transform, and the exact matching below passes over it
	var integ *Transform
	offeredInteg := false
	for i := range proposal.Transforms {
		transform := proposal.Transforms[i]
		switch transform.Type {
		case TransEncr, TransPRF:
		case TransDH:
			// RFC 7296 section 2.18: "In other words, an initiator MUST NOT propose the value "NONE" for the Diffie-Hellman transform, and a responder MUST NOT accept such a proposal."
			// a proposal that lists NONE among its Diffie-Hellman transforms proposes it, whatever else it lists
			if transform.ID == 0 {
				return nil, SASuite{}, 0, false
			}
		case TransInteg:
			// An AEAD cipher needs no integrity transform, and a peer naming
			// NONE says the same thing as omitting it, the way
			// selectIKEProposal already takes it on the initial exchange.
			// Refusing it here would leave such a peer established and unable
			// to rekey from its own side. An integrity algorithm this end has
			// no key for is one unacceptable transform, not an unacceptable
			// proposal: "other transforms with the same Transform Type are
			// processed as usual".
			offeredInteg = true
			if integ == nil && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
				integ = &transform
			}
		default:
			return nil, SASuite{}, 0, false
		}
	}
	// The offer named integrity transforms and this end can take none of them,
	// so there is no complete set of parameters to select.
	if offeredInteg && integ == nil {
		return nil, SASuite{}, 0, false
	}
	offered := ikeRekeyProposal(nil, prfID).Transforms
	selected := make([]Transform, 0, 4)
	for _, typ := range []TransformType{TransEncr, TransPRF} {
		found := false
		for _, want := range offered {
			if want.Type != typ {
				continue
			}
			for _, got := range proposal.Transforms {
				if got == want {
					selected = append(selected, got)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, SASuite{}, 0, false
		}
	}
	matchingDH, preferredDH, ok := selectDHTransform(proposal.Transforms, keGroup, false)
	if !ok {
		return nil, SASuite{}, preferredDH, false
	}
	selected = append(selected, matchingDH)
	suite, err := suiteFromProposal(Proposal{Number: 1, Protocol: ProtoIKE, Transforms: selected})
	if err != nil {
		return nil, SASuite{}, 0, false
	}
	// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
	// so an integrity transform the peer offered is echoed, after the suite is derived from the three transforms that decide keys
	if integ != nil {
		selected = append(selected, *integ)
	}
	return selected, suite, preferredDH, true
}
