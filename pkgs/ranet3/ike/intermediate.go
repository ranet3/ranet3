// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
)

// intAuthChunk is IntAuth_[i/r]*A followed by IntAuth_[i/r]*P of one IKE_INTERMEDIATE message
// raw is the message whole as it went on the wire without the non-ESP marker, or as merge rebuilt it from its fragments, skOffset the offset of its Encrypted payload's generic header, and inner its inner payloads in plaintext
// so both ends take the same octets, the critical bit and RESERVED of the Encrypted payload header among them
// RFC 9242 section 3.3.2: "The IntAuth_[i/r]*A chunk consists of the sequence of octets from the first octet of the IKE Header (not including the prepended four octets of zeros, if UDP encapsulation or TCP encapsulation of ESP packets is used) to the last octet of the generic header of the Encrypted payload."
// RFC 9242 section 3.3.2: "In other words, the IntAuth_[i/r]*P chunk is the inner payloads of the Encrypted payload in plaintext form, which is stressed by using the "P" suffix in its name."
// RFC 9242 section 3.3.2: "In other words, the Length field in the IKE Header (denoted as Adjusted Length in Figure 1) is set to the sum of the lengths of IntAuth_[i/r]*A and IntAuth_[i/r]*P, and the Payload Length field in the Encrypted payload header (denoted as Adjusted Payload Length in Figure 1) is set to the length of IntAuth_[i/r]*P plus the size of the Encrypted payload header (four octets)."
func intAuthChunk(raw []byte, skOffset int, inner []byte) ([]byte, error) {
	if skOffset < HeaderLen || len(raw) < skOffset+genericPayloadHeaderLen {
		return nil, fmt.Errorf("ike: IKE_INTERMEDIATE message of %d octets has no Encrypted payload header at %d", len(raw), skOffset)
	}
	a := raw[:skOffset+genericPayloadHeaderLen]
	chunk := make([]byte, 0, len(a)+len(inner))
	chunk = append(chunk, a...)
	chunk = append(chunk, inner...)
	binary.BigEndian.PutUint32(chunk[24:28], uint32(len(a)+len(inner)))
	binary.BigEndian.PutUint16(chunk[skOffset+2:skOffset+4], uint16(genericPayloadHeaderLen+len(inner)))
	return chunk, nil
}

// intAuth is IntAuth_iN and IntAuth_rN so far, both nil before the first IKE_INTERMEDIATE exchange
type intAuth struct {
	i, r []byte
}

// add takes one IKE_INTERMEDIATE exchange, its request and response as intAuthChunk gives them, under the SK_pi and SK_pr that protected it
// RFC 9242 section 3.3.2: "IntAuth_iN = prf(SK_piN, IntAuth_iN-1 | IntAuth_iNA [| IntAuth_iNP])" and "IntAuth_rN = prf(SK_prN, IntAuth_rN-1 | IntAuth_rNA [| IntAuth_rNP])"
// RFC 9242 section 3.3.2: "Note that if keys are updated, then for any given IKE_INTERMEDIATE exchange, the keys SK_e[i/r] and SK_a[i/r] used for protection of its messages (see Section 3.3.1) and the key SK_p[i/r] for its authentication are always from the same generation."
func (a intAuth) add(prfID uint16, skpi, skpr, request, response []byte) intAuth {
	return intAuth{
		i: prf(prfID, skpi, concat(a.i, request)),
		r: prf(prfID, skpr, concat(a.r, response)),
	}
}

// octets is IntAuth, which each end appends to the octets its AUTH covers, and nothing where no IKE_INTERMEDIATE exchange ran
// RFC 9242 section 3.3.2: "If one or more IKE_INTERMEDIATE exchanges took place, the definition of the blob to be signed (or MACed) from Section 2.15 of [RFC7296] is modified as follows:"
// RFC 9242 section 3.3.2: "IntAuth =  IntAuth_iN | IntAuth_rN | IKE_AUTH_MID"
// RFC 9242 section 3.3.2: "It is represented as a four-octet integer in network byte order (in other words, exactly as it appears on the wire)."
func (a intAuth) octets(authMID uint32) []byte {
	if a.i == nil {
		return nil
	}
	return binary.BigEndian.AppendUint32(concat(a.i, a.r), authMID)
}

// keData is the KE data of the one KE payload of an IKE_INTERMEDIATE or IKE_FOLLOWUP_KE message, which names method
// RFC 9370 sections 2.2.2 and 2.2.4: "The former "Diffie-Hellman Group Num" (now called "Key Exchange Method") field in the KEi(n) and KEr(n) payloads MUST match the n-th negotiated additional key exchange."
func keData(inner []RawPayload, method uint16) ([]byte, error) {
	var data []byte
	found := false
	for _, payload := range inner {
		if payload.Type != PayloadKE {
			continue
		}
		if found {
			return nil, errors.New("ike: the message carries two KE payloads")
		}
		got, body, err := DecodeKE(payload.Body)
		if err != nil {
			return nil, err
		}
		if got != method {
			return nil, fmt.Errorf("ike: the KE payload names method %d, and the exchange runs %d", got, method)
		}
		data, found = body, true
	}
	if !found {
		return nil, errors.New("ike: the message carries no KE payload")
	}
	return data, nil
}

// kexRejection is the peer's KE data of side, the key or the ciphertext, that the exchange of method refused
type kexRejection struct {
	exchange string
	method   uint16
	side     string
	err      error
}

func (e *kexRejection) Error() string {
	return fmt.Sprintf("ike: %s %s %s refused: %v", e.exchange, transformName(Transform{Type: TransDH, ID: e.method}), e.side, e.err)
}

func (e *kexRejection) Unwrap() error { return e.err }

func (e *kexRejection) attrs() []slog.Attr {
	return []slog.Attr{
		slog.String("exchange", e.exchange),
		slog.String("method", transformName(Transform{Type: TransDH, ID: e.method})),
		slog.String("side", e.side),
	}
}

// runIntermediates runs an IKE_INTERMEDIATE exchange for each additional key exchange of the SA's entry, at Message IDs from 1, and leaves the SA under the keys of the last
// it returns IntAuth's chain over them
// RFC 9370 section 2.2.2: "For each additional key exchange agreed to in the IKE_SA_INIT exchange, the initiator and the responder perform an IKE_INTERMEDIATE exchange, as described in [RFC9242]."
// RFC 9242 section 3.3.1: "Every subsequent IKE_INTERMEDIATE exchange uses the most recently calculated IKE SA keys before this exchange is started."
func (s *Session) runIntermediates(ni, nr []byte) (intAuth, error) {
	ctx := s.current
	var chain intAuth
	for n, method := range ctx.suite.entry().added() {
		mid := uint32(n + 1)
		pair, err := generateKEM(method)
		if err != nil {
			return intAuth{}, err
		}
		inner := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, pair.PublicBytes())}}
		hdr := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: mid}
		sent, err := s.sealRequest(ctx, hdr, inner)
		if err != nil {
			return intAuth{}, err
		}
		raw, response, answer, plaintext, err := s.encryptedExchange(ctx, sent, maxRetransmits, nil)
		if err != nil {
			return intAuth{}, fmt.Errorf("ike: IKE_INTERMEDIATE %d: %w", mid, err)
		}
		if unsupported, found := firstUnsupportedCritical(response.Payloads, answer); found {
			return intAuth{}, fmt.Errorf("ike: IKE_INTERMEDIATE %d response marks unsupported payload type %d critical", mid, unsupported)
		}
		// RFC 9242 section 3.4 on the error handling of RFC 7296 sections 2.21.1 and 2.21.2: "these considerations are also applied to the IKE_INTERMEDIATE exchange"
		if err := refusal(exchangeName(IKE_INTERMEDIATE), answer); err != nil {
			return intAuth{}, fmt.Errorf("ike: IKE_INTERMEDIATE %d: %w", mid, err)
		}
		ciphertext, err := keData(answer, method)
		var secret []byte
		if err == nil {
			secret, err = pair.SharedSecret(ciphertext)
		}
		if err != nil {
			// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the check fails, the initiator MUST reject the ciphertext and MUST fail the exchange, log the error, and stop creating the SA (i.e. not initiate IKE_AUTH or next IKE_INTERMEDIATE)."
			rejected := &kexRejection{exchange: exchangeName(IKE_INTERMEDIATE), method: method, side: "ciphertext", err: err}
			slog.Warn("ike rejected the responder's ML-KEM ciphertext", "mid", mid, "err", rejected)
			s.emit("ike.kex.rejected", rejected.attrs()...)
			return intAuth{}, fmt.Errorf("ike: IKE_INTERMEDIATE %d: %w", mid, rejected)
		}
		// RFC 9242 section 3.3.2: "The prf calculations MUST be applied to whole messages only, before possible IKE fragmentation."
		requestChunk, err := intAuthChunk(sent.message.whole, HeaderLen, sent.message.inner)
		if err != nil {
			return intAuth{}, err
		}
		responseChunk, err := intAuthChunk(raw, response.skHeaderOffset, plaintext)
		if err != nil {
			return intAuth{}, err
		}
		chain = chain.add(ctx.suite.PRFID, ctx.skpi, ctx.skpr, requestChunk, responseChunk)
		if err := ctx.nextGeneration(secret, ni, nr); err != nil {
			return intAuth{}, err
		}
	}
	return chain, nil
}

// RFC 9370 section 2.2.2: "SKEYSEED(n) = prf(SK_d(n-1), SK(n) | Ni | Nr)"
// that is the SKEYSEED of an IKE SA rekey, with the nonces of IKE_SA_INIT and the PRF kept
// RFC 9370 section 2.2.2: "Both the initiator and the responder use these updated key values in the next exchange (IKE_INTERMEDIATE or IKE_AUTH)."
func (ctx *ikeContext) nextGeneration(secret, ni, nr []byte) error {
	keys, err := DeriveRekeyedIKEKeys(ctx.suite.PRFID, ctx.skD, ctx.suite, secret, ni, nr, ctx.spiI, ctx.spiR)
	if err != nil {
		return err
	}
	ctx.skD, ctx.skei, ctx.sker, ctx.skpi, ctx.skpr = keys.SKd, keys.SKei, keys.SKer, keys.SKpi, keys.SKpr
	return nil
}

// answerIntermediate answers the IKE_INTERMEDIATE request of the exchange running method, decrypted into its first payload's type and plain, and moves the SA to that exchange's keys
// it returns the response, which a retransmission of the request draws again, and chain with the exchange taken in
// a request this end refuses is answered with the refusal and ends the half-open SA
// RFC 7296 section 2.21.2: "request messages that contain an unsupported critical payload, or where the whole message is malformed (rather than just bad payload contents), MUST be rejected in their entirety, and MUST only lead to an UNSUPPORTED_CRITICAL_PAYLOAD or INVALID_SYNTAX Notification sent as a response."
func (s *Session) answerIntermediate(chain intAuth, request *authRequest, method uint16, ni, nr []byte) (*transmission, intAuth, error) {
	ctx, mid := s.current, request.outer.Header.MessageID
	refuse := func(notify NotifyType, data []byte, err error) (*transmission, intAuth, error) {
		if response, buildErr := s.responseNotifyData(ctx, mid, IKE_INTERMEDIATE, notify, data); buildErr == nil {
			s.answer(response, request.form, request.source)
		}
		return nil, intAuth{}, err
	}
	plaintext, err := unpadded(request.plaintext)
	var inner []RawPayload
	if err == nil {
		inner, err = decodeInnerPayloads(request.innerFirst, plaintext)
	}
	if err != nil {
		return refuse(N_INVALID_SYNTAX, nil, fmt.Errorf("ike: malformed IKE_INTERMEDIATE %d request: %w", mid, err))
	}
	if unsupported, found := firstUnsupportedCritical(request.outer.Payloads, inner); found {
		return refuse(N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)}, fmt.Errorf("ike: IKE_INTERMEDIATE %d request marks payload type %d critical", mid, unsupported))
	}
	key, err := keData(inner, method)
	if err != nil {
		return refuse(N_INVALID_SYNTAX, nil, err)
	}
	secret, ciphertext, err := encapsulateKEM(method, key)
	if err != nil {
		// draft-ietf-ipsecme-ikev2-mlkem-09 section 2.2: "If the checks fail, the responder MUST reject the initiator's improper public key and SHOULD send a Notify payload of type INVALID_SYNTAX as a response to the request to prevent resource exhaustion or denial of service risks."
		// the handshake's failure records ike.kex.rejected under the limit of ike.handshake.failed
		return refuse(N_INVALID_SYNTAX, nil, &kexRejection{exchange: exchangeName(IKE_INTERMEDIATE), method: method, side: "key", err: err})
	}
	answer := []RawPayload{{Type: PayloadKE, Body: EncodeKE(method, ciphertext)}}
	response, err := s.response(ctx, mid, IKE_INTERMEDIATE, answer)
	if err != nil {
		return nil, intAuth{}, err
	}
	// RFC 9242 section 3.3.2: "If the message was received in fragmented form, it MUST be reconstructed before calculating the prf as if it were received unfragmented."
	requestChunk, err := intAuthChunk(request.raw, request.outer.skHeaderOffset, plaintext)
	if err != nil {
		return nil, intAuth{}, err
	}
	// RFC 9242 section 3.3.2: "The prf calculations MUST be applied to whole messages only, before possible IKE fragmentation."
	responseChunk, err := intAuthChunk(response.whole, HeaderLen, response.inner)
	if err != nil {
		return nil, intAuth{}, err
	}
	sent, err := s.transmit(response, request.form)
	if err != nil {
		return nil, intAuth{}, err
	}
	chain = chain.add(ctx.suite.PRFID, ctx.skpi, ctx.skpr, requestChunk, responseChunk)
	if err := ctx.nextGeneration(secret, ni, nr); err != nil {
		return nil, intAuth{}, err
	}
	// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
	// the handshake adopts a source at IKE_AUTH alone
	if err := s.sendTo(sent.datagrams, request.source); err != nil {
		return nil, intAuth{}, err
	}
	return sent, chain, nil
}
