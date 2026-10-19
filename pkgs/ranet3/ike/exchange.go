// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// errOvertaken ends an exchange whose own answer no longer matters, since a request the peer sent while it was out settled it
var errOvertaken = errors.New("ike: the peer's own request settled the exchange")

// encryptedRoundTrip ignores a packet that does not authenticate though its header matches the outstanding exchange
// a syntax error once the tag verifies goes to the caller with the response that carried it, so a nil response means none decrypted
func (s *Session) encryptedRoundTrip(ctx *ikeContext, req *transmission) (*Message, []RawPayload, error) {
	_, response, inner, _, err := s.encryptedExchange(ctx, req, maxRetransmits, nil)
	return response, inner, err
}

// encryptedExchange also returns the response's octets and its inner payloads in plaintext, which IntAuth covers
// a response that arrives in fragments is the message they make
func (s *Session) encryptedExchange(ctx *ikeContext, req *transmission, attempts int, request func([]byte, transport.Endpoint) bool) (raw []byte, response *Message, inner []RawPayload, plaintext []byte, err error) {
	var answer *opened
	var limit error
	resend := func(t *transmission) (bool, error) { return s.retransmit(t, s.mux.SendIKE) }
	_, err = sendRecvWithin(s.mux, req, attempts, requestTimeout, resend, func(raw []byte) bool {
		m, err := DecodeMessage(raw)
		if err != nil {
			return false
		}
		answer, limit = s.open(ctx, &ctx.responseFragments, raw, m)
		return answer != nil || limit != nil
	}, request)
	if err == nil {
		err = limit
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if plaintext, err = unpadded(answer.plaintext); err != nil {
		return answer.raw, answer.outer, nil, nil, err
	}
	inner, err = decodeInnerPayloads(answer.innerFirst, plaintext)
	return answer.raw, answer.outer, inner, plaintext, err
}

// sendRecv sends req until a correlated response accept takes arrives, and a nil accept takes any
// RFC 7815 section 2.1: "A minimal implementation can simply ignore those errors and retransmit its request until it times out, and if that happens, then the IKE SA (and Child SA) creation failed."
func sendRecv(mux *transport.Mux, req []byte, accept func([]byte) bool) ([]byte, error) {
	return sendRecvWithin(mux, &transmission{datagrams: [][]byte{req}}, maxRetransmits, requestTimeout, nil, accept, nil)
}

// sendRecvWithin is sendRecv within attempts sends whose backoff starts at timeout, and request, where it is set, takes each request the peer sends meanwhile with the address it came from and reports whether it settles the exchange
// resend, where it is set, sends each attempt and reports whether it cut the request again, and the request otherwise goes as it is
func sendRecvWithin(mux *transport.Mux, req *transmission, attempts int, timeout time.Duration, resend func(*transmission) (bool, error), accept func([]byte) bool, request func([]byte, transport.Endpoint) bool) ([]byte, error) {
	reqHdr, err := decodeHeader(req.datagrams[0])
	if err != nil {
		return nil, err
	}
	// registered before the first send, so a response cannot race the receive loop on a shared hub
	if err := mux.RegisterIKE(reqHdr.SPIInitiator); err != nil {
		return nil, err
	}
	if resend == nil {
		resend = func(t *transmission) (bool, error) { return false, sendEach(mux.SendIKE, t.datagrams) }
	}
	sends := 0
	// a split again starts the budget over, so the sends of a busy peer's exchange bound it
	for attempt := 0; attempt < attempts && sends < maxRetransmitsWhileBusy; attempt++ {
		again, err := resend(req)
		if err != nil {
			return nil, err
		}
		// RFC 7383 section 2.5.2: "When starting a new probe, the node MUST reset its retransmission timers so that if it employs exponential back-off the timers will start over."
		if again {
			attempt = 0
		}
		sends++
		deadline := time.Now().Add(retransmitDelay(timeout, attempt+1))
		for time.Now().Before(deadline) {
			raw, source, err := mux.RecvIKEFromUntil(deadline)
			if err != nil {
				// a closed mux still sends, so its exchange ends here instead of retransmitting
				if mux.IsClosed() {
					return nil, err
				}
				break
			}
			h, err := decodeHeader(raw)
			if err != nil || higherVersion(mux.SendIKETo, h, source) {
				continue
			}
			if validResponseHeader(reqHdr, h, len(raw)) {
				if accept == nil || accept(raw) {
					return raw, nil
				}
				// a correlated response accept refuses, such as an unauthenticated error notify, may be forged
				continue
			}
			// RFC 7296 section 2.3: "An IKE endpoint MUST be prepared to accept and process a request while it has a request outstanding in order to avoid a deadlock in this situation."
			if request != nil && !h.IsResponse() && request(raw, source) {
				return nil, errOvertaken
			}
		}
	}
	return nil, fmt.Errorf("ike: no response after %d attempts", sends)
}

func validResponseHeader(request, response *Header, rawLen int) bool {
	if response.MajorVersion != 2 || response.ExchangeType != request.ExchangeType ||
		response.MessageID != request.MessageID || !response.IsResponse() ||
		response.IsInitiator() == request.IsInitiator() ||
		response.SPIInitiator != request.SPIInitiator || response.Length != uint32(rawLen) {
		return false
	}
	if request.SPIResponder == 0 {
		// IKE_SA_INIT error responses such as COOKIE and
		// INVALID_KE_PAYLOAD carry a zero responder SPI (RFC 7296
		// section 2.6.1). The exchange-specific accept callback validates the
		// payload before treating such an unauthenticated response as useful.
		return request.ExchangeType == IKE_SA_INIT
	}
	return response.SPIResponder == request.SPIResponder
}

// higherVersion reports whether header is at a major version above this end's, and answers a request among those at source
// RFC 7296 section 2.5: "If an endpoint receives a message with a higher major version number, it MUST drop the message and SHOULD send an unauthenticated Notify message of type INVALID_MAJOR_VERSION containing the highest (closest) version number it supports."
// the version the answer carries is that of its own header, 2.0
func higherVersion(send func([]byte, transport.Endpoint) error, header *Header, source transport.Endpoint) bool {
	if header.MajorVersion <= 2 {
		return false
	}
	// RFC 7296 section 3.1: "An IKE endpoint MUST NOT generate a response to a message that is marked as being a response"
	if !header.IsResponse() && statelessErrors.take() {
		_ = send(statelessNotify(header, N_INVALID_MAJOR_VERSION, nil), source)
	}
	return true
}

// statelessErrors is the one limit on the error notifies this node sends in the clear, from no IKE SA, that end the exchange: INVALID_MAJOR_VERSION, UNSUPPORTED_CRITICAL_PAYLOAD and NO_PROPOSAL_CHOSEN
// RFC 7296 section 2.21.4: "A node needs to limit the rate at which it will send messages in response to unprotected messages."
// section 2.6.1: "There are two common reasons why the initiator may have to retry the IKE_SA_INIT exchange: the responder requests a cookie or wants a different Diffie-Hellman group than was included in the KEi payload."
// COOKIE and INVALID_KE_PAYLOAD, the two answers an initiator retries after, are outside it, so one source that spends it cannot stop another's dial
// INVALID_KE_PAYLOAD is one answer to one request, shorter than the request, and holds its half-open slot only until it goes out, so cookies do not bound how many are sent
var statelessErrors = newAnswerLimit(statelessErrorBurst, statelessErrorsPerSecond)

// answerLimit is a bucket of answers that refills at a steady rate, and counts the answers it holds back
type answerLimit struct {
	mu        sync.Mutex
	burst     float64
	perSecond float64
	tokens    float64
	filled    time.Time
	// held counts the answers held back since said, the last time a line told of them
	held int
	said time.Time
}

func newAnswerLimit(burst int, perSecond float64) *answerLimit {
	now := time.Now()
	// one interval in the past, so the first answer held back is said rather than spaced against a zero that means never
	return &answerLimit{burst: float64(burst), perSecond: perSecond, tokens: float64(burst), filled: now, said: now.Add(-statelessHeldReport)}
}

// take reports whether one more answer may go out, and says how many it held back at most once a statelessHeldReport
func (l *answerLimit) take() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens = min(l.burst, l.tokens+now.Sub(l.filled).Seconds()*l.perSecond)
	l.filled = now
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	l.held++
	if now.Sub(l.said) >= statelessHeldReport {
		slog.Warn("ike held back error answers to unprotected messages", "held", l.held)
		l.held, l.said = 0, now
	}
	return false
}

// statelessNotify is an answer to request that carries one notify in the clear, from no IKE SA
// RFC 7296 section 1.5: "The message is a response message, and thus it is sent to the IP address and port from whence it came with the same IKE SPIs and the Message ID and Exchange Type are copied from the request."
// section 3.1 on the I flag: "It is used by the recipient to determine which eight octets of the SPI were generated by the recipient."
// so the answer's I flag is the request's turned over
func statelessNotify(request *Header, notify NotifyType, data []byte) []byte {
	flags := FlagResponse
	if !request.IsInitiator() {
		flags |= FlagInitiator
	}
	header := Header{SPIInitiator: request.SPIInitiator, SPIResponder: request.SPIResponder, ExchangeType: request.ExchangeType, Flags: flags, MessageID: request.MessageID}
	return (&Message{Header: header, Payloads: []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: notify, Data: data})}}}).Encode()
}
