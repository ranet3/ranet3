// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"errors"
	"fmt"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// errOvertaken ends an exchange whose own answer no longer matters, since a request the peer sent while it was out settled it
var errOvertaken = errors.New("ike: the peer's own request settled the exchange")

// encryptedRoundTrip ignores unauthenticated packets even if their public
// header matches the outstanding exchange (RFC 7296 section 2.21). Once the
// tag verifies, syntax errors are returned to the caller rather than retried,
// with the response that carried them, so a nil response means none decrypted.
func encryptedRoundTrip(mux *transport.Mux, ctx *ikeContext, req []byte) (*Message, []RawPayload, error) {
	return encryptedRoundTripWithin(mux, ctx, req, maxRetransmits, nil)
}

// encryptedRoundTripWithin is encryptedRoundTrip with its own retransmission
// budget, for an exchange whose answer this end does not depend on.
func encryptedRoundTripWithin(mux *transport.Mux, ctx *ikeContext, req []byte, attempts int, request func([]byte) bool) (*Message, []RawPayload, error) {
	var response *Message
	var first PayloadType
	var plain []byte
	_, err := sendRecvWithin(mux, req, attempts, func(raw []byte) bool {
		m, err := DecodeMessage(raw)
		if err != nil {
			return false
		}
		first, plain, err = decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, m)
		if err != nil {
			return false
		}
		response = m
		return true
	}, request)
	if err != nil {
		return nil, nil, err
	}
	inner, err := decodeMessagePlaintext(first, plain)
	return response, inner, err
}

// sendRecv sends req and waits for a correlated response, retransmitting on
// timeout. accept is consulted for every response matching req's SPI and
// Message ID: of an unauthenticated error notification, RFC 7815 section 2.1 says an
// implementation "can simply ignore" it and keep retransmitting until timeout,
// which this does, since an IKE_SA_INIT response (and the outer,
// pre-decryption layer of an IKE_AUTH response) carries no integrity
// protection of its own: anyone able to
// spoof the initiator's SPI, visible in the plaintext request, can inject a
// forged error notify to abort an in-progress handshake otherwise. accept
// lets each exchange decide what counts as a real response worth stopping
// for. A nil accept treats any correlated response as final.
func sendRecv(mux *transport.Mux, req []byte, accept func([]byte) bool) ([]byte, error) {
	return sendRecvWithin(mux, req, maxRetransmits, accept, nil)
}

// sendRecvWithin is sendRecv with the retransmission budget as a parameter,
// and request, where it is set, takes each request the peer sends meanwhile
// and reports whether that request settles the exchange.
func sendRecvWithin(mux *transport.Mux, req []byte, attempts int, accept func([]byte) bool, request func([]byte) bool) ([]byte, error) {
	reqHdr, err := decodeHeader(req)
	if err != nil {
		return nil, err
	}
	// Register before the first transmission so a response cannot race the
	// receive loop on a shared hub.
	if err := mux.RegisterIKE(reqHdr.SPIInitiator); err != nil {
		return nil, err
	}
	for attempt := range attempts {
		if err := mux.SendIKE(req); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(retransmitDelay(requestTimeout, attempt+1))
		for time.Now().Before(deadline) {
			raw, err := mux.RecvIKEUntil(deadline)
			if err != nil {
				// a closed mux still sends, so its exchange ends here instead of retransmitting
				if mux.IsClosed() {
					return nil, err
				}
				break // timeout, retransmit
			}
			h, err := decodeHeader(raw)
			if err != nil {
				continue
			}
			if validResponseHeader(reqHdr, h, len(raw)) {
				if accept == nil || accept(raw) {
					return raw, nil
				}
				// Correlated but rejected by accept (e.g. a bare,
				// unauthenticated error notify): keep waiting instead of
				// treating a possibly-forged message as authoritative.
				continue
			}
			// RFC 7296 section 2.3: "An IKE endpoint MUST be prepared to accept and process a request while it has a request outstanding in order to avoid a deadlock in this situation."
			if request != nil && !h.IsResponse() && request(raw) {
				return nil, errOvertaken
			}
		}
	}
	return nil, fmt.Errorf("ike: no response after %d attempts", attempts)
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
