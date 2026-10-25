// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

// fragmentationSupported is the notify by which an end says it supports IKE fragmentation
var fragmentationSupported = RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_IKEV2_FRAGMENTATION_SUPPORTED})}

// floorRoom is the octets of IKE message one datagram carries on an IPv4 path of 576 octets, past an IP header without options, the UDP header and the non-ESP marker
const floorRoom = 576 - 20 - 8 - NonESPMarkerLen

// noPathMTU is a host that knows no path MTU to the peer
func noPathMTU() (int, error) { return 0, errors.ErrUnsupported }

// pathMTUOf is a host that knows a path MTU of mtu to the peer
func pathMTUOf(mtu int) func() (int, error) { return func() (int, error) { return mtu, nil } }

// sealedFragment is one IKE Fragment message of header under suite and key, cleartext and then an Encrypted Fragment payload naming next, with flags as its octet of the C bit and RESERVED, numbered number of total and carrying content padded with nothing
func sealedFragment(suite SASuite, key []byte, header Header, cleartext []RawPayload, next PayloadType, flags byte, number, total uint16, content []byte) ([]byte, error) {
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, params.IVLen)
	rand.Read(iv)
	encrypted := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16([]byte{byte(next), flags, 0, 0}, number), total)
	return sealMessage(suite, key, header, cleartext, PayloadSKF, encrypted, append(slices.Clip(content), 0), iv)
}

// openFragment is the plaintext of the IKE Fragment message raw whose Encrypted Fragment payload starts at offset
// the nonce is the key's salt and then the IV, and the associated data runs from the IKE header to the end of Total Fragments
func openFragment(suite SASuite, key, raw []byte, offset int) ([]byte, error) {
	params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(suite.EncrID, key[:params.KeyLen])
	if err != nil {
		return nil, err
	}
	if len(raw) < offset+genericPayloadHeaderLen+4+params.IVLen {
		return nil, errors.New("no IV")
	}
	body := raw[offset+genericPayloadHeaderLen+4:]
	return aead.Open(nil, concat(key[params.KeyLen:], body[:params.IVLen]), body[params.IVLen:], raw[:offset+genericPayloadHeaderLen+4])
}

// cutInto is the message of header carrying inner under suite and key as IKE Fragment messages of size octets of plaintext each, the last one shorter
func cutInto(t *testing.T, suite SASuite, key []byte, header Header, inner []RawPayload, size int) [][]byte {
	t.Helper()
	plain := encodePayloadChain(inner)
	total := max(1, (len(plain)+size-1)/size)
	datagrams := make([][]byte, total)
	for i := range datagrams {
		next := PayloadNone
		if i == 0 && len(inner) > 0 {
			next = inner[0].Type
		}
		raw, err := sealedFragment(suite, key, header, nil, next, 0, uint16(i+1), uint16(total), plain[min(i*size, len(plain)):min((i+1)*size, len(plain))])
		if err != nil {
			t.Fatal(err)
		}
		datagrams[i] = raw
	}
	return datagrams
}

// collect reads datagrams from read until one message has come whole or in every fragment of one Total Fragments, past messages of IKE_SA_INIT, and returns them in Fragment Number order
func collect(t *testing.T, read func() ([]byte, error)) [][]byte {
	t.Helper()
	cuts := map[uint16]map[uint16][]byte{}
	for {
		raw, err := read()
		if err != nil {
			t.Fatalf("no message came whole or in all its fragments: %v", err)
		}
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if m.Header.ExchangeType == IKE_SA_INIT {
			continue
		}
		if !fragment(m) {
			return [][]byte{raw}
		}
		number, total := fragmentNumbers(m)
		if cuts[total] == nil {
			cuts[total] = map[uint16][]byte{}
		}
		cuts[total][number] = raw
		if len(cuts[total]) == int(total) {
			datagrams := make([][]byte, total)
			for n, datagram := range cuts[total] {
				datagrams[n-1] = datagram
			}
			return datagrams
		}
	}
}

// assembled opens under suite and key the message datagrams carry, whole or as IKE Fragment messages without unprotected payloads in Fragment Number order
// it returns the message's header, its inner payloads, its octets through the Encrypted payload's generic header as the message has them whole, and its Total Fragments, zero for a message whole
// RFC 7383 section 2.6: "When all IKE Fragment messages (as indicated in the Total Fragments field) are received, the decrypted content of all Encrypted Fragment payloads is merged together to form the content of the original Encrypted payload and, therefore, along with the IKE header and unprotected payloads (if any), the original message."
func assembled(t *testing.T, suite SASuite, key []byte, datagrams [][]byte) (Header, []RawPayload, []byte, int) {
	t.Helper()
	first, err := DecodeMessage(datagrams[0])
	if err != nil {
		t.Fatal(err)
	}
	if !fragment(first) {
		inner, err := DecryptMessage(suite, key, datagrams[0], first)
		if err != nil {
			t.Fatalf("the message does not open under the key: %v", err)
		}
		return first.Header, inner, datagrams[0], 0
	}
	var content []byte
	for i, raw := range datagrams {
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if number, total := fragmentNumbers(m); len(m.Payloads) != 1 || int(number) != i+1 || int(total) != len(datagrams) {
			t.Fatalf("fragment %d carries payload types %v and is number %d of %d", i+1, payloadTypes(m.Payloads), number, total)
		}
		plain, err := openFragment(suite, key, raw, HeaderLen)
		if err != nil {
			t.Fatalf("fragment %d does not open under the key: %v", i+1, err)
		}
		chunk, err := unpadded(plain)
		if err != nil {
			t.Fatal(err)
		}
		content = append(content, chunk...)
	}
	next := PayloadType(datagrams[0][HeaderLen])
	inner, err := decodeInnerPayloads(next, content)
	if err != nil {
		t.Fatalf("the fragments' content does not decode: %v", err)
	}
	whole := concat(datagrams[0][:HeaderLen], []byte{byte(next), datagrams[0][HeaderLen+1], 0, 0})
	whole[16] = byte(PayloadSK)
	return first.Header, inner, whole, len(datagrams)
}

// wantFragmentationSupported fails t unless m carries IKEV2_FRAGMENTATION_SUPPORTED as RFC 7383 section 2.3 lays it out
// RFC 7383 section 2.3: "Protocol ID (1 octet) - MUST be 0."
// RFC 7383 section 2.3: "SPI Size (1 octet) - MUST be 0, meaning no Security Parameter Index (SPI) is present."
// RFC 7383 section 2.3: "Notify Message Type (2 octets) - MUST be 16430, the value assigned for the IKEV2_FRAGMENTATION_SUPPORTED notification."
// RFC 7383 section 2.3: "This notification contains no data."
func wantFragmentationSupported(t *testing.T, m *Message) {
	t.Helper()
	for _, payload := range m.Payloads {
		if notify, err := DecodeNotify(payload.Body); payload.Type == PayloadN && err == nil && notify.Type == N_IKEV2_FRAGMENTATION_SUPPORTED {
			if !bytes.Equal(payload.Body, []byte{0, 0, 0x40, 0x2e}) {
				t.Errorf("IKEV2_FRAGMENTATION_SUPPORTED reads %x, want protocol 0, no SPI, type 16430 and no data", payload.Body)
			}
			return
		}
	}
	t.Errorf("the IKE_SA_INIT message carries no IKEV2_FRAGMENTATION_SUPPORTED among payload types %v", payloadTypes(m.Payloads))
}

// wantFits fails t unless each datagram, its non-ESP marker taken off, carries at most room octets
func wantFits(t *testing.T, datagrams [][]byte, room int) {
	t.Helper()
	for i, raw := range datagrams {
		if len(raw) > room {
			t.Errorf("datagram %d of %d carries %d octets of IKE message, past the %d a datagram of the threshold carries", i+1, len(datagrams), len(raw), room)
		}
	}
}

// the threshold is the path MTU where the host knows one at or above its family's floor, and the floor otherwise, 576 octets for IPv4 and 1280 for IPv6
// a datagram carries the threshold less an IP header without options, the UDP header and the non-ESP marker, and a message larger than that goes in fragments that each fit it
// RFC 7383 section 2.5.1: "the sender SHOULD choose their size so that the resulting IP datagrams will be smaller than some fragmentation threshold."
// RFC 7383 section 2.5.1: "If the sender has information about the PMTU size, it SHOULD use it."
// RFC 7383 section 2.5.1: "Otherwise, for messages to be sent over IPv6, it is RECOMMENDED that a value of 1280 bytes as a maximum IP datagram size be used ([RFC2460]). For messages to be sent over IPv4, it is RECOMMENDED that a value of 576 bytes as a maximum IP datagram size be used."
func TestThresholdIsThePathMTUOrTheFloorOfItsFamily(t *testing.T) {
	v4, v6, mapped := net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.ParseIP("::ffff:127.0.0.1")
	for name, test := range map[string]struct {
		peer      net.IP
		mtu       func() (int, error)
		threshold int
		room      int
	}{
		"IPv4 with no path MTU":                  {v4, noPathMTU, 576, 544},
		"IPv4 mapped into IPv6 with no path MTU": {mapped, noPathMTU, 576, 544},
		"IPv6 with no path MTU":                  {v6, noPathMTU, 1280, 1228},
		"IPv4 under a path MTU of 1500":          {v4, pathMTUOf(1500), 1500, 1468},
		"IPv6 under a path MTU of 9000":          {v6, pathMTUOf(9000), 9000, 8948},
		"IPv4 under a path MTU below its floor":  {v4, pathMTUOf(400), 576, 544},
		"IPv6 under a path MTU below its floor":  {v6, pathMTUOf(1000), 1280, 1228},
	} {
		t.Run(name, func(t *testing.T) {
			mux, err := transport.Dial(":0", test.peer, 4500)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { mux.Close() })
			s := &Session{mux: mux, fragments: true, pathMTU: test.mtu}
			if threshold, room, _ := s.path(); threshold != test.threshold || room != test.room {
				t.Errorf("the threshold is %d with room for %d octets, want %d and %d", threshold, room, test.threshold, test.room)
			}
			ctx := testContext()
			for _, size := range []int{test.room - 100, test.room + 100} {
				message, err := ctx.seal(ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, []RawPayload{bulkyStatus(size)})
				if err != nil {
					t.Fatal(err)
				}
				sent, err := s.transmit(message, form{})
				if err != nil {
					t.Fatal(err)
				}
				if whole := len(message.whole) <= test.room; whole != (sent.total == 0) {
					t.Errorf("a message of %d octets went in %d fragments, want it whole %v", len(message.whole), sent.total, whole)
				}
				wantFits(t, sent.datagrams, test.room)
			}
		})
	}
}

// a session that sets no path MTU of its own takes the one the host holds for the path its mux sends on, and sends whole a message that path carries though the family's floor would cut it
// RFC 7383 section 2.5.1: "If the sender has information about the PMTU size, it SHOULD use it."
func TestThresholdIsThePathMTUTheHostHolds(t *testing.T) {
	s, _ := fragmentingSession(t, &recorder{})
	mtu, err := s.mux.PathMTU()
	if errors.Is(err, errors.ErrUnsupported) {
		t.Skip("the host sends without DF and holds no path MTU")
	}
	if err != nil {
		t.Fatal(err)
	}
	ctx := s.current
	message, err := ctx.seal(ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, []RawPayload{bulkyStatus(floorRoom)})
	if err != nil {
		t.Fatal(err)
	}
	threshold, room, _ := s.path()
	if threshold != mtu || len(message.whole) > room {
		t.Fatalf("the threshold is %d with room for %d octets, want the host's path MTU of %d with room for a message of %d", threshold, room, mtu, len(message.whole))
	}
	sent, err := s.transmit(message, form{})
	if err != nil {
		t.Fatal(err)
	}
	if sent.total != 0 {
		t.Errorf("a message of %d octets went in %d fragments under a path MTU of %d, want it whole", len(message.whole), sent.total, mtu)
	}
}

// a session tells whether its ends both said they support IKE fragmentation, and where they did the threshold it cuts its messages for now
func TestSessionTellsTheThresholdItCutsFor(t *testing.T) {
	s, _ := fragmentingSession(t, &recorder{})
	s.pathMTU = pathMTUOf(1400)
	if supported, threshold := s.Fragments(); !supported || threshold != 1400 {
		t.Errorf("a session whose ends negotiated fragments on a path MTU of 1400 tells %v at %d", supported, threshold)
	}
	s.fragments = false
	if supported, threshold := s.Fragments(); supported || threshold != 0 {
		t.Errorf("a session whose ends did not negotiate fragments tells %v at %d", supported, threshold)
	}
}

// bulkyStatus is a status notify of a type nothing assigns carrying size octets, which a request may hold and its answer passes over
func bulkyStatus(size int) RawPayload {
	return RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: 40000, Data: make([]byte, size)})}
}

// a dial says in IKE_SA_INIT that it supports IKE fragmentation, and cuts its IKE_INTERMEDIATE request, larger than an IPv4 path of 576 octets carries, into fragments that fit it only once the responder said so too
// the dial then reassembles the responder's fragments and signs IntAuth over the messages as they are whole, which the model's octets check
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
// RFC 7383 section 2.4: "If either peer has information that a part of the transaction is likely to be fragmented at the IP layer, causing interference with the IKE exchange, that peer SHOULD use IKE fragmentation."
func TestDialCutsARequestOnlyOnceTheResponderSaysItSupportsFragments(t *testing.T) {
	for name, supports := range map[string]bool{"responder with the notify": true, "responder without the notify": false} {
		t.Run(name, func(t *testing.T) {
			p := dialPlayedWith(t, Suites{kex: []kexEntry{entry768}}, nil, func(cfg *PeerConfig) { cfg.pathMTU = noPathMTU })
			wantFragmentationSupported(t, p.request)
			p.fragments = supports
			if supports {
				p.cut = 400
			}
			p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), true)
			p.answerIntermediate(1, ML_KEM_768, nil)
			if cut := len(p.last) > 1; cut != supports {
				t.Errorf("the dial sent its IKE_INTERMEDIATE request in %d datagrams, want it cut %v", len(p.last), supports)
			}
			if supports {
				wantFits(t, p.last, floorRoom)
			}
			p.answerAuth(2, nil)
			session, err := p.ended()
			if err != nil {
				t.Fatalf("the dial failed: %v", err)
			}
			if ctx := session.current; !slices.EqualFunc([][]byte{ctx.skD, ctx.skei, ctx.sker, ctx.skpi, ctx.skpr}, p.model.keys[:], bytes.Equal) {
				t.Error("the dial's IKE SA keys are not those of the model's last generation")
			}
		})
	}
}

// a responder answers IKE_SA_INIT with IKEV2_FRAGMENTATION_SUPPORTED where the request carried it, and then cuts its IKE_INTERMEDIATE response, larger than an IPv4 path of 576 octets carries, into fragments that fit it though the request came whole
// one whose initiator did not say it supports fragments sends the response whole
// either way the responder's AUTH signs IntAuth over its response as it is whole, which the model's octets check
// RFC 7383 section 2.3: "If the responder also supports this extension and is willing to use it, it includes this notification in the response message."
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
// RFC 7383 section 2.4: "If either peer knows that IKE fragmentation has been used in a previous exchange in the context of the current IKE SA, that peer SHOULD continue to use IKE fragmentation for the messages that are larger than the current fragmentation threshold (see Section 2.5.1)."
// RFC 9242 section 3.3.2: "The prf calculations MUST be applied to whole messages only, before possible IKE fragmentation."
func TestResponderCutsAnAnswerOnlyWhereTheInitiatorSaidItSupportsFragments(t *testing.T) {
	for name, supports := range map[string]bool{"initiator with the notify": true, "initiator without the notify": false} {
		t.Run(name, func(t *testing.T) {
			h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = noPathMTU })
			h.lists.Store(&Suites{kex: []kexEntry{entry768}})
			var extra []RawPayload
			if supports {
				extra = []RawPayload{fragmentationSupported}
			}
			s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), extra, true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", refused)
			}
			if got := carriesNotify(s.answer, N_IKEV2_FRAGMENTATION_SUPPORTED); got != supports {
				t.Errorf("the IKE_SA_INIT answer carries IKEV2_FRAGMENTATION_SUPPORTED %v, want %v", got, supports)
			}
			if supports {
				wantFragmentationSupported(t, s.answer)
			}
			s.intermediate(1, ML_KEM_768)
			if cut := len(s.got) > 1; cut != supports {
				t.Errorf("the responder sent its IKE_INTERMEDIATE response in %d datagrams, want it cut %v", len(s.got), supports)
			}
			if supports {
				wantFits(t, s.got, floorRoom)
			}
			if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
				t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
			}
			s.accepted(2, []uint16{ML_KEM_768})
		})
	}
}

// a responder that has room for its answer whole, on its path and in the largest of the request's datagrams, sends it whole to a request that came whole, and in one IKE Fragment message to a request that came in fragments, IKE_INTERMEDIATE and IKE_AUTH alike, whether it takes the IKE_AUTH or refuses it
// its AUTH and the initiator's then sign IntAuth over the request as it is whole, which the model's octets check
// RFC 7383 section 2.4: "IKE fragmentation SHOULD NOT be used in cases where IP-layer fragmentation of both the request and response messages is unlikely."
// RFC 7383 section 2.4: "If none of the above apply, the responder SHOULD respond in the same form (fragmented or not) as the request message to which it is responding."
// RFC 9242 section 3.3.2: "If the message was received in fragmented form, it MUST be reconstructed before calculating the prf as if it were received unfragmented."
func TestResponderAnswersARequestInItsFormWhereTheAnswerFits(t *testing.T) {
	for name, cut := range map[string]int{"request whole": 0, "request in fragments": 1200} {
		for _, refuse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, IKE_AUTH refused %v", name, refuse), func(t *testing.T) {
				h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(9000) })
				h.lists.Store(&Suites{kex: []kexEntry{entry768}})
				s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
				if s == nil {
					t.Fatalf("the responder refused the offer with notify %d", refused)
				}
				s.cut = cut
				inForm := func(exchange string) {
					t.Helper()
					m, err := DecodeMessage(s.got[0])
					if err != nil {
						t.Fatal(err)
					}
					if len(s.got) != 1 || fragment(m) != (cut > 0) {
						t.Errorf("the responder answered %s in %d datagrams, in fragments %v, want one datagram in fragments %v", exchange, len(s.got), fragment(m), cut > 0)
					}
				}
				s.intermediate(1, ML_KEM_768)
				inForm("IKE_INTERMEDIATE")
				if refuse {
					s.send(IKE_AUTH, 2, s.authPayloads([]byte("octets nothing signed")))
					if header, answer, _ := s.receive(); header.ExchangeType != IKE_AUTH || !notified(answer, N_AUTHENTICATION_FAILED, nil) {
						t.Fatalf("the responder answered an IKE_AUTH whose AUTH fails with exchange %d carrying %v, want AUTHENTICATION_FAILED", header.ExchangeType, answer)
					}
					inForm("the refused IKE_AUTH")
					return
				}
				if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
					t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
				}
				inForm("IKE_AUTH")
				s.accepted(2, []uint16{ML_KEM_768})
			})
		}
	}
}

// a responder on an IPv4 path that knows no path MTU reassembles a request strongSwan cut for 1280 octets, and cuts its own answer for 576
// RFC 7383 section 2.5.1: "For messages to be sent over IPv4, it is RECOMMENDED that a value of 576 bytes as a maximum IP datagram size be used."
// RFC 7383 section 2.5.1: "Implementations may use other values if they are appropriate in the current environment."
func TestResponderTakesFragmentsCutFor1280OverIPv4AndCutsItsOwnFor576(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = noPathMTU })
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	// strongSwan's fragment_size of 1280 less the IPv4 and UDP headers, the non-ESP marker, the IKE header, the Encrypted Fragment payload's header and IV, the Pad Length octet and the ICV
	s.cut = 1280 - 20 - 8 - NonESPMarkerLen - HeaderLen - genericPayloadHeaderLen - 4 - 8 - 1 - 16
	s.intermediate(1, ML_KEM_768)
	if len(s.sent) < 2 {
		t.Fatalf("the request went in %d datagrams, want it cut", len(s.sent))
	}
	if len(s.got) < 2 {
		t.Errorf("the responder answered in %d datagrams, want its answer cut for 576 octets", len(s.got))
	}
	wantFits(t, s.got, floorRoom)
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_768})
}

// a responder under a path MTU of 1500 answers an ML-KEM-1024 request strongSwan cut for 1280 octets in fragments no larger than the request's, where its path alone would have it send one of 1500
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestResponderAnswersARequestCutFor1280WithinItsDatagrams(t *testing.T) {
	entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(1500) })
	h.lists.Store(&Suites{kex: []kexEntry{entry1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	// strongSwan's fragment_size of 1280 less the IPv4 and UDP headers, the non-ESP marker, the IKE header, the Encrypted Fragment payload's header and IV, the Pad Length octet and the ICV
	s.cut = 1280 - 20 - 8 - NonESPMarkerLen - HeaderLen - genericPayloadHeaderLen - 4 - 8 - 1 - 16
	s.intermediate(1, ML_KEM_1024)
	if len(s.sent) < 2 || len(s.got) < 2 {
		t.Fatalf("the request went in %d datagrams and the answer in %d, want both cut", len(s.sent), len(s.got))
	}
	wantFits(t, s.got, largest(s.sent))
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_1024})
}

// in Run and in the wait after IKE_AUTH the first answer to a request in fragments is kept under the threshold of the request's largest datagram, never under the floor's, where the path is wider
// so once the path falls from 1500 to 1280, still over that threshold, a repeat of fragment 1 draws it as it went
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestFirstAnswerKeepsTheRequestsThresholdOnceThePathFalls(t *testing.T) {
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			mtu := 1500
			s.pathMTU = func() (int, error) { return mtu, nil }
			ctx := s.current
			request := cutInto(t, ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(1200), unsupportedCritical}, 500)
			for _, raw := range request {
				take(s, raw, s.mux.Endpoint())
			}
			answer := peerReads(t, peer, answerBudget)
			if kept := ctx.lastPeer.response; len(answer) == 0 || kept == nil || kept.threshold != max(576, largest(request)+20+8+NonESPMarkerLen) {
				t.Fatalf("the request in %d fragments of at most %d octets drew %d datagrams, want the answer kept under the threshold of its largest datagram", len(request), largest(request), len(answer))
			}
			mtu = 1280
			take(s, request[0], s.mux.Endpoint())
			if again := peerReads(t, peer, answerBudget); !slices.EqualFunc(again, answer, bytes.Equal) {
				t.Errorf("with the path at 1280, fragment 1 drew %d datagrams of at most %d octets, want the answer as it went in %d of at most %d", len(again), largest(again), len(answer), largest(answer))
			}
		})
	}
}

// the IKE_AUTH answer to a request in fragments, kept for Run, is kept under the threshold of the request's largest datagram, or the IPv4 floor where that is smaller, though the path is 1500
// so once the path falls to 1280, which is still over that threshold, fragment 1 draws it as it went
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestIKEAuthAnswerKeepsTheRequestsThresholdOnceThePathFalls(t *testing.T) {
	var mtu atomic.Int64
	mtu.Store(1500)
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) {
		cfg.pathMTU = func() (int, error) { return int(mtu.Load()), nil }
	})
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	s.intermediate(1, ML_KEM_768)
	s.cut = 300
	s.authenticate(2, 2)
	request, answer := s.sent, s.got
	session := s.accepted(2, []uint16{ML_KEM_768})
	if kept := session.current.lastPeer.response; kept == nil || kept.threshold != max(576, largest(request)+20+8+NonESPMarkerLen) {
		t.Fatalf("IKE_AUTH in %d fragments of at most %d octets drew %d datagrams, want the answer kept under the threshold of the request's largest datagram or the floor's", len(request), largest(request), len(answer))
	}
	mtu.Store(1280)
	var pending *pendingRequest
	session.dispatch(request[0], session.mux.Endpoint(), &pending)
	if again := heard(s.mux); !slices.EqualFunc(again, answer, bytes.Equal) {
		t.Errorf("with the path at 1280, fragment 1 of IKE_AUTH drew %d datagrams of at most %d octets, want the answer as it went in %d of at most %d", len(again), largest(again), len(answer), largest(answer))
	}
}

// the IKE_AUTH answer grows with the responder's identity, which nothing bounds, so with an identity text of 316 octets it passes the request's largest datagram of 661 octets
// over a path of 9000 it goes in fragments within that datagram
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestIKEAuthAnswerOfALongIdentityGoesWithinTheRequestsDatagrams(t *testing.T) {
	local := identity.MustParse("testorg/server" + strings.Repeat("x", 300) + ":1")
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{local: IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(9000) })
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	s.intermediate(1, ML_KEM_768)
	payloads := s.authPayloads(s.model.signed(s.message1, s.model.nr, s.model.keys[3], scriptedIDi, 2))
	payloads[1].Body = idBody(local.String())
	s.cut = 600
	s.send(IKE_AUTH, 2, payloads)
	header, inner, _ := s.receive()
	if header.ExchangeType != IKE_AUTH || findType(inner, PayloadAUTH) == nil {
		t.Fatalf("the responder answered exchange %d with payload types %v", header.ExchangeType, payloadTypes(inner))
	}
	// the answer whole carries the IKE header, the Encrypted payload's header, an IV of 8 octets, the Pad Length and an ICV of 16 past its plaintext
	if whole := len(encodePayloadChain(inner)) + HeaderLen + genericPayloadHeaderLen + 8 + 1 + 16; len(local.String()) != 316 || largest(s.sent) != 661 || whole <= largest(s.sent) {
		t.Fatalf("an identity text of %d octets and a request in datagrams of at most %d drew an answer of %d octets whole, want 316, 661 and an answer past the request's datagrams", len(local.String()), largest(s.sent), whole)
	}
	if len(s.got) < 2 || largest(s.got) > largest(s.sent) {
		t.Errorf("the IKE_AUTH answer went in %d datagrams of at most %d octets, over a path of 9000, want fragments within the request's %d", len(s.got), largest(s.got), largest(s.sent))
	}
	s.accepted(2, []uint16{ML_KEM_768})
}

// two ends on an IPv4 path that knows no path MTU cut each IKE_INTERMEDIATE message, larger than 576 octets carries, into fragments that fit it, send IKE_SA_INIT and IKE_AUTH whole, and agree on every key
// the dialing end records how many fragments each of its messages took and the threshold it cut them for, and a half-open SA records nothing
// the Child SA rekey after IKE_AUTH completes
func TestTwoEndsCutEachMessageThePathCannotCarryAndAgree(t *testing.T) {
	dialed, answered := &recorder{}, &recorder{}
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = noPathMTU }, answered.record)
	lists := Suites{kex: []kexEntry{entry768And1024, entryX25519}}
	h.lists.Store(&lists)
	var mu sync.Mutex
	fragments := map[string]int{}
	largest := 0
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.pathMTU = noPathMTU
	cfg.Events = dialed.record
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if m, err := DecodeMessage(raw); header != nil && err == nil && fragment(m) {
			mu.Lock()
			fragments[fmt.Sprintf("%s response %v", fmtExchange(header), header.IsResponse())]++
			largest = max(largest, len(raw))
			mu.Unlock()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	for _, s := range []*Session{initiator, responder} {
		t.Cleanup(func() { s.Mux().Close() })
	}
	a, b := initiator.current, responder.current
	if !slices.EqualFunc([][]byte{a.skD, a.skei, a.sker, a.skpi, a.skpr}, [][]byte{b.skD, b.skei, b.sker, b.skpi, b.skpr}, bytes.Equal) {
		t.Error("the two ends hold different IKE SA keys")
	}
	// a fragment carries the threshold's room less what an IKE Fragment message adds around its plaintext under AES-GCM
	capacity := floorRoom - HeaderLen - genericPayloadHeaderLen - 4 - 8 - 1 - 16
	cut := func(octets int) int { return (genericPayloadHeaderLen + 4 + octets + capacity - 1) / capacity }
	want := map[string]int{
		"IKE_INTERMEDIATE 1 response false": cut(kemSizes[ML_KEM_768][0]), "IKE_INTERMEDIATE 1 response true": cut(kemSizes[ML_KEM_768][1]),
		"IKE_INTERMEDIATE 2 response false": cut(kemSizes[ML_KEM_1024][0]), "IKE_INTERMEDIATE 2 response true": cut(kemSizes[ML_KEM_1024][1]),
	}
	mu.Lock()
	if !maps.Equal(fragments, want) || largest > floorRoom {
		t.Errorf("the ends sent fragments %v of at most %d octets, want %v of at most %d", fragments, largest, want, floorRoom)
	}
	mu.Unlock()
	for mid, method := range []uint16{ML_KEM_768, ML_KEM_1024} {
		line := fmt.Sprintf("exchange=IKE_INTERMEDIATE message_id=%d fragments=%d threshold=576", mid+1, cut(kemSizes[method][0]))
		if !slices.ContainsFunc(dialed.recorded(), func(recorded string) bool {
			return strings.HasPrefix(recorded, "ike.message.fragmented testorg/client:2>testorg/server:1 ") && strings.HasSuffix(recorded, line)
		}) {
			t.Errorf("the dialing end recorded %q, want ike.message.fragmented with %s", dialed.recorded(), line)
		}
	}
	if recordedKind(answered, "ike.message.fragmented") != 0 {
		t.Errorf("the answering end recorded %q before it took the initiator in", answered.recorded())
	}
	runSession(t, initiator)
	runSession(t, responder)
	if err := initiator.RekeyChild(); err != nil {
		t.Fatalf("the Child SA rekey after IKE_AUTH failed: %v", err)
	}
}

// a request whose first send the path lost, and whose path MTU the host lowered after, goes again in fragments that fit the lower path MTU, and the exchange completes
// RFC 7383 section 2.5.2: "the initiator SHOULD stop retransmitting the probe and SHOULD select a new value for the fragmentation threshold that is less than or equal to the value from the ICMP message"
// RFC 7383 section 2.5.2: "Implementations MUST be prepared to probe in every exchange that utilizes IKE fragmentation to deal with possible changes in path MTU over time."
func TestRetransmissionCutsTheRequestAgainOnceThePathMTUFalls(t *testing.T) {
	h := newResponderHarness(t, nil)
	lists := Suites{kex: []kexEntry{entry768}}
	h.lists.Store(&lists)
	var mtu atomic.Int64
	mtu.Store(9000)
	var mu sync.Mutex
	var lost bool
	var resent [][]byte
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.pathMTU = func() (int, error) { return int(mtu.Load()), nil }
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if header == nil || !fromInitiator || header.ExchangeType != IKE_INTERMEDIATE {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		if !lost {
			// the first send is lost to a path narrower than the host knew, and the ICMP message that says so lowers the host's path MTU
			lost = true
			mtu.Store(1280)
			return false
		}
		resent = append(resent, slices.Clone(raw))
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	for _, s := range []*Session{initiator, responder} {
		t.Cleanup(func() { s.Mux().Close() })
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resent) < 2 {
		t.Fatalf("the request went again in %d datagrams, want it cut", len(resent))
	}
	for _, raw := range resent {
		if m, err := DecodeMessage(raw); err != nil || !fragment(m) {
			t.Errorf("the request went again as %d octets that are no IKE Fragment message (%v)", len(raw), err)
		}
	}
	wantFits(t, resent, 1280-20-8-NonESPMarkerLen)
}

// a split again cuts a request at the lower threshold into more fragments than before, though the lower threshold alone would cut no more, and a request at the family's floor is cut no further
// RFC 7383 section 2.5.2: "While doing probes, it MUST start from larger values and refragment the original message, using the next smaller value of the threshold if it did not receive a response in a reasonable time after several retransmissions."
// RFC 7383 section 2.5.2: "When selecting the next smaller value for the fragmentation threshold, the sender MUST ensure that the value in the Total Fragments field is really increased."
// RFC 7383 section 2.5.2: "After reaching the smallest allowed value for the fragmentation threshold, an implementation MUST continue retransmitting until the exchange either completes or times out using some timeout interval as discussed in Section 2.4 of [RFC7296]."
func TestSplitAgainGrowsTotalFragmentsDownToTheFloor(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	mtu := func() (int, error) { return 9000, nil }
	s := &Session{mux: mux, fragments: true, pathMTU: func() (int, error) { return mtu() }}
	ctx := testContext()
	message, err := ctx.seal(ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, []RawPayload{bulkyStatus(1600)})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := s.transmit(message, form{})
	if err != nil || sent.total != 0 {
		t.Fatalf("a message that fits went in %d fragments (%v)", sent.total, err)
	}
	// each step is a send that goes nowhere
	recutAt := func(request *transmission) bool {
		again, _ := s.resend(request, 0, func([]byte) error { return nil })
		return again
	}
	for _, step := range []struct {
		path  func() (int, error)
		recut bool
	}{
		{pathMTUOf(1500), true}, {pathMTUOf(1450), true}, {pathMTUOf(1400), true}, {pathMTUOf(576), true},
		{pathMTUOf(500), false}, {noPathMTU, false}, {pathMTUOf(576), false},
	} {
		mtu = step.path
		before, at := sent.total, sent.threshold
		recut := recutAt(sent)
		threshold, room, _ := s.path()
		if recut != step.recut || recut && (sent.total <= before || sent.threshold != threshold) || !recut && (sent.total != before || sent.threshold != at) {
			t.Fatalf("at a threshold of %d the request went from %d fragments at %d to %d at %d, cut again %v, want %v and more fragments where cut", threshold, before, at, sent.total, sent.threshold, recut, step.recut)
		}
		wantFits(t, sent.datagrams, room)
	}
	// a whole request that the lower threshold still carries stays whole, under that threshold
	// RFC 7383 section 2.4: "IKE fragmentation SHOULD NOT be used in cases where IP-layer fragmentation of both the request and response messages is unlikely."
	small, err := ctx.seal(ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, []RawPayload{bulkyStatus(1000)})
	if err != nil {
		t.Fatal(err)
	}
	mtu = pathMTUOf(9000)
	whole, err := s.transmit(small, form{})
	if err != nil {
		t.Fatal(err)
	}
	mtu = pathMTUOf(1500)
	if recut := recutAt(whole); recut || whole.total != 0 || whole.threshold != 1500 || len(whole.datagrams) != 1 {
		t.Errorf("a request of %d octets that a threshold of 1500 carries was cut again %v into %d fragments under %d, want it whole under 1500", len(small.whole), recut, whole.total, whole.threshold)
	}
}

// Run sends a request it cut again after the first interval of its backoff, so the timers start over
// RFC 7383 section 2.5.2: "When starting a new probe, the node MUST reset its retransmission timers so that if it employs exponential back-off the timers will start over."
func TestRunStartsARequestsBackoffOverWhenItCutsItAgain(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	mtu := 9000
	s := &Session{mux: mux, current: testContext(), fragments: true, retransmitAfter: time.Minute, pathMTU: func() (int, error) { return mtu, nil }}
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: []RawPayload{bulkyStatus(2000)}})
	if err != nil {
		t.Fatal(err)
	}
	s.sendPending(pending)
	if pending.attempts != 2 || pending.total != 0 {
		t.Fatalf("the second send counted %d attempts in %d fragments, want 2 whole", pending.attempts, pending.total)
	}
	mtu = 1280
	sent := time.Now()
	s.sendPending(pending)
	if pending.attempts != 1 || pending.sent != 3 || pending.total < 2 || pending.deadline.After(sent.Add(s.retransmitAfter+time.Second)) {
		t.Errorf("the send cut again counted %d attempts of %d sends in %d fragments and waits until %s after it, want the first attempt again, cut, and one interval of %s",
			pending.attempts, pending.sent, pending.total, pending.deadline.Sub(sent), s.retransmitAfter)
	}
}

// Run cuts a request the path cannot carry from its first send, into fragments that fit the path
// RFC 7383 section 2.4: "If either peer has information that a part of the transaction is likely to be fragmented at the IP layer, causing interference with the IKE exchange, that peer SHOULD use IKE fragmentation."
// RFC 7383 section 2.5.1: "the sender SHOULD choose their size so that the resulting IP datagrams will be smaller than some fragmentation threshold."
func TestRunCutsARequestThePathCannotCarryFromItsFirstSend(t *testing.T) {
	s, peer := fragmentingSession(t, &recorder{})
	s.pathMTU = noPathMTU
	if _, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: []RawPayload{bulkyStatus(2000)}}); err != nil {
		t.Fatal(err)
	}
	sent := peerReads(t, peer, answerBudget)
	wantFits(t, sent, floorRoom)
	if _, inner, _, total := assembled(t, s.current.suite, s.current.localEncryptionKey(), sent); total < 2 || len(inner) != 1 || !bytes.Equal(inner[0].Body, bulkyStatus(2000).Body) {
		t.Errorf("the first send went as payload types %v in %d fragments, want the request cut", payloadTypes(inner), total)
	}
}

// an IKE_FOLLOWUP_KE request of ML-KEM-768, larger than an IPv4 path of 576 octets carries, goes in fragments, and the peer's answer in fragments is reassembled
// the event of the cut and the two debug lines name the exchange IKE_FOLLOWUP_KE
func TestFragmentedFollowupNamesItsExchange(t *testing.T) {
	lines := recordLines(t)
	events := &recorder{}
	s, peer := fragmentingSession(t, events)
	s.pathMTU = noPathMTU
	ctx := s.current
	_, key := modelKEM(t, ML_KEM_768)
	request := &localRequest{exchange: IKE_FOLLOWUP_KE, inner: []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}, linkPayload([]byte("link1"))}, result: make(chan requestResult, 1)}
	pending, err := s.startRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if sent := peerReads(t, peer, answerBudget); len(sent) < 2 {
		t.Fatalf("the IKE_FOLLOWUP_KE request went in %d datagrams, want it cut", len(sent))
	}
	_, ciphertext := modelEncapsulate(t, ML_KEM_768, key)
	header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: IKE_FOLLOWUP_KE, Flags: FlagResponse, MessageID: pending.msgID}
	for _, raw := range cutInto(t, ctx.suite, ctx.sker, header, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, ciphertext)}}, 500) {
		s.dispatch(raw, s.mux.Endpoint(), &pending)
	}
	if pending != nil {
		t.Fatal("the answer in fragments did not settle the request")
	}
	if result := <-request.result; result.err != nil || findType(result.inner, PayloadKE) == nil {
		t.Fatalf("the request settled with %v carrying %v, want the answer's KE payload", result.err, payloadTypes(result.inner))
	}
	if !slices.ContainsFunc(events.recorded(), func(recorded string) bool {
		return strings.HasPrefix(recorded, "ike.message.fragmented ") && strings.Contains(recorded, " exchange=IKE_FOLLOWUP_KE message_id=0 ")
	}) {
		t.Errorf("the session recorded %q, want ike.message.fragmented naming IKE_FOLLOWUP_KE", events.recorded())
	}
	for _, line := range []string{"ike sending a message in fragments", "ike reassembled a message from fragments"} {
		if said := lines.said(slog.LevelDebug, line, "exchange"); len(said) != 1 || said[0].String() != "IKE_FOLLOWUP_KE" {
			t.Errorf("the line %q named the exchange %v, want IKE_FOLLOWUP_KE once", line, said)
		}
	}
}

// a probe of the outstanding request after its path MTU fell sends it cut again for the lower path MTU and counts as the send that starts its backoff over
// a probe that cuts nothing again sends the datagrams of the last send and leaves the request's attempts as they were
// RFC 7383 section 2.5.2: "While doing probes, it MUST start from larger values and refragment the original message, using the next smaller value of the threshold if it did not receive a response in a reasonable time after several retransmissions."
// RFC 7383 section 2.5.2: "When starting a new probe, the node MUST reset its retransmission timers so that if it employs exponential back-off the timers will start over."
func TestProbeCutsTheRequestAgainOnceThePathMTUFalls(t *testing.T) {
	s, peer := fragmentingSession(t, &recorder{})
	mtu := 9000
	s.pathMTU = func() (int, error) { return mtu, nil }
	s.retransmitAfter = time.Minute
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: []RawPayload{bulkyStatus(2000)}})
	if err != nil {
		t.Fatal(err)
	}
	s.sendPending(pending)
	if sent := peerReads(t, peer, answerBudget); len(sent) != 2 || pending.attempts != 2 || pending.total != 0 {
		t.Fatalf("two sends went as %d datagrams counting %d attempts in %d fragments, want two whole", len(sent), pending.attempts, pending.total)
	}
	mtu = 1280
	room := 1280 - 20 - 8 - NonESPMarkerLen
	var first [][]byte
	for probe := range 2 {
		at := time.Now()
		if _, err := s.probe(pending); err != nil {
			t.Fatal(err)
		}
		sent := peerReads(t, peer, answerBudget)
		wantFits(t, sent, room)
		_, inner, _, total := assembled(t, s.current.suite, s.current.localEncryptionKey(), sent)
		if total < 2 || len(inner) != 1 || !bytes.Equal(inner[0].Body, bulkyStatus(2000).Body) {
			t.Fatalf("probe %d sent payload types %v in %d fragments, want the request cut again", probe+1, payloadTypes(inner), total)
		}
		if pending.attempts != 1 || pending.sent != 3 || pending.deadline.After(at.Add(s.retransmitAfter+time.Second)) {
			t.Errorf("after probe %d the request counts %d attempts of %d sends and waits until %s after it, want the first attempt of three sends and one interval of %s",
				probe+1, pending.attempts, pending.sent, pending.deadline.Sub(at), s.retransmitAfter)
		}
		if probe == 0 {
			first = sent
		} else if !slices.EqualFunc(sent, first, bytes.Equal) {
			t.Error("a probe under the same path MTU sent datagrams other than the last send's")
		}
	}
}

// an exchange that cuts its request again sends it once more than its attempts allow, after the first interval of its backoff
// RFC 7383 section 2.5.2: "When starting a new probe, the node MUST reset its retransmission timers so that if it employs exponential back-off the timers will start over."
func TestExchangeStartsItsBackoffOverWhenItCutsTheRequestAgain(t *testing.T) {
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	request := encodeTestMessage(t, Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(), ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, nil)
	arrivals := make(chan time.Time, 8)
	peerLoop(t, peer, func() {
		buf := make([]byte, 2048)
		for {
			if _, _, err := peer.ReadFromUDP(buf); err != nil {
				return
			}
			arrivals <- time.Now()
		}
	})
	sent := 0
	// the second send is the one cut again
	resend := func(t *transmission) (bool, error) {
		sent++
		return sent == 2, sendEach(mux.SendIKE, t.datagrams)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = sendRecvWithin(mux, &transmission{datagrams: [][]byte{request}}, 2, requestTimeout, resend, nil, nil)
	}()
	var sends []time.Time
	for len(sends) < 3 {
		select {
		case arrived := <-arrivals:
			sends = append(sends, arrived)
		case <-time.After(retransmitDelay(requestTimeout, 2) + requestTimeout):
			t.Fatalf("the exchange sent %d times with two attempts and a cut, want three", len(sends))
		}
	}
	if gap := sends[2].Sub(sends[1]); gap > requestTimeout+requestTimeout/2 {
		t.Errorf("the send after the cut came %s after the one before, want the first interval of %s", gap, requestTimeout)
	}
	mux.Close()
	<-done
}

// a split again starts a request's attempts over, and its sends stop at maxRetransmitsWhileBusy all the same, in an exchange and in Run
// so a path MTU that falls before every send holds the one outstanding request no longer than a busy peer does
func TestSplitAgainStartsNoRequestOverPastTheBusyBound(t *testing.T) {
	t.Run("exchange", func(t *testing.T) {
		peer := listenPeer(t)
		at := peer.LocalAddr().(*net.UDPAddr)
		mux, err := transport.Dial("127.0.0.1:0", at.IP, at.Port)
		if err != nil {
			t.Fatal(err)
		}
		defer mux.Close()
		request := encodeTestMessage(t, Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(), ExchangeType: INFORMATIONAL, Flags: FlagInitiator}, nil)
		sends := 0
		// every send cuts the request again, and one past the bound closes the mux, which ends the exchange
		resend := func(req *transmission) (bool, error) {
			sends++
			if sends > maxRetransmitsWhileBusy {
				mux.Close()
			}
			return true, sendEach(mux.SendIKE, req.datagrams)
		}
		if _, err := sendRecvWithin(mux, &transmission{datagrams: [][]byte{request}}, maxRetransmits, unansweredRetransmit, resend, nil, nil); err == nil || sends != maxRetransmitsWhileBusy {
			t.Errorf("an exchange whose every send cut the request again sent it %d times and ended with %v, want %d sends and a failure", sends, err, maxRetransmitsWhileBusy)
		}
	})
	t.Run("Run", func(t *testing.T) {
		for _, test := range []struct {
			attempts, sent int
			exhausted      bool
		}{
			{1, maxRetransmitsWhileBusy - 1, false},
			{1, maxRetransmitsWhileBusy, true},
			{maxRetransmits - 1, maxRetransmitsWhileBusy, true},
		} {
			if exhausted := pendingRetransmitsExhausted(&pendingRequest{attempts: test.attempts, sent: test.sent}, true); exhausted != test.exhausted {
				t.Errorf("a request at attempt %d after %d sends is spent %v, want %v", test.attempts, test.sent, exhausted, test.exhausted)
			}
		}
	})
}

// a dial over a path that drops datagrams above the IPv4 floor while the host's path MTU stays at 1500, as on darwin behind a narrower hop or where ICMP is filtered, sends its IKE_INTERMEDIATE request whole twice and then cut for the floor, starting its backoff over, and completes
// RFC 7383 section 2.5.2: "While doing probes, it MUST start from larger values and refragment the original message, using the next smaller value of the threshold if it did not receive a response in a reasonable time after several retransmissions."
// RFC 7383 section 2.5.2: "When starting a new probe, the node MUST reset its retransmission timers so that if it employs exponential back-off the timers will start over."
// RFC 7383 section 2.5.2: "When selecting the next smaller value for the fragmentation threshold, the sender MUST ensure that the value in the Total Fragments field is really increased."
func TestDialStepsARequestDownToTheFloorOnAPathNarrowerThanItsMTU(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.HandshakeTimeout = answerBudget })
	lists := Suites{kex: []kexEntry{entry768}}
	h.lists.Store(&lists)
	var mu sync.Mutex
	var whole int
	var firsts []time.Time
	var totals []uint16
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.pathMTU = pathMTUOf(1500)
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if header == nil || !fromInitiator || header.ExchangeType != IKE_INTERMEDIATE {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		m, err := DecodeMessage(raw)
		if err != nil {
			return false
		}
		if !fragment(m) {
			whole++
			return len(raw) <= floorRoom
		}
		if number, total := fragmentNumbers(m); number == 1 {
			firsts, totals = append(firsts, time.Now()), append(totals, total)
		}
		// the first send under the floor is lost too, so the send after it shows where the backoff stands
		return len(raw) <= floorRoom && len(firsts) > 1
	})
	initiator, responder := dialPaused(t, h, cfg)
	for _, s := range []*Session{initiator, responder} {
		t.Cleanup(func() { s.Mux().Close() })
	}
	mu.Lock()
	defer mu.Unlock()
	if whole != stepDownSends || len(firsts) < 2 || totals[0] < 2 || totals[1] != totals[0] {
		t.Fatalf("the request went whole %d times and then in fragments from fragment 1 of %v, want whole %d times and then cut once", whole, totals, stepDownSends)
	}
	if gap := firsts[1].Sub(firsts[0]); gap > requestTimeout+requestTimeout/2 {
		t.Errorf("the send after the first under the floor came %s after it, want the first interval of %s", gap, requestTimeout)
	}
}

// a dial of two additional key exchanges over a path that drops every datagram above the IPv4 floor while both ends' path MTU stays at 1500 steps the first IKE_INTERMEDIATE request down to the floor
// and sends the second cut for the floor from its first send
// RFC 7383 section 2.5.2: "In subsequent exchanges, the node should start with the current value of the fragmentation threshold."
func TestLaterExchangeStartsAtTheThresholdAnEarlierSteppedDownTo(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) {
		cfg.HandshakeTimeout = answerBudget
		cfg.pathMTU = pathMTUOf(1500)
	})
	lists := Suites{kex: []kexEntry{entry768And1024}}
	h.lists.Store(&lists)
	var mu sync.Mutex
	// the sends of each IKE_INTERMEDIATE request by Message ID whose first datagram, the message whole or fragment 1, the path dropped
	lost := map[uint32]int{}
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.pathMTU = pathMTUOf(1500)
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		m, err := DecodeMessage(raw)
		if err != nil || !fromInitiator || header.ExchangeType != IKE_INTERMEDIATE || len(raw) <= floorRoom {
			return len(raw) <= floorRoom
		}
		if fragment(m) {
			if number, _ := fragmentNumbers(m); number != 1 {
				return false
			}
		}
		mu.Lock()
		defer mu.Unlock()
		lost[header.MessageID]++
		return false
	})
	initiator, responder := dialPaused(t, h, cfg)
	for _, s := range []*Session{initiator, responder} {
		t.Cleanup(func() { s.Mux().Close() })
	}
	mu.Lock()
	defer mu.Unlock()
	if lost[1] != stepDownSends || lost[2] != 0 {
		t.Errorf("the path dropped %d sends of the first IKE_INTERMEDIATE request and %d of the second, want %d of the first and the second cut for the floor from its first send", lost[1], lost[2], stepDownSends)
	}
}

// unansweredSession is a fragmentingSession under the path MTU it returns, 1500 at first, whose request of inner went unanswered stepDownSends times there, so that its next send steps it down to the IPv4 floor, the request still pending
// amid, where not nil, runs before each of those sends after the first
func unansweredSession(t *testing.T, inner []RawPayload, amid func(s *Session, hub *transport.Hub, mtu *int)) (*Session, *transport.Hub, *pendingRequest, *int) {
	t.Helper()
	s, _, hub := fragmentingSessionAt(t, &recorder{})
	mtu := 1500
	s.pathMTU = func() (int, error) { return mtu, nil }
	s.retransmitAfter = time.Minute
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: inner})
	if err != nil {
		t.Fatal(err)
	}
	for pending.sends < stepDownSends {
		if amid != nil {
			amid(s, hub, &mtu)
		}
		s.sendPending(pending)
	}
	if pending.threshold != 1500 || s.stepped.Load() != nil {
		t.Fatalf("the request sent %d times under 1500 is under %d with a record %v, want under 1500 with none", pending.sends, pending.threshold, s.stepped.Load())
	}
	return s, hub, pending, &mtu
}

// steppedSession is an unansweredSession whose request of 2000 octets of status stepped down to the IPv4 floor at its next send, the request still pending
func steppedSession(t *testing.T) (*Session, *transport.Hub, *pendingRequest, *int) {
	t.Helper()
	s, hub, pending, mtu := unansweredSession(t, []RawPayload{bulkyStatus(2000)}, nil)
	s.sendPending(pending)
	if pending.threshold != 576 || pending.total < 2 {
		t.Fatalf("the request sent %d times under 1500 went in %d fragments under %d, want it stepped down to the floor", stepDownSends+1, pending.total, pending.threshold)
	}
	return s, hub, pending, mtu
}

// firstCut is how s readies a new message of 2000 octets of status on its current IKE SA with flags for its first send, a request or an answer to a request that came whole
func firstCut(t *testing.T, s *Session, flags uint8) *transmission {
	t.Helper()
	return firstCutFor(t, s, flags, form{})
}

// firstCutFor is firstCut for an answer to a request that came as request says
func firstCutFor(t *testing.T, s *Session, flags uint8, request form) *transmission {
	t.Helper()
	ctx := s.current
	message, err := ctx.seal(ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: flags}, []RawPayload{bulkyStatus(2000)})
	if err != nil {
		t.Fatal(err)
	}
	sent, err := s.transmit(message, request)
	if err != nil {
		t.Fatal(err)
	}
	return sent
}

// once a request stepped down to the IPv4 floor, a later request and an answer to a later request that came whole are cut for the floor at their first send, on another current IKE SA too, as a rekey of the IKE SA makes, and the session tells the floor as its threshold
// a request's sends count from its last cut, so one cut again for a path MTU that fell steps on that path and carries the floor
// an answer to a request in fragments larger than the floor's is cut for the floor too, and so is an answer cut before the step at the repeat whole that draws it after the step
// RFC 7383 section 2.5.2: "In subsequent exchanges, the node should start with the current value of the fragmentation threshold."
func TestLaterMessageIsCutForTheFloorARequestSteppedDownTo(t *testing.T) {
	for name, flags := range map[string]uint8{"request": FlagInitiator, "answer to a request that came whole": FlagInitiator | FlagResponse} {
		t.Run(name, func(t *testing.T) {
			s, _, _, _ := steppedSession(t)
			for _, sa := range []string{"the IKE SA the request stepped on", "another current IKE SA"} {
				sent := firstCut(t, s, flags)
				if sent.threshold != 576 || sent.total < 2 {
					t.Errorf("on %s the %s went in %d fragments under %d, want it cut for the floor", sa, name, sent.total, sent.threshold)
				}
				wantFits(t, sent.datagrams, floorRoom)
				if _, threshold := s.Fragments(); threshold != 576 {
					t.Errorf("on %s the session tells a threshold of %d, want the floor", sa, threshold)
				}
				s.current = testContext()
			}
		})
	}
	t.Run("request stepped down on the path MTU it was cut again for", func(t *testing.T) {
		s, _ := fragmentingSession(t, &recorder{})
		mtu := 1500
		s.pathMTU = func() (int, error) { return mtu, nil }
		sent := firstCut(t, s, FlagInitiator)
		mtu = 1400
		for range stepDownSends + 1 {
			if _, err := s.retransmit(sent, func([]byte) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		if sent.threshold != 576 {
			t.Fatalf("the request cut again for 1400 and sent %d times there went under %d, want it stepped down to the floor", stepDownSends, sent.threshold)
		}
		if next := firstCut(t, s, FlagInitiator); next.threshold != 576 {
			t.Errorf("a later request went in %d fragments under %d, want it cut for the floor", next.total, next.threshold)
		}
	})
	t.Run("answer to a request in fragments of 1000 octets", func(t *testing.T) {
		s, _, _, _ := steppedSession(t)
		sent := firstCutFor(t, s, FlagInitiator|FlagResponse, form{total: 2, largest: 1000})
		if sent.threshold != 576 {
			t.Errorf("the answer went in %d fragments under %d, want it cut for the floor", sent.total, sent.threshold)
		}
		wantFits(t, sent.datagrams, floorRoom)
	})
	t.Run("answer cut before the step and drawn again by a repeat whole", func(t *testing.T) {
		s, _, pending, _ := unansweredSession(t, []RawPayload{bulkyStatus(2000)}, nil)
		answer := firstCut(t, s, FlagInitiator|FlagResponse)
		before := answer.total
		s.sendPending(pending)
		if again, err := s.resend(answer, 0, func([]byte) error { return nil }); err != nil || !again || answer.threshold != 576 || answer.total <= before {
			t.Errorf("the answer went from %d fragments to %d under %d at the repeat, cut again %v, %v, want it cut again for the floor in more", before, answer.total, answer.threshold, again, err)
		}
		wantFits(t, answer.datagrams, floorRoom)
	})
}

// the floor a request stepped down to holds while the path the host reads stays as it was, and ends for good once the reading rises or falls, the peer's endpoint moves, or the session is asked to probe its path
// a reading that comes back to the one the step was taken under takes the floor back for no later exchange
func TestCarriedFloorEndsWhereThePathMayHaveChanged(t *testing.T) {
	for name, test := range map[string]struct {
		change    func(t *testing.T, s *Session, hub *transport.Hub, mtu *int)
		threshold int
	}{
		"the reading rises": {func(_ *testing.T, _ *Session, _ *transport.Hub, mtu *int) { *mtu = 9000 }, 9000},
		"the reading falls": {func(_ *testing.T, _ *Session, _ *transport.Hub, mtu *int) { *mtu = 1400 }, 1400},
		"the peer moves": {func(t *testing.T, s *Session, hub *transport.Hub, _ *int) {
			moved, _ := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			if !s.mux.AdoptEndpoint(moved) {
				t.Fatal("the mux did not move")
			}
		}, 1500},
		"the session probes": {func(_ *testing.T, s *Session, _ *transport.Hub, _ *int) { s.Probe() }, 1500},
	} {
		t.Run(name, func(t *testing.T) {
			s, hub, _, mtu := steppedSession(t)
			test.change(t, s, hub, mtu)
			if sent := firstCut(t, s, FlagInitiator); sent.threshold != test.threshold {
				t.Errorf("a request after the change went in %d fragments under %d, want under %d", sent.total, sent.threshold, test.threshold)
			}
			if *mtu == 1500 {
				return
			}
			*mtu = 1500
			if sent := firstCut(t, s, FlagInitiator); sent.threshold != 1500 {
				t.Errorf("a request once the reading came back to 1500 went in %d fragments under %d, want under 1500", sent.total, sent.threshold)
			}
		})
	}
}

// a reset after a request went unanswered stepDownSends times and before its next send steps it down to the IPv4 floor holds for the exchanges after it
// the request still steps, since its own sends went unanswered, and carries the floor to no later exchange, since some of its unanswered sends went on a path that may since have changed
// so does a change that one of those sends finds and that is undone by the step, since that send went on another path than the step
// RFC 7383 section 2.5.2: "Implementations MUST be prepared to probe in every exchange that utilizes IKE fragmentation to deal with possible changes in path MTU over time."
func TestResetBeforeARequestStepsHoldsForTheExchangesAfterIt(t *testing.T) {
	probed := func(t *testing.T, s *Session, _ *transport.Hub, pending *pendingRequest, _ *int) {
		s.Probe()
		if _, err := s.probe(pending); err != nil {
			t.Fatal(err)
		}
	}
	for name, test := range map[string]struct {
		inner     []RawPayload
		change    func(t *testing.T, s *Session, hub *transport.Hub, pending *pendingRequest, mtu *int)
		threshold int
	}{
		"the session probes and its probe steps a request":        {[]RawPayload{bulkyStatus(2000)}, probed, 1500},
		"the session probes and its probe steps a liveness check": {nil, probed, 1500},
		"the session probes and the next scheduled send steps a request": {[]RawPayload{bulkyStatus(2000)}, func(_ *testing.T, s *Session, _ *transport.Hub, pending *pendingRequest, _ *int) {
			s.Probe()
			s.sendPending(pending)
		}, 1500},
		"the peer moves and the next scheduled send steps a request": {[]RawPayload{bulkyStatus(2000)}, func(t *testing.T, s *Session, hub *transport.Hub, pending *pendingRequest, _ *int) {
			moved, _ := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			if !s.mux.AdoptEndpoint(moved) {
				t.Fatal("the mux did not move")
			}
			s.sendPending(pending)
		}, 1500},
		"the reading rises and the next scheduled send steps a request": {[]RawPayload{bulkyStatus(2000)}, func(_ *testing.T, s *Session, _ *transport.Hub, pending *pendingRequest, mtu *int) {
			*mtu = 9000
			s.sendPending(pending)
		}, 9000},
	} {
		t.Run(name, func(t *testing.T) {
			s, hub, pending, mtu := unansweredSession(t, test.inner, nil)
			test.change(t, s, hub, pending, mtu)
			if pending.threshold != 576 {
				t.Fatalf("the request went under %d at its send after the reset, want it stepped down to the floor", pending.threshold)
			}
			if sent := firstCut(t, s, FlagInitiator); sent.threshold != test.threshold {
				t.Errorf("a later request went in %d fragments under %d, want under %d", sent.total, sent.threshold, test.threshold)
			}
		})
	}
	for name, change := range map[string]func(t *testing.T, s *Session, hub *transport.Hub, mtu *int) (back func()){
		"the reading rises and falls back": func(_ *testing.T, _ *Session, _ *transport.Hub, mtu *int) func() {
			*mtu = 9000
			return func() { *mtu = 1500 }
		},
		"the peer moves and moves back": func(t *testing.T, s *Session, hub *transport.Hub, _ *int) func() {
			first := s.mux.Endpoint()
			moved, _ := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			if !s.mux.AdoptEndpoint(moved) {
				t.Fatal("the mux did not move")
			}
			return func() {
				if !s.mux.AdoptEndpoint(first) {
					t.Fatal("the mux did not move back")
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var back func()
			s, _, pending, _ := unansweredSession(t, []RawPayload{bulkyStatus(2000)}, func(s *Session, hub *transport.Hub, mtu *int) {
				if back == nil {
					back = change(t, s, hub, mtu)
				}
			})
			back()
			s.sendPending(pending)
			if pending.threshold != 576 {
				t.Fatalf("the request went under %d at its send after the change was undone, want it stepped down to the floor", pending.threshold)
			}
			if sent := firstCut(t, s, FlagInitiator); sent.threshold != 1500 {
				t.Errorf("a later request went in %d fragments under %d, want under 1500", sent.total, sent.threshold)
			}
		})
	}
}

// a request that fits its family's floor whole, such as a liveness check, steps down to the IPv4 floor at its send after stepDownSends unanswered ones and carries the floor to no exchange after it
// RFC 7383 section 2.4: "IKE fragmentation SHOULD NOT be used in cases where IP-layer fragmentation of both the request and response messages is unlikely. For example, there is no point in fragmenting liveness check messages."
// so its sends going unanswered says nothing of datagrams larger than the floor
func TestRequestThatFitsTheFloorWholeCarriesNothing(t *testing.T) {
	s, _, pending, _ := unansweredSession(t, nil, nil)
	s.sendPending(pending)
	if pending.threshold != 576 || len(pending.datagrams) != 1 {
		t.Fatalf("the liveness check went in %d datagrams under %d at its send after stepDownSends, want it whole under the floor", len(pending.datagrams), pending.threshold)
	}
	if sent := firstCut(t, s, FlagInitiator); sent.threshold != 1500 {
		t.Errorf("a later request went in %d fragments under %d, want under 1500", sent.total, sent.threshold)
	}
}

// a request cut again for a path MTU that fell above the IPv4 floor carries nothing to the exchanges after it, and neither does an answer a smaller repeat cuts again for the floor, nor a stepped request sent again at the floor after a reset
// RFC 7383 section 2.5.2: "It is the initiator of the exchange who performs PMTU discovery."
func TestOnlyARequestsStepCarriesTheFloor(t *testing.T) {
	t.Run("a request cut again for 1400", func(t *testing.T) {
		s, _ := fragmentingSession(t, &recorder{})
		mtu := 1500
		s.pathMTU = func() (int, error) { return mtu, nil }
		sent := firstCut(t, s, FlagInitiator)
		mtu = 1400
		if again, err := s.retransmit(sent, func([]byte) error { return nil }); err != nil || !again || sent.threshold != 1400 {
			t.Fatalf("the request went in %d fragments under %d after the fall, cut again %v, %v, want it cut again for 1400", sent.total, sent.threshold, again, err)
		}
		if next := firstCut(t, s, FlagInitiator); next.threshold != 1400 {
			t.Errorf("a later request went in %d fragments under %d, want under 1400", next.total, next.threshold)
		}
	})
	t.Run("an answer cut again for the floor", func(t *testing.T) {
		s, _ := fragmentingSession(t, &recorder{})
		s.pathMTU = pathMTUOf(1500)
		answer := firstCut(t, s, FlagInitiator|FlagResponse)
		if again, err := s.resend(answer, 100, func([]byte) error { return nil }); err != nil || !again || answer.threshold != 576 {
			t.Fatalf("the answer went in %d fragments under %d for a repeat of 100 octets, cut again %v, %v, want it cut again for the floor", answer.total, answer.threshold, again, err)
		}
		if next := firstCut(t, s, FlagInitiator); next.threshold != 1500 {
			t.Errorf("a later request went in %d fragments under %d, want under 1500", next.total, next.threshold)
		}
	})
	t.Run("a stepped request sent again at the floor after a reset", func(t *testing.T) {
		s, _, pending, _ := steppedSession(t)
		s.Probe()
		s.sendPending(pending)
		if next := firstCut(t, s, FlagInitiator); next.threshold != 1500 {
			t.Errorf("a later request went in %d fragments under %d, want under 1500", next.total, next.threshold)
		}
	})
}

// a status read keeps the record a step stores while the read waits on the host's path MTU, as a step on Run's goroutine does during a stalled read
func TestStatusReadKeepsTheRecordAStepStoresDuringIt(t *testing.T) {
	s, _ := fragmentingSession(t, &recorder{})
	newer := &pathRead{endpoint: s.mux.Endpoint().AddrPort(), read: 1400}
	s.pathMTU = func() (int, error) {
		s.stepped.Store(newer)
		return 1500, nil
	}
	s.Fragments()
	if kept := s.stepped.Load(); kept != newer {
		t.Errorf("the record after the status read is %p, want %p, the one of the reading 1400 a step stored during it", kept, newer)
	}
}

// dropping a record path read as stale keeps the one a step stored since, as where a status read finds the old record while a send steps on Run's goroutine
func TestDroppedRecordKeepsTheOneAStepStoredSince(t *testing.T) {
	s := &Session{}
	s.stepped.Store(&pathRead{read: 1500})
	stale := s.stepped.Load()
	newer := &pathRead{read: 9000}
	s.stepped.Store(newer)
	s.forget(stale)
	if kept := s.stepped.Load(); kept != newer {
		t.Errorf("the record after the stale one was dropped is %+v, want the newer %+v", kept, newer)
	}
}

// a responder whose path drops its datagrams over the IPv4 floor while its path MTU stays at 1500, as on darwin behind a narrower hop or where ICMP is filtered, answers the IKE_INTERMEDIATE request whole until the initiator steps down to the floor
// and then cut again within the fragment 1 that drew the answer, in more fragments, and the exchange completes
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
// RFC 7383 section 2.5.2: "It is the initiator of the exchange who performs PMTU discovery."
// RFC 7383 section 2.5.2: "When selecting the next smaller value for the fragmentation threshold, the sender MUST ensure that the value in the Total Fragments field is really increased."
// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
func TestResponderCutsItsAnswerForTheRepeatOnAPathNarrowerThanItsMTU(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) {
		cfg.HandshakeTimeout = answerBudget
		cfg.pathMTU = pathMTUOf(1500)
	})
	lists := Suites{kex: []kexEntry{entry768}}
	h.lists.Store(&lists)
	var mu sync.Mutex
	// the Total Fragments of each send of the IKE_INTERMEDIATE request and of its answer, zero for one whole
	var requests, answers []uint16
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return lists }
	cfg.pathMTU = pathMTUOf(1500)
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if m, err := DecodeMessage(raw); header != nil && err == nil && header.ExchangeType == IKE_INTERMEDIATE {
			var number, total uint16
			if fragment(m) {
				number, total = fragmentNumbers(m)
			}
			mu.Lock()
			switch {
			case number > 1:
			case fromInitiator:
				requests = append(requests, total)
			default:
				answers = append(answers, total)
			}
			mu.Unlock()
		}
		return fromInitiator || len(raw) <= floorRoom
	})
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		t.Fatalf("the dial failed with the request sent in Total Fragments %v and the answer in %v: %v", requests, answers, err)
	}
	initiator.Mux().Close()
	if len(answers) < 2 || answers[0] != 0 || answers[len(answers)-1] < 2 || !slices.IsSorted(answers) {
		t.Errorf("the answer went in Total Fragments %v to the request's %v, want it whole and then in more fragments, never fewer", answers, requests)
	}
}

// Run sends a request under the path MTU, cut again when that falls, and once those datagrams went twice under a threshold above its family's floor, cut for the floor in more fragments, each cut starting its backoff over
// it goes on sending the floor's cut until its budget ends
// RFC 7383 section 2.5.2: "After reaching the smallest allowed value for the fragmentation threshold, an implementation MUST continue retransmitting until the exchange either completes or times out using some timeout interval as discussed in Section 2.4 of [RFC7296]."
func TestRunStepsARequestDownToTheFloorAndSendsItThereUntilItsBudgetEnds(t *testing.T) {
	s, _ := fragmentingSession(t, &recorder{})
	mtu := 9000
	s.pathMTU = func() (int, error) { return mtu, nil }
	s.retransmitAfter = time.Minute
	pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: []RawPayload{bulkyStatus(2000)}})
	if err != nil {
		t.Fatal(err)
	}
	mtu = 1500
	for send, want := range []struct {
		threshold, attempts int
		cut                 bool
	}{{1500, 1, true}, {1500, 2, false}, {576, 1, true}} {
		total, at := pending.total, time.Now()
		s.sendPending(pending)
		if pending.threshold != want.threshold || pending.attempts != want.attempts || want.cut != (pending.total > total) || want.attempts == 1 && pending.deadline.After(at.Add(s.retransmitAfter+time.Second)) {
			t.Fatalf("send %d went in %d fragments under %d counting %d attempts and waits until %s after it, want %d attempts under %d, cut again %v",
				send+2, pending.total, pending.threshold, pending.attempts, pending.deadline.Sub(at), want.attempts, want.threshold, want.cut)
		}
	}
	wantFits(t, pending.datagrams, floorRoom)
	stepped := pending.datagrams
	for !pendingRetransmitsExhausted(pending, false) {
		s.sendPending(pending)
		if !slices.EqualFunc(pending.datagrams, stepped, bytes.Equal) {
			t.Fatalf("send %d under the floor went in other datagrams than the first there", pending.sent)
		}
	}
	if pending.attempts != maxRetransmits || pending.sent != 1+stepDownSends+maxRetransmits {
		t.Errorf("the request ended after %d sends at attempt %d, want one under 9000, %d under 1500 and %d under the floor", pending.sent, pending.attempts, stepDownSends, maxRetransmits)
	}
}

// two probes right after the first send of an IKE_FOLLOWUP_KE request of ML-KEM-768, which a path MTU of 1500 carries whole and the IPv4 floor does not, send it whole again and leave its cut as it was, as a network change or an operator asks for them
// the backoff's own sends then step it to the floor after stepDownSends of them, as they would without the probes
// the send after them steps it, the backoff's or a probe's, and starts its backoff over
// RFC 7383 section 2.5.2: "While doing probes, it MUST start from larger values and refragment the original message, using the next smaller value of the threshold if it did not receive a response in a reasonable time after several retransmissions."
func TestProbesCountNoSendTowardTheStepToTheFloor(t *testing.T) {
	for name, probed := range map[string]bool{"the backoff's send": false, "a probe": true} {
		t.Run(name, func(t *testing.T) {
			s, _ := fragmentingSession(t, &recorder{})
			s.pathMTU = pathMTUOf(1500)
			s.retransmitAfter = time.Minute
			_, key := modelKEM(t, ML_KEM_768)
			pending, err := s.startRequest(&localRequest{exchange: IKE_FOLLOWUP_KE, inner: []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}, linkPayload([]byte("link1"))}})
			if err != nil {
				t.Fatal(err)
			}
			if len(pending.message.whole) <= floorRoom || pending.total != 0 || pending.threshold != 1500 {
				t.Fatalf("the request of %d octets went in %d fragments under %d, want it whole under 1500 and larger than the floor's room of %d", len(pending.message.whole), pending.total, pending.threshold, floorRoom)
			}
			first := pending.datagrams
			for probe := range 2 {
				if _, err := s.probe(pending); err != nil {
					t.Fatal(err)
				}
				if pending.total != 0 || pending.threshold != 1500 || !slices.EqualFunc(pending.datagrams, first, bytes.Equal) {
					t.Fatalf("probe %d sent the request in %d fragments under %d, want it whole under 1500 as its first send went", probe+1, pending.total, pending.threshold)
				}
			}
			for send := 2; send <= stepDownSends; send++ {
				s.sendPending(pending)
				if pending.total != 0 || pending.threshold != 1500 {
					t.Fatalf("send %d of the backoff went in %d fragments under %d, want it whole under 1500", send, pending.total, pending.threshold)
				}
			}
			at := time.Now()
			if probed {
				if _, err := s.probe(pending); err != nil {
					t.Fatal(err)
				}
			} else {
				s.sendPending(pending)
			}
			if pending.threshold != 576 || pending.total < 2 || pending.attempts != 1 || pending.deadline.After(at.Add(s.retransmitAfter+time.Second)) {
				t.Fatalf("%s after %d of the backoff went in %d fragments under %d at attempt %d and waits until %s after it, want it cut for the floor of 576 and its backoff started over", name, stepDownSends, pending.total, pending.threshold, pending.attempts, pending.deadline.Sub(at))
			}
			wantFits(t, pending.datagrams, floorRoom)
		})
	}
}

// a request sent stepDownSends times under a path MTU above its family's floor goes under the floor at its next send, and an answer resent as often goes under the path's threshold still
// RFC 7383 section 2.5.2: "It is the initiator of the exchange who performs PMTU discovery."
func TestOnlyARequestStepsDownToTheFloor(t *testing.T) {
	for _, test := range []struct {
		name  string
		flags uint8
		steps bool
	}{{"request", FlagInitiator, true}, {"answer", FlagInitiator | FlagResponse, false}} {
		// a session of its own, since the request's step carries the floor to every message after it
		s, _ := fragmentingSession(t, &recorder{})
		s.pathMTU = pathMTUOf(1500)
		sent := firstCut(t, s, test.flags)
		cut := sent.total
		again := false
		var err error
		for range stepDownSends + 1 {
			if again, err = s.retransmit(sent, func([]byte) error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		if again != test.steps || (sent.threshold == 576) != test.steps || test.steps != (sent.total > cut) {
			t.Errorf("the %s sent %d times went in %d fragments under %d, cut again %v at the last, from %d under 1500, want under the floor %v", test.name, stepDownSends+1, sent.total, sent.threshold, again, cut, test.steps)
		}
	}
}

// an INFORMATIONAL request whose mux closed unanswered goes once more after the exchange, and that send is cut for the path as it stands then
// RFC 7383 section 2.5.2: "it MUST start from larger values and refragment the original message"
func TestClosingSendOfAnUnansweredRequestIsCutForThePath(t *testing.T) {
	s, peer := fragmentingSession(t, &recorder{})
	wide := pathMTUOf(9000)
	s.pathMTU = func() (int, error) {
		if s.mux.IsClosed() {
			return 0, errors.New("the mux closed")
		}
		return wide()
	}
	first := make(chan int, 1)
	go func() {
		defer s.mux.Close()
		buf := make([]byte, 65536)
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			first <- 0
			return
		}
		n, _, _ := peer.ReadFromUDP(buf)
		first <- n
	}()
	if err := s.informAfterAuth([]RawPayload{bulkyStatus(2000)}); err == nil {
		t.Fatal("an INFORMATIONAL whose mux closed unanswered succeeded")
	}
	if n := <-first; n < 2000 {
		t.Fatalf("the exchange's send took %d octets, want the request whole under 9000", n)
	}
	last := peerReads(t, peer, answerBudget)
	for _, raw := range last {
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, total := fragmentNumbers(m); !fragment(m) || int(total) != len(last) || len(raw) > 576-20-8-NonESPMarkerLen {
			t.Errorf("the send after the mux closed carried a datagram of %d octets, fragment %v of %d in %d datagrams, want fragments under the IPv4 floor", len(raw), fragment(m), total, len(last))
		}
	}
	if len(last) < 2 {
		t.Errorf("the send after the mux closed went in %d datagrams, want the request cut again under the IPv4 floor", len(last))
	}
}

// the answer Run keeps for a request that came whole goes whole where it fits the path, and in fragments that fit where it does not
// RFC 7383 section 2.4: "If either peer has information that a part of the transaction is likely to be fragmented at the IP layer, causing interference with the IKE exchange, that peer SHOULD use IKE fragmentation."
func TestRunCutsTheAnswerToAWholeRequestThatDoesNotFitThePath(t *testing.T) {
	s, _ := fragmentingSession(t, &recorder{})
	s.pathMTU = pathMTUOf(1280)
	_, room, _ := s.path()
	ctx := s.current
	for _, test := range []struct {
		octets int
		cut    bool
	}{{room / 2, false}, {2 * room, true}} {
		mid := ctx.nextPeerMID
		response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, []RawPayload{bulkyStatus(test.octets)})
		if err != nil {
			t.Fatal(err)
		}
		sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{peerRequestWhole(t, s, mid, nil)}))
		if err != nil {
			t.Fatal(err)
		}
		if ctx.lastPeerResponseID != mid || ctx.lastPeer.response != sent || ctx.nextPeerMID != mid+1 {
			t.Errorf("the answer to the request at %d left the kept answer at %d and the window at %d", mid, ctx.lastPeerResponseID, ctx.nextPeerMID)
		}
		if (sent.total > 1) != test.cut || (len(sent.datagrams) > 1) != test.cut {
			t.Errorf("the answer of %d octets under a room of %d went in %d datagrams of Total Fragments %d, want it cut %v", len(response.whole), room, len(sent.datagrams), sent.total, test.cut)
		}
		for _, raw := range sent.datagrams {
			if len(raw) > room {
				t.Errorf("the answer to a whole request went in a datagram of %d octets, over the room of %d the path leaves", len(raw), room)
			}
		}
	}
}

// fragmentingSession is a session of testContext's SA whose ends negotiated IKE fragmentation, recording into events, and the socket of its peer
func fragmentingSession(t *testing.T, events *recorder) (*Session, *net.UDPConn) {
	t.Helper()
	s, peer, _ := fragmentingSessionAt(t, events)
	return s, peer
}

// fragmentingSessionAt is fragmentingSession with the hub its mux is on, where datagrams from another address arrive
func fragmentingSessionAt(t *testing.T, events *recorder) (*Session, *net.UDPConn, *transport.Hub) {
	t.Helper()
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	hub := listenHub(t)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	ctx := testContext()
	if err := mux.RegisterIKE(ctx.spiI); err != nil {
		t.Fatal(err)
	}
	return &Session{mux: mux, current: ctx, fragments: true, events: events.record}, peer, hub
}

// openedOf is the request datagrams carry as s opens them, whole or reassembled in a queue of its own
func openedOf(t *testing.T, s *Session, datagrams [][]byte) *opened {
	t.Helper()
	var q reassembly
	for _, raw := range datagrams {
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		request, err := s.open(s.current, &q, raw, m)
		if err != nil {
			t.Fatal(err)
		}
		if request != nil {
			return request
		}
	}
	t.Fatalf("the %d datagrams made no request", len(datagrams))
	return nil
}

// peerRequest is the peer's INFORMATIONAL request at mid under s's SA, carrying a status notify of octets, in IKE Fragment messages of size octets of plaintext
func peerRequest(t *testing.T, s *Session, mid uint32, octets, size int) [][]byte {
	t.Helper()
	ctx := s.current
	return cutInto(t, ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}, []RawPayload{bulkyStatus(octets)}, size)
}

// peerRequestWhole is the peer's INFORMATIONAL request at mid under s's SA carrying inner, whole
func peerRequestWhole(t *testing.T, s *Session, mid uint32, inner []RawPayload) []byte {
	t.Helper()
	ctx := s.current
	raw, err := EncryptMessage(ctx.suite, ctx.peerEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}, nil, inner)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// peerTakes is the next n datagrams peer takes, each within answerBudget, their non-ESP markers taken off
func peerTakes(t *testing.T, peer *net.UDPConn, n int) [][]byte {
	t.Helper()
	buf := make([]byte, 65536)
	got := make([][]byte, 0, n)
	for range n {
		if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
			t.Fatal(err)
		}
		read, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			return got
		}
		got = append(got, slices.Clone(buf[min(read, NonESPMarkerLen):read]))
	}
	return got
}

// peerReads is each datagram peer takes until it waits for one in vain, its non-ESP marker taken off
func peerReads(t *testing.T, peer *net.UDPConn, wait time.Duration) [][]byte {
	t.Helper()
	buf := make([]byte, 65536)
	var got [][]byte
	for {
		if err := peer.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			return got
		}
		got = append(got, slices.Clone(buf[min(n, NonESPMarkerLen):n]))
		wait = quietPeriod
	}
}

// a fragment whose ICV fails is discarded, and the request it belongs to waits for the fragment that authenticates
// RFC 7383 section 2.6: "If the ICV check fails, the message MUST be silently discarded."
func TestFragmentWhoseICVFailsIsDiscarded(t *testing.T) {
	s, peer := fragmentingSession(t, &recorder{})
	request := peerRequest(t, s, 0, 1200, 500)
	var pending *pendingRequest
	s.dispatch(request[0], s.mux.Endpoint(), &pending)
	forged := slices.Clone(request[1])
	forged[len(forged)-1] ^= 1
	if s.dispatch(forged, s.mux.Endpoint(), &pending) || len(s.current.requestFragments.chunks) != 1 {
		t.Errorf("a fragment whose ICV fails was taken, and the queue holds %d fragments", len(s.current.requestFragments.chunks))
	}
	if sent := peerReads(t, peer, quietPeriod); len(sent) != 0 {
		t.Errorf("the request drew %d datagrams before its last fragment authenticated", len(sent))
	}
	for _, raw := range request[1:] {
		s.dispatch(raw, s.mux.Endpoint(), &pending)
	}
	if sent := peerReads(t, peer, answerBudget); len(sent) != 1 {
		t.Errorf("the request whose fragments authenticated drew %d datagrams, want its answer", len(sent))
	}
}

// fragments of a message left incomplete for reassemblyTimeout go, as one that comes after starts the queue over alone and Run's sweep drops what the queue holds
// reassemblyTimeout is requestBudget, the time the sends of one cut of a request take before this end as initiator gives up, and followupWait the same budget
// a request cut for its family's floor at the step, or cut again, starts its waits over and gives up later, which the shorter timeout RFC 7383 allows covers
// RFC 7383 section 2.6: "If the receiver does not get all IKE fragments needed to reassemble the original message within a timeout interval, it MUST discard all IKE Fragment messages received so far for the exchange."
// RFC 7383 section 2.6: "It is RECOMMENDED that the reassembling timeout for the responder be equal to the time interval that the implementation waits before completely giving up when acting as the initiator of an exchange."
// and: "Implementations can use a shorter timeout to conserve memory."
func TestFragmentsLeftIncompleteGoAtTheBudgetOfOneCut(t *testing.T) {
	var budget time.Duration
	for attempt := 1; attempt <= maxRetransmits; attempt++ {
		budget += retransmitDelay(requestTimeout, attempt)
	}
	for name, wait := range map[string]time.Duration{"fragments": reassemblyTimeout, "a peer's next IKE_FOLLOWUP_KE": followupWait} {
		if wait != budget {
			t.Errorf("the wait for %s is %s, want the %s the sends of one cut of a request take", name, wait, budget)
		}
	}
	ctx := testContext()
	datagrams := cutInto(t, ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(600)}, 400)
	messages := make([]*Message, len(datagrams))
	for i, raw := range datagrams {
		m, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		messages[i] = m
	}
	take := func(q *reassembly, i int, at time.Time) *opened {
		t.Helper()
		message, err := q.take(ctx.suite, ctx.sker, datagrams[i], messages[i], at)
		if err != nil {
			t.Fatal(err)
		}
		return message
	}
	start := time.Now()
	var q reassembly
	take(&q, 0, start)
	if message := take(&q, 1, start.Add(reassemblyTimeout)); message != nil || len(q.chunks) != 1 || q.chunks[2] == nil {
		t.Errorf("a fragment past the timeout made a message %v and left %d fragments, want it alone", message != nil, len(q.chunks))
	}
	if message := take(&q, 0, start.Add(reassemblyTimeout+time.Second)); message == nil {
		t.Error("the fragments within one timeout of each other made no message")
	}
	s := &Session{current: ctx}
	take(&ctx.requestFragments, 0, start)
	if ends, held := s.expireFragments(start.Add(reassemblyTimeout - time.Nanosecond)); !held || !ends.Equal(start.Add(reassemblyTimeout)) || ctx.requestFragments.chunks == nil {
		t.Errorf("before the timeout the sweep holds %v until %s, want the fragment held until %s", held, ends, start.Add(reassemblyTimeout))
	}
	if _, held := s.expireFragments(start.Add(reassemblyTimeout)); held || ctx.requestFragments.chunks != nil {
		t.Error("at the timeout the sweep kept the fragment")
	}
}

// sendsOf runs the backoff of an IKE_FOLLOWUP_KE request of ML-KEM-768 to a silent IPv4 peer on its own clock, each send reading the path MTU mtu gives for its number, the first numbered 1
// it returns the time of the last send and of the give-up, each from the first send
func sendsOf(t *testing.T, mtu func(send int) int) (last, gives time.Duration) {
	t.Helper()
	s, _ := fragmentingSession(t, &recorder{})
	send := 1
	s.pathMTU = func() (int, error) { return mtu(send), nil }
	s.retransmitAfter = requestTimeout
	_, key := modelKEM(t, ML_KEM_768)
	pending, err := s.startRequest(&localRequest{exchange: IKE_FOLLOWUP_KE, inner: []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}, linkPayload([]byte("link1"))}})
	if err != nil {
		t.Fatal(err)
	}
	for {
		gives += retransmitDelay(requestTimeout, pending.attempts)
		if pendingRetransmitsExhausted(pending, false) {
			return last, gives
		}
		send++
		last = gives
		s.sendPending(pending)
	}
}

// an IKE_FOLLOWUP_KE request of ML-KEM-768, whole under a path MTU of 1500 and too large for the IPv4 floor, gives up past requestBudget where it steps to the floor, which starts its waits over
// its last send still comes within requestBudget, so within followupWait of the answer before, through the step and through one or two path MTU falls at the sends after its cuts
// and a chain of such falls carries its last send past requestBudget
// RFC 9370 section 2.2.4: "The responder MUST handle this situation gracefully and delete the associated state if it does not receive the next expected IKE_FOLLOWUP_KE request after some reasonable period of time."
func TestRequestBudgetHoldsTheLastSendThroughAStepAndTwoFalls(t *testing.T) {
	// falls is the path MTU at each send of n falls, one at each send from the second, the first from 1500 to 1290 and each after it 50 lower
	falls := func(n int) func(send int) int {
		return func(send int) int {
			if send < 2 || n == 0 {
				return 1500
			}
			return 1290 - 50*(min(send, n+1)-2)
		}
	}
	for _, test := range []struct {
		falls int
		// past is whether the last send comes at requestBudget or after it
		past bool
	}{{0, false}, {1, false}, {2, false}, {13, true}} {
		last, gives := sendsOf(t, falls(test.falls))
		if gives <= requestBudget || (last >= requestBudget) != test.past {
			t.Errorf("through the step and %d falls the last send came at %s and the request gave up at %s, want the give-up past the budget of %s and the last send past it %v", test.falls, last, gives, requestBudget, test.past)
		}
	}
}

// the sweep drops what each IKE SA's queues hold past reassemblyTimeout, the current one's, a retained one's and those of the loser of a collision, and the repeat each credit of its answered request gathers
// and returns the earliest timeout of the queues it keeps, which started apart and in no order
func TestSweepDropsTheFragmentsOfEveryIKESA(t *testing.T) {
	start := time.Now()
	s := &Session{current: &ikeContext{}, old: &ikeContext{}, collision: &ikeContext{}}
	var queues []*reassembly
	var names []string
	for _, sa := range []struct {
		name string
		ctx  *ikeContext
	}{{"current", s.current}, {"retained", s.old}, {"collision", s.collision}} {
		sa.ctx.lastPeer.others = []*credit{{}}
		queues = append(queues, &sa.ctx.requestFragments, &sa.ctx.responseFragments, &sa.ctx.lastPeer.others[0].repeat)
		names = append(names, sa.name+" IKE SA's requests", sa.name+" IKE SA's answers", sa.name+" IKE SA's repeat")
	}
	// started is the second after start each queue started, the earliest neither first nor last
	started := []int{4, 7, 2, 8, 0, 5, 3, 6, 1}
	for i, q := range queues {
		*q = reassembly{messageID: 1, total: 2, started: start.Add(time.Duration(started[i]) * time.Second), held: 100, chunks: map[uint16][]byte{1: {0}}}
	}
	for _, sweep := range []struct {
		// at is the second past start's timeout the sweep runs, and next the second after start the earliest queue it keeps started, -1 for none
		at, next int
	}{{-1, 0}, {2, 3}, {8, -1}} {
		ends, held := s.expireFragments(start.Add(reassemblyTimeout + time.Duration(sweep.at)*time.Second))
		if want := start.Add(reassemblyTimeout + time.Duration(sweep.next)*time.Second); held != (sweep.next >= 0) || held && !ends.Equal(want) {
			t.Errorf("the sweep %ds past the first queue's timeout holds %v until %s, want the timeout of the queue started %ds after it", sweep.at, held, ends.Sub(start), sweep.next)
		}
		for i, q := range queues {
			if kept := q.chunks != nil; kept != (started[i] > sweep.at) {
				t.Errorf("the sweep %ds past the first queue's timeout kept the %s %v, started %ds after it", sweep.at, names[i], kept, started[i])
			}
		}
	}
}

// fragmentsLeft is how far short of reassemblyTimeout the fragment Run's queue holds arrived, and sweepWait how long Run runs, long past that and short of any other work waking it
const (
	fragmentsLeft = 300 * time.Millisecond
	sweepWait     = 2 * time.Second
)

// Run wakes for the fragments it holds at their timeout and drops them, though no other work wakes it before then
// RFC 7383 section 2.6: "If the receiver does not get all IKE fragments needed to reassemble the original message within a timeout interval, it MUST discard all IKE Fragment messages received so far for the exchange."
func TestRunSweepsFragmentsAtTheirTimeout(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, responder := dialPaused(t, h, h.peerConfig())
	t.Cleanup(func() { initiator.Mux().Close(); responder.Mux().Close() })
	ctx := initiator.current
	ctx.requestFragments = reassembly{messageID: 7, total: 2, started: time.Now().Add(fragmentsLeft - reassemblyTimeout), held: 100, chunks: map[uint16][]byte{1: {0}}}
	run, stop := context.WithTimeout(context.Background(), sweepWait)
	defer stop()
	_ = initiator.Run(run)
	if ctx.requestFragments.chunks != nil {
		t.Error("Run kept the fragments past their timeout")
	}
}

// a send that fails leaves the datagrams after it to go, since each fragment the peer gets is one it keeps, and the first failure is the one told
func TestSendEachSendsPastAFailedSend(t *testing.T) {
	var sent []byte
	err := sendEach(func(datagram []byte) error {
		sent = append(sent, datagram[0])
		if datagram[0] < 3 {
			return fmt.Errorf("datagram %d refused", datagram[0])
		}
		return nil
	}, [][]byte{{1}, {2}, {3}})
	if !bytes.Equal(sent, []byte{1, 2, 3}) || err == nil || err.Error() != "datagram 1 refused" {
		t.Errorf("the sends went for datagrams %v and told %v, want all three and the first failure", sent, err)
	}
}

// takers are the two ways an IKE SA past IKE_AUTH takes a request of the peer's from source, Run and the dial's wait after IKE_AUTH
// each returns what its site reports, which for a repeat of the answered request holds only where the repeat ends the IKE SA
var takers = map[string]func(s *Session, raw []byte, source transport.Endpoint) bool{
	"Run": func(s *Session, raw []byte, source transport.Endpoint) bool {
		var pending *pendingRequest
		return s.dispatch(raw, source, &pending)
	},
	"wait after IKE_AUTH": func(s *Session, raw []byte, source transport.Endpoint) bool {
		return s.answerAfterAuth(s.current, raw, source)
	},
}

// halfOpenSite is the half-open SA's wait for IKE_AUTH, which awaitAuthRequest runs, as a test names it beside the sites of takers
const halfOpenSite = "half-open wait"

// after a request that came in fragments is answered, a repeat of its fragment 1 draws the answer again and a repeat of any other draws nothing, in Run, in the wait after IKE_AUTH and in the half-open wait
// a fragment 1 that does not authenticate draws nothing
// RFC 7383 section 2.6.1: "If the responder receives a retransmitted fragment of a request when it has already processed that request and has sent back a response, that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
// and: "otherwise, it MUST be ignored."
func TestOnlyFragmentOneOfAnAnsweredRequestDrawsTheAnswerAgain(t *testing.T) {
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			request := peerRequest(t, s, 0, 1200, 500)
			for _, raw := range request {
				take(s, raw, s.mux.Endpoint())
			}
			answer := peerReads(t, peer, answerBudget)
			if len(answer) != 1 {
				t.Fatalf("the request drew %d datagrams, want its answer", len(answer))
			}
			forged := slices.Clone(request[0])
			forged[len(forged)-1] ^= 1
			take(s, forged, s.mux.Endpoint())
			if again := peerReads(t, peer, quietPeriod); len(again) != 0 {
				t.Errorf("a fragment 1 that does not authenticate drew %d datagrams", len(again))
			}
			for i := len(request) - 1; i >= 0; i-- {
				take(s, request[i], s.mux.Endpoint())
				again := peerReads(t, peer, quietPeriod)
				if i == 0 && (len(again) != 1 || !bytes.Equal(again[0], answer[0])) || i > 0 && len(again) != 0 {
					t.Errorf("a repeat of fragment %d drew %d datagrams, want the answer again %v", i+1, len(again), i == 0)
				}
			}
		})
	}
	t.Run("half-open wait", func(t *testing.T) {
		h := newResponderHarness(t, nil)
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		s.cut = 500
		s.intermediate(1, ML_KEM_768)
		request, answer := s.sent, s.got
		for i := len(request) - 1; i >= 0; i-- {
			if err := s.mux.SendIKE(request[i]); err != nil {
				t.Fatal(err)
			}
			if i > 0 && !s.silent() {
				t.Errorf("a repeat of fragment %d drew an answer", i+1)
			}
		}
		for _, want := range answer {
			if again, err := s.mux.RecvIKEUntil(time.Now().Add(answerBudget)); err != nil || !bytes.Equal(again, want) {
				t.Fatalf("a repeat of fragment 1 drew %d octets (%v), want the answer again", len(again), err)
			}
		}
		s.cut = 0
		if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
			t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
		}
		s.accepted(2, []uint16{ML_KEM_768})
	})
}

// an answer kept for a repeat of its request goes again cut for the path at that send, in more fragments that fit a path MTU that fell since it went, in Run, in the wait after IKE_AUTH and in the half-open wait
// a repeat under the same path MTU draws the same datagrams again
// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
// RFC 7383 section 2.5.2: "Implementations MUST be prepared to probe in every exchange that utilizes IKE fragmentation to deal with possible changes in path MTU over time."
func TestKeptAnswerGoesAgainCutForThePathAtItsSend(t *testing.T) {
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			mtu := 9000
			s.pathMTU = func() (int, error) { return mtu, nil }
			ctx := s.current
			// the answer is UNSUPPORTED_CRITICAL_PAYLOAD, which carries octets a cut can spread over more fragments
			request := cutInto(t, ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(1200), unsupportedCritical}, 500)
			for _, raw := range request {
				take(s, raw, s.mux.Endpoint())
			}
			answer := peerReads(t, peer, answerBudget)
			_, inner, _, total := assembled(t, ctx.suite, ctx.localEncryptionKey(), answer)
			if total != 1 || !notified(inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
				t.Fatalf("the request in fragments drew %v in %d fragments, want UNSUPPORTED_CRITICAL_PAYLOAD in one", inner, total)
			}
			mtu = 576
			var first [][]byte
			for repeat := range 2 {
				take(s, request[0], s.mux.Endpoint())
				again := peerReads(t, peer, answerBudget)
				wantFits(t, again, floorRoom)
				_, inner, _, total := assembled(t, ctx.suite, ctx.localEncryptionKey(), again)
				if total < 2 || !notified(inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
					t.Fatalf("repeat %d of fragment 1 under the lower path MTU drew %v in %d fragments, want the answer cut again", repeat+1, inner, total)
				}
				if repeat == 0 {
					first = again
				} else if !slices.EqualFunc(again, first, bytes.Equal) {
					t.Error("a repeat under the same path MTU drew datagrams other than the last send's")
				}
			}
		})
	}
	t.Run("half-open wait", func(t *testing.T) {
		var mtu atomic.Int64
		mtu.Store(1500)
		h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) {
			cfg.pathMTU = func() (int, error) { return int(mtu.Load()), nil }
		})
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		// one fragment carries the request, and its datagram the answer
		s.cut = 1200
		key := s.model.keys[2]
		s.intermediate(1, ML_KEM_768)
		_, want, _, total := assembled(t, modelSuite, key, s.got)
		if total != 1 {
			t.Fatalf("the IKE_INTERMEDIATE request in fragments drew an answer in %d fragments, want one", total)
		}
		mtu.Store(576)
		var first [][]byte
		for repeat := range 2 {
			if err := s.mux.SendIKE(s.sent[0]); err != nil {
				t.Fatal(err)
			}
			again := collect(t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
			wantFits(t, again, floorRoom)
			if _, inner, _, total := assembled(t, modelSuite, key, again); total < 2 || !slices.EqualFunc(inner, want, func(a, b RawPayload) bool { return a.Type == b.Type && bytes.Equal(a.Body, b.Body) }) {
				t.Fatalf("repeat %d of fragment 1 under the lower path MTU drew payload types %v in %d fragments, want the answer cut again", repeat+1, payloadTypes(inner), total)
			}
			if repeat == 0 {
				first = again
			} else if !slices.EqualFunc(again, first, bytes.Equal) {
				t.Error("a repeat under the same path MTU drew datagrams other than the last send's")
			}
		}
		s.cut = 0
		if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
			t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
		}
		s.accepted(2, []uint16{ML_KEM_768})
	})
}

// an answer kept for a repeat of its request goes again cut within the repeat's fragment 1 where a datagram of the answer is larger, in more fragments, and as it stands where its datagrams fit, in Run, in the wait after IKE_AUTH and in the half-open wait
// a fragment 1 smaller than the IPv4 floor's datagram cuts the answer for the floor and no smaller, and the next leaves it as it stands
// a repeat whole carries no fragment size, and leaves an answer as it stands though the repeat is smaller
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
// RFC 7383 section 2.5.2: "When selecting the next smaller value for the fragmentation threshold, the sender MUST ensure that the value in the Total Fragments field is really increased."
func TestKeptAnswerIsCutAgainWithinASmallerRepeatAndNoFurther(t *testing.T) {
	// steps draws the answer again with fragment 1 of each size, the first as large as the answer's largest datagram, and checks each answer against the one before it
	// the third size is under the second, which the answer then fits however far its threshold is above
	steps := func(t *testing.T, answer [][]byte, open func([][]byte) []RawPayload, repeat func(size int) [][]byte) {
		t.Helper()
		want := open(answer)
		for _, size := range []int{largest(answer), largest(answer) - 100, largest(answer) - 150, 100, 100} {
			again := repeat(size)
			if got := open(again); !samePayloads(got, want) {
				t.Fatalf("fragment 1 of %d octets drew payload types %v, want the answer again", size, payloadTypes(got))
			}
			bound := max(size, floorRoom)
			if largest(answer) <= bound {
				if !slices.EqualFunc(again, answer, bytes.Equal) {
					t.Errorf("fragment 1 of %d octets drew %d datagrams of at most %d octets, want the %d of at most %d as they went", size, len(again), largest(again), len(answer), largest(answer))
				}
			} else if largest(again) > bound || len(again) <= len(answer) || size < floorRoom && largest(again) <= size {
				t.Errorf("fragment 1 of %d octets drew %d datagrams of at most %d octets from %d of at most %d, want more fragments of at most %d and the floor's cut at the least", size, len(again), largest(again), len(answer), largest(answer), bound)
			}
			answer = again
		}
	}
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			s.pathMTU = pathMTUOf(9000)
			ctx := s.current
			mid := ctx.nextPeerMID
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, []RawPayload{bulkyStatus(1500)})
			if err != nil {
				t.Fatal(err)
			}
			header := Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}
			// the answer to a request in three fragments of at most 900 octets each, 839 octets of plaintext and what an IKE Fragment message adds around them
			request := openedOf(t, s, cutInto(t, ctx.suite, ctx.sker, header, []RawPayload{bulkyStatus(2000)}, 839))
			sent, err := s.keepAnswer(ctx, mid, response, request)
			if err != nil {
				t.Fatal(err)
			}
			if request.form != (form{total: 3, largest: 900}) || largest(sent.datagrams) != 900 {
				t.Fatalf("the answer to a request in %+v went in %d datagrams of at most %d octets, want them within the request's 900", request.form, len(sent.datagrams), largest(sent.datagrams))
			}
			empty, err := sealedFragment(ctx.suite, ctx.sker, header, nil, PayloadN, 0, 1, 8, nil)
			if err != nil {
				t.Fatal(err)
			}
			steps(t, slices.Clone(sent.datagrams), func(datagrams [][]byte) []RawPayload {
				_, inner, _, _ := assembled(t, ctx.suite, ctx.localEncryptionKey(), datagrams)
				return inner
			}, func(size int) [][]byte {
				raw, err := sealedFragment(ctx.suite, ctx.sker, header, nil, PayloadN, 0, 1, 8, make([]byte, size-len(empty)))
				if err != nil {
					t.Fatal(err)
				}
				take(s, raw, s.mux.Endpoint())
				return peerReads(t, peer, answerBudget)
			})
			// the answer to a request that came whole goes whole, and that request again, far under the floor's datagram, draws it so
			mid = ctx.nextPeerMID
			response, err = ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, []RawPayload{bulkyStatus(1500)})
			if err != nil {
				t.Fatal(err)
			}
			whole := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(32)})
			if sent, err = s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{whole})); err != nil {
				t.Fatal(err)
			}
			went := slices.Clone(sent.datagrams)
			take(s, whole, s.mux.Endpoint())
			if again := peerReads(t, peer, answerBudget); len(went) != 1 || !slices.EqualFunc(again, went, bytes.Equal) {
				t.Errorf("a repeat whole of %d octets drew %d datagrams of at most %d octets, want the answer whole as it went in %d", len(whole), len(again), largest(again), len(went))
			}
		})
	}
	t.Run("half-open wait", func(t *testing.T) {
		entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
		h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(9000) })
		h.lists.Store(&Suites{kex: []kexEntry{entry1024}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		key, answerKey := s.model.keys[1], s.model.keys[2]
		header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
		s.cut = 900
		s.intermediate(1, ML_KEM_1024)
		if largest(s.got) != largest(s.sent) {
			t.Fatalf("the answer went in datagrams of at most %d octets, want them within the request's %d", largest(s.got), largest(s.sent))
		}
		empty, err := sealedFragment(modelSuite, key, header, nil, PayloadKE, 0, 1, 8, nil)
		if err != nil {
			t.Fatal(err)
		}
		steps(t, s.got, func(datagrams [][]byte) []RawPayload {
			_, inner, _, _ := assembled(t, modelSuite, answerKey, datagrams)
			return inner
		}, func(size int) [][]byte {
			raw, err := sealedFragment(modelSuite, key, header, nil, PayloadKE, 0, 1, 8, make([]byte, size-len(empty)))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.mux.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
			return collect(t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
		})
		s.cut = 0
		if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
			t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
		}
		s.accepted(2, []uint16{ML_KEM_1024})
	})
}

// heard is each datagram mux takes until it waits quietPeriod in vain
func heard(mux *transport.Mux) [][]byte {
	var got [][]byte
	for {
		raw, err := mux.RecvIKEUntil(time.Now().Add(quietPeriod))
		if err != nil {
			return got
		}
		got = append(got, raw)
	}
}

// in the half-open wait a repeat from an address and port other than those the IKE SA was set up from draws the answer there only once all of the request came from there, and only within the octets that address sent repeating it
// the shortest fragment 1 that authenticates, fragment 1 of the request, the request's fragments from two places, the request's fragments carrying other content, and all of the request in fewer fragments than it came in draw nothing anywhere, sent maxRetransmits+1 times
// a fragment that does not authenticate from a third place moves nothing, and all of the request in more fragments from a fourth draws the answer cut again within them
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestHalfOpenRepeatFromAnotherAddressDrawsNoMoreOctetsThanItSent(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	key := s.model.keys[1]
	header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
	s.cut = 500
	s.intermediate(1, ML_KEM_768)
	request, answer := s.sent, s.got
	_, inner, _, _ := assembled(t, modelSuite, key, request)
	total := uint16(len(request))
	shortest, err := sealedFragment(modelSuite, key, header, nil, PayloadNone, 0, 1, total, nil)
	if err != nil {
		t.Fatal(err)
	}
	// the request's content with one octet of its KE payload turned, cut as the request was, so its octets cover the answer and only its content keeps it from drawing one
	turned := slices.Clone(inner)
	turned[0].Body = slices.Clone(turned[0].Body)
	turned[0].Body[len(turned[0].Body)/2] ^= 0xff
	other := cutInto(t, modelSuite, key, header, turned, s.cut)
	if len(other) != len(request) || octetsOf(other) != octetsOf(request) {
		t.Fatalf("the other content went in %d fragments of %d octets, want the request's %d of %d", len(other), octetsOf(other), len(request), octetsOf(request))
	}
	// each case sends each of its parts from a place of its own
	for name, parts := range map[string][][][]byte{
		"the shortest fragment 1 that authenticates":                         {{shortest}},
		"fragment 1 of the request":                                          {request[:1]},
		"fragment 1 of the request from one place and the rest from another": {request[:1], request[1:]},
		"the request's fragments carrying other content":                     {other},
		"all of the request in fewer fragments":                              {cutInto(t, modelSuite, key, header, inner, 700)},
	} {
		var places []*transport.Mux
		for _, part := range parts {
			place := s.moved()
			places = append(places, place)
			for range maxRetransmits + 1 {
				for _, raw := range part {
					if err := place.SendIKE(raw); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		for _, place := range places {
			if got := heard(place); len(got) != 0 {
				t.Errorf("%s from another address drew %d datagrams there", name, len(got))
			}
		}
	}
	if !s.silent() {
		t.Error("repeats from other addresses drew an answer at the one the IKE SA was set up from")
	}
	// all of the request from one place draws the answer there, though a fragment that does not authenticate came from a third between its fragments
	place := s.moved()
	forged := slices.Clone(request[1])
	forged[len(forged)-1] ^= 1
	for i, raw := range request {
		if err := place.SendIKE(raw); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if err := s.moved().SendIKE(forged); err != nil {
				t.Fatal(err)
			}
		}
	}
	again := collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
	if drawn, sent := wireOf(again), wireOf(request); !slices.EqualFunc(again, answer, bytes.Equal) || drawn > sent {
		t.Errorf("all of the request from another address, %d octets on the wire, drew %d there, want the answer of no more", sent, drawn)
	}
	if !s.silent() {
		t.Error("all of the request from another address drew an answer at the one the IKE SA was set up from")
	}
	// fragments of 400 octets of plaintext come in datagrams under the floor's, which the answer's are not
	finer, place := cutInto(t, modelSuite, key, header, inner, 400), s.moved()
	for _, raw := range finer {
		if err := place.SendIKE(raw); err != nil {
			t.Fatal(err)
		}
	}
	again = collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
	if drawn, sent := wireOf(again), wireOf(finer); len(again) <= len(answer) || largest(again) > max(largest(finer), floorRoom) || drawn > sent {
		t.Errorf("all of the request in fragments of at most %d octets, %d on the wire in all, drew %d datagrams of at most %d octets, %d on the wire in all, from %d, want more fragments within the floor's and no more octets", largest(finer), sent, len(again), largest(again), drawn, len(answer))
	}
	s.cut = 0
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_768})
}

// octetsOf is the octets of IKE message datagrams carry in all
func octetsOf(datagrams [][]byte) int {
	n := 0
	for _, raw := range datagrams {
		n += len(raw)
	}
	return n
}

// wireOf is the octets datagrams take on an IPv4 path, with an IP header without options, the UDP header and the non-ESP marker around each
func wireOf(datagrams [][]byte) int {
	return octetsOf(datagrams) + len(datagrams)*(20+8+NonESPMarkerLen)
}

// in the half-open wait an initiator that sent its IKE_INTERMEDIATE request in one IKE Fragment message from the address the IKE SA was set up from, and moved, repeats it from another address
// the answer, cut for the responder's threshold, takes more octets on the wire than the repeat, so the repeat draws nothing there, and the next repeat draws the answer, never more octets on the wire in all than the repeats sent
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
func TestMovedSetDrawsNoMoreOctetsThanItSent(t *testing.T) {
	entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
	for _, test := range []struct {
		name   string
		entry  kexEntry
		method uint16
		mtu    func() (int, error)
	}{
		{"ML-KEM-768 at the IPv4 floor", entry768, ML_KEM_768, noPathMTU},
		{"ML-KEM-1024 at the IPv4 floor", entry1024, ML_KEM_1024, noPathMTU},
		{"ML-KEM-1024 under a path MTU of 1500", entry1024, ML_KEM_1024, pathMTUOf(1500)},
		{"ML-KEM-1024 under a path MTU of 1280", entry1024, ML_KEM_1024, pathMTUOf(1280)},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = test.mtu })
			h.lists.Store(&Suites{kex: []kexEntry{test.entry}})
			s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, test.method)), []RawPayload{fragmentationSupported}, true)
			if s == nil {
				t.Fatalf("the responder refused the offer with notify %d", refused)
			}
			s.cut = 4000
			s.intermediate(1, test.method)
			movedRepeats(t, s, s.sent, s.got)
			s.cut = 0
			if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
				t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
			}
			s.accepted(2, []uint16{test.method})
		})
	}
}

// the same for a request whole under a path MTU of 1500, whose answer goes in fragments, and the repeat whole from another address
// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
func TestMovedWholeRepeatDrawsNoMoreOctetsThanItSent(t *testing.T) {
	entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(1500) })
	h.lists.Store(&Suites{kex: []kexEntry{entry1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	s.intermediate(1, ML_KEM_1024)
	if len(s.sent) != 1 || len(s.got) < 2 {
		t.Fatalf("the request went in %d datagrams and the answer in %d, want the request whole and the answer cut", len(s.sent), len(s.got))
	}
	movedRepeats(t, s, s.sent, s.got)
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_1024})
}

// in the half-open wait under a path MTU of 1500 the origin's fragment 1 of the request cut finer than it came cuts the answer again within it, into datagrams that carry fewer octets of IKE message than the request whole and take more on the wire
// so the request whole from another address draws nothing there, and the same once more draws the answer as it went, since a credit counts each datagram on the wire as path counts one
// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
func TestMovedWholeRepeatIsReadOnTheWire(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(1500) })
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	key := s.model.keys[1]
	s.intermediate(1, ML_KEM_768)
	whole := s.sent
	_, inner, _, _ := assembled(t, modelSuite, key, whole)
	finer := cutInto(t, modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}, inner, 700)
	if err := s.mux.SendIKE(finer[0]); err != nil {
		t.Fatal(err)
	}
	answer := collect(t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
	if len(whole) != 1 || octetsOf(answer) >= octetsOf(whole) || wireOf(answer) <= wireOf(whole) {
		t.Fatalf("the request went in %d datagrams, %d octets of IKE message and %d on the wire, and the answer cut again in %d, %d and %d, want the request whole and the answer fewer octets of IKE message and more on the wire", len(whole), octetsOf(whole), wireOf(whole), len(answer), octetsOf(answer), wireOf(answer))
	}
	place := s.moved()
	for repeat := range 2 {
		if err := place.SendIKE(whole[0]); err != nil {
			t.Fatal(err)
		}
		var again [][]byte
		if repeat == 0 {
			again = heard(place)
		} else {
			again = collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
		}
		if repeat == 0 && len(again) != 0 || repeat == 1 && !slices.EqualFunc(again, answer, bytes.Equal) {
			t.Errorf("repeat %d of the request whole from another address drew %d datagrams, %d octets on the wire, want nothing at the first and the answer at the second", repeat+1, len(again), wireOf(again))
		}
	}
	if !s.silent() {
		t.Error("the repeats from another address drew an answer at the one the IKE SA was set up from")
	}
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_768})
}

// movedRepeats sends request, whose answer went as answer and takes more octets on the wire, three times from another address, and checks that the first send there draws nothing, the second and the third the answer, and the address never more octets on the wire than it sent
func movedRepeats(t *testing.T, s *scripted, request, answer [][]byte) {
	t.Helper()
	if wireOf(answer) <= wireOf(request) {
		t.Fatalf("the request took %d octets on the wire and the answer %d, want the answer larger", wireOf(request), wireOf(answer))
	}
	place := s.moved()
	sent, drawn := 0, 0
	for repeat := range 3 {
		for _, raw := range request {
			if err := place.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
		}
		sent += wireOf(request)
		var again [][]byte
		if repeat == 0 {
			again = heard(place)
		} else {
			again = collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
		}
		drawn += wireOf(again)
		if drawn > sent || repeat == 0 && len(again) != 0 || repeat > 0 && !slices.EqualFunc(again, answer, bytes.Equal) {
			t.Errorf("repeat %d from another address drew %d datagrams, %d octets on the wire of %d sent from there in all, want nothing at the first, the answer after it, and no more octets than sent", repeat+1, len(again), drawn, sent)
		}
	}
	if !s.silent() {
		t.Error("the repeats from another address drew an answer at the one the IKE SA was set up from")
	}
}

// in the half-open wait a set of the request in finer fragments from another address cuts the answer again within them, and the set's octets are read against the answer as that send cuts it
// under a path MTU of 1500 the ML-KEM-1024 answer went in 2 fragments, as many octets as a set of the request in 2 fragments of 800 octets of plaintext carries, and cut again within that set it carries more
// so the set draws nothing there, and the same set once more draws the answer cut again, never more octets on the wire than the sets sent
// RFC 7383 section 2.5.1: "The responder in the exchange may use the maximum size of the received IKE Fragment message IP datagrams as a threshold when constructing a fragmented response."
func TestMovedFinerSetIsReadAgainstTheAnswerCutAgain(t *testing.T) {
	entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = pathMTUOf(1500) })
	h.lists.Store(&Suites{kex: []kexEntry{entry1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	key := s.model.keys[1]
	s.cut = 4000
	s.intermediate(1, ML_KEM_1024)
	_, inner, _, _ := assembled(t, modelSuite, key, s.sent)
	finer := cutInto(t, modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}, inner, 800)
	if len(finer) != 2 || len(s.got) != 2 || octetsOf(finer) != octetsOf(s.got) {
		t.Fatalf("the set went in %d datagrams, %d octets, and the answer in %d, %d octets, want 2 of each carrying as many octets", len(finer), octetsOf(finer), len(s.got), octetsOf(s.got))
	}
	place := s.moved()
	sent, drawn := 0, 0
	for repeat := range 2 {
		for _, raw := range finer {
			if err := place.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
		}
		sent += wireOf(finer)
		var again [][]byte
		if repeat == 0 {
			again = heard(place)
		} else {
			again = collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
		}
		drawn += wireOf(again)
		if drawn > sent || repeat == 0 && len(again) != 0 || repeat == 1 && (len(again) <= len(s.got) || largest(again) > largest(finer)) {
			t.Errorf("set %d from another address drew %d datagrams of at most %d octets, %d octets on the wire of %d sent from there in all, want nothing at the first, the answer cut again within the set at the second, and no more octets than sent", repeat+1, len(again), largest(again), drawn, sent)
		}
	}
	if !s.silent() {
		t.Error("the sets from another address drew an answer at the one the IKE SA was set up from")
	}
	s.cut = 0
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_1024})
}

// in the half-open wait the octets another address sent repeating a request count in that exchange alone
// at the IPv4 floor a moved initiator's repeat of the first IKE_INTERMEDIATE request draws nothing there, its answer taking more octets on the wire, and neither does its repeat of the second, which the octets of both would cover
func TestOctetsFromAnotherAddressCountInTheirExchangeAlone(t *testing.T) {
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = noPathMTU })
	h.lists.Store(&Suites{kex: []kexEntry{entry768And1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	s.cut = 4000
	place, sent := s.moved(), 0
	for i, method := range []uint16{ML_KEM_768, ML_KEM_1024} {
		mid := uint32(i + 1)
		s.intermediate(mid, method)
		if wireOf(s.got) <= wireOf(s.sent) || i > 0 && wireOf(s.got) > sent+wireOf(s.sent) {
			t.Fatalf("the request at %d took %d octets on the wire and the answer %d, want the answer larger, and within the octets sent from the other address in all from the second on", mid, wireOf(s.sent), wireOf(s.got))
		}
		for _, raw := range s.sent {
			if err := place.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
		}
		sent += wireOf(s.sent)
		if got := heard(place); len(got) != 0 {
			t.Errorf("the request at %d, %d octets from another address, drew %d datagrams there, %d octets, want nothing", mid, octetsOf(s.sent), len(got), octetsOf(got))
		}
	}
	if !s.silent() {
		t.Error("the repeats from another address drew an answer at the one the IKE SA was set up from")
	}
	s.cut = 0
	if header, _ := s.authenticate(3, 3); header.ExchangeType != IKE_AUTH || header.MessageID != 3 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 3", header.ExchangeType, header.MessageID)
	}
	s.accepted(3, []uint16{ML_KEM_768, ML_KEM_1024})
}

// in the half-open wait a moved initiator repeats its IKE_INTERMEDIATE request of ML-KEM-1024 at the IPv4 floor, whole or cut again for the floor, and an observer replays one captured datagram of it from a third address after each of the initiator's
// the replay's octets go to the third address's own credit, so the initiator draws the answer as it does with no replay, on its second repeat whole and its first cut
// and the third address draws no more octets on the wire than it sent
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
func TestReplayFromAThirdAddressHoldsNoMovedInitiator(t *testing.T) {
	entry1024 := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_1024}}
	for _, c := range []struct {
		name       string
		refragment int
		sends      int
	}{{"the request whole", 0, 2}, {"the request cut again for the floor", 483, 1}} {
		for _, replayed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s, replayed %v", c.name, replayed), func(t *testing.T) {
				h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.pathMTU = noPathMTU })
				h.lists.Store(&Suites{kex: []kexEntry{entry1024}})
				s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
				if s == nil {
					t.Fatalf("the responder refused the offer with notify %d", refused)
				}
				key := s.model.keys[1]
				header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
				s.intermediate(1, ML_KEM_1024)
				request, answer := s.sent, s.got
				if c.refragment > 0 {
					_, inner, _, _ := assembled(t, modelSuite, key, s.sent)
					request = cutInto(t, modelSuite, key, header, inner, c.refragment)
				}
				moved, third := s.moved(), s.moved()
				send := func(m *transport.Mux, raw []byte) {
					if err := m.SendIKE(raw); err != nil {
						t.Fatal(err)
					}
					time.Sleep(arrivalGap)
				}
				var drawn, elsewhere [][]byte
				sends, replays := 0, 0
				for sends < 4 && len(drawn) == 0 {
					sends++
					for _, raw := range request {
						send(moved, raw)
						if replayed {
							send(third, request[0])
							replays++
						}
					}
					drawn = heard(moved)
					elsewhere = append(elsewhere, heard(third)...)
				}
				if !slices.EqualFunc(drawn, answer, bytes.Equal) || sends != c.sends {
					t.Errorf("the moved initiator's repeat in %d datagrams drew %d datagrams in %d sends of it, want the answer in %d", len(request), len(drawn), sends, c.sends)
				}
				if sent := replays * wireOf(request[:1]); wireOf(elsewhere) > sent {
					t.Errorf("the third address drew %d octets on the wire for the %d it sent", wireOf(elsewhere), sent)
				}
				if !s.silent() {
					t.Error("the repeats from other addresses drew an answer at the one the IKE SA was set up from")
				}
				s.authenticate(2, 2)
				s.accepted(2, []uint16{ML_KEM_1024})
			})
		}
	}
}

// repeatSites are the sites of takers and the half-open wait, which awaitAuthRequest runs through answerRepeat, each reporting whether the repeat ended the IKE SA
func repeatSites() map[string]func(s *Session, raw []byte, source transport.Endpoint) bool {
	sites := map[string]func(s *Session, raw []byte, source transport.Endpoint) bool{
		halfOpenSite: func(s *Session, raw []byte, source transport.Endpoint) bool {
			m, err := DecodeMessage(raw)
			return err == nil && s.answerRepeat(s.current, raw, m, source) != nil
		},
	}
	maps.Copy(sites, takers)
	return sites
}

// at each site that resends a kept answer, a moved peer's repeat in fragments outlasts movedCredits-1 addresses new to the exchange that repeat between its first datagram and its second
// and a newcomer past them takes the place of its credit, the one whose last datagram arrived least recently, so its repeat then draws nothing
// each newcomer replays fragment 1, which its own credit gathers, so none draws the answer
func TestMovedRepeatOutlastsNewcomersUpToTheBound(t *testing.T) {
	for name, take := range repeatSites() {
		for _, newcomers := range []int{movedCredits - 1, movedCredits} {
			t.Run(fmt.Sprintf("%s, %d newcomers", name, newcomers), func(t *testing.T) {
				s, peer, hub := fragmentingSessionAt(t, &recorder{})
				s.pathMTU = noPathMTU
				ctx := s.current
				moved, movedAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
				sources, others := make([]transport.Endpoint, newcomers), make([]*net.UDPConn, newcomers)
				for i := range newcomers {
					sources[i], others[i] = observedPeerFrom(t, hub, 0x9192939495969700+uint64(i), net.IPv4(127, 0, 0, 1))
				}
				mid := ctx.nextPeerMID
				request := peerRequest(t, s, mid, 1200, 500)
				response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
				if err != nil {
					t.Fatal(err)
				}
				sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, request))
				if err != nil {
					t.Fatal(err)
				}
				take(s, request[0], moved)
				for _, source := range sources {
					take(s, request[0], source)
				}
				for _, raw := range request[1:] {
					take(s, raw, moved)
				}
				draws, wait := newcomers < movedCredits, quietPeriod
				if draws {
					wait = answerBudget
				}
				if got := peerReads(t, movedAt, wait); draws != slices.EqualFunc(got, sent.datagrams, bytes.Equal) || !draws && len(got) != 0 {
					t.Errorf("the moved peer's request in %d fragments, %d newcomers repeating between its first and second, drew %d datagrams, want the answer %v", len(request), newcomers, len(got), draws)
				}
				for i, other := range others {
					if got := peerReads(t, other, quietPeriod); len(got) != 0 {
						t.Errorf("newcomer %d drew %d datagrams", i+1, len(got))
					}
				}
				if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
					t.Errorf("the endpoint drew %d datagrams", len(got))
				}
			})
		}
	}
}

// at each site that resends a kept answer, fragments that do not authenticate from movedCredits addresses new to the exchange, between a moved peer's first datagram and its second, take no credit's place
// so the moved peer's repeat draws the answer there, and only the key holder, or a replay of what it sent, makes or moves a credit
func TestFragmentsThatDoNotAuthenticateTakeNoCredit(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer, hub := fragmentingSessionAt(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			moved, movedAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			sources, others := make([]transport.Endpoint, movedCredits), make([]*net.UDPConn, movedCredits)
			for i := range movedCredits {
				sources[i], others[i] = observedPeerFrom(t, hub, 0x9192939495969700+uint64(i), net.IPv4(127, 0, 0, 1))
			}
			mid := ctx.nextPeerMID
			request := peerRequest(t, s, mid, 1200, 500)
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, request))
			if err != nil {
				t.Fatal(err)
			}
			forged := slices.Clone(request[0])
			forged[len(forged)-1] ^= 1
			take(s, request[0], moved)
			for _, source := range sources {
				if take(s, forged, source) {
					t.Fatal("a fragment that does not authenticate ended the IKE SA")
				}
			}
			for _, raw := range request[1:] {
				take(s, raw, moved)
			}
			if got := peerReads(t, movedAt, answerBudget); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
				t.Errorf("the moved peer's request in %d fragments, %d fragments that do not authenticate from new addresses between its first and second, drew %d datagrams, want the answer", len(request), movedCredits, len(got))
			}
			for i, other := range others {
				if got := peerReads(t, other, quietPeriod); len(got) != 0 {
					t.Errorf("new address %d drew %d datagrams", i+1, len(got))
				}
			}
			if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
				t.Errorf("the endpoint drew %d datagrams", len(got))
			}
		})
	}
}

// at each site that resends a kept answer, each address's repeat in fragments is gathered apart from every other address's
// so fragment 1 from one address and the rest of the request from a second draw nothing at either, and the first, sending the rest, draws the answer there
func TestRepeatsFromTwoAddressesAreGatheredApart(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer, hub := fragmentingSessionAt(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			first, firstAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			second, secondAt := observedPeerFrom(t, hub, 0x9192939495969798, net.IPv4(127, 0, 0, 1))
			mid := ctx.nextPeerMID
			request := peerRequest(t, s, mid, 1200, 500)
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, request))
			if err != nil {
				t.Fatal(err)
			}
			take(s, request[0], first)
			for _, raw := range request[1:] {
				take(s, raw, second)
			}
			if got := peerReads(t, secondAt, quietPeriod); len(got) != 0 {
				t.Errorf("fragment 1 from one address and the other %d fragments from a second drew %d datagrams at the second", len(request)-1, len(got))
			}
			if got := peerReads(t, firstAt, quietPeriod); len(got) != 0 {
				t.Errorf("fragment 1 from one address and the other %d fragments from a second drew %d datagrams at the first", len(request)-1, len(got))
			}
			for _, raw := range request[1:] {
				take(s, raw, first)
			}
			if got := peerReads(t, firstAt, answerBudget); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
				t.Errorf("the first address's request in %d fragments drew %d datagrams there, want the answer", len(request), len(got))
			}
			if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
				t.Errorf("the endpoint drew %d datagrams", len(got))
			}
		})
	}
}

// arrivalGap is how long a test waits between sends from two sockets, so the responder takes them in the order they went
const arrivalGap = 50 * time.Millisecond

// in the half-open wait a repeat of the answered IKE_INTERMEDIATE request from another address, a moved initiator's late repeat or a replay, that arrives among the fragments of the next request leaves them be
// a fragment of the request is dropped, the request whole is taken as a repeat, and the next request, a second IKE_INTERMEDIATE or IKE_AUTH, draws its answer once its last fragment arrives
func TestRepeatFromAnotherAddressKeepsTheNextRequest(t *testing.T) {
	for name, methods := range map[string][]uint16{"IKE_INTERMEDIATE": {ML_KEM_768, ML_KEM_1024}, "IKE_AUTH": {ML_KEM_768}} {
		// the number of the request's fragment repeated, zero for the request whole
		for number, repeat := range []string{"the request whole", "fragment 1", "fragment 2"} {
			t.Run(fmt.Sprintf("%s after %s", name, repeat), func(t *testing.T) {
				h := newResponderHarness(t, nil)
				entry, offer := entry768, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768))
				if len(methods) == 2 {
					entry, offer = entry768And1024, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024))
				}
				h.lists.Store(&Suites{kex: []kexEntry{entry}})
				s, refused := openScriptedWith(t, h, offer, []RawPayload{fragmentationSupported}, true)
				if s == nil {
					t.Fatalf("the responder refused the offer with notify %d", refused)
				}
				if number > 0 {
					s.cut = 500
				}
				s.intermediate(1, ML_KEM_768)
				answered, place := s.sent, s.moved()
				s.between = func() {
					time.Sleep(arrivalGap)
					if err := place.SendIKE(answered[max(number, 1)-1]); err != nil {
						t.Fatal(err)
					}
					time.Sleep(arrivalGap)
				}
				authMID := uint32(len(methods) + 1)
				if len(methods) == 2 {
					s.cut = 500
					s.intermediate(2, ML_KEM_1024)
					s.between = nil
				} else {
					s.cut = 100
				}
				if header, _ := s.authenticate(authMID, authMID); header.ExchangeType != IKE_AUTH || header.MessageID != authMID {
					t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at %d", header.ExchangeType, header.MessageID, authMID)
				}
				s.accepted(authMID, methods)
			})
		}
	}
}

// in the half-open wait the repeats of a request that the address the IKE SA was set up from sends draw the answer at most maxRetransmitsWhileBusy times in each exchange, the most sends this end makes of one request
// the repeat is the shortest fragment 1 that authenticates, which a request that came whole lets through, and the answer it draws is cut for the family's floor and no smaller
func TestHalfOpenAnswersAtMostMaxRetransmitsWhileBusyRepeatsOfEachExchange(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768And1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	methods := []uint16{ML_KEM_768, ML_KEM_1024}
	for i, method := range methods {
		mid := uint32(i + 1)
		key, answerKey := s.model.keys[1], s.model.keys[2]
		s.intermediate(mid, method)
		_, answer, _, _ := assembled(t, modelSuite, answerKey, s.got)
		shortest, err := sealedFragment(modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: mid}, nil, PayloadNone, 0, 1, 1, nil)
		if err != nil {
			t.Fatal(err)
		}
		for repeat := range maxRetransmitsWhileBusy + 1 {
			if err := s.mux.SendIKE(shortest); err != nil {
				t.Fatal(err)
			}
			if repeat == maxRetransmitsWhileBusy {
				if !s.silent() {
					t.Errorf("repeat %d at %d drew the answer, want at most %d", repeat+1, mid, maxRetransmitsWhileBusy)
				}
				continue
			}
			again := collect(t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
			wantFits(t, again, floorRoom)
			if _, inner, _, _ := assembled(t, modelSuite, answerKey, again); !samePayloads(inner, answer) {
				t.Fatalf("repeat %d at %d drew payload types %v, want the answer again", repeat+1, mid, payloadTypes(inner))
			}
		}
	}
	authMID := uint32(len(methods) + 1)
	if header, _ := s.authenticate(authMID, authMID); header.ExchangeType != IKE_AUTH || header.MessageID != authMID {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at %d", header.ExchangeType, header.MessageID, authMID)
	}
	s.accepted(authMID, methods)
}

// in the half-open wait of a responder whose initiator did not say it supports IKE fragmentation, all of the request in fragments from another address draws nothing however often it comes
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
func TestHalfOpenRepeatInFragmentsFromAnotherAddressIsDiscardedWithoutTheNotify(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScripted(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	key := s.model.keys[1]
	s.intermediate(1, ML_KEM_768)
	_, inner, _, _ := assembled(t, modelSuite, key, s.sent)
	place := s.moved()
	for range maxRetransmits {
		for _, raw := range cutInto(t, modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}, inner, 500) {
			if err := place.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
		}
	}
	if got := heard(place); len(got) != 0 {
		t.Errorf("all of the request in fragments from another address drew %d datagrams there", len(got))
	}
	if !s.silent() {
		t.Error("all of the request in fragments from another address drew an answer at the one the IKE SA was set up from")
	}
	if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
	}
	s.accepted(2, []uint16{ML_KEM_768})
}

// in the half-open wait a fragment of a repeat of the first IKE_INTERMEDIATE request from another address, left alone when the second request comes whole, keeps out no repeat of the second in fragments
// all of the second request in fragments from a place of its own draws the answer there
func TestRepeatLeftIncompleteKeepsOutNoRepeatOfTheNextExchange(t *testing.T) {
	h := newResponderHarness(t, nil)
	h.lists.Store(&Suites{kex: []kexEntry{entry768And1024}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768), addkeOf(TransADDKE1+1, ML_KEM_1024)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	s.cut = 500
	s.intermediate(1, ML_KEM_768)
	if err := s.moved().SendIKE(s.sent[0]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(arrivalGap)
	key, answerKey := s.model.keys[1], s.model.keys[2]
	s.cut = 0
	s.intermediate(2, ML_KEM_1024)
	_, inner, _, _ := assembled(t, modelSuite, key, s.sent)
	_, answer, _, _ := assembled(t, modelSuite, answerKey, s.got)
	place := s.moved()
	for _, raw := range cutInto(t, modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 2}, inner, 700) {
		if err := place.SendIKE(raw); err != nil {
			t.Fatal(err)
		}
	}
	again := collect(t, func() ([]byte, error) { return place.RecvIKEUntil(time.Now().Add(answerBudget)) })
	if _, got, _, _ := assembled(t, modelSuite, answerKey, again); !samePayloads(got, answer) {
		t.Errorf("all of the second request in fragments from another address drew payload types %v, want its answer", payloadTypes(got))
	}
	if header, _ := s.authenticate(3, 3); header.ExchangeType != IKE_AUTH || header.MessageID != 3 {
		t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 3", header.ExchangeType, header.MessageID)
	}
	s.accepted(3, []uint16{ML_KEM_768, ML_KEM_1024})
}

// after a request that came in fragments is answered, a repeat of its fragment 1 in more fragments draws the answer again, and one in fewer, or the request whole, draws nothing, in Run, in the wait after IKE_AUTH and in the half-open wait
// RFC 7383 section 2.6.1: "If an incoming message contains an Encrypted Fragment payload, the values of the Fragment Number and Total Fragments fields MUST be used along with the Message ID to detect retransmissions and replays."
// RFC 7383 section 2.5.2: "Since the sender starts from larger fragments and then makes them smaller, the value in the Total Fragments field increases with each new probe."
func TestRepeatIsReadAgainstTheTotalFragmentsOfTheAnsweredRequest(t *testing.T) {
	type repeat struct {
		name  string
		raw   []byte
		draws bool
	}
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			ctx := s.current
			request := peerRequest(t, s, 0, 1200, 500)
			for _, raw := range request {
				take(s, raw, s.mux.Endpoint())
			}
			answer := peerReads(t, peer, answerBudget)
			if len(answer) != 1 {
				t.Fatalf("the request in %d fragments drew %d datagrams, want its answer", len(request), len(answer))
			}
			whole, err := EncryptMessage(ctx.suite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL}, nil, []RawPayload{bulkyStatus(1200)})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range []repeat{
				{"in fewer fragments", peerRequest(t, s, 0, 1200, 700)[0], false},
				{"whole", whole, false},
				{"in more fragments", peerRequest(t, s, 0, 1200, 300)[0], true},
			} {
				take(s, r.raw, s.mux.Endpoint())
				if again := peerReads(t, peer, quietPeriod); r.draws != (len(again) == 1 && bytes.Equal(again[0], answer[0])) {
					t.Errorf("a repeat %s of a request in %d fragments drew %d datagrams, want the answer again %v", r.name, len(request), len(again), r.draws)
				}
			}
		})
	}
	t.Run("half-open wait", func(t *testing.T) {
		h := newResponderHarness(t, nil)
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		key, answerKey := s.model.keys[1], s.model.keys[2]
		header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
		s.cut = 500
		s.intermediate(1, ML_KEM_768)
		request := s.sent
		_, answer, _, _ := assembled(t, modelSuite, answerKey, s.got)
		_, inner, _, _ := assembled(t, modelSuite, key, request)
		whole, err := EncryptMessage(modelSuite, key, header, nil, inner)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []repeat{
			{"in fewer fragments", cutInto(t, modelSuite, key, header, inner, 700)[0], false},
			{"whole", whole, false},
			{"in more fragments", cutInto(t, modelSuite, key, header, inner, 300)[0], true},
		} {
			if err := s.mux.SendIKE(r.raw); err != nil {
				t.Fatal(err)
			}
			if !r.draws {
				if !s.silent() {
					t.Errorf("a repeat %s of a request in %d fragments drew an answer", r.name, len(request))
				}
				continue
			}
			again := collect(t, func() ([]byte, error) { return s.mux.RecvIKEUntil(time.Now().Add(answerBudget)) })
			if _, got, _, _ := assembled(t, modelSuite, answerKey, again); !samePayloads(got, answer) {
				t.Errorf("a repeat %s of a request in %d fragments drew payload types %v, want the answer again", r.name, len(request), payloadTypes(got))
			}
		}
		s.cut = 0
		if header, _ := s.authenticate(2, 2); header.ExchangeType != IKE_AUTH || header.MessageID != 2 {
			t.Fatalf("the responder answered exchange %d at Message ID %d, want IKE_AUTH at 2", header.ExchangeType, header.MessageID)
		}
		s.accepted(2, []uint16{ML_KEM_768})
	})
}

// in Run and in the wait after IKE_AUTH a repeat is answered as in the half-open wait, the session's endpoint standing for the origin
// a captured fragment 1 of a peer's request whose answer is over the IPv4 floor's room, replayed maxRetransmits+1 times from another address, draws nothing there or at the endpoint
// all of the request from a third address draws the answer there once the octets that address sent repeating it cover the answer's, so its first set draws nothing and its second the answer
// the third address's answer spends its own credit and nothing of the endpoint's count, so the endpoint's own repeats of fragment 1 then draw the answer maxRetransmitsWhileBusy times and the one after draws nothing, and a repeat in the next exchange draws that one's
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
// RFC 7383 section 2.6.1: "that event MUST only trigger a retransmission of the response message (fragmented or not) if the Fragment Number field in the received fragment is set to 1"
func TestRepeatPastIKEAuthIsAnsweredAsInTheHalfOpenWait(t *testing.T) {
	for name, take := range takers {
		t.Run(name, func(t *testing.T) {
			s, peer, hub := fragmentingSessionAt(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			replayed, replayedAt := observedPeerFrom(t, hub, 0x7172737475767778, net.IPv4(127, 0, 0, 1))
			moved, movedAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			// keep answers the peer's request at mid, a status of 1200 octets in fragments of 500 octets of plaintext, with a status of 1500, which the IPv4 floor cuts into four
			keep := func(mid uint32) ([][]byte, [][]byte) {
				t.Helper()
				request := peerRequest(t, s, mid, 1200, 500)
				response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, []RawPayload{bulkyStatus(1500)})
				if err != nil {
					t.Fatal(err)
				}
				sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, request))
				if err != nil {
					t.Fatal(err)
				}
				return request, slices.Clone(sent.datagrams)
			}
			// took reads the datagrams each of the three addresses took, the endpoint, the replaying one and the third, waiting for the answer at the one that draws it
			took := func(draws *net.UDPConn) [3][][]byte {
				t.Helper()
				var got [3][][]byte
				for i, place := range []*net.UDPConn{peer, replayedAt, movedAt} {
					wait := quietPeriod
					if place == draws {
						wait = answerBudget
					}
					got[i] = peerReads(t, place, wait)
				}
				return got
			}
			request, answer := keep(ctx.nextPeerMID)
			if len(answer) < 2 || octetsOf(answer) <= octetsOf(request) {
				t.Fatalf("the answer went in %d datagrams of %d octets, want it cut and larger than the request's %d", len(answer), octetsOf(answer), octetsOf(request))
			}
			for range maxRetransmits + 1 {
				take(s, request[0], replayed)
			}
			if got := took(nil); len(got[0]) != 0 || len(got[1]) != 0 {
				t.Errorf("fragment 1 replayed from another address drew %d datagrams at the endpoint and %d there, want none", len(got[0]), len(got[1]))
			}
			for set := range 2 {
				for _, raw := range request {
					take(s, raw, moved)
				}
				draws := set == 1
				var at *net.UDPConn
				if draws {
					at = movedAt
				}
				if got := took(at); len(got[0]) != 0 || len(got[1]) != 0 || draws != slices.EqualFunc(got[2], answer, bytes.Equal) || !draws && len(got[2]) != 0 {
					t.Errorf("set %d of the request from a third address, %d octets each, drew %d datagrams of %d octets there and %d elsewhere, want the answer of %d octets there %v", set+1, octetsOf(request), len(got[2]), octetsOf(got[2]), len(got[0])+len(got[1]), octetsOf(answer), draws)
				}
			}
			for repeat := 1; repeat <= maxRetransmitsWhileBusy; repeat++ {
				take(s, request[0], s.mux.Endpoint())
				if got := peerTakes(t, peer, len(answer)); !slices.EqualFunc(got, answer, bytes.Equal) {
					t.Fatalf("the endpoint's repeat %d of fragment 1 drew %d datagrams, want the answer", repeat, len(got))
				}
			}
			take(s, request[0], s.mux.Endpoint())
			if got := took(nil); len(got[0])+len(got[1])+len(got[2]) != 0 {
				t.Errorf("the endpoint's repeat %d of fragment 1 drew %d datagrams there and %d elsewhere, want none", maxRetransmitsWhileBusy+1, len(got[0]), len(got[1])+len(got[2]))
			}
			next, answer := keep(ctx.nextPeerMID)
			take(s, next[0], s.mux.Endpoint())
			if got := took(peer); !slices.EqualFunc(got[0], answer, bytes.Equal) {
				t.Errorf("the endpoint's repeat of fragment 1 in the next exchange drew %d datagrams, want its answer", len(got[0]))
			}
		})
	}
}

// at each site that resends a kept answer, a repeat whose answer cannot go to the address it came from ends nothing, and the endpoint's next repeat draws the answer
// the request whole from an arrival address that went away draws the answer there, since its octets cover the answer's, and that send fails
func TestRepeatWhoseAnswerCannotGoEndsNothing(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			ctx := s.current
			unreachable := unsendableMux(t).Endpoint()
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(200)})
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			// the answer spent the credit the repeat made, so it was drawn
			ended := take(s, request, unreachable)
			if others := ctx.lastPeer.others; ended || s.mux.IsClosed() || len(others) != 1 || others[0].octets >= onWire(unreachable, 1, len(request)) {
				t.Fatalf("a repeat whose answer could not go ended the IKE SA %v and its mux %v, with the credits %+v, want neither and the answer drawn from the one credit", ended, s.mux.IsClosed(), others)
			}
			take(s, request, s.mux.Endpoint())
			if got := peerReads(t, peer, answerBudget); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
				t.Errorf("the endpoint's repeat after one whose answer could not go drew %d datagrams, want the answer's %d", len(got), len(sent.datagrams))
			}
		})
	}
}

// at each site that resends a kept answer, maxRetransmitsWhileBusy replays of the request whole from another address each draw the answer there, its octets covering the answer's
// they spend that address's credit and nothing of the endpoint's count, so the endpoint's own repeats then draw the answer maxRetransmitsWhileBusy times, and the one after draws nothing
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
func TestReplaysFromAnotherAddressSpendNothingOfTheEndpointsAnswers(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer, hub := fragmentingSessionAt(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			replayer, replayerAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(300)})
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			for replay := 1; replay <= maxRetransmitsWhileBusy; replay++ {
				take(s, request, replayer)
				if got := peerTakes(t, replayerAt, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Fatalf("replay %d from another address drew %d datagrams there, want the answer", replay, len(got))
				}
			}
			for repeat := 1; repeat <= maxRetransmitsWhileBusy; repeat++ {
				take(s, request, s.mux.Endpoint())
				if got := peerTakes(t, peer, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Fatalf("the endpoint's repeat %d after %d replays answered elsewhere drew %d datagrams, want the answer", repeat, maxRetransmitsWhileBusy, len(got))
				}
			}
			take(s, request, s.mux.Endpoint())
			if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
				t.Errorf("the endpoint's repeat %d drew %d datagrams, want none", maxRetransmitsWhileBusy+1, len(got))
			}
		})
	}
}

// at each site that resends a kept answer, once the endpoint's repeats have drawn maxRetransmitsWhileBusy answers, the request whole repeated from another address still draws the answer there, its octets covering the answer's
// the endpoint's count holds no other address, so replays in the endpoint's own address and port cannot hold a peer that moved
// RFC 7296 section 2.11: "MUST respond to the address and port from which the request was received."
func TestRepeatFromAnotherAddressIsAnsweredOnceTheEndpointsAnswersAreSpent(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer, hub := fragmentingSessionAt(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			moved, movedAt := observedPeerFrom(t, hub, 0x8182838485868788, net.IPv4(127, 0, 0, 1))
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(300)})
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			for repeat := 1; repeat <= maxRetransmitsWhileBusy; repeat++ {
				take(s, request, s.mux.Endpoint())
				if got := peerTakes(t, peer, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Fatalf("the endpoint's repeat %d drew %d datagrams, want the answer", repeat, len(got))
				}
			}
			take(s, request, s.mux.Endpoint())
			if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
				t.Fatalf("the endpoint's repeat %d drew %d datagrams, want none", maxRetransmitsWhileBusy+1, len(got))
			}
			take(s, request, moved)
			if got := peerTakes(t, movedAt, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
				t.Errorf("the request repeated from another address after the endpoint's %d answers drew %d datagrams there, want the answer", maxRetransmitsWhileBusy, len(got))
			}
		})
	}
}

// at each site that resends a kept answer, after a request that came whole, fragment 1 of Total Fragments 0 under the answered key, from the endpoint, draws nothing
// fragment 1 of Total Fragments 1 under the same key draws the answer, so the first is discarded for its Total Fragments alone
// RFC 7383 section 2.6: "check that the Fragment Number and the Total Fragments fields contain non-zero values"
// RFC 7383 section 2.6: "If any of these tests fail, the message MUST be silently discarded."
func TestFragmentOneOfTotalZeroOfAnAnsweredRequestDrawsNothing(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(300)})
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			for _, total := range []uint16{0, 1} {
				raw, err := sealedFragment(ctx.suite, ctx.peerEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}, nil, PayloadNone, 0, 1, total, nil)
				if err != nil {
					t.Fatal(err)
				}
				take(s, raw, s.mux.Endpoint())
				if total == 0 {
					if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
						t.Errorf("fragment 1 of Total Fragments 0 drew %d datagrams, want none", len(got))
					}
					continue
				}
				if got := peerTakes(t, peer, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Errorf("fragment 1 of Total Fragments 1 drew %d datagrams, want the answer", len(got))
				}
			}
		})
	}
}

// at each site that resends a kept answer, after a request that came whole, Fragment Number 0 of Total Fragments 1 under the answered key, from the endpoint, draws nothing
// fragment 1 of Total Fragments 1 under the same key draws the answer, so the first is discarded for its Fragment Number alone
// RFC 7383 section 2.6: "check that the Fragment Number and the Total Fragments fields contain non-zero values"
// RFC 7383 section 2.6: "If any of these tests fail, the message MUST be silently discarded."
func TestFragmentNumberZeroOfAnAnsweredRequestDrawsNothing(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(300)})
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			for _, number := range []uint16{0, 1} {
				raw, err := sealedFragment(ctx.suite, ctx.peerEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, MessageID: mid}, nil, PayloadNone, 0, number, 1, nil)
				if err != nil {
					t.Fatal(err)
				}
				take(s, raw, s.mux.Endpoint())
				if number == 0 {
					if got := peerReads(t, peer, quietPeriod); len(got) != 0 {
						t.Errorf("Fragment Number 0 of Total Fragments 1 drew %d datagrams, want none", len(got))
					}
					continue
				}
				if got := peerTakes(t, peer, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Errorf("fragment 1 of Total Fragments 1 drew %d datagrams, want the answer", len(got))
				}
			}
		})
	}
}

// the backoff sends a request that its step cuts for its family's floor stepDownSends+maxRetransmits times on a path that holds
// so at each site that resends a kept answer, each of the endpoint's repeats of it past the send that drew the answer draws the answer: the request whole as it came, then fragment 1 of a cut into fragments, as the step makes
func TestEveryRepeatOfARequestThatStepsDrawsTheAnswer(t *testing.T) {
	for name, take := range repeatSites() {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			s.pathMTU = noPathMTU
			ctx := s.current
			mid := ctx.nextPeerMID
			request := peerRequestWhole(t, s, mid, []RawPayload{bulkyStatus(1200)})
			stepped := peerRequest(t, s, mid, 1200, 500)
			response, err := ctx.seal(ctx.localEncryptionKey(), Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR, ExchangeType: INFORMATIONAL, Flags: FlagInitiator | FlagResponse, MessageID: mid}, nil)
			if err != nil {
				t.Fatal(err)
			}
			sent, err := s.keepAnswer(ctx, mid, response, openedOf(t, s, [][]byte{request}))
			if err != nil {
				t.Fatal(err)
			}
			repeats := append([][]byte{request}, slices.Repeat([][]byte{stepped[0]}, stepDownSends+maxRetransmits-2)...)
			for i, raw := range repeats {
				take(s, raw, s.mux.Endpoint())
				if got := peerTakes(t, peer, len(sent.datagrams)); !slices.EqualFunc(got, sent.datagrams, bytes.Equal) {
					t.Fatalf("repeat %d of %d from the endpoint drew %d datagrams, want the answer", i+1, len(repeats), len(got))
				}
			}
		})
	}
}

// fragments from a peer whose IKE_SA_INIT did not say it supports IKE fragmentation are discarded before the queue holds anything of them, and the same fragments from a peer that said so are answered
// RFC 7383 section 2.4: "IKE fragmentation MUST NOT be used unless both peers have indicated their support for it."
func TestFragmentsFromAPeerThatDidNotNegotiateThemAreDiscarded(t *testing.T) {
	for name, negotiated := range map[string]bool{"negotiated": true, "not negotiated": false} {
		t.Run(name, func(t *testing.T) {
			s, peer := fragmentingSession(t, &recorder{})
			s.fragments = negotiated
			var pending *pendingRequest
			for i, raw := range peerRequest(t, s, 0, 1200, 500) {
				s.dispatch(raw, s.mux.Endpoint(), &pending)
				if i == 0 && (s.current.requestFragments.chunks != nil) != negotiated {
					t.Errorf("the queue holds fragment 1 %v, want %v", s.current.requestFragments.chunks != nil, negotiated)
				}
			}
			if answered := len(peerReads(t, peer, quietPeriod)) > 0; answered != negotiated {
				t.Errorf("the request in fragments drew an answer %v, want %v", answered, negotiated)
			}
		})
	}
}

// the fragments of one message a peer sends past reassemblyLimit octets of datagrams end the IKE SA in Run, a retained IKE SA alone, the wait after IKE_AUTH, the half-open SA in the handshake, a request or a repeat of it from another address, and the dial
// RFC 7383 section 5: "it is RECOMMENDED that the receiver limit the number of fragments it stores in the reassembling queue so that the sum of the sizes of Encrypted Fragment payload contents (after decryption) for fragments that are already placed into the reassembling queue is less than some value that is reasonable for the implementation."
// RFC 7383 section 5: "In either case, the receiver SHOULD drop the connection and discard all the received fragments."
func TestFragmentsPastTheLimitEndTheSA(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		events := &recorder{}
		s, _ := fragmentingSession(t, events)
		var pending *pendingRequest
		for _, raw := range peerRequest(t, s, 0, reassemblyLimit, 4000) {
			s.dispatch(raw, s.mux.Endpoint(), &pending)
		}
		if closed := events.recorded(); !s.mux.IsClosed() || len(closed) != 1 || !strings.HasPrefix(closed[0], "ike.sa.closed ") || !strings.Contains(closed[0], "reason=fragment limit") {
			t.Errorf("fragments past the limit left the IKE SA open %v and recorded %q, want it closed for the fragment limit", !s.mux.IsClosed(), closed)
		}
	})
	// RFC 7296 section 2.8: "An IKE SA so created inherits all of the original IKE SA's Child SAs", so the retained IKE SA holds none and goes alone
	t.Run("Run on a retained IKE SA", func(t *testing.T) {
		events := &recorder{}
		s, _ := fragmentingSession(t, events)
		current := s.current
		old := testContext()
		old.spiI, old.spiR = 0x2122232425262728, 0x3132333435363738
		s.old = old
		if err := s.mux.RegisterIKE(old.spiI); err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		for _, raw := range cutInto(t, old.suite, old.sker, Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, ExchangeType: INFORMATIONAL}, []RawPayload{bulkyStatus(reassemblyLimit)}, 4000) {
			s.dispatch(raw, s.mux.Endpoint(), &pending)
		}
		if now, retained := s.contexts(); s.mux.IsClosed() || now != current || retained != nil || len(events.recorded()) != 0 {
			t.Errorf("fragments past the limit on the retained IKE SA closed the session %v, left current %p and retained %p, and recorded %q, want the retained IKE SA gone alone", s.mux.IsClosed(), now, retained, events.recorded())
		}
	})
	t.Run("wait after IKE_AUTH", func(t *testing.T) {
		s, _ := fragmentingSession(t, &recorder{})
		ends := slices.ContainsFunc(peerRequest(t, s, 0, reassemblyLimit, 4000), func(raw []byte) bool { return s.answerAfterAuth(s.current, raw, s.mux.Endpoint()) })
		if !ends {
			t.Error("fragments past the limit left the wait after IKE_AUTH going")
		}
	})
	t.Run("half-open wait", func(t *testing.T) {
		answered := &recorder{}
		h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.HandshakeTimeout = 4 * answerBudget }, answered.record)
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		s.cut = 4000
		s.send(IKE_INTERMEDIATE, 1, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, make([]byte, reassemblyLimit))}})
		for deadline := time.Now().Add(answerBudget); recordedKind(answered, "ike.handshake.failed") == 0; time.Sleep(recordPoll) {
			if time.Now().After(deadline) {
				t.Fatalf("the half-open SA outlived fragments past the limit, recording only %q", answered.recorded())
			}
		}
	})
	t.Run("half-open wait, a repeat from another address", func(t *testing.T) {
		answered := &recorder{}
		h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.HandshakeTimeout = 4 * answerBudget }, answered.record)
		h.lists.Store(&Suites{kex: []kexEntry{entry768}})
		s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
		if s == nil {
			t.Fatalf("the responder refused the offer with notify %d", refused)
		}
		key := s.model.keys[1]
		s.intermediate(1, ML_KEM_768)
		place := s.moved()
		for _, raw := range cutInto(t, modelSuite, key, Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}, []RawPayload{bulkyStatus(reassemblyLimit)}, 4000) {
			if err := place.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
		}
		for deadline := time.Now().Add(answerBudget); recordedKind(answered, "ike.handshake.failed") == 0; time.Sleep(recordPoll) {
			if time.Now().After(deadline) {
				t.Fatalf("the half-open SA outlived a repeat's fragments past the limit, recording only %q", answered.recorded())
			}
		}
	})
	t.Run("dial", func(t *testing.T) {
		p := dialPlayed(t, Suites{kex: []kexEntry{entry768}}, nil)
		p.fragments, p.cut = true, 4000
		p.answerSAInit(1, slices.Concat(modelBase, addkeOf(TransADDKE1, ML_KEM_768)), true)
		p.answerIntermediate(1, ML_KEM_768, func(ciphertext []byte) []RawPayload {
			return []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, ciphertext)}, {Type: PayloadType(200), Body: make([]byte, reassemblyLimit)}}
		})
		if _, err := p.ended(); !errors.Is(err, errFragmentLimit) {
			t.Errorf("the dial ended with %v, want the limit's", err)
		}
	})
}

// reassemblyLimit is under 64 KB and holds the fragments of the largest message a peer sends, its ML-KEM-1024 IKE_INTERMEDIATE request, cut for an IPv4 path of 576 octets
// RFC 7383 section 5: "It is NOT RECOMMENDED for this value to exceed 64 KB because any IKE message before fragmentation would likely be shorter than that."
func TestReassemblyLimitHoldsTheLargestMessageAtTheIPv4Floor(t *testing.T) {
	if reassemblyLimit > 64<<10 {
		t.Errorf("the reassembly limit is %d octets, past 64 KB", reassemblyLimit)
	}
	ctx := &ikeContext{suite: modelSuite}
	message, err := ctx.seal(make([]byte, modelKeyLen), Header{ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_1024, make([]byte, kemSizes[ML_KEM_1024][0]))}})
	if err != nil {
		t.Fatal(err)
	}
	datagrams, err := message.fragments(message.capacity(floorRoom))
	if err != nil {
		t.Fatal(err)
	}
	held := 0
	for _, raw := range datagrams {
		held += len(raw)
	}
	if held >= reassemblyLimit {
		t.Errorf("the ML-KEM-1024 request takes %d octets in %d fragments at the IPv4 floor, past the limit of %d", held, len(datagrams), reassemblyLimit)
	}
}

// a half-open SA's queue holds at most reassemblyLimit octets of datagrams, so at most that over the shortest IKE Fragment message's datagram, and goes with the SA at handshakeTimeout, before reassemblyTimeout
// halfOpenLimit of them hold a bounded amount whatever initiators send
func TestHalfOpenSAsHoldABoundedReassemblyQueueEach(t *testing.T) {
	if handshakeTimeout >= reassemblyTimeout {
		t.Errorf("a half-open SA lasts %s, not within the reassembly timeout of %s", handshakeTimeout, reassemblyTimeout)
	}
	header := Header{SPIInitiator: 1, SPIResponder: 2, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
	shortest := math.MaxInt
	for _, cipher := range (Suites{}).ikeCiphers() {
		suite := SASuite{EncrID: cipher.ID, EncrKeyBits: cipher.KeyLengthBits}
		params, err := aeadParams(suite.EncrID, suite.EncrKeyBits)
		if err != nil {
			t.Fatal(err)
		}
		key := make([]byte, params.KeyLen+params.SaltLen)
		var q reassembly
		for number := 1; ; number++ {
			raw, err := sealedFragment(suite, key, header, nil, PayloadNone, 0, uint16(number), math.MaxUint16, nil)
			if err != nil {
				t.Fatal(err)
			}
			shortest = min(shortest, len(raw))
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := q.take(suite, key, raw, m, time.Now()); err != nil {
				break
			}
			if number*len(raw) > reassemblyLimit {
				t.Fatalf("the queue under cipher %d holds %d empty fragments of %d octets each, past the limit of %d", cipher.ID, number, len(raw), reassemblyLimit)
			}
		}
	}
	const ceiling = 8 << 20
	if bound := halfOpenLimit * reassemblyLimit; bound > ceiling {
		t.Errorf("%d half-open SAs hold up to %d octets of fragments in up to %d fragments each, past %d", halfOpenLimit, bound, reassemblyLimit/shortest, ceiling)
	}
}

// halfOpenWait is the handshake timeout of a responder whose half-open SA holds a fragment, far short of reassemblyTimeout
const halfOpenWait = time.Second

// a half-open SA holding fragment 1 of an IKE_INTERMEDIATE request whose other fragments never come ends at its handshake timeout, and its queue with it, where reassemblyTimeout would hold the fragment on
func TestHalfOpenSAHoldingAFragmentEndsAtItsHandshakeTimeout(t *testing.T) {
	answered := &recorder{}
	h := newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil, func(cfg *ResponderConfig) { cfg.HandshakeTimeout = halfOpenWait }, answered.record)
	h.lists.Store(&Suites{kex: []kexEntry{entry768}})
	s, refused := openScriptedWith(t, h, ikeOffer(addkeOf(TransADDKE1, ML_KEM_768)), []RawPayload{fragmentationSupported}, true)
	if s == nil {
		t.Fatalf("the responder refused the offer with notify %d", refused)
	}
	_, key := modelKEM(t, ML_KEM_768)
	header := Header{SPIInitiator: s.spiI, SPIResponder: s.spiR, ExchangeType: IKE_INTERMEDIATE, Flags: FlagInitiator, MessageID: 1}
	request := cutInto(t, modelSuite, s.model.keys[1], header, []RawPayload{{Type: PayloadKE, Body: EncodeKE(ML_KEM_768, key)}}, 500)
	if err := s.mux.SendIKE(request[0]); err != nil {
		t.Fatal(err)
	}
	for sent := time.Now(); recordedKind(answered, "ike.handshake.failed") == 0; time.Sleep(recordPoll) {
		if time.Since(sent) > halfOpenWait+answerBudget {
			t.Fatalf("the half-open SA holding fragment 1 of %d outlived its handshake timeout of %s by %s, recording only %q", len(request), halfOpenWait, answerBudget, answered.recorded())
		}
	}
}
