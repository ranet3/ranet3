// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/transport"
)

type payloadExchange struct {
	initiator, responder                   identity.Identity
	idi, idr, initiatorAuth, responderAuth string
	otherLocal                             []identity.Identity
	requestIDr                             string
}

var (
	goldenSuite        = SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	goldenInitiatorKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	goldenResponderKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	goldenMessage1     = []byte("the IKE_SA_INIT request")
	goldenMessage2     = []byte("the IKE_SA_INIT response")
	goldenNi           = bytes.Repeat([]byte{0x33}, 32)
	goldenNr           = bytes.Repeat([]byte{0x44}, 32)
)

func goldenContext(responder bool) *ikeContext {
	return &ikeContext{suite: goldenSuite, spiI: 0x0102030405060708, spiR: 0x1112131415161718, responder: responder,
		skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20),
		skpi: bytes.Repeat([]byte{4}, 32), skpr: bytes.Repeat([]byte{5}, 32)}
}

// each end sends the IDi, IDr and AUTH bytes ranet and strongSwan verify, and takes the other end's
func TestIdentityAndAuthPayloadsKeepTheirBytes(t *testing.T) {
	client := identity.MustParse("testorg/client:2")
	for name, x := range map[string]payloadExchange{
		"the strongSwan check's names": {
			initiator:     client,
			responder:     identity.MustParse("testorg/server:1"),
			idi:           "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr:           "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06736572766572310a30080603550405130131",
			initiatorAuth: "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth: "0e00000007300506032b65705388c14fc14cb7690686c75cb527eb6ff751f2fc31ae65d8353c5c8e1019a480ddf7c691fa8b9c72de293739a8d87694a41fab2b4a4e3db094544454be14640b",
		},
		"a non-ASCII organization with a 130 octet common name": {
			initiator: client,
			responder: identity.MustParse("r%C3%A9seau/" + strings.Repeat("node", 32) + "-1:13001"),
			idi:       "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr: "090000003081b23110300e060355040a0c0772c3a97365617531818d30818a06035504030c8182" +
				strings.Repeat("6e6f6465", 32) + "2d31310e300c060355040513053133303031",
			initiatorAuth: "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth: "0e00000007300506032b65702d26b1c575218e3bbdec04977abc1c39bf2cf44a7a23e528ac134a09c79ce0896c4a7318a76cd37e38ba59845dbe1b75216408beeeb4bdbb5b26719d2fb4020b",
		},
		// strongSwan writes O and CN as PrintableString when the value allows it
		"IDr in PrintableString naming one of two local endpoints": {
			initiator:     client,
			responder:     identity.MustParse("testorg/server:1"),
			otherLocal:    []identity.Identity{identity.MustParse("testorg/server:2")},
			requestIDr:    "09000000302f3110300e060355040a1307746573746f7267310f300d06035504031306736572766572310a30080603550405130131",
			idi:           "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr:           "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06736572766572310a30080603550405130131",
			initiatorAuth: "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth: "0e00000007300506032b65705388c14fc14cb7690686c75cb527eb6ff751f2fc31ae65d8353c5c8e1019a480ddf7c691fa8b9c72de293739a8d87694a41fab2b4a4e3db094544454be14640b",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("initiator", func(t *testing.T) { checkInitiatorPayloads(t, x) })
			t.Run("responder", func(t *testing.T) { checkResponderPayloads(t, x) })
		})
	}
}

// the responder here is scripted with x's responder bytes
func checkInitiatorPayloads(t *testing.T, x payloadExchange) {
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	ctx := goldenContext(false)
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1)}
	cfg := PeerConfig{
		Local:           x.initiator,
		LocalPrivateKey: goldenInitiatorKey,
		Remote:          x.responder,
		RemotePublicKey: goldenResponderKey.Public().(ed25519.PublicKey),
	}
	sent := make(chan []RawPayload, 1)
	peerLoop(t, peer, func() {
		defer close(sent)
		buf := make([]byte, 4096)
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		n, from, err := peer.ReadFromUDP(buf)
		if err != nil || n <= 4 {
			return
		}
		raw := bytes.Clone(buf[4:n])
		request, err := DecodeMessage(raw)
		if err != nil {
			return
		}
		inner, err := DecryptMessage(goldenSuite, ctx.skei, raw, request)
		if err != nil {
			return
		}
		sent <- inner
		answer := Proposal{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}
		response, err := EncryptMessage(goldenSuite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR,
			ExchangeType: IKE_AUTH, Flags: FlagResponse, MessageID: 1}, nil, []RawPayload{
			{Type: PayloadIDr, Body: goldenBytes(x.idr)},
			{Type: PayloadAUTH, Body: goldenBytes(x.responderAuth)},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{answer})},
			{Type: PayloadTSi, Body: fullRangeSelectors()},
			{Type: PayloadTSr, Body: fullRangeSelectors()},
		})
		if err != nil {
			return
		}
		_, _ = peer.WriteToUDP(withNonESPMarker(response), from)
	})
	authErr := s.completeIKEAuth(cfg, goldenMessage1, goldenMessage2, goldenNi, goldenNr)
	inner := <-sent
	if inner == nil {
		t.Fatal("the initiator sent no IKE_AUTH request the responder could read")
	}
	samePayload(t, "IDi", findType(inner, PayloadIDi), x.idi)
	samePayload(t, "IDr", findType(inner, PayloadIDr), x.idr)
	samePayload(t, "AUTH", findType(inner, PayloadAUTH), x.initiatorAuth)
	if authErr != nil {
		t.Fatalf("the initiator refused the responder's IDr and AUTH: %v", authErr)
	}
}

// the initiator here is scripted with x's initiator bytes
func checkResponderPayloads(t *testing.T, x payloadExchange) {
	hub, initiatorHub := listenHub(t), listenHub(t)
	r, err := NewResponder(ResponderConfig{
		Hub:             hub,
		Local:           append(x.otherLocal, x.responder),
		LocalPrivateKey: goldenResponderKey,
		Trust: trustFunc(func(id identity.Identity) (ed25519.PublicKey, error) {
			if id != x.initiator {
				return nil, errUntrusted
			}
			return goldenInitiatorKey.Public().(ed25519.PublicKey), nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), initiatorHub.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	peer, err := initiatorHub.NewMux(net.IPv4(127, 0, 0, 1), hub.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	requestIDr := x.idr
	if x.requestIDr != "" {
		requestIDr = x.requestIDr
	}
	ctx := goldenContext(true)
	s := &Session{mux: mux, current: ctx}
	if err := mux.RegisterIKE(ctx.spiI); err != nil {
		t.Fatal(err)
	}
	if err := peer.RegisterIKE(ctx.spiI); err != nil {
		t.Fatal(err)
	}
	request, err := EncryptMessage(goldenSuite, ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR,
		ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}, nil, []RawPayload{
		{Type: PayloadIDi, Body: goldenBytes(x.idi)},
		{Type: PayloadIDr, Body: goldenBytes(requestIDr)},
		{Type: PayloadAUTH, Body: goldenBytes(x.initiatorAuth)},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal([]byte{0, 0, 0, 9})})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	accepted, authErr := s.completeResponderAuth(r, goldenMessage1, goldenMessage2, goldenNi, goldenNr, time.Now().Add(answerBudget))
	raw, err := peer.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("the responder sent no answer: %v", err)
	}
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(goldenSuite, ctx.sker, raw, message)
	if err != nil {
		t.Fatal(err)
	}
	samePayload(t, "IDr", findType(inner, PayloadIDr), x.idr)
	samePayload(t, "AUTH", findType(inner, PayloadAUTH), x.responderAuth)
	if authErr != nil {
		t.Fatalf("the responder refused the initiator's IDi and AUTH: %v", authErr)
	}
	if accepted.Peer != x.initiator || accepted.Local != x.responder {
		t.Fatalf("the responder accepted %s at %s, want %s at %s", accepted.Peer, accepted.Local, x.initiator, x.responder)
	}
}

func goldenBytes(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}

func samePayload(t *testing.T, what string, got *RawPayload, want string) {
	t.Helper()
	if got == nil {
		t.Errorf("no %s was sent", what)
		return
	}
	if hex.EncodeToString(got.Body) != want {
		t.Errorf("%s is %x, want %s", what, got.Body, want)
	}
}
