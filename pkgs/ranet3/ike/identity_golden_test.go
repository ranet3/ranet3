// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
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
	// initiatorAliases and responderAliases are each end's auth.aliases
	initiatorAliases, responderAliases Aliases
	// noIDr has the initiator send no IDr, as it does where its aliases name the responder by several IDs
	// the scripted one then sends requestIDr or none
	noIDr bool
	// initiatorResolved and responderResolved are the attributes of the ike.id.resolved each end records
	initiatorResolved, responderResolved string
	// over is the loopback address of the family the exchange runs in, 127.0.0.1 where nil
	over net.IP
	// families gives a responder endpoint a family, each one it leaves out in the family of over
	families map[identity.Identity]Family
	// initiatorFamily is the family the trust gives the initiator's endpoint, where zero the family of over
	initiatorFamily Family
	// childOffer is the Child SA the scripted initiator offers, where nil the ESP proposal ranet3 sends
	childOffer []Proposal
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
	return &ikeContext{suite: goldenSuite, spiI: 0x0102030405060708, spiR: 0x1112131415161718, responder: responder, authMID: 1,
		skD: bytes.Repeat([]byte{1}, 32), skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20),
		skpi: bytes.Repeat([]byte{4}, 32), skpr: bytes.Repeat([]byte{5}, 32)}
}

// each end sends the IDi, IDr and AUTH bytes ranet and strongSwan verify for a DN, and takes the other end's
// an end with an alias toward the other presents it in place of its DN
// the initiator asks in IDr for the one ID its aliases name the responder by
func TestIdentityAndAuthPayloadsKeepTheirBytes(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	text := func(s string) string { return hex.EncodeToString([]byte(s)) }
	for name, x := range map[string]payloadExchange{
		"the strongSwan check's names": {
			initiator:         client,
			responder:         server,
			idi:               "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr:               "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06736572766572310a30080603550405130131",
			initiatorAuth:     "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth:     "0e00000007300506032b65705388c14fc14cb7690686c75cb527eb6ff751f2fc31ae65d8353c5c8e1019a480ddf7c691fa8b9c72de293739a8d87694a41fab2b4a4e3db094544454be14640b",
			initiatorResolved: "type=dn sent=dn",
			responderResolved: "type=dn sent=dn",
		},
		"a non-ASCII organization with a 130 octet common name": {
			initiator: client,
			responder: identity.MustParse("r%C3%A9seau/" + strings.Repeat("node", 32) + "-1:13001"),
			idi:       "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr: "090000003081b23110300e060355040a0c0772c3a97365617531818d30818a06035504030c8182" +
				strings.Repeat("6e6f6465", 32) + "2d31310e300c060355040513053133303031",
			initiatorAuth:     "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth:     "0e00000007300506032b65702d26b1c575218e3bbdec04977abc1c39bf2cf44a7a23e528ac134a09c79ce0896c4a7318a76cd37e38ba59845dbe1b75216408beeeb4bdbb5b26719d2fb4020b",
			initiatorResolved: "type=dn sent=dn",
			responderResolved: "type=dn sent=dn",
		},
		// strongSwan writes O and CN as PrintableString when the value allows it
		"IDr in PrintableString naming one of two local endpoints": {
			initiator:         client,
			responder:         server,
			otherLocal:        []identity.Identity{identity.MustParse("testorg/server:2")},
			requestIDr:        "09000000302f3110300e060355040a1307746573746f7267310f300d06035504031306736572766572310a30080603550405130131",
			idi:               "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06636c69656e74310a30080603550405130132",
			idr:               "09000000302f3110300e060355040a0c07746573746f7267310f300d06035504030c06736572766572310a30080603550405130131",
			initiatorAuth:     "0e00000007300506032b6570414fe458e1f05bcd413a5f8d44612a1ce4bc89e8ca64e1aa27ae262e88deebd288e862bf1447095e4640f06cb1848fbe19be0f382129705cd45c402423c3c106",
			responderAuth:     "0e00000007300506032b65705388c14fc14cb7690686c75cb527eb6ff751f2fc31ae65d8353c5c8e1019a480ddf7c691fa8b9c72de293739a8d87694a41fab2b4a4e3db094544454be14640b",
			initiatorResolved: "type=dn sent=dn",
			responderResolved: "type=dn sent=dn",
		},
		"an IPv4 address each way": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{IP: map[string]identity.Identity{"192.0.2.1": server}},
				Local:  map[string]LocalAlias{"testorg/server:1": {IP: "192.0.2.2"}},
			},
			responderAliases: Aliases{
				Remote: RemoteAliases{IP: map[string]identity.Identity{"192.0.2.2": client}},
				Local:  map[string]LocalAlias{"testorg/client:2": {IP: "192.0.2.1"}},
			},
			idi:               "01000000c0000202",
			idr:               "01000000c0000201",
			initiatorAuth:     "0e00000007300506032b6570a005d15ad83366cec7f115ee04346a8f24e0fa2ea2c8bf92415102c938714f646ebc5372778faa168c3c36e5b9a753718b3158096f27b4b08befa30e4c9b4606",
			responderAuth:     "0e00000007300506032b65702ca3d858f4a4ca955b95eb0460fbf33cd49a4c034b0a65f4e283a72062d4c0c45f1e6991b9c6594042a592b4f595172420e21fd4cd6135c10a47c5af1a4d620a",
			initiatorResolved: "type=ipv4 id=192.0.2.1 sent=ipv4",
			responderResolved: "type=ipv4 id=192.0.2.2 sent=ipv4",
		},
		// an entry for the node serves each of its endpoints
		"an IPv6 address each way": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{IP: map[string]identity.Identity{"2001:db8::1": server}},
				Local:  map[string]LocalAlias{"testorg/server": {IP: "2001:db8::2"}},
			},
			responderAliases: Aliases{
				Remote: RemoteAliases{IP: map[string]identity.Identity{"2001:db8::2": client}},
				Local:  map[string]LocalAlias{"testorg/client": {IP: "2001:db8::1"}},
			},
			idi:               "0500000020010db8000000000000000000000002",
			idr:               "0500000020010db8000000000000000000000001",
			initiatorAuth:     "0e00000007300506032b6570594a29c53ba51f32ab00bf705ced172f6c46e7fd6940189997fb8b253f081ad13788cc69dcbde846c4c934fa80a6d48c5fbdcfa9a8e42788291778d2ca4e1b03",
			responderAuth:     "0e00000007300506032b6570eed63ea548c63055293865fc4857a7b273501bdcb511b6307688bb85362a1a4eb92ed924a9bf91ee07f0e4fdc26d373be38948343a02d9035c4f187bef984e0a",
			initiatorResolved: "type=ipv6 id=2001:db8::1 sent=ipv6",
			responderResolved: "type=ipv6 id=2001:db8::2 sent=ipv6",
		},
		// the initiator asks in IDr for the FQDN as its table writes it, and the responder answers with the ID it was asked for
		"an FQDN each way, matched without case": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{FQDN: map[string]identity.Identity{"Server.TestOrg.Example": server}},
				Local:  map[string]LocalAlias{"testorg/server:1": {FQDN: "client.testorg.example"}},
			},
			responderAliases: Aliases{
				Remote: RemoteAliases{FQDN: map[string]identity.Identity{"CLIENT.testorg.example": client}},
				Local:  map[string]LocalAlias{"testorg/client:2": {FQDN: "server.testorg.example"}},
			},
			idi:               "02000000" + text("client.testorg.example"),
			idr:               "02000000" + text("Server.TestOrg.Example"),
			initiatorAuth:     "0e00000007300506032b6570dc08a0c0fefbf8a3c62ebf98881b500b7dec27a99b7950df5a087c778667f11b2c1850d0b1b64c61d84ce8f9c9012beb608c7a79e952fca1a66ad88d9eefc300",
			responderAuth:     "0e00000007300506032b6570db81f3e38cd446e12e74c5a5a25192928ef85cd88b3f960d37ce2469d09fefc8524c0c74ea8edf737a8053d697814b783c8721ffdbb3d1e92618a7cb4c60e60e",
			initiatorResolved: "type=fqdn id=Server.TestOrg.Example sent=fqdn",
			responderResolved: "type=fqdn id=client.testorg.example sent=fqdn",
		},
		"an email address each way, its domain matched without case": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{Email: map[string]identity.Identity{"server@TestOrg.Example": server}},
				Local:  map[string]LocalAlias{"testorg/server:1": {Email: "client@testorg.example"}},
			},
			responderAliases: Aliases{
				Remote: RemoteAliases{Email: map[string]identity.Identity{"client@TESTORG.example": client}},
				Local:  map[string]LocalAlias{"testorg/client:2": {Email: "server@testorg.example"}},
			},
			idi:               "03000000" + text("client@testorg.example"),
			idr:               "03000000" + text("server@TestOrg.Example"),
			initiatorAuth:     "0e00000007300506032b657058e5a4c399cd2a464cd8805eb9f2386613e1600ea18cc8dad20dcd0932b3e5f3ab33f8126fafcc67045c2f55eeaee3efc397b22c155ca18dbc8a6a115cfeb406",
			responderAuth:     "0e00000007300506032b65705b6ac12c41c00ed2e4162e14b045c2ada3b2a89981b5b5b30b349f9c65cb50c89c0dc1d15ca91b9b094a4c0f57b617114b51f0d6946f42d750943a0b8049d20d",
			initiatorResolved: "type=email id=server@TestOrg.Example sent=email",
			responderResolved: "type=email id=client@testorg.example sent=email",
		},
		"a KEY_ID each way": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{KeyID: map[string]identity.Identity{"0A1B2C3D": server}},
				Local:  map[string]LocalAlias{"testorg/server:1": {KeyID: "0a1b2c3e"}},
			},
			responderAliases: Aliases{
				Remote: RemoteAliases{KeyID: map[string]identity.Identity{"0a1b2c3e": client}},
				Local:  map[string]LocalAlias{"testorg/client:2": {KeyID: "0a1b2c3d"}},
			},
			idi:               "0b0000000a1b2c3e",
			idr:               "0b0000000a1b2c3d",
			initiatorAuth:     "0e00000007300506032b65704a90e9bf52f70120d7a1573f4bcdced257cbdf9f8d29dbaed59148db42c97ee5df701ae4625dde04307d22088d39164f2d500b84ffb115ac77ea19722df35806",
			responderAuth:     "0e00000007300506032b65707a06e0746e23d5dba470854e57e800634cbe98dfda172905b06727b9a8784fd59af99b6b4ab52dc515c84f5793d5244871960a61a9b6f8bdddb5c5f6c718650e",
			initiatorResolved: "type=keyid id=0a1b2c3d sent=keyid",
			responderResolved: "type=keyid id=0a1b2c3e sent=keyid",
		},
		// neither end reads the other's KEY_ID from a table, since the initiator's one entry spells the endpoint it names and the responder lists none
		// the responder answers the KEY_ID it is asked for as the endpoint it spells
		"a KEY_ID spelling each endpoint": {
			initiator: client,
			responder: server,
			initiatorAliases: Aliases{
				Remote: RemoteAliases{KeyID: map[string]identity.Identity{text("testorg/server:1"): server}},
				Local:  map[string]LocalAlias{"testorg/server:1": {KeyID: text("testorg/client:2")}},
			},
			idi:               "0b000000" + text("testorg/client:2"),
			idr:               "0b000000" + text("testorg/server:1"),
			initiatorAuth:     "0e00000007300506032b6570993345b15892ecb79233baa6bb665faaacabbaffdce91e66d221720b9436c785aafb556f7ce7b6458d884a4b74dee997eca9f80f403cbc30aff27322e7fc2904",
			responderAuth:     "0e00000007300506032b6570dc6d891ebfbfe6b3231ac1470230aa5ae4f116fa045fbde1fe48b21e6a896323ff5742f6bc9ef472aead4674614cb483b19c005d7163b23c05b3a4311236c90e",
			initiatorResolved: "type=keyid id=" + text("testorg/server:1") + " sent=keyid",
			responderResolved: "type=keyid id=" + text("testorg/client:2") + " sent=keyid",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Run("initiator", func(t *testing.T) { checkInitiatorPayloads(t, x) })
			t.Run("responder", func(t *testing.T) { checkResponderPayloads(t, x) })
		})
	}
}

func checkInitiatorPayloads(t *testing.T, x payloadExchange) {
	events := &recorder{}
	inner, authErr := initiatorExchange(t, x, events.record)
	if inner == nil {
		t.Fatal("the initiator sent no IKE_AUTH request the responder could read")
	}
	samePayload(t, "IDi", findType(inner, PayloadIDi), x.idi)
	if idr := findType(inner, PayloadIDr); x.noIDr && idr != nil {
		t.Errorf("the initiator sent IDr %x to a responder its aliases name", idr.Body)
	} else if !x.noIDr {
		samePayload(t, "IDr", idr, x.idr)
	}
	samePayload(t, "AUTH", findType(inner, PayloadAUTH), x.initiatorAuth)
	if authErr != nil {
		t.Fatalf("the initiator refused the responder's IDr and AUTH: %v", authErr)
	}
	if got, want := events.recorded(), []string{"ike.id.resolved " + x.initiator.String() + ">" + x.responder.String() + " " + x.initiatorResolved}; !slices.Equal(got, want) {
		t.Errorf("the initiator recorded %q, want %q", got, want)
	}
}

func checkResponderPayloads(t *testing.T, x payloadExchange) {
	events := &recorder{}
	inner, accepted, authErr := responderExchange(t, x, events.record)
	samePayload(t, "IDr", findType(inner, PayloadIDr), x.idr)
	samePayload(t, "AUTH", findType(inner, PayloadAUTH), x.responderAuth)
	if authErr != nil {
		t.Fatalf("the responder refused the initiator's IDi and AUTH: %v", authErr)
	}
	if accepted.Peer != x.initiator || accepted.Local != x.responder {
		t.Fatalf("the responder accepted %s at %s, want %s at %s", accepted.Peer, accepted.Local, x.initiator, x.responder)
	}
	if got, want := events.recorded(), []string{"ike.id.resolved " + x.responder.String() + ">" + x.initiator.String() + " " + x.responderResolved}; !slices.Equal(got, want) {
		t.Errorf("the responder recorded %q, want %q", got, want)
	}
}

// initiatorExchange runs the initiator's IKE_AUTH against a responder scripted with x's responder bytes, and returns the request and how the initiator took the answer
// the scripted responder answers the INFORMATIONAL request a refusal sends, which spares the initiator its retransmissions
func initiatorExchange(t *testing.T, x payloadExchange, events Recorder) ([]RawPayload, error) {
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	mux, err := testNetwork(t).Dial(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	ctx := goldenContext(false)
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), events: events, local: x.initiator, remote: x.responder}
	cfg := PeerConfig{
		Local:           x.initiator,
		LocalPrivateKey: goldenInitiatorKey,
		Remote:          x.responder,
		RemotePublicKey: goldenResponderKey.Public().(ed25519.PublicKey),
		Aliases:         x.initiatorAliases,
	}
	sent := make(chan []RawPayload, 1)
	peerLoop(t, peer, func() {
		defer close(sent)
		buf := make([]byte, 4096)
		read := func() (*Message, []RawPayload, *net.UDPAddr) {
			_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
			n, from, err := peer.ReadFromUDP(buf)
			if err != nil || n <= 4 {
				return nil, nil, nil
			}
			raw := bytes.Clone(buf[4:n])
			request, err := DecodeMessage(raw)
			if err != nil {
				return nil, nil, nil
			}
			inner, err := DecryptMessage(goldenSuite, ctx.skei, raw, request)
			if err != nil {
				return nil, nil, nil
			}
			return request, inner, from
		}
		answer := func(to *net.UDPAddr, request *Message, payloads []RawPayload) {
			response, err := EncryptMessage(goldenSuite, ctx.sker, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR,
				ExchangeType: request.Header.ExchangeType, Flags: FlagResponse, MessageID: request.Header.MessageID}, nil, payloads)
			if err == nil {
				_, _ = peer.WriteToUDP(withNonESPMarker(response), to)
			}
		}
		request, inner, from := read()
		if request == nil {
			return
		}
		sent <- inner
		proposal := Proposal{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}
		answer(from, request, []RawPayload{
			{Type: PayloadIDr, Body: goldenBytes(x.idr)},
			{Type: PayloadAUTH, Body: goldenBytes(x.responderAuth)},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
			{Type: PayloadTSi, Body: fullRangeSelectors()},
			{Type: PayloadTSr, Body: fullRangeSelectors()},
		})
		for request != nil && request.Header.ExchangeType != INFORMATIONAL {
			request, _, from = read()
		}
		if request != nil {
			answer(from, request, nil)
		}
	})
	authErr := s.completeIKEAuth(cfg, goldenMessage1, goldenMessage2, goldenNi, goldenNr, intAuth{})
	return <-sent, authErr
}

// responderExchange runs the responder's IKE_AUTH against an initiator scripted with x's initiator bytes, and returns the answer, whom the responder accepted and how it took the request
func responderExchange(t *testing.T, x payloadExchange, events Recorder) ([]RawPayload, Accepted, error) {
	t.Helper()
	return answerExchange(t, x, events, t.Cleanup)
}

// answerExchange is responderExchange handing each socket it opens to cleanup, which a property runs at the end of each case
func answerExchange(t testing.TB, x payloadExchange, events Recorder, cleanup func(func())) ([]RawPayload, Accepted, error) {
	t.Helper()
	var hubs [2]*transport.Hub
	for i := range hubs {
		hub, err := testNetwork(t).NewHub()
		if err != nil {
			t.Fatal(err)
		}
		cleanup(func() { hub.Close() })
		hubs[i] = hub
	}
	hub, initiatorHub := hubs[0], hubs[1]
	over := x.over
	if over == nil {
		over = net.IPv4(127, 0, 0, 1)
	}
	arrival, _ := netip.AddrFromSlice(over)
	local := make(map[identity.Identity]Family)
	for _, id := range append(x.otherLocal, x.responder) {
		local[id] = familyOf(arrival)
		if family, ok := x.families[id]; ok {
			local[id] = family
		}
	}
	var initiatorKey atomic.Pointer[ed25519.PublicKey]
	public := goldenInitiatorKey.Public().(ed25519.PublicKey)
	initiatorKey.Store(&public)
	initiatorFamily := x.initiatorFamily
	if initiatorFamily == 0 {
		initiatorFamily = familyOf(arrival)
	}
	r, err := NewResponder(ResponderConfig{
		Hub:             hub,
		Local:           local,
		LocalPrivateKey: goldenResponderKey,
		Trust:           trustIn(&initiatorKey, map[identity.Identity]Family{x.initiator: initiatorFamily}),
		Aliases:         func() Aliases { return x.responderAliases },
		Events:          events,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux, err := hub.NewMux(over, initiatorHub.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func() { mux.Close() })
	peer, err := initiatorHub.NewMux(over, hub.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	cleanup(func() { peer.Close() })
	ctx := goldenContext(true)
	s := &Session{mux: mux, current: ctx}
	if err := mux.RegisterIKE(ctx.spiI); err != nil {
		t.Fatal(err)
	}
	if err := peer.RegisterIKE(ctx.spiI); err != nil {
		t.Fatal(err)
	}
	payloads := []RawPayload{{Type: PayloadIDi, Body: goldenBytes(x.idi)}}
	switch {
	case x.requestIDr != "":
		payloads = append(payloads, RawPayload{Type: PayloadIDr, Body: goldenBytes(x.requestIDr)})
	case !x.noIDr:
		payloads = append(payloads, RawPayload{Type: PayloadIDr, Body: goldenBytes(x.idr)})
	}
	offer := x.childOffer
	if offer == nil {
		offer = []Proposal{espProposal([]byte{0, 0, 0, 9})}
	}
	payloads = append(payloads,
		RawPayload{Type: PayloadAUTH, Body: goldenBytes(x.initiatorAuth)},
		RawPayload{Type: PayloadSA, Body: EncodeSA(offer)},
		RawPayload{Type: PayloadTSi, Body: fullRangeSelectors()},
		RawPayload{Type: PayloadTSr, Body: fullRangeSelectors()},
	)
	request, err := EncryptMessage(goldenSuite, ctx.skei, Header{SPIInitiator: ctx.spiI, SPIResponder: ctx.spiR,
		ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}, nil, payloads)
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	accepted, _, authErr := s.completeResponderAuth(r, goldenMessage1, goldenMessage2, goldenNi, goldenNr, time.Now().Add(answerBudget))
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
	return inner, accepted, authErr
}

// RFC 7296 section 2.15 signs "RestOfInitIDPayload = IDType | RESERVED | InitIDData" and "RestOfRespIDPayload = IDType | RESERVED | RespIDData", and each end verifies AUTH over the ID payload as it arrived
// an ID naming the endpoint in other octets than the ones signed is refused, and RESERVED octets the signer set are taken as signed, which section 3.5's "MUST be ignored on receipt" asks
func TestEachEndVerifiesAUTHOverTheIDPayloadAsItArrived(t *testing.T) {
	client, server := identity.MustParse("testorg/client:2"), identity.MustParse("testorg/server:1")
	fqdn := func(name string, reserved byte) []byte {
		body := EncodeID(ID_FQDN, []byte(name))
		body[1] = reserved
		return body
	}
	for name, test := range map[string]struct {
		sent, signed []byte
		want         string // the refusal, or empty where the ID is taken
	}{
		"an FQDN in another case than the one signed": {sent: fqdn("Peer.TestOrg.Example", 0), signed: fqdn("peer.testorg.example", 0),
			want: "AUTH signature verification failed"},
		"RESERVED octets set after signing": {sent: fqdn("peer.testorg.example", 1), signed: fqdn("peer.testorg.example", 0),
			want: "AUTH signature verification failed"},
		"RESERVED octets the signer set": {sent: fqdn("peer.testorg.example", 1), signed: fqdn("peer.testorg.example", 1)},
	} {
		t.Run(name+" in IDr", func(t *testing.T) {
			_, err := initiatorExchange(t, payloadExchange{
				initiator: client, responder: server,
				initiatorAliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"peer.testorg.example": server}}},
				idr:              hex.EncodeToString(test.sent), responderAuth: goldenResponderAuth(test.signed),
			}, nil)
			takenAsSigned(t, err, test.want)
		})
		t.Run(name+" in IDi", func(t *testing.T) {
			_, accepted, err := responderExchange(t, payloadExchange{
				initiator: client, responder: server, noIDr: true,
				responderAliases: Aliases{Remote: RemoteAliases{FQDN: map[string]identity.Identity{"peer.testorg.example": client}}},
				idi:              hex.EncodeToString(test.sent), initiatorAuth: goldenInitiatorAuth(test.signed),
			}, nil)
			takenAsSigned(t, err, test.want)
			if test.want == "" && accepted.Peer != client {
				t.Errorf("the responder accepted %s, want %s", accepted.Peer, client)
			}
		})
	}
}

// goldenInitiatorAuth is the AUTH payload body, in hex, of the golden initiator signing an IDi whose body is idi
func goldenInitiatorAuth(idi []byte) string {
	signed := concat(goldenMessage1, goldenNr, prf(goldenSuite.PRFID, goldenContext(false).skpi, idi))
	return hex.EncodeToString(BuildAuth(goldenInitiatorKey, signed))
}

// goldenResponderAuth is the AUTH payload body, in hex, of the golden responder signing an IDr whose body is idr
func goldenResponderAuth(idr []byte) string {
	signed := concat(goldenMessage2, goldenNi, prf(goldenSuite.PRFID, goldenContext(false).skpr, idr))
	return hex.EncodeToString(BuildAuth(goldenResponderKey, signed))
}

// takenAsSigned fails t unless err refuses with want, or is nil where want is empty
func takenAsSigned(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("an ID sent as it was signed was refused: %v", err)
	case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
		t.Fatalf("an ID sent in other octets than the ones signed was taken with %v, want a refusal naming %q", err, want)
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
