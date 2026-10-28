// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
	"ranet3.com/pkgs/ranet3/transport"
)

// answeredRemoteSPI is the inbound SPI the peer of these tests answers with
const answeredRemoteSPI = 0x90a0b0c0

// spiSession is a session dialed to a peer socket on a hub of its own, its timers an hour out, with the hub and another mux on it
func spiSession(t *testing.T) (*Session, *transport.MemoryConn, *transport.Hub, *transport.Mux) {
	t.Helper()
	peer := listenPeer(t)
	at := peer.LocalAddr().(*net.UDPAddr)
	hub := listenHub(t)
	mux, err := hub.NewMux(at.IP, at.Port)
	if err != nil {
		t.Fatal(err)
	}
	other, err := hub.NewMux(net.ParseIP("192.0.2.1"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	current := testContext()
	current.skD = make([]byte, 32)
	if err := mux.RegisterIKE(current.spiI); err != nil {
		t.Fatal(err)
	}
	return &Session{mux: mux, current: current, requests: make(chan *localRequest, 1), probes: make(chan struct{}, 1),
		dpdEvery: time.Hour, retransmitAfter: time.Hour}, peer, hub, other
}

// offeredSPI is the SPI of the one proposal a request's SA payload holds, the inbound SPI the session picked
func offeredSPI(t *testing.T, inner []RawPayload) uint32 {
	t.Helper()
	sa := findType(inner, PayloadSA)
	if sa == nil {
		t.Fatal("the request carries no SA payload")
	}
	proposals, err := DecodeSA(sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("the request offers %+v (%v), want one proposal with an SPI", proposals, err)
	}
	return binary.BigEndian.Uint32(proposals[0].SPI)
}

// sendEarlyESP has peer send ESP on spi to s's hub, as a peer that installed the SA sends before its answer arrives, and checks the hub took it as ESP on an SPI it holds
func sendEarlyESP(t *testing.T, s *Session, peer *transport.MemoryConn, hub *transport.Hub, spi uint32) {
	t.Helper()
	refused := hub.Refused()
	if _, err := peer.WriteToUDP(binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1), muxLoopback(s.mux)); err != nil {
		t.Fatal(err)
	}
	synctest.Wait()
	if hub.Refused() != refused || len(s.mux.InvalidSPI()) != 0 {
		t.Errorf("ESP on SPI %08x before the answer was refused %d times and handed on %d times, want it taken for the session", spi, hub.Refused()-refused, len(s.mux.InvalidSPI()))
	}
}

// tookEarlyESP checks the ESP sendEarlyESP sent reached the session's mux
func tookEarlyESP(t *testing.T, s *Session, spi uint32) {
	t.Helper()
	packet, err := s.mux.RecvESPUntil(time.Now().Add(answerBudget))
	if err != nil || binary.BigEndian.Uint32(packet) != spi {
		t.Errorf("the session read %x (%v), want the ESP on SPI %08x that came before the answer", packet, err, spi)
	}
}

// released checks an exchange that installed no SA with spi let it go, so another mux can take it
func released(t *testing.T, other *transport.Mux, spi uint32) {
	t.Helper()
	if err := other.RegisterESP(spi); err != nil {
		t.Errorf("the SPI the exchange picked is still held: %v", err)
	}
}

// childAnswer is the peer's answer accepting a CREATE_CHILD_SA, its SA inbound on answeredRemoteSPI
func childAnswer() []RawPayload {
	return []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, answeredRemoteSPI),
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
}

// authPeer holds the config an IKE_AUTH initiator dials with, and the key and identity of the peer it dials
type authPeer struct {
	cfg     PeerConfig
	private ed25519.PrivateKey
	idr     []byte
}

func newAuthPeer(t *testing.T) authPeer {
	t.Helper()
	_, local, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return authPeer{
		cfg: PeerConfig{Local: identity.MustParse("ranet-test/initiator:1"), LocalPrivateKey: local,
			Remote: identity.MustParse("ranet-test/responder:2"), RemotePublicKey: public},
		private: private,
		idr:     idBody("ranet-test/responder:2"),
	}
}

// authenticated is the peer's IDr and AUTH for s's IKE_AUTH, the IKE_SA_INIT response and initiator nonce it signs being what the tests pass doIKEAuth
func (p authPeer) authenticated(s *Session) []RawPayload {
	signed := concat([]byte("the IKE_SA_INIT response"), make([]byte, 32), prf(s.current.suite.PRFID, s.current.skpr, p.idr))
	return []RawPayload{{Type: PayloadIDr, Body: p.idr}, {Type: PayloadAUTH, Body: BuildAuth(p.private, signed)}}
}

// startIKEAuth runs s's IKE_AUTH toward p and answers how it ends
func startIKEAuth(s *Session, p authPeer) <-chan error {
	s.current.authMID, s.current.nextLocalMID = 1, 2
	s.current.skpi, s.current.skpr = make([]byte, 32), make([]byte, 32)
	ended := make(chan error, 1)
	go func() {
		_, err := s.doIKEAuth(p.cfg, []byte("the IKE_SA_INIT request"), []byte("the IKE_SA_INIT response"), make([]byte, 32), make([]byte, 32), intAuth{})
		ended <- err
	}()
	return ended
}

// a responder installs the Child SA before it answers IKE_AUTH and may send on it at once
// ESP on the SPI the initiator offered that arrives before the answer reaches the session, and the hub refuses none of it nor hands it on as unknown
func TestIKEAuthTakesESPThatComesBeforeTheAnswer(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, hub, _ := spiSession(t)
		p := newAuthPeer(t)
		ended := startIKEAuth(s, p)
		_, header, inner := readOwnRequest(t, s, peer)
		spi := offeredSPI(t, inner)
		sendEarlyESP(t, s, peer, hub, spi)
		answerOwnRequest(t, s, peer, header, append(p.authenticated(s), childAnswer()[0], childAnswer()[2], childAnswer()[3]))
		if err := <-ended; err != nil {
			t.Fatalf("the IKE_AUTH ended with %v", err)
		}
		if got := s.currentChild(); got.LocalSPI != spi || got.RemoteSPI != answeredRemoteSPI {
			t.Errorf("the session holds Child SA %08x/%08x, want %08x/%08x", got.LocalSPI, got.RemoteSPI, spi, answeredRemoteSPI)
		}
		tookEarlyESP(t, s, spi)
	})(t)
}

// an IKE_AUTH that installs no Child SA lets the SPI it picked go, however it ends
func TestIKEAuthThatInstallsNoChildSALetsItsSPIGo(t *testing.T) {
	for _, test := range []struct {
		name   string
		answer func(authPeer, *Session) []RawPayload
	}{
		{"the Child SA refused", func(p authPeer, s *Session) []RawPayload {
			return append(p.authenticated(s), RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NO_PROPOSAL_CHOSEN})})
		}},
		{"the IKE SA refused", func(authPeer, *Session) []RawPayload {
			return []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_AUTHENTICATION_FAILED})}}
		}},
		{"no answer", nil},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			s, peer, _, other := spiSession(t)
			p := newAuthPeer(t)
			ended := startIKEAuth(s, p)
			_, header, inner := readOwnRequest(t, s, peer)
			spi := offeredSPI(t, inner)
			if test.answer != nil {
				answerOwnRequest(t, s, peer, header, test.answer(p, s))
			}
			if err := <-ended; err == nil {
				t.Fatal("the IKE_AUTH succeeded")
			}
			released(t, other, spi)
		}))
	}
}

// RFC 7296 section 2.8: "The responder to a CREATE_CHILD_SA MUST be prepared to accept messages on an SA before sending its response to the creation request, so there is no ambiguity for the initiator."
// ESP on the SPI a Child SA rekey offered that arrives before the answer reaches the session, and the hub refuses none of it nor hands it on as unknown
func TestChildSARekeyTakesESPThatComesBeforeTheAnswer(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		s, peer, hub, _ := spiSession(t)
		s.Child = ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
		runSession(t, s)
		rekeyed := make(chan error, 1)
		go func() { rekeyed <- s.RekeyChild() }()
		_, header, inner := readOwnRequest(t, s, peer)
		spi := offeredSPI(t, inner)
		sendEarlyESP(t, s, peer, hub, spi)
		answerOwnRequest(t, s, peer, header, childAnswer())
		_, deletion, _ := readOwnRequest(t, s, peer)
		answerOwnRequest(t, s, peer, deletion, nil)
		if err := <-rekeyed; err != nil {
			t.Fatalf("the rekey ended with %v", err)
		}
		if got := s.currentChild(); got.LocalSPI != spi || got.RemoteSPI != answeredRemoteSPI {
			t.Errorf("the session holds Child SA %08x/%08x, want %08x/%08x", got.LocalSPI, got.RemoteSPI, spi, answeredRemoteSPI)
		}
		tookEarlyESP(t, s, spi)
	})(t)
}

// a Child SA rekey that installs no SA lets the SPI it picked go, whether the peer refuses it or the IKE SA carrying it is replaced before its answer
func TestChildSARekeyThatInstallsNothingLetsItsSPIGo(t *testing.T) {
	for _, test := range []struct {
		name string
		end  func(*testing.T, *Session, *transport.MemoryConn, Header)
	}{
		{"refused with TEMPORARY_FAILURE", func(t *testing.T, s *Session, peer *transport.MemoryConn, header Header) {
			answerOwnRequest(t, s, peer, header, []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_TEMPORARY_FAILURE})}})
		}},
		{"its IKE SA replaced", func(_ *testing.T, s *Session, _ *transport.MemoryConn, _ Header) {
			s.stateMu.Lock()
			s.current = testContext()
			s.stateMu.Unlock()
		}},
	} {
		t.Run(test.name, bubble.Run(func(t *testing.T) {
			s, peer, _, other := spiSession(t)
			s.Child = ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
			runSession(t, s)
			rekeyed := make(chan error, 1)
			go func() { rekeyed <- s.RekeyChild() }()
			_, header, inner := readOwnRequest(t, s, peer)
			spi := offeredSPI(t, inner)
			test.end(t, s, peer, header)
			select {
			case err := <-rekeyed:
				if err == nil {
					t.Fatal("the rekey succeeded")
				}
			case <-time.After(2 * time.Hour):
				t.Fatal("the rekey never ended")
			}
			released(t, other, spi)
		}))
	}
}
