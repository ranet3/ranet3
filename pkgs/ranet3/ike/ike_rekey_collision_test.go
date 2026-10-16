// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT AND FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

func TestLosingLocalIKERekeyAcceptsDeleteResponse(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), ikeRekeyNonce: func(n []byte) error {
		copy(n, bytes.Repeat([]byte{1}, len(n)))
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	request := <-s.requests
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	winner := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	// The winner is routed by its own SPI the way handleIKERekey leaves it,
	// so releasing the redundant candidate's registration can be told apart
	// from releasing the SPI the session is about to be current on.
	if err := mux.RegisterIKE(winner.spiI); err != nil {
		t.Fatal(err)
	}
	s.stateMu.Lock()
	s.collision = winner
	s.localRekey.peerNonce = bytes.Repeat([]byte{2}, 32)
	s.localRekey.peerResponseNonce = bytes.Repeat([]byte{2}, 32)
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, 22)
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}}
	deleteRequest := <-s.requests
	pending, err := s.startRequest(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	c := deleteRequest.context
	response, err := EncryptMessage(c.suite, c.peerEncryptionKey(), Header{SPIInitiator: c.spiI, SPIResponder: c.spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: pending.msgID}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The peer may retire the original IKE SA while our redundant-SA Delete
	// is still outstanding. Completing that Delete must not resurrect it.
	s.removeRetainedContext(old)
	if !s.dispatch(response, nil, &pending) {
		deleteRequest.result <- requestResult{err: fmt.Errorf("test cleanup")}
		<-done
		t.Fatal("valid Delete response for the losing local IKE SA was discarded")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current, retained := s.contexts()
	if current != winner || retained != nil || s.collision != nil {
		t.Fatal("collision did not retain only the winning IKE SA")
	}
	// Probed from a second mux on the same hub, because registering an SPI a
	// mux already owns succeeds: only another mux can tell held from released.
	if err := other.RegisterIKE(winner.spiI); err == nil {
		t.Error("the losing branch released the SPI the session is now current on")
	}
	if err := other.RegisterIKE(22); err != nil {
		t.Errorf("the redundant candidate kept its SPI registered: %v", err)
	}
}

// RFC 7296 section 2.8: "the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// the candidate this end's rekey made and lost a collision with is deleted by this end, so it is kept past its lifetime for that Delete, and an answer held past the lifetime completes the rekey
func TestLosingCandidateIsKeptPastItsLifetimeForItsDelete(t *testing.T) {
	const lifetime, margin = 2 * time.Second, time.Second
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const oldSPIi, oldSPIr, peerSPIi, loserSPIr = 0x0102030405060708, 0x1112131415161718, 0x2122232425262728, 0x3132333435363738
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	transforms := []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}
	// the scheduled rekey falls due scheduleDue into the test, well inside the old SA's lifetime
	old := &ikeContext{suite: suite, spiI: oldSPIi, spiR: oldSPIr, nextLocalMID: 2, established: time.Now().Add(scheduleDue - (lifetime - margin)),
		skD: []byte("old IKE rekey SK_d material-------"), skei: make([]byte, 20), sker: make([]byte, 20)}
	// the peer's answer carries the lowest of the four nonces, so the candidate this end's rekey makes loses
	localNonce, peerNonce, answerNonce := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32), bytes.Repeat([]byte{1}, 32)
	events := &recorder{}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), events: events.record,
		ikeRekeyInterval: lifetime, rekeyMargin: margin,
		ikeRekeyNonce: func(n []byte) error {
			copy(n, localNonce)
			return nil
		}}
	if err := mux.RegisterIKE(oldSPIi); err != nil {
		t.Fatal(err)
	}

	peerLoop(t, peer, func() {
		buf := make([]byte, 2048)
		read := func(what string) (*Message, []byte, *net.UDPAddr, bool) {
			if err := peer.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
				t.Errorf("set a read deadline: %v", err)
				return nil, nil, nil, false
			}
			n, addr, err := peer.ReadFromUDP(buf)
			if err != nil {
				t.Errorf("read %s: %v", what, err)
				return nil, nil, nil, false
			}
			raw := append([]byte(nil), buf[4:n]...)
			message, err := DecodeMessage(raw)
			if err != nil {
				t.Errorf("decode %s: %v", what, err)
				return nil, nil, nil, false
			}
			return message, raw, addr, true
		}
		send := func(what string, raw []byte, err error, addr *net.UDPAddr) bool {
			if err == nil {
				_, err = peer.WriteToUDP(withNonESPMarker(raw), addr)
			}
			if err != nil {
				t.Errorf("send %s: %v", what, err)
			}
			return err == nil
		}

		rekey, raw, addr, ok := read("the scheduled rekey")
		if !ok {
			return
		}
		inner, err := DecryptMessage(suite, old.skei, raw, rekey)
		if err != nil || rekey.Header.ExchangeType != CREATE_CHILD_SA || findType(inner, PayloadSA) == nil || findType(inner, PayloadKE) == nil {
			t.Errorf("the first request is %+v, %v, want the scheduled IKE SA rekey", rekey.Header, err)
			return
		}
		props, err := DecodeSA(findType(inner, PayloadSA).Body)
		if err != nil || len(props) != 1 {
			t.Errorf("the rekey proposes %v, %v", props, err)
			return
		}
		localSPIi := binary.BigEndian.Uint64(props[0].SPI)
		_, localPublic, err := DecodeKE(findType(inner, PayloadKE).Body)
		if err != nil {
			t.Errorf("decode the rekey's KE: %v", err)
			return
		}

		// the peer's own rekey crosses it, and this end answers it before it sees its own answered
		peerDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate the peer's DH: %v", err)
			return
		}
		spi := binary.BigEndian.AppendUint64(nil, peerSPIi)
		raw, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, MessageID: 0}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: transforms}})},
			{Type: PayloadNonce, Body: EncodeNonce(peerNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, peerDH.PublicBytes())},
		})
		if !send("the peer's rekey", raw, err, addr) {
			return
		}
		if answer, _, _, ok := read("the answer to the peer's rekey"); !ok || !answer.Header.IsResponse() || answer.Header.ExchangeType != CREATE_CHILD_SA {
			t.Errorf("the peer's rekey was not answered first")
			return
		}

		responderDH, err := GenerateDH(DH_CURVE25519)
		if err != nil {
			t.Errorf("generate the answer's DH: %v", err)
			return
		}
		spi = binary.BigEndian.AppendUint64(nil, loserSPIr)
		raw, err = EncryptMessage(suite, old.sker, Header{SPIInitiator: oldSPIi, SPIResponder: oldSPIr, ExchangeType: CREATE_CHILD_SA, Flags: FlagResponse, MessageID: rekey.Header.MessageID}, nil, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: transforms}})},
			{Type: PayloadNonce, Body: EncodeNonce(answerNonce)},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, responderDH.PublicBytes())},
		})
		if !send("the answer to the scheduled rekey", raw, err, addr) {
			return
		}
		shared, err := responderDH.SharedSecret(localPublic)
		if err != nil {
			t.Errorf("derive the losing candidate's shared secret: %v", err)
			return
		}
		loser, err := DeriveRekeyedIKEKeys(PRF_HMAC_SHA2_256, old.skD, suite, shared, localNonce, answerNonce, localSPIi, loserSPIr)
		if err != nil {
			t.Errorf("derive the losing candidate's keys: %v", err)
			return
		}

		del, raw, addr, ok := read("the Delete of the losing candidate")
		if !ok {
			return
		}
		inner, err = DecryptMessage(suite, loser.SKei, raw, del)
		if err != nil || del.Header.SPIInitiator != localSPIi || del.Header.SPIResponder != loserSPIr || findType(inner, PayloadD) == nil {
			t.Errorf("the request after the collision is %+v, %v, want the Delete of the losing candidate", del.Header, err)
			return
		}
		s.stateMu.RLock()
		held := s.collision
		s.stateMu.RUnlock()
		if held == nil || held.spiI != localSPIi {
			t.Errorf("the session holds %+v while its Delete is out, want the losing candidate", held)
			return
		}
		// the retransmissions the hold draws are read and left unanswered
		for until := held.established.Add(lifetime + answerLate); time.Now().Before(until); {
			if err := peer.SetReadDeadline(until); err != nil {
				t.Errorf("set a read deadline: %v", err)
				return
			}
			if _, _, err := peer.ReadFromUDP(buf); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("read a retransmission: %v", err)
				return
			}
		}
		raw, err = EncryptMessage(suite, loser.SKer, Header{SPIInitiator: localSPIi, SPIResponder: loserSPIr, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: del.Header.MessageID}, nil, nil)
		send("the answer to the Delete", raw, err, addr)
	})

	run, stop := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- s.Run(run) }()
	defer func() {
		stop()
		<-runDone
	}()
	completed, failed := "ike.rekey.completed > sa=ike", "ike.rekey.failed > sa=ike"
	for deadline := time.Now().Add(answerBudget); ; time.Sleep(recordPoll) {
		got := events.recorded()
		if slices.Contains(got, failed) {
			t.Fatalf("the rekey failed with its losing candidate's Delete outstanding past the candidate's lifetime, the session recorded %q", got)
		}
		if slices.Contains(got, completed) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rekey never ended, the session recorded %q", got)
		}
	}
	s.stateMu.RLock()
	current, held := s.current, s.collision
	s.stateMu.RUnlock()
	if current.spiI != peerSPIi || held != nil {
		t.Errorf("after the rekey the session is current on %016x and holds %+v, want the peer's candidate alone", current.spiI, held)
	}
}

// RFC 7296 section 2.8.2: "If the peer that did notice the simultaneous rekey
// gets the delete request from the other peer for the old IKE SA, it knows
// that the other peer did not detect the simultaneous rekey, and the first
// peer can forget its own rekey attempt." Closing the session instead throws
// away an SA the peer believes is current.
func TestOneSidedIKERekeyCollisionAdoptsPeersSA(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	peerSA := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, current: old}
	// Only this end noticed: the peer's new SA is held as the collision
	// candidate while this end's own rekey is still outstanding.
	s.collision = peerSA
	s.localRekey = &ikeRekey{old: old, nonce: make([]byte, 32)}

	if !s.adoptCollisionOnPeerDelete(old) {
		t.Fatal("the peer's Delete for the old SA closed the session instead of resolving the collision")
	}
	if s.current != peerSA {
		t.Errorf("current SA is %p, want the peer's %p", s.current, peerSA)
	}
	if s.collision != nil || s.localRekey != nil {
		t.Error("the abandoned local rekey attempt was not forgotten")
	}
	// It applies only to that case: a Delete on any other SA still ends the
	// session, and so does one with no collision outstanding.
	if s.adoptCollisionOnPeerDelete(old) {
		t.Error("a second Delete for the replaced SA resolved a collision that is over")
	}
}

// The same case driven through the path a real Delete takes, because the
// resolution above is only reached if dispatch asks for it.
func TestPeerDeleteOnOneSidedCollisionKeepsSessionOpen(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: make([]byte, 20), sker: make([]byte, 20)}
	peerSA := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	s := &Session{mux: mux, current: old, collision: peerSA, localRekey: &ikeRekey{old: old, nonce: make([]byte, 32)}}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	del, err := EncryptMessage(suite, old.sker, Header{
		SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, MessageID: 0,
	}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(del), dst); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("the peer's Delete was not authenticated")
	}
	if mux.IsClosed() {
		t.Fatal("the peer's Delete for the SA it replaced closed the whole session")
	}
	if s.current != peerSA {
		t.Errorf("current SA is %p, want the peer's %p", s.current, peerSA)
	}
}

// An exchange whose IKE SA has gone can never be answered, and IKEv2 permits
// one outstanding local request at a time, so leaving it pending stops every
// later rekey and the Delete on teardown for the life of the session.
func TestRequestOnRetiredIKESAFailsRatherThanPends(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	current := &ikeContext{suite: suite, spiI: 11, spiR: 12}
	retired := &ikeContext{suite: suite, spiI: 21, spiR: 22}
	s := &Session{current: current}
	if s.contextRetired(current) {
		t.Error("the current SA reports as retired")
	}
	if !s.contextRetired(retired) {
		t.Error("an SA this session no longer holds reports as live")
	}
	s.old, s.collision = retired, nil
	if s.contextRetired(retired) {
		t.Error("a retained old SA reports as retired")
	}
	s.old, s.collision = nil, retired
	if s.contextRetired(retired) {
		t.Error("a retained collision candidate reports as retired")
	}
}

// RFC 7296 section 2.8.2 makes the Delete for a replaced or redundant IKE SA a
// SHOULD, and handleIKERekey refuses every peer-initiated rekey while either
// is still held. A peer that rekeys once and never sends the Delete would
// otherwise lock this end out of rekeying for the life of the session, which
// is the shape retirementDeadline already stops for a Child SA.
func TestRetainedIKESAThePeerNeverDeletesIsGivenUp(t *testing.T) {
	mine, theirs := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	replaced := &ikeContext{suite: suite, spiI: 11, spiR: 12}
	redundant := &ikeContext{suite: suite, spiI: 21, spiR: 22}
	s := &Session{mux: mine, current: &ikeContext{suite: suite, spiI: 31, spiR: 32}}
	for _, spi := range []uint64{replaced.spiI, redundant.spiI} {
		if err := mine.RegisterIKE(spi); err != nil {
			t.Fatal(err)
		}
	}
	s.stateMu.Lock()
	s.retainOldLocked(replaced)
	s.retainCollisionLocked(redundant)
	s.stateMu.Unlock()
	if _, ok := s.nextRetainedExpiry(); !ok {
		t.Fatal("nothing wakes the control loop to give up on a Delete that is not coming")
	}

	// Held for as long as the peer's Delete could still be in flight.
	s.expireRetainedContexts(time.Now().Add(retainedContextDeadline - time.Second))
	if s.contextRetired(replaced) || s.contextRetired(redundant) {
		t.Fatal("an SA was dropped while the peer's Delete could still be outstanding")
	}

	s.expireRetainedContexts(time.Now().Add(retainedContextDeadline))
	if !s.contextRetired(replaced) || !s.contextRetired(redundant) {
		t.Error("an SA the peer never deleted is still held, so every later peer rekey is refused")
	}
	for _, spi := range []uint64{replaced.spiI, redundant.spiI} {
		if err := theirs.RegisterIKE(spi); err != nil {
			t.Errorf("SPI %016x is still routed to a session that gave up on it: %v", spi, err)
		}
	}
}

// A peer that answers this end's rekey with one of its own may name any SPI
// it likes, and every SPI this session routes is one it has already been told.
// Sharing one makes two contexts indistinguishable to the mux, and whichever
// of them is dropped first unregisters the SPI the other is still reached by,
// which leaves the control channel deaf while ESP keeps flowing. RFC 7296
// section 2.6 leaves the choice to the initiator, so refusing it costs a
// conforming peer nothing.
func TestPeerIKERekeyRefusesTheSPIThisEndAlreadyOffered(t *testing.T) {
	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	const inFlight = 0x2122232425262728
	const free = 0x3132333435363738
	const retained = 0x4142434445464748
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	for name, offered := range map[string]uint64{
		"the SPI this end has in flight": inFlight,
		"the current SA's initiator SPI": spiI,
		"the current SA's responder SPI": spiR,
		"a retained SA's initiator SPI":  retained,
		"an SPI nothing else holds":      free,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR,
				skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
			mux, _ := lifecycleMuxes(t)
			s := &Session{mux: mux, current: ctx, old: &ikeContext{suite: suite, spiI: retained, spiR: retained + 1},
				localRekey: &ikeRekey{old: ctx, spiI: inFlight}}
			proposed := make([]byte, 8)
			binary.BigEndian.PutUint64(proposed, offered)
			raw, err := s.handleIKERekey(ctx, 0, []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE,
					SPI: proposed, Transforms: ikeProposal().Transforms}})},
				{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{7}, 32))},
				{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
			})
			if err != nil {
				t.Fatal(err)
			}
			header, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(suite, ctx.skei, raw, header)
			if err != nil {
				t.Fatal(err)
			}
			refused := false
			if payload := findType(inner, PayloadN); payload != nil {
				notify, err := DecodeNotify(payload.Body)
				if err != nil {
					t.Fatal(err)
				}
				refused = notify.Type == N_NO_PROPOSAL_CHOSEN
			}
			if want := offered != free; refused != want {
				t.Errorf("offering %#x was refused=%v, want %v", offered, refused, want)
			}
			// The accepted arm answers with a whole SA, so the three refusals
			// above are not all failing somewhere earlier for a shared reason.
			if offered == free && findType(inner, PayloadSA) == nil {
				t.Errorf("an SPI nothing else holds drew no SA payload: %v", inner)
			}
		})
	}
}

// A peer-initiated IKE rekey costs a key exchange, a shared secret, a full key
// derivation and a registration in the hub's SPI map, on the goroutine that
// also runs this session's dead peer detection and its Delete handling, and
// the request plus the Delete that lets the peer ask again are 282 bytes. The
// gate keeps that from being about 33 Mbit/s of someone else's bandwidth. Its Child-path sibling has had a test since both were added,
// and this one did not, so the asymmetry was an accident.
func TestPeerIKERekeyIsRateLimited(t *testing.T) {
	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	ask := func(t *testing.T, s *Session, ctx *ikeContext) []RawPayload {
		t.Helper()
		proposed := make([]byte, 8)
		binary.BigEndian.PutUint64(proposed, 0x2122232425262728)
		raw, err := s.handleIKERekey(ctx, 0, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE,
				SPI: proposed, Transforms: ikeProposal().Transforms}})},
			{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{7}, 32))},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		})
		if err != nil {
			t.Fatal(err)
		}
		header, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ctx.skei, raw, header)
		if err != nil {
			t.Fatal(err)
		}
		return inner
	}
	session := func(t *testing.T) (*Session, *ikeContext) {
		t.Helper()
		mux, _ := lifecycleMuxes(t)
		ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR,
			skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
		return &Session{mux: mux, current: ctx, started: time.Now()}, ctx
	}

	t.Run("the first is answered", func(t *testing.T) {
		s, ctx := session(t)
		if findType(ask(t, s, ctx), PayloadSA) == nil {
			t.Error("the first peer rekey was refused, so the arm below proves nothing")
		}
	})
	t.Run("a second inside the interval is refused", func(t *testing.T) {
		s, ctx := session(t)
		// The record one accepted rekey leaves, without the state a completed
		// one also leaves: this end is otherwise willing, so a refusal here is
		// the rate gate and nothing else.
		s.lastPeerIKERekey.Store(int64(time.Since(s.started)) + 1)
		payload := findType(ask(t, s, ctx), PayloadN)
		if payload == nil {
			t.Fatal("a second peer rekey inside the interval was answered with a whole SA")
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			t.Fatal(err)
		}
		if notify.Type != N_TEMPORARY_FAILURE {
			t.Errorf("the refusal is notify type %d, want TEMPORARY_FAILURE", notify.Type)
		}
	})
}

// A local failure answering a peer's rekey is not the peer's fault and not a
// reason to lose the SA. Returning an error instead sends Run down the
// teardown path, so a transient shortage on this side drops a working session
// and every route through it. RFC 7296 section 1.3.1: "A failed attempt to
// create a Child SA SHOULD NOT tear down the IKE SA: there is no reason to
// lose the work done to set up the IKE SA."
func TestLocalFailureAnsweringARekeyIsTemporary(t *testing.T) {
	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	proposed := make([]byte, 8)
	binary.BigEndian.PutUint64(proposed, 0x2122232425262728)
	request := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE,
			SPI: proposed, Transforms: ikeProposal().Transforms}})},
		{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{7}, 32))},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}

	for name, breaks := range map[string]func(*Session, *transport.Mux){
		"the nonce source fails": func(s *Session, _ *transport.Mux) {
			s.ikeRekeyNonce = func([]byte) error { return errors.New("no entropy") }
		},
		// A peer holding two sessions with this node knows an SPI the hub's
		// map already carries, so it can make this registration fail.
		"the SPI is already taken": func(_ *Session, other *transport.Mux) {
			if err := other.RegisterIKE(0x2122232425262728); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mux, other := lifecycleMuxes(t)
			ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR,
				skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
			s := &Session{mux: mux, current: ctx, started: time.Now()}
			breaks(s, other)

			raw, err := s.handleIKERekey(ctx, 0, request)
			if err != nil {
				t.Fatalf("a local failure was returned as an error, which Run turns into a teardown: %v", err)
			}
			header, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(suite, ctx.skei, raw, header)
			if err != nil {
				t.Fatal(err)
			}
			payload := findType(inner, PayloadN)
			if payload == nil {
				t.Fatal("a local failure answered with a whole SA")
			}
			notify, err := DecodeNotify(payload.Body)
			if err != nil {
				t.Fatal(err)
			}
			if notify.Type != N_TEMPORARY_FAILURE {
				t.Errorf("the answer is notify type %d, want TEMPORARY_FAILURE", notify.Type)
			}
		})
	}
}

// Two contexts can be routed by one SPI: a peer that names back the SPI this
// end published, and the shapes a simultaneous rekey passes through. Dropping
// either one must not take the registration with it, because the other is
// still the session's way of receiving IKE, and a mux that has forgotten it
// refuses every datagram for the session while ESP keeps flowing.
//
// Every case here probes from a second mux on the same hub, because
// registering an SPI a mux already owns succeeds: only another mux can tell
// held from released.
func TestDroppingOneContextKeepsAnSPIAnotherStillUses(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := func(spiI uint64) *ikeContext { return &ikeContext{suite: suite, spiI: spiI, spiR: spiI + 1} }

	for name, shared := range map[string]bool{
		"a retained context shares the current one's SPI": true,
		"a retained context has an SPI of its own":        false,
	} {
		t.Run(name, func(t *testing.T) {
			mux, other := lifecycleMuxes(t)
			retained := ctx(0x1111)
			current := ctx(0x3333)
			if shared {
				current = ctx(retained.spiI)
			}
			s := &Session{mux: mux, current: current, old: retained}
			if err := mux.RegisterIKE(retained.spiI); err != nil {
				t.Fatal(err)
			}
			if !s.removeRetainedContext(retained) {
				t.Fatal("the retained context was not dropped")
			}
			err := other.RegisterIKE(retained.spiI)
			if shared && err == nil {
				t.Error("dropping it released an SPI the current context is still routed by")
			}
			if !shared && err != nil {
				t.Errorf("dropping a context nothing else shares kept its SPI: %v", err)
			}
		})
	}

	// retainOldLocked is the same rule on the other path, where a second rekey
	// displaces a retained context rather than a Delete dropping it.
	for name, shared := range map[string]bool{
		"a displaced context shares the replacement's SPI": true,
		"a displaced context has an SPI of its own":        false,
	} {
		t.Run(name, func(t *testing.T) {
			mux, other := lifecycleMuxes(t)
			displaced := ctx(0x4444)
			replacement := ctx(0x7777)
			if shared {
				replacement = ctx(displaced.spiI)
			}
			s := &Session{mux: mux, current: ctx(0x5555), old: displaced}
			if err := mux.RegisterIKE(displaced.spiI); err != nil {
				t.Fatal(err)
			}
			s.retainOldLocked(replacement)
			err := other.RegisterIKE(displaced.spiI)
			if shared && err == nil {
				t.Error("displacing a context released an SPI its replacement is routed by")
			}
			if !shared && err != nil {
				t.Errorf("displacing a context nothing else shares kept its SPI: %v", err)
			}
		})
	}
}

// The replacement is current from the moment the exchange completes, so the
// rekey has taken effect whatever the Delete of the old SA then does. RFC 7296
// section 2.8 has the initiator delete the replaced SA, and a peer that
// deletes it first is the same outcome. Reporting the failure would cost a
// backoff and a second rekey this end does not need.
func TestDeleteOfAReplacedIKESAIsBestEffort(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32),
		skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1),
		ikeRekeyNonce: func(n []byte) error {
			copy(n, bytes.Repeat([]byte{1}, len(n)))
			return nil
		}}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()

	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	request := <-s.requests
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, 22)
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi,
			Transforms: []Transform{
				{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
				{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
				{Type: TransDH, ID: DH_CURVE25519},
			}}})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}}

	// The Delete of the SA the rekey replaced, refused. A peer that deleted it
	// first is exactly this from here.
	deleteRequest := <-s.requests
	if deleteRequest.exchange != INFORMATIONAL {
		t.Fatalf("the exchange after the rekey is %d, want the INFORMATIONAL that retires the old SA", deleteRequest.exchange)
	}
	deleteRequest.result <- requestResult{err: errors.New("the peer already deleted it")}

	if err := <-done; err != nil {
		t.Errorf("a refused Delete failed a rekey that had already taken effect: %v", err)
	}
	if current, _ := s.contexts(); current == old {
		t.Error("the replacement is not current, so the rekey did not take effect")
	}
}
