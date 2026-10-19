// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
)

// a peer's IKE_SA_INIT offer of every transform a node writing none of the cap.crypto lists takes, in one proposal with Curve25519 first
func ikeProposal() Proposal { return combinedProposal(nil, Suites{}.ikePRFs()) }

// a peer's offer replacing an IKE SA whose PRF is prfID, every cipher and group in one proposal
func ikeRekeyProposal(spi []byte, prfID uint16) Proposal {
	return combinedProposal(spi, Suites{}.rekeyPRFs(prfID))
}

func combinedProposal(spi []byte, prfs []Transform) Proposal {
	var lists Suites
	transforms := slices.Concat(lists.ikeCiphers(), prfs)
	for _, entry := range lists.kexEntries() {
		transforms = append(transforms, Transform{Type: TransDH, ID: entry.group})
	}
	return Proposal{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: transforms}
}

// the offers of a node that writes none of the cap.crypto lists
func espProposal(spi []byte) Proposal { return Suites{}.espProposal(spi) }
func espRekeyProposal(spi []byte, old ChildSA) Proposal {
	return Suites{}.espRekeyProposal(spi, old)
}

// the transforms the cap.crypto names stand for, as a proposal carries them
var (
	encrAES256 = Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256}
	encrAES128 = Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}
	encrChaCha = Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}
	prfSHA384  = Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_384}
	prfSHA256  = Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256}
	dhX25519   = Transform{Type: TransDH, ID: DH_CURVE25519}
	dhP256     = Transform{Type: TransDH, ID: DH_ECP_256}
	esnNone    = Transform{Type: TransESN, ID: ESN_NO}
)

// suitesOf resolves lists a test wrote to be valid
func suitesOf(t testing.TB, c Crypto) Suites {
	t.Helper()
	suites, err := c.Suites()
	if err != nil {
		t.Fatal(err)
	}
	return suites
}

// a node offers one IKE SA proposal for each kex entry, numbered from 1 in the order the list gives, each holding every cipher and PRF
// a node that writes no list offers the entries in the order kexNames gives
// a written list offers its names in the order written
func TestListsResolveToOffersInTheirOrder(t *testing.T) {
	spi := []byte{1, 2, 3, 4}
	every := "0300000c01000014800e0100" + "0300000c01000014800e0080" + "030000080100001c" + "0300000802000006" + "0300000802000005"
	written := "030000080100001c" + "0300000c01000014800e0080" + "0300000802000005"
	for name, test := range map[string]struct {
		crypto   Crypto
		ike, esp string
	}{
		"every list left out": {
			ike: "0200004001010006" + every + "000000080400001f" +
				"0200004002010006" + every + "0000000804000014" +
				"0000004003010006" + every + "0000000804000013",
			esp: "0000003401030404" + "01020304" + "0300000c01000014800e0100" + "0300000c01000014800e0080" + "030000080100001c" + "0000000805000000",
		},
		"every list written": {
			crypto: Crypto{
				IKE: IKESuites{Cipher: []string{"chacha20poly1305", "aes128gcm"}, PRF: []string{"sha256"}, Kex: []string{"p256", "x25519"}},
				ESP: ESPSuites{Cipher: []string{"aes128gcm"}},
			},
			ike: "0200002c01010004" + written + "0000000804000013" +
				"0000002c02010004" + written + "000000080400001f",
			esp: "0000002001030402" + "01020304" + "0300000c01000014800e0080" + "0000000805000000",
		},
	} {
		t.Run(name, func(t *testing.T) {
			suites := suitesOf(t, test.crypto)
			if got := hex.EncodeToString(EncodeSA(suites.ikeProposals(suites.kexEntries()[0].group))); got != test.ike {
				t.Errorf("the IKE_SA_INIT offer is %s, want %s", got, test.ike)
			}
			if got := hex.EncodeToString(EncodeSA([]Proposal{suites.espProposal(spi)})); got != test.esp {
				t.Errorf("the Child SA offer is %s, want %s", got, test.esp)
			}
		})
	}
}

// Validate refuses a list no session negotiates from, naming the field and what is wrong with it
// an entry joins with + one ML-KEM method after a classical key exchange, and mlkem1024 waits for the fragmentation of RFC 7383
// and an ML-KEM name runs only after a classical exchange
func TestListsRefuseWhatNoSessionNegotiates(t *testing.T) {
	for _, test := range []struct {
		crypto Crypto
		want   string
	}{
		{Crypto{IKE: IKESuites{Cipher: []string{}}}, "cap.crypto ike cipher is empty"},
		{Crypto{IKE: IKESuites{PRF: []string{}}}, "cap.crypto ike prf is empty"},
		{Crypto{IKE: IKESuites{Kex: []string{}}}, "cap.crypto ike kex is empty"},
		{Crypto{ESP: ESPSuites{Cipher: []string{}}}, "cap.crypto esp cipher is empty"},
		{Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm", "aes128gcm", "aes256gcm"}}}, "cap.crypto ike cipher names aes256gcm twice"},
		{Crypto{IKE: IKESuites{PRF: []string{"sha256", "sha256"}}}, "cap.crypto ike prf names sha256 twice"},
		{Crypto{IKE: IKESuites{Kex: []string{"p256", "x25519", "p256"}}}, "cap.crypto ike kex names p256 twice"},
		{Crypto{ESP: ESPSuites{Cipher: []string{"chacha20poly1305", "chacha20poly1305"}}}, "cap.crypto esp cipher names chacha20poly1305 twice"},
		{Crypto{IKE: IKESuites{Cipher: []string{"AES256GCM"}}}, `cap.crypto ike cipher names "AES256GCM", which is not one of aes256gcm, aes128gcm and chacha20poly1305`},
		{Crypto{IKE: IKESuites{PRF: []string{"sha384", "sha512"}}}, `cap.crypto ike prf names "sha512", which is not one of sha384 and sha256`},
		{Crypto{IKE: IKESuites{Kex: []string{"x448"}}}, `cap.crypto ike kex names "x448", which is not one of x25519, p384 and p256`},
		{Crypto{ESP: ESPSuites{Cipher: []string{"sha256"}}}, `cap.crypto esp cipher names "sha256", which is not one of aes256gcm, aes128gcm and chacha20poly1305`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519", "x25519+mlkem1024"}}},
			`cap.crypto ike kex entry "x25519+mlkem1024" joins mlkem1024, whose IKE_INTERMEDIATE messages pass 1500 octets and need the IKE fragmentation of RFC 7383, which is not implemented`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519+p256"}}},
			`cap.crypto ike kex entry "x25519+p256" joins p256, and an entry joins only an ML-KEM method after its first, one of mlkem768 and mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"p384+mlkem768+mlkem768"}}},
			`cap.crypto ike kex entry "p384+mlkem768+mlkem768" joins 2 key exchanges after its first, and an entry joins one`},
		{Crypto{IKE: IKESuites{Kex: []string{"p384+mlkem1024+mlkem512"}}},
			`cap.crypto ike kex entry "p384+mlkem1024+mlkem512" names "mlkem512", which is not one of x25519, p384, p256, mlkem768 and mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519+mlkem512"}}},
			`cap.crypto ike kex entry "x25519+mlkem512" names "mlkem512", which is not one of x25519, p384, p256, mlkem768 and mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"mlkem768"}}},
			`cap.crypto ike kex entry "mlkem768" starts with mlkem768, which runs only after a classical key exchange, as in x25519+mlkem768`},
		{Crypto{IKE: IKESuites{Kex: []string{"mlkem1024+p384"}}},
			`cap.crypto ike kex entry "mlkem1024+p384" starts with mlkem1024, which runs only after a classical key exchange, as in x25519+mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519+x448"}}},
			`cap.crypto ike kex entry "x25519+x448" names "x448", which is not one of x25519, p384, p256, mlkem768 and mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519+"}}},
			`cap.crypto ike kex entry "x25519+" names "", which is not one of x25519, p384, p256, mlkem768 and mlkem1024`},
		{Crypto{IKE: IKESuites{Kex: []string{"x25519+mlkem768", "x25519+mlkem768"}}}, "cap.crypto ike kex names x25519+mlkem768 twice"},
	} {
		err := test.crypto.Validate()
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%+v was refused with %v, want %q", test.crypto, err, test.want)
		}
	}
	every := Crypto{
		IKE: IKESuites{Cipher: []string{"chacha20poly1305", "aes256gcm", "aes128gcm"}, PRF: []string{"sha256", "sha384"}, Kex: []string{"p256", "p384", "x25519"}},
		ESP: ESPSuites{Cipher: []string{"aes128gcm", "chacha20poly1305", "aes256gcm"}},
	}
	if err := every.Validate(); err != nil {
		t.Errorf("every name in another order was refused: %v", err)
	}
	joined := Crypto{IKE: IKESuites{Kex: []string{"p256+mlkem768", "x25519", "x25519+mlkem768", "p384+mlkem768"}}}
	if err := joined.Validate(); err != nil {
		t.Errorf("entries joining mlkem768 were refused: %v", err)
	}
}

// a reload names each list it changed by its key
// a list written out as the one a node runs without it is no change
func TestChangedNamesEachListByItsKey(t *testing.T) {
	written := suitesOf(t, Crypto{
		IKE: IKESuites{Cipher: []string{"aes256gcm", "aes128gcm", "chacha20poly1305"}, PRF: []string{"sha384", "sha256"}, Kex: []string{"x25519", "p384", "p256"}},
		ESP: ESPSuites{Cipher: []string{"aes256gcm", "aes128gcm", "chacha20poly1305"}},
	})
	if got := (Suites{}).Changed(written); len(got) != 0 {
		t.Errorf("writing out the lists a node runs without them changed %q", got)
	}
	reordered := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256", "sha384"}}})
	if got := (Suites{}).Changed(reordered); !slices.Equal(got, []string{"cap.crypto.ike.prf"}) {
		t.Errorf("reordering ike prf changed %q", got)
	}
	every := suitesOf(t, Crypto{
		IKE: IKESuites{Cipher: []string{"aes128gcm"}, PRF: []string{"sha256"}, Kex: []string{"p256"}},
		ESP: ESPSuites{Cipher: []string{"chacha20poly1305"}},
	})
	if got, want := every.Changed(Suites{}), []string{"cap.crypto.ike.cipher", "cap.crypto.ike.prf", "cap.crypto.ike.kex", "cap.crypto.esp.cipher"}; !slices.Equal(got, want) {
		t.Errorf("changing every list changed %q, want %q", got, want)
	}
}

// a session names each SA's transforms as cap.crypto spells them, a Child SA keyed by a key exchange of its own with its group after a /
func TestSuiteNamesTransformsAsTheListsDo(t *testing.T) {
	ikeSA := ikeSuite(SASuite{EncrID: ENCR_CHACHA20_POLY1305, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_384})
	if got := ikeSA.IKE(); got != "chacha20poly1305/sha256/p384" {
		t.Errorf("the IKE SA is named %s", got)
	}
	cipher, kex := childSuite(ChildSA{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256, LocalSPI: 1}, DH_CURVE25519)
	if got := (Suite{ESPCipher: cipher, ESPKex: kex}).ESP(); got != "chacha20poly1305/x25519" {
		t.Errorf("a Child SA keyed by its own X25519 exchange is named %s", got)
	}
	cipher, kex = childSuite(ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 1}, 0)
	if got := (Suite{ESPCipher: cipher, ESPKex: kex}).ESP(); got != "aes128gcm" {
		t.Errorf("a Child SA keyed from SK_d alone is named %s", got)
	}
	// a peer's IKE SA in a transform no list names still reads as its type and number
	if got := transformName(Transform{Type: TransEncr, ID: 12, KeyLengthBits: 128}); got != "1:12" {
		t.Errorf("a cipher no list names is named %s", got)
	}
	if got := (&Session{}).Suite(); got != (Suite{}) || got.IKE() != "" || got.ESP() != "" {
		t.Errorf("a session no handshake built is named %+v", got)
	}
}

// sealedAnswer is the payloads of an answer a session built under ctx
func sealedAnswer(t testing.TB, ctx *ikeContext, raw []byte) []RawPayload {
	t.Helper()
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(ctx.suite, ctx.localEncryptionKey(), raw, message)
	if err != nil {
		t.Fatal(err)
	}
	return inner
}

// notifyIn is the type of the notify among payloads, or zero where they carry none
func notifyIn(t testing.TB, payloads []RawPayload) NotifyType {
	t.Helper()
	payload := findType(payloads, PayloadN)
	if payload == nil {
		return 0
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatal(err)
	}
	return notify.Type
}

// a responder answers an IKE_SA_INIT proposal its lists share no transform of one type with NO_PROPOSAL_CHOSEN
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
func TestResponderRefusesAnIKESAInitItsListsDoNotMeet(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	// encodeTestSAInit writes its KE in X25519, the one group offered
	offer := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{encrAES256, prfSHA384, dhX25519}}
	for _, test := range []struct {
		name    string
		lists   Crypto
		refused bool
	}{
		{"cipher", Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm", "chacha20poly1305"}}}, true},
		{"prf", Crypto{IKE: IKESuites{PRF: []string{"sha256"}}}, true},
		{"kex", Crypto{IKE: IKESuites{Kex: []string{"p384", "p256"}}}, true},
		{"none", Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm", "aes256gcm"}, PRF: []string{"sha256", "sha384"}, Kex: []string{"p256", "x25519"}}}, false},
	} {
		t.Run("lists apart in "+test.name, func(t *testing.T) {
			suites := suitesOf(t, test.lists)
			h.lists.Store(&suites)
			spiI := randUint64Nonzero()
			if err := mux.RegisterIKE(spiI); err != nil {
				t.Fatal(err)
			}
			reply := statelessAnswer(t, mux, encodeTestSAInit(t, spiI, bytes.Repeat([]byte{1}, 32), offer, nil), "the offer drew no answer")
			message, err := DecodeMessage(reply)
			if err != nil {
				t.Fatal(err)
			}
			if !test.refused {
				if message.find(PayloadSA) == nil {
					t.Errorf("lists meeting the offer in every type answered %v", message.Payloads)
				}
				return
			}
			if got := firstTestNotify(t, reply); got.Type != N_NO_PROPOSAL_CHOSEN {
				t.Errorf("lists apart in %s answered notify %d, want NO_PROPOSAL_CHOSEN", test.name, got.Type)
			}
		})
	}
}

// a responder answers an IKE_AUTH with its AUTH and NO_PROPOSAL_CHOSEN where its esp cipher list shares no cipher with the Child SA offer
// and an esp cipher list meeting the offer takes the cipher it lists first
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
func TestResponderRefusesAnIKEAuthChildSAItsListsDoNotMeet(t *testing.T) {
	h := newResponderHarness(t, nil)
	offer := Proposal{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 9}, Transforms: []Transform{encrAES256, encrChaCha, esnNone}}
	inner, err := answerIKEAuth(t, h, suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm"}}}), offer)
	if err == nil {
		t.Fatal("a Child SA offer the lists share no cipher with was taken")
	}
	if findType(inner, PayloadAUTH) == nil || findType(inner, PayloadSA) != nil {
		t.Fatalf("the refusal carried %v, want this end's AUTH and no Child SA", inner)
	}
	if got := notifyIn(t, inner); got != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("the refusal carried notify %d, want NO_PROPOSAL_CHOSEN", got)
	}
	inner, err = answerIKEAuth(t, h, suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"aes128gcm", "chacha20poly1305", "aes256gcm"}}}), offer)
	if err != nil {
		t.Fatal(err)
	}
	sa := findType(inner, PayloadSA)
	if sa == nil {
		t.Fatalf("the answer carried %v, want a Child SA", inner)
	}
	if _, encr, _, err := decodeChildProposal(sa.Body, offer.Transforms); err != nil || encr.ID != ENCR_CHACHA20_POLY1305 {
		t.Errorf("the answer chose %+v, %v, want the first cipher of the list the offer holds", encr, err)
	}
}

// a responder answers a peer's rekey its lists share no transform of one type with NO_PROPOSAL_CHOSEN
// it keeps the SA and asks Run to check its SAs
// an IKE SA rekey naming another PRF than the SA's is refused the same way
// so is one naming the SA's PRF where ike prf left it out
// no rekey changes the PRF
// and so is one offering the group NONE, or no group at all
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
// RFC 7296 section 2.18: "an initiator MUST NOT propose the value "NONE" for the Diffie-Hellman transform, and a responder MUST NOT accept such a proposal."
// RFC 7296 section 2.18: "Therefore, implementations MUST perform a new Diffie-Hellman exchange when rekeying the IKE SA."
func TestResponderRefusesARekeyItsListsDoNotMeet(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	for name, test := range map[string]struct {
		lists      Crypto
		transforms []Transform
		ike        bool
		// ke is the group of the request's KE payload, zero for none
		ke      uint16
		refused bool
		// esp names the Child SA a Child SA rekey the lists meet leaves the session running
		esp string
	}{
		"an IKE SA rekey in a cipher ike cipher left out": {
			lists: Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm"}}}, transforms: []Transform{encrAES128, prfSHA256, dhX25519}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey in a group ike kex left out": {
			lists: Crypto{IKE: IKESuites{Kex: []string{"p256"}}}, transforms: []Transform{encrAES128, prfSHA256, dhX25519}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey keeping a PRF ike prf left out": {
			lists: Crypto{IKE: IKESuites{PRF: []string{"sha384"}}}, transforms: []Transform{encrAES128, prfSHA256, prfSHA384, dhX25519}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey changing the PRF": {
			transforms: []Transform{encrAES128, prfSHA384, dhX25519}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey offering the group NONE": {
			transforms: []Transform{encrAES128, prfSHA256, {Type: TransDH}}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey offering no group": {
			transforms: []Transform{encrAES128, prfSHA256}, ike: true, ke: DH_CURVE25519, refused: true},
		"an IKE SA rekey the lists meet": {
			transforms: []Transform{encrAES128, prfSHA256, dhX25519}, ike: true, ke: DH_CURVE25519},
		"a Child SA rekey in a cipher esp cipher left out": {
			lists: Crypto{ESP: ESPSuites{Cipher: []string{"aes256gcm", "chacha20poly1305"}}}, transforms: []Transform{encrAES128, esnNone}, refused: true},
		"a Child SA rekey the lists meet": {
			lists: Crypto{ESP: ESPSuites{Cipher: []string{"aes256gcm", "chacha20poly1305"}}}, transforms: []Transform{encrAES128, encrChaCha, esnNone}, esp: "chacha20poly1305"},
		"a Child SA rekey with a key exchange in a group ike kex left out": {
			lists: Crypto{IKE: IKESuites{Kex: []string{"p256"}}}, transforms: []Transform{encrAES128, dhX25519, esnNone}, ke: DH_CURVE25519, refused: true},
		"a Child SA rekey with a key exchange in a group ike kex holds": {
			transforms: []Transform{encrAES128, dhX25519, esnNone}, ke: DH_CURVE25519, esp: "aes128gcm/x25519"},
	} {
		t.Run(name, func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			s := answeringSession(t, mux, suite, old, 0, suitesOf(t, test.lists))
			ctx := s.current
			answer := answerPeerRekey(t, s, test.ike, peerRekeyOf(t, s, test.ike, []Proposal{{Transforms: test.transforms}}, test.ke))
			if !test.refused {
				if answer.proposal.Number == 0 {
					t.Errorf("a rekey the lists meet was answered %+v", answer)
				}
				if got := s.Suite().ESP(); test.esp != "" && got != test.esp {
					t.Errorf("the session runs %s after the rekey, want %s", got, test.esp)
				}
				return
			}
			if answer.notify.Type != N_NO_PROPOSAL_CHOSEN {
				t.Errorf("the refusal carried notify %d, want NO_PROPOSAL_CHOSEN", answer.notify.Type)
			}
			if current, _ := s.contexts(); current != ctx || s.currentChild().LocalSPI != old.LocalSPI {
				t.Error("a refused rekey replaced the SA it named")
			}
			if len(s.rechecks) != 1 {
				t.Error("a refused rekey left Run to find out about the lists at the next reload")
			}
		})
	}
}

// a peer's rekey of a Child SA is answered in that SA's cipher where the offer and esp cipher hold it, ahead of the one the list puts first
// and from the list where the offer leaves it out
// a peer whose own lists dropped that cipher offers such a rekey
// RFC 7296 section 2.8: "the new Child SA SHOULD NOT have different Traffic Selectors and algorithms than the old one"
func TestPeerRekeyIsAnsweredInTheCipherItReplaces(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	lists := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{"chacha20poly1305", "aes256gcm", "aes128gcm"}}})
	for name, test := range map[string]struct {
		offer []Transform
		want  Transform
	}{
		"an offer holding the cipher":     {[]Transform{encrAES256, encrChaCha, encrAES128, esnNone}, encrAES128},
		"an offer leaving the cipher out": {[]Transform{encrAES256, encrChaCha, esnNone}, Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256}},
	} {
		offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 32}, Transforms: test.offer}})
		selection, err := selectChildRequestProposal(offer, lists.rekeyChoice(old), lists.kexEntries(), 0, groupOptional)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if selection.encryption != test.want {
			t.Errorf("%s was answered in %+v, want %+v", name, selection.encryption, test.want)
		}
	}
}

// a Child SA keyed by a key exchange of its own is unlisted once ike kex leaves out that exchange's group
// one keyed from SK_d alone is held by its cipher alone
func TestChildSAKeyedInAGroupTheListsLeftOutIsUnlisted(t *testing.T) {
	p256Only := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}})
	ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256, PRFID: PRF_HMAC_SHA2_384, DHGroup: DH_ECP_256}}
	child := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	for _, test := range []struct {
		group uint16
		want  string
	}{
		{DH_CURVE25519, "aes128gcm/x25519"},
		{DH_ECP_256, ""},
		{0, ""},
	} {
		s := &Session{current: ctx, Child: child, childGroup: childPFS{spi: child.LocalSPI, group: test.group},
			suites: func() Suites { return p256Only }}
		if got, ikeSA, _ := s.unlisted(); got != test.want || ikeSA != "" {
			t.Errorf("a Child SA keyed in group %d is unlisted as %q beside an IKE SA unlisted as %q, want %q", test.group, got, ikeSA, test.want)
		}
	}
}

// an offer puts first the first proposal whose Transform Type 4 is the KE payload's group, and the rest keep the order of the lists
// at the first offer, at the retry INVALID_KE_PAYLOAD asks for and at an IKE SA rekey alike
// RFC 7296 section 3.3: "If there is more than one, they MUST be ordered from most preferred to least preferred."
// RFC 7296 section 3.4: "SHOULD match the Diffie-Hellman group in the first group in the first proposal, if such exists."
func TestOfferLeadsWithOneProposalInTheKEGroup(t *testing.T) {
	joined := kexEntry{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}
	x25519, p384, p256 := kexEntry{group: DH_CURVE25519}, kexEntry{group: DH_ECP_384}, kexEntry{group: DH_ECP_256}
	spi := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	for name, test := range map[string]struct {
		offer []Proposal
		want  []kexEntry
	}{
		"the first offer, in the group of the first entry": {
			Suites{kex: []kexEntry{joined, p384, x25519}}.ikeProposals(DH_CURVE25519), []kexEntry{joined, p384, x25519},
		},
		"the retry in the group of a later entry": {
			Suites{kex: []kexEntry{p384, joined, p256, x25519}}.ikeProposals(DH_CURVE25519), []kexEntry{joined, p384, p256, x25519},
		},
		"an IKE SA rekey in the group of a later entry": {
			Suites{kex: []kexEntry{p384, joined, p256, x25519}}.ikeRekeyProposals(spi, PRF_HMAC_SHA2_256, DH_CURVE25519), []kexEntry{x25519, p384, p256},
		},
	} {
		var got []kexEntry
		for i, proposal := range test.offer {
			if proposal.Number != uint8(i+1) {
				t.Errorf("%s: proposal %d is numbered %d", name, i+1, proposal.Number)
			}
			var entry kexEntry
			for _, transform := range proposal.Transforms {
				switch {
				case transform.Type == TransDH:
					entry.group = transform.ID
				case additional(transform.Type):
					entry.additions[transform.Type-TransADDKE1] = transform.ID
				}
			}
			got = append(got, entry)
		}
		if !slices.Equal(got, test.want) {
			t.Errorf("%s: offered %+v, want %+v", name, got, test.want)
		}
	}
}

// an initiator offers its lists in IKE_SA_INIT with the KE payload in the first kex group
// and ends the handshake on an answer choosing a transform its lists left out
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
func TestInitiatorRefusesAnIKESAInitAnswerOutsideItsLists(t *testing.T) {
	lists := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}, Kex: []string{"p256", "x25519"}}})
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	peerLoop(t, peer, func() {
		buf := make([]byte, 4096)
		_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
		n, from, err := peer.ReadFromUDP(buf)
		if err != nil || n <= NonESPMarkerLen {
			t.Errorf("no IKE_SA_INIT request arrived: %d bytes, %v", n, err)
			return
		}
		request, err := DecodeMessage(buf[NonESPMarkerLen:n])
		if err != nil {
			t.Error(err)
			return
		}
		if sa := request.find(PayloadSA); sa == nil || !bytes.Equal(sa.Body, EncodeSA(lists.ikeProposals(DH_ECP_256))) {
			t.Errorf("the initiator offered %+v, want its lists", sa)
		}
		if ke := request.find(PayloadKE); ke == nil {
			t.Error("the request carried no KE payload")
		} else if group, _, err := DecodeKE(ke.Body); err != nil || group != DH_ECP_256 {
			t.Errorf("the KE payload is in group %d, %v, want the first kex group", group, err)
		}
		dh, err := GenerateDH(DH_ECP_256)
		if err != nil {
			t.Error(err)
			return
		}
		answer := (&Message{
			Header: Header{SPIInitiator: request.Header.SPIInitiator, SPIResponder: 0x1112131415161718, ExchangeType: IKE_SA_INIT, Flags: FlagResponse},
			Payloads: []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{encrAES256, prfSHA384, dhP256}}})},
				{Type: PayloadKE, Body: EncodeKE(DH_ECP_256, dh.PublicBytes())},
				{Type: PayloadNonce, Body: EncodeNonce(bytes.Repeat([]byte{7}, 32))},
				{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
			},
		}).Encode()
		if _, err := peer.WriteToUDP(withNonESPMarker(answer), from); err != nil {
			t.Error(err)
		}
	})
	_, local, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	remote, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	session, err := InitiateContext(ctx, PeerConfig{
		Local: identity.MustParse("testorg/client:2"), LocalPrivateKey: local,
		Remote: identity.MustParse("testorg/server:1"), RemotePublicKey: remote,
		RemoteAddr: peerAddr.IP, RemotePort: peerAddr.Port,
		Suites: func() Suites { return lists },
	})
	if err == nil {
		session.Mux().Close()
		t.Fatal("the initiator took an answer choosing a cipher its lists left out")
	}
	if !strings.Contains(err.Error(), "unoffered transform 1/20") {
		t.Errorf("the initiator refused with %q, want the cipher its lists left out named", err)
	}
}

// a rekey this end starts offers the cipher of the Child SA it replaces while esp cipher holds it
// and it offers the list once esp cipher does not
// an IKE SA rekey offers the lists with the PRF the SA keeps
// and its KE payload is in the first kex group once kex left out the SA's group
// each refuses an answer choosing a transform its offer left out
// RFC 7296 section 3.3.6: "The initiator of an exchange MUST check that the accepted offer is consistent with one of its proposals, and if not MUST terminate the exchange."
func TestInitiatorRefusesARekeyAnswerOutsideItsLists(t *testing.T) {
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	for name, test := range map[string]struct {
		esp     []string
		offered []Transform
		answer  Transform
	}{
		"a Child SA rekey while esp cipher holds its cipher":   {[]string{"aes256gcm", "aes128gcm"}, []Transform{encrAES128, esnNone}, encrAES256},
		"a Child SA rekey once esp cipher left its cipher out": {[]string{"chacha20poly1305", "aes256gcm"}, []Transform{encrChaCha, encrAES256, esnNone}, encrAES128},
	} {
		t.Run(name, func(t *testing.T) {
			s := newRekeyableSession(t, old)
			lists := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: test.esp}})
			s.suites = func() Suites { return lists }
			done := make(chan error, 1)
			go func() { done <- s.RekeyChild() }()
			rekey := <-s.requests
			payloads, err := decodeChildExchangePayloads(rekey.inner, PRF_HMAC_SHA2_256)
			if err != nil {
				t.Fatal(err)
			}
			proposals, err := DecodeSA(payloads.sa.Body)
			if err != nil || len(proposals) != 1 || !slices.Equal(proposals[0].Transforms, test.offered) {
				t.Errorf("the rekey offered %+v, %v, want %+v", proposals, err, test.offered)
			}
			rekey.result <- requestResult{inner: []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 0x60708090),
					Transforms: []Transform{test.answer, esnNone}}})},
				{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
				{Type: PayloadTSi, Body: fullRangeSelectors()},
				{Type: PayloadTSr, Body: fullRangeSelectors()},
			}}
			// the peer installed what it answered
			// so the refusal deletes it
			orphan := <-s.requests
			if orphan.exchange != INFORMATIONAL {
				t.Errorf("after the refused answer the rekey sent exchange %d, want the Delete", orphan.exchange)
			}
			orphan.result <- requestResult{}
			if err := <-done; err == nil || !strings.Contains(err.Error(), "unoffered transform") {
				t.Errorf("the rekey ended with %v, want the answer's cipher refused", err)
			}
			if s.currentChild().LocalSPI != old.LocalSPI {
				t.Error("a refused answer replaced the Child SA")
			}
		})
	}

	t.Run("an IKE SA rekey of an SA in a group ike kex left out", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_384},
			spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
		lists := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes256gcm", "chacha20poly1305"}, Kex: []string{"p256", "x25519"}}})
		s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return lists }}
		done := make(chan error, 1)
		go func() { done <- s.RekeyIKE() }()
		request := <-s.requests
		sa, ke := findType(request.inner, PayloadSA), findType(request.inner, PayloadKE)
		if sa == nil || ke == nil {
			t.Fatalf("the rekey request carried %v", request.inner)
		}
		proposals, err := DecodeSA(sa.Body)
		want := [][]Transform{{encrAES256, encrChaCha, prfSHA256, dhP256}, {encrAES256, encrChaCha, prfSHA256, dhX25519}}
		if err != nil || len(proposals) != len(want) || !slices.Equal(proposals[0].Transforms, want[0]) || !slices.Equal(proposals[1].Transforms, want[1]) {
			t.Errorf("the rekey offered %+v, %v, want a proposal of each of %+v", proposals, err, want)
		}
		if group, _, err := DecodeKE(ke.Body); err != nil || group != DH_ECP_256 {
			t.Errorf("the KE payload is in group %d, %v, want the first kex group", group, err)
		}
		dh, err := GenerateDH(DH_ECP_256)
		if err != nil {
			t.Fatal(err)
		}
		request.result <- requestResult{inner: []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: binary.BigEndian.AppendUint64(nil, 22),
				Transforms: []Transform{encrAES128, prfSHA256, dhP256}}})},
			{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
			{Type: PayloadKE, Body: EncodeKE(DH_ECP_256, dh.PublicBytes())},
		}}
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "unoffered transform 1/20") {
				t.Errorf("the rekey ended with %v, want the answer's cipher refused by name", err)
			}
		case next := <-s.requests:
			next.result <- requestResult{err: errors.New("nothing answers past the rekey")}
			t.Fatalf("the rekey installed the answer and asked for exchange %d next, then returned %v", next.exchange, <-done)
		}
		if current, _ := s.contexts(); current != ctx {
			t.Error("a refused answer replaced the IKE SA")
		}
	})

	t.Run("an IKE SA rekey asked to retry in a group ike kex left out", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_ECP_256},
			spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
		lists := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256", "x25519"}}})
		s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return lists }}
		done := make(chan error, 1)
		go func() { done <- s.RekeyIKE() }()
		request := <-s.requests
		// p384 is a group this end generates
		// and one its offer left out
		request.result <- requestResult{inner: []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD, Data: binary.BigEndian.AppendUint16(nil, DH_ECP_384)})},
		}}
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "unoffered DH group") {
				t.Errorf("the rekey ended with %v, want the group its offer left out refused", err)
			}
		case retry := <-s.requests:
			retry.result <- requestResult{err: errors.New("nothing answers the retry")}
			t.Fatalf("the rekey retried in a group its offer left out, then returned %v", <-done)
		}
		if current, _ := s.contexts(); current != ctx {
			t.Error("a refused retry replaced the IKE SA")
		}
	})
}

// an IKE SA rekey under lists that left out the SA's PRF sends nothing
// no rekey changes the PRF
// so only the replacement Run starts moves the SA off it
func TestIKESARekeyLeavesAnUnlistedPRFToTheReplacement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519},
		spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	lists := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha384"}}})
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1), suites: func() Suites { return lists }}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrPRFUnlisted) {
			t.Errorf("the rekey ended with %v, want the PRF named unlisted", err)
		}
	case request := <-s.requests:
		request.result <- requestResult{err: errors.New("nothing answers the rekey")}
		t.Fatalf("the rekey sent exchange %d, then returned %v", request.exchange, <-done)
	}
}

// an IKE SA rekey this end starts sends its KE payload in the group the IKE SA runs while kex holds it
// so a peer that chose a group after this end's first takes the rekey in one exchange and keeps the group
// RFC 7296 section 1.3: "The Diffie-Hellman group of the KEi MUST be an element of the group the initiator expects the responder to accept (additional Diffie-Hellman groups can be proposed)."
func TestIKESARekeyKeepsTheGroupThePeerChose(t *testing.T) {
	h := newResponderHarness(t, nil)
	p256 := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}})
	h.lists.Store(&p256)
	var mu sync.Mutex
	rekeys := map[uint32]bool{}
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
			mu.Lock()
			rekeys[header.MessageID] = true
			mu.Unlock()
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	runSession(t, initiator)
	runSession(t, responder)
	if got := initiator.Suite().IKEKex; got != "p256" {
		t.Fatalf("the IKE SA runs %s, want the group the peer chose after this end's first", got)
	}
	if err := initiator.RekeyIKE(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(rekeys) != 1 {
		t.Errorf("the rekey sent %d CREATE_CHILD_SA requests, want one with no INVALID_KE_PAYLOAD before it", len(rekeys))
	}
	if got, peer := initiator.Suite().IKEKex, responder.Suite().IKEKex; got != "p256" || peer != "p256" {
		t.Errorf("the new IKE SA runs %s here and %s at the peer, want the group of the SA it replaced", got, peer)
	}
}

// waitUntil polls cond until it holds, and reports false where answerBudget ran out first
func waitUntil(cond func() bool) bool {
	for deadline := time.Now().Add(answerBudget); !cond(); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			return false
		}
	}
	return true
}

// awaitRecorded waits for r to hold line
func awaitRecorded(t testing.TB, r *recorder, line string) {
	t.Helper()
	if !waitUntil(func() bool { return slices.Contains(r.recorded(), line) }) {
		t.Fatalf("%q was not recorded, only %q", line, r.recorded())
	}
}

// dialSuited dials h's responder with the lists dialing holds, the dialing session recording into dialed
// a non-nil pass carries the sessions' datagrams through a relay that forwards what it reports
// it runs both sessions
// it returns how each Run ended
func dialSuited(t *testing.T, h *responderHarness, dialing *atomic.Pointer[Suites], dialed Recorder, pass func(fromInitiator bool, header *Header, raw []byte) bool) (initiator, responder *Session, initiatorRun, responderRun <-chan error) {
	t.Helper()
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return *dialing.Load() }
	cfg.Events = dialed
	if pass != nil {
		cfg.RemotePort = relay(t, h.remotePort, pass)
	}
	initiator, responder = dialPaused(t, h, cfg)
	return initiator, responder, runSession(t, initiator), runSession(t, responder)
}

// dialPaused dials h's responder with cfg and hands back both sessions before either Run starts
func dialPaused(t *testing.T, h *responderHarness, cfg PeerConfig) (initiator, responder *Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case responder = <-h.sessions:
		<-h.identities
	case <-ctx.Done():
		initiator.Mux().Close()
		t.Fatal("the responder handed over no session")
	}
	return initiator, responder
}

// endedWithin waits for one Run to end
func endedWithin(t *testing.T, run <-chan error, which string) error {
	t.Helper()
	select {
	case err := <-run:
		return err
	case <-time.After(answerBudget):
		t.Fatalf("the %s session did not end", which)
		return nil
	}
}

// a reload whose lists left out the cipher or the group of a live SA rekeys that SA under the lists after a delay drawn within the rekey jitter, the IKE SA first
// and the Child SA once the IKE SA it takes SK_d from holds listed transforms
// the harness runs no jitter, so each rekey starts at once
func TestReloadRekeysAtOnceAnSAWhoseCipherOrGroupItLeftOut(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	initiator, responder, _, _ := dialSuited(t, h, dialing, dialed.record, nil)
	if got := initiator.Suite(); got.IKE() != "aes256gcm/sha384/x25519" || got.ESP() != "aes256gcm" {
		t.Fatalf("the session runs %s and %s before the reload", got.IKE(), got.ESP())
	}
	// the initiator's Run answers a rekey the responder starts after the check Run makes when it starts
	// so only the change of the lists below reaches the SAs
	if err := responder.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	next := suitesOf(t, Crypto{IKE: IKESuites{Kex: []string{"p256"}}, ESP: ESPSuites{Cipher: []string{"chacha20poly1305", "aes128gcm"}}})
	dialing.Store(&next)
	initiator.SuitesChanged()
	const ends = "testorg/client:2>testorg/server:1"
	// the responder lists every cipher and takes the first of them the offer holds
	want := []string{
		"ike.suite.unlisted " + ends + " sa=ike suite=aes256gcm/sha384/x25519 action=rekey",
		"ike.rekey.completed " + ends + " sa=ike suite=aes256gcm/sha384/p256",
		"ike.suite.unlisted " + ends + " sa=child suite=aes256gcm action=rekey",
		"ike.rekey.completed " + ends + " sa=child suite=aes128gcm",
	}
	for _, line := range want {
		awaitRecorded(t, dialed, line)
	}
	var order []string
	for _, line := range dialed.recorded() {
		if slices.Contains(want, line) {
			order = append(order, line)
		}
	}
	if !slices.Equal(order, want) {
		t.Errorf("the session recorded %q, want %q in that order", order, want)
	}
	if got, want := responder.Suite(), initiator.Suite(); got != want {
		t.Errorf("the responder runs %+v and the initiator %+v", got, want)
	}
}

// a reload whose lists still hold every transform of the live SAs leaves them be, an entry joining ML-KEM-768 to the IKE SA's group ahead of its own among them
// and a rekey keeps the cipher of the SA it replaces
func TestReloadLeavesAnSAWhoseTransformsItStillLists(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	initiator, responder, initiatorRun, _ := dialSuited(t, h, dialing, dialed.record, nil)
	next := suitesOf(t, Crypto{
		IKE: IKESuites{Cipher: []string{"aes128gcm", "aes256gcm"}, Kex: []string{"x25519+mlkem768", "x25519", "p384", "p256"}},
		ESP: ESPSuites{Cipher: []string{"aes128gcm", "aes256gcm"}},
	})
	dialing.Store(&next)
	if ended, err := recheck(t, initiator, initiatorRun); ended {
		t.Fatalf("the session ended with %v", err)
	}
	time.Sleep(quietPeriod)
	if got := recordedKind(dialed, "ike.suite.unlisted"); got != 0 {
		t.Fatalf("lists still holding every transform marked %d SAs unlisted: %q", got, dialed.recorded())
	}
	if err := initiator.RekeyChild(); err != nil {
		t.Fatal(err)
	}
	if got := initiator.Suite().ESP(); got != "aes256gcm" || responder.Suite().ESP() != got {
		t.Errorf("the rekey runs %s at the initiator and %s at the responder, want the cipher it replaced", got, responder.Suite().ESP())
	}
}

// a session whose lists changed between its handshake and the start of its Run checks its SAs when Run starts
// a reload's sweep of the live sessions misses one adopted after it
func TestRunChecksTheSAsOfListsChangedBeforeItStarted(t *testing.T) {
	dialed := &recorder{}
	h := newResponderHarness(t, nil)
	dialing := new(atomic.Pointer[Suites])
	dialing.Store(&Suites{})
	cfg := h.peerConfig()
	cfg.Suites = func() Suites { return *dialing.Load() }
	cfg.Events = dialed.record
	initiator, responder := dialPaused(t, h, cfg)
	runSession(t, responder)
	next := suitesOf(t, Crypto{IKE: IKESuites{Cipher: []string{"aes128gcm"}}})
	dialing.Store(&next)
	runSession(t, initiator)
	const ends = "testorg/client:2>testorg/server:1"
	awaitRecorded(t, dialed, "ike.suite.unlisted "+ends+" sa=ike suite=aes256gcm/sha384/x25519 action=rekey")
	awaitRecorded(t, dialed, "ike.rekey.completed "+ends+" sa=ike suite=aes128gcm/sha384/x25519")
}

// a reload whose ike prf left out the PRF of a live IKE SA deletes that SA, whichever end reloaded
// and the next handshake runs a listed PRF
// RFC 7296 section 1.4.1: "Deleting an IKE SA implicitly closes any remaining Child SAs negotiated under it."
func TestReloadLeavingOutThePRFReplacesTheIKESA(t *testing.T) {
	for _, reloading := range []string{"dialing", "answering"} {
		t.Run("the "+reloading+" end", func(t *testing.T) {
			dialed, answered := &recorder{}, &recorder{}
			h := newResponderHarness(t, nil, answered.record)
			dialing := new(atomic.Pointer[Suites])
			dialing.Store(&Suites{})
			initiator, responder, initiatorRun, responderRun := dialSuited(t, h, dialing, dialed.record, nil)
			if got := initiator.Suite().IKEPRF; got != "sha384" {
				t.Fatalf("the IKE SA runs %s before the reload", got)
			}
			sha256Only := suitesOf(t, Crypto{IKE: IKESuites{PRF: []string{"sha256"}}})
			replacing, other, replacingRun, otherRun, record, ends := initiator, responder, initiatorRun, responderRun, dialed, "testorg/client:2>testorg/server:1"
			if reloading == "answering" {
				replacing, other, replacingRun, otherRun, record, ends = responder, initiator, responderRun, initiatorRun, answered, "testorg/server:1>testorg/client:2"
			}
			// the reloading end's Run answers a rekey the other end starts after the check Run makes when it starts
			// so only the change of the lists below reaches the SA
			if err := other.RekeyChild(); err != nil {
				t.Fatal(err)
			}
			if reloading == "answering" {
				h.lists.Store(&sha256Only)
			} else {
				dialing.Store(&sha256Only)
			}
			replacing.SuitesChanged()
			if err := endedWithin(t, replacingRun, reloading); !errors.Is(err, ErrPRFUnlisted) || !strings.Contains(err.Error(), "deleted the IKE SA") {
				t.Errorf("the %s session ended with %v, want its IKE SA deleted for a new handshake", reloading, err)
			}
			awaitRecorded(t, record, "ike.suite.unlisted "+ends+" sa=ike suite=aes256gcm/sha384/x25519 action=replace")
			if err := endedWithin(t, otherRun, "other"); err == nil {
				t.Error("the other end's session outlived the Delete")
			}
			next, _, _, _ := dialSuited(t, h, dialing, nil, nil)
			if got := next.Suite().IKEPRF; got != "sha256" {
				t.Errorf("the next handshake runs %s, want the PRF the lists hold", got)
			}
		})
	}
}
