// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"context"
	"net"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// what a list left out holds, each kind's names in the order a node runs them
var (
	everyCipher = []string{"aes256gcm", "aes128gcm", "chacha20poly1305"}
	everyPRF    = []string{"sha384", "sha256"}
	everyKex    = []string{"x25519", "p384", "p256"}
)

// drawnList draws a list left out or a run of distinct names from every in the order drawn
func drawnList(tc hegel.TestCase, every []string) []string {
	if hegel.Draw(tc, hegel.WeightedBooleans(1.0/4)) {
		return nil
	}
	remaining := slices.Clone(every)
	out := make([]string, 0, len(every))
	for range hegel.Draw(tc, pbt.Spanning(1, len(every))) {
		at := hegel.Draw(tc, hegel.Integers(0, len(remaining)-1))
		out = append(out, remaining[at])
		remaining = slices.Delete(remaining, at, at+1)
	}
	return out
}

// firstShared is the first name of the responder's list the initiator's holds, a list left out holding every name
func firstShared(responder, initiator, every []string) string {
	if responder == nil {
		responder = every
	}
	if initiator == nil {
		initiator = every
	}
	for _, name := range responder {
		if slices.Contains(initiator, name) {
			return name
		}
	}
	return ""
}

// two ends whose lists meet in every type run, at both ends, the first transform of each responder list the initiator's holds
// two ends apart in one type are refused with NO_PROPOSAL_CHOSEN, in IKE_SA_INIT for a type of the IKE SA and in IKE_AUTH for the Child SA's cipher
// RFC 7296 section 3.3.4: "The implementation MUST reject SA proposals that are not authorized by these IKE suite controls."
func TestHandshakeRunsTheResponderFirstChoiceOrIsRefused(t *testing.T) {
	h := newResponderHarness(t, nil)
	probe, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { probe.Close() })
	pbt.Check(t, func(ht *hegel.T) {
		var drawn [2]Crypto
		for i := range drawn {
			drawn[i] = Crypto{
				IKE: IKESuites{Cipher: drawnList(ht, everyCipher), PRF: drawnList(ht, everyPRF), Kex: drawnList(ht, everyKex)},
				ESP: ESPSuites{Cipher: drawnList(ht, everyCipher)},
			}
		}
		dialing, answering := drawn[0], drawn[1]
		want := Suite{
			IKECipher: firstShared(answering.IKE.Cipher, dialing.IKE.Cipher, everyCipher),
			IKEPRF:    firstShared(answering.IKE.PRF, dialing.IKE.PRF, everyPRF),
			IKEKex:    firstShared(answering.IKE.Kex, dialing.IKE.Kex, everyKex),
			ESPCipher: firstShared(answering.ESP.Cipher, dialing.ESP.Cipher, everyCipher),
		}
		initiatorLists, responderLists := suitesOf(ht, dialing), suitesOf(ht, answering)
		h.lists.Store(&responderLists)
		switch {
		case want.IKECipher == "" || want.IKEPRF == "" || want.IKEKex == "":
			spiI := randUint64Nonzero()
			if err := probe.RegisterIKE(spiI); err != nil {
				ht.Fatal(err)
			}
			offer := encodeTestSAInit(ht, spiI, bytes.Repeat([]byte{1}, 32), initiatorLists.ikeProposal(initiatorLists.kexGroups()[0].ID), nil)
			reply := statelessAnswer(ht, probe, offer, "an offer the lists do not meet drew no answer")
			if got := firstTestNotify(ht, reply); got.Type != N_NO_PROPOSAL_CHOSEN {
				ht.Fatalf("lists apart in a type of the IKE SA answered notify %d, want NO_PROPOSAL_CHOSEN", got.Type)
			}
		case want.ESPCipher == "":
			inner, err := answerIKEAuth(ht, h, responderLists, initiatorLists.espProposal([]byte{0, 0, 0, 9}))
			if err == nil || findType(inner, PayloadAUTH) == nil || notifyIn(ht, inner) != N_NO_PROPOSAL_CHOSEN {
				ht.Fatalf("lists apart in the Child SA's cipher answered %v, %v, want AUTH and NO_PROPOSAL_CHOSEN", inner, err)
			}
		default:
			cfg := h.peerConfig()
			cfg.Suites = func() Suites { return initiatorLists }
			ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
			defer cancel()
			initiator, err := InitiateContext(ctx, cfg)
			if err != nil {
				ht.Fatalf("lists meeting in every type failed the handshake: %v", err)
			}
			defer initiator.Mux().Close()
			var responder *Session
			select {
			case responder = <-h.sessions:
				<-h.identities
			case <-ctx.Done():
				ht.Fatal("the responder handed over no session")
			}
			defer responder.Mux().Close()
			if got := initiator.Suite(); got != want {
				ht.Fatalf("the initiator runs %+v, want %+v", got, want)
			}
			if got := responder.Suite(); got != want {
				ht.Fatalf("the responder runs %+v, want %+v", got, want)
			}
		}
	})
}
