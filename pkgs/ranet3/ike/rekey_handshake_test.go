// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"errors"
	"log/slog"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// deletesSeen counts the INFORMATIONAL requests an initiator sends through a relay, each Message ID once, so a retransmission counts as the request it repeats
type deletesSeen struct {
	mu  sync.Mutex
	ids []uint32
}

func (d *deletesSeen) pass(fromInitiator bool, header *Header, _ []byte) bool {
	if fromInitiator && header != nil && header.ExchangeType == INFORMATIONAL && !header.IsResponse() {
		d.mu.Lock()
		if !slices.Contains(d.ids, header.MessageID) {
			d.ids = append(d.ids, header.MessageID)
		}
		d.mu.Unlock()
	}
	return true
}

func (d *deletesSeen) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.ids)
}

// hybridSession dials h's responder and hands back both sessions before either Run starts, the initiator's IKE SA keyed as by x25519+mlkem768 and its lists in lists
func hybridSession(t *testing.T, h *responderHarness, lists *atomic.Pointer[Suites], record Recorder, sent *deletesSeen) (initiator, responder *Session) {
	t.Helper()
	cfg := h.peerConfig()
	cfg.Events = record
	cfg.RemotePort = relay(t, h.remotePort, sent.pass)
	initiator, responder = dialPaused(t, h, cfg)
	initiator.current.suite.Additions = [addkeTypes]uint16{ML_KEM_768}
	initiator.suites = func() Suites { return *lists.Load() }
	return initiator, responder
}

// hybridOf is x25519+mlkem768 beside the default classical entries, so an IKE SA of x25519+mlkem768 is listed
var hybridOf = Suites{kex: []kexEntry{{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}, {group: DH_ECP_384}, {group: DH_ECP_256}}}

// a rekey this end owes an IKE SA no CREATE_CHILD_SA can run ends the SA with one Delete and ike.sa.closed, for a new handshake under the lists in force
// that is an SA whose entry has additional key exchanges, since this end runs no IKE_FOLLOWUP_KE, and an SA whose lists hold no entry of one key exchange
// the rekey sends no CREATE_CHILD_SA and counts as no failure
// RFC 9370 section 2.2.4: "If the initiator includes any ADDKE Transform Types in the SA payload (along with Transform Type 4), and if the responder agrees to perform additional key exchanges, then the additional key exchanges are performed in a series of new IKE_FOLLOWUP_KE exchanges that follow the CREATE_CHILD_SA exchange."
func TestIKESAThatNoCreateChildSARekeysIsReplacedByAHandshake(t *testing.T) {
	for name, test := range map[string]struct {
		hybrid bool
		// next is the lists of the reload that forces the rekey
		next Suites
	}{
		"an SA of x25519+mlkem768 whose entry a reload removed": {hybrid: true, next: Suites{}},
		"an SA of x25519 whose lists hold only x25519+mlkem768": {next: Suites{kex: []kexEntry{{group: DH_CURVE25519, additions: [addkeTypes]uint16{ML_KEM_768}}}}},
	} {
		t.Run(name, func(t *testing.T) {
			dialed, sent := &recorder{}, &deletesSeen{}
			h := newResponderHarness(t, nil)
			lists := new(atomic.Pointer[Suites])
			lists.Store(&Suites{})
			if test.hybrid {
				lists.Store(&hybridOf)
			}
			initiator, responder := hybridSession(t, h, lists, dialed.record, sent)
			if !test.hybrid {
				initiator.current.suite.Additions = [addkeTypes]uint16{}
			}
			initiatorRun, responderRun := runSession(t, initiator), runSession(t, responder)
			lists.Store(&test.next)
			initiator.SuitesChanged()
			if err := endedWithin(t, initiatorRun, "dialing"); !errors.Is(err, ErrRekeyByHandshake) {
				t.Errorf("the session ended with %v, want its IKE SA deleted for a new handshake", err)
			}
			if err := endedWithin(t, responderRun, "answering"); err == nil {
				t.Error("the answering session outlived the Delete")
			}
			awaitRecorded(t, dialed, "ike.sa.closed testorg/client:2>testorg/server:1 sa=ike reason=rekey by handshake")
			if got := sent.count(); got != 1 {
				t.Errorf("the session sent %d INFORMATIONAL requests, want the one Delete", got)
			}
			if started, failed := recordedKind(dialed, "ike.rekey.started"), recordedKind(dialed, "ike.rekey.failed"); started != 0 || failed != 0 {
				t.Errorf("the session recorded %d rekeys started and %d failed, want none: %q", started, failed, dialed.recorded())
			}
		})
	}
}

// a rekey that only a new handshake runs, ending while the IKE SA's replacement for a PRF the lists left out is under way, sends no Delete and records no close
// the replacement's Delete is the last request of the SA
// RFC 7296 section 2.8: "After the new equivalent IKE SA is created, the initiator deletes the old IKE SA, and the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
func TestRekeyByHandshakeEndingBehindAReplacementSendsNoSecondDelete(t *testing.T) {
	started := make(chan struct{})
	var once sync.Once
	logtest.SetDefault(t, slog.New(&messageSignal{message: "ike scheduled rekey starting", attr: slog.String("sa", "IKE SA"), seen: func() { once.Do(func() { close(started) }) }}))
	dialed, sent := &recorder{}, &deletesSeen{}
	h := newResponderHarness(t, nil)
	lists := new(atomic.Pointer[Suites])
	lists.Store(&hybridOf)
	initiator, responder := hybridSession(t, h, lists, dialed.record, sent)
	// both the rekey and the replacement's Delete wait on the session's one outstanding request
	initiator.requestMu.Lock()
	locked := true
	defer func() {
		if locked {
			initiator.requestMu.Unlock()
		}
	}()
	initiatorRun, _ := runSession(t, initiator), runSession(t, responder)
	// a reload removing the SA's entry starts its rekey
	lists.Store(&Suites{})
	initiator.SuitesChanged()
	select {
	case <-started:
	case err := <-initiatorRun:
		t.Fatalf("the session ended with %v before its rekey started", err)
	}
	// a mutex wakes the waiter parked first, so the rekey parked ahead of the replacement's Delete ends while the replacement is under way
	if !waitUntil(func() bool { return parkedOnMutex("ike.(*Session).RekeyIKE(") }) {
		t.Fatal("the rekey never waited on the session's outstanding request")
	}
	// and one removing its PRF replaces the SA while the rekey waits
	sha256Only := Suites{ikePRF: []Transform{prfSHA256}}
	lists.Store(&sha256Only)
	initiator.SuitesChanged()
	replacing := func() bool {
		return slices.ContainsFunc(dialed.recorded(), func(line string) bool {
			return strings.HasPrefix(line, "ike.suite.unlisted ") && strings.HasSuffix(line, " action=replace")
		})
	}
	if !waitUntil(replacing) {
		t.Fatalf("the session started no replacement: %q", dialed.recorded())
	}
	if !waitUntil(func() bool { return parkedOnMutex("ike.(*Session).DeleteIKE(") }) {
		t.Fatal("the replacement's Delete never waited on the session's outstanding request")
	}
	initiator.requestMu.Unlock()
	locked = false
	if err := endedWithin(t, initiatorRun, "dialing"); !errors.Is(err, ErrPRFUnlisted) {
		t.Errorf("the session ended with %v, want the replacement's end", err)
	}
	if got := sent.count(); got != 1 {
		t.Errorf("the session sent %d INFORMATIONAL requests, want the replacement's Delete alone", got)
	}
	if got := recordedKind(dialed, "ike.sa.closed"); got != 0 {
		t.Errorf("the session recorded %d closes beside its replacement: %q", got, dialed.recorded())
	}
}

// parkedOnMutex reports whether a goroutine running fn is parked on a sync.Mutex, which holds it in the mutex's queue
func parkedOnMutex(fn string) bool {
	var all strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&all, 2)
	return slices.ContainsFunc(strings.Split(all.String(), "\n\n"), func(stack string) bool {
		return strings.Contains(stack, " [sync.Mutex.Lock") && strings.Contains(stack, fn)
	})
}

// messageSignal calls seen at each record whose message and attributes hold message and attr
type messageSignal struct {
	message string
	attr    slog.Attr
	seen    func()
}

func (h *messageSignal) Enabled(context.Context, slog.Level) bool { return true }
func (h *messageSignal) Handle(_ context.Context, r slog.Record) error {
	if r.Message != h.message {
		return nil
	}
	r.Attrs(func(attr slog.Attr) bool {
		if attr.Equal(h.attr) {
			h.seen()
			return false
		}
		return true
	})
	return nil
}
func (h *messageSignal) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *messageSignal) WithGroup(string) slog.Handler      { return h }

// a peer's rekey of an IKE SA whose entry has additional key exchanges is refused, since the replacement would run without them
// this end's own rekey replaces such an SA by a new handshake
func TestPeerRekeyOfAnSAWithAdditionsIsRefused(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256, DHGroup: DH_CURVE25519, Additions: [addkeTypes]uint16{ML_KEM_768}}
	s := answeringSession(t, mux, suite, ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}, 0, hybridOf)
	ctx := s.current
	offer := []Proposal{{Transforms: []Transform{encrAES128, prfSHA256, dhX25519}}}
	if answer := answerPeerRekey(t, s, true, peerRekeyOf(t, s, true, offer, DH_CURVE25519)); answer.notify.Type != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("a peer's rekey of an SA of x25519+mlkem768 was answered %+v, want NO_PROPOSAL_CHOSEN", answer)
	}
	if current, _ := s.contexts(); current != ctx {
		t.Error("the refused rekey replaced the SA")
	}
	if len(s.rechecks) != 0 {
		t.Error("the refusal asked Run to check lists that still hold the SA")
	}
}
