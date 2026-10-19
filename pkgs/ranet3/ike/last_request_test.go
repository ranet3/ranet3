// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// heldRetransmit spaces the sends of a Delete whose first send is lost, so the session has started ending well before the second
const heldRetransmit = 500 * time.Millisecond

// RFC 7296 section 2.8: "the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// once a Delete of the IKE SA has gone out, a request queued behind it is refused, and neither a probe nor the liveness interval starts a check, so nothing more goes out on that SA
func TestNothingFollowsADeleteOfTheIKESA(t *testing.T) {
	h := newResponderHarness(t, nil)
	var requests atomic.Int32
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && !header.IsResponse() && header.ExchangeType == INFORMATIONAL {
			requests.Add(1)
		}
		return true
	})
	initiator, responder := dialPaused(t, h, cfg)
	initiator.retransmitAfter = busyRetransmit
	initiator.dpdEvery, responder.dpdEvery = quietDPD, time.Hour
	runSession(t, responder)
	runSession(t, initiator)
	if !waitUntil(initiator.serving.Load) {
		t.Fatal("Run never served the session")
	}
	if err := initiator.DeleteIKE(); err != nil {
		t.Fatalf("the Delete of the IKE SA failed: %v", err)
	}
	sent := requests.Load()
	if _, err := initiator.request(INFORMATIONAL, nil); err == nil {
		t.Error("a request after the Delete of the IKE SA was answered")
	}
	initiator.Probe()
	// a liveness check would fall due an interval after the Delete's answer
	time.Sleep(quietDPD + quietPeriod)
	if got := requests.Load() - sent; got != 0 {
		t.Errorf("%d INFORMATIONAL requests went out after the Delete of the IKE SA, want none", got)
	}
}

// RFC 7296 section 2.8: "the Delete payload to delete itself MUST be the last request sent over the old IKE SA."
// the session starts ending while a caller's Delete of the IKE SA is out, or reaches a lifetime once that Delete is answered
// so it ends with the ending's error and sends no Delete of its own, whether or not the caller closes the mux once its Delete returns, as closeSession does
func TestSessionEndingBehindADeleteOfTheIKESASendsNoDeleteOfItsOwn(t *testing.T) {
	for name, c := range map[string]struct{ closeAfter, lifetime bool }{
		"the caller keeps the mux":                     {},
		"the caller closes the mux":                    {closeAfter: true},
		"a lifetime falls once the Delete is answered": {lifetime: true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			events := &recorder{}
			var mu sync.Mutex
			var watching atomic.Bool
			// the sends of each request the initiator makes once the Delete is asked for, by exchange and Message ID
			sends := map[[2]uint32]int{}
			// with held set, every send of the Delete is lost
			var held atomic.Bool
			held.Store(!c.lifetime)
			lost := make(chan struct{})
			var first sync.Once
			cfg := h.peerConfig()
			cfg.Events = events.record
			if c.lifetime {
				// the Child SA's rekey falls due well after the Delete is answered and is refused, and its lifetime then falls with no rekey running
				cfg.IKERekeyInterval, cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, 2*time.Second, time.Second
			}
			cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
				if !watching.Load() || !fromInitiator || header == nil || header.IsResponse() {
					return true
				}
				mu.Lock()
				sends[[2]uint32{uint32(header.ExchangeType), header.MessageID}]++
				mu.Unlock()
				if held.Load() {
					first.Do(func() { close(lost) })
					return false
				}
				return true
			})
			initiator, responder := dialPaused(t, h, cfg)
			initiator.retransmitAfter = heldRetransmit
			initiator.rekeyJitterSource = func(time.Duration) (time.Duration, error) { return 0, nil }
			initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
			runSession(t, responder)
			run := runSession(t, initiator)
			if !waitUntil(initiator.serving.Load) {
				t.Fatal("Run never served the session")
			}
			watching.Store(true)
			done := make(chan error, 1)
			go func() { done <- initiator.DeleteIKE() }()

			failure := errors.New("dataplane failure")
			if !c.lifetime {
				select {
				case <-lost:
				case <-time.After(answerBudget):
					t.Fatal("no Delete of the IKE SA went out")
				}
				initiator.ChildFailed(failure)
				if !waitUntil(func() bool {
					return slices.ContainsFunc(events.recorded(), func(line string) bool { return strings.HasPrefix(line, "ike.sa.closed ") })
				}) {
					t.Fatal("the session did not start ending")
				}
				held.Store(false)
			}
			if err := answeredWithin(t, done, "the Delete of the IKE SA"); err != nil {
				t.Fatalf("the Delete of the IKE SA failed: %v", err)
			}
			if c.closeAfter {
				_ = initiator.Mux().Close()
			}
			ended := endedWithin(t, run, "initiator")
			switch {
			case c.lifetime && (ended == nil || !strings.Contains(ended.Error(), "the Child SA reached its lifetime")):
				t.Errorf("the session ended with %v, want the Child SA's lifetime", ended)
			case !c.lifetime && !errors.Is(ended, failure):
				t.Errorf("the session ended with %v, want %v", ended, failure)
			}
			// a Delete sent just before Run returned may still be on its way through the relay
			time.Sleep(quietPeriod)
			mu.Lock()
			defer mu.Unlock()
			if len(sends) != 1 {
				t.Errorf("the initiator sent %v by exchange and Message ID, want the Delete of the IKE SA alone", sends)
			}
		})
	}
}
