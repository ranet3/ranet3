// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// the responder's Run returns on the IKE SA's Delete, and otherwise only on a liveness check that outlasts the budget
func (p *refusingPair) ended(t *testing.T, why string) error {
	t.Helper()
	select {
	case err := <-p.initiatorDone:
		select {
		case <-p.responderDone:
		case <-time.After(answerBudget):
			t.Fatal("the responder still holds the IKE SA, so no Delete for it reached it")
		}
		return err
	case <-time.After(answerBudget):
		t.Fatal(why)
		return nil
	}
}

// an SA whose rekey the peer keeps refusing lives out its configured interval and no longer, then the session deletes the IKE SA under RFC 7296 section 2.8
// the retry backoff is longer than the test, so only the lifetime wakes the session to close it, and a dial after it builds a new IKE SA
func TestSAWhoseRekeyKeepsFailingIsDeletedAtItsLifetime(t *testing.T) {
	const lifetime = time.Second
	for _, tc := range []struct {
		sa          string
		set         func(*PeerConfig)
		established func(*Session) time.Time
	}{
		{"child", func(cfg *PeerConfig) { cfg.ChildRekeyInterval = lifetime }, func(s *Session) time.Time { return s.childEstablished }},
		{"ike", func(cfg *PeerConfig) { cfg.IKERekeyInterval = lifetime }, func(s *Session) time.Time { return s.current.established }},
	} {
		t.Run(tc.sa, func(t *testing.T) {
			var established time.Time
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				tc.set(cfg)
				cfg.RekeyMargin = lifetime - 300*time.Millisecond
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
			}, func(initiator, responder *Session) {
				established = tc.established(initiator)
				refuseRekeys(initiator, responder)
			})
			err := pair.ended(t, "the session went on past its SA's lifetime")
			ended := time.Since(established)
			if err == nil || !strings.Contains(err.Error(), "reached its lifetime") {
				t.Errorf("the session ended with %v, want its SA's lifetime", err)
			}
			if ended < lifetime {
				t.Errorf("the IKE SA's Delete was answered %s into the SA's lifetime of %s", ended, lifetime)
			}
			if late := ended - lifetime; late >= answerBudget/4 {
				t.Errorf("the IKE SA's Delete was answered %s past the SA's lifetime, which only the next retry reaches", late)
			}
			got := pair.dialed.recorded()
			want := "ike.sa.closed testorg/client:2>testorg/server:1 sa=" + tc.sa + " reason=lifetime"
			if !slices.Contains(got, "ike.rekey.failed testorg/client:2>testorg/server:1 sa="+tc.sa) || got[len(got)-1] != want {
				t.Errorf("the session recorded %q, want its rekey failing and then %q", got, want)
			}
			again, err := pair.h.dial(t)
			if err != nil {
				t.Fatalf("a dial after the close failed: %v", err)
			}
			again.Mux().Close()
			(<-pair.h.sessions).Mux().Close()
			<-pair.h.identities
		})
	}
}

// in the tests of a rekey outstanding at its SA's lifetime, the rekey starts rekeyStart into the SA's life, and an answer held back comes answerLate past its end
const (
	rekeyStart = 300 * time.Millisecond
	answerLate = 300 * time.Millisecond
	// unansweredRetransmit spaces the retransmissions of a request the peer never sees, so their budget runs out well inside answerBudget
	unansweredRetransmit = 50 * time.Millisecond
)

// a rekey outstanding at its SA's lifetime is left its answer while the SA is used no more: the Child SA's keys leave the dataplane at the lifetime, which the session records, a late success puts the new SA's in and the session goes on, and a refusal or no answer at all ends the IKE SA
func TestRekeyOutstandingAtTheLifetime(t *testing.T) {
	const lifetime = time.Second
	for _, sa := range []string{"child", "ike"} {
		t.Run(sa, func(t *testing.T) {
			for _, answer := range []string{"succeeds", "fails", "never comes"} {
				t.Run(answer, func(t *testing.T) {
					var (
						established, late time.Time
						spiI              uint64
						old, oldOut       uint32
						keys              *dataplane
					)
					pair := dialRefusing(t, func(cfg *PeerConfig) {
						if sa == "child" {
							cfg.ChildRekeyInterval = lifetime
						} else {
							cfg.IKERekeyInterval = lifetime
						}
						cfg.RekeyMargin = lifetime - rekeyStart
						cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
						if answer == "never comes" {
							cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
								return !fromInitiator || header == nil || header.ExchangeType != CREATE_CHILD_SA || header.IsResponse()
							})
						}
					}, func(initiator, responder *Session) {
						established, spiI, old, oldOut = initiator.childEstablished, initiator.current.spiI, initiator.Child.LocalSPI, initiator.Child.RemoteSPI
						if sa == "ike" {
							established = initiator.current.established
						}
						late = established.Add(lifetime + answerLate)
						keys = newDataplane(initiator)
						initiator.childRetireDelay = quietPeriod / 3
						held := func() error {
							time.Sleep(time.Until(late))
							if answer == "fails" {
								return errors.New("the rekey is refused")
							}
							return nil
						}
						switch {
						case answer == "never comes":
							initiator.retransmitAfter, initiator.dpdEvery = unansweredRetransmit, lifetime
						case sa == "child":
							responder.SetChildHandler(func(ChildSA) error { return held() })
						default:
							responder.ikeRekeyNonce = func(nonce []byte) error {
								if err := held(); err != nil {
									return err
								}
								_, err := rand.Read(nonce)
								return err
							}
						}
					})
					ends := "testorg/client:2>testorg/server:1 sa=" + sa
					closed := func(line string) bool { return strings.HasPrefix(line, "ike.sa.closed ") }
					switch answer {
					case "succeeds":
						for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), "ike.rekey.completed "+ends+" suite="+defaultSuite[sa]); time.Sleep(recordPoll) {
							select {
							case err := <-pair.initiatorDone:
								t.Fatalf("the session ended with %v, its rekey not completed, and recorded %q", err, pair.dialed.recorded())
							default:
							}
							if time.Now().After(deadline) {
								t.Fatalf("the rekey never completed, the session recorded %q", pair.dialed.recorded())
							}
						}
						if time.Since(established) < lifetime {
							t.Fatal("the rekey completed inside the lifetime, so nothing ran across it")
						}
						select {
						case err := <-pair.initiatorDone:
							t.Fatalf("the session ended after its rekey succeeded: %v", err)
						default:
						}
						if got := pair.dialed.recorded(); slices.ContainsFunc(got, closed) {
							t.Errorf("the session closed the IKE SA under a rekey that succeeded, it recorded %q", got)
						}
						if sa == "ike" && pair.initiator.currentContext().spiI == spiI {
							t.Error("the session is not on the IKE SA its rekey made")
						}
					case "fails":
						err := pair.ended(t, "the session went on after its rekey failed past the SA's lifetime")
						if err == nil || !strings.Contains(err.Error(), "reached its lifetime") {
							t.Errorf("the session ended with %v, want its SA's lifetime", err)
						}
						if got := pair.dialed.recorded(); !slices.Contains(got, "ike.rekey.failed "+ends) || got[len(got)-1] != "ike.sa.closed "+ends+" reason=lifetime" {
							t.Errorf("the session recorded %q, want its rekey failing and then the IKE SA closed at the lifetime", got)
						}
					case "never comes":
						select {
						case err := <-pair.initiatorDone:
							if err == nil || !strings.Contains(err.Error(), "peer unresponsive") {
								t.Errorf("the session ended with %v, want the rekey's retransmissions spent", err)
							}
						case <-time.After(answerBudget):
							t.Fatal("the session went on with its rekey unanswered")
						}
						if got := pair.dialed.recorded(); slices.ContainsFunc(got, closed) {
							t.Errorf("the session recorded %q, but no Delete can pass the rekey holding the one request out", got)
						}
					}
					if sa != "child" {
						return
					}
					expired := fmt.Sprintf("ike.sa.expired %s spi_in=%08x spi_out=%08x", ends, old, oldOut)
					if got := pair.dialed.recorded(); !slices.Equal(slices.DeleteFunc(slices.Clone(got), func(line string) bool { return !strings.HasPrefix(line, "ike.sa.expired ") }), []string{expired}) {
						t.Errorf("the session recorded %q, want the Child SA expiring once, as %q", got, expired)
					}
					if answer == "succeeds" {
						// a Child SA kept on after its keys left would have them removed once more when it drains
						time.Sleep(quietPeriod)
					}
					changes := keys.recorded()
					removed := slices.IndexFunc(changes, func(change keyChange) bool { return change.spi == old && change.removed })
					if removed < 0 || slices.ContainsFunc(changes[removed+1:], func(change keyChange) bool { return change.spi == old }) {
						t.Fatalf("the dataplane saw %+v, want the expired Child SA's keys out once", changes)
					}
					if at := changes[removed].at; at.Before(established.Add(lifetime)) || !at.Before(late) {
						t.Errorf("the expired Child SA's keys came out %s into its life, want at its lifetime of %s, before the answer %s later", at.Sub(established), lifetime, answerLate)
					}
					if added := slices.IndexFunc(changes, func(change keyChange) bool { return !change.removed }); (answer == "succeeds") != (added > removed) {
						t.Errorf("the dataplane saw %+v, want the new SA's keys in after the expired SA's came out, and only on a rekey that succeeds", changes)
					}
					if answer != "succeeds" {
						return
					}
					// the hub gives an SPI to a second mux only once the session's mux has let it go
					other, err := pair.h.initiator.NewMux(net.ParseIP("127.0.0.1"), pair.h.remotePort)
					if err != nil {
						t.Fatal(err)
					}
					defer other.Close()
					if err := other.RegisterESP(old); err != nil {
						t.Errorf("the session still routes the expired Child SA's SPI after its Delete: %v", err)
					}
				})
			}
		})
	}
}

// a Child SA rekey this end starts outside its schedule counts at the Child SA's lifetime as a scheduled one does: a late success keeps the IKE SA, and only its failure deletes it
// the responder holds its answer until answerLate past the lifetime, and nothing but the rekey's end wakes the session then
// a failed rekey ends quietPeriod after its answer, once the session has handled that answer and waits again
func TestProactiveRekeyOutstandingAtTheChildSALifetime(t *testing.T) {
	const lifetime = time.Second
	for _, answer := range []string{"succeeds", "fails"} {
		t.Run(answer, func(t *testing.T) {
			var established, late time.Time
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				cfg.ChildRekeyInterval = lifetime
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = time.Hour, time.Hour
				record := cfg.Events
				cfg.Events = func(local, remote identity.Identity, kind string, attrs ...slog.Attr) {
					record(local, remote, kind, attrs...)
					if kind == "ike.rekey.failed" {
						time.Sleep(quietPeriod)
					}
				}
			}, func(initiator, responder *Session) {
				established = initiator.childEstablished
				late = established.Add(lifetime + answerLate)
				initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
				responder.SetChildHandler(func(ChildSA) error {
					time.Sleep(time.Until(late))
					if answer == "fails" {
						return errors.New("the rekey is refused")
					}
					return nil
				})
			})
			time.Sleep(time.Until(established.Add(rekeyStart)))
			rekeyed := make(chan error, 1)
			go func() { rekeyed <- pair.initiator.RekeyChildProactively() }()
			var err error
			select {
			case err = <-rekeyed:
			case err := <-pair.initiatorDone:
				t.Fatalf("the session ended with %v while its rekey was out", err)
			case <-time.After(answerBudget):
				t.Fatal("the proactive rekey never ended")
			}
			if time.Now().Before(late) {
				t.Fatal("the rekey ended before its answer was let through, so nothing ran across the lifetime")
			}
			ends := "testorg/client:2>testorg/server:1 sa=child"
			closed := func(line string) bool { return strings.HasPrefix(line, "ike.sa.closed ") }
			if answer == "succeeds" {
				if err != nil {
					t.Fatalf("the proactive rekey failed: %v", err)
				}
				time.Sleep(quietPeriod)
				select {
				case err := <-pair.initiatorDone:
					t.Fatalf("the session ended after its rekey succeeded: %v", err)
				default:
				}
				if got := pair.dialed.recorded(); slices.ContainsFunc(got, closed) {
					t.Errorf("the session closed the IKE SA under a rekey that succeeded, it recorded %q", got)
				}
				return
			}
			if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != N_TEMPORARY_FAILURE {
				t.Fatalf("the proactive rekey ended with %v, want the responder's TEMPORARY_FAILURE", err)
			}
			ended := pair.ended(t, "the session went on after its rekey failed past the Child SA's lifetime")
			if ended == nil || !strings.Contains(ended.Error(), "the Child SA reached its lifetime") {
				t.Errorf("the session ended with %v, want the Child SA's lifetime", ended)
			}
			got := pair.dialed.recorded()
			if failed := slices.Index(got, "ike.rekey.failed "+ends); failed < 0 || slices.IndexFunc(got, closed) < failed || got[len(got)-1] != "ike.sa.closed "+ends+" reason=lifetime" {
				t.Errorf("the session recorded %q, want the rekey failing and only then the IKE SA closed at the Child SA's lifetime", got)
			}
		})
	}
}

// RFC 7296 section 2.8: "If an SA has expired or is about to expire and rekeying attempts using the mechanisms described here fail, an implementation MUST close the IKE SA and any associated Child SAs and then MAY start new ones."
// a Child SA rekey asked for once the SA's keys have left at its lifetime starts no exchange, so with none running then the IKE SA closes
// the ask comes as the keys leave, as internal/client's comes from the first batch that finds them gone, and is under way before the session decides on the close
func TestRekeyAskedForPastTheChildSALifetimeStartsNothing(t *testing.T) {
	const lifetime = time.Second
	asked := make(chan error, 1)
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval = lifetime
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = time.Hour, time.Hour
	}, func(initiator, _ *Session) {
		initiator.SetChildRetireHandler(func(uint32) error {
			go func() { asked <- initiator.RekeyChildProactively() }()
			for deadline := time.Now().Add(answerBudget); !initiator.childRekeying.Load(); time.Sleep(recordPoll) {
				if time.Now().After(deadline) {
					return errors.New("the rekey asked for never started")
				}
			}
			return nil
		})
	})
	select {
	case err := <-asked:
		if err == nil || !strings.Contains(err.Error(), "the Child SA is past its lifetime") {
			t.Fatalf("the rekey asked for past the Child SA's lifetime ended with %v, want it refused", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("the rekey asked for past the Child SA's lifetime never ended")
	}
	err := pair.ended(t, "the session went on past its Child SA's lifetime")
	if err == nil || !strings.Contains(err.Error(), "the Child SA reached its lifetime") {
		t.Errorf("the session ended with %v, want the Child SA's lifetime", err)
	}
	if got := pair.dialed.recorded(); slices.ContainsFunc(got, func(line string) bool { return strings.HasPrefix(line, "ike.rekey.") }) {
		t.Errorf("the session recorded %q, want no rekey past the lifetime", got)
	}
}

// an exchange out past its IKE SA's lifetime is retransmitted as to a silent peer however much traffic the peer keeps up, and then the IKE SA is deemed failed as section 2.1 allows
// the relay drops the rekey of the IKE SA on its way to the responder, while the peer's traffic, noted as internal/client notes ESP, goes on throughout
func TestExchangeOutstandingPastTheIKESALifetimeHasTheIdleBudget(t *testing.T) {
	const lifetime = time.Second
	var dropped atomic.Int32
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.IKERekeyInterval = lifetime
		cfg.RekeyMargin = lifetime - rekeyStart
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
		cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
			if fromInitiator && header != nil && header.ExchangeType == CREATE_CHILD_SA && !header.IsResponse() {
				dropped.Add(1)
				return false
			}
			return true
		})
	}, func(initiator, _ *Session) {
		initiator.retransmitAfter, initiator.dpdEvery = unansweredRetransmit, lifetime
	})
	carrying := time.NewTicker(recordPoll)
	defer carrying.Stop()
	timeout := time.After(answerBudget)
	for {
		select {
		case err := <-pair.initiatorDone:
			if want := fmt.Sprintf("peer unresponsive after %d attempts", maxRetransmits); err == nil || !strings.Contains(err.Error(), want) {
				t.Errorf("the session ended with %v, want %s", err, want)
			}
			if got := dropped.Load(); got != maxRetransmits {
				t.Errorf("the initiator sent its rekey %d times, want %d", got, maxRetransmits)
			}
			return
		case <-carrying.C:
			pair.initiator.NoteTraffic()
		case <-timeout:
			t.Fatal("the session went on with its rekey unanswered past the IKE SA's lifetime")
		}
	}
}

type keyChange struct {
	spi     uint32
	removed bool
	at      time.Time
}

// dataplane stands in for internal/client's tunnel, recording each Child SA's keys going in and coming out, and refusing to remove keys it does not hold
type dataplane struct {
	mu      sync.Mutex
	held    map[uint32]bool
	changes []keyChange
}

func newDataplane(s *Session) *dataplane {
	d := &dataplane{held: map[uint32]bool{s.Child.LocalSPI: true}}
	s.SetChildHandler(func(child ChildSA) error { return d.change(child.LocalSPI, false) })
	s.SetChildRetireHandler(func(spi uint32) error { return d.change(spi, true) })
	return d
}

func (d *dataplane) change(spi uint32, removed bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.changes = append(d.changes, keyChange{spi: spi, removed: removed, at: time.Now()})
	if removed && !d.held[spi] {
		return fmt.Errorf("the keys of SPI %08x are not installed", spi)
	}
	d.held[spi] = !removed
	return nil
}

func (d *dataplane) recorded() []keyChange {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.changes)
}

// a Child SA with no lifetime keeps its keys in the dataplane however old it grows
func TestChildSAWithoutALifetimeKeepsItsKeys(t *testing.T) {
	s := &Session{Child: ChildSA{LocalSPI: 7}, childEstablished: time.Now()}
	keys := newDataplane(s)
	if err := s.expireChild(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if changes := keys.recorded(); len(changes) != 0 {
		t.Errorf("the dataplane saw %+v, want the keys of an SA with no lifetime left in", changes)
	}
}

// an IKE SA past its lifetime starts nothing but its Delete: no liveness check, asked for or falling due, and not the rekey that comes too late to replace it
// it is one this end is closing from its lifetime on, so it answers the peer's rekeys with TEMPORARY_FAILURE while its own rekey still holds and no close is decided
// the initiator's rekey holds before its request until past the lifetime, so nothing is outstanding while the IKE SA is expired
func TestIKESAPastItsLifetimeStartsNothingButItsDelete(t *testing.T) {
	const lifetime = time.Second
	var (
		mu          sync.Mutex
		requests    []Header
		established time.Time
	)
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.IKERekeyInterval = lifetime
		cfg.RekeyMargin = lifetime - rekeyStart
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
		cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
			if fromInitiator && header != nil && !header.IsResponse() && header.ExchangeType != IKE_SA_INIT && header.ExchangeType != IKE_AUTH {
				mu.Lock()
				requests = append(requests, *header)
				mu.Unlock()
			}
			return true
		})
	}, func(initiator, _ *Session) {
		established = initiator.current.established
		held := established.Add(lifetime + 3*answerLate)
		initiator.ikeRekeyNonce = func(nonce []byte) error {
			time.Sleep(time.Until(held))
			_, err := rand.Read(nonce)
			return err
		}
		// a liveness check falls due past the lifetime, after the probe and while the rekey still holds
		initiator.dpdEvery = lifetime + 2*answerLate/3
	})
	time.Sleep(time.Until(established.Add(lifetime + answerLate/3)))
	pair.initiator.Probe()
	// an authenticated request puts the next liveness check off, so the peer's rekeys come after one would have fallen due and before the rekey stops holding
	time.Sleep(time.Until(established.Add(lifetime + 2*answerLate)))
	for _, rekey := range []struct {
		sa  string
		run func() error
	}{{"Child SA", pair.responder.RekeyChild}, {"IKE SA", pair.responder.RekeyIKE}} {
		err := rekey.run()
		if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != N_TEMPORARY_FAILURE {
			t.Errorf("the peer's %s rekey past the IKE SA's lifetime ended with %v, want TEMPORARY_FAILURE", rekey.sa, err)
		}
	}
	err := pair.ended(t, "the IKE SA went on past its lifetime")
	if err == nil || !strings.Contains(err.Error(), "the IKE SA reached its lifetime") {
		t.Errorf("the session ended with %v, want the IKE SA's lifetime", err)
	}
	mu.Lock()
	sent := slices.Clone(requests)
	mu.Unlock()
	if len(sent) == 0 || slices.ContainsFunc(sent, func(header Header) bool { return header.ExchangeType != INFORMATIONAL || header.MessageID != 2 }) {
		t.Errorf("past the handshake the initiator sent the requests %+v, want its Delete alone, at Message ID 2", sent)
	}
	ends := "testorg/client:2>testorg/server:1 sa=ike"
	if got := pair.dialed.recorded(); !slices.Contains(got, "ike.rekey.failed "+ends) || got[len(got)-1] != "ike.sa.closed "+ends+" reason=lifetime" {
		t.Errorf("the session recorded %q, want the late rekey refused and then the IKE SA closed at its lifetime", got)
	}
}

// a Child SA that reaches its lifetime while the IKE SA's rekey is outstanding ends the IKE SA there, and that Delete waits for the rekey's answer and the replaced IKE SA's own Delete, then goes out on the IKE SA the rekey made
// the Child SA's rekey cannot start while the IKE SA's runs, so it reaches its lifetime never tried, and the close is decided at that lifetime, before the IKE SA's rekey ends
func TestIKESADeleteAtAChildSALifetimeWaitsForTheIKESARekey(t *testing.T) {
	// under one margin the IKE SA's shorter lifetime starts its rekey first
	const ikeLifetime, childLifetime, margin = 2 * time.Second, 2500 * time.Millisecond, 1500 * time.Millisecond
	pair := dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval, cfg.IKERekeyInterval = childLifetime, ikeLifetime
		cfg.RekeyMargin = margin
		cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
	}, func(initiator, responder *Session) {
		late := initiator.childEstablished.Add(childLifetime + answerLate)
		responder.ikeRekeyNonce = func(nonce []byte) error {
			time.Sleep(time.Until(late))
			_, err := rand.Read(nonce)
			return err
		}
	})
	err := pair.ended(t, "the session went on past its Child SA's lifetime")
	if err == nil || !strings.Contains(err.Error(), "the Child SA reached its lifetime") {
		t.Errorf("the session ended with %v, want the Child SA's lifetime", err)
	}
	ends := "testorg/client:2>testorg/server:1 sa="
	got := pair.dialed.recorded()
	closes := slices.DeleteFunc(slices.Clone(got), func(line string) bool { return !strings.HasPrefix(line, "ike.sa.closed ") })
	closed := "ike.sa.closed " + ends + "child reason=lifetime"
	completed := slices.Index(got, "ike.rekey.completed "+ends+"ike suite="+defaultSuite["ike"])
	if completed < 0 || !slices.Equal(closes, []string{closed}) || slices.Index(got, closed) > completed {
		t.Errorf("the session recorded %q, want one close, at the Child SA's lifetime and so before the IKE SA's rekey completed", got)
	}
	if _, old := pair.responder.contexts(); old != nil {
		t.Error("the responder still held the IKE SA the rekey replaced, so the Delete ending the session went out before that SA's own")
	}
}

// RFC 7296 section 2.3: "An IKE endpoint MUST be prepared to accept and process a request while it has a request outstanding in order to avoid a deadlock in this situation."
// section 2.25.1: "If a peer receives a request to rekey a Child SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
// section 2.25.2: "If a peer receives a request to rekey an IKE SA that it is currently trying to close, it SHOULD reply with TEMPORARY_FAILURE."
// an IKE SA closed at its own lifetime or a Child SA's with a liveness check out goes on retransmitting that check and answering the peer, refusing from the decision to close the rekeys the peer asks for, and its Delete goes out once the check is answered, the one request it keeps outstanding
// the relay drops the responder's answers until answerLate past the lifetime, and with no margin the rekey falls due at the lifetime, which closes the IKE SA first
func TestIKESADeleteAtALifetimeWaitsForTheOutstandingLivenessCheck(t *testing.T) {
	const lifetime = time.Second
	type relayed struct {
		header Header
		raw    []byte
		at     time.Time
	}
	for _, sa := range []struct{ name, short string }{{"Child SA", "child"}, {"IKE SA", "ike"}} {
		t.Run(sa.short, func(t *testing.T) {
			var (
				mu                       sync.Mutex
				requests, answers        []relayed
				established, answersFrom time.Time
			)
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				if sa.short == "child" {
					cfg.ChildRekeyInterval = lifetime
				} else {
					cfg.IKERekeyInterval = lifetime
				}
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
				cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
					if header == nil || header.ExchangeType != INFORMATIONAL {
						return true
					}
					mu.Lock()
					defer mu.Unlock()
					seen := relayed{*header, slices.Clone(raw), time.Now()}
					switch {
					case !fromInitiator:
						return !header.IsResponse() || !seen.at.Before(answersFrom)
					case header.IsResponse():
						answers = append(answers, seen)
					default:
						requests = append(requests, seen)
					}
					return true
				})
			}, func(initiator, _ *Session) {
				established = initiator.childEstablished
				if sa.short == "ike" {
					established = initiator.current.established
				}
				mu.Lock()
				answersFrom = established.Add(lifetime + answerLate)
				mu.Unlock()
				initiator.dpdEvery, initiator.retransmitAfter = lifetime-rekeyStart, rekeyStart+answerLate/3
			})
			time.Sleep(time.Until(established.Add(lifetime + answerLate/3)))
			for _, rekey := range []struct {
				sa  string
				run func() error
			}{{"Child SA", pair.responder.RekeyChild}, {"IKE SA", pair.responder.RekeyIKE}} {
				err := rekey.run()
				if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != N_TEMPORARY_FAILURE {
					t.Errorf("the peer's %s rekey past the %s's lifetime ended with %v, want TEMPORARY_FAILURE", rekey.sa, sa.name, err)
				}
			}
			pair.responder.Probe()
			err := pair.ended(t, "the IKE SA went on past the lifetime")
			if err == nil || !strings.Contains(err.Error(), "the "+sa.name+" reached its lifetime") {
				t.Errorf("the session ended with %v, want the %s's lifetime", err, sa.name)
			}
			mu.Lock()
			sent, answered := slices.Clone(requests), slices.Clone(answers)
			mu.Unlock()
			expiry := established.Add(lifetime)
			if len(sent) == 0 {
				t.Fatal("the initiator sent no INFORMATIONAL request")
			}
			check := sent[0]
			d := slices.IndexFunc(sent, func(request relayed) bool { return !bytes.Equal(request.raw, check.raw) })
			if d < 0 {
				t.Fatalf("the initiator sent its liveness check at Message ID %d %d times and nothing after it", check.header.MessageID, len(sent))
			}
			if !slices.ContainsFunc(sent[1:d], func(request relayed) bool { return request.at.After(expiry) }) {
				t.Error("the liveness check out at the lifetime was not retransmitted past it")
			}
			if deleting := sent[d]; deleting.header.MessageID != check.header.MessageID+1 || deleting.at.Before(answersFrom) {
				t.Errorf("the initiator sent its Delete at Message ID %d, %s past the lifetime, want it at %d once the check was answered, %s past", deleting.header.MessageID, deleting.at.Sub(expiry), check.header.MessageID+1, answerLate)
			}
			if !slices.ContainsFunc(answered, func(seen relayed) bool { return seen.at.After(expiry) && seen.at.Before(answersFrom) }) {
				t.Errorf("the initiator answered %d requests, none past the lifetime while its check was out", len(answered))
			}
			ends := "testorg/client:2>testorg/server:1 sa=" + sa.short
			if got := pair.dialed.recorded(); len(got) == 0 || slices.Contains(got, "ike.rekey.started "+ends) || got[len(got)-1] != "ike.sa.closed "+ends+" reason=lifetime" {
				t.Errorf("the session recorded %q, want no rekey and the IKE SA closed at the %s's lifetime", got, sa.name)
			}
		})
	}
}

// an SA's lifetime runs from when it is made, in each place one is made: the initial exchanges at both ends, and a rekey at the end that starts it and the end that answers it
func TestEverySAStartsItsLifetimeWhenItIsMade(t *testing.T) {
	h := newResponderHarness(t, nil)
	before := time.Now()
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}
	responder := <-h.sessions
	<-h.identities
	made := func(when string, from time.Time) {
		t.Helper()
		to := time.Now()
		for _, end := range []struct {
			role    string
			session *Session
		}{{"initiator", initiator}, {"responder", responder}} {
			ike, _ := end.session.ikeEstablishedAt()
			child, ok := end.session.childEstablishedAt()
			if ike.Before(from) || ike.After(to) {
				t.Errorf("the %s's IKE SA %s starts its lifetime at %v, want between %v and %v", end.role, when, ike, from, to)
			}
			if !ok || child.Before(from) || child.After(to) {
				t.Errorf("the %s's Child SA %s starts its lifetime at %v, want between %v and %v", end.role, when, child, from, to)
			}
		}
	}
	made("from the initial exchanges", before)

	run, stop := context.WithCancel(context.Background())
	var running sync.WaitGroup
	running.Go(func() { _ = initiator.Run(run) })
	running.Go(func() { _ = responder.Run(run) })
	defer func() {
		stop()
		running.Wait()
	}()
	before = time.Now()
	if err := initiator.RekeyIKE(); err != nil {
		t.Fatalf("the initiator could not rekey the IKE SA: %v", err)
	}
	if err := initiator.RekeyChild(); err != nil {
		t.Fatalf("the initiator could not rekey the Child SA: %v", err)
	}
	made("from the rekeys", before)
}

// the streak is seeded a span old, so the first TEMPORARY_FAILURE on the same IKE SA closes it and nothing waits out the minutes
// the answer counts on every path a Child SA rekey takes, the schedule's and one asked for at once as a sequence space near its end asks for one
func TestTemporaryFailureForTheSpanClosesTheIKESA(t *testing.T) {
	for _, tc := range []struct {
		name, sa string
		set      func(*PeerConfig)
		// ask, where it is set, starts the rekey the responder refuses, and otherwise the schedule does
		ask func(*Session) error
	}{
		{"child", "child", func(cfg *PeerConfig) {
			cfg.ChildRekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-300*time.Millisecond
		}, nil},
		{"ike", "ike", func(cfg *PeerConfig) {
			cfg.IKERekeyInterval, cfg.RekeyMargin = time.Hour, time.Hour-300*time.Millisecond
		}, nil},
		{"proactive", "child", func(cfg *PeerConfig) { cfg.ChildRekeyInterval = time.Hour }, (*Session).RekeyChildProactively},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				tc.set(cfg)
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = answerBudget, answerBudget
			}, func(initiator, responder *Session) {
				initiator.temporary = temporaryStreak{on: initiator.current, since: time.Now().Add(-temporaryFailureSpan)}
				refuseRekeys(initiator, responder)
			})
			if tc.ask != nil {
				if err := tc.ask(pair.initiator); err == nil {
					t.Fatal("a rekey the responder refuses succeeded")
				}
			}
			err := pair.ended(t, "the session went on after TEMPORARY_FAILURE for the whole span")
			if err == nil || !strings.Contains(err.Error(), "TEMPORARY_FAILURE") {
				t.Errorf("the session ended with %v, want the TEMPORARY_FAILURE streak", err)
			}
			ends := "testorg/client:2>testorg/server:1 sa=" + tc.sa
			if got, want := pair.dialed.recorded(), []string{
				"ike.id.resolved testorg/client:2>testorg/server:1 type=dn sent=dn",
				"ike.rekey.started " + ends, "ike.rekey.failed " + ends, "ike.sa.closed " + ends + " reason=temporary failure",
			}; !slices.Equal(got, want) {
				t.Errorf("the session recorded %q, want %q", got, want)
			}
		})
	}
}

// a rekey that succeeds ends the streak, on whichever path, so the TEMPORARY_FAILUREs after it start a new one rather than close the IKE SA a span after the first
func TestRekeySucceedingInsideTheSpanStartsTheStreakOver(t *testing.T) {
	ends := "testorg/client:2>testorg/server:1 sa=child"
	rekeyed := "ike.rekey.completed " + ends + " suite=" + defaultSuite["child"]
	for _, tc := range []struct {
		name string
		// succeed has the first rekey succeed and returns once it has
		succeed func(t *testing.T, pair *refusingPair)
	}{
		{"scheduled", func(t *testing.T, pair *refusingPair) {
			for deadline := time.Now().Add(answerBudget); !slices.Contains(pair.dialed.recorded(), rekeyed); time.Sleep(recordPoll) {
				if time.Now().After(deadline) {
					t.Fatalf("the first rekey did not complete, the session recorded %q", pair.dialed.recorded())
				}
			}
		}},
		{"proactive", func(t *testing.T, pair *refusingPair) {
			if err := pair.initiator.RekeyChildProactively(); err != nil {
				t.Fatalf("the rekey asked for failed: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				cfg.ChildRekeyInterval = time.Hour
				cfg.RekeyMargin = time.Hour - 300*time.Millisecond
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = 100*time.Millisecond, 100*time.Millisecond
			}, func(initiator, _ *Session) {
				initiator.temporary = temporaryStreak{on: initiator.current, since: time.Now().Add(-temporaryFailureSpan)}
			})
			tc.succeed(t, pair)
			refuseRekeys(pair.initiator, pair.responder)
			for deadline := time.Now().Add(answerBudget); ; time.Sleep(recordPoll) {
				got := pair.dialed.recorded()
				if slices.Contains(got, "ike.sa.closed "+ends+" reason=temporary failure") {
					t.Fatalf("the session closed the IKE SA on the streak a successful rekey had ended, it recorded %q", got)
				}
				failed := 0
				for _, line := range got[slices.Index(got, rekeyed):] {
					if line == "ike.rekey.failed "+ends {
						failed++
					}
				}
				if failed >= 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("the rekeys after the first did not fail twice, the session recorded %q", got)
				}
			}
			select {
			case err := <-pair.initiatorDone:
				t.Fatalf("the session ended inside the span of its new streak: %v", err)
			default:
			}
		})
	}
}

// RFC 7296 section 2.25 counts TEMPORARY_FAILURE "on the same IKE SA", so a refusal of any other kind leaves the streak as it was and one on another IKE SA starts it over
func TestTemporaryFailureStreakSpansOneIKESA(t *testing.T) {
	first, second := &ikeContext{}, &ikeContext{}
	temporary := &rejectedError{exchange: "Child SA negotiation", notify: Notify{Type: N_TEMPORARY_FAILURE}}
	noProposal := &rejectedError{exchange: "Child SA negotiation", notify: Notify{Type: N_NO_PROPOSAL_CHOSEN}}
	start := time.Now()
	var streak temporaryStreak
	for _, step := range []struct {
		on    *ikeContext
		err   error
		at    time.Duration
		close bool
	}{
		{first, temporary, 0, false},
		{first, temporary, temporaryFailureSpan - time.Nanosecond, false},
		{first, noProposal, temporaryFailureSpan, false},
		{first, errors.New("ike: peer unresponsive after 2 attempts"), temporaryFailureSpan, false},
		{first, temporary, temporaryFailureSpan, true},
		{second, temporary, temporaryFailureSpan + time.Second, false},
		{second, temporary, 2*temporaryFailureSpan + time.Second - time.Nanosecond, false},
		{second, temporary, 2*temporaryFailureSpan + time.Second, true},
	} {
		if got := streak.outlasted(step.on, step.err, start.Add(step.at)); got != step.close {
			t.Errorf("%v at %s on IKE SA %p closes %v, want %v", step.err, step.at, step.on, got, step.close)
		}
	}
}

// RFC 7296 section 2.8: "If an SA has expired or is about to expire and rekeying attempts using the mechanisms described here fail, an implementation MUST close the IKE SA and any associated Child SAs and then MAY start new ones."
// a Child SA whose sequence space is spent has reached its limit on data, so the session deletes the IKE SA once no rekey can replace the SA, whatever its interval, and a rekey running then that replaces it keeps the session
// the rekey was refused with NO_PROPOSAL_CHOSEN a quiet period before, which no TEMPORARY_FAILURE span counts and after which nothing is due for an hour, or runs as the space runs out with the responder holding its answer for two quiet periods
func TestSpentSequenceSpaceClosesTheIKESAUnlessARekeyReplacesIt(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval time.Duration
		answer   string
	}{
		{"refused before with a lifetime", time.Hour, "refused before"},
		{"refused before with no lifetime", 0, "refused before"},
		{"running and refused", time.Hour, "refused"},
		{"running and replacing it", 0, "succeeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				cfg.ChildRekeyInterval = tc.interval
				cfg.RekeyRetryInitial, cfg.RekeyRetryMax = time.Hour, time.Hour
			}, func(initiator, responder *Session) {
				initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
				held := time.Now().Add(2 * quietPeriod)
				switch tc.answer {
				case "refused before":
					// the responder expects another cipher and its lists hold that one alone, so it refuses every rekey with NO_PROPOSAL_CHOSEN
					cipher := "chacha20poly1305"
					if responder.Child.EncrID == ENCR_AES_GCM_16 {
						responder.Child.EncrID, responder.Child.EncrKeyBits = ENCR_CHACHA20_POLY1305, 256
					} else {
						responder.Child.EncrID, responder.Child.EncrKeyBits = ENCR_AES_GCM_16, 128
						cipher = "aes128gcm"
					}
					only := suitesOf(t, Crypto{ESP: ESPSuites{Cipher: []string{cipher}}})
					responder.suites = func() Suites { return only }
				case "refused":
					refuseInstalls(responder, held)
				case "succeeds":
					responder.SetChildHandler(func(ChildSA) error {
						time.Sleep(time.Until(held))
						return nil
					})
				}
			})
			spi := pair.initiator.currentChild().LocalSPI
			rekeyed := make(chan error, 1)
			if tc.answer == "refused before" {
				err := pair.initiator.RekeyChildProactively()
				if rejected, ok := errors.AsType[*rejectedError](err); !ok || rejected.notify.Type != N_NO_PROPOSAL_CHOSEN {
					t.Fatalf("the rekey before the space ran out ended with %v, want NO_PROPOSAL_CHOSEN", err)
				}
				time.Sleep(quietPeriod)
			} else {
				// asked for as the space runs out, as internal/client asks
				go func() { rekeyed <- pair.initiator.RekeyChildProactively() }()
				for deadline := time.Now().Add(answerBudget); childRekeyLines(pair, "ike.rekey.started") == 0; time.Sleep(recordPoll) {
					if time.Now().After(deadline) {
						t.Fatal("the rekey asked for never started")
					}
				}
			}
			pair.initiator.ChildSequenceSpent(spi)
			ends := "testorg/client:2>testorg/server:1 sa=child"
			closed := "ike.sa.closed " + ends + " reason=sequence space"
			if tc.answer != "refused before" {
				select {
				case err := <-pair.initiatorDone:
					t.Fatalf("the session ended with %v while a rekey that may replace the spent SA ran", err)
				case <-time.After(quietPeriod):
				}
			}
			if tc.answer == "succeeds" {
				if err := <-rekeyed; err != nil {
					t.Fatalf("the rekey replacing the spent SA failed: %v", err)
				}
				time.Sleep(quietPeriod)
				select {
				case err := <-pair.initiatorDone:
					t.Fatalf("the session ended after a rekey replaced its spent SA: %v", err)
				default:
				}
				if got := pair.dialed.recorded(); slices.Contains(got, closed) {
					t.Errorf("the session recorded %q, want no close after a rekey replaced its spent SA", got)
				}
				return
			}
			err := pair.ended(t, "the session went on with its Child SA's sequence space spent and no rekey replacing it")
			if err == nil || !strings.Contains(err.Error(), "ran out of sequence numbers") {
				t.Errorf("the session ended with %v, want its spent sequence space", err)
			}
			if got := pair.dialed.recorded(); !slices.Contains(got, "ike.rekey.failed "+ends) || got[len(got)-1] != closed {
				t.Errorf("the session recorded %q, want its rekey failing and then %q", got, closed)
			}
		})
	}
}

// RFC 4303 section 3.3.3 has an attempt to transmit past the sequence space "an auditable event"
// each spent SA is logged once, with the time, the SPI of the outbound SA, both endpoints, the addresses its packets leave from and go to and the sequence number the refused packet needed, however often a send finds it spent
func TestSpentSequenceSpaceIsLoggedOncePerSA(t *testing.T) {
	var logged bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	mux, _ := lifecycleMuxes(t)
	first, second := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}, ChildSA{LocalSPI: 0x11213141, RemoteSPI: 0x51617181}
	s := &Session{mux: mux, Child: first, childSpent: make(chan struct{}, 1),
		local: identity.MustParse("testorg/client:2"), remote: identity.MustParse("testorg/server:1")}
	for range 3 {
		s.ChildSequenceSpent(first.LocalSPI)
	}
	s.Child = second
	for range 3 {
		s.ChildSequenceSpent(second.LocalSPI)
	}
	var lines []string
	for line := range strings.Lines(logged.String()) {
		if strings.Contains(line, `msg="ike Child SA ran out of sequence numbers"`) {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("the two spent SAs were logged %d times, want once each: %q", len(lines), lines)
	}
	for i, child := range []ChildSA{first, second} {
		want := fmt.Sprintf("spi=%08x spi_in=%08x local=testorg/client:2 remote=testorg/server:1 src=%s dst=%s seq=4294967296", child.RemoteSPI, child.LocalSPI, mux.LocalAddr(), mux.Endpoint())
		if !strings.HasPrefix(lines[i], "time=") || !strings.Contains(lines[i], want) {
			t.Errorf("spent SA %d was logged as %q, want its time and %q", i, lines[i], want)
		}
	}
}

// in the test of a peer that accepts every rekey, each SA lives keptLifetime, its rekey falls due keptMargin before that, and the session starts and each Delete is answered keptLate later than it would be, which is longer than the margin
// the rekeys are further apart than the peer's floor between two of its SA's, minPeerChildRekeyInterval and minPeerIKERekeyInterval, and the test watches keptLifetimes lifetimes of the SA
const (
	keptLifetime  = 2 * time.Second
	keptMargin    = 700 * time.Millisecond
	keptLate      = 800 * time.Millisecond
	keptLifetimes = 3
)

// a scheduled rekey counts from its SA's establishment, when Run starts and when a rekey replaces the SA, so the margin is the time each rekey has before the lifetime
// a peer that accepts every rekey then keeps one session across many lifetimes of each SA, however late Run starts and however long the replaced SA's Delete takes
func TestSessionKeepsItsSAsAcrossTheirLifetimes(t *testing.T) {
	if keptLate <= keptMargin || keptLifetime-keptMargin <= max(minPeerChildRekeyInterval, minPeerIKERekeyInterval) {
		t.Fatalf("a delay of %s against a margin of %s, and rekeys %s apart, prove nothing about the rekey's start", keptLate, keptMargin, keptLifetime-keptMargin)
	}
	for _, sa := range []string{"child", "ike"} {
		t.Run(sa, func(t *testing.T) {
			pair := dialRefusing(t, func(cfg *PeerConfig) {
				if sa == "child" {
					cfg.ChildRekeyInterval = keptLifetime
				} else {
					cfg.IKERekeyInterval = keptLifetime
				}
				cfg.RekeyMargin, cfg.RekeyJitter = keptMargin, 0
				cfg.RemotePort = relay(t, cfg.RemotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
					if !fromInitiator && header != nil && header.ExchangeType == INFORMATIONAL && header.IsResponse() {
						time.Sleep(keptLate)
					}
					return true
				})
			}, func(initiator, responder *Session) {
				initiator.dpdEvery, responder.dpdEvery = time.Hour, time.Hour
				time.Sleep(keptLate)
			})
			select {
			case err := <-pair.initiatorDone:
				t.Fatalf("the session ended with a peer that accepts every rekey: %v, it recorded %q", err, pair.dialed.recorded())
			case <-time.After(keptLifetimes * keptLifetime):
			}
			ends := "testorg/client:2>testorg/server:1 sa=" + sa
			got := pair.dialed.recorded()
			completed := 0
			for _, line := range got {
				if line == "ike.rekey.completed "+ends+" suite="+defaultSuite[sa] {
					completed++
				}
			}
			if completed < keptLifetimes-1 || slices.ContainsFunc(got, func(line string) bool {
				return strings.HasPrefix(line, "ike.sa.closed ") || strings.HasPrefix(line, "ike.rekey.failed ")
			}) {
				t.Errorf("over %d lifetimes the session recorded %q, want a rekey completed in each and none failed or closed", keptLifetimes, got)
			}
		})
	}
}

// a Child SA replaced a second before its lifetime, its Delete answered at once, drains no longer than that lifetime
func TestReplacedChildSAKeysLeaveByItsLifetime(t *testing.T) {
	const lifetime = 2 * time.Second
	var (
		established time.Time
		old         uint32
		keys        *dataplane
	)
	dialRefusing(t, func(cfg *PeerConfig) {
		cfg.ChildRekeyInterval = lifetime
		cfg.RekeyMargin, cfg.RekeyJitter = lifetime/2, 0
	}, func(initiator, _ *Session) {
		established, old = initiator.childEstablished, initiator.Child.LocalSPI
		keys = newDataplane(initiator)
	})
	end := established.Add(lifetime)
	removed := func(change keyChange) bool { return change.spi == old && change.removed }
	for deadline := end.Add(childRetireDelay + answerBudget); !slices.ContainsFunc(keys.recorded(), removed); time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("the replaced Child SA's keys never came out, the dataplane saw %+v", keys.recorded())
		}
	}
	changes := keys.recorded()
	if !slices.ContainsFunc(changes, func(change keyChange) bool { return !change.removed }) {
		t.Fatalf("the dataplane saw %+v, want the replacement's keys in before the replaced SA's came out", changes)
	}
	if at := changes[slices.IndexFunc(changes, removed)].at; !at.Before(end.Add(answerLate)) {
		t.Errorf("the replaced Child SA's keys came out %s past its lifetime, want by it", at.Sub(end))
	}
}

// a Child SA the peer replaced two seconds before its lifetime and has not deleted yet is withdrawn at that lifetime, which the session wakes for, and its SPI stays routed for the Delete
func TestReplacedChildSAAwaitingItsDeleteIsWithdrawnAtItsLifetime(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	old := ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, Child: old, childRekeyInterval: time.Hour, childEstablished: time.Now().Add(-time.Hour + 2*time.Second)}
	keys := newDataplane(s)
	ends := s.childEstablished.Add(time.Hour)
	if err := s.replaceChild(ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}); err != nil {
		t.Fatal(err)
	}
	if at, ok := s.nextRetirement(); !ok || !at.Equal(ends) {
		t.Errorf("the session next wakes for its replaced SA at %v, want its lifetime's end %v", at, ends)
	}
	removed := func(change keyChange) bool { return change.spi == old.LocalSPI && change.removed }
	if err := s.expireChild(ends.Add(-time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(keys.recorded(), removed) {
		t.Fatal("the replaced Child SA's keys came out before its lifetime")
	}
	if err := s.expireChild(ends); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(keys.recorded(), removed) {
		t.Fatalf("at its lifetime the replaced Child SA's keys are still in, the dataplane saw %+v", keys.recorded())
	}
	if at, ok := s.nextRetirement(); !ok || !at.Equal(s.retiringBy) {
		t.Errorf("after the withdrawal the session next wakes for its replaced SA at %v, want the wait for the peer's Delete to end at %v", at, s.retiringBy)
	}
	if err := other.RegisterESP(old.LocalSPI); err == nil {
		t.Fatal("the withdrawn SA's SPI is no longer routed, so the peer's Delete for it finds nothing")
	}
	if spis, err := s.deleteChildren([]uint32{old.RemoteSPI}); err != nil || !slices.Equal(spis, []uint32{old.LocalSPI}) {
		t.Fatalf("the peer's Delete of the withdrawn SA was answered with %08x, %v, want its SPI", spis, err)
	}
	if err := other.RegisterESP(old.LocalSPI); err != nil {
		t.Errorf("after the peer's Delete the withdrawn SA's SPI is still routed: %v", err)
	}
	if got := slices.DeleteFunc(keys.recorded(), func(change keyChange) bool { return !removed(change) }); len(got) != 1 {
		t.Errorf("the replaced Child SA's keys came out %d times, want once", len(got))
	}
}

// a replaced Child SA whose Delete arrives past its lifetime, before the session has withdrawn it, has nothing left to drain, so its keys leave with the Delete
func TestReplacedChildSADeletedPastItsLifetimeIsNotDrained(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	old := ChildSA{LocalSPI: 0x11111111, RemoteSPI: 0x33333333}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, Child: old, childRekeyInterval: time.Hour, childRetireDelay: childRetireDelay, childEstablished: time.Now().Add(-time.Hour - time.Second)}
	keys := newDataplane(s)
	if err := s.replaceChild(ChildSA{LocalSPI: 0x22222222, RemoteSPI: 0x44444444}); err != nil {
		t.Fatal(err)
	}
	if spis, err := s.deleteChildren([]uint32{old.RemoteSPI}); err != nil || !slices.Equal(spis, []uint32{old.LocalSPI}) {
		t.Fatalf("the peer's Delete of the replaced SA was answered with %08x, %v, want its SPI", spis, err)
	}
	if !slices.ContainsFunc(keys.recorded(), func(change keyChange) bool { return change.spi == old.LocalSPI && change.removed }) {
		t.Errorf("the replaced Child SA's keys stayed in past its lifetime to drain, the dataplane saw %+v", keys.recorded())
	}
	if len(s.retired) != 0 {
		t.Errorf("the replaced Child SA past its lifetime was left to drain until %v", s.retired[0].expiresAt)
	}
	if err := other.RegisterESP(old.LocalSPI); err != nil {
		t.Errorf("after the peer's Delete the replaced SA's SPI is still routed: %v", err)
	}
}

// an IKE SA the peer's rekey replaced two seconds before its lifetime is kept for the peer's Delete until that lifetime and no longer, and answers no request past it
// one this end replaced is kept for its own Delete, the last request section 2.8 has it send there, and takes that Delete's answer past its lifetime
func TestReplacedIKESAIsDroppedAtItsLifetime(t *testing.T) {
	for _, ownDelete := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleted here %v", ownDelete), func(t *testing.T) {
			mux, other := lifecycleMuxes(t)
			now := time.Now()
			old := &ikeContext{spiI: 0x0102030405060708, spiR: 0x1112131415161718, established: now.Add(-time.Hour + 2*time.Second), ownDelete: ownDelete}
			if err := mux.RegisterIKE(old.spiI); err != nil {
				t.Fatal(err)
			}
			s := &Session{mux: mux, current: &ikeContext{spiI: 0x2122232425262728, spiR: 0x3132333435363738, established: now}, ikeRekeyInterval: time.Hour}
			ends, deadline := old.established.Add(time.Hour), now.Add(retainedContextDeadline)
			s.stateMu.Lock()
			s.retainOldLocked(old)
			s.stateMu.Unlock()
			want := ends
			if ownDelete {
				want = deadline
			}
			if at, ok := s.nextRetainedExpiry(); !ok || at.Before(want) || at.After(want.Add(time.Second)) {
				t.Errorf("the replaced IKE SA is kept until %v, want %v", at, want)
			}
			request, response := &Header{SPIInitiator: old.spiI, SPIResponder: old.spiR}, &Header{SPIInitiator: old.spiI, SPIResponder: old.spiR, Flags: FlagResponse}
			if s.contextForHeader(request) != old || s.contextForHeader(response) != old {
				t.Fatal("inside its lifetime the replaced IKE SA takes nothing")
			}
			// the clock is the SA's own, so its start moving back an hour is the hour passing
			old.established = old.established.Add(-time.Hour)
			if s.contextForHeader(request) != nil {
				t.Error("past its lifetime the replaced IKE SA still answers a request")
			}
			if s.contextForHeader(response) != old {
				t.Error("past its lifetime the replaced IKE SA no longer takes the answer to this end's request on it")
			}
			s.expireRetainedContexts(ends)
			if _, held := s.contexts(); (held == nil) == ownDelete {
				t.Errorf("at its lifetime the session holds the replaced IKE SA %v, want it held only for its own Delete", held)
			}
			if err := other.RegisterIKE(old.spiI); (err == nil) == ownDelete {
				t.Errorf("at its lifetime registering the replaced IKE SA's SPI elsewhere returned %v", err)
			}
		})
	}
}
