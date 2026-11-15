// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/bubble"
)

const (
	authDeadline = handshakeTimeout
	authPause    = authDeadline + requestTimeout/2
)

// a committed handshake must hand over open muxes even if the handshake deadline passes before its return
func TestResponderHandshakeHandoffOutlivesDeadline(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		h := newConfiguredResponderHarness(t,
			map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil,
			func(cfg *ResponderConfig) {
				cfg.HandshakeTimeout = authDeadline
				cfg.InitialContact = func(s *Session, _ identity.Identity) bool {
					s.SetChildHandler(func(ChildSA) error {
						time.Sleep(authPause)
						return nil
					})
					return false
				}
			})
		initiator, err := InitiateContext(context.Background(), h.peerConfig())
		if err != nil {
			t.Fatalf("the initiator did not authenticate the response: %v", err)
		}
		defer initiator.mux.Close()
		select {
		case responder := <-h.sessions:
			defer responder.mux.Close()
			if responder.mux.IsClosed() || initiator.mux.IsClosed() {
				t.Fatal("the handshake handed over a closed mux")
			}
		case <-time.After(answerBudget):
			t.Fatal("the responder did not hand over the authenticated session")
		}
	})(t)
}

// an authenticated handshake that loses its commit reports whether its deadline or the responder's stop ended it
func TestResponderHandshakeReportsCancellation(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name, cause := "deadline", context.DeadlineExceeded
		if stop {
			name, cause = "responder stop", context.Canceled
		}
		t.Run(name, bubble.Run(func(t *testing.T) {
			ended := make(chan string, 1)
			var h *responderHarness
			h = newConfiguredResponderHarness(t,
				map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil,
				func(cfg *ResponderConfig) { cfg.HandshakeTimeout = handshakeTimeout },
				func(_, _ identity.Identity, kind string, attrs ...slog.Attr) {
					if kind == "ike.id.resolved" {
						if stop {
							h.cancel()
						} else {
							time.Sleep(authPause)
						}
					}
					if kind == "ike.handshake.failed" {
						for _, attr := range attrs {
							if attr.Key == "err" {
								ended <- attr.Value.String()
							}
						}
					}
				})
			mux := childRefusedMux(t, h)
			dialRefusedChild(t, h, mux)
			select {
			case failure := <-ended:
				if !strings.Contains(failure, "authenticated handshake") || !strings.Contains(failure, cause.Error()) {
					t.Errorf("the responder reported %q, want authenticated handshake and %q", failure, cause)
				}
			case <-time.After(authPause + answerBudget):
				t.Fatal("the responder did not report why the authenticated handshake ended")
			}
		}))
	}
}

// a handshake whose deadline wins cannot publish an authenticated answer or change initial contact state
func TestResponderHandshakeDeadlinePreventsSuccess(t *testing.T) {
	for _, refused := range []bool{false, true} {
		name := "accepted child"
		if refused {
			name = "refused child"
		}
		t.Run(name, bubble.Run(func(t *testing.T) {
			var contacts atomic.Int32
			failures := &recorder{}
			h := newConfiguredResponderHarness(t,
				map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil,
				func(cfg *ResponderConfig) {
					cfg.HandshakeTimeout = handshakeTimeout
					cfg.InitialContact = func(*Session, identity.Identity) bool {
						contacts.Add(1)
						return true
					}
				}, func(local, remote identity.Identity, kind string, attrs ...slog.Attr) {
					failures.record(local, remote, kind, attrs...)
					if kind == "ike.id.resolved" {
						time.Sleep(authPause)
					}
				})
			mux := childRefusedMux(t, h)
			var held *ikeContext
			if refused {
				held, _ = dialRefusedChild(t, h, mux)
			} else {
				held, _ = dialSignedBy(t, h, mux, h.private, "testorg/client:2", "testorg/server:1",
					func(child *Proposal) { *child = espProposal([]byte{0, 0, 0, 9}) })
			}
			time.Sleep(authPause)
			awaitHandshakeEnd(t, h, failures, held.spiI)
			if contacts.Load() != 0 {
				t.Fatal("the responder changed initial contact state after the handshake deadline")
			}
			if raw, err := recvIKEUntil(mux, time.Now().Add(quietPeriod)); err == nil {
				t.Fatalf("the responder sent %d bytes after the handshake deadline, want silence", len(raw))
			}
			select {
			case session := <-h.sessions:
				session.mux.Close()
				t.Fatal("the responder handed over a session after the handshake deadline")
			default:
			}
		}))
	}
}
