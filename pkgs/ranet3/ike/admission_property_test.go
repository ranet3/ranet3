// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package ike

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/transport"
)

func TestConcurrentAdmissionKeepsCookieThresholds(t *testing.T) {
	hub := listenHub(t)
	var endpoints []transport.Endpoint
	for i := range 8 {
		endpoints = append(endpoints, observedEndpointFrom(t, hub, uint64(i+1), net.IPv4(192, 0, 2, byte(i+1))))
	}
	nonce := bytes.Repeat([]byte{7}, 32)
	check := func(errorf func(string, ...any), n, addresses, perSource, initial int) {
		r := &Responder{halfOpen: initial, halfOpenBySource: make(map[netip.Addr]int), cookieRotated: time.Now()}
		r.cfg.Hub = hub
		for _, endpoint := range endpoints[:addresses] {
			r.halfOpenBySource[endpoint.AddrPort().Addr()] = perSource
		}
		type result struct {
			source     netip.Addr
			challenged bool
			err        error
		}
		decided, release := make(chan struct{}, n), make(chan struct{})
		r.afterAdmission = func() {
			decided <- struct{}{}
			<-release
		}
		r.beforeReservation = r.afterAdmission
		done := make(chan result, n)
		for i := range n {
			go func() {
				endpoint := endpoints[i%addresses]
				challenged, err := r.admit(&Message{}, nonce, uint64(i+1), endpoint)
				if challenged || err != nil {
					decided <- struct{}{}
				}
				done <- result{endpoint.AddrPort().Addr(), challenged, err}
			}()
		}
		// a split entering a fresh reservation also pauses before that second lock
		timer := time.NewTimer(answerBudget)
		complete := true
	decisions:
		for range n {
			select {
			case <-decided:
			case <-timer.C:
				complete = false
				break decisions
			}
		}
		timer.Stop()
		close(release)
		admitted := make(map[netip.Addr]int)
		total := 0
		var admissionError error
		for range n {
			got := <-done
			if got.err != nil {
				admissionError = got.err
			}
			if !got.challenged && got.err == nil {
				admitted[got.source]++
				total++
			}
		}
		if !complete {
			errorf("admission callers did not reach their decisions before the wait expired")
			return
		}
		if admissionError != nil {
			errorf("admission failed: %v", admissionError)
		}
		room := 0
		for i := range addresses {
			requests := n / addresses
			if i < n%addresses {
				requests++
			}
			room += min(requests, halfOpenPerSourceWithoutCookie-perSource)
			source := endpoints[i].AddrPort().Addr()
			if got := perSource + admitted[source]; got > halfOpenPerSourceWithoutCookie || r.halfOpenBySource[source] != got {
				errorf("source %s admitted %d, holds %d, threshold %d", source, got, r.halfOpenBySource[source], halfOpenPerSourceWithoutCookie)
			}
		}
		want := min(room, cookieThreshold-initial)
		if total != want || r.halfOpen != initial+total {
			errorf("admitted %d, want %d, holds %d from initial %d", total, want, r.halfOpen, initial)
		}
	}
	t.Run("source", func(t *testing.T) {
		check(t.Fatalf, halfOpenPerSourceWithoutCookie+1, 1, 0, 0)
	})
	t.Run("node", func(t *testing.T) {
		check(t.Fatalf, 2, 2, 0, cookieThreshold-1)
	})
	if t.Failed() {
		return
	}
	pbt.Check(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, pbt.Spanning(1, 2*cookieThreshold))
		addresses := hegel.Draw(ht, pbt.Spanning(1, len(endpoints)))
		perSource := hegel.Draw(ht, pbt.Spanning(0, halfOpenPerSourceWithoutCookie))
		initial := hegel.Draw(ht, pbt.Spanning(addresses*perSource, cookieThreshold))
		check(ht.Errorf, n, addresses, perSource, initial)
	})
}

func TestCookieThresholdsLeaveRoomUnderHardCaps(t *testing.T) {
	if cookieThreshold >= halfOpenLimit || halfOpenPerSourceWithoutCookie >= halfOpenPerSource {
		t.Fatal("cookie thresholds must be below both hard caps")
	}
}
