// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"net"
	"testing"
	"time"
)

// dial is a mux to remoteIP and remotePort on a hub of its own at an ephemeral port, the hub closed when the test ends
func dial(t *testing.T, remoteIP net.IP, remotePort int) *Mux {
	t.Helper()
	hub, err := NewHub(0, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	m, err := hub.NewMux(remoteIP, remotePort)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *Mux) RecvIKE() ([]byte, error) {
	select {
	case d := <-m.ikeCh:
		return d.Raw, nil
	case <-m.done:
		return nil, m.doneError()
	}
}

func (m *Mux) RecvIKEUntil(deadline time.Time) ([]byte, error) {
	b, _, err := m.RecvIKEFromUntil(deadline)
	return b, err
}

func (m *Mux) SendESP(b []byte) error { return m.SendESPBatch([][]byte{b}) }

// espReader reads a mux's ESP one packet at a time through RecvESPBatchConcurrent, keeping the rest of each batch for the reads after
type espReader struct {
	m       *Mux
	pending [][]byte
}

func newESPReader(m *Mux) *espReader { return &espReader{m: m} }

// next is the next packet, waiting for a batch until deadline
// a wait that times out closes the mux, which ends the receive it started
func (r *espReader) next(deadline time.Time) ([]byte, error) {
	if len(r.pending) == 0 {
		var packets [][]byte
		read := make(chan error, 1)
		go func() {
			var err error
			_, packets, _, err = r.m.RecvESPBatchConcurrent()
			read <- err
		}()
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case err := <-read:
			if err != nil {
				return nil, err
			}
		case <-timer.C:
			_ = r.m.Close()
			<-read
			return nil, errTimeout
		}
		r.pending = packets
	}
	packet := r.pending[0]
	r.pending = r.pending[1:]
	return packet, nil
}
