// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"time"

	"ranet3.com/pkgs/ranet3/transport"
)

// recvIKEUntil is the next IKE message mux holds, waiting for it until deadline
func recvIKEUntil(mux *transport.Mux, deadline time.Time) ([]byte, error) {
	raw, _, err := mux.RecvIKEFromUntil(deadline)
	return raw, err
}

// recvESPUntil is the first packet of the next ESP batch mux holds, waiting for it until deadline
// a wait that times out closes the mux, which ends the receive it started
func recvESPUntil(mux *transport.Mux, deadline time.Time) ([]byte, error) {
	var packets [][]byte
	read := make(chan error, 1)
	go func() {
		var err error
		_, packets, _, err = mux.RecvESPBatchConcurrent()
		read <- err
	}()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case err := <-read:
		if err != nil {
			return nil, err
		}
		return packets[0], nil
	case <-timer.C:
		_ = mux.Close()
		<-read
		return nil, errors.New("no ESP arrived")
	}
}
