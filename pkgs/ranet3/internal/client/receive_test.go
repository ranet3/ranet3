// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/binary"
	"net"
	"testing"

	"ranet3.com/pkgs/ranet3/transport"
)

// receivedSPI is the SPI the datagrams receivedBatches reads carry
const receivedSPI = 0x1000

// receivedBatches is count batches of one datagram each read off a memory hub, which a test hands the emitter as a worker would, each datagram's fifth byte its index
// a datagram past them is read too, so every block the batches lie in is one the reader read past, which a release puts back in the pool and the memory hub overwrites
func receivedBatches(t *testing.T, count int) []*transport.Received {
	t.Helper()
	network := transport.NewMemoryNetwork()
	hub, err := network.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hub.Close() })
	loopback := net.IPv4(127, 0, 0, 1)
	sender, err := network.ListenUDP(loopback)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sender.Close() })
	mux, err := hub.NewMux(loopback, sender.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterESP(receivedSPI); err != nil {
		t.Fatal(err)
	}
	destination := &net.UDPAddr{IP: loopback, Port: hub.LocalAddr().(*net.UDPAddr).Port}
	batches := make([]*transport.Received, 0, count)
	for i := range count + 1 {
		datagram := binary.BigEndian.AppendUint32(nil, receivedSPI)
		if _, err := sender.WriteToUDP(append(datagram, byte(i), 0, 0, 0), destination); err != nil {
			t.Fatal(err)
		}
		batch, err := mux.RecvESPBatchConcurrent()
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
	}
	return batches[:count]
}
