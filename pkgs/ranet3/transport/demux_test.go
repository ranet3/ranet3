// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

const (
	// churnBatches is how many batches each receive loop of the churn test demultiplexes
	churnBatches = 2000
	// churners is how many goroutines open, register and close muxes beside those loops
	churners = 4
	// churnSPIs is how many SPIs of each protocol the loops and the churners share
	churnSPIs = 8
	// tableChanges is how many registrations the visibility test makes, each followed by a datagram
	tableChanges = 32
)

// two receive loops demultiplex while muxes register, unregister and close around them
// a loop reads a published table without a lock, so a change written into one in place is a race the detector reports
// every packet a mux is handed carries an SPI that mux registered, whether it arrives before or after the close
func TestReceiveLoopsReadTablesThatRegistrationsReplace(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	hub.Listen()
	var datagrams [][]byte
	for spi := range uint32(churnSPIs) {
		esp := binary.BigEndian.AppendUint32(nil, spi+1)
		datagrams = append(datagrams, binary.BigEndian.AppendUint32(esp, 1))
		ike := binary.BigEndian.AppendUint64(make([]byte, nonESPMarkerLen), uint64(spi)+1)
		datagrams = append(datagrams, append(ike, make([]byte, 16)...))
	}

	var loops sync.WaitGroup
	for range 2 {
		left := churnBatches
		loops.Go(func() {
			hub.receiveLoop(func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
				if left == 0 {
					return 0, 0, errors.New("the churn is over")
				}
				left--
				for i, datagram := range datagrams {
					bufs[i], sizes[i], endpoints[i] = datagram, len(datagram), nil
				}
				return len(datagrams), 0, nil
			})
		})
	}
	var churn sync.WaitGroup
	for worker := range churners {
		churn.Go(func() {
			for turn := 0; ; turn++ {
				// the first loop to finish fails the hub, which refuses the next mux and ends the churn
				mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 9)
				if err != nil {
					return
				}
				spi := uint32((worker+turn)%churnSPIs) + 1
				ownsESP := mux.RegisterESP(spi) == nil
				ownsIKE := mux.RegisterIKE(uint64(spi)) == nil
				if turn%2 == 0 {
					mux.UnregisterESP(spi)
					mux.UnregisterIKE(uint64(spi))
				}
				mux.Close()
			drain:
				for {
					select {
					case batch := <-mux.espCh:
						for _, packet := range batch.packets {
							if got := binary.BigEndian.Uint32(packet); !ownsESP || got != spi {
								t.Errorf("a mux that registered ESP SPI %d (%v) was handed SPI %d", spi, ownsESP, got)
							}
						}
					case datagram := <-mux.ikeCh:
						if got := binary.BigEndian.Uint64(datagram.Raw); !ownsIKE || got != uint64(spi) {
							t.Errorf("a mux that registered IKE SPI %d (%v) was handed SPI %d", spi, ownsIKE, got)
						}
					default:
						break drain
					}
				}
			}
		})
	}
	loops.Wait()
	churn.Wait()
}

// a registration that returned before a datagram arrives routes it, and an unregistration refuses it
// the receive loop loads the tables for each batch, so a change reaches the next datagram read
func TestTableChangesReachTheNextDatagram(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 9)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hub.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	for spi := uint32(1); spi <= tableChanges; spi++ {
		if err := mux.RegisterESP(spi); err != nil {
			t.Fatal(err)
		}
		packet := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1)
		if _, err := sender.Write(packet); err != nil {
			t.Fatal(err)
		}
		got, err := mux.RecvESPUntil(time.Now().Add(arrivalBudget))
		if err != nil || binary.BigEndian.Uint32(got) != spi {
			t.Fatalf("ESP SPI %d registered before its datagram arrived, and the mux read %x, %v", spi, got, err)
		}

		mux.UnregisterESP(spi)
		refused := hub.Refused()
		if _, err := sender.Write(packet); err != nil {
			t.Fatal(err)
		}
		for deadline := time.Now().Add(arrivalBudget); hub.Refused() == refused; time.Sleep(pollInterval) {
			if time.Now().After(deadline) {
				t.Fatalf("ESP SPI %d was unregistered before its datagram arrived, and the datagram was not refused", spi)
			}
		}

		if err := mux.RegisterIKE(uint64(spi)); err != nil {
			t.Fatal(err)
		}
		request := append(binary.BigEndian.AppendUint64(make([]byte, nonESPMarkerLen), uint64(spi)), make([]byte, 20)...)
		if _, err := sender.Write(request); err != nil {
			t.Fatal(err)
		}
		message, _, err := mux.RecvIKEFromUntil(time.Now().Add(arrivalBudget))
		if err != nil || binary.BigEndian.Uint64(message) != uint64(spi) {
			t.Fatalf("IKE SPI %d registered before its datagram arrived, and the mux read %x, %v", spi, message, err)
		}
	}
}

// a closed mux gives up its SPIs, so a datagram for one is refused and another mux can register it and read its datagrams
func TestClosedMuxGivesUpItsSPIs(t *testing.T) {
	hub, err := NewHub(":0", Underlay{}, Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	const spi = 7
	closed, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.RegisterESP(spi); err != nil {
		t.Fatal(err)
	}
	if err := closed.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}
	closed.Close()
	sender, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hub.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	packet := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, spi), 1)
	refused := hub.Refused()
	if _, err := sender.Write(packet); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(arrivalBudget); hub.Refused() == refused; time.Sleep(pollInterval) {
		if time.Now().After(deadline) {
			t.Fatalf("a datagram for ESP SPI %d of a closed mux was not refused", spi)
		}
	}

	next, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 9)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err := next.RegisterESP(spi); err != nil {
		t.Fatalf("ESP SPI %d of a closed mux: %v", spi, err)
	}
	if err := next.RegisterIKE(spi); err != nil {
		t.Fatalf("IKE SPI %d of a closed mux: %v", spi, err)
	}
	if _, err := sender.Write(packet); err != nil {
		t.Fatal(err)
	}
	if got, err := next.RecvESPUntil(time.Now().Add(arrivalBudget)); err != nil || binary.BigEndian.Uint32(got) != spi {
		t.Fatalf("the mux that took ESP SPI %d over read %x, %v", spi, got, err)
	}
	request := append(binary.BigEndian.AppendUint64(make([]byte, nonESPMarkerLen), spi), make([]byte, 20)...)
	if _, err := sender.Write(request); err != nil {
		t.Fatal(err)
	}
	if message, _, err := next.RecvIKEFromUntil(time.Now().Add(arrivalBudget)); err != nil || binary.BigEndian.Uint64(message) != spi {
		t.Fatalf("the mux that took IKE SPI %d over read %x, %v", spi, message, err)
	}
}
