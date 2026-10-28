// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"ranet3.com/pkgs/ranet3/internal/bubble"
)

// memoryNetworkAt opens a network with a hub, a mux dialed from a hub of its own to that hub and a socket, and closes them at cleanup
func memoryNetworkAt(t *testing.T) (*MemoryNetwork, *Hub, *Mux, *MemoryConn) {
	t.Helper()
	network := NewMemoryNetwork()
	hub, err := network.NewHub()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	mux, err := network.Dial(net.IPv4(127, 0, 0, 1), hub.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	conn, err := network.ListenUDP(net.IPv6loopback)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return network, hub, mux, conn
}

// a hub, a mux that owns one and a socket of a memory network wait where a bubble's clock can pass them, so a sleep returns at its fake end
func TestMemoryNetworkLeavesTheBubblesClockToRun(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		memoryNetworkAt(t)
		start := time.Now()
		time.Sleep(time.Hour)
		if slept := time.Since(start); slept != time.Hour {
			t.Errorf("the sleep took %v, want an hour", slept)
		}
	})(t)
}

// a socket's read deadline runs on the bubble's clock, and its read ends at the deadline with the error net's sockets answer
// and a read waiting on a socket that never had a deadline wakes once one is set in its past, which is how a test stops a peer it reads for
func TestMemorySocketReadEndsAtItsDeadline(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		_, _, _, conn := memoryNetworkAt(t)
		read := make(chan error)
		go func() {
			_, _, err := conn.ReadFromUDP(make([]byte, 16))
			read <- err
		}()
		time.Sleep(time.Minute)
		if err := conn.SetDeadline(time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := <-read; !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("the read waiting when its deadline moved to now answered %v, want os.ErrDeadlineExceeded", err)
		}
		start := time.Now()
		if err := conn.SetReadDeadline(start.Add(30 * time.Second)); err != nil {
			t.Fatal(err)
		}
		_, _, err := conn.ReadFromUDP(make([]byte, 16))
		if waited := time.Since(start); waited != 30*time.Second {
			t.Errorf("the read waited %v, want its deadline's 30s", waited)
		}
		var timeout net.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Errorf("the read past its deadline answered %v, want a timeout that is os.ErrDeadlineExceeded", err)
		}
	})(t)
}

// closing a hub, a mux that owns one and a socket ends every goroutine they run and wakes every read waiting on them
// the bubble fails where a goroutine it started is left
func TestClosingMemoryHubsAndSocketsEndsWhatTheyRan(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		network := NewMemoryNetwork()
		hub, err := network.NewHub()
		if err != nil {
			t.Fatal(err)
		}
		mux, err := network.Dial(net.IPv4(127, 0, 0, 1), hub.LocalAddr().(*net.UDPAddr).Port)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := network.ListenUDP(net.IPv4(127, 0, 0, 1))
		if err != nil {
			t.Fatal(err)
		}
		read := make(chan error)
		go func() {
			_, _, err := conn.ReadFromUDP(make([]byte, 16))
			read <- err
		}()
		synctest.Wait()
		if err := hub.Close(); err != nil {
			t.Errorf("closing the hub answered %v", err)
		}
		if err := mux.Close(); err != nil {
			t.Errorf("closing the mux answered %v", err)
		}
		if err := conn.Close(); err != nil {
			t.Errorf("closing the socket answered %v", err)
		}
		if err := <-read; !errors.Is(err, net.ErrClosed) {
			t.Errorf("the read waiting when its socket closed answered %v, want net.ErrClosed", err)
		}
		if _, err := conn.WriteToUDP([]byte{1}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}); !errors.Is(err, net.ErrClosed) {
			t.Errorf("a write on the closed socket answered %v, want net.ErrClosed", err)
		}
		if err := conn.Close(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("closing the socket again answered %v, want net.ErrClosed", err)
		}
		for name, done := range map[string]<-chan struct{}{"hub": hub.Done(), "mux": mux.Done()} {
			select {
			case <-done:
			default:
				t.Errorf("the %s is not done once closed", name)
			}
		}
	})(t)
}

// a mux on a memory network reads the path MTU linux gives a loopback path of its family, and sends with DF
func TestMemoryMuxReadsTheLoopbackPathMTU(t *testing.T) {
	network := NewMemoryNetwork()
	for _, test := range []struct {
		peer net.IP
		mtu  int
	}{{net.IPv4(127, 0, 0, 1), 65535}, {net.ParseIP("::ffff:127.0.0.1"), 65535}, {net.IPv6loopback, 65536}} {
		mux, err := network.Dial(test.peer, 4500)
		if err != nil {
			t.Fatal(err)
		}
		if mtu, err := mux.PathMTU(); mtu != test.mtu || err != nil {
			t.Errorf("the path to %s reads %d (%v), want %d", test.peer, mtu, err, test.mtu)
		}
		if !mux.DontFragment() {
			t.Errorf("sends to %s leave without DF", test.peer)
		}
		mux.Close()
	}
}

// the record of each datagram a hub receives, ESP and IKE alike, holds the address and port it came from
// here two senders on two ports of one address and a third on another
func TestReceiveRecordCarriesEachDatagramsSource(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		network := NewMemoryNetwork()
		p := network.hold(netip.Addr{})
		b := &memoryBind{network: network, port: p}
		defer b.Close()
		var sent []netip.AddrPort
		for _, address := range []string{"192.0.2.1", "192.0.2.1", "192.0.2.2"} {
			conn, err := network.ListenUDP(net.ParseIP(address))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			esp, ike := binary.BigEndian.AppendUint32(nil, 1), withMarker(binary.BigEndian.AppendUint64(nil, 1))
			for _, datagram := range [][]byte{esp, ike} {
				if _, err := conn.WriteToUDP(datagram, &net.UDPAddr{IP: net.ParseIP("192.0.2.9"), Port: int(p.port)}); err != nil {
					t.Fatal(err)
				}
				sent = append(sent, conn.LocalAddr().(*net.UDPAddr).AddrPort())
			}
		}
		bufs, sizes, endpoints, records := make([][]byte, len(sent)), make([]int, len(sent)), make([]Endpoint, len(sent)), make([]receiveRecord, len(sent))
		n, _, err := b.receiver(p.queues[0])(bufs, sizes, endpoints, records)
		if err != nil || n != len(sent) {
			t.Fatalf("the receive answered %d datagrams and %v, want the %d sent", n, err, len(sent))
		}
		for i, from := range sent {
			if records[i].source != from {
				t.Errorf("datagram %d from %s came with the source %v", i, from, records[i].source)
			}
		}
	})(t)
}

// a hub's receive of one family takes what its queue holds up to the vector's length, oldest first, and nothing of the other family
// as the kernel bind reads a batch from its socket of that family, the batch the hub hands a mux's ESP in
func TestMemoryHubReceivesABatchOfOneFamily(t *testing.T) {
	bubble.Run(func(t *testing.T) {
		network := NewMemoryNetwork()
		p := network.hold(netip.Addr{})
		b := &memoryBind{network: network, port: p}
		defer b.Close()
		loopbacks := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
		for family, sent := range []int{3, 2} {
			conn, err := network.ListenUDP(loopbacks[family])
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			for i := range sent {
				if _, err := conn.WriteToUDP([]byte{byte(family), byte(i)}, &net.UDPAddr{IP: loopbacks[family], Port: int(p.port)}); err != nil {
					t.Fatal(err)
				}
			}
		}
		for _, read := range []struct {
			family, vector int
			want           [][]byte
		}{
			{0, 2, [][]byte{{0, 0}, {0, 1}}},
			{0, 4, [][]byte{{0, 2}}},
			{1, 4, [][]byte{{1, 0}, {1, 1}}},
		} {
			bufs, sizes, endpoints, records := make([][]byte, read.vector), make([]int, read.vector), make([]Endpoint, read.vector), make([]receiveRecord, read.vector)
			n, _, err := b.receiver(p.queues[read.family])(bufs, sizes, endpoints, records)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(bufs[:n], read.want, bytes.Equal) {
				t.Fatalf("a receive of family %d into %d buffers took %x, want %x", read.family, read.vector, bufs[:n], read.want)
			}
		}
	})(t)
}
