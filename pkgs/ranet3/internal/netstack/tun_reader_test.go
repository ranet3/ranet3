// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// scriptedRead is one answer of a scriptedDevice to Read
type scriptedRead struct {
	packets [][]byte
	err     error
}

// scriptedDevice answers each Read with the next scripted answer
// and reports closure once the mesh closes it
type scriptedDevice struct {
	recordingDevice
	reads  chan scriptedRead
	closed chan struct{}
}

func (d *scriptedDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case read := <-d.reads:
		for i, packet := range read.packets {
			sizes[i] = copy(bufs[i][offset:], packet)
		}
		return len(read.packets), read.err
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *scriptedDevice) Close() error {
	close(d.closed)
	return nil
}

// deliveryTimeout bounds the wait for the packets a reader hands on
// and deliveryPoll is how often the test looks for them
const (
	deliveryTimeout = 5 * time.Second
	deliveryPoll    = time.Millisecond
)

// a GSO frame of more segments than one read holds
// comes back cut short with ErrTooManySegments
// and a reader that stopped there would leave its queue's flows unread
func TestReaderKeepsReadingPastACutGSOFrame(t *testing.T) {
	dev := &scriptedDevice{reads: make(chan scriptedRead, 2), closed: make(chan struct{})}
	sent := &recordingPeer{}
	m := &Mesh{
		Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + outboundPacketBufferSize,
	}
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("::/0"), sent.peer("peer"))
	m.startOutboundPipeline()
	t.Cleanup(m.Close)

	source, destination := segAddr("fd00::1"), segAddr("fd00::2")
	want := [][]byte{
		plainV6(source, destination, "first segment of the frame"),
		plainV6(source, destination, "last segment the read held"),
		plainV6(source, destination, "next read"),
	}
	dev.reads <- scriptedRead{packets: want[:2], err: tun.ErrTooManySegments}
	dev.reads <- scriptedRead{packets: want[2:]}

	deadline := time.Now().Add(deliveryTimeout)
	for len(sent.packets()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(deliveryPoll)
	}
	got := sent.packets()
	if len(got) != len(want) {
		t.Fatalf("the peer was sent %d packets, want the two of the cut read and the one after it", len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("packet %d is %x, want %x", i, got[i], want[i])
		}
	}
}
