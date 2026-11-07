// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// The link holds no more bytes than its bound: a packet past it is dropped,
// counted and reported as a full device queue, and a released packet's bytes
// make room again
func TestLinkDropsWhatItsBoundHasNoRoomFor(t *testing.T) {
	const size = 1000
	l := newLink(2*size + size/2)
	defer l.Close()
	write := func() (int, tcpip.Error) {
		var list stack.PacketBufferList
		list.PushBack(stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, size))}))
		defer list.DecRef()
		return l.WritePackets(list)
	}
	for i := range 2 {
		if n, err := write(); n != 1 || err != nil {
			t.Fatalf("write %d within the bound took %d: %v", i, n, err)
		}
	}
	n, err := write()
	if _, full := err.(*tcpip.ErrNoBufferSpace); n != 0 || !full {
		t.Fatalf("a write past the bound took %d: %v, want none and a full queue", n, err)
	}
	if dropped := l.dropped.Load(); dropped != 1 {
		t.Errorf("dropped %d, want 1", dropped)
	}
	l.release(l.poll())
	if n, err := write(); n != 1 || err != nil {
		t.Errorf("a write once a packet was released took %d: %v", n, err)
	}
}
