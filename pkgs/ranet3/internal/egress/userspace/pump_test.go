// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package userspace

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"ranet3.com/pkgs/wireguard/tun"
)

const (
	// pumpAllocRuns is the runs of the pump each allocation count averages
	pumpAllocRuns = 100
	// pumpFills is the calls of its lane's fill in a long run of the pump
	pumpFills = 64
)

// fillsLane is a lane whose Fill lays nothing and reports false at its
// fills-th call. Its other methods are the nil Lane's, which the pump calls
// none of while it holds a packet.
type fillsLane struct {
	Lane
	fills, calls int
}

func (l *fillsLane) Fill(func(slab []byte, reads []tun.ReadPacket) int) bool {
	l.calls++
	return l.calls < l.fills
}

func (*fillsLane) Close() {}

// The pump allocates nothing at a call of its lane's fill: a run that calls
// it pumpFills times allocates what a run that calls it once does, and the
// two runs differ in nothing else
func TestPumpAllocatesNothingAtAFill(t *testing.T) {
	l := newLink(1 << 30)
	defer l.Close()
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(make([]byte, 100))})
	defer pkt.DecRef()
	p := &pump{link: l, unlaid: func() {}}
	allocs := func(fills int) float64 {
		lane := &fillsLane{fills: fills}
		return testing.AllocsPerRun(pumpAllocRuns, func() {
			lane.calls = 0
			// the run gives the packet back as it ends, so it holds one more
			// reference each time
			p.held = pkt.IncRef()
			p.run(lane, nil)
		})
	}
	if one, many := allocs(1), allocs(pumpFills); many != one {
		t.Errorf("a run of the pump that called its lane's fill %d times allocated %v times, one that called it once %v", pumpFills, many, one)
	}
}
