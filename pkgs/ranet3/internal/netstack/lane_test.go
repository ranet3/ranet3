// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"ranet3.com/pkgs/wireguard/tun"
)

// newLaneNode is newTransitNode on a mesh opened ownedOnly, as every platform
// shipping a userspace exit opens it, so a read off the tun from a source this
// node does not own is dropped toward any destination
func newLaneNode(tb testing.TB) *transitNode {
	tb.Helper()
	dev := &scriptedDevice{writes: make(chan recordedWrite, 64), reads: make(chan scriptedRead), closed: make(chan struct{})}
	m := &Mesh{Name: "test0", Routes: NewRouteTable(), closed: make(chan struct{}), ownedOnly: true}
	m.setDevice(dev)
	m.startSegmentReports()
	m.startOutboundPipeline()
	m.SetOverlay(transitOverlay)
	m.SetAnswerSources(AnswerSources{Router4: transitOwn[4], Router6: transitOwn[6]})
	m.SetAnswerTTL(64)
	tb.Cleanup(m.Close)
	n := &transitNode{m: m, tun: dev, from: &recordingPeer{}, out: &recordingPeer{}, exit: &recordingExit{}}
	n.fromPeer = n.from.peer(tb, "from")
	n.outPeer = n.out.peer(tb, "out")
	for _, family := range []int{4, 6} {
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitSender[family]), n.fromPeer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitFar[family]), n.outPeer)
		m.Routes.Set(netip.Prefix{}, hostPrefix(transitOwn[family]), Local)
	}
	return n
}

// laid is a fill laying packets as a tun read lays them
func laid(packets ...[]byte) func([]byte, []tun.ReadPacket) int {
	return func(slab []byte, reads []tun.ReadPacket) int { return layOut(slab, reads, packets) }
}

// An exit's reply comes from the destination its leaf sent to, a source this
// node does not own, which a read off the tun of an ownedOnly mesh drops. The
// lane carries it to the leaf's session, and still drops a source another node
// owns, as a read off the tun does.
func TestLaneCarriesExitReplyTunReadDropsAsUnowned(t *testing.T) {
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprintf("IPv%d", family), func(t *testing.T) {
			n := newLaneNode(t)
			reply := udpPacket(transitNowhere[family], transitSender[family], 100, false)

			b := newOutboundBatch(1)
			if peer := rereadTo(n.m, b, reply)[0]; peer != nil {
				t.Fatalf("a read off the tun from %s, which this node does not own, went to %v, so this proves nothing", transitNowhere[family], peer)
			}

			lane := n.m.OpenLane()
			defer lane.Close()
			if !lane.Fill(laid(reply)) {
				t.Fatal("an open lane of an open mesh filled nothing")
			}
			forged := udpPacket(transitFar[family], transitSender[family], 100, false)
			if !lane.Fill(laid(forged)) {
				t.Fatal("an open lane of an open mesh filled nothing")
			}
			sent := n.from.packets(t)
			if len(sent) != 1 || !bytes.Equal(sent[0], reply) {
				t.Errorf("the leaf's session was sent %d packets, want the reply alone", len(sent))
			}
			if counted := n.m.TransitCounters(); counted.UnownedSource != 1 || counted.Forged != 1 {
				t.Errorf("counted %+v, want the tun read's unowned source and the lane's forged one", counted)
			}
		})
	}
}

// The mesh's Close waits for an open lane as for a tun reader, and returns once
// the lane is given back. A lane opened after Close began fills nothing, and
// Close does not wait for it.
func TestMeshCloseWaitsForOpenLaneAndRefusesLaterOne(t *testing.T) {
	n := newLaneNode(t)
	lane := n.m.OpenLane()
	closed := make(chan struct{})
	go func() { n.m.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned while a lane was open")
	case <-time.After(closeHold):
	}
	select {
	case <-lane.Done():
	default:
		t.Fatal("the lane's Done is open while the mesh closes")
	}
	if lane.Fill(laid(udpPacket(transitNowhere[4], transitSender[4], 100, false))) {
		t.Error("a lane filled once the mesh was closing")
	}
	lane.Close()
	select {
	case <-closed:
	case <-time.After(deliveryTimeout):
		t.Fatal("Close did not return once the lane was given back")
	}
	late := n.m.OpenLane()
	if late.Fill(laid(udpPacket(transitNowhere[4], transitSender[4], 100, false))) {
		t.Error("a lane opened after Close filled")
	}
	late.Close()
	lane.Close()
}

// Each kind of an exit's answer is sent toward the leaf from the router-id as
// its family's error: a flow past a limit is host
// unreachable over IPv4 and administratively prohibited over IPv6, as RFC 6888
// REQ-11 has it, and a too big carries the MTU it is given
func TestLaneAnswersEachKindAsItsFamilyAnswersIt(t *testing.T) {
	type want struct{ kind, code byte }
	for _, c := range []struct {
		name string
		kind ExitAnswer
		by   map[int]want
		rest uint32
	}{
		{"expired", ExitExpired, map[int]want{4: {11, 0}, 6: {3, 0}}, 0},
		{"prohibited", ExitProhibited, map[int]want{4: {3, 13}, 6: {1, 1}}, 0},
		{"too big", ExitTooBig, map[int]want{4: {3, 4}, 6: {2, 0}}, 1280},
		{"past the limit", ExitPastLimit, map[int]want{4: {3, 1}, 6: {1, 1}}, 0},
	} {
		for _, family := range []int{4, 6} {
			t.Run(fmt.Sprintf("%s IPv%d", c.name, family), func(t *testing.T) {
				n := newLaneNode(t)
				lane := n.m.OpenLane()
				defer lane.Close()
				offending := udpPacket(transitSender[family], transitNowhere[family], 1400, true)
				if !lane.Answer(offending, c.kind, 1280) {
					t.Fatal("the answer did not go out")
				}
				sent := n.from.packets(t)
				if len(sent) != 1 {
					t.Fatalf("the leaf's session was sent %d packets, want the answer", len(sent))
				}
				got := readAnswer(t, sent[0])
				if got.kind != c.by[family].kind || got.code != c.by[family].code || got.rest != c.rest {
					t.Errorf("answered type %d code %d carrying %d, want type %d code %d carrying %d", got.kind, got.code, got.rest, c.by[family].kind, c.by[family].code, c.rest)
				}
				if got.from != transitOwn[family] || got.to != transitSender[family] {
					t.Errorf("answered from %s to %s, want from the router-id %s to the leaf %s", got.from, got.to, transitOwn[family], transitSender[family])
				}
			})
		}
	}
}

// MTU is the largest packet the leaf's session carries, and zero toward an
// address the mesh routes to no peer
func TestLaneMTUIsTheSessionsTowardTheLeaf(t *testing.T) {
	n := newLaneNode(t)
	n.fromPeer.SetMTU(1360)
	lane := n.m.OpenLane()
	defer lane.Close()
	for _, family := range []int{4, 6} {
		if got := lane.MTU(transitNowhere[family], transitSender[family]); got != 1360 {
			t.Errorf("IPv%d: the MTU toward the leaf is %d, want its session's 1360", family, got)
		}
		if got := lane.MTU(transitNowhere[family], transitUnrouted[family]); got != 0 {
			t.Errorf("IPv%d: the MTU toward an unrouted address is %d, want 0", family, got)
		}
	}
}
