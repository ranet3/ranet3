// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// the address the test below gives the egress device, and the far end the kernel routes out of it
var (
	egressLocal = netip.MustParseAddr("10.67.0.1")
	egressFar   = netip.MustParseAddr("10.67.0.2")
)

// egressTUN is a mesh holding egressTable with a real tun of the copy installed as its egress device, opened as the mesh opens its own
func egressTUN(t *testing.T) (*Mesh, string) {
	t.Helper()
	m, err := NewNamed(DefaultMTU, "egmesh0", nil)
	if err != nil {
		t.Fatalf("open the mesh: %v", err)
	}
	t.Cleanup(m.Close)
	m.SetSegments(egressTable(t))
	dev, name, err := createTUNQueues("egtest0", DefaultMTU, 1)
	if err != nil {
		t.Fatalf("open the egress device: %v", err)
	}
	if err := bringTUNUp(name, unix.IFF_MULTICAST); err != nil {
		_ = dev.Close()
		t.Fatalf("bring %s up: %v", name, err)
	}
	m.SetEgress(dev)
	m.SetEgressReady(true, true)
	routeLeaf(t, m, egressFar, tooBigSource[4])
	return m, name
}

// the inner packet of an egress segment reaches a kernel socket through the egress device whole, from the inner source
// and a packet the kernel routes into it is read by the drain and counted once, whatever link-local IPv6 multicast the kernel sends there of its own
func TestTUNEgressDeviceCarriesAndDrains(t *testing.T) {
	enterEmptyNamespace(t)
	m, name := egressTUN(t)
	assignPeer(t, name, egressLocal, egressFar)

	// udpPacket sends from port 4000 to port 5000
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(egressLocal, 5000)))
	if err != nil {
		t.Fatalf("listen on %s: %v", egressLocal, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	payload := []byte("left through the egress device")
	inner := udpPacket(egressFar, egressLocal, 20+8+len(payload), false)
	copy(inner[20+8:], payload)
	m.DeliverInboundBatch(framed(steered(t, inner, headend, egressExit)), DefaultMTU, nil)
	if err := listener.SetReadDeadline(time.Now().Add(deliveryTimeout)); err != nil {
		t.Fatalf("bound the read: %v", err)
	}
	buf := make([]byte, DefaultMTU)
	n, from, err := listener.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatalf("the kernel socket read nothing the egress device carried: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) || from != netip.AddrPortFrom(egressFar, 4000) {
		t.Errorf("the kernel socket read %q from %s, want %q from %s:4000", buf[:n], from, payload, egressFar)
	}
	if counters := m.SegmentCounters(); counters.Egressed != 1 || counters.Dropped != 0 || counters.NotReady != 0 {
		t.Errorf("the egressed packet counted %+v, want 1 egressed", counters)
	}

	before := tunPackets(t, name, sentPackets)
	sendUDP(t, egressFar, []byte("routed into the wrong device"))
	waitUntil(t, "the drain to count the one packet a route sent into the egress device", func() bool {
		return tunPackets(t, name, sentPackets) > before && m.SegmentCounters().Drained == 1
	})
}

// a batch of more egress results than one tun write carries, each of a TCP flow of its own, reaches the egress device whole
// the copy's tun write sizes its GRO tables for inboundWriteBatchSize flows, and one write past them panics
func TestTUNEgressWritesMoreFlowsThanABatch(t *testing.T) {
	const flows = 2*inboundWriteBatchSize + 1
	enterEmptyNamespace(t)
	m, _ := egressTUN(t)
	frames := make([][]byte, flows)
	for i := range frames {
		inner := tcpPacket(4, 0, false, 0x10, nil, 0, 100)
		binary.BigEndian.PutUint16(inner[20:], uint16(30000+i))
		binary.BigEndian.PutUint16(inner[20+tcpChecksum:], tcpSum(inner, 20))
		frames[i] = steered(t, inner, headend, egressExit)
	}
	m.DeliverInboundBatch(framed(frames...), DefaultMTU, nil)
	if counters := m.SegmentCounters(); counters.Egressed != flows || counters.Dropped != 0 || counters.NotReady != 0 {
		t.Errorf("%d egress results of distinct flows counted %+v, want each egressed", flows, counters)
	}
}
