// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/srv6"
)

// probeAnswerTimeout bounds how long a test waits for the Ack to a probe that crosses an in-memory link
const probeAnswerTimeout = 5 * time.Second

// probeAck is one report Runtime.ProbeAcked heard
type probeAck struct {
	peer  *netstack.Peer
	nonce uint16
}

func (a probeAck) String() string { return fmt.Sprintf("%d through %s", a.nonce, a.peer.ID) }

// a probe leaves as one packet of exactly the size asked for, carrying the caller's nonce
// it leaves whole past the size of the speaker's own packets
// the path is asked to carry that much at once
func TestProbeLeavesAsOnePacketOfItsSize(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{})
	// the bounds, and both sides of the inner packet a babel packet of defaultPacketSize makes
	for _, size := range []int{smallestProbe, srv6.MinimumIPv6MTU - 1, srv6.MinimumIPv6MTU, srv6.MinimumIPv6MTU + 1, 9000, math.MaxUint16} {
		nonce := uint16(size)
		*packets = nil
		if err := speaker.Probe(neighbor.peer, size, nonce); err != nil {
			t.Fatalf("a probe of %d bytes: %v", size, err)
		}
		var sizes []int
		for _, packet := range *packets {
			sizes = append(sizes, len(packet))
		}
		if !slices.Equal(sizes, []int{size}) {
			t.Fatalf("a probe of %d bytes left as packets of %v bytes", size, sizes)
		}
		packet := (*packets)[0]
		if counted := ipv6HeaderLen + int(binary.BigEndian.Uint16(packet[4:6])); counted != size {
			t.Fatalf("a probe of %d bytes counts %d in its IPv6 header", size, counted)
		}
		_, payload, err := parsePacket(packet, neighbor.addr)
		if err != nil {
			t.Fatalf("a probe of %d bytes: %v", size, err)
		}
		tlvs, err := DecodePacket(payload)
		if err != nil || len(tlvs) != 1 || tlvs[0].Type != TLVAckReq {
			t.Fatalf("a probe of %d bytes carries %v, %v", size, tlvs, err)
		}
		if got, err := DecodeAckReq(tlvs[0].Body); err != nil || got != nonce {
			t.Fatalf("a probe sent with nonce %d carries %d, %v", nonce, got, err)
		}
	}
}

// a probe smaller than smallestProbe is refused and sends nothing
// one past the 2^16-1 octets RFC 8966 section 4 allows a babel packet with its lower-layer headers is refused too
func TestProbeRefusesASizeOutsideItsBounds(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{})
	*packets = nil
	for _, size := range []int{smallestProbe - 1, math.MaxUint16 + 1} {
		if err := speaker.Probe(neighbor.peer, size, 1); err == nil {
			t.Errorf("a probe of %d bytes was taken", size)
		}
	}
	if len(*packets) != 0 {
		t.Errorf("refused probes sent %d packets", len(*packets))
	}
}

// a probe goes only through the session registered under its peer's ID
// one a newer session replaced and one the speaker never held are refused and send nothing
// Receive ignores both
func TestProbeGoesOnlyThroughTheRegisteredSession(t *testing.T) {
	speaker, neighbor, packets := captureSpeaker(t, Config{})
	*packets = nil
	for _, peer := range []*netstack.Peer{{ID: neighbor.peer.ID}, {ID: "unknown"}} {
		if err := speaker.Probe(peer, srv6.MinimumIPv6MTU, 1); err == nil {
			t.Errorf("a probe through a session %s the speaker does not hold was taken", peer.ID)
		}
	}
	if len(*packets) != 0 {
		t.Errorf("a probe through a session the speaker does not hold sent %d packets", len(*packets))
	}
}

// a probe its session refuses a place to is an error
func TestRefusedProbeIsAnError(t *testing.T) {
	speaker, err := New(Config{}, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		t.Fatal(err)
	}
	// a closed session refuses every place
	closed := netstack.NewPeerReserved("closed", plainSealer, func([][]byte) error { return nil }, nil)
	closed.Close()
	speaker.AddPeer(closed)
	if err := speaker.Probe(closed, srv6.MinimumIPv6MTU, 1); err == nil {
		t.Error("a probe the session refused was taken")
	}
}

// every Ack the speaker receives is reported with the session it came through, in the order it arrived
// the speaker keeps no record of its probes
// a repeated Ack and one no probe asked for are reported too
// an Ack through a session a newer one replaced is reported to nobody
// Receive ignores that session
func TestEveryAckIsReportedWithItsSession(t *testing.T) {
	var heard []probeAck
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{ProbeAcked: func(peer *netstack.Peer, nonce uint16) {
		heard = append(heard, probeAck{peer, nonce})
	}})
	other := netstack.NewPeer("other", plainEncrypt, func([]byte) error { return nil })
	speaker.AddPeer(other)
	acks := func(nonces ...uint16) []byte {
		var tlvs []RawTLV
		for _, nonce := range nonces {
			tlvs = append(tlvs, EncodeAck(nonce))
		}
		return buildPacket(neighbor.addr, speaker.linkLocal, EncodePacket(tlvs))
	}

	if err := speaker.Probe(neighbor.peer, srv6.MinimumIPv6MTU, 7); err != nil {
		t.Fatal(err)
	}
	speaker.Receive(neighbor.peer, acks(7, 7, 9))
	speaker.Receive(other, acks(7))
	speaker.Receive(&netstack.Peer{ID: neighbor.peer.ID}, acks(11))
	if want := []probeAck{{neighbor.peer, 7}, {neighbor.peer, 7}, {neighbor.peer, 9}, {other, 7}}; !slices.Equal(heard, want) {
		t.Fatalf("the Acks were reported as %v, where %v arrived through the sessions the speaker holds", heard, want)
	}
}

// an Ack too short to hold its nonce fails to decode rather than being read past its end
// one from a neighbor is ignored
// the Acks after it in the packet are still reported
func TestShortAckIsIgnored(t *testing.T) {
	for _, body := range [][]byte{nil, {7}} {
		if _, err := DecodeAck(body); err == nil {
			t.Errorf("an Ack of %d octets decoded", len(body))
		}
	}
	var heard []probeAck
	speaker, neighbor, _ := captureSpeaker(t, Config{}, Runtime{ProbeAcked: func(peer *netstack.Peer, nonce uint16) {
		heard = append(heard, probeAck{peer, nonce})
	}})
	payload := EncodePacket([]RawTLV{{Type: TLVAck}, {Type: TLVAck, Body: []byte{7}}, EncodeAck(9)})
	speaker.Receive(neighbor.peer, buildPacket(neighbor.addr, speaker.linkLocal, payload))
	if want := []probeAck{{neighbor.peer, 9}}; !slices.Equal(heard, want) {
		t.Fatalf("Acks of 0, 1 and 2 octets were reported as %v, where the one whole Ack is %v", heard, want)
	}
}

// a speaker whose runtime names no ProbeAcked takes an Ack and reports it to nobody
func TestAckWithNoProbeAckedIsTaken(t *testing.T) {
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	raw := buildPacket(neighbor.addr, speaker.linkLocal, EncodePacket([]RawTLV{EncodeAck(1)}))
	if !speaker.Receive(neighbor.peer, raw) {
		t.Fatal("an Ack was handed back as data")
	}
}

// a probe of every size is answered by the neighbor's own receive path
// the caller hears the nonce it chose with the speaker's lock released
// it may call the speaker from there
func TestProbeIsAnsweredByTheNeighbor(t *testing.T) {
	_, _, speakerA, _ := wireSpeakerPair(t, Config{})
	heard := make(chan probeAck, 1)
	speakerA.probeAcked = func(peer *netstack.Peer, nonce uint16) {
		speakerA.Passes()
		heard <- probeAck{peer, nonce}
	}
	peerB := speakerA.neighbors["b"].peer
	for _, size := range []int{smallestProbe, srv6.MinimumIPv6MTU, 9000, largestProbe} {
		nonce := uint16(size)
		if err := speakerA.Probe(peerB, size, nonce); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-heard:
			if got != (probeAck{peerB, nonce}) {
				t.Fatalf("a probe of %d bytes with nonce %d was answered as %v", size, nonce, got)
			}
		case <-time.After(probeAnswerTimeout):
			t.Fatalf("a probe of %d bytes went unanswered for %s", size, probeAnswerTimeout)
		}
	}
}
