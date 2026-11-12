// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// saidCounts is the value of key on each line of said that holds msg
func saidCounts(said, msg, key string) []string {
	var counts []string
	for line := range strings.Lines(said) {
		if strings.Contains(line, msg) {
			_, count, _ := strings.Cut(line, key+"=")
			count, _, _ = strings.Cut(strings.TrimSpace(count), " ")
			counts = append(counts, count)
		}
	}
	return counts
}

// an Update that does not decode is said at most once per refusalLogInterval, however many a neighbor packs into a packet or sends in packets after it
// each line counts the Updates ignored since the one before
func TestBadUpdatesAreSaidOncePerIntervalWithTheirCount(t *testing.T) {
	var said strings.Builder
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&said, nil)))
	speaker, neighbor, _ := captureSpeaker(t, Config{})
	bad := RawTLV{Type: TLVUpdate, Body: []byte{1}}
	packet := EncodePacket([]RawTLV{bad, bad})
	start := time.Now()
	speaker.mu.Lock()
	for _, at := range []time.Duration{0, 0, refusalLogInterval / 2, refusalLogInterval + time.Second} {
		speaker.handlePacketLocked(neighbor, neighbor.addr, packet, start.Add(at))
	}
	speaker.mu.Unlock()
	if got, want := saidCounts(said.String(), "babel bad update", "ignored_since_last"), []string{"1", "6"}; !slices.Equal(got, want) {
		t.Fatalf("four packets of two undecodable Updates each, the fourth past the interval, were said with counts %q, want %q, in\n%s", got, want, said.String())
	}
}

// a malformed packet the speaker consumes is said at most once per refusalLogInterval, each line with the packets refused since the one before
func TestMalformedPacketsAreSaidOncePerIntervalWithTheirCount(t *testing.T) {
	hello := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})})
	for _, test := range []struct {
		name   string
		packet func(from netip.Addr) []byte
	}{
		{"bad checksum", func(from netip.Addr) []byte {
			raw := buildPacket(from, multicastGroup, hello)
			raw[46] ^= 0xff
			return raw
		}},
		{"magic 41", func(from netip.Addr) []byte {
			payload := bytes.Clone(hello)
			payload[0] = 41
			return buildPacket(from, multicastGroup, payload)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var said strings.Builder
			logtest.SetDefault(t, slog.New(slog.NewTextHandler(&said, nil)))
			speaker, neighbor, _ := captureSpeaker(t, Config{})
			raw := test.packet(neighbor.addr)
			for range 3 {
				if !speaker.Receive(neighbor.peer, raw) {
					t.Fatal("the speaker handed back a malformed packet addressed to it")
				}
			}
			speaker.mu.Lock()
			speaker.malformedLog.said = speaker.malformedLog.said.Add(-refusalLogInterval - time.Second)
			speaker.mu.Unlock()
			speaker.Receive(neighbor.peer, raw)
			if got, want := saidCounts(said.String(), "babel dropped a malformed packet", "refused_since_last"), []string{"1", "3"}; !slices.Equal(got, want) {
				t.Fatalf("three malformed packets back to back and a fourth past the interval were said with counts %q, want %q, in\n%s", got, want, said.String())
			}
		})
	}
}

// a packet RFC 8966 section 4.2 has silently ignored, its magic other than 42 or its version other than 2, leaves the neighbor's address where it was, as does one whose body does not decode
// a packet that decodes, from the same address, moves it
func TestUndecodablePacketLeavesTheNeighborsAddress(t *testing.T) {
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(io.Discard, nil)))
	hello := EncodePacket([]RawTLV{EncodeHello(Hello{Seqno: 1, Interval: 100})})
	elsewhere := netip.MustParseAddr("fe80::99")
	for _, test := range []struct {
		name string
		edit func([]byte)
	}{
		{"magic 41", func(p []byte) { p[0] = 41 }},
		{"version 3", func(p []byte) { p[1] = 3 }},
		{"body past the packet", func(p []byte) { p[3]++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			speaker, neighbor, _ := captureSpeaker(t, Config{})
			at := neighbor.addr
			payload := bytes.Clone(hello)
			test.edit(payload)
			if !speaker.Receive(neighbor.peer, buildPacket(elsewhere, multicastGroup, payload)) {
				t.Fatal("the speaker handed back a packet addressed to it")
			}
			if neighbor.addr != at {
				t.Fatalf("a packet from %v the speaker could not decode moved the neighbor's address from %v to %v", elsewhere, at, neighbor.addr)
			}
			if !speaker.Receive(neighbor.peer, buildPacket(elsewhere, multicastGroup, hello)) || neighbor.addr != elsewhere {
				t.Fatalf("a well formed packet from %v left the neighbor's address at %v, so the case above proves nothing", elsewhere, neighbor.addr)
			}
		})
	}
}

// lockHeld is how long TestReceiveTimestampIsTakenBeforeTheSpeakersLock holds the speaker's lock while a packet arrives
const lockHeld = 80 * time.Millisecond

// RFC 9616 section 3.2: "receive timestamps SHOULD be computed just after the packet is received from the network stack"
// a packet that arrives while the speaker's lock is held yields a round trip sample without the wait for the lock, whether it arrives whole or its last fragment does
func TestReceiveTimestampIsTakenBeforeTheSpeakersLock(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(map[bool]string{false: "whole", true: "fragmented"}[fragmented], func(t *testing.T) {
			speaker, neighbor, _ := captureSpeaker(t, Config{})
			makeNeighborReachable(neighbor)
			// the neighbor answers this node's Hello sent at sent in no time, so the round trip is the time the packet takes to reach the speaker
			sent := nowMicros()
			raw := buildPacket(neighbor.addr, multicastGroup, EncodePacket([]RawTLV{
				EncodeHello(Hello{Seqno: 1, Interval: 400, TxTS: 5000, HasTS: true}),
				EncodeIHU(IHU{RxCost: 96, Interval: 400, OriginTS: sent, ReceiveTS: 5000, HasTS: true}),
			}))
			arriving := [][]byte{raw}
			if fragmented {
				arriving = fragment(raw, 1, 8)
			}
			for _, f := range arriving[:len(arriving)-1] {
				speaker.Receive(neighbor.peer, f)
			}
			speaker.mu.Lock()
			done := make(chan struct{})
			go func() {
				speaker.Receive(neighbor.peer, arriving[len(arriving)-1])
				close(done)
			}()
			time.Sleep(lockHeld)
			speaker.mu.Unlock()
			<-done

			speaker.mu.Lock()
			defer speaker.mu.Unlock()
			if !neighbor.haveRTT {
				t.Fatal("no round trip sample was taken")
			}
			if neighbor.measuredRTT >= lockHeld/2 {
				t.Errorf("the sample is %s for a packet that arrived at once and waited %s for the lock", neighbor.measuredRTT, lockHeld)
			}
		})
	}
}
