// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// senderBounds are the bounds of a histogram of packets, and of one of nanoseconds that counts in microseconds
func senderBounds(unit uint64) []uint64 {
	bounds := make([]uint64, 16)
	for i := range bounds {
		bounds[i] = unit << i
	}
	return bounds
}

// senderFixture is a session whose sender released hundreds of packets after waiting on late heads, and one that has sent nothing
func senderFixture() SenderInfo {
	releases := make([]uint64, 17)
	releases[0], releases[3], releases[9] = 40, 9, 1
	waits := make([]uint64, 17)
	waits[4], waits[7], waits[16] = 6, 3, 1
	seals := make([]uint64, 17)
	seals[3], seals[5] = 99, 1
	return SenderInfo{Sessions: []SenderSession{
		{
			Path: "example/bravo:2@alpha", Peer: "example/bravo",
			DataHeld: 1400 * 300, DataLimit: 1400 * 4096, ControlHeld: 2, ControlLimit: 256,
			Releases:  SenderHistogram{Bounds: senderBounds(1), Counts: releases, Sum: 40 + 9*6 + 400},
			HeadWaits: SenderHistogram{Bounds: senderBounds(1000), Counts: waits, Sum: 6*12000 + 3*100000 + 40000000},
			Seals:     SenderHistogram{Bounds: senderBounds(1000), Counts: seals, Sum: 99*6000 + 25000},
		},
		{
			Path: "example/charlie:3@alpha", Peer: "example/charlie", DataLimit: 1400 * 4096, ControlLimit: 256,
			Releases:  SenderHistogram{Bounds: senderBounds(1), Counts: make([]uint64, 17)},
			HeadWaits: SenderHistogram{Bounds: senderBounds(1000), Counts: make([]uint64, 17)},
			Seals:     SenderHistogram{Bounds: senderBounds(1000), Counts: make([]uint64, 17)},
		},
	}}
}

func TestSenderRendersAsTheGoldenFiles(t *testing.T) {
	info := senderFixture()
	var out strings.Builder
	RenderSender(&out, info)
	golden(t, "sender.txt", []byte(out.String()))
	goldenJSON(t, "sender.json", info)
}

// senderSource serves the sender view, keeping the peer it was asked for
type senderSource struct {
	fakeSource
	asked chan string
}

func (s senderSource) DebugSender(peer string) SenderInfo {
	s.asked <- peer
	return senderFixture()
}

// the view reads the named peer's senders, the peer reaching the source as it was written, and a POST is refused
func TestSenderReadsTheNamedPeer(t *testing.T) {
	source := senderSource{asked: make(chan string, 1)}
	server := served(t, source)
	if status, body := get(t, server.Client(), server.URL+PathDebugSender+"?peer=example%2Fbravo"); status != http.StatusOK {
		t.Errorf("the sender view was answered %d %q", status, body)
	}
	select {
	case peer := <-source.asked:
		if peer != "example/bravo" {
			t.Errorf("the source was asked for %q, want example/bravo", peer)
		}
	case <-time.After(testWait):
		t.Error("the source was never asked for the sender view")
	}
	if refused := post(t, server.URL+PathDebugSender, ""); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the sender view was answered %s", refused.Status)
	}
}

// the client asks for the peer it is given and decodes the view the daemon answers
func TestSenderClientNamesThePeer(t *testing.T) {
	source := senderSource{asked: make(chan string, 1)}
	client := serveStream(t, source, func(*http.Server) {})
	info, err := client.Sender(context.Background(), "bravo")
	if err != nil {
		t.Fatal(err)
	}
	if peer := <-source.asked; peer != "bravo" {
		t.Errorf("the source was asked for %q, want bravo", peer)
	}
	if len(info.Sessions) != 2 || info.Sessions[0].Releases.Counts[9] != 1 {
		t.Errorf("the client decoded %+v", info)
	}
}
