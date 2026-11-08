// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// senderHold is the least time a test leaves the head of a sender's queue unsealed while the sender waits on it
// long enough that the wait falls past the first bound, and short enough that the time waitFor takes to see the wait still leaves it under the last
const senderHold = time.Millisecond

// clientWith is a client holding a session through each peer given, under the peer's ID as its path
func clientWith(t *testing.T, peers ...*netstack.Peer) *Client {
	t.Helper()
	mux, err := loopbackHub(t).NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mux.Close() })
	c := &Client{sessions: newSessionSet(), Mesh: &netstack.Mesh{Routes: netstack.NewRouteTable()}}
	for _, peer := range peers {
		d := newPathDriver(mux, nil, events.New(), &probeTotals{}, driverProbeTimeout, confirmInterval)
		d.peer = peer
		c.sessions.live[peer.ID] = &liveSession{pmtu: d}
	}
	return c
}

// senderClient is a client holding a session for each path, each through a peer that has sent one babel packet and seen its sender wait again
func senderClient(t *testing.T, paths ...string) *Client {
	t.Helper()
	var peers []*netstack.Peer
	for _, path := range paths {
		peer := sinkPeer(t, path)
		place, err := peer.ReserveRawOrDrop([]byte("hello"), 41)
		if err != nil {
			t.Fatal(err)
		}
		if err := place.Send(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, convergeBudget, "the sender to end its release", func() bool { return peer.SendStats().Releases.Counts[0] == 1 })
		peers = append(peers, peer)
	}
	return clientWith(t, peers...)
}

// waitingPeer is a peer for path whose sender has waited senderHold or more for the head of its queue to be sealed
// it reserves a babel packet's place while its transport holds the one before, and sends it only once the sender waits on it
// a sender that starts after the first place is reserved waits on that head as well, briefly
func waitingPeer(t *testing.T, path string) *netstack.Peer {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	var hold sync.Once
	peer := netstack.NewPeer(path, func(int) (netstack.BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) { return append(out[:0], raw...), nil }, nil
	}, func([][]byte) error {
		hold.Do(func() { close(entered); <-release })
		return nil
	}, nil)
	t.Cleanup(peer.Close)
	first, err := peer.ReserveRawOrDrop([]byte("hello"), 41)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Send(); err != nil {
		t.Fatal(err)
	}
	<-entered
	head, err := peer.ReserveRawOrDrop([]byte("hello"), 41)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	// the sender ends the release of the first packet as it starts to wait on the head
	waitFor(t, convergeBudget, "the sender to wait on the head of its queue", func() bool { return peer.SendStats().Releases.Counts[0] == 1 })
	time.Sleep(senderHold)
	if err := head.Send(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the sender to send the head", func() bool { return peer.SendStats().Releases.Sum == 2 })
	return peer
}

// each session's sender reaches a scrape as three histograms under the names the docs give them, labeled by the session's path
// the buckets count up to their bound, the last one every observation
func TestMetricsRendersSenderHistograms(t *testing.T) {
	c := senderClient(t, "example/bravo:2@1")
	var out strings.Builder
	c.renderSenders(&out)
	for _, want := range []string{
		"# TYPE ranet3_peer_send_release_packets histogram\n",
		"ranet3_peer_send_release_packets_bucket{peer=\"example/bravo:2@1\",le=\"1\"} 1\n",
		"ranet3_peer_send_release_packets_bucket{peer=\"example/bravo:2@1\",le=\"32768\"} 1\n",
		"ranet3_peer_send_release_packets_bucket{peer=\"example/bravo:2@1\",le=\"+Inf\"} 1\n",
		"ranet3_peer_send_release_packets_sum{peer=\"example/bravo:2@1\"} 1\n",
		"ranet3_peer_send_release_packets_count{peer=\"example/bravo:2@1\"} 1\n",
		"# TYPE ranet3_peer_send_head_wait_seconds histogram\n",
		"ranet3_peer_send_head_wait_seconds_bucket{peer=\"example/bravo:2@1\",le=\"1e-06\"} ",
		"ranet3_peer_send_head_wait_seconds_bucket{peer=\"example/bravo:2@1\",le=\"0.032768\"} ",
		"# TYPE ranet3_peer_send_seal_seconds histogram\n",
		// a babel packet is no data batch, so no seal time
		"ranet3_peer_send_seal_seconds_bucket{peer=\"example/bravo:2@1\",le=\"+Inf\"} 0\n",
		"ranet3_peer_send_seal_seconds_sum{peer=\"example/bravo:2@1\"} 0\n",
		"ranet3_peer_send_seal_seconds_count{peer=\"example/bravo:2@1\"} 0\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}
}

// a wait histogram's sum is in seconds as its bounds are, so the sum of a sender's head waits lies between what the bounds of the buckets counting them allow
func TestMetricsRendersWaitSumsInSeconds(t *testing.T) {
	const path = "example/bravo:2@1"
	c := clientWith(t, waitingPeer(t, path))
	var out strings.Builder
	c.renderSenders(&out)
	bucket := "ranet3_peer_send_head_wait_seconds_bucket{peer=\"" + path + "\",le=\""
	total := "ranet3_peer_send_head_wait_seconds_sum{peer=\"" + path + "\"} "
	// lower and upper bound the sum the buckets allow, each observation over the bound before its bucket and at or under its own
	var lower, upper, sum, previous float64
	var count uint64
	sums := 0
	for line := range strings.Lines(out.String()) {
		line = strings.TrimSuffix(line, "\n")
		if rest, ok := strings.CutPrefix(line, bucket); ok {
			le, n, _ := strings.Cut(rest, "\"} ")
			bound, err := strconv.ParseFloat(le, 64)
			if err != nil {
				t.Fatalf("the bucket bound %q: %v", le, err)
			}
			cumulative, err := strconv.ParseUint(n, 10, 64)
			if err != nil {
				t.Fatalf("the bucket count %q: %v", n, err)
			}
			if in := cumulative - count; in != 0 {
				lower += float64(in) * previous
				upper += float64(in) * bound
			}
			previous, count = bound, cumulative
		}
		if rest, ok := strings.CutPrefix(line, total); ok {
			var err error
			if sum, err = strconv.ParseFloat(rest, 64); err != nil {
				t.Fatalf("the sum %q: %v", rest, err)
			}
			sums++
		}
	}
	if count == 0 || sums != 1 {
		t.Fatalf("the scrape carries %d head waits and %d sums, want the waits and their sum:\n%s", count, sums, out.String())
	}
	if math.IsInf(upper, 1) {
		t.Fatalf("a head wait ran past every bound, so no bound checks the sum:\n%s", out.String())
	}
	if sum < lower || sum > upper {
		t.Errorf("the head waits sum to %v seconds, outside the %v to %v their buckets allow:\n%s", sum, lower, upper, out.String())
	}
}
