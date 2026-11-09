// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// senderHold is how long a test leaves the head of a sender's queue unsealed after the sender ends its release
// the wait usually falls past the first bound, but a sender descheduled meanwhile can count less
// such a run cannot catch a sum 1000 times too small, and no run fails a correct sum
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

// waitedPeer is waitingPeer with the time it took
// the window starts before the first send and ends once the sender has counted the head wait, so every wait counted lies inside it whatever the host's scheduling
func waitedPeer(t *testing.T, path string) (*netstack.Peer, time.Duration) {
	t.Helper()
	start := time.Now()
	peer := waitingPeer(t, path)
	return peer, time.Since(start)
}

// waitLimit is an upper bound on the sum of the head waits a sender counts within window
// the sender counts each wait rounded up to a WaitUnit and its waits do not overlap, so the window rounded up and a unit for each wait is the most
func waitLimit(window time.Duration, waits uint64) time.Duration {
	return (window+netstack.WaitUnit-1)/netstack.WaitUnit*netstack.WaitUnit + time.Duration(waits)*netstack.WaitUnit
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

// waitUnits is a rendered number of seconds as a count of WaitUnits, rounded to the nearest
func waitUnits(seconds string) (uint64, error) {
	v, err := strconv.ParseFloat(seconds, 64)
	if err != nil {
		return 0, err
	}
	return uint64(v/netstack.WaitUnit.Seconds() + 0.5), nil
}

// waitSumFault is why the sum a scrape renders for head waits is not one its buckets and limit allow, nil when it is
// bounds are the buckets' rendered bounds and counts their cumulative counts, the last bucket past every bound
// the check counts whole WaitUnits, since the sum of two bounds in seconds can fall one ulp under the exact sum
func waitSumFault(bounds []string, counts []uint64, sum string, limit time.Duration) error {
	// lower and upper bound the sum the buckets allow, each observation over the bound before its bucket and at or under its own
	var lower, upper, previous, seen uint64
	unbounded := false
	for i, le := range bounds {
		in := counts[i] - seen
		seen = counts[i]
		lower += in * previous
		if le == "+Inf" {
			unbounded = in != 0
			continue
		}
		bound, err := waitUnits(le)
		if err != nil {
			return fmt.Errorf("the bucket bound %q: %w", le, err)
		}
		upper += in * bound
		previous = bound
	}
	got, err := waitUnits(sum)
	if err != nil {
		return fmt.Errorf("the sum %q: %w", sum, err)
	}
	if most := uint64(limit / netstack.WaitUnit); unbounded || most < upper {
		upper = most
	}
	if got < lower || got > upper {
		return fmt.Errorf("the head wait sum is %d units, outside the %d to %d their buckets and the limit allow", got, lower, upper)
	}
	return nil
}

// the check holds for waits on bucket bounds exactly, where the sum of the bounds 1e-06 and 0.001024 in seconds falls one ulp under 0.001025
func TestWaitSumFaultHoldsAtExactBounds(t *testing.T) {
	bounds := []string{"1e-06", "0.001024", "+Inf"}
	for _, c := range []struct {
		name   string
		counts []uint64
		sum    string
		limit  time.Duration
		fault  bool
	}{
		{"waits of 1 and 1024 units", []uint64{1, 2, 2}, "0.001025", time.Second, false},
		{"sum one unit over the bounds", []uint64{1, 2, 2}, "0.001026", time.Second, true},
		{"sum one unit under the bounds", []uint64{1, 2, 2}, "0", time.Second, true},
		{"sum over the limit", []uint64{1, 2, 2}, "0.001025", time.Millisecond, true},
		{"past the last bound within the limit", []uint64{0, 0, 1}, "0.0015", 2 * time.Millisecond, false},
		{"past the last bound over the limit", []uint64{0, 0, 1}, "0.003", 2 * time.Millisecond, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := waitSumFault(bounds, c.counts, c.sum, c.limit); (err != nil) != c.fault {
				t.Errorf("the sum %s of counts %v under %v gives the fault %v, want fault %v", c.sum, c.counts, c.limit, err, c.fault)
			}
		})
	}
}

// a wait histogram's sum is in seconds as its bounds are, so a sender's head wait sum lies within what its buckets and waitLimit allow
// the sum is checked against the unit of the bounds, which TestMetricsRendersSenderHistograms pins
func TestMetricsRendersWaitSumsInSeconds(t *testing.T) {
	const path = "example/bravo:2@1"
	peer, window := waitedPeer(t, path)
	c := clientWith(t, peer)
	var out strings.Builder
	c.renderSenders(&out)
	bucket := "ranet3_peer_send_head_wait_seconds_bucket{peer=\"" + path + "\",le=\""
	total := "ranet3_peer_send_head_wait_seconds_sum{peer=\"" + path + "\"} "
	var bounds []string
	var counts []uint64
	var sum string
	sums := 0
	for line := range strings.Lines(out.String()) {
		line = strings.TrimSuffix(line, "\n")
		if rest, ok := strings.CutPrefix(line, bucket); ok {
			le, n, _ := strings.Cut(rest, "\"} ")
			cumulative, err := strconv.ParseUint(n, 10, 64)
			if err != nil {
				t.Fatalf("the bucket count %q: %v", n, err)
			}
			bounds = append(bounds, le)
			counts = append(counts, cumulative)
		}
		if rest, ok := strings.CutPrefix(line, total); ok {
			sum = rest
			sums++
		}
	}
	if len(counts) == 0 || counts[len(counts)-1] == 0 || sums != 1 {
		t.Fatalf("the scrape carries the bucket counts %v and %d sums, want head waits and their sum:\n%s", counts, sums, out.String())
	}
	if err := waitSumFault(bounds, counts, sum, waitLimit(window, counts[len(counts)-1])); err != nil {
		t.Errorf("%v:\n%s", err, out.String())
	}
}
