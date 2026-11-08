// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"sync"
	"testing"
	"time"
)

// metricsHold is how long a test holds the transport or a seal, past every bucket bound a hold must not reach
// and metricsIdle how long a sender sits on an empty queue
const (
	metricsHold = 100 * time.Millisecond
	metricsIdle = 50 * time.Millisecond
)

// observations is how many observations h holds and how many of them fell past bound, in h's unit
func observations(h Histogram, bound uint64) (all, past uint64) {
	for i, n := range h.Counts {
		all += n
		if i == len(h.Counts)-1 || uint64(1)<<i > bound {
			past += n
		}
	}
	return all, past
}

// a release is every packet the sender hands the transport between two of its waits, however many transmits carry them
// a batch held in the transport and two sealed behind it meanwhile are one release, which ends when the sender waits on its empty queue
func TestReleaseSizesCountRunsBetweenWaits(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
		select {
		case entered <- struct{}{}:
			<-release
		default:
		}
		return nil
	}, nil)
	defer peer.Close()
	if err := filled(peer, 1).finish(); err != nil {
		t.Fatal(err)
	}
	<-entered
	for _, count := range []int{2, 5} {
		if err := filled(peer, count).finish(); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	waitUntil(t, "the sender to end its release", func() bool { return peer.SendStats().Releases.Sum != 0 })
	releases := peer.SendStats().Releases
	if all, past := observations(releases, 8); all != 1 || past != 0 || releases.Counts[3] != 1 || releases.Sum != 8 {
		t.Errorf("one release of 8 packets in 2 transmits reads %+v", releases)
	}
}

// a head wait is the sender waiting for the batch at the head of its queue to be sealed, and the release before it ends there
// its wait on an empty queue is none, however long, and so is its taking a head already sealed
func TestHeadWaitCountsOnlyAQueuedUnsealedHead(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var hold sync.Once
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
		hold.Do(func() { close(entered); <-release })
		return nil
	}, nil)
	defer peer.Close()
	time.Sleep(metricsIdle)
	// sealed before the sender, idle until then, takes it
	if err := filled(peer, 1).finish(); err != nil {
		t.Fatal(err)
	}
	<-entered
	// the next head is reserved and left unsealed, with a batch sealed behind it
	head := filled(peer, 2)
	if err := filled(peer, 4).finish(); err != nil {
		t.Fatal(err)
	}
	close(release)
	taken(t, peer)
	time.Sleep(metricsHold)
	if err := head.finish(); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "the sender to end its releases", func() bool { return peer.SendStats().Releases.Sum == 7 })
	stats := peer.SendStats()
	held := uint64(metricsHold / WaitUnit)
	if all, past := observations(stats.HeadWaits, held/2); all != 1 || past != 1 {
		t.Errorf("one wait of %s for an unsealed head after one sealed head reads %+v, want it alone and past %s", metricsHold, stats.HeadWaits, metricsHold/2)
	}
	if stats.HeadWaits.Sum >= uint64((metricsHold+metricsIdle)/WaitUnit) {
		t.Errorf("the head waits come to %d microseconds, which counts the empty queue's %s", stats.HeadWaits.Sum, metricsIdle)
	}
	if all, _ := observations(stats.Releases, 0); all != 2 || stats.Releases.Counts[0] != 1 || stats.Releases.Counts[3] != 1 {
		t.Errorf("a release of 1 packet, a head wait and a release of 6 read %+v", stats.Releases)
	}
}

// a batch's seal time ends when its filler seals it, not when the sender takes it
// so a batch sealed behind one the transport holds reads no time for that hold
func TestSealTimeEndsAtTheSeal(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, func([][]byte) error {
		select {
		case entered <- struct{}{}:
			<-release
		default:
		}
		return nil
	}, nil)
	defer peer.Close()
	if err := filled(peer, 1).finish(); err != nil {
		t.Fatal(err)
	}
	<-entered
	if err := filled(peer, 1).finish(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(metricsHold)
	close(release)
	waitUntil(t, "the sender to take both batches", func() bool { return peer.SendStats().Releases.Sum == 2 })
	seals := peer.SendStats().Seals
	if all, past := observations(seals, uint64(metricsHold/WaitUnit)/2); all != 2 || past != 0 {
		t.Errorf("two batches sealed as they were reserved read %+v, want neither past %s", seals, metricsHold/2)
	}
}

// the wait histograms' largest bound is past the delay the sender's CoDel holds its queue to
func TestWaitHistogramsReachPastTheCodelTarget(t *testing.T) {
	if largest := WaitUnit << (histogramBounds - 1); largest <= codelTarget {
		t.Errorf("the wait histograms end at %s, at or under CoDel's target of %s", largest, codelTarget)
	}
}
