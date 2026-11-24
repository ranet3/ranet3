// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

const (
	metricsHold      = 100 * time.Millisecond
	metricsIdle      = 50 * time.Millisecond
	peerClockEnv     = "RANET3_TEST_PEER_CLOCK"
	peerClockTimeout = 30 * time.Second
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

func withPeerClock(t *testing.T, run func(*testing.T)) {
	// pooled batch channels belong to the bubble that allocated them
	if os.Getenv(peerClockEnv) == "" {
		t.Helper()
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(t.Name()), "/", "$/^") + "$"
		child := exec.Command(os.Args[0], "-test.run="+pattern, "-test.v", "-test.timeout="+peerClockTimeout.String())
		child.Env = append(os.Environ(), peerClockEnv+"=1")
		out, err := child.CombinedOutput()
		if err != nil {
			t.Fatalf("the child test exited with %v:\n%s", err, out)
		}
		if !strings.Contains(string(out), "--- PASS: "+t.Name()+" ") {
			t.Fatalf("the child did not pass %s:\n%s", t.Name(), out)
		}
		return
	}

	synctest.Test(t, run)
}

func withMetricsPeer(t *testing.T, run func(*testing.T, *Peer, *holdingTransport)) {
	withPeerClock(t, func(t *testing.T) {
		h := newHoldingTransport(false)
		peer := NewPeer("peer", func(int) (BatchSealer, error) { return passThrough, nil }, h.transmit, nil)
		defer peer.Close()
		defer h.letGo()
		run(t, peer, h)
	})
}

// a head wait is the sender waiting for the batch at the head of its queue to be sealed, and the release before it ends there
// its wait on an empty queue is none, however long, and so is its taking a head already sealed
func TestHeadWaitCountsOnlyAQueuedUnsealedHead(t *testing.T) {
	withMetricsPeer(t, func(t *testing.T, peer *Peer, h *holdingTransport) {
		time.Sleep(metricsIdle)
		queue(t, filled(peer, 1))
		<-h.entered
		head := filled(peer, 2)
		queue(t, filled(peer, 4))
		time.Sleep(metricsHold)

		start := time.Now()
		h.letGo()
		synctest.Wait()
		time.Sleep(metricsHold)
		queue(t, head)
		waitUntil(t, "the sender to end its releases", func() bool { return peer.SendStats().Releases.Sum == 7 })
		limit := uint64((time.Since(start) + WaitUnit - 1) / WaitUnit)
		stats := peer.SendStats()
		if all, _ := observations(stats.HeadWaits, 0); all != 1 || stats.HeadWaits.Sum < uint64(metricsHold/WaitUnit) {
			t.Errorf("head waits read %+v, want one wait of at least %s", stats.HeadWaits, metricsHold)
		}
		if stats.HeadWaits.Sum > limit {
			t.Errorf("the head waits total %d microseconds, past the %d since the transport was released", stats.HeadWaits.Sum, limit)
		}
		if all, _ := observations(stats.Releases, 0); all != 2 || stats.Releases.Counts[0] != 1 || stats.Releases.Counts[3] != 1 {
			t.Errorf("a release of 1 packet, a head wait and a release of 6 read %+v", stats.Releases)
		}
	})
}

// a batch's seal time ends when its filler seals it, not when the sender takes it
// so a batch sealed behind one the transport holds reads no time for that hold
func TestSealTimeEndsAtTheSeal(t *testing.T) {
	withMetricsPeer(t, func(t *testing.T, peer *Peer, h *holdingTransport) {
		seal := func() uint64 {
			start := time.Now()
			queue(t, filled(peer, 1))
			return uint64((time.Since(start) + WaitUnit - 1) / WaitUnit)
		}
		limit := seal()
		<-h.entered
		limit += seal()
		time.Sleep(metricsHold)
		h.letGo()
		waitUntil(t, "the sender to take both batches", func() bool { return peer.SendStats().Releases.Sum == 2 })
		seals := peer.SendStats().Seals
		if all, _ := observations(seals, 0); all != 2 || seals.Sum > limit {
			t.Errorf("seal times read %+v, want two totaling at most %d microseconds", seals, limit)
		}
	})
}

// the wait histograms' largest bound is past the delay the sender's CoDel holds its queue to
func TestWaitHistogramsReachPastTheCodelTarget(t *testing.T) {
	if largest := WaitUnit << (histogramBounds - 1); largest <= codelTarget {
		t.Errorf("the wait histograms end at %s, at or under CoDel's target of %s", largest, codelTarget)
	}
}
