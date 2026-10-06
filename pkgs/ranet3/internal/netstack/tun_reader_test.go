// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// scriptedRead is one answer of a scriptedDevice to Read
type scriptedRead struct {
	packets [][]byte
	err     error
}

// scriptedDevice answers each Read with the next scripted answer
// and reports closure once the mesh closes it
type scriptedDevice struct {
	recordingDevice
	reads  chan scriptedRead
	closed chan struct{}
}

func (d *scriptedDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case read := <-d.reads:
		for i, packet := range read.packets {
			sizes[i] = copy(bufs[i][offset:], packet)
		}
		return len(read.packets), read.err
	case <-d.closed:
		return 0, os.ErrClosed
	}
}

func (d *scriptedDevice) Close() error {
	close(d.closed)
	return nil
}

// deliveryTimeout bounds every wait of these tests for something they expect to happen
// and deliveryPoll is how often one looks again
const (
	deliveryTimeout = 5 * time.Second
	deliveryPoll    = time.Millisecond
)

// waitUntil looks at cond every deliveryPoll until it holds
// and fails the test with what it waited for once deliveryTimeout has passed
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(deliveryTimeout); !cond(); time.Sleep(deliveryPoll) {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s", deliveryTimeout, what)
		}
	}
}

// a GSO frame of more segments than one read holds
// comes back cut short with ErrTooManySegments
// and a reader that stopped there would leave its queue's flows unread
func TestReaderKeepsReadingPastACutGSOFrame(t *testing.T) {
	dev := &scriptedDevice{reads: make(chan scriptedRead, 2), closed: make(chan struct{})}
	sent := &recordingPeer{}
	m := &Mesh{
		Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + outboundPacketBufferSize,
	}
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("::/0"), sent.peer("peer"))
	m.startOutboundPipeline()
	t.Cleanup(m.Close)

	source, destination := segAddr("fd00::1"), segAddr("fd00::2")
	want := [][]byte{
		plainV6(source, destination, "first segment of the frame"),
		plainV6(source, destination, "last segment the read held"),
		plainV6(source, destination, "next read"),
	}
	dev.reads <- scriptedRead{packets: want[:2], err: tun.ErrTooManySegments}
	dev.reads <- scriptedRead{packets: want[2:]}

	deadline := time.Now().Add(deliveryTimeout)
	for len(sent.packets()) < len(want) && time.Now().Before(deadline) {
		time.Sleep(deliveryPoll)
	}
	got := sent.packets()
	if len(got) != len(want) {
		t.Fatalf("the peer was sent %d packets, want the two of the cut read and the one after it", len(got))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("packet %d is %x, want %x", i, got[i], want[i])
		}
	}
	if cut := m.TUNReadsTruncated(); cut != 1 {
		t.Errorf("%d reads were counted as cut short, want the one", cut)
	}
}

// a linux read hands over every segment of a GSO frame at once
// and a read off one queue can carry packets for several peers
// so every packet of the read goes to its own peer, in the order the read held them
func TestReaderRoutesEveryPacketOfOneRead(t *testing.T) {
	dev := &scriptedDevice{reads: make(chan scriptedRead, 1), closed: make(chan struct{})}
	var mu sync.Mutex
	sent := map[string][][]byte{}
	peer := func(id string) *Peer {
		p := NewPeerReserved(id, func(int) (BatchSealer, error) {
			return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
				out = out[:0]
				for _, packet := range raw {
					out = append(out, bytes.Clone(packet))
				}
				return out, nil
			}, nil
		}, func(sealed [][]byte) error {
			mu.Lock()
			defer mu.Unlock()
			sent[id] = append(sent[id], sealed...)
			return nil
		})
		t.Cleanup(p.Close)
		return p
	}
	a, b := peer("a"), peer("b")
	m := &Mesh{
		Name: "test0", Routes: NewRouteTable(), devs: []tun.Device{dev}, closed: make(chan struct{}),
		outboundBufferSize: tunOffset + outboundPacketBufferSize,
	}
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("fd00::a/128"), a)
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("fd00::b/128"), b)
	m.startOutboundPipeline()
	t.Cleanup(m.Close)

	source := segAddr("fd00::1")
	read := [][]byte{
		plainV6(source, segAddr("fd00::a"), "a first"),
		plainV6(source, segAddr("fd00::b"), "b first"),
		plainV6(source, segAddr("fd00::a"), "a second"),
		plainV6(source, segAddr("fd00::b"), "b second"),
		plainV6(source, segAddr("fd00::a"), "a third"),
	}
	want := map[string][][]byte{"a": {read[0], read[2], read[4]}, "b": {read[1], read[3]}}
	dev.reads <- scriptedRead{packets: read}

	sentTo := func(id string) [][]byte {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(sent[id])
	}
	waitUntil(t, "every packet of one read to reach its peer", func() bool {
		return len(sentTo("a")) >= len(want["a"]) && len(sentTo("b")) >= len(want["b"])
	})
	for id := range want {
		if got := sentTo(id); !slices.EqualFunc(got, want[id], bytes.Equal) {
			t.Errorf("peer %s was sent %q, want %q", id, got, want[id])
		}
	}
	if a.Dropped() != 0 || b.Dropped() != 0 {
		t.Errorf("the peers counted %d and %d packets dropped out of one read they had room for", a.Dropped(), b.Dropped())
	}
}

// warnedReads points the default logger at a buffer for the test
// and returns the reads= count of every warning written so far
func warnedReads(t *testing.T) func() []uint64 {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return func() []uint64 {
		var counts []uint64
		for _, match := range regexp.MustCompile(`reads=(\d+)`).FindAllStringSubmatch(logs.String(), -1) {
			count, err := strconv.ParseUint(match[1], 10, 64)
			if err != nil {
				t.Fatalf("a warning carried %q: %v", match[0], err)
			}
			counts = append(counts, count)
		}
		return counts
	}
}

// startedMesh spaces its cut-read warnings the way NewNamed sets them up
func startedMesh() *Mesh {
	m := &Mesh{Name: "test0"}
	m.startSegmentReports()
	return m
}

// a sender with a small MSS cuts read after read
// the count stays exact while the log gets one line an interval
// and each line says how many reads were cut since the one before
func TestCutReadsAreCountedExactlyAndWarnedRarely(t *testing.T) {
	warned := warnedReads(t)
	m := startedMesh()
	const cut = 1000
	for range cut {
		m.noteTruncatedRead()
	}
	if got := m.TUNReadsTruncated(); got != cut {
		t.Errorf("the counter reads %d for %d reads cut short", got, cut)
	}
	if got := warned(); !slices.Equal(got, []uint64{1}) {
		t.Fatalf("%d reads cut short warned with counts %v, want one line for the first", cut, got)
	}

	m.truncatedNextWarning.Add(-int64(truncatedReadInterval))
	m.noteTruncatedRead()
	if got := warned(); !slices.Equal(got, []uint64{1, cut}) {
		t.Errorf("once the interval passed the warnings carried %v, want the %d cut since the first line", got, cut)
	}
}

// every queue has a reader of its own that can cut a read
// and all of them share one warning an interval
// whose counts add up to the counter
// each wave lets every reader go at once just as an interval has run out
func TestCutReadsOnEveryQueueShareOneWarning(t *testing.T) {
	warned := warnedReads(t)
	m := startedMesh()
	const queues, waves = 8, 200
	for wave := range waves {
		var start atomic.Bool
		var readers sync.WaitGroup
		for range queues {
			readers.Go(func() {
				for !start.Load() {
					runtime.Gosched()
				}
				m.noteTruncatedRead()
			})
		}
		start.Store(true)
		readers.Wait()
		if got := warned(); len(got) != wave+1 {
			t.Fatalf("after wave %d of %d readers cutting reads at once the warnings are %v, want one a wave", wave, queues, got)
		}
		m.truncatedNextWarning.Add(-int64(truncatedReadInterval))
	}

	m.noteTruncatedRead()
	got := warned()
	var sum uint64
	for _, count := range got {
		sum += count
	}
	if len(got) != waves+1 || sum != m.TUNReadsTruncated() {
		t.Errorf("the warnings carried %v, want %d whose counts add up to the %d reads counted", got, waves+1, m.TUNReadsTruncated())
	}
}

// readers that cut a read at the same moment can all load the same time for the next warning
// and only the first of them to claim it writes the line
// the claims are made one after another here, so the check holds on one cpu as on many
func TestOnlyOneReaderClaimsAWarning(t *testing.T) {
	m := startedMesh()
	now, next := int64(time.Since(m.segmentsStarted)), m.truncatedNextWarning.Load()
	if !m.claimTruncatedWarning(now, next) {
		t.Fatal("the first reader to cut a read did not get to warn")
	}
	if m.claimTruncatedWarning(now, next) {
		t.Fatal("a second reader warned as well, with the time it had loaded before the first claim")
	}
	later := m.truncatedNextWarning.Load()
	if later != now+int64(truncatedReadInterval) {
		t.Fatalf("the claim put the next warning %s after it, want %s", time.Duration(later-now), truncatedReadInterval)
	}
	if m.claimTruncatedWarning(later-1, later) {
		t.Error("a reader warned before the interval had passed")
	}
	if !m.claimTruncatedWarning(later, later) {
		t.Error("the first reader once the interval had passed did not get to warn")
	}
}
