// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
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

// deliveryTimeout bounds the wait for the packets a reader hands on
// and deliveryPoll is how often the test looks for them
const (
	deliveryTimeout = 5 * time.Second
	deliveryPoll    = time.Millisecond
)

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
	m.truncatedWarned.Store(-int64(truncatedReadInterval))
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

	m.truncatedWarned.Add(-int64(truncatedReadInterval))
	m.noteTruncatedRead()
	if got := warned(); !slices.Equal(got, []uint64{1, cut}) {
		t.Errorf("once the interval passed the warnings carried %v, want the %d cut since the first line", got, cut)
	}
}

// every queue has a reader of its own that can cut a read
// and all of them share one warning an interval
// whose counts add up to the counter
func TestCutReadsOnEveryQueueShareOneWarning(t *testing.T) {
	warned := warnedReads(t)
	m := startedMesh()
	const queues, cutsPerQueue = 8, 125
	start := make(chan struct{})
	var readers sync.WaitGroup
	for range queues {
		readers.Go(func() {
			<-start
			for range cutsPerQueue {
				m.noteTruncatedRead()
			}
		})
	}
	close(start)
	readers.Wait()
	if got := warned(); len(got) != 1 {
		t.Fatalf("%d readers cutting reads at once wrote warnings %v in one interval, want one", queues, got)
	}

	m.truncatedWarned.Add(-int64(truncatedReadInterval))
	m.noteTruncatedRead()
	got := warned()
	var sum uint64
	for _, count := range got {
		sum += count
	}
	if len(got) != 2 || sum != m.TUNReadsTruncated() {
		t.Errorf("the warnings carried %v, want two whose counts add up to the %d reads counted", got, m.TUNReadsTruncated())
	}
}
