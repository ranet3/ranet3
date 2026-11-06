// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"bytes"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// monitorWakeBudget is how long a test waits for a monitor's wake, generous for a loaded machine
const monitorWakeBudget = time.Second

// scriptedSource is a monitor's socket whose reads a test queues, a standing error failing every read while set
// a read with nothing queued waits for the queue or for Close
type scriptedSource struct {
	queue    chan scriptedRead
	closed   chan struct{}
	closing  sync.Once
	standing error
	reads    atomic.Int32
}

type scriptedRead struct {
	datagram []byte
	err      error
}

func newScriptedSource(standing error) *scriptedSource {
	return &scriptedSource{queue: make(chan scriptedRead, 4), closed: make(chan struct{}), standing: standing}
}

func (s *scriptedSource) Read(buf []byte) (int, error) {
	select {
	case <-s.closed:
		return 0, os.ErrClosed
	default:
	}
	if s.standing != nil {
		s.reads.Add(1)
		return 0, s.standing
	}
	select {
	case <-s.closed:
		return 0, os.ErrClosed
	case read := <-s.queue:
		s.reads.Add(1)
		return copy(buf, read.datagram), read.err
	}
}

func (s *scriptedSource) Close() error {
	s.closing.Do(func() { close(s.closed) })
	return nil
}

// awaitWake fails the test unless signal wakes within monitorWakeBudget
func awaitWake(t *testing.T, signal <-chan struct{}, step string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(monitorWakeBudget):
		t.Fatalf("%s did not wake the monitor", step)
	}
}

// notificationReader is readNotifications reading a scripted source, its wakes on woke and the datagrams it hands on on got
type notificationReader struct {
	woke     chan struct{}
	got      chan []byte
	stop     chan struct{}
	stopping sync.Once
	done     chan struct{}
}

func readingNotifications(t *testing.T, source *scriptedSource) *notificationReader {
	r := &notificationReader{woke: make(chan struct{}, 1), got: make(chan []byte, 4), stop: make(chan struct{}), done: make(chan struct{})}
	wake := func() {
		select {
		case r.woke <- struct{}{}:
		default:
		}
	}
	go func() {
		defer close(r.done)
		readNotifications("scripted", source, make([]byte, 64), r.stop, wake, func(datagram []byte) { r.got <- slices.Clone(datagram) })
	}()
	t.Cleanup(func() {
		r.end()
		_ = source.Close()
		<-r.done
	})
	return r
}

func (r *notificationReader) end() { r.stopping.Do(func() { close(r.stop) }) }

// handedOn fails the test unless the next datagram handed on is want and comes before deadline
func (r *notificationReader) handedOn(t *testing.T, want []byte, deadline <-chan time.Time, what string) {
	t.Helper()
	select {
	case got := <-r.got:
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: handed on %q, want %q", what, got, want)
		}
	case <-deadline:
		t.Fatalf("%s was not handed on in time", what)
	}
}

// an error other than ENOBUFS wakes and the next read follows at once, so the notification queued behind it is handed on
// well before the backoff of a second error in a row
func TestReadNotificationsReadsAgainAtOnceAfterAnError(t *testing.T) {
	source := newScriptedSource(nil)
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	source.queue <- scriptedRead{datagram: []byte("after the error")}
	deadline := time.After(closeBudget)
	reader := readingNotifications(t, source)
	reader.handedOn(t, []byte("after the error"), deadline, "the notification after an error")
	select {
	case <-reader.woke:
	default:
		t.Error("the error did not wake")
	}
	select {
	case <-reader.done:
		t.Error("the reading stopped")
	default:
	}
}

// pacedWindow is how long a test counts the reads of a source whose every read fails
const pacedWindow = 7 * minRetryInterval / 2

// a source whose every read fails is read again at once after the first failure, then on a backoff doubling from minRetryInterval
func TestReadNotificationsPacesRepeatedErrors(t *testing.T) {
	source := newScriptedSource(unix.EMSGSIZE)
	readingNotifications(t, source)
	time.Sleep(pacedWindow)
	if reads, limit := int(source.reads.Load()), maxReadsIn(pacedWindow, 2); reads > limit {
		t.Errorf("a source failing every read was read %d times in %v, want at most %d", reads, pacedWindow, limit)
	}
}

// ENOBUFS reports an overrun the next read has already ended, so the reading goes on at once however often it comes
func TestReadNotificationsNeverPausesOnAnOverrun(t *testing.T) {
	source := newScriptedSource(unix.ENOBUFS)
	readingNotifications(t, source)
	time.Sleep(closeBudget)
	if reads := int(source.reads.Load()); reads <= maxReadsIn(closeBudget, 2) {
		t.Errorf("a source reporting ENOBUFS on every read was read %d times in %v, so an overrun paused the reading", reads, closeBudget)
	}
}

// stop ends a backoff at once, and the reading with it
func TestReadNotificationsEndsABackoffWhenStopCloses(t *testing.T) {
	source := newScriptedSource(unix.EMSGSIZE)
	reader := readingNotifications(t, source)
	// from the second error in a row on, each leaves the reading waiting out a backoff of at least minRetryInterval, which stop must
	// end at once
	waitFor(t, func() bool { return source.reads.Load() >= 3 })
	reader.end()
	select {
	case <-reader.done:
	case <-time.After(closeBudget):
		t.Fatalf("the reading waited out the backoff after stop closed, more than %v", closeBudget)
	}
}

// a read that succeeds ends a streak of errors and its backoff, so a later streak waits minRetryInterval at its second error and
// not the longer backoff the first streak doubled to
func TestReadNotificationsStartsItsBackoffOverAfterARead(t *testing.T) {
	source := newScriptedSource(nil)
	for range 3 {
		source.queue <- scriptedRead{err: unix.EMSGSIZE}
	}
	source.queue <- scriptedRead{datagram: []byte("after the first streak")}
	reader := readingNotifications(t, source)
	// the first streak waits out a backoff from its second error on, starting at minRetryInterval and doubling
	reader.handedOn(t, []byte("after the first streak"), time.After(3*minRetryInterval+monitorWakeBudget), "the notification after the first streak")
	deadline := time.After(2 * minRetryInterval)
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	source.queue <- scriptedRead{err: unix.EMSGSIZE}
	source.queue <- scriptedRead{datagram: []byte("after the second streak")}
	reader.handedOn(t, []byte("after the second streak"), deadline, "the notification after a later streak of two errors")
}
