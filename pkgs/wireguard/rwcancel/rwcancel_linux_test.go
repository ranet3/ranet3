// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: MIT

package rwcancel

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// orderWait bounds each wait of TestCloseWaitsForCancelInWrite.
const orderWait = 10 * time.Second

// parked waits until a goroutine whose stack holds fn is parked with the wait
// reason reason, and reports true, or until done is closed, and reports false.
// Only the runtime tells that a goroutine waits and on what: parked reads the
// wait reason from the header of each goroutine in runtime.Stack, as in
// "goroutine 7 [IO wait]:", and the reasons are those of go 1.27.
func parked(t *testing.T, done <-chan struct{}, fn, reason string) bool {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(orderWait); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		select {
		case <-done:
			return false
		default:
		}
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			header, stack, _ := strings.Cut(g, "\n")
			if strings.Contains(header, " ["+reason) && strings.Contains(stack, fn) {
				return true
			}
		}
	}
	t.Fatalf("no goroutine in %s was parked with wait reason %q within %v", fn, reason, orderWait)
	return false
}

// TestCloseWaitsForCancelInWrite starts Close while Cancel's write waits for
// room in a full pipe, then drains the pipe, and requires the write to succeed.
func TestCloseWaitsForCancelInWrite(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	rw, err := NewRWCancel(fds[0])
	if err != nil {
		t.Fatal(err)
	}

	sc, err := rw.closingWriter.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	filled := 0
	var ferr error
	if err := sc.Control(func(fd uintptr) {
		chunk := make([]byte, 4096)
		for ferr == nil {
			var n int
			n, ferr = unix.Write(int(fd), chunk)
			filled += max(n, 0)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != unix.EAGAIN {
		t.Fatalf("filling the pipe stopped on %v after %d bytes, want EAGAIN", ferr, filled)
	}

	cancelled := make(chan error, 1)
	go func() { cancelled <- rw.Cancel() }()
	parked(t, nil, "(*RWCancel).Cancel", "IO wait")

	closed := make(chan struct{})
	go func() {
		rw.Close()
		close(closed)
	}()
	// Close has returned, or it waits for Cancel to leave the Once
	parked(t, closed, "(*RWCancel).Close", "sync.Mutex.Lock")

	drained, derr := rw.closingReader.Read(make([]byte, filled))
	select {
	case err := <-cancelled:
		if err != nil {
			t.Fatalf("Cancel with Close called during its write: %v (the drain read %d of %d bytes, %v)", err, drained, filled, derr)
		}
	case <-time.After(orderWait):
		t.Fatalf("Cancel did not return within %v of the drain, which read %d of %d bytes, %v", orderWait, drained, filled, derr)
	}
	select {
	case <-closed:
	case <-time.After(orderWait):
		t.Fatalf("Close did not return within %v of Cancel", orderWait)
	}
}
