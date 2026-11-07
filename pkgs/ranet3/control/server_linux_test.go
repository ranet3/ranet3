// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// A socket bound at its path sits there at the mode the umask leaves until
// the chmod after it, which a umask of 0 makes open to everyone. The kernel
// reports each change to a directory's entries as it makes it, so the events
// show the socket arriving at its path by a rename alone, with no change to
// its mode after.
func TestListenRenamesTheSocketInAtItsMode(t *testing.T) {
	path := socketPath(t)
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, filepath.Dir(path), unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_ATTRIB); err != nil {
		t.Fatal(err)
	}
	defer unix.Umask(unix.Umask(0))

	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	moved := false
	for _, event := range inotifyEvents(t, watch) {
		if event.name != filepath.Base(path) {
			continue
		}
		switch {
		case event.mask&unix.IN_CREATE != 0:
			t.Error("the socket was made at its path, where it sits at the umask's mode until the chmod")
		case event.mask&unix.IN_MOVED_TO != 0:
			moved = true
		case event.mask&unix.IN_ATTRIB != 0 && moved:
			t.Error("the socket's mode or group changed after it reached its path")
		}
	}
	if !moved {
		t.Error("the socket did not reach its path by a rename")
	}
	if mode, _ := modeAndGroup(t, path); mode.Perm() != 0o660 {
		t.Errorf("the socket is mode %o under a umask of 0, want 660", mode.Perm())
	}
}

// A daemon that takes the lock the moment it is released renames its own
// socket onto the path, so an unlink after the release can take that socket
// away. The lock is held by a descriptor opened for writing, which the kernel
// reports closed after the unlink it reports for the socket.
func TestCloseUnlinksTheSocketBeforeItReleasesTheLock(t *testing.T) {
	path := socketPath(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	watch, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, filepath.Dir(path), unix.IN_DELETE|unix.IN_CLOSE_WRITE); err != nil {
		t.Fatal(err)
	}

	if err := listener.Close(); err != nil {
		t.Fatalf("closing reported %v", err)
	}

	var order []string
	for _, event := range inotifyEvents(t, watch) {
		switch {
		case event.mask&unix.IN_DELETE != 0 && event.name == filepath.Base(path):
			order = append(order, "unlink")
		case event.mask&unix.IN_CLOSE_WRITE != 0 && event.name == filepath.Base(path)+lockSuffix:
			order = append(order, "release")
		}
	}
	if want := []string{"unlink", "release"}; !slices.Equal(order, want) {
		t.Errorf("Close did %q, want %q", order, want)
	}
}

type inotifyEvent struct {
	mask uint32
	name string
}

// inotifyEvents reads every event queued on watch, which never blocks
func inotifyEvents(t *testing.T, watch int) []inotifyEvent {
	t.Helper()
	var events []inotifyEvent
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Read(watch, buf)
		if errors.Is(err, unix.EAGAIN) {
			return events
		}
		if err != nil {
			t.Fatal(err)
		}
		for record := buf[:n]; len(record) >= unix.SizeofInotifyEvent; {
			size := unix.SizeofInotifyEvent + int(binary.NativeEndian.Uint32(record[12:16]))
			name := bytes.TrimRight(record[unix.SizeofInotifyEvent:size], "\x00")
			events = append(events, inotifyEvent{mask: binary.NativeEndian.Uint32(record[4:8]), name: string(name)})
			record = record[size:]
		}
	}
}
