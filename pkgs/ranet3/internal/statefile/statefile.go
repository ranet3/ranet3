// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

// Package statefile keeps the files that record which kernel objects this
// daemon holds, so a run after a crash releases what the crashed one left. A
// record is the only claim a run makes on such an object, and an object is
// never claimed by its shape.
//
// Each file lives in the daemon's state directory, which outlives a reboot, so
// a record names kernel objects a reboot may have ended and the reader checks
// each against the kernel before it acts on it.
//
// Its lock and its whole-file write serve the daemon's other files too: the
// control socket's lock and the client's down flag and Babel state.
package statefile

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// errNoPath refuses a record with no file, which would hold nothing for the
// next start to give back
var errNoPath = errors.New("statefile: a record needs a path")

// Lock is the claim on a record, held for the life of the process. It makes
// the file this process's to read and rewrite: without it a second daemon
// starting beside a running one would act on the first's live record and then
// write its own over it.
type Lock struct{ file *os.File }

// Close releases the claim, once however often it is called. The flock goes
// with the descriptor.
func (l *Lock) Close() error {
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

// Take claims the record at path, in a directory that exists, or reports that
// another process holds it
func Take(path string) (*Lock, error) {
	if path == "" {
		return nil, errNoPath
	}
	file, err := Flock(path + ".lock")
	switch {
	case errors.Is(err, unix.EWOULDBLOCK):
		return nil, fmt.Errorf("statefile: another process holds the record at %s: %w", path, err)
	case err != nil:
		return nil, fmt.Errorf("statefile: %w", err)
	}
	return &Lock{file: file}, nil
}

// Flock opens the file at path, creating it at mode, and takes its exclusive
// flock without waiting, which the file holds for as long as it is open. A
// lock another process holds is reported, its error wrapping
// unix.EWOULDBLOCK, rather than waited for.
func Flock(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, mode)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	return file, nil
}

// Write replaces the file at path with raw, whole or not at all: raw goes to
// a file beside it, named path with tempSuffix, at mode, which is renamed
// over path, so a process dying mid-write leaves the file as it was
func Write(path string, raw []byte) error {
	return write(path, raw, false)
}

// WriteSynced is Write with the written file synced before the rename, so a
// crash after it returns finds raw once the directory's entry is synced too
func WriteSynced(path string, raw []byte) error {
	return write(path, raw, true)
}

func write(path string, raw []byte, sync bool) error {
	if path == "" {
		return errNoPath
	}
	temp := path + tempSuffix
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	// the mode the open gives holds only for a file it creates, and the umask
	// takes from it, so a temporary file a crash left keeps its own without this
	err = file.Chmod(mode)
	if err == nil {
		_, err = file.Write(raw)
	}
	if err == nil && sync {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err == nil {
		err = os.Rename(temp, path)
	}
	if err != nil {
		_ = os.Remove(temp)
	}
	return err
}
