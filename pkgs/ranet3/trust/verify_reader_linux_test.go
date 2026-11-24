// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package trust

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type zeroStream struct{}

func (zeroStream) Read(body []byte) (int, error) {
	clear(body)
	return len(body), nil
}

func TestReadSignedFileCapsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stream")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			finished <- err
			return
		}
		_, err = io.CopyN(file, zeroStream{}, MaxSignedBytes+1)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		finished <- err
	}()
	_, err := ReadSignedFile(path, nil)
	writeErr := <-finished
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if err == nil || !strings.Contains(err.Error(), "at read") {
		t.Fatalf("accepted a stream larger than 64 MiB: %v", err)
	}
}
