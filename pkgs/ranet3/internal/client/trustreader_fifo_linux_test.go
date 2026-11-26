// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTrustBoundedFIFOReaderWithUnknownLength(t *testing.T) {
	if path := os.Getenv("RANET3_TEST_TRUST_FIFO_PATH"); path != "" {
		ready := os.NewFile(3, "fifo-ready")
		if ready == nil {
			t.Fatal("no readiness pipe")
		}
		n, err := ready.Write([]byte{1})
		if closeErr := ready.Close(); err != nil || closeErr != nil || n != 1 {
			t.Fatalf("readiness: wrote %d bytes, write %v, close %v", n, err, closeErr)
		}
		got, err := readTrustBytes(path, 8)
		switch os.Getenv("RANET3_TEST_TRUST_FIFO_CASE") {
		case "at":
			if err != nil || string(got) != "01234567" {
				t.Fatalf("exact eight-byte stream: %q, %v", got, err)
			}
		case "over":
			if err == nil || err.Error() != fmt.Sprintf("trust: %s exceeds its size limit", path) || got != nil {
				t.Fatalf("nine-byte stream at eight-byte cap: %q, %v", got, err)
			}
		case "abort":
			t.Fatalf("reader returned without a writer: %q, %v", got, err)
		default:
			t.Fatal("unknown FIFO child case")
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bounded.fifo")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"at", []byte("01234567")},
		{"over", []byte("012345678")},
		{"abort", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info, err := os.Stat(path)
			if err != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Size() != 0 {
				t.Fatalf("FIFO must hide stream length: %v, %v", info, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			readReady, writeReady, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readReady.Close()
			defer writeReady.Close()
			var output bytes.Buffer
			command := exec.CommandContext(ctx, executable, "-test.run=^TestTrustBoundedFIFOReaderWithUnknownLength$")
			command.Env = append(os.Environ(), "RANET3_TEST_TRUST_FIFO_PATH="+path, "RANET3_TEST_TRUST_FIFO_CASE="+tc.name)
			command.ExtraFiles = []*os.File{writeReady}
			command.Stdout = &output
			command.Stderr = &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- command.Wait() }()
			joined := false
			defer func() {
				cancel()
				if !joined {
					<-done
				}
			}()
			if err := writeReady.Close(); err != nil {
				t.Fatal(err)
			}
			var marker [1]byte
			if _, err := io.ReadFull(readReady, marker[:]); err != nil || marker[0] != 1 {
				cancel()
				childErr := <-done
				joined = true
				t.Fatalf("child readiness: %x, %v, reader %v, %s", marker, err, childErr, output.String())
			}
			if tc.name == "abort" {
				timer := time.NewTimer(50 * time.Millisecond)
				defer timer.Stop()
				select {
				case err := <-done:
					joined = true
					t.Fatalf("reader exited before cancellation: %v, %s", err, output.String())
				case <-timer.C:
					cancel()
					err := <-done
					joined = true
					var exit *exec.ExitError
					if ctx.Err() != context.Canceled || !errors.As(err, &exit) {
						t.Fatalf("reader cancellation: %v, %v, %s", ctx.Err(), err, output.String())
					}
					status, ok := exit.Sys().(syscall.WaitStatus)
					if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
						t.Fatalf("reader not killed and reaped: %v, %s", exit, output.String())
					}
				}
				return
			}
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			var writer int
			for {
				writer, err = unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
				if err == nil {
					break
				}
				if !errors.Is(err, unix.ENXIO) {
					t.Fatalf("nonblocking writer open: %v", err)
				}
				select {
				case <-ctx.Done():
					t.Fatalf("writer open timed out: %v", ctx.Err())
				case err := <-done:
					joined = true
					t.Fatalf("reader exited before writer open: %v, %s", err, output.String())
				case <-ticker.C:
				}
			}
			n, writeErr := unix.Write(writer, tc.body)
			closeErr := unix.Close(writer)
			childErr := <-done
			joined = true
			if writeErr != nil || closeErr != nil || n != len(tc.body) || childErr != nil {
				t.Fatalf("bounded transfer: wrote %d/%d, write %v, close %v, reader %v, output %s", n, len(tc.body), writeErr, closeErr, childErr, output.String())
			}
		})
	}
}
