// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !race

// The 256 MiB plus one byte authored read has no concurrent access and uses 2.4 GiB under the race detector.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"ranet3.com/pkgs/ranet3/trust"
)

func TestTrustSigningShortStatByteLimit(t *testing.T) {
	// A FIFO reports zero at stat but supplies exactly one byte beyond the cap.
	keyPath, input, public := trustSigningFixture(t)
	parent := filepath.Join(t.TempDir(), "parent.cose")
	if _, _, err := runTrustCommand("trust", "init", "--key", keyPath, "--out", parent, input); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"init", "sign"} {
		path := filepath.Join(t.TempDir(), "authored.fifo")
		if err := syscall.Mkfifo(path, 0600); err != nil {
			t.Fatal(err)
		}
		if info, err := os.Stat(path); err != nil || info.Size() != 0 {
			t.Fatalf("authored stream stat: %v, %v", info, err)
		}
		sent := make(chan error, 1)
		stop := make(chan struct{})
		go func() {
			fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
			for err == syscall.ENXIO {
				select {
				case <-stop:
					sent <- fmt.Errorf("reader did not open FIFO")
					return
				default:
				}
				runtime.Gosched()
				fd, err = syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
			}
			if err != nil {
				sent <- err
				return
			}
			defer syscall.Close(fd)
			chunk := make([]byte, 32<<10)
			for remaining := trust.MaxJSONBytes + 1; remaining > 0; {
				n, err := syscall.Write(fd, chunk[:min(remaining, len(chunk))])
				if err == syscall.EAGAIN {
					select {
					case <-stop:
						sent <- fmt.Errorf("reader stopped before byte limit")
						return
					default:
					}
					runtime.Gosched()
					continue
				}
				if err != nil {
					sent <- err
					return
				}
				remaining -= n
			}
			sent <- nil
		}()
		output := filepath.Join(t.TempDir(), "signed.cose")
		args := []string{"trust", verb, "--key", keyPath, "--out", output}
		if verb == "sign" {
			args = append(args, "--previous", parent, "--authority", public)
		}
		out, stderr, err := runTrustCommand(append(args, path)...)
		close(stop)
		if writeErr := <-sent; writeErr != nil {
			t.Fatalf("%s supplied fewer than %d bytes: %v", verb, trust.MaxJSONBytes+1, writeErr)
		}
		if err == nil || out != "" || stderr != path+": authored JSON exceeds 256 MiB\n" {
			t.Fatalf("%s short-stat byte limit: stdout %q, stderr %q, error %v", verb, out, stderr, err)
		}
		if _, err := os.Lstat(output); !os.IsNotExist(err) {
			t.Fatalf("%s published over-limit stream: %v", verb, err)
		}
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			t.Log(line)
		}
	}
}
