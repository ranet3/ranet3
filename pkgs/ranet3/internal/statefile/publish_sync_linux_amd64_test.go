// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && amd64

package statefile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "--sync-child" {
		return
	}
	// Only the initial OS thread is traced, so publication must stay on it.
	runtime.LockOSThread()
	if err := PublishNew(os.Args[2], []byte("complete"), 0600); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestPublishNewDefaultSyncs(t *testing.T) {
	// ptrace commands must come from the same OS thread that started the trace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	path := filepath.Join(t.TempDir(), "signed.cose")
	child := exec.Command(os.Args[0], "--sync-child", path)
	child.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	reaped := false
	defer func() {
		if !reaped {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			var status syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &status, 0, nil)
		}
		_ = child.Process.Release()
	}()
	var status syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil || !status.Stopped() {
		t.Fatalf("traced publisher did not stop at exec: %v, %v", status, err)
	}
	if err := syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		t.Fatal(err)
	}
	type syncTarget struct {
		path string
		mode os.FileMode
	}
	var targets []syncTarget
	entering := true
	signal := 0
	for {
		if err := syscall.PtraceSyscall(pid, signal); err != nil {
			t.Fatal(err)
		}
		if _, err := syscall.Wait4(pid, &status, 0, nil); err != nil {
			t.Fatal(err)
		}
		if status.Exited() || status.Signaled() {
			reaped = true
			if !status.Exited() || status.ExitStatus() != 0 {
				t.Fatalf("publisher exited before success: %v", status)
			}
			break
		}
		signal = 0
		switch status.StopSignal() {
		case syscall.SIGTRAP | 0x80:
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); err != nil {
				t.Fatal(err)
			}
			if entering && regs.Orig_rax == syscall.SYS_FSYNC {
				descriptor := fmt.Sprintf("/proc/%d/fd/%d", pid, regs.Rdi)
				info, err := os.Stat(descriptor)
				if err != nil {
					t.Fatalf("stat synced descriptor %s: %v", descriptor, err)
				}
				name, err := os.Readlink(descriptor)
				if err != nil {
					t.Fatalf("read synced descriptor %s: %v", descriptor, err)
				}
				targets = append(targets, syncTarget{name, info.Mode()})
			}
			entering = !entering
		case syscall.SIGTRAP:
		default:
			signal = int(status.StopSignal())
		}
	}
	directory := filepath.Dir(path)
	temporaryPrefix := "." + filepath.Base(path) + "."
	if len(targets) != 2 ||
		!targets[0].mode.IsRegular() || filepath.Dir(targets[0].path) != directory ||
		!strings.HasPrefix(filepath.Base(targets[0].path), temporaryPrefix) ||
		!targets[1].mode.IsDir() || targets[1].path != directory {
		t.Fatalf("want temporary-file fsync then directory fsync, observed %+v", targets)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "complete" {
		t.Fatalf("published bytes %q: %v", body, err)
	}
}
