// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package pf

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// referenceHelper names the record a helper process takes a reference
// through, and referenceHelperExit makes it exit rather than wait to be
// killed, which it does for at most helperWait
const (
	referenceHelper     = "RANET3_PF_REFERENCE_HELPER"
	referenceHelperExit = "RANET3_PF_REFERENCE_HELPER_EXIT"
	helperWait          = time.Minute
)

// TestPfReferenceHelper takes a reference through Take and prints its token,
// then waits to be killed, or exits without releasing it where asked. It runs
// only as the reference test's child.
func TestPfReferenceHelper(t *testing.T) {
	path := os.Getenv(referenceHelper)
	if path == "" {
		t.Skip("run only as the reference test's child")
	}
	r, err := Take(NewCtl(), path)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("token %d\n", r.Token())
	if os.Getenv(referenceHelperExit) == "1" {
		return
	}
	time.Sleep(helperWait)
}

// helper runs the test binary again as a process holding a reference recorded
// at path, and returns it with the token it took
func helper(t *testing.T, path string, exit bool) (*exec.Cmd, uint64) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestPfReferenceHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), referenceHelper+"="+path)
	if exit {
		cmd.Env = append(cmd.Env, referenceHelperExit+"=1")
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewScanner(out)
	for lines.Scan() {
		if word, ok := strings.CutPrefix(lines.Text(), "token "); ok {
			token, err := strconv.ParseUint(word, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return cmd, token
		}
	}
	_ = cmd.Wait()
	t.Fatal("the helper printed no token")
	return nil, 0
}

func listed(t *testing.T, ctl Ctl, token uint64) bool {
	t.Helper()
	enablers, err := ctl.References()
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(enablers, func(e Enabler) bool { return e.Token == token })
}

// a reference taken through Take outlives its process killed with SIGKILL,
// and the next Take over the same record gives it back and takes its own. A
// reference listed under this binary's name for a process that has exited,
// which no record holds, is left alone, and so is one a record names under
// another pid than pf lists it under. pf ends as it started.
func TestPfReferenceOutlivesItsProcessAndTheRecordReleasesIt(t *testing.T) {
	requireRoot(t)
	ctl := NewCtl()
	wasRunning, err := ctl.Running()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "pf.json")
	// each token a helper took goes back at cleanup if a failure left it held
	var taken []uint64
	t.Cleanup(func() {
		for _, token := range taken {
			if listed(t, ctl, token) {
				t.Logf("releasing token %d a failure left held: %v", token, ctl.Release(token))
			}
		}
	})

	killed, leaked := helper(t, path, false)
	taken = append(taken, leaked)
	if err := killed.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = killed.Wait()
	if !listed(t, ctl, leaked) {
		t.Fatalf("the killed helper's token %d is not listed", leaked)
	}

	planter, planted := helper(t, filepath.Join(dir, "elsewhere.json"), true)
	taken = append(taken, planted)
	if err := planter.Wait(); err != nil {
		t.Fatalf("the planting helper: %v", err)
	}

	r, err := Take(ctl, path)
	if err != nil {
		t.Fatal(err)
	}
	if listed(t, ctl, leaked) {
		t.Errorf("the killed helper's recorded token %d is still listed after Take", leaked)
	}
	if !listed(t, ctl, planted) {
		t.Errorf("Take released token %d, which no record it holds names", planted)
	}
	if !listed(t, ctl, r.Token()) {
		t.Errorf("Take's own token %d is not listed", r.Token())
	}
	if err := r.Release(); err != nil {
		t.Fatal(err)
	}

	// a record naming the planted token under another pid than pf lists it
	// under names another reference, which Take leaves held
	misnamed := filepath.Join(dir, "misnamed.json")
	if err := os.WriteFile(misnamed, fmt.Appendf(nil, `{"held":[{"token":"%d","pid":%d}]}`, planted, os.Getpid()), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := Take(ctl, misnamed)
	if err != nil {
		t.Fatal(err)
	}
	if !listed(t, ctl, planted) {
		t.Errorf("Take released token %d, which pf lists under another pid than the record holds", planted)
	}
	if err := other.Release(); err != nil {
		t.Fatal(err)
	}
	if err := ctl.Release(planted); err != nil {
		t.Fatal(err)
	}
	if running, err := ctl.Running(); err != nil || running != wasRunning {
		t.Errorf("pf running %v (%v) after the test, %v before", running, err, wasRunning)
	}
}
