// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPublishNewFaults(t *testing.T) {
	failure := errors.New("injected failure")
	for _, test := range []struct {
		name      string
		ops       publishOps
		published bool
	}{
		{"write", publishOps{write: func(*os.File, []byte) (int, error) { return 0, failure }}, false},
		{"file sync", publishOps{fileSync: func(*os.File) error { return failure }}, false},
		{"link", publishOps{link: func(string, string) error { return failure }}, false},
		{"directory sync", publishOps{dirSync: func(*os.File) error { return failure }}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "authority.pem")
			if err := publishNew(path, []byte("new"), 0600, test.ops); !errors.Is(err, failure) {
				t.Fatalf("error %v, want injected failure", err)
			}
			body, err := os.ReadFile(path)
			if test.published {
				if err != nil || !bytes.Equal(body, []byte("new")) {
					t.Fatalf("published bytes %q, error %v", body, err)
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected path bytes %q, error %v", body, err)
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != btoi(test.published) {
				t.Fatalf("directory entries %v, error %v", entries, err)
			}
		})
	}
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func TestPublishNewPreservesExistingAndMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	if err := PublishNew(path, []byte("first"), 0600); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatalf("mode %v, error %v", stat, err)
	}
	secondErr := PublishNew(path, []byte("second"), 0600)
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "first" {
		t.Errorf("existing bytes %q, error %v", body, readErr)
	}
	if !errors.Is(secondErr, os.ErrExist) {
		t.Errorf("existing path error %v, want file exists", secondErr)
	}
}

func TestPublishNewRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.pem")
	var started sync.WaitGroup
	started.Add(2)
	begin := make(chan struct{})
	var errs [2]error
	var running sync.WaitGroup
	running.Add(2)
	for i := range errs {
		go func() {
			defer running.Done()
			started.Done()
			<-begin
			errs[i] = PublishNew(path, []byte{byte('a' + i)}, 0600)
		}()
	}
	started.Wait()
	close(begin)
	running.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("racing publishers: %v", errs)
	}
	if loser := errs[btoi(errs[0] == nil)]; !errors.Is(loser, os.ErrExist) {
		t.Fatalf("losing publisher: %v", loser)
	}
	body, err := os.ReadFile(path)
	if err != nil || len(body) != 1 || body[0] != byte('a'+btoi(errs[0] != nil)) {
		t.Fatalf("winning bytes %q, error %v, writers %v", body, err, errs)
	}
}
