// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTrustMissingSourceDoesNotOpenInput(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "blocked.cose")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "empty.toml")
	configuration := "node = \"example/laptop\"\n[auth]\nkey = \"key.pem\"\ntrust = \"trust.cose\"\n[link]\nport = 13000\nendpoints = [{serial = \"0\", family = \"ip4\"}]\n[dial]\nall = true\n"
	if err := os.WriteFile(configPath, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"show", "verify", "sign"} {
		for _, source := range []struct {
			name string
			args []string
			want string
		}{
			{"absent", nil, "--authority or --config"},
			{"empty configuration", []string{"--config", configPath}, "no authority key"},
			{"invalid key", []string{"--authority", "not base64"}, "invalid --authority key"},
		} {
			t.Run(verb+"/"+source.name, func(t *testing.T) {
				fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
				if err != nil {
					t.Fatal(err)
				}
				defer syscall.Close(fd)
				if _, err := syscall.InotifyAddWatch(fd, path, syscall.IN_OPEN); err != nil {
					t.Fatal(err)
				}
				args := []string{"trust", verb}
				if verb == "sign" {
					args = append(args, "--key", "absent.pem", "--previous", path, "--out", "absent.cose")
				}
				args = append(args, source.args...)
				if verb == "sign" {
					args = append(args, "absent.json")
				} else {
					args = append(args, path)
				}
				out, stderr, err := runTrustCommand(args...)
				if err == nil || out != "" || !strings.Contains(stderr, source.want) {
					t.Fatalf("%s returned stdout %q, stderr %q, error %v", verb, out, stderr, err)
				}
				var events [syscall.SizeofInotifyEvent]byte
				n, err := syscall.Read(fd, events[:])
				if n > 0 || err != syscall.EAGAIN {
					t.Fatalf("command opened the signed file before selecting a key: %d event bytes, error %v", n, err)
				}
			})
		}
	}
}
