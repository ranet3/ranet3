// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux

package client

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// a node with an egress segment refuses to start off linux, naming the
// segment, before it makes the mesh tun
func TestEgressSegmentRefusesTheStartOffLinux(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	dir := t.TempDir()
	cfg.Link.Port = 13000
	cfg.Auth.Key = filepath.Join(dir, "key.pem")
	cfg.Auth.Trust = filepath.Join(dir, "registry.json")
	writeKey(t, cfg.Auth.Key, privateKey)
	writeRegistry(t, cfg.Auth.Trust, reg)
	egressNode(cfg, egressSegment("3fff:1:69c:8c6::3", "3fff:a::/32"))
	c, err := New(cfg, events.New())
	if err == nil {
		c.Close()
		t.Fatal("a node with an egress segment started")
	}
	for _, want := range []string{"cap.segment local 3fff:1:69c:8c6::3 delivers to egress", "which " + runtime.GOOS + " does not have"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the start was refused with %q, want it to say %q", err, want)
		}
	}
}
