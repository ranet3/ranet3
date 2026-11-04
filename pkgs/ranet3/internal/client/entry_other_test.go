// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package client

import (
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// a cap.route announcement that counts as a default is refused at the start and at a reload, naming the prefix and the platform,
// and a refused reload keeps the announcements in force
func TestCountedAnnouncementIsRefusedHereAtTheStartAndAtReload(t *testing.T) {
	cfg, privateKey, reg := runtimeFixture(t)
	cfg.Cap.Route = &babel.Routes{Announce: announce("::/0")}
	err := validateRuntimeConfig(cfg, privateKey, trust(t, reg))
	for _, want := range []string{"cap.route announces ::/0", runtime.GOOS, "carries no exit"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the start refused announcing ::/0 with %v, which does not name %q", err, want)
		}
	}

	c, path, _, _ := reloadOf(t, func(*config.Config) {})
	before := c.config().Cap.Route
	next := *c.config()
	next.Cap.Route = &babel.Routes{Announce: announce("fd00::/8")}
	writeConfig(t, path, &next)
	err = c.ReloadFrom(path)
	for _, want := range []string{"cap.route announces fd00::/8", runtime.GOOS, "carries no exit"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("a reload announcing fd00::/8 was refused with %v, which does not name %q", err, want)
		}
	}
	if c.config().Cap.Route != before {
		t.Errorf("a refused reload put cap.route %+v in force", c.config().Cap.Route)
	}
}
