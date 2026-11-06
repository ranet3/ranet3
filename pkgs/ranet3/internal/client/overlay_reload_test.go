// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"slices"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/config"
)

// A reload adding a link-local prefix to the overlay is refused by the loader,
// naming the prefix, before anything applies, so the overlay in force stays
// with the node, its kernel runtime and its reconciler
func TestReloadRefusesALinkLocalOverlayPrefix(t *testing.T) {
	for _, added := range []string{"169.254.0.0/16", "fe80::/16"} {
		t.Run(added, func(t *testing.T) {
			running := overlayOf("3fff::/20")
			c, path, reconciler, bus := reloadOf(t, func(cfg *config.Config) { cfg.Overlay = running })
			next := *c.config()
			next.Overlay = overlayOf("3fff::/20", added)
			writeConfig(t, path, &next)
			err := c.ReloadFrom(path)
			want := "egress: overlay " + added + " holds link-local addresses"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("the reload was answered %v, want %q", err, want)
			}
			if got := c.config().Overlay; !slices.Equal(got, running) {
				t.Errorf("the refused reload left the overlay %v, want %v", got, running)
			}
			if got := c.KernelRuntime().Overlay; !slices.Equal(got, running) {
				t.Errorf("the refused reload left the kernel the overlay %v, want %v", got, running)
			}
			if len(reconciler.tables) != 0 || len(reconciler.overlays) != 0 {
				t.Errorf("the refused reload handed the reconciler %v", reconciler.overlays)
			}
			if got := lastReload(t, bus)["err"]; got != err.Error() {
				t.Errorf("daemon.reload carried %q, want %q", got, err)
			}
		})
	}
}
