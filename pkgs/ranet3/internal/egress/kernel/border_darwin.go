// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"log/slog"
	"path/filepath"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pf"
)

// newBorderBackend takes a reference on pf where overlay is written, which
// enables pf for the whole host, recording it in the state directory, and
// writes into pfAnchor. Where overlay is not written it opens no backend and
// gives back the anchor and the references an earlier run recorded, so a
// start without overlay takes over what a crash or the mesh's failure left.
func newBorderBackend(cfg *egress.Border, rt egress.BorderRuntime) (borderBackend, error) {
	if rt.StateDir == "" {
		return nil, errors.New("egress: the antispoof filter on pf records its reference in the state directory, and none is named")
	}
	ctl := pf.NewCtl()
	record := filepath.Join(rt.StateDir, pfRecord)
	if !Filters(cfg) {
		gaveBack, err := pf.Clear(ctl, record, pfAnchor)
		if gaveBack && err == nil {
			slog.Info("antispoof filter gave back the pf anchor and reference an earlier run left, since overlay is not written", "where", "pf anchor "+pfAnchor)
		}
		return nil, err
	}
	ref, err := pf.Take(ctl, record)
	if err != nil {
		return nil, err
	}
	return &borderPF{ctl: ctl, ref: ref, anchor: pfAnchor, tun: rt.Tun, inside: rt.Inside, events: rt.Events, every: pfSweep}, nil
}

// Filters reports whether the filter runs for cfg, nil where overlay is not
// written. pf filters for the whole host once enabled, so it runs only where
// overlay is written.
func Filters(cfg *egress.Border) bool { return cfg != nil }

// RefuseBorder refuses, where the filter runs for cfg, an exemption's exact
// interface name the anchor cannot write
func RefuseBorder(cfg *egress.Border) error {
	if !Filters(cfg) {
		return nil
	}
	return refuseUnwritable(cfg)
}
