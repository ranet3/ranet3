// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// KernelStatus is the reconciler as the control surface reports it: what it
// was configured to own and what its last pass did. The configuration half
// comes from the capability the reconciler resolved rather than from the file,
// so the defaults it filled in are the ones reported. The command hands it to
// SetKernelStatus, and the root labs hand it the same way.
func KernelStatus(routes *kernel.Reconciler) control.KernelStatus {
	table, stats := routes.Table(), routes.Stats()
	return control.KernelStatus{
		Enabled:   true,
		Where:     routes.Where(),
		Table:     uint32(table.ID),
		Protocol:  table.Proto,
		Metric:    table.Metric,
		PassAt:    stats.At,
		Installed: stats.Installed,
		Skipped:   stats.Skipped,
		Added:     stats.Added,
		Removed:   stats.Removed,
		Cover:     familyNames(stats.Cover),
		Exit:      kernelExit(stats.Exit),
		ExitPath:  kernelExitPath(stats.Path),
		Err:       stats.Err,
	}
}

// kernelExit is cap.exit's mode as the control surface reports it, nil in mode off
func kernelExit(exit *kernel.ExitStatus) *control.KernelExit {
	if exit == nil {
		return nil
	}
	out := &control.KernelExit{Forwarded: exit.Forwarded, Unaddressed: familyNames(exit.Unaddressed)}
	for _, skip := range exit.Skipped {
		out.Skipped = append(out.Skipped, control.KernelSkip{Entry: skip.Entry, Link: skip.Link, Reason: skip.Reason})
	}
	if f := exit.Fallback; f != nil {
		out.Fallback = &control.KernelFallback{State: string(f.State), Reason: f.Fault, Dropped: f.Dropped, DroppedBytes: f.DroppedBytes}
		for _, network := range f.Captured {
			out.Fallback.Captured = append(out.Fallback.Captured, network.String())
		}
		for _, network := range f.Public {
			out.Fallback.Public = append(out.Fallback.Public, network.String())
		}
	}
	return out
}

// kernelExitPath is cap.exit via's path as the control surface reports it,
// nil outside mode 3, its counts left for kernel, which reads the dataplane
func kernelExitPath(path *kernel.PathStatus) *control.KernelExitPath {
	if path == nil {
		return nil
	}
	out := &control.KernelExitPath{Source: path.Source.String(), State: "up", Installed: familyNames(path.Installed)}
	for _, sid := range path.Via {
		out.Via = append(out.Via, sid.String())
	}
	if path.Down.IsValid() {
		out.State, out.Down, out.Verdict = "down", path.Down.String(), path.Verdict
	}
	return out
}

func familyNames(families []kernel.Family) []string {
	var names []string
	for _, family := range families {
		names = append(names, string(family))
	}
	return names
}
