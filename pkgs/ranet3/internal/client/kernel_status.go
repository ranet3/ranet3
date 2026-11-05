// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"net/netip"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/schema"
)

// Reconciler is the route reconciler as the node reads and drives it. The
// command builds the reconciler, since it owns the kernel and this owns the
// mesh, and hands it over whole through SetReconciler. A field a test leaves
// nil reads as a node with no reconciler.
type Reconciler struct {
	// Status is its own view of its last pass, the status's and the metrics'
	Status func() control.KernelStatus
	// Enable stops and starts it, for the write path and for down and up
	Enable func(bool)
	// Table hands it a reloaded cap.table with the overlay and the prefixes cap.route announces
	Table func(kernel.Table, []schema.Prefix, []netip.Prefix) error
	// Network wakes it for a change of the host's network
	Network func(kernel.NetworkChange)
	// Endpoints wakes it for a change of the addresses the underlay sends to
	Endpoints func()
	// Rules reads the rules it derived, for the rules and route views
	Rules func() []kernel.DumpedRule
	// Lookups reads the lookups its last pass whose batch answered asked
	Lookups func() []kernel.Lookup
	// Resolvers asks systemd-resolved for the DNS servers beyond the switch's LAN, which a status read asks and a metrics scrape and debug rules do not
	Resolvers func() []kernel.LinkResolver
	// Covers reports a member of the cover its last pass left installed at a destination, for the route view
	Covers func(netip.Prefix) bool
	// Holes reports the hole its last pass cut a piece at a destination from, for the route view
	Holes func(netip.Prefix) (kernel.Hole, bool)
	// Beneath reports the longest route its last pass scoped beneath a route of the host's holding a destination, for the route view
	Beneath func(netip.Addr) (kernel.Beneath, bool)
}

// ReconcilerOf is routes as the node reads and drives it, every field set
func ReconcilerOf(routes *kernel.Reconciler) Reconciler {
	return Reconciler{
		Status:    func() control.KernelStatus { return kernelStatus(routes) },
		Enable:    routes.SetEnabled,
		Table:     routes.SetTable,
		Network:   routes.NetworkChanged,
		Endpoints: routes.EndpointsChanged,
		Rules:     routes.DerivedRules,
		Lookups:   func() []kernel.Lookup { return routes.Stats().Lookups },
		Resolvers: routes.FallbackResolvers,
		Covers:    routes.CoverInstalled,
		Holes:     routes.HoleAt,
		Beneath:   routes.BeneathAt,
	}
}

// SetReconciler hands the node the reconciler the command built, before the
// socket serves, SIGHUP reloads or Run starts. A node that starts down hands
// it its stop here, before its first pass.
func (c *Client) SetReconciler(r Reconciler) {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	c.reconciler.Store(&r)
	if r.Enable != nil && c.downSince.Load() != nil {
		r.Enable(false)
	}
}

// reconcilerNow is the reconciler SetReconciler took, the zero value before it or on a node with no cap.table
func (c *Client) reconcilerNow() Reconciler {
	if r := c.reconciler.Load(); r != nil {
		return *r
	}
	return Reconciler{}
}

// kernelStatus is the reconciler as the control surface reports it: what it
// was configured to own and what its last pass did. The configuration half
// comes from the capability the reconciler resolved rather than from the file,
// so the defaults it filled in are the ones reported.
func kernelStatus(routes *kernel.Reconciler) control.KernelStatus {
	table, stats := routes.Table(), routes.Stats()
	return control.KernelStatus{
		Enabled:   true,
		Where:     routes.Where(),
		Table:     uint32(table.ID),
		Protocol:  table.Proto,
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
		out.Fallback = &control.KernelFallback{State: string(f.State), Reason: f.Fault}
		if f.DropsRead {
			out.Fallback.Dropped = &control.FallbackDrops{Packets: f.Dropped, Bytes: f.DroppedBytes}
		}
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
