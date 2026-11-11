// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (linux && !android) || (darwin && !ios)

package kernel

import (
	"net/netip"
	"slices"
	"testing"
)

// rewritingCover is the covering fake on a platform whose kernel rewrites a
// host route out of the tun at an address of the tun's, as darwin's does
type rewritingCover struct{ *coveringKernel }

func (rewritingCover) rewritesOwnRoutes() {}

// In mode 2 beside a host table whose route for an endpoint cuts the member
// 128.0.0.0/1 around it, the tun holding the endpoint's sibling /32, a mesh
// route the kernel refuses hands the members back, cut again. On a platform
// whose kernel rewrites a host route at an address of the tun's no route
// stands at that sibling on either of two passes, and the hole still names
// the endpoint but no piece there, so HoleAt answers nothing for it. On one
// that does not the piece goes in and HoleAt names its hole.
func TestHandedPieceAtAnAddressOfTheTunsGoesInOnlyWhereTheKernelKeepsIt(t *testing.T) {
	own := prefix("203.0.113.8/32")
	for _, rewrites := range []bool{false, true} {
		reconciler, table, kernel := modeCovering(t, Table{}.WithMode(&ExitMode{}), nil, append(slices.Clone(coverAddresses), own)...)
		if rewrites {
			reconciler.use(rewritingCover{kernel})
			reconciler.rules, reconciler.look = nil, nil
		}
		reconciler.rt.Underlay = func() []netip.Addr { return []netip.Addr{halfEndpoint} }
		reconciler.rt.Selection = newFakeSelection(
			hostRoute{destination: prefix("0.0.0.0/1"), index: 2},
			hostRoute{destination: prefix("0.0.0.0/0"), index: 3},
		)
		refused := Route{Destination: prefix("198.51.100.0/24")}
		table.Set(netip.Prefix{}, refused.Destination, nil)
		kernel.failAdd[refused] = errRouteSkipped
		for pass := range 2 {
			if err := reconciler.reconcile(); err != nil {
				t.Fatalf("rewritten %v, pass %d: %v", rewrites, pass, err)
			}
			if at := routesAt(kernel.fakeKernel, own.String()); (len(at) > 0) == rewrites {
				t.Errorf("rewritten %v, pass %d: the kernel holds %v at the tun's %s: %v", rewrites, pass, at, own, kernel.snapshot())
			}
			if _, holed := reconciler.HoleAt(own); holed == rewrites {
				t.Errorf("rewritten %v, pass %d: HoleAt(%s) answers %v, want %v: %+v", rewrites, pass, own, holed, !rewrites, reconciler.Stats().Holes)
			}
			if !slices.ContainsFunc(reconciler.Stats().Holes, func(hole Hole) bool { return slices.Contains(hole.Endpoints, halfEndpoint) }) {
				t.Errorf("rewritten %v, pass %d: no hole names %s: %+v", rewrites, pass, halfEndpoint, reconciler.Stats().Holes)
			}
		}
	}
}
