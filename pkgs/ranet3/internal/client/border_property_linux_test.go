// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"os"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// readinessMoves is the longest run of readiness moves one case makes
const readinessMoves = 8

// Over a run of the translator's words and the border's readiness, handed over
// in any order, the mesh writes into a real egress device each family the
// translator holds ready while the border's chain reads back, and the SID's
// /128 is originated exactly while the translator serves the SIDs and the
// border's chain reads back
func TestTUNEgressFollowsTheTranslatorOnlyWhileTheBorderReadsBack(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("creating a tun needs root on linux")
	}
	sid := labSID.String()
	c, _, _, bus := reloadOf(t, func(cfg *config.Config) { egressNode(cfg, egressSegment(sid, labLeaves...)) })
	carried := meshCarrying(t, c)
	speakerRecording(t, c, bus)
	pbt.Check(t, func(ht *hegel.T) {
		border := hegel.Draw(ht, hegel.Booleans())
		v4, v6, serves := hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
		c.SetBorderReady(border)
		c.SetEgressReady(v4, v6, serves)
		for range hegel.Draw(ht, pbt.Spanning(1, readinessMoves)) {
			if hegel.Draw(ht, hegel.Booleans()) {
				border = hegel.Draw(ht, hegel.Booleans())
				c.SetBorderReady(border)
			} else {
				v4, v6, serves = hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans()), hegel.Draw(ht, hegel.Booleans())
				c.SetEgressReady(v4, v6, serves)
			}
			if got := carried(); got != [2]bool{v4 && border, v6 && border} {
				ht.Fatalf("with the translator holding %v %v and the border ready %v the mesh carries %v", v4, v6, border, got)
			}
			if got := sidOriginated(c, sid); got != (serves && border) {
				ht.Fatalf("with the translator serving %v and the border ready %v the SID's /128 is originated %v", serves, border, got)
			}
		}
	})
}
