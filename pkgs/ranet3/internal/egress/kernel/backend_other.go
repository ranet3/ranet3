// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"fmt"
	"runtime"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// newBackend refuses the capability by name where there is nothing to install
// it with. It is a refusal rather than a stub that does nothing, for the same
// reason internal/kernel refuses a policy rule on darwin: a node that accepted
// the configuration and translated nothing would come up with a working mesh,
// advertise itself as an exit, and drop every flow that took it.
//
// iOS and android have no packet filter a process may write at all, and a
// phone has to use an exit node rather than be one.
func newBackend(cfg egress.Egress, rt Runtime) (backend, error) {
	return nil, refuseWhatThisPlatformLacks(cfg, rt)
}

// refuseWhatThisPlatformLacks is the refusal on its own, so that a capability
// translating nothing is not refused for a facility it never named. New
// refuses such a capability before this, so the nil backend that arm hands
// back reaches no caller.
func refuseWhatThisPlatformLacks(cfg egress.Egress, rt Runtime) error {
	if len(cfg.Translated(rt.Steered)) == 0 {
		return nil
	}
	return fmt.Errorf("%w: cap.egress asks this node to translate a source address, and nftables is a linux facility", egress.ErrUnsupported)
}

// errNoBorder refuses cap.border by name, as newBackend refuses cap.egress: a
// node that accepted the block and filtered nothing would carry forged mesh
// sources from its other links while its status said otherwise.
var errNoBorder = fmt.Errorf("egress: cap.border is an nftables chain, which %s does not have, so this node cannot filter what enters the mesh from its other links", runtime.GOOS)

func newBorderBackend() (borderBackend, error) { return nil, errNoBorder }
