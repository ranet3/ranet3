// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"fmt"
	"net/netip"
)

// PathMTUError reports a send of which linux refused a datagram as larger than the path to Endpoint carries
// MTU is that path's MTU as its route held it, the largest IP packet the path carries
// a send that answers it bare sent every datagram no longer than Largest and refused the longer ones
// but for any that went ahead of the refusal on a path that narrowed while the send ran
// a send that answers it wrapped with another error lost more than that
// only linux sends with DF and refuses such a datagram, so no other platform answers one
type PathMTUError struct {
	Endpoint netip.AddrPort
	MTU      int
}

func (e *PathMTUError) Error() string {
	return fmt.Sprintf("transport: the path to %s carries IP packets of at most %d bytes", e.Endpoint, e.MTU)
}

// Largest is the longest datagram the path carries, after an outer IP header without options and the UDP header
func (e *PathMTUError) Largest() int {
	if e.Endpoint.Addr().Is4() {
		return e.MTU - 20 - 8
	}
	return e.MTU - 40 - 8
}
