// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"fmt"
	"net/netip"
)

// PathMTUError reports a send of which linux refused a datagram as larger than the path to Endpoint carries
// MTU is that path's MTU as its route held it, the largest IP packet the path carries
// the datagrams of the send within it went and the rest did not
// only linux sends with DF and refuses such a datagram, so no other platform answers one
type PathMTUError struct {
	Endpoint netip.AddrPort
	MTU      int
}

func (e *PathMTUError) Error() string {
	return fmt.Sprintf("transport: the path to %s carries IP packets of at most %d bytes", e.Endpoint, e.MTU)
}
