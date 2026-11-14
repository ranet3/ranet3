// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import "fmt"

// PathMTUError reports a send of which the host refused a datagram as larger than the path to Endpoint carries
// Endpoint is the endpoint the send was handed, which a mux that moved since no longer sends to
// MTU is that path's MTU as the host's route held it, the largest IP packet the path carries
// a send that answers it bare sent every datagram no longer than Largest and refused the longer ones
// but for any that went ahead of the refusal on a path that narrowed while the send ran
// a send that answers it wrapped with another error lost more than that
// linux refuses past the route's path MTU and darwin past the interface's MTU
type PathMTUError struct {
	Endpoint Endpoint
	MTU      int
}

func (e *PathMTUError) Error() string {
	return fmt.Sprintf("transport: the path to %s carries IP packets of at most %d bytes", e.Endpoint, e.MTU)
}

// Largest is the longest datagram the path carries, after an outer IP header without options and the UDP header
func (e *PathMTUError) Largest() int {
	if e.Endpoint.AddrPort().Addr().Is4() {
		return e.MTU - 20 - 8
	}
	return e.MTU - 40 - 8
}

// PathMTU reads the MTU the host holds for the path to the mux's endpoint, the largest IP packet a send may carry
func (m *Mux) PathMTU() (int, error) {
	return m.hub.bind.readPathMTU(m.Endpoint())
}

// Fragment lets the host fragment sends to the mux's endpoint past the path MTU, or stops that
// it is for a path too narrow to carry the IPv6 minimum MTU in one datagram
// linux fragments every send of the endpoint's family while any mux asks, and so does darwin for IPv4
// darwin fragments IPv6 sends to that endpoint alone
// it stays with the endpoint it was set for, and a call after the mux moved hands it to the new one
func (m *Mux) Fragment(on bool) error {
	bind := m.hub.bind
	m.fragmentMu.Lock()
	defer m.fragmentMu.Unlock()
	moved := false
	defer func() {
		if moved {
			m.hub.followFragmenting()
		}
	}()
	// a closed mux takes nothing, so Close leaves no family fragmenting behind it
	endpoint := m.Endpoint()
	on = on && !m.closed.Load()
	if m.fragmented != nil && (!on || m.fragmented != endpoint) {
		if err := bind.fragment(m.fragmented, false); err != nil {
			return err
		}
		m.fragmented, moved = nil, true
	}
	if on && m.fragmented == nil {
		if err := bind.fragment(endpoint, true); err != nil {
			return err
		}
		m.fragmented, moved = endpoint, true
	}
	return nil
}

// DontFragment reports whether sends to the mux's endpoint leave with DF now, which a probe needs to measure the path
func (m *Mux) DontFragment() bool {
	return m.hub.bind.dontFragment(m.Endpoint())
}
