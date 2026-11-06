// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import "net/netip"

// Originate adds prefix to the set the speaker originates, see OriginateFrom
func (s *Speaker) Originate(prefix netip.Prefix) {
	s.OriginateFrom(prefix, netip.Prefix{})
}

// OriginateFrom adds dest from source to the set the speaker originates and
// hands the whole set to SetOriginated, the path a reload takes. It reads the
// set and writes it back, so it is not safe beside another writer of the set.
func (s *Speaker) OriginateFrom(dest, source netip.Prefix) {
	s.SetOriginated(append(s.Originated(), OriginatedRoute{Destination: dest, Source: source}))
}
