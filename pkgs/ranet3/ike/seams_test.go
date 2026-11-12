// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

// seamed sets each seam a hand-built Session leaves unset to the value newSession gives
func seamed(s *Session) *Session {
	made := newSession(nil, nil, RekeyTiming{}, nil, false, nil)
	if s.clock == nil {
		s.clock = made.clock
	}
	if s.dpdEvery == 0 {
		s.dpdEvery = made.dpdEvery
	}
	if s.retransmitAfter == 0 {
		s.retransmitAfter = made.retransmitAfter
	}
	if s.rekeyJitterSource == nil {
		s.rekeyJitterSource = made.rekeyJitterSource
	}
	if s.ikeRekeyNonce == nil {
		s.ikeRekeyNonce = made.ikeRekeyNonce
	}
	return s
}
