// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"encoding/binary"
	"encoding/hex"
	"log/slog"
)

// invalidSPINotify tells the peer of ESP that came on spi, which no Child SA of this node holds
// RFC 7296 section 1.5: "The Notification Data contains the SPI of the invalid packet."
// section 3.10: "Of the notifications defined in this document, the SPI is included only with INVALID_SELECTORS, REKEY_SA, and CHILD_SA_NOT_FOUND. If the SPI field is empty, this field MUST be sent as zero and MUST be ignored on receipt."
func invalidSPINotify(spi uint32) RawPayload {
	return RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_INVALID_SPI, Data: binary.BigEndian.AppendUint32(nil, spi)})}
}

// InvalidSPIReports is how many INVALID_SPI notifies the session sent its peer
func (s *Session) InvalidSPIReports() uint64 { return s.invalidSPIReports.Load() }

// logInvalidSPIs logs each INVALID_SPI notify of a request, whose data names the SPI the peer holds no Child SA for
// RFC 7296 section 2.21.4: "The recipient MUST NOT change the state of any SAs as a result"
func logInvalidSPIs(inner []RawPayload) {
	for _, p := range inner {
		if p.Type != PayloadN {
			continue
		}
		if n, err := DecodeNotify(p.Body); err == nil && n.Type == N_INVALID_SPI {
			slog.Debug("ike the peer received ESP on an SPI it holds no Child SA for", "spi", hex.EncodeToString(n.Data))
		}
	}
}
