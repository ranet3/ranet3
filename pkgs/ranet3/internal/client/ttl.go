// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"log"
	"log/slog"
)

// defaultTTL is hostDefaultTTL, which a test replaces to stand in for a host's setting
var defaultTTL = hostDefaultTTL

// ttlOf is the TTL a host's default TTL setting holds, read as value, refusing a value no TTL can carry and 0, which RFC 1812 section 4.2.2.9 has no router originate
func ttlOf(setting string, value uint64, err error) (uint8, error) {
	if err == nil && (value == 0 || value > 0xff) {
		err = fmt.Errorf("%d is no TTL a router may send", value)
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", setting, err)
	}
	return uint8(value), nil
}

// retakeTTL hands the mesh the host's default TTL again, as a reload does
// a read that fails keeps the TTL the mesh holds, and is logged and recorded as daemon.ttl
func (c *Client) retakeTTL() {
	ttl, err := defaultTTL()
	if err != nil {
		kept := c.Mesh.AnswerTTL()
		log.Printf("reload: %v, so ICMPv4 errors keep the TTL %d", err, kept)
		c.events.Emit("daemon.ttl", "", slog.Int("ttl", int(kept)), slog.String("err", err.Error()))
		return
	}
	c.Mesh.SetAnswerTTL(ttl)
}
