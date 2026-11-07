// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"fmt"
	"log/slog"
)

// defaultTTL is hostDefaultTTL, which a test replaces to stand in for a host's setting
var defaultTTL = hostDefaultTTL

// defaultHopLimit is hostDefaultHopLimit, which a test replaces to stand in for a host's setting
var defaultHopLimit = hostDefaultHopLimit

// hopLimited is an exit that builds packets of its own, which carry the TTL and the hop limit it holds
type hopLimited interface {
	SetHopLimits(ttl, hopLimit uint8)
	HopLimits() (ttl, hopLimit uint8)
}

// ttlOf is the TTL a host's default TTL setting holds, read as value, refusing a value no TTL can carry and 0, which RFC 1812 section 4.2.2.9 has no router originate
func ttlOf(setting string, value uint64, err error) (uint8, error) {
	if err != nil {
		return 0, fmt.Errorf("%s: %w", setting, err)
	}
	if value == 0 || value > 0xff {
		return 0, fmt.Errorf("%s: %d is no TTL a router may send", setting, value)
	}
	return uint8(value), nil
}

// retakeTTL hands the mesh the host's default TTL again, and an exit that builds packets of its own that TTL and the host's default hop limit, as a reload does
// a read that fails keeps the TTL the mesh holds, and is logged and recorded as daemon.ttl
func (c *Client) retakeTTL() {
	if ttl, err := defaultTTL(); err != nil {
		kept := c.Mesh.AnswerTTL()
		slog.Warn(fmt.Sprintf("reload: %v, so ICMPv4 errors keep the TTL %d", err, kept))
		c.events.Emit("daemon.ttl", "", slog.Int("ttl", int(kept)), slog.String("err", err.Error()))
	} else {
		c.Mesh.SetAnswerTTL(ttl)
	}
	if exit := c.exit.Load(); exit != nil {
		if limited, ok := (*exit).(hopLimited); ok {
			c.handHopLimits(limited)
		}
	}
}

// handHopLimits hands exit the TTL the mesh holds and the host's default hop limit
// a read of the hop limit that fails keeps the one exit holds, and is logged and recorded as daemon.ttl
func (c *Client) handHopLimits(exit hopLimited) {
	_, hopLimit := exit.HopLimits()
	if read, err := defaultHopLimit(); err != nil {
		slog.Warn(fmt.Sprintf("%v, so the exit's IPv6 packets keep the hop limit %d", err, hopLimit))
		c.events.Emit("daemon.ttl", "", slog.Int("hop_limit", int(hopLimit)), slog.String("err", err.Error()))
	} else {
		hopLimit = read
	}
	exit.SetHopLimits(c.Mesh.AnswerTTL(), hopLimit)
}
