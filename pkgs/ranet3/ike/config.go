// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"fmt"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/schema"
)

// Crypto is the cap.crypto capability as the file writes it
// it holds how long a key lives, how far out of order a packet may arrive and which transforms a session negotiates
// every value reaches a session this package builds, the replay window included
// both ends capture the window when the Child SA is set up
// an explicit zero turns a rekey off and an absent timing takes the default
// so each timing is a pointer
// an empty list is refused and an absent one runs the defaults
// so a list needs no pointer
type Crypto struct {
	// Replay is the ESP receive window in packets, esp.DefaultReplayWindow when omitted
	// an explicit 0 turns replay checking off
	// the default is wider than the interoperable minimum
	// a multicore sender reorders bursts by more than 32 before they reach userspace
	Replay *uint32   `yaml:"replay,omitempty" json:"replay,omitempty" toml:"replay,omitempty"`
	Rekey  Rekey     `yaml:"rekey,omitempty" json:"rekey,omitzero" toml:"rekey,omitempty"`
	IKE    IKESuites `yaml:"ike,omitempty" json:"ike,omitzero" toml:"ike,omitempty"`
	ESP    ESPSuites `yaml:"esp,omitempty" json:"esp,omitzero" toml:"esp,omitempty"`
}

// Rekey is when a key is replaced. A rekey runs before its interval expires:
// Margin is always subtracted and Jitter is independently randomized from zero
// through its value, so a fleet does not rekey in lockstep.
type Rekey struct {
	Child  *schema.Duration `yaml:"child,omitempty" json:"child,omitempty" toml:"child,omitempty"`
	IKE    *schema.Duration `yaml:"ike,omitempty" json:"ike,omitempty" toml:"ike,omitempty"`
	Margin *schema.Duration `yaml:"margin,omitempty" json:"margin,omitempty" toml:"margin,omitempty"`
	Jitter *schema.Duration `yaml:"jitter,omitempty" json:"jitter,omitempty" toml:"jitter,omitempty"`
	Retry  Retry            `yaml:"retry,omitempty" json:"retry,omitzero" toml:"retry,omitempty"`
}

// Retry is the capped exponential backoff after a rekey fails, which for the
// Child SA holds back the next exchange whichever path asks for it.
type Retry struct {
	First *schema.Duration `yaml:"first,omitempty" json:"first,omitempty" toml:"first,omitempty"`
	Max   *schema.Duration `yaml:"max,omitempty" json:"max,omitempty" toml:"max,omitempty"`
}

func (c Crypto) ReplayWindow() uint32 {
	if c.Replay == nil {
		return esp.DefaultReplayWindow
	}
	return *c.Replay
}

func (c Crypto) ChildInterval() time.Duration { return interval(c.Rekey.Child, DefaultChildRekey) }
func (c Crypto) IKEInterval() time.Duration   { return interval(c.Rekey.IKE, DefaultIKERekey) }
func (c Crypto) Margin() time.Duration        { return interval(c.Rekey.Margin, DefaultRekeyMargin) }
func (c Crypto) Jitter() time.Duration        { return interval(c.Rekey.Jitter, DefaultRekeyJitter) }
func (c Crypto) RetryFirst() time.Duration    { return interval(c.Rekey.Retry.First, DefaultRetryFirst) }
func (c Crypto) RetryMax() time.Duration      { return interval(c.Rekey.Retry.Max, DefaultRetryMax) }

func interval(configured *schema.Duration, fallback time.Duration) time.Duration {
	if configured == nil {
		return fallback
	}
	return configured.Duration()
}

// Validate refuses timings and lists a session could not run, naming the field as the operator wrote it
func (c Crypto) Validate() error {
	if c.Replay != nil && *c.Replay > esp.MaxReplayWindow {
		return fmt.Errorf("ike: cap.crypto replay must not exceed %d", esp.MaxReplayWindow)
	}
	for _, named := range []struct {
		name     string
		value    *schema.Duration
		positive bool
	}{
		{name: "rekey child", value: c.Rekey.Child},
		{name: "rekey ike", value: c.Rekey.IKE},
		{name: "rekey margin", value: c.Rekey.Margin},
		{name: "rekey jitter", value: c.Rekey.Jitter},
		{name: "rekey retry first", value: c.Rekey.Retry.First, positive: true},
		{name: "rekey retry max", value: c.Rekey.Retry.Max, positive: true},
	} {
		if named.value == nil {
			continue
		}
		if named.positive && named.value.Duration() <= 0 {
			return fmt.Errorf("ike: cap.crypto %s must be positive when set", named.name)
		}
		if named.value.Duration() < 0 {
			return fmt.Errorf("ike: cap.crypto %s must be nonnegative when set", named.name)
		}
	}
	if c.RetryFirst() > c.RetryMax() {
		return fmt.Errorf("ike: cap.crypto rekey retry first must not exceed retry max")
	}
	// a rekey runs at interval less margin less jitter
	// a disabled interval runs none
	for _, named := range []struct {
		name     string
		interval time.Duration
	}{{"child", c.ChildInterval()}, {"ike", c.IKEInterval()}} {
		interval := named.interval
		if interval == 0 {
			continue
		}
		if c.Margin() == 0 {
			return fmt.Errorf("ike: cap.crypto rekey margin must be positive beside rekey %s, since a rekey due at the end of the SA's lifetime can never replace it", named.name)
		}
		if !(c.Margin() < interval && c.Jitter() < interval-c.Margin()) {
			return fmt.Errorf("ike: cap.crypto rekey margin plus jitter must be less than rekey %s", named.name)
		}
	}
	_, err := c.Suites()
	return err
}
