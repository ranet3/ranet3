// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package kernel

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

// The capability is refused by name where there is no packet filter to write
// into, rather than accepted and quietly doing nothing. A node that came up as
// an exit and translated nothing would advertise itself and then drop every
// flow that took it, which is the failure internal/kernel refuses a policy
// rule on darwin to avoid.
func TestUnsupportedPlatformRefusesTheCapabilityByName(t *testing.T) {
	cfg := egress.Egress{Advertise: []schema.Prefix{schema.MustPrefix("0.0.0.0/0")}}
	forwarding := func() (bool, bool) { return true, true }
	lookup := func([]Lookup) ([]Answer, error) { return nil, nil }
	sysctl := func(string) string { return "" }
	_, err := New(cfg, Runtime{Interface: "ranet0", Forwarding: forwarding, Lookup: lookup, Sysctl: sysctl})
	if !errors.Is(err, egress.ErrUnsupported) {
		t.Fatalf("New returned %v, want the unsupported sentinel", err)
	}
	if !strings.Contains(err.Error(), "cap.egress") {
		t.Errorf("the refusal %q does not name the capability that asked for it", err)
	}
	if !strings.Contains(err.Error(), "nftables") {
		t.Errorf("the refusal %q does not say what is missing", err)
	}
	// an exit advertising nothing still asks to translate what its egress segment carries
	_, err = New(egress.Egress{}, Runtime{Interface: "utun9", Steered: true, Forwarding: forwarding, Lookup: lookup, Sysctl: sysctl})
	if !errors.Is(err, egress.ErrUnsupported) {
		t.Errorf("New returned %v for an exit advertising nothing, want the unsupported sentinel", err)
	}
}

// cap.border is refused by name where there is no nftables, rather than
// accepted with no chain behind it, since a node whose status read the
// border as written would carry forged mesh sources from its other links
func TestBorderIsRefusedOffLinux(t *testing.T) {
	f, err := NewBorderFilter(egress.Border{Overlay: []schema.Prefix{schema.MustPrefix("198.18.0.0/15")}}, egress.BorderRuntime{Inside: []string{"utun9", "lo0"}})
	want := "egress: cap.border is an nftables chain, which " + runtime.GOOS + " does not have"
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("NewBorderFilter returned %v, want a refusal containing %q", err, want)
	}
	if f != nil {
		t.Error("the refusal handed back a filter")
	}
}
