// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package client

import "testing"

// a setting the kernel does not answer for is neither on nor off, and each family's setting is one it answers for
func TestForwardingSettingThatCannotBeReadIsUnknown(t *testing.T) {
	if got := onOffUnread(sysctlIsOne("net.inet.ip.no_such_setting")); got != "unread" {
		t.Errorf("a setting the kernel does not name is read as %s, want it unread", got)
	}
	if v4, v6 := forwardingEnabled(); v4 == nil || v6 == nil {
		t.Errorf("this host's forwarding is read as %s and %s, want both read", onOffUnread(v4), onOffUnread(v6))
	}
}
