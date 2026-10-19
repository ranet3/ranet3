// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"net/netip"
	"syscall"
	"testing"
)

// A pair no platform can look up is refused before the platform is asked, so
// the error is neither a kernel's errno nor a platform's refusal
func TestRouteGetRefusesAPairNoPlatformLooksUp(t *testing.T) {
	for _, c := range []struct {
		name     string
		src, dst netip.Addr
	}{
		{"an invalid destination", netip.Addr{}, netip.Addr{}},
		{"an IPv4 destination from an IPv6 source", netip.MustParseAddr("3fff:a:1::1"), netip.MustParseAddr("192.0.2.1")},
		{"an IPv6 destination from an IPv4 source", netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("3fff:a:1::1")},
		{"a zoned destination", netip.Addr{}, netip.MustParseAddr("fe80::1%lo")},
	} {
		var errno syscall.Errno
		got, err := RouteGet(c.src, c.dst, "")
		if err == nil || errors.As(err, &errno) || errors.Is(err, ErrUnsupported) {
			t.Errorf("%s answered %+v and %v, want a refusal of the pair", c.name, got, err)
		}
	}
}
