// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package netnstest

import (
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// the refusal of a namespace that holds a route is the only such check of the root tests that enter through EnterEmpty
// a loopback that is up holds the local routes of 127.0.0.1 and ::1, so a namespace with a route is one the refusal must see
func TestRouteRefusalSeesTheRoutesOfALoopbackThatIsUp(t *testing.T) {
	EnterEmpty(t)
	err := holdsNoRoute()
	if err == nil || !strings.Contains(err.Error(), "already holds routes") {
		t.Fatalf("a namespace whose loopback is up was answered %v, want the refusal for a held route", err)
	}
}

// an unreachable route needs no link, so a namespace with every link down and no address can still hold one
// the process's own namespace is taken only when it holds none
func TestClaimProcessRefusesANamespaceThatHoldsARoute(t *testing.T) {
	EnterEmptyLoopbackDown(t)
	netlink, err := OpenNetlink()
	if err != nil {
		t.Fatal(err)
	}
	defer netlink.Close()
	header := []byte{unix.AF_INET, 24, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNREACHABLE, 0, 0, 0, 0}
	body := slices.Concat(header, Attr(unix.RTA_DST, []byte{192, 0, 2, 0}))
	if err := netlink.Request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, body); err != nil {
		t.Fatalf("add an unreachable route: %v", err)
	}
	_, err = ClaimProcess()
	if err == nil || !strings.Contains(err.Error(), "already holds routes") {
		t.Fatalf("a namespace holding a route was answered %v, want the refusal for a held route", err)
	}
}
