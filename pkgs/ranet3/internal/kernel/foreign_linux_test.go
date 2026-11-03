// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"maps"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// routeReply builds one RTM_NEWROUTE the way a dump delivers it. The table
// goes in the byte when it fits and in RTA_TABLE when it does not, which is
// the same split the kernel makes.
func routeReply(table uint32, protocol, kind uint8) nlMessage {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET
	if table <= 255 {
		body[4] = uint8(table)
	}
	body[5] = protocol
	body[7] = kind
	body = putAttrU32(body, unix.RTA_TABLE, table)
	return nlMessage{Kind: unix.RTM_NEWROUTE, Data: body}
}

// The report exists because an install asks for its key exclusively, so a
// second writer in one table leaves the routes it holds uninstalled, and
// nothing else says so before the first refusal.
func TestForeignWritersReportsOnlyOurOwnTable(t *testing.T) {
	const ours = DefaultProtocol
	for name, test := range map[string]struct {
		replies []nlMessage
		want    []uint8
	}{
		"another protocol in our table": {
			replies: []nlMessage{routeReply(200, unix.RTPROT_BIRD, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_BIRD},
		},
		"our own routes are not foreign": {
			replies: []nlMessage{routeReply(200, ours, unix.RTN_UNICAST)},
		},
		"a route that is not unicast is not a writer": {
			replies: []nlMessage{routeReply(200, unix.RTPROT_BIRD, unix.RTN_LOCAL)},
		},
		"the kernel's own routes in our table are a writer": {
			replies: []nlMessage{routeReply(200, unix.RTPROT_KERNEL, unix.RTN_UNICAST)},
			want:    []uint8{unix.RTPROT_KERNEL},
		},
	} {
		t.Run(name, func(t *testing.T) {
			seen := map[uint8]bool{}
			collectForeignWriters(test.replies, ours, seen)
			got := slices.Sorted(maps.Keys(seen))
			if !slices.Equal(got, test.want) {
				t.Errorf("reported %v, want %v", got, test.want)
			}
		})
	}
}
