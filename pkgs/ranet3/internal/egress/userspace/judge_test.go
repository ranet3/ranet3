// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"net/netip"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// Over any bytes a session may hand the exit, the judgment never reads past
// them, answers time exceeded only where the TTL or hop limit is 1 or less,
// and delivers only a whole packet with a TTL or hop limit left toward a
// destination the host does not hold, or a UDP datagram toward one the host
// holds, which the relay judges by its port
func FuzzJudge(f *testing.F) {
	for _, c := range []judgeCase{
		{ipv4: true, ttl: 64, protocol: 6},
		{ipv4: true, ttl: 1, protocol: 17},
		{ipv4: true, ttl: 64, protocol: protoUncarried, fragment: 2},
		{ttl: 64, protocol: 58, destination: 1},
		{ttl: 64, protocol: 17, fragment: 2, extensions: []byte{0, 60}},
		{ttl: 64, protocol: 6, extensions: []byte{43}, segmentsLeft: 1},
		{ttl: 64, protocol: 17, fragment: 1, afterFragment: 60},
	} {
		f.Add(c.bytes())
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		j := judge(raw, heldByHost)
		if j.act == drop {
			return
		}
		var ttl, protocol byte
		var destination netip.Addr
		switch raw[0] >> 4 {
		case 4:
			ttl, protocol, destination = raw[8], raw[9], netip.AddrFrom4([4]byte(raw[16:20]))
		case 6:
			ttl, destination = raw[7], netip.AddrFrom16([16]byte(raw[24:40]))
			protocol, _ = upperLayer6(raw)
		default:
			t.Fatalf("judged %+v a packet of version %d", j, raw[0]>>4)
		}
		switch {
		case j.act == answer && j.kind == netstack.ExitExpired && ttl > 1:
			t.Fatalf("answered expired with %d left", ttl)
		case j.act == deliver && ttl <= 1:
			t.Fatalf("delivered with %d left", ttl)
		case j.act == deliver && (heldByHost(destination) && protocol != protoUDP || unservable(destination)):
			t.Fatalf("delivered protocol %d toward %s", protocol, destination)
		}
	})
}
