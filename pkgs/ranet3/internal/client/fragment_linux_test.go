// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/netstack"
)

// the fragments of a Babel packet alpha's stack cut reach bravo's speaker, which reads the packet whole, and never bravo's tun
// a fragment of ordinary traffic to an address of bravo's, sent over the same session after them, reaches the tun as alpha sent it
// alpha hands each fragment straight to its session, and a capture on bravo's tun reads every packet the mesh writes into it
func TestTUNTakesFragmentsOfOrdinaryTrafficAndNoneOfABabelPacket(t *testing.T) {
	enterEmptyNamespace(t)
	mesh, err := netstack.NewNamed(0, "babelfrag0", nil)
	if err != nil {
		t.Fatalf("open bravo's mesh: %v", err)
	}
	t.Cleanup(mesh.Close)
	capture := captureInbound(t, mesh.Name)
	alpha, bravo := newLoopbackMeshOn(t, mesh)
	run(t, alpha, bravo)
	var peer *netstack.Peer
	waitFor(t, convergeBudget, "alpha forwarding to bravo's prefix", func() bool {
		found, verdict := alpha.client.Mesh.Routes.Resolve(netip.Addr{}, bravo.prefix.Addr().Next())
		peer = found
		return verdict == netstack.RoutePeer && found != nil
	})
	// alpha's speaker as bravo's heard it, which the Babel packet comes from so that bravo's view of alpha stays as it is
	var from netip.Addr
	waitFor(t, convergeBudget, "bravo hearing alpha's speaker", func() bool {
		if neighbors := bravo.client.speaker.Stats().Neighbors; len(neighbors) == 1 {
			from = neighbors[0].Addr
		}
		return from.IsLinkLocalUnicast()
	})
	ordinary := udpPacket(alpha.prefix.Addr().Next(), bravo.prefix.Addr().Next(), 40000, 9, make([]byte, 1435))
	buf := make([]byte, 1<<16)
	deadline := time.Now().Add(convergeBudget)
	for id := uint32(1); time.Now().Before(deadline); id++ {
		cut := fragmentsOf(ordinary, id, 1336)
		for _, f := range slices.Concat(fragmentsOf(babelFrom(from, 1443), id, 1336), cut) {
			place, err := peer.ReserveRawOrDrop(bytes.Clone(f), esp.NextHeaderIPv6)
			if err != nil {
				t.Fatalf("hand a fragment to the session: %v", err)
			}
			if err := place.Send(); err != nil {
				t.Fatalf("send a fragment: %v", err)
			}
		}
		arrived := 0
		for {
			n, _, err := unix.Recvfrom(capture, buf, 0)
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				t.Fatalf("read the capture: %v", err)
			}
			got := buf[:n]
			if n >= 40 && got[0]>>4 == 6 && netip.AddrFrom16([16]byte(got[24:40])) == babelGroup {
				t.Fatalf("a packet to the Babel group reached bravo's tun, its headers reading %x", got[:min(n, 48)])
			}
			if slices.ContainsFunc(cut, func(f []byte) bool { return bytes.Equal(got, f) }) {
				arrived++
			}
		}
		if arrived == len(cut) && bravo.client.speaker.Stats().Neighbors[0].Fragments.Read > 0 {
			return
		}
	}
	t.Fatalf("within %s no try brought both fragments of ordinary traffic to the tun with bravo's speaker reading a Babel packet put back together, which read %+v",
		convergeBudget, bravo.client.speaker.Stats().Neighbors[0].Fragments)
}
