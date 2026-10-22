// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package netstack

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"
)

// withheldArms are the senders BenchmarkDecideWithheld and BenchmarkICMPTake draw for, one and many of each family
var withheldArms = []struct{ family, sources int }{{4, 1}, {4, 64}, {6, 1}, {6, 4096}}

// withheldSources is count senders of family, each held in m's table with its bucket spent, and m's cap full after
// the IPv4 senders are 192.0.2.128 on, and the IPv6 ones are drawn inside 3fff::/20 by a generator of a fixed seed, so they spread as a flood of spoofed sources would
// and every run, at every tree, draws the same ones
// the cap goes back to full before each sender, since the cap withholds a draw before the sender's bucket sees it
// it fails b unless the table holds every sender once all have drawn, so no arm draws for a sender the table gave the place of
// the limit's seed is new to each process, and 4096 random senders put more than a shard's 96 in one shard in about 0.44 percent of processes
// about 0.9 percent of an arms run's two processes at the tip, so a setup that fails is chance and is run again
func withheldSources(b *testing.B, m *Mesh, family, count int) []netip.Addr {
	draw := rand.New(rand.NewPCG(4096, 6))
	seen := make(map[netip.Addr]bool, count)
	sources := make([]netip.Addr, count)
	for i := range sources {
		sources[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(128 + i)})
		for family == 6 && (!sources[i].Is6() || seen[sources[i]]) {
			var address [16]byte
			binary.BigEndian.PutUint64(address[:8], 0x3fff<<48|draw.Uint64()>>20)
			binary.BigEndian.PutUint64(address[8:], draw.Uint64())
			sources[i] = netip.AddrFrom16(address)
		}
		seen[sources[i]] = true
		refillCap(m)
		for m.takeICMPToken(sources[i]) {
		}
	}
	refillCap(m)
	for _, source := range sources {
		if !holdsSource(m, source) {
			b.Fatalf("the table does not hold %s once all %d senders have drawn", source, count)
		}
	}
	return sources
}

// BenchmarkICMPTake is the limit's draw alone at BenchmarkDecideWithheld's arms, on the mesh's clock
// each goroutine RunParallel starts drawing for every sender in turn, as each emitter of that benchmark does
// take is the limit with its counts, and takeICMPToken the draw an answer makes, which adds the withheld report
func BenchmarkICMPTake(b *testing.B) {
	for _, via := range []struct {
		name string
		draw func(m *Mesh, source netip.Addr)
	}{
		{"take", func(m *Mesh, source netip.Addr) { m.icmpLimit.take(int64(time.Since(m.segmentsStarted)), source) }},
		{"takeICMPToken", func(m *Mesh, source netip.Addr) { m.takeICMPToken(source) }},
	} {
		for _, c := range withheldArms {
			b.Run(fmt.Sprintf("%s IPv%d sources=%d", via.name, c.family, c.sources), func(b *testing.B) {
				m := benchTransitMesh(b)
				sources := withheldSources(b, m, c.family, c.sources)
				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for i := 0; pb.Next(); i = (i + 1) % len(sources) {
						via.draw(m, sources[i])
					}
				})
			})
		}
	}
}
