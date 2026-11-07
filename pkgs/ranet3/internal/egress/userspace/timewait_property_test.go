// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"math/big"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// after is the order of RFC 9293's sequence space, written over the integers:
// syn comes after fin where it lies less than half the sequence space ahead
// of it, 2^31, counting forward from fin across the wrap
func after(fin, syn uint32) bool {
	space := new(big.Int).Lsh(big.NewInt(1), 32)
	ahead := new(big.Int).Sub(big.NewInt(int64(syn)), big.NewInt(int64(fin)))
	ahead.Mod(ahead, space)
	return ahead.Sign() > 0 && ahead.Cmp(new(big.Int).Lsh(big.NewInt(1), 31)) < 0
}

// synSentAccepts is RFC 9293 section 3.10.7.3's test of a reset's ACK by a
// connection in SYN-SENT that sent iss: acceptable only where SND.UNA < SEG.ACK
// =< SND.NXT, ISS and ISS plus one, else the reset is dropped
func synSentAccepts(iss, ack uint64) bool {
	return ack%(1<<32) == (iss+1)%(1<<32)
}

// For any FIN and SYN sequence numbers, the wrap included, the exit aborts a
// TIME_WAIT endpoint exactly where the SYN comes after RCV.NXT, the FIN plus
// one, and every
// reset such an abort sends, its ACK the FIN plus one, is one the leaf's
// SYN-SENT drops, so the new connection completes on its first SYN
func TestTimeWaitAbortsExactlyWhereTheSynComesAfterRcvNxt(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		fin := hegel.Draw(ht, pbt.Spanning(uint32(0), ^uint32(0)))
		var syn uint32
		switch hegel.Draw(ht, hegel.Integers(0, 2)) {
		case 0:
			syn = hegel.Draw(ht, pbt.Spanning(uint32(0), ^uint32(0)))
		case 1:
			syn = fin + hegel.Draw(ht, hegel.SampledFrom([]uint32{0, 1, 2, 1<<31 - 1, 1 << 31, 1<<31 + 1, 1<<31 + 2, ^uint32(0)}))
		default:
			syn = fin + hegel.Draw(ht, pbt.Spanning(uint32(1<<31-8), uint32(1<<31+8)))
		}
		if got, want := reuses(fin, syn), after(fin+1, syn); got != want {
			ht.Fatalf("FIN %d SYN %d: reused %t, want %t", fin, syn, got, want)
		}
		if reuses(fin, syn) && synSentAccepts(uint64(syn), uint64(fin)+1) {
			ht.Fatalf("FIN %d SYN %d: the abort's reset, ACK %d, is one SYN-SENT accepts", fin, syn, uint64(fin)+1)
		}
	})
}
