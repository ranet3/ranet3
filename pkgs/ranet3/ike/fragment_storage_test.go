// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestReassemblyCountsSmallFragmentStorage(t *testing.T) {
	if runAllocationChild(t) {
		return
	}
	const copies = 64
	for _, size := range []int{0, 1} {
		key := make([]byte, modelKeyLen)
		header := Header{SPIInitiator: 1, SPIResponder: 2, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
		var raws [][]byte
		var messages []*Message
		var probe reassembly
		now := time.Now()
		for number := uint16(2); ; number++ {
			raw, err := sealedFragment(modelSuite, key, header, nil, PayloadNone, 0, number, 1000, make([]byte, size))
			if err != nil {
				t.Fatal(err)
			}
			m, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := probe.take(modelSuite, key, raw, m, now); errors.Is(err, errFragmentLimit) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			raws, messages = append(raws, raw), append(messages, m)
			if number == 999 {
				t.Fatal("a queue never reached its limit")
			}
		}
		all := make([]reassembly, copies)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for i := range all {
			for j, raw := range raws {
				if got, err := all[i].take(modelSuite, key, raw, messages[j], now); got != nil || err != nil {
					t.Fatalf("an incomplete queue returned %v, %v", got, err)
				}
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		retained := (int64(after.HeapAlloc) - int64(before.HeapAlloc)) / copies
		t.Logf("content %d: %d fragments, charged %d, heap retained %d per queue", size, len(raws), all[0].held, retained)
		if retained <= 0 || retained >= reassemblyLimit || retained > int64(all[0].held) {
			t.Fatalf("small fragments retain %d octets, charged %d below %d", retained, all[0].held, reassemblyLimit)
		}
		runtime.KeepAlive(all)
		runtime.KeepAlive(raws)
		runtime.KeepAlive(messages)
	}
}
