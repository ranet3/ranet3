// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/goldentest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
)

// Every request the table's transaction sends, written whole, remade, with
// nothing forwarded, no LAN, no own prefix and no service, and withdrawn,
// keeps the kind, flags and body testdata/fallback.golden holds. The root
// test holds the same table beside nft's own listing of it.
func TestFallbackBatchKeepsItsBytes(t *testing.T) {
	var out bytes.Buffer
	write := func(name string, requests []nftables.Request, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fmt.Fprintf(&out, "%s\n", name)
		for _, request := range requests {
			fmt.Fprintf(&out, "  kind %#06x flags %#06x body %x\n", request.Kind, request.Flags, request.Body)
		}
	}
	requests, err := fallbackBatch(fallbackSample, false)
	write("the table of every line", requests, err)
	requests, err = fallbackBatch(fallbackSample, true)
	write("the table remade", requests, err)
	requests, err = fallbackBatch(fallbackSets{tun: "ranetsw0"}, false)
	write("the table with nothing forwarded, no LAN, no own prefix and no service", requests, err)
	write("the withdrawal", []nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, FallbackTable)}, nil)
	goldentest.Check(t, "./internal/kernel", "testdata/fallback.golden", out.Bytes())
}
