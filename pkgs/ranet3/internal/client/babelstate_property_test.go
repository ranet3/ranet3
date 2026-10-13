// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// every state a save is handed reads back as it was written, whatever the node's names hold
// every prefix of the file, which a torn write would leave, reads back as written or is refused, never as another state
func TestBabelStateReadsBackAsWritten(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		state := babelState{
			node:   config.Node{Org: hegel.Draw(ht, hegel.Text().MaxSize(24)), Name: hegel.Draw(ht, hegel.Text().MaxSize(24))},
			origin: babel.Origin{Limit: uint16(hegel.Draw(ht, pbt.Spanning(0, 65535)))},
		}
		for i := range state.origin.RouterID {
			state.origin.RouterID[i] = byte(hegel.Draw(ht, pbt.Spanning(0, 255)))
		}
		// RFC 8966 section 4.6.7 rules out the two, and a speaker never draws them
		if state.origin.RouterID == [8]byte{} || bytes.Count(state.origin.RouterID[:], []byte{0xff}) == len(state.origin.RouterID) {
			state.origin.RouterID[0] ^= 1
		}
		dir := ht.T.TempDir()
		if err := writeBabelState(dir, state); err != nil {
			ht.Fatalf("%v", err)
		}
		got, found, err := readBabelState(dir)
		if err != nil || !found || got != state {
			ht.Fatalf("%+v was written and read back as %+v (found %v, err %v)", state, got, found, err)
		}
		body, err := os.ReadFile(filepath.Join(dir, babelStateFile))
		if err != nil {
			ht.Fatalf("%v", err)
		}
		for cut := range len(body) {
			if partial, err := parseBabelState(body[:cut]); err == nil && partial != state {
				ht.Fatalf("the first %d bytes of %q read as %+v", cut, body, partial)
			}
		}
	})
}
