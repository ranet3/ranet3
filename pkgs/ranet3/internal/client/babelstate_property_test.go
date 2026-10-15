// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// drawBabelState draws a state whose node's names hold any text, with the organization and name it was drawn from
func drawBabelState(ht *hegel.T) (state babelState, organization, name string) {
	organization, name = hegel.Draw(ht, hegel.Text().MinSize(1).MaxSize(24)), hegel.Draw(ht, hegel.Text().MinSize(1).MaxSize(24))
	node, err := identity.From(organization, name, "")
	if err != nil {
		ht.Fatalf("%v", err)
	}
	state = babelState{
		node:   node,
		origin: babel.Origin{Limit: uint16(hegel.Draw(ht, pbt.Spanning(0, 65535)))},
	}
	for i := range state.origin.RouterID {
		state.origin.RouterID[i] = byte(hegel.Draw(ht, pbt.Spanning(0, 255)))
	}
	// RFC 8966 section 4.6.7 rules out the two, and a speaker never draws them
	if state.origin.RouterID == [8]byte{} || bytes.Count(state.origin.RouterID[:], []byte{0xff}) == len(state.origin.RouterID) {
		state.origin.RouterID[0] ^= 1
	}
	return state, organization, name
}

// every state a save is handed reads back as it was written, whatever the node's names hold
// every prefix of the file, which a torn write would leave, reads back as written or is refused, never as another state
func TestBabelStateReadsBackAsWritten(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		state, _, _ := drawBabelState(ht)
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

// olderNode and olderStateBody are the file's types as an older release declares them
type olderNode struct {
	Org  string `yaml:"org" json:"org" toml:"org"`
	Name string `yaml:"name" json:"name" toml:"name"`
}

type olderStateBody struct {
	Node     *olderNode `json:"node"`
	RouterID string     `json:"router_id"`
	Limit    *uint16    `json:"seqno_limit"`
}

// an older release reads every file a save writes as naming the same node, router id and limit, so a node run back to it keeps its router id
func TestBabelStateReadsUnderTheTypesOfAnOlderRelease(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		state, organization, name := drawBabelState(ht)
		dir := ht.T.TempDir()
		if err := writeBabelState(dir, state); err != nil {
			ht.Fatalf("%v", err)
		}
		body, err := os.ReadFile(filepath.Join(dir, babelStateFile))
		if err != nil {
			ht.Fatalf("%v", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.DisallowUnknownFields()
		var older olderStateBody
		if err := decoder.Decode(&older); err != nil {
			ht.Fatalf("an older release refuses %s: %v", body, err)
		}
		if _, err := decoder.Token(); err != io.EOF {
			ht.Fatalf("an older release finds more after the object in %s", body)
		}
		if older.Node == nil || *older.Node != (olderNode{organization, name}) || older.RouterID != hex.EncodeToString(state.origin.RouterID[:]) || older.Limit == nil || *older.Limit != state.origin.Limit {
			ht.Fatalf("an older release reads %s as %+v, want %q and %q at %x up to %d", body, older, organization, name, state.origin.RouterID, state.origin.Limit)
		}
	})
}
