// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/control"
)

// keyTexts is every text a key's octets reach a string as: the octets
// themselves, hex in either case, base64 in either alphabet with and without
// padding, and the list of numbers fmt and slog print a byte slice as
func keyTexts(key []byte) []string {
	return []string{
		string(key),
		hex.EncodeToString(key), strings.ToUpper(hex.EncodeToString(key)),
		base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key),
		base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key),
		fmt.Sprint(key),
	}
}

// keyAt is where under v, named at, one of texts sits inside a string, a
// map's key or a run of bytes, empty where none does. It reads every exported
// field, element, map key and value.
func keyAt(v reflect.Value, texts []string, at string) string {
	switch v.Kind() {
	case reflect.String:
		for _, text := range texts {
			if strings.Contains(v.String(), text) {
				return at
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return keyAt(v.Elem(), texts, at)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			octets := make([]byte, v.Len())
			reflect.Copy(reflect.ValueOf(octets), v)
			return keyAt(reflect.ValueOf(string(octets)), texts, at)
		}
		for i := range v.Len() {
			if found := keyAt(v.Index(i), texts, fmt.Sprintf("%s[%d]", at, i)); found != "" {
				return found
			}
		}
	case reflect.Map:
		for entry := v.MapRange(); entry.Next(); {
			name := fmt.Sprintf("%s[%v]", at, entry.Key())
			if found := keyAt(entry.Key(), texts, name+" key"); found != "" {
				return found
			}
			if found := keyAt(entry.Value(), texts, name); found != "" {
				return found
			}
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if field := v.Type().Field(i); field.IsExported() {
				if found := keyAt(v.Field(i), texts, at+"."+field.Name); found != "" {
					return found
				}
			}
		}
	}
	return ""
}

// no debug view of either end of a live session, the events among them,
// carries its Child SA's keys, the keys of the SA a rekey replaced, or the
// node's private key, as octets or as any text of them, in any string, map
// key or run of bytes. A debug path the daemon serves that is neither walked
// nor left out with its reason fails, so a new view joins the walk.
func TestDebugViewsCarryNoKeyOfALiveSession(t *testing.T) {
	leftOut := map[string]string{
		control.PathDebugProbe: "it asks the sessions to prove their path and answers with the call's result, not a state the node holds",
		control.PathDebugTrace: "it streams each packet's forwarding decision as the node makes it, not a state the node holds",
	}
	walked := map[string]bool{}
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so both ends hold the one session alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})
	held := alpha.client.sessions.snapshot()
	if len(held) != 1 {
		t.Fatalf("alpha holds %d sessions, want the one it dialed", len(held))
	}
	replaced := held[0].session.Child()
	if err := held[0].session.RekeyChild(); err != nil {
		t.Fatalf("alpha could not rekey its session: %v", err)
	}
	child := held[0].session.Child()
	if child.LocalSPI == replaced.LocalSPI {
		t.Fatalf("the rekey left the Child SA of SPI %08x in place", child.LocalSPI)
	}
	keys := map[string][]byte{
		"the Child SA's inbound key": child.InboundKey, "the Child SA's outbound key": child.OutboundKey,
		"the replaced Child SA's inbound key": replaced.InboundKey, "the replaced Child SA's outbound key": replaced.OutboundKey,
		"the node's private key": alpha.client.privateKey,
	}
	for _, node := range []*loopbackNode{alpha, bravo} {
		c := node.client
		peer := c.sessions.snapshot()
		if len(peer) != 1 {
			t.Fatalf("%s holds %d sessions, want the one alpha dialed", node.name, len(peer))
		}
		other := alpha
		if node == alpha {
			other = bravo
		}
		route, err := c.DebugRoute(other.prefix.Addr().Next(), node.prefix.Addr().Next(), "", peer[0].path)
		if err != nil {
			t.Fatalf("%s's route view of a packet from %s: %v", node.name, peer[0].path, err)
		}
		views := map[string]any{
			control.PathDebugEgress:   c.DebugEgress(),
			control.PathDebugEvents:   c.DebugEvents(control.EventQuery{}),
			control.PathDebugNetmon:   c.DebugNetmon(),
			control.PathDebugPMTU:     c.DebugPMTU(""),
			control.PathDebugRoute:    route,
			control.PathDebugRules:    c.DebugRules(),
			control.PathDebugRuntime:  c.DebugRuntime(),
			control.PathDebugSegments: c.DebugSegments(),
			control.PathDebugSender:   c.DebugSender(""),
			control.PathDebugUpDown:   c.DebugUpDown(),
		}
		for path, view := range views {
			walked[path] = true
			for name, key := range keys {
				if at := keyAt(reflect.ValueOf(view), keyTexts(key), "answer"); at != "" {
					t.Errorf("%s's %s carries %s at %s", node.name, path, name, at)
				}
			}
		}
	}
	for path := range control.DebugPaths() {
		if _, left := leftOut[path]; !walked[path] && !left {
			t.Errorf("%s is served, and the walk neither reads it nor leaves it out with its reason", path)
		}
	}
}
