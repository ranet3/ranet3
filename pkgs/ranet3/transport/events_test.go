// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"errors"
	"log/slog"
	"slices"
	"testing"
)

// movingBind is a socket that can be moved between interfaces and carries nothing
type movingBind struct{}

func (movingBind) ParseEndpoint(string) (Endpoint, error) { return nil, errors.New("carries nothing") }
func (movingBind) Send([][]byte, Endpoint) error          { return nil }
func (movingBind) Close() error                           { return nil }
func (movingBind) bindInterface(int, bool) error          { return nil }

// a move of the underlay socket onto another interface is recorded, and a binding that changes nothing is not
func TestUnderlayMoveIsRecorded(t *testing.T) {
	var recorded []string
	hub := &Hub{bind: movingBind{}, events: func(kind string, attrs ...slog.Attr) {
		recorded = append(recorded, kind+" "+attrs[0].String())
	}}
	for _, index := range []int{3, 3, 5} {
		if err := hub.BindUnderlay(index); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"transport.underlay.bound interface_index=3", "transport.underlay.bound interface_index=5"}
	if !slices.Equal(recorded, want) {
		t.Errorf("the hub recorded %q, want %q", recorded, want)
	}
}
