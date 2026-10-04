// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package control

import (
	"math"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// a query survives its trip through the path's parameters, which is how the client asks and the daemon reads
func TestEventQueryRoundTripsThroughItsParameters(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		var want EventQuery
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			want.Kinds = append(want.Kinds, hegel.Draw(ht, hegel.Text().MaxSize(16)))
		}
		want.Peer = hegel.Draw(ht, hegel.Text().MaxSize(16))
		// a key ends at the first =, which a value may hold
		for range hegel.Draw(ht, pbt.Spanning(0, 3)) {
			if want.Attrs == nil {
				want.Attrs = map[string]string{}
			}
			want.Attrs[strings.ReplaceAll(hegel.Draw(ht, hegel.Text().MaxSize(8)), "=", "")] = hegel.Draw(ht, hegel.Text().MaxSize(16))
		}
		want.Since = time.Duration(hegel.Draw(ht, pbt.Spanning[int64](0, math.MaxInt64)))
		want.Follow = hegel.Draw(ht, hegel.Booleans())
		encoded := want.values().Encode()
		values, err := url.ParseQuery(encoded)
		if err != nil {
			ht.Fatalf("%+v encoded as %q, which does not parse: %v", want, encoded, err)
		}
		got, err := parseEventQuery(values)
		if err != nil || !reflect.DeepEqual(got, want) {
			ht.Fatalf("%+v encoded as %q and read back as %+v, %v", want, encoded, got, err)
		}
	})
}
