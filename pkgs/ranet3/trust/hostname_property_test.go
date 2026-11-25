// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestHostNameProperty(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		numLabels := hegel.Draw(ht, pbt.Spanning(1, 6))
		labels := make([]string, 0, numLabels)
		numbers := make([]string, 0, numLabels)
		labelsFit := true
		for range numLabels {
			length := hegel.Draw(ht, pbt.Spanning(1, 64))
			if length > 63 {
				labelsFit = false
			}
			label := "a" + strings.Repeat("2", length-1)
			labels = append(labels, label)
			numbers = append(numbers, strings.Repeat("2", length))
		}
		valid := strings.Join(labels, ".")
		want := labelsFit && len(valid) <= 253
		if err := hostName(valid); (err == nil) != want {
			ht.Fatalf("ASCII host %q: %v, want valid %v", valid, err, want)
		}
		if err := hostName(strings.Join(numbers, ".")); err == nil {
			ht.Fatalf("accepted all-numeric host %q", numbers)
		}
		if err := hostName("A" + valid[1:]); err == nil {
			ht.Fatalf("accepted mixed-case host %q", valid)
		}
		prefix := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "."
		for _, tail := range [...]int{61, 62} {
			name := prefix + strings.Repeat("d", tail)
			if err := hostName(name); (err == nil) != (len(name) == 253) {
				ht.Fatalf("host length %d: %v", len(name), err)
			}
		}
		bad := [...]string{"a..b", "ab--cd", "xn--a"}[hegel.Draw(ht, pbt.Spanning(0, 2))]
		if err := hostName(bad); err == nil {
			ht.Fatalf("accepted malformed host %q", bad)
		}
	})
}
