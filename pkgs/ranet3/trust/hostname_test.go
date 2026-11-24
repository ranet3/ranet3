// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"strings"
	"testing"
)

func TestHostNameProfile(t *testing.T) {
	for _, test := range []struct {
		name string
		want bool
	}{
		{"gateway.example.org", true},
		{"xn--bcher-kva.example", true},
		{"xn--zca.example", true},
		{"a-1.example", true},
		{"123.example", true},
		{strings.Repeat("a", 63) + ".example", true},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), true},
		{"", false},
		{"123.456", false},
		{"1.2.3", false},
		{"GATEWAY.example.org", false},
		{"XN--BCHER-KVA.example", false},
		{"b\u00fccher.example", false},
		{"example\u3002org", false},
		{"xn--a.example", false},
		{"xn--a-zhc.example", false},
		{"xn--.example", false},
		{"ab--cd.example", false},
		{"-gateway.example", false},
		{"gateway-.example", false},
		{"gateway..example", false},
		{".gateway.example", false},
		{"gateway.example.", false},
		{"gateway_.example", false},
		{strings.Repeat("a", 64) + ".example", false},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := hostName(test.name); (err == nil) != test.want {
				t.Fatalf("hostName(%q): %v; want valid %v", test.name, err, test.want)
			}
		})
	}
}
