// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"testing"
)

func TestByteStringWidthForms(t *testing.T) {
	for _, size := range []int{23, 24} {
		body := bytes.Repeat([]byte{0x11}, size)
		encoded := appendBstr(nil, body)
		at := 0
		got, err := takeBstr(encoded, &at)
		if err != nil || !bytes.Equal(got, body) || at != len(encoded) {
			t.Fatalf("canonical length %d: %v", size, err)
		}
	}
	for _, test := range []struct {
		name string
		head []byte
	}{
		{"one byte for 23", []byte{0x58, 0x17}},
		{"two bytes for 255", []byte{0x59, 0x00, 0xff}},
		{"four bytes for 65535", []byte{0x5a, 0x00, 0x00, 0xff, 0xff}},
		{"eight bytes for 4294967295", []byte{0x5b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}},
	} {
		t.Run(test.name, func(t *testing.T) {
			at := 0
			if _, err := takeBstr(test.head, &at); err == nil || err.Error() != "nonminimal byte string length" {
				t.Fatalf("accepted overlong length head %x: %v", test.head, err)
			}
		})
	}
}
