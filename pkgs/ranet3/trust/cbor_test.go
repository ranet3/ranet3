// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type codecValue struct {
	Height uint64   `cbor:"1,keyasint"`
	Items  []string `cbor:"3,keyasint"`
}

func TestCanonicalCBOR(t *testing.T) {
	value := codecValue{Height: 24}
	got, err := marshalCBOR(value)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8949 core deterministic map ordering, shortest integer and empty array
	want, _ := hex.DecodeString("a20118180380")
	if !bytes.Equal(got, want) {
		t.Fatalf("encoding %x, want %x", got, want)
	}
	var decoded codecValue
	if err := unmarshalCBOR(got, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Height != value.Height || len(decoded.Items) != 0 {
		t.Fatalf("decoded %+v", decoded)
	}
}

func TestCanonicalRefusals(t *testing.T) {
	cases := map[string]string{
		"long integer":     "a2011900180380",
		"unsorted keys":    "a20380011818",
		"duplicate key":    "a30118180118180380",
		"unknown key":      "a301181802000380",
		"indefinite array": "a2011818039fff",
		"tag":              "d818a20118180380",
		"null":             "f6",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatal(err)
			}
			var value codecValue
			if err := unmarshalCBOR(data, &value); err == nil {
				t.Fatalf("accepted %x", data)
			}
		})
	}
}
