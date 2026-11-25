// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package trust

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

func TestAuthorityOverlapProperty(t *testing.T) {
	keys := make([]AuthorityKey, len(independentVectors))
	for i, vector := range independentVectors {
		var err error
		keys[i], err = ParseAuthorityKey(vector.key)
		if err != nil {
			t.Fatal(err)
		}
	}
	pbt.Check(t, func(ht *hegel.T) {
		authority := hegel.Draw(ht, pbt.Spanning(0, len(keys)-1))
		count := hegel.Draw(ht, pbt.Spanning(0, 5))
		payload := Payload{Document: Document{Nodes: make([]Node, 0, count)}}
		want := false
		for i := range count {
			choice := hegel.Draw(ht, pbt.Spanning(0, len(keys)))
			node := Node{Name: fmt.Sprintf("example/n%d", i)}
			if choice < len(keys) {
				spelling := independentVectors[choice].key
				node.Key = &spelling
				raw, err := base64.StdEncoding.DecodeString(spelling)
				if err != nil {
					ht.Fatal(err)
				}
				want = want || bytes.Equal(raw, keys[authority].DER)
			}
			payload.Document.Nodes = append(payload.Document.Nodes, node)
		}
		if err := CheckOverlap([]AuthorityKey{keys[authority]}, payload); (err != nil) != want {
			ht.Fatalf("key %d, nodes %+v: overlap %v, want %v", authority, payload.Document.Nodes, err, want)
		}
	})
}
