// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"encoding/base64"
	"fmt"
)

// CheckOverlap refuses any record's raw device key that is also in K.
// It also accepts an authenticated payload that has not passed field validation.
func CheckOverlap(keys []AuthorityKey, snapshot Payload) error {
	if len(keys) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		known[base64.StdEncoding.EncodeToString(key.DER)] = struct{}{}
	}
	for _, node := range snapshot.Document.Nodes {
		if node.Key == nil {
			continue
		}
		if _, found := known[*node.Key]; found {
			return fmt.Errorf("trust: authority key also belongs to node %q", node.Name)
		}
	}
	return nil
}
