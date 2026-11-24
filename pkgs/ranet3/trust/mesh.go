// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"
)

// MeshID is the UUIDv7 embedded in a signed snapshot, never in authored JSON.
type MeshID [16]byte

func (id MeshID) Validate() error {
	if id[6]>>4 != 7 {
		return errors.New("trust: mesh is not UUID version 7")
	}
	if id[8]&0xc0 != 0x80 {
		return errors.New("trust: mesh has no RFC 9562 variant")
	}
	return nil
}

func NewMeshID() (MeshID, error) {
	return newMeshID(time.Now().UnixMilli(), rand.Reader)
}

func newMeshID(milliseconds int64, random io.Reader) (MeshID, error) {
	var id MeshID
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return MeshID{}, fmt.Errorf("trust: mesh random source: %w", err)
	}
	if milliseconds < 0 || milliseconds >= 1<<48 {
		return MeshID{}, errors.New("trust: timestamp does not fit UUIDv7")
	}
	for i := range 6 {
		id[5-i] = byte(milliseconds >> (8 * i))
	}
	id[6] = id[6]&0x0f | 0x70
	id[8] = id[8]&0x3f | 0x80
	return id, nil
}

func (id MeshID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
}
