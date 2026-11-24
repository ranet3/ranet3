// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	encodeCBOR = func() cbor.EncMode {
		options := cbor.CoreDetEncOptions()
		options.NilContainers = cbor.NilContainerAsEmpty
		mode, err := options.EncMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
	decodeCBOR = func() cbor.DecMode {
		mode, err := (cbor.DecOptions{
			DupMapKey:         cbor.DupMapKeyEnforcedAPF,
			IndefLength:       cbor.IndefLengthForbidden,
			TagsMd:            cbor.TagsForbidden,
			ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
			FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
			MaxArrayElements:  MaxEntries,
		}).DecMode()
		if err != nil {
			panic(err)
		}
		return mode
	}()
)

func marshalCBOR(value any) ([]byte, error) {
	return encodeCBOR.Marshal(value)
}

func unmarshalCBOR(data []byte, value any) error {
	if err := decodeCBOR.Unmarshal(data, value); err != nil {
		return fmt.Errorf("trust: decode CBOR: %w", err)
	}
	canonical, err := marshalCBOR(value)
	if err != nil {
		return fmt.Errorf("trust: encode CBOR: %w", err)
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("trust: CBOR is not deterministic")
	}
	return nil
}
