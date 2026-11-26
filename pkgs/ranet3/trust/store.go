// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// CompromisedKey carries a key even when no recovery floor has been recorded.
type CompromisedKey struct {
	Key   AuthorityKey
	Floor uint64
}

// StoreImage is the single on-disk snapshot and compromised-key list.
// An image with no snapshot has no signer.
type StoreImage struct {
	Signed      []byte
	Signer      AuthorityKey
	Verified    *Verified
	Compromised []CompromisedKey
}

type storeWire struct {
	Signed []byte         `cbor:"1,keyasint,omitempty"`
	Signer []byte         `cbor:"2,keyasint,omitempty"`
	List   []storeKeyWire `cbor:"3,keyasint"`
}

type storeKeyWire struct {
	Key   []byte  `cbor:"1,keyasint"`
	Floor *uint64 `cbor:"2,keyasint,omitempty"`
}

// DecodeStore accepts only the closed canonical map and verifies the stored
// signed file under its recorded signer, regardless of current authority keys.
func DecodeStore(raw []byte) (StoreImage, error) {
	if len(raw) > MaxStoreBytes {
		return StoreImage{}, errors.New("trust: store exceeds 64 MiB plus 16 KiB")
	}
	var wire storeWire
	if err := unmarshalCBOR(raw, &wire); err != nil {
		return StoreImage{}, err
	}
	if (wire.Signed == nil) != (wire.Signer == nil) || len(wire.List) > 64 {
		return StoreImage{}, errors.New("trust: invalid store members")
	}
	image := StoreImage{Compromised: make([]CompromisedKey, 0, len(wire.List))}
	if wire.Signed != nil {
		if len(wire.Signed) == 0 || len(wire.Signer) == 0 {
			return StoreImage{}, errors.New("trust: invalid stored snapshot")
		}
		key, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(wire.Signer))
		if err != nil {
			return StoreImage{}, fmt.Errorf("trust: stored signer: %w", err)
		}
		verified, err := VerifySignedFile(wire.Signed, []AuthorityKey{key})
		if err != nil {
			return StoreImage{}, fmt.Errorf("trust: stored snapshot: %w", err)
		}
		image.Signed, image.Signer, image.Verified = wire.Signed, key, &verified
	}
	for i, item := range wire.List {
		key, err := ParseAuthorityKey(base64.StdEncoding.EncodeToString(item.Key))
		if err != nil {
			return StoreImage{}, fmt.Errorf("trust: stored compromised key %d: %w", i, err)
		}
		if i > 0 && bytes.Compare(wire.List[i-1].Key, item.Key) >= 0 {
			return StoreImage{}, errors.New("trust: compromised keys are not strictly ordered")
		}
		var floor uint64
		if item.Floor != nil {
			floor = *item.Floor
			if floor == 0 || floor > MaxHeight {
				return StoreImage{}, errors.New("trust: invalid compromised floor")
			}
		}
		image.Compromised = append(image.Compromised, CompromisedKey{Key: key, Floor: floor})
	}
	return image, nil
}

// EncodeStore writes the closed canonical map in key order.
func EncodeStore(image StoreImage) ([]byte, error) {
	wire := storeWire{List: make([]storeKeyWire, 0, len(image.Compromised))}
	if image.Verified != nil {
		wire.Signed, wire.Signer = image.Signed, image.Signer.DER
	}
	if len(image.Compromised) > 64 || image.Verified == nil && (len(image.Signed) != 0 || len(image.Signer.DER) != 0) || image.Verified != nil && (len(image.Signed) == 0 || len(image.Signer.DER) == 0 || len(image.Signed) > MaxSignedBytes) {
		return nil, errors.New("trust: invalid store image")
	}
	for i, entry := range image.Compromised {
		if i > 0 && bytes.Compare(image.Compromised[i-1].Key.DER, entry.Key.DER) >= 0 || entry.Floor > MaxHeight {
			return nil, errors.New("trust: invalid compromised keys")
		}
		item := storeKeyWire{Key: entry.Key.DER}
		if entry.Floor != 0 {
			floor := entry.Floor
			item.Floor = &floor
		}
		wire.List = append(wire.List, item)
	}
	body, err := marshalCBOR(wire)
	if err != nil {
		return nil, err
	}
	if len(body) > MaxStoreBytes {
		return nil, errors.New("trust: store exceeds 64 MiB plus 16 KiB")
	}
	return body, nil
}
