// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

const trustStoreName = "trust.store"

// TrustHeld is the serving snapshot, separate from the last renamed image.
type TrustHeld struct {
	Signed   []byte
	Verified trustdoc.Verified
	ReadAt   time.Time
}

type TrustMarker struct {
	Image  trustdoc.StoreImage
	Synced bool
}

// TrustRecord belongs to the loader, not the serving node. A failed reload
// cannot roll back either its compromised keys or its disk marker.
type TrustRecord struct {
	List   []trustdoc.CompromisedKey
	Marker *TrustMarker
}

type TrustRefusal struct {
	Reason string
	At     time.Time
	Height *uint64
	Digest string
}

type TrustEvent struct {
	Kind  string
	Attrs map[string]string
}

type TrustResult struct {
	Start              bool
	Row                trustdoc.Row
	Decision           trustdoc.Row
	Held               *TrustHeld
	Prepared           *TrustHeld
	Offered            *TrustHeld
	Record             *TrustRecord
	Refused            *TrustRefusal
	ClearRefusal       bool
	Events             []TrustEvent
	NotPersisted       []trustdoc.CompromisedKey
	Failure            string
	PersistenceFailure string
	FailureStage       statefile.Stage
	ResetReady         string
	ResetWaits         string
	CanFallback        bool
}

func readTrustBytes(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() > int64(limit) {
		return nil, fmt.Errorf("trust: %s exceeds its size limit", path)
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > limit {
		return nil, fmt.Errorf("trust: %s exceeds its size limit", path)
	}
	return body, nil
}

func readTrustStore(path string) (trustdoc.StoreImage, bool, error) {
	raw, err := readTrustBytes(path, trustdoc.MaxStoreBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return trustdoc.StoreImage{}, false, nil
	}
	if err != nil {
		return trustdoc.StoreImage{}, false, err
	}
	image, err := trustdoc.DecodeStore(raw)
	return image, true, err
}

func authorityKeys(cfg *config.Config) ([]trustdoc.AuthorityKey, error) {
	keys := make([]trustdoc.AuthorityKey, 0, len(cfg.Auth.Authority))
	for _, text := range cfg.Auth.Authority {
		key, err := trustdoc.ParseAuthorityKey(text)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func compromisedEntry(list []trustdoc.CompromisedKey, der []byte) (trustdoc.CompromisedKey, bool) {
	index, found := slices.BinarySearchFunc(list, der, func(entry trustdoc.CompromisedKey, key []byte) int {
		return bytes.Compare(entry.Key.DER, key)
	})
	if !found {
		return trustdoc.CompromisedKey{}, false
	}
	return list[index], true
}

func candidateList(stored []trustdoc.CompromisedKey, revoked []config.RevokedKey) ([]trustdoc.CompromisedKey, []trustdoc.CompromisedKey, error) {
	list := slices.Clone(stored)
	entries := make([]trustdoc.CompromisedKey, 0, len(revoked))
	for _, entry := range revoked {
		key, err := trustdoc.ParseAuthorityKey(entry.Key)
		if err != nil {
			return nil, nil, err
		}
		entries = append(entries, trustdoc.CompromisedKey{Key: key, Floor: entry.Height})
		index, found := slices.BinarySearchFunc(list, key.DER, func(item trustdoc.CompromisedKey, der []byte) int {
			return bytes.Compare(item.Key.DER, der)
		})
		if !found {
			list = slices.Insert(list, index, trustdoc.CompromisedKey{Key: key})
		}
	}
	if len(list) > 64 {
		return nil, nil, fmt.Errorf("config: compromised key list has %d entries, at most 64 allowed", len(list))
	}
	return list, entries, nil
}

func raiseFloors(list, entries []trustdoc.CompromisedKey, offered *TrustHeld) {
	if offered == nil {
		return
	}
	for _, entry := range entries {
		if offered.Verified.Payload.Height < entry.Floor {
			continue
		}
		index, _ := slices.BinarySearchFunc(list, entry.Key.DER, func(item trustdoc.CompromisedKey, der []byte) int {
			return bytes.Compare(item.Key.DER, der)
		})
		list[index].Floor = max(list[index].Floor, entry.Floor)
	}
}

func eligibleAuthorities(keys []trustdoc.AuthorityKey, list []trustdoc.CompromisedKey) []trustdoc.AuthorityKey {
	eligible := make([]trustdoc.AuthorityKey, 0, len(keys))
	for _, key := range keys {
		if _, found := compromisedEntry(list, key.DER); !found {
			eligible = append(eligible, key)
		}
	}
	return eligible
}

func equalCompromised(a, b []trustdoc.CompromisedKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Key.DER, b[i].Key.DER) || a[i].Floor != b[i].Floor {
			return false
		}
	}
	return true
}

func notPersisted(list []trustdoc.CompromisedKey, marker *TrustMarker) []trustdoc.CompromisedKey {
	if marker != nil && marker.Synced {
		var owed []trustdoc.CompromisedKey
		for _, entry := range list {
			if persisted, ok := compromisedEntry(marker.Image.Compromised, entry.Key.DER); !ok || persisted.Floor < entry.Floor {
				owed = append(owed, entry)
			}
		}
		return owed
	}
	return slices.Clone(list)
}

func markerImage(held *TrustHeld, list []trustdoc.CompromisedKey) trustdoc.StoreImage {
	image := trustdoc.StoreImage{Compromised: slices.Clone(list)}
	if held != nil {
		image.Signed = held.Signed
		image.Signer = held.Verified.Key
		image.Verified = &held.Verified
	}
	return image
}

func replaceTrustMarker(path string, record *TrustRecord, image trustdoc.StoreImage, replace func(string, []byte) error) error {
	body, err := trustdoc.EncodeStore(image)
	if err != nil {
		return err
	}
	err = replace(path, body)
	var failure *statefile.ReplaceError
	if errors.As(err, &failure) {
		if failure.Renamed {
			record.Marker = &TrustMarker{Image: image}
		}
		return err
	}
	if err == nil {
		record.Marker = &TrustMarker{Image: image, Synced: true}
	}
	return err
}

func rowTakesOffered(row trustdoc.Row) bool {
	switch row {
	case trustdoc.D2, trustdoc.D7, trustdoc.D8, trustdoc.D9, trustdoc.D20, trustdoc.D21:
		return true
	}
	return false
}

func rowRefuses(row trustdoc.Row, start bool, held, offered *TrustHeld, floor, entry uint64) bool {
	switch row {
	case trustdoc.D11, trustdoc.D13:
		return !start
	case trustdoc.D24:
		if offered == nil {
			return !start
		}
		if held != nil && offered.Verified.Payload.Mesh != held.Verified.Payload.Mesh {
			return true
		}
		return !start && floor == 0 && entry == 0
	case trustdoc.C1, trustdoc.D1, trustdoc.D5, trustdoc.D6, trustdoc.D12, trustdoc.D14, trustdoc.D16, trustdoc.D19, trustdoc.D23:
		return true
	}
	return false
}

type trustPersistence struct {
	replace func(string, []byte) error
	syncDir func(string) error
}

// LoadTrust prepares a local decision and disk record without publishing it.
// previous is nil only at a start. Base checks cannot read membership, while
// Members checks the index the selected row would run.
type TrustChecks struct {
	Base    func(*config.Config) error
	Members func(*trustdoc.Index) error
}

func LoadTrust(cfg *config.Config, dir string, previous *TrustRecord, serving *TrustHeld, checks *TrustChecks) (TrustResult, error) {
	return loadTrust(cfg, dir, previous, serving, checks, trustPersistence{statefile.ReplaceSynced, statefile.SyncDirectory})
}

func loadTrust(cfg *config.Config, dir string, previous *TrustRecord, serving *TrustHeld, checks *TrustChecks, persistence trustPersistence) (TrustResult, error) {
	start := previous == nil
	path := filepath.Join(dir, trustStoreName)
	result := TrustResult{Start: start, Held: serving, Record: previous}
	if err := cfg.Validate(); err != nil {
		if errors.Is(err, config.ErrAuthorityRevokedOverlap) {
			result.Row, result.Failure = trustdoc.C1, err.Error()
			if !start {
				result.Refused = &TrustRefusal{Reason: "config error", At: time.Now().UTC()}
			}
			return result, nil
		}
		return TrustResult{}, err
	}
	if start {
		previous = &TrustRecord{}
		image, present, err := readTrustStore(path)
		if err != nil {
			result.Row, result.Failure = trustdoc.D14, fmt.Sprintf("store %s unreadable: %v", path, err)
			return result, nil
		}
		if present {
			previous.List = image.Compromised
			previous.Marker = &TrustMarker{Image: image}
			if image.Verified != nil {
				result.Held = &TrustHeld{Signed: image.Signed, Verified: *image.Verified, ReadAt: time.Now().UTC()}
			}
		}
	} else if serving == nil {
		return TrustResult{}, errors.New("trust: reload requires a serving snapshot")
	}
	result.Record = previous
	keys, err := authorityKeys(cfg)
	if err != nil {
		return TrustResult{}, err
	}
	list, entries, err := candidateList(previous.List, cfg.Auth.Revoked)
	if err != nil {
		result.Row, result.Failure = trustdoc.C1, err.Error()
		if !start {
			result.Refused = &TrustRefusal{Reason: "config error", At: time.Now().UTC()}
		}
		return result, nil
	}
	eligible := eligibleAuthorities(keys, list)
	var authenticated *trustdoc.Authenticated
	var absent bool
	body, readErr := readTrustBytes(cfg.Auth.Trust, trustdoc.MaxSignedBytes)
	if readErr == nil {
		if value, err := trustdoc.AuthenticateSignedFile(body, eligible); err == nil {
			authenticated = &value
		}
	} else {
		absent = errors.Is(readErr, fs.ErrNotExist)
	}
	var overlap error
	if result.Held != nil {
		overlap = trustdoc.CheckOverlap(keys, result.Held.Verified.Payload)
	}
	if overlap == nil && authenticated != nil {
		overlap = trustdoc.CheckOverlap(keys, authenticated.Payload())
	}
	if overlap != nil {
		result.Failure = overlap.Error()
	}
	if authenticated != nil && overlap == nil {
		if verified, err := authenticated.Validate(); err == nil {
			result.Offered = &TrustHeld{Signed: body, Verified: verified, ReadAt: time.Now().UTC()}
		}
	}
	raiseFloors(list, entries, result.Offered)
	var floor, entryHeight uint64
	var eligibleSigner, compromised bool
	if result.Held != nil {
		if found, ok := compromisedEntry(list, result.Held.Verified.Key.DER); ok {
			compromised, floor = true, found.Floor
		}
		for _, entry := range entries {
			if bytes.Equal(entry.Key.DER, result.Held.Verified.Key.DER) {
				entryHeight = entry.Floor
				break
			}
		}
		for _, key := range eligible {
			if bytes.Equal(key.DER, result.Held.Verified.Key.DER) {
				eligibleSigner = true
				break
			}
		}
	}
	input := trustdoc.OrderInput{Start: start, Held: verifiedTrust(result.Held), Offered: verifiedTrust(result.Offered), HeldSignerEligible: eligibleSigner, HeldSignerCompromised: compromised, Floor: floor, EntryHeight: entryHeight, Overlap: overlap != nil}
	if !input.Overlap {
		err := checkTrustBase(cfg)
		if err == nil && checks != nil && checks.Base != nil {
			err = checks.Base(cfg)
		}
		if err != nil {
			input.ConfigChecksRefused = true
			result.Failure = err.Error()
		}
	}
	checkMembership := func(target *TrustHeld) error {
		index, err := trustdoc.NewIndex(target.Verified.Payload.Document)
		if err != nil {
			return err
		}
		if checks != nil && checks.Members != nil {
			return checks.Members(index)
		}
		key, err := trustdoc.LoadPrivateKey(cfg.Auth.Key)
		if err != nil {
			return err
		}
		return checkTrustMembership(cfg, key, index)
	}
	provisional := trustdoc.Order(input)
	if !input.ConfigChecksRefused && !input.Overlap && (rowTakesOffered(provisional) || !rowRefuses(provisional, start, result.Held, result.Offered, floor, entryHeight)) {
		target := result.Held
		if rowTakesOffered(provisional) {
			target = result.Offered
		}
		if target != nil {
			if err := checkMembership(target); err != nil {
				input.ConfigChecksRefused = true
				result.Failure = err.Error()
			}
		}
	}
	result.Row = trustdoc.Order(input)
	result.Decision = result.Row
	if start && rowTakesOffered(result.Row) && result.Held != nil {
		result.CanFallback = checkMembership(result.Held) == nil
	}
	if start && !rowTakesOffered(result.Row) {
		result.CanFallback = result.Held != nil && !input.ConfigChecksRefused && !input.Overlap
	}
	previous.List = list
	if previous.Marker == nil && len(list) != 0 || previous.Marker != nil && !equalCompromised(list, previous.Marker.Image.Compromised) {
		if err := replaceTrustMarker(path, previous, markerImage(result.Held, list), persistence.replace); err != nil {
			result.markFailure(err, "compromised keys not persisted", !rowRefuses(result.Row, start, result.Held, result.Offered, floor, entryHeight))
		}
	} else if previous.Marker != nil && !previous.Marker.Synced {
		if err := persistence.syncDir(path); err != nil {
			result.markFailure(err, "compromised keys not persisted", !rowRefuses(result.Row, start, result.Held, result.Offered, floor, entryHeight))
		} else {
			previous.Marker.Synced = true
		}
	}
	result.NotPersisted = notPersisted(list, previous.Marker)
	if result.FailureStage != "" {
		var names []string
		for _, item := range result.NotPersisted {
			names = append(names, keyFingerprint(item.Key.DER))
		}
		set := "none"
		if len(names) != 0 {
			set = strings.Join(names, ", ")
		}
		result.PersistenceFailure = fmt.Sprintf("compromised keys not persisted: %s, %s failed", set, result.FailureStage)
		if result.Row == trustdoc.D15 {
			result.Failure = result.PersistenceFailure
		}
	}
	if result.FailureStage == "" && rowTakesOffered(result.Row) {
		if err := replaceTrustMarker(path, previous, markerImage(result.Offered, list), persistence.replace); err != nil {
			result.markFailure(err, "snapshot not persisted", true)
		} else {
			result.Prepared = result.Offered
		}
	}
	result.finishTrust(cfg.Auth.Trust, path, absent, floor, entryHeight, result.Held)
	return result, nil
}

func verifiedTrust(held *TrustHeld) *trustdoc.Verified {
	if held == nil {
		return nil
	}
	return &held.Verified
}

func (r *TrustResult) markFailure(err error, subject string, replaceRow bool) {
	var failure *statefile.ReplaceError
	if errors.As(err, &failure) {
		r.FailureStage = failure.Stage
	} else {
		r.FailureStage = statefile.StageWrite
	}
	if subject == "snapshot not persisted" {
		r.Failure = fmt.Sprintf("%s: %s failed", subject, r.FailureStage)
	}
	if replaceRow {
		r.Row = trustdoc.D15
	}
}
