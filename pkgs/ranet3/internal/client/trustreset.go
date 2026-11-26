// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

// ResetTrust replaces only the selected stopped daemon's store after all
// checks against the proposed image have passed without a write.
func ResetTrust(configPath, dir, digest string) (string, error) {
	return resetTrust(configPath, dir, digest, statefile.ReplaceSynced)
}

func resetTrust(configPath, dir, digest string, replace func(string, []byte) error) (string, error) {
	path := filepath.Join(dir, trustStoreName)
	refuse := func(reason string) (string, error) {
		return "", fmt.Errorf("reset refused: config %s, store %s: %s", configPath, path, reason)
	}
	step := func(number, diagnostic string) (string, error) {
		return refuse(fmt.Sprintf("the configuration refuses the replacement: load step %s, %s", number, diagnostic))
	}
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
		return refuse("digest must be 64 lowercase hex characters")
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return refuse("configuration cannot be loaded")
		}
		if errors.Is(err, config.ErrAuthorityRevokedOverlap) {
			return step("2", err.Error())
		}
		return step("1", err.Error())
	}
	image, present, err := readTrustStore(path)
	if err != nil {
		return refuse("the store is unreadable")
	}
	if !present {
		return refuse("the store does not exist")
	}
	if image.Verified == nil {
		return refuse("the store has no stored signer")
	}
	if _, found := compromisedEntry(image.Compromised, image.Signer.DER); !found {
		return refuse("the store's signer " + keyFingerprint(image.Signer.DER) + " is not on its list of compromised keys")
	}
	candidate, _, err := candidateList(image.Compromised, cfg.Auth.Revoked)
	if err != nil {
		return step("3b", err.Error())
	}
	keys, err := authorityKeys(cfg)
	if err != nil {
		return step("1", err.Error())
	}
	body, err := readTrustBytes(cfg.Auth.Trust, trustdoc.MaxSignedBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return refuse("configured file absent")
	}
	if err != nil {
		return refuse("not verified")
	}
	authenticated, err := trustdoc.AuthenticateSignedFile(body, eligibleAuthorities(keys, candidate))
	if err != nil {
		return refuse("not verified")
	}
	if err := trustdoc.CheckOverlap(keys, authenticated.Payload()); err != nil {
		return step("6", err.Error())
	}
	verified, err := authenticated.Validate()
	if err != nil {
		return refuse("not verified")
	}
	if hex.EncodeToString(verified.Digest[:]) != digest {
		return refuse(fmt.Sprintf("%s has digest %x, not the one given", cfg.Auth.Trust, verified.Digest))
	}
	if err := checkTrustBase(cfg); err != nil {
		return step("8a", err.Error())
	}
	key, err := trustdoc.LoadPrivateKey(cfg.Auth.Key)
	if err != nil {
		return step("8b", err.Error())
	}
	index, err := trustdoc.NewIndex(verified.Payload.Document)
	if err != nil {
		return step("8b", err.Error())
	}
	if err := checkTrustMembership(cfg, key, index); err != nil {
		return step("8b", err.Error())
	}
	replacement := trustdoc.StoreImage{Signed: body, Signer: verified.Key, Verified: &verified, Compromised: image.Compromised}
	encoded, err := trustdoc.EncodeStore(replacement)
	if err != nil {
		return "", err
	}
	if err := replace(path, encoded); err != nil {
		var failure *statefile.ReplaceError
		if !errors.As(err, &failure) {
			return "", err
		}
		stage := "while writing"
		reason := "store unchanged"
		switch failure.Stage {
		case statefile.StageFileSync:
			stage = "at the file sync"
		case statefile.StageRename:
			stage = "at the rename"
		case statefile.StageDirectorySync:
			stage, reason = "at the directory sync", "replacement not durable"
		}
		return "", fmt.Errorf("reset failed %s: config %s, store %s: %s", stage, configPath, path, reason)
	}
	return fmt.Sprintf("reset done: config %s, store %s", configPath, path), nil
}
