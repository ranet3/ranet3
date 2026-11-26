// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/statefile"
	trustdoc "ranet3.com/pkgs/ranet3/trust"
)

func keyFingerprint(der []byte) string {
	digest := sha256.Sum256(der)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func heldAttrs(attrs map[string]string, prefix string, held *TrustHeld) {
	if held == nil {
		return
	}
	attrs[prefix+"height"] = fmt.Sprint(held.Verified.Payload.Height)
	attrs[prefix+"digest"] = hex.EncodeToString(held.Verified.Digest[:])
}

func (r *TrustResult) finishTrust(distributionPath, storePath string, absent bool, floor, entry uint64, before *TrustHeld) {
	if r.Row == trustdoc.D24 && before != nil {
		r.ResetReady, r.ResetWaits = trustReadiness(r.Record.Marker, before, r.NotPersisted)
	}
	if r.FailureStage != "" {
		keys := make([]string, 0, len(r.NotPersisted))
		for _, entry := range r.NotPersisted {
			keys = append(keys, base64.StdEncoding.EncodeToString(entry.Key.DER))
		}
		encoded, _ := json.Marshal(keys)
		r.Events = append(r.Events, TrustEvent{Kind: "trust.persistence_failed", Attrs: map[string]string{
			"stage": string(r.FailureStage), "path": storePath, "keys": string(encoded),
		}})
	}
	attrs := map[string]string{"path": distributionPath}
	refused := func(reason string) {
		attrs["reason"] = reason
		heldAttrs(attrs, "held_", before)
		heldAttrs(attrs, "offered_", r.Offered)
		r.Events = append(r.Events, TrustEvent{Kind: "trust.refused", Attrs: attrs})
		r.Refused = &TrustRefusal{Reason: reason, At: time.Now().UTC()}
		if r.Offered != nil {
			height := r.Offered.Verified.Payload.Height
			r.Refused.Height = &height
			r.Refused.Digest = hex.EncodeToString(r.Offered.Verified.Digest[:])
		}
	}
	switch r.Row {
	case trustdoc.D2, trustdoc.D7, trustdoc.D8, trustdoc.D21:
		if r.Offered != nil {
			attrs["height"] = fmt.Sprint(r.Offered.Verified.Payload.Height)
			attrs["digest"] = hex.EncodeToString(r.Offered.Verified.Digest[:])
			if r.Offered.Verified.Payload.Previous != nil {
				attrs["previous"] = hex.EncodeToString(r.Offered.Verified.Payload.Previous[:])
			}
			r.Events = append(r.Events, TrustEvent{Kind: "trust.accepted", Attrs: attrs})
		}
	case trustdoc.D9:
		attrs["reason"] = "recovery"
		heldAttrs(attrs, "held_", before)
		heldAttrs(attrs, "offered_", r.Offered)
		r.Events = append(r.Events, TrustEvent{Kind: "trust.accepted", Attrs: attrs})
	case trustdoc.D4, trustdoc.D22:
		refused("older")
	case trustdoc.D5, trustdoc.D23:
		reason := "conflict"
		if before != nil && r.Offered != nil && r.Offered.Verified.Payload.Height > before.Verified.Payload.Height {
			reason = "parent"
		}
		refused(reason)
	case trustdoc.D6:
		refused("parent")
	case trustdoc.D12:
		refused("file of another mesh")
	case trustdoc.D11, trustdoc.D13:
		if absent {
			refused("configured file absent")
		} else {
			refused("not verified")
		}
	case trustdoc.D24:
		refused("stored signer compromised")
		attrs["stored_signer"] = keyFingerprint(before.Verified.Key.DER)
		if floor == 0 {
			attrs["floor_status"] = "floor not yet recorded"
		}
		if entry != 0 && before.Verified.Payload.Height > entry {
			attrs["stored_height_status"] = "stored height above the entry's"
		}
		if r.Offered != nil && before.Verified.Payload.Mesh != r.Offered.Verified.Payload.Mesh {
			attrs["file_mesh_status"] = "file of another mesh"
		}
		if r.ResetReady != "" {
			attrs["reset_ready"] = r.ResetReady
		} else {
			attrs["reset_waits"] = r.ResetWaits
		}
	case trustdoc.C1, trustdoc.D16:
		r.Refused = &TrustRefusal{Reason: "config error", At: time.Now().UTC()}
	case trustdoc.D19:
		r.Refused = &TrustRefusal{Reason: "reload error", At: time.Now().UTC()}
	case trustdoc.D15:
		if !(r.Start && r.CanFallback && (r.Decision == trustdoc.D3 || r.Decision == trustdoc.D20)) {
			r.Refused = &TrustRefusal{Reason: r.Failure, At: time.Now().UTC()}
			if r.Offered != nil {
				height := r.Offered.Verified.Payload.Height
				r.Refused.Height = &height
				r.Refused.Digest = hex.EncodeToString(r.Offered.Verified.Digest[:])
			}
		}
	}
	if r.Row == trustdoc.D11 || r.Row == trustdoc.D22 || r.Row == trustdoc.D23 {
		if len(r.Events) != 0 && r.Events[len(r.Events)-1].Kind == "trust.refused" {
			r.Events[len(r.Events)-1].Attrs["stored_signer_status"] = "signer not listed"
		}
	}
	if r.FailureStage != "" && r.Row != trustdoc.D15 && r.Refused == nil {
		r.Refused = &TrustRefusal{Reason: r.Failure, At: time.Now().UTC()}
	}
	if r.FailureStage == "" {
		switch r.Row {
		case trustdoc.D2, trustdoc.D3, trustdoc.D7, trustdoc.D8, trustdoc.D9, trustdoc.D20, trustdoc.D21:
			r.ClearRefusal = true
		}
	}
	if r.Start && (rowRefuses(r.Row, true, before, r.Offered, floor, entry) || r.Row == trustdoc.D15 && !r.CanFallback) {
		r.Events = nil
	}
}

func trustReadiness(marker *TrustMarker, held *TrustHeld, notPersisted []trustdoc.CompromisedKey) (ready, waits string) {
	if marker == nil || !marker.Synced {
		return "", "directory sync owed"
	}
	if !bytes.Equal(marker.Image.Signer.DER, held.Verified.Key.DER) {
		return "", "store's signer is " + keyFingerprint(marker.Image.Signer.DER)
	}
	if _, found := compromisedEntry(notPersisted, held.Verified.Key.DER); found {
		return "", keyFingerprint(held.Verified.Key.DER) + " not persisted"
	}
	return keyFingerprint(held.Verified.Key.DER), ""
}

// TrustStatus is constructed for later rendering, not published to a daemon.
type TrustStatus struct {
	Path          string             `json:"path,omitempty"`
	Height        *uint64            `json:"height,omitempty"`
	Previous      string             `json:"previous,omitempty"`
	Digest        string             `json:"digest,omitempty"`
	Nodes         *int               `json:"nodes,omitempty"`
	Organizations *int               `json:"organizations,omitempty"`
	Shared        *int               `json:"shared,omitempty"`
	ReadAt        string             `json:"read_at,omitempty"`
	Compromised   []TrustCompromised `json:"compromised"`
	NotPersisted  *TrustUnpersisted  `json:"not_persisted,omitempty"`
	Reset         *TrustReset        `json:"reset,omitempty"`
	Refused       *TrustRefusalView  `json:"refused,omitempty"`
}

type TrustCompromised struct {
	Key   string  `json:"key"`
	Floor *uint64 `json:"floor,omitempty"`
	Entry any     `json:"entry"`
}

type TrustUnpersisted struct {
	Keys  []string        `json:"keys"`
	Stage statefile.Stage `json:"stage"`
}

type TrustReset struct {
	Ready string `json:"ready,omitempty"`
	Waits string `json:"waits,omitempty"`
}

type TrustRefusalView struct {
	Reason     string  `json:"reason"`
	At         string  `json:"at"`
	Height     *uint64 `json:"height,omitempty"`
	Digest     string  `json:"digest,omitempty"`
	HeldHeight *uint64 `json:"held_height,omitempty"`
	HeldDigest string  `json:"held_digest,omitempty"`
}

type TrustDebug struct {
	Path          string             `json:"path,omitempty"`
	Height        *uint64            `json:"height,omitempty"`
	Previous      string             `json:"previous,omitempty"`
	Digest        string             `json:"digest,omitempty"`
	Algorithm     string             `json:"algorithm,omitempty"`
	Key           string             `json:"key,omitempty"`
	ReadAt        string             `json:"read_at,omitempty"`
	Nodes         *int               `json:"nodes,omitempty"`
	Organizations *int               `json:"organizations,omitempty"`
	Shared        *int               `json:"shared,omitempty"`
	Document      *trustdoc.Document `json:"document,omitempty"`
	Refused       *TrustRefusalView  `json:"refused,omitempty"`
}

func trustCounts(document trustdoc.Document) (nodes, organizations, shared int) {
	keys := make(map[string]int)
	orgs := make(map[string]struct{})
	for _, node := range document.Nodes {
		nodes++
		name := node.Name
		for i := range name {
			if name[i] == '/' {
				orgs[name[:i]] = struct{}{}
				break
			}
		}
		if node.Key != nil {
			keys[*node.Key]++
		}
	}
	organizations = len(orgs)
	for _, count := range keys {
		if count > 1 {
			shared += count
		}
	}
	return
}
func (r TrustResult) Status(cfg *config.Config) *TrustStatus {
	held := r.Held
	if r.Prepared != nil {
		held = r.Prepared
	}
	if r.Start && r.Row == trustdoc.D24 && held != nil && r.Offered != nil && held.Verified.Payload.Mesh != r.Offered.Verified.Payload.Mesh {
		return nil
	}
	if r.Start && (r.Row == trustdoc.C1 || r.Row == trustdoc.D1 || r.Row == trustdoc.D5 || r.Row == trustdoc.D6 || r.Row == trustdoc.D12 || r.Row == trustdoc.D14 || r.Row == trustdoc.D16 || r.Row == trustdoc.D19 || r.Row == trustdoc.D23 || r.Row == trustdoc.D15 && !r.CanFallback) {
		return nil
	}
	status := &TrustStatus{Path: cfg.Auth.Trust, Compromised: make([]TrustCompromised, 0)}
	if held != nil {
		verified := held.Verified
		height := verified.Payload.Height
		status.Height = &height
		status.Digest = hex.EncodeToString(verified.Digest[:])
		if previous := verified.Payload.Previous; previous != nil {
			status.Previous = hex.EncodeToString(previous[:])
		}
		nodes, orgs, shared := trustCounts(verified.Payload.Document)
		status.Nodes, status.Organizations, status.Shared = &nodes, &orgs, &shared
		status.ReadAt = held.ReadAt.UTC().Format(time.RFC3339)
	}
	if r.Record != nil {
		for _, item := range r.Record.List {
			entry := TrustCompromised{Key: base64.StdEncoding.EncodeToString(item.Key.DER), Entry: "removed"}
			if item.Floor != 0 {
				floor := item.Floor
				entry.Floor = &floor
			}
			for _, configured := range cfg.Auth.Revoked {
				if configured.Key == entry.Key {
					entry.Entry = configured.Height
					break
				}
			}
			status.Compromised = append(status.Compromised, entry)
		}
	}
	if r.FailureStage != "" {
		keys := make([]string, 0, len(r.NotPersisted))
		for _, entry := range r.NotPersisted {
			keys = append(keys, base64.StdEncoding.EncodeToString(entry.Key.DER))
		}
		status.NotPersisted = &TrustUnpersisted{Keys: keys, Stage: r.FailureStage}
	}
	if r.Row == trustdoc.D24 {
		status.Reset = &TrustReset{Ready: r.ResetReady, Waits: r.ResetWaits}
	}
	if r.Refused != nil {
		status.Refused = &TrustRefusalView{Reason: r.Refused.Reason, At: r.Refused.At.UTC().Format(time.RFC3339), Height: r.Refused.Height, Digest: r.Refused.Digest}
	}
	return status
}

func (r TrustResult) Debug(cfg *config.Config) *TrustDebug {
	status := r.Status(cfg)
	if status == nil {
		return nil
	}
	held := r.Held
	if r.Prepared != nil {
		held = r.Prepared
	}
	debug := &TrustDebug{
		Path: status.Path, Height: status.Height, Previous: status.Previous,
		Digest: status.Digest, ReadAt: status.ReadAt, Nodes: status.Nodes,
		Organizations: status.Organizations, Shared: status.Shared, Refused: status.Refused,
	}
	if held != nil {
		switch held.Verified.Key.Algorithm {
		case -19:
			debug.Algorithm = "Ed25519"
		case -9:
			debug.Algorithm = "ESP256"
		case -51:
			debug.Algorithm = "ESP384"
		}
		debug.Key = keyFingerprint(held.Verified.Key.DER)
		debug.Document = &held.Verified.Payload.Document
		if debug.Refused != nil {
			height := held.Verified.Payload.Height
			debug.Refused.HeldHeight = &height
			debug.Refused.HeldDigest = hex.EncodeToString(held.Verified.Digest[:])
		}
	}
	return debug
}

// ApplyFailure records a supplied pre-publication stage, without performing it.
func (r *TrustResult) ApplyFailure(stage string) {
	if stage != "retable" && stage != "reborder" {
		return
	}
	r.Row = trustdoc.D15
	r.ClearRefusal = false
	r.Prepared = nil
	r.CanFallback = false
	r.Failure = "apply failed: " + stage
	r.Refused = &TrustRefusal{Reason: r.Failure, At: time.Now().UTC()}
	if r.Offered != nil {
		height := r.Offered.Verified.Payload.Height
		r.Refused.Height = &height
		r.Refused.Digest = hex.EncodeToString(r.Offered.Verified.Digest[:])
	}
	r.Events = slices.DeleteFunc(r.Events, func(event TrustEvent) bool {
		return event.Kind == "trust.accepted"
	})
}
