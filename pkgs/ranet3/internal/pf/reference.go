// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package pf

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"

	"ranet3.com/pkgs/ranet3/internal/statefile"
)

// Reference is this daemon's reference on pf, which keeps pf enabled while any
// reference is held, and the record of its token. A token outlives the
// process that took it, so the record is the only claim a later run makes on
// it. pf gives a freed token's value to later references of any process, so a
// recorded token counts as the recorded reference only where pf lists it under
// the pid the record holds beside it, and none is released for its value or
// its name alone.
type Reference struct {
	ctl   Ctl
	path  string
	lock  *statefile.Lock
	start func() (uint64, error)
	token uint64
	pid   int
	// inherited is whether the take found a reference an earlier run left
	// that pf still listed under its pid, whose place this one took
	inherited bool
}

// held is one reference as the record holds it: its token, as a string since
// it uses all 64 bits, and the pid of the process that took it, which pf lists
// it under
type held struct {
	Token uint64 `json:"token,string"`
	PID   int    `json:"pid"`
}

// referenceRecord is the record: the reference this run holds first, and
// while a take gives them back, those an earlier run left
type referenceRecord struct {
	Held []held `json:"held,omitempty"`
}

// take claims the record at path, takes a new reference through start and
// records it beside those an earlier run recorded there before it gives those
// back, so pf stays enabled throughout where they kept it so, and a process
// killed after the record's write leaves its token recorded
func take(ctl Ctl, path string, start func() (uint64, error)) (*Reference, error) {
	lock, err := statefile.Take(path)
	if err != nil {
		return nil, err
	}
	r := &Reference{ctl: ctl, path: path, lock: lock, start: start, pid: os.Getpid()}
	if r.inherited, err = r.renew(loadEarlier(path)); err != nil {
		return nil, errors.Join(err, lock.Close())
	}
	return r, nil
}

// Renew takes a new reference in place of this process's, which pf no longer
// lists once pfctl -d or another program's pfctl -X ended it, and records it
func (r *Reference) Renew() error {
	_, err := r.renew([]held{{Token: r.token, PID: r.pid}})
	return err
}

// renew takes a new reference and records it beside earlier, then gives back
// each of earlier that pf lists under its pid, records the new one alone, and
// reports whether pf listed any of earlier. One of earlier that pf no longer
// lists so was ended, and its value may be another process's reference now,
// so it is dropped unreleased. One pf refuses to give back stays recorded
// beside the new one for the next start, and fails the renewal.
func (r *Reference) renew(earlier []held) (bool, error) {
	token, err := r.start()
	if err != nil {
		return false, fmt.Errorf("pf: take a reference: %w", err)
	}
	now := held{Token: token, PID: r.pid}
	if err := saveReference(r.path, append([]held{now}, earlier...)); err != nil {
		// a token no record holds would outlive a crash, so it goes back now
		_, released := r.release(now)
		return false, errors.Join(fmt.Errorf("pf: record the reference: %w", err), released)
	}
	r.token = token
	if len(earlier) == 0 {
		return false, nil
	}
	// the value and the pid of an ended reference may both have come back as the new one's
	kept, listed, refused := r.giveBack(slices.DeleteFunc(slices.Clone(earlier), func(e held) bool { return e == now }))
	return listed, errors.Join(saveReference(r.path, append([]held{now}, kept...)), refused)
}

// giveBack gives back each of earlier that pf lists under its pid, and
// returns those pf refused, whether pf listed any, and the refusals
func (r *Reference) giveBack(earlier []held) ([]held, bool, error) {
	var kept []held
	var refused error
	listed := false
	for _, e := range earlier {
		released, err := r.release(e)
		switch {
		case err != nil:
			kept, refused, listed = append(kept, e), errors.Join(refused, err), true
		case released:
			listed = true
			slog.Info("pf released the reference an earlier run left", "token", e.Token, "pid", e.PID)
		default:
			slog.Info("pf dropped the record of a reference it no longer lists under its pid, which a reboot or another program stopping pf ends", "token", e.Token, "pid", e.PID)
		}
	}
	if refused != nil {
		refused = fmt.Errorf("pf: release the recorded reference: %w", refused)
	}
	return kept, listed, refused
}

// Clear gives back what an earlier run left, where this run takes no
// reference: where the record at path holds any reference, it empties anchor,
// gives back each reference pf lists under its recorded pid and records those
// pf refused, and it reports whether pf listed any, which a reboot leaves it
// listing none of. A record that holds none leaves pf alone, so a host that
// never ran the filter runs no pfctl.
func Clear(ctl Ctl, path, anchor string) (bool, error) {
	lock, err := statefile.Take(path)
	if err != nil {
		return false, err
	}
	earlier := loadEarlier(path)
	if len(earlier) == 0 {
		return false, lock.Close()
	}
	if err := ctl.Withdraw(anchor); err != nil {
		return false, errors.Join(err, lock.Close())
	}
	r := &Reference{ctl: ctl, path: path, lock: lock}
	kept, listed, refused := r.giveBack(earlier)
	return listed, errors.Join(saveReference(path, kept), refused, lock.Close())
}

// Inherited reports whether the take found a reference an earlier run left
// that pf still listed under its pid, so that this one now keeps pf enabled
// in its place
func (r *Reference) Inherited() bool {
	return r.inherited
}

// Token is the reference pf lists for this process
func (r *Reference) Token() uint64 {
	return r.token
}

// PID is the process pf lists the reference under, the one that took it
func (r *Reference) PID() int {
	return r.pid
}

// Release gives the reference back, which stops pf when no other holder
// remains, empties the record and lets go of it. A release pf refuses for a
// token it still lists keeps the record, so the next start tries again.
func (r *Reference) Release() error {
	if r.token != 0 {
		if _, err := r.release(held{Token: r.token, PID: r.pid}); err != nil {
			return err
		}
		r.token = 0
		if err := saveReference(r.path, nil); err != nil {
			return err
		}
	}
	return r.lock.Close()
}

// Close lets go of the record and keeps the reference held and recorded, so
// pf stays enabled after this process and the next start over the record
// gives the reference back
func (r *Reference) Close() error {
	return r.lock.Close()
}

// release gives back h where pf lists its token under its pid, and reports
// whether it did. A token pf does not list so was ended, by a reboot or by
// pfctl -d, which end every reference, or by another program's pfctl -X.
func (r *Reference) release(h held) (bool, error) {
	if listed, err := r.lists(h); err != nil || !listed {
		return false, err
	}
	if err := r.ctl.Release(h.Token); err != nil {
		// a refusal of a token pf no longer lists lost the race with its end
		if listed, listErr := r.lists(h); listErr != nil || listed {
			return false, errors.Join(err, listErr)
		}
		return false, nil
	}
	return true, nil
}

// lists reports whether pf lists h's token under h's pid
func (r *Reference) lists(h held) (bool, error) {
	enablers, err := r.ctl.References()
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(enablers, func(e Enabler) bool { return e.Token == h.Token && e.PID == h.PID }), nil
}

// loadEarlier reads the references an earlier run recorded at path, and warns
// of a record it cannot read, which then holds none
func loadEarlier(path string) []held {
	earlier, err := loadReference(path)
	if err != nil {
		slog.Warn("pf could not read the reference an earlier run recorded",
			"path", path, "err", err,
			"detail", "a reference that run left stays held until a reboot")
	}
	return earlier
}

// loadReference reads the references an earlier run recorded. A file that is
// absent holds none, and one that will not parse holds none and an error the
// caller reports.
func loadReference(path string) ([]held, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pf: read %s: %w", path, err)
	}
	var record referenceRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("pf: parse %s: %w", path, err)
	}
	return record.Held, nil
}

// saveReference records references at path, none for an empty list
func saveReference(path string, references []held) error {
	raw, err := json.Marshal(referenceRecord{Held: references})
	if err != nil {
		return err
	}
	return statefile.Write(path, raw)
}
