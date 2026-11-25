// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"net/netip"
	"slices"
)

// SourcedAnswer names a destination subrange and an optional source subrange.
// An invalid From means the local, source-unselected baseline for To.
// Protection records an installed refusal independently of packet carriage.
type SourcedAnswer struct {
	To           netip.Prefix
	From         netip.Prefix
	Kind         string
	MainPrefix   netip.Prefix
	MainProtocol uint8
	Protection   bool
}

// SourcedStatus is an immutable observation of kernel admission, not a
// prediction from a requested configuration. State is active, limited,
// pending, failing or withdrawn. An Error makes every unknown answer explicit.
type SourcedStatus struct {
	Named, Supported, Pairs, Rules int
	Limited                        bool
	State, Error                   string
	Answers                        []SourcedAnswer
}

// SourcedStatus returns a detached copy so a status reader cannot mutate a
// subsequent change comparison or another reader's view.
func (r *Reconciler) SourcedStatus() (SourcedStatus, bool) {
	current := r.sourcedStatus.Load()
	if current == nil {
		return SourcedStatus{}, false
	}
	copy := *current
	copy.Answers = slices.Clone(current.Answers)
	return copy, true
}

// SourcedChanges reports changed answers, protection, counts, capacity or
// failure state. It is nil until a sourced key has been accepted.
func (r *Reconciler) SourcedChanges() <-chan struct{} {
	if channel := r.sourcedChanged.Load(); channel != nil {
		return *channel
	}
	return nil
}

func (r *Reconciler) publishSourced(next SourcedStatus) {
	previous := r.sourcedStatus.Load()
	if previous != nil && previous.Named == next.Named && previous.Supported == next.Supported &&
		previous.Pairs == next.Pairs && previous.Rules == next.Rules && previous.Limited == next.Limited &&
		previous.State == next.State && previous.Error == next.Error && slices.Equal(previous.Answers, next.Answers) {
		return
	}
	r.sourcedStatus.Store(&next)
	if channel := r.sourcedChanged.Load(); channel != nil {
		select {
		case *channel <- struct{}{}:
		default:
		}
	}
}

func (r *Reconciler) sourcedFailure(err error) {
	if err == nil || r.table.Sourced == nil {
		return
	}
	previous := r.sourcedStatus.Load()
	status := SourcedStatus{Named: len(r.table.Sourced.To), Supported: len(r.sourcedSources),
		Pairs: len(r.table.Sourced.To) * len(r.sourcedSources), Limited: r.sourcedLimited,
		State: "failing", Error: err.Error()}
	if previous != nil {
		status.Rules = previous.Rules
	}
	for _, destination := range r.table.Sourced.To {
		status.Answers = append(status.Answers, SourcedAnswer{To: destination.Prefix, Kind: "unknown"})
	}
	r.publishSourced(status)
}
