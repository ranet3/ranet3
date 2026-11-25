// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package kernel

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"ranet3.com/pkgs/ranet3/schema"
)

type sourcedReloadState struct {
	table     schema.TableID
	addresses []netip.Prefix
	routes    []Route
	rules     []Rule
	mirror    []Route
	admission []DumpedRule
	owned     map[netip.Prefix]bool
}

func (r *Reconciler) readSourcedReloadState(id schema.TableID) (sourcedReloadState, error) {
	state := sourcedReloadState{table: id, owned: maps.Clone(r.owned)}
	var err error
	if state.addresses, err = r.plat.Addrs(); err != nil {
		return sourcedReloadState{}, fmt.Errorf("read tun addresses before sourced reload: %w", err)
	}
	if state.routes, err = r.plat.Routes(); err != nil {
		return sourcedReloadState{}, fmt.Errorf("read ordinary routes before sourced reload: %w", err)
	}
	if r.rules == nil {
		return sourcedReloadState{}, errors.New("read ordinary rules before sourced reload: rule reader unavailable")
	}
	if state.rules, err = r.rules.Rules(); err != nil {
		return sourcedReloadState{}, fmt.Errorf("read ordinary rules before sourced reload: %w", err)
	}
	reader, ok := r.plat.(interface {
		SourcedRoutes(schema.TableID) ([]Route, int, error)
		SourcedRules() ([]DumpedRule, error)
	})
	if !ok {
		return sourcedReloadState{}, errors.New("read sourced policy before reload: policy reader unavailable")
	}
	var foreign int
	if state.mirror, foreign, err = reader.SourcedRoutes(id); err != nil {
		return sourcedReloadState{}, fmt.Errorf("read sourced mirror before reload: %w", err)
	}
	if foreign != 0 {
		return sourcedReloadState{}, fmt.Errorf("sourced table %d holds %d foreign routes before reload", id, foreign)
	}
	if state.admission, err = reader.SourcedRules(); err != nil {
		return sourcedReloadState{}, fmt.Errorf("read sourced rules before reload: %w", err)
	}
	state.addresses = slices.Clone(state.addresses)
	state.routes = slices.Clone(state.routes)
	state.rules = slices.Clone(state.rules)
	state.mirror = slices.Clone(state.mirror)
	state.admission = slices.Clone(state.admission)
	return state, nil
}

func sameSourcedMembers[T comparable](before, after []T) bool {
	if len(before) != len(after) {
		return false
	}
	remaining := make(map[T]int, len(before))
	for _, value := range before {
		remaining[value]++
	}
	for _, value := range after {
		if remaining[value] == 0 {
			return false
		}
		remaining[value]--
	}
	return true
}

func (r *Reconciler) verifySourcedReloadState(state sourcedReloadState) error {
	actual, err := r.readSourcedReloadState(state.table)
	if err != nil {
		return err
	}
	if !sameSourcedMembers(state.addresses, actual.addresses) ||
		!sameSourcedMembers(state.routes, actual.routes) ||
		!sameSourcedMembers(state.rules, actual.rules) ||
		!sameSourcedMembers(state.mirror, actual.mirror) ||
		!sameSourcedMembers(state.admission, actual.admission) || !maps.Equal(state.owned, actual.owned) {
		return errors.New("owned routes, rules, mirror or tun addresses differ from the old policy")
	}
	return nil
}

func (r *Reconciler) restoreSourcedReload(previous error) error {
	state := r.reloadState
	var restoreErr error
	if r.reloadPrevious.table.Sourced == nil && r.table.Sourced != nil {
		// A rejected first key may have installed standing protection and
		// mirrors. Unknown ownership leaves protection in place instead of
		// deleting a foreign lookalike.
		if remove, ok := r.plat.(interface{ removeSourcedKey(*Reconciler) error }); ok {
			restoreErr = remove.removeSourcedKey(r)
		} else {
			restoreErr = errors.New("sourced withdrawal is unavailable on this platform")
		}
	}
	r.restoreReload()
	r.trigger = "reload restore"
	if r.enabled.Load() {
		restoreErr = errors.Join(restoreErr, r.reconcile())
	} else {
		withdrawErr := r.withdraw(errStopped)
		if withdrawErr == nil {
			withdrawErr = r.observeSourced(nil)
		}
		restoreErr = errors.Join(restoreErr, withdrawErr)
	}
	readErr := r.verifySourcedReloadState(*state)
	r.reloadState = nil
	if restoreErr != nil || readErr != nil {
		degraded := fmt.Errorf("kernel: sourced reload failed and owned kernel state could not be restored: %w", errors.Join(previous, restoreErr, readErr))
		if r.sourcedUnverified == nil {
			if r.table.Sourced == nil {
				r.publishSourced(SourcedStatus{State: "failing", Error: degraded.Error()})
			} else {
				r.sourcedFailure(degraded)
			}
			r.sourcedUnverified = state
		}
		return degraded
	}
	return previous
}
