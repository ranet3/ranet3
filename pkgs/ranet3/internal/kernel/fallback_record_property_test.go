// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package kernel

import (
	"errors"
	"slices"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// the steps of the record's property: a pass, another writer's change of the
// switch, which only a reading monitor reports, a loss the monitor reports,
// the monitor stopping, the host's network moving the switch's sets, the
// switch's reads or writes starting or stopping to fail, and its last lines
// dropping a packet
const (
	recordPass = iota
	recordChange
	recordLoss
	recordStop
	recordMove
	recordReadFails
	recordWriteFails
	recordDrop
	recordSteps
)

// recordWeights is how often each step is drawn against the others: a pass
// most and a move of the sets next, so that a pass a route change alone wakes
// often meets sets that moved and nothing else, and a stop, which lasts for
// the rest of the case, as seldom as any
var recordWeights = [recordSteps]int{recordPass: 8, recordChange: 1, recordLoss: 1, recordStop: 1, recordMove: 4, recordReadFails: 1, recordWriteFails: 1, recordDrop: 1}

// recordStep is the step drawn at pick, a number below the sum of recordWeights
func recordStep(pick int) int {
	for step, weight := range recordWeights {
		if pick < weight {
			return step
		}
		pick -= weight
	}
	return recordPass
}

// recordRun is a reconciler on a fake, its switch watched by a monitor or not
type recordRun struct {
	r       *Reconciler
	fake    *fakeKernel
	network *hostNetwork
}

// recordCaseSteps is the most steps a case of the record's property takes
const recordCaseSteps = 40

// Over sequences of passes, monitor reports and faults, a reconciler whose
// switch a monitor watches skips the read of it exactly where the pass was
// woken by a route change alone, the monitor still reads, it reported nothing
// since the last read began, the switch's sets are those of that read, and
// that read found the switch as written. At each pass that reads, it reports
// the switch as a reconciler reading it on every pass does, the drops of a read
// that fails aside, which each keeps from its own last read.
func TestFallbackKeepsTheLastReadOnlyWhereNothingItReadsMoved(t *testing.T) {
	// the triggers Run names for a route change alone
	routeTriggers := []string{"mesh", "kernel"}
	hosts := []NetworkState{recordHost, recordMovedHost}
	weights := 0
	for _, weight := range recordWeights {
		weights += weight
	}
	pbt.Check(t, func(ht *hegel.T) {
		recorded, watched, recordedNetwork := watchedHarness(t)
		plain := recordRun{network: &hostNetwork{state: recordHost}}
		plain.r, plain.fake = unwatchedHarness(t, plain.network)
		runs := []recordRun{{recorded, watched.fakeKernel, recordedNetwork}, plain}
		// the model of the record: what the monitor reported since the last read began, whether it stopped, and the host and
		// the outcome of the last read
		reported, stopped, readHost, readClean, host := false, false, 0, true, 0
		for step := range hegel.Draw(ht, pbt.Spanning(1, recordCaseSteps)) {
			switch recordStep(hegel.Draw(ht, pbt.Spanning(0, weights-1))) {
			case recordPass:
				// a route change alone wakes half the passes
				pool := readingTriggers
				if hegel.Draw(ht, pbt.Spanning(0, 1)) == 0 {
					pool = routeTriggers
				}
				trigger := pool[hegel.Draw(ht, pbt.Spanning(0, len(pool)-1))]
				skips := slices.Contains(routeTriggers, trigger) && !stopped && !reported && host == readHost && readClean
				reported = false
				reads, _ := watched.pass(recorded, trigger)
				plain.r.trigger = trigger
				_ = plain.r.reconcile()
				if (reads == 0) != skips {
					ht.Fatalf("step %d, a pass woken by %s read the switch %d times, where the model skips %t (stopped %t, reported since the last read, host %d against %d, last read clean %t)",
						step, trigger, reads, skips, stopped, host, readHost, readClean)
				}
				if reads == 0 {
					continue
				}
				got, want := *recorded.Stats().Exit.Fallback, *plain.r.Stats().Exit.Fallback
				if watched.failFallback != nil {
					got.Dropped, got.DroppedBytes, want.Dropped, want.DroppedBytes = 0, 0, 0, 0
				}
				if got.State != want.State || got.Fault != want.Fault || got.Dropped != want.Dropped || got.DroppedBytes != want.DroppedBytes || got.DropsRead != want.DropsRead {
					ht.Fatalf("step %d, a pass woken by %s that read the switch reported %+v, where one reading on every pass reported %+v", step, trigger, got, want)
				}
				readHost, readClean = host, got.Fault == ""
			case recordChange:
				for _, run := range runs {
					run.fake.mu.Lock()
					run.fake.fallback = nil
					run.fake.mu.Unlock()
				}
				reported = reported || !stopped
				if !stopped {
					watched.rec.moved.Store(true)
				}
			case recordLoss:
				reported = reported || !stopped
				if !stopped {
					watched.rec.moved.Store(true)
				}
			case recordStop:
				stopped, watched.stopped = true, true
			case recordMove:
				host = 1 - host
				for _, run := range runs {
					run.network.set(hosts[host])
				}
			case recordReadFails:
				for _, run := range runs {
					run.fake.failFallback = toggled(run.fake.failFallback, "netlink: dump interrupted")
				}
			case recordWriteFails:
				for _, run := range runs {
					run.fake.failWrite = toggled(run.fake.failWrite, "netlink: write refused")
				}
			case recordDrop:
				for _, run := range runs {
					run.fake.fallbackDropped++
				}
			}
		}
	})
}

// toggled is nil where err is set, and an error saying what otherwise
func toggled(err error, what string) error {
	if err != nil {
		return nil
	}
	return errors.New(what)
}
