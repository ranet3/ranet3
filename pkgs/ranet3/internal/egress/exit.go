// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package egress

import (
	"context"
	"net/netip"
	"time"

	"ranet3.com/pkgs/ranet3/internal/events"
)

// Exit carries other nodes' traffic out of the mesh: the packets of the
// prefixes cap.egress advertises that count as a default and those of the
// egress segments, each family announced only while it is ready. The daemon
// starts, stops, enables, announces through and reports from it, and both
// egress verdicts of the dataplane hand it their batches.
type Exit interface {
	// Run carries until ctx ends, then returns once readiness has gone false
	// in both families, the announcement has been published empty and the
	// backend holds nothing. It is called once, and its error is the
	// withdrawal's.
	Run(ctx context.Context) error
	// SetEnabled withdraws everything while Run runs, in the order Run's end
	// takes, and restores it, for a node taken off the mesh and put back. It
	// returns before the backend has caught up, which Status then reports.
	SetEnabled(on bool)
	// Egress takes the packets a verdict decided to egress, all of them in
	// families Ready last named ready and those through an advertised prefix
	// also in families Announce last answered. The caller has read the
	// family's readiness first, so Egress judges none.
	//
	// Every backend takes concurrent calls, one from each session's receive
	// path. Each frame is TUNHeadroom bytes of internal/netstack that a tun
	// write may overwrite and then the packet to the frame's end, and the
	// frames are the exit's from the call on the terms the mesh's
	// DeliverInboundBatch states for itself: until written, or copied before
	// the call returns.
	Egress(frames [][]byte)
	// Announce is the advertised prefixes of the families ready now, and
	// nothing before the first pass
	Announce() []netip.Prefix
	// Status answers the status and the debug views
	Status() Status
}

// Hooks are the calls every backend reports through, which each backend's
// constructor takes
type Hooks struct {
	// Ready receives each family's readiness, and whether the egress SIDs are
	// served, whenever one of the three moves, starting from none. A family is
	// reported not ready before what carries it is withdrawn. Nil where nothing
	// reads it, which only a test does.
	Ready func(v4, v6, serves bool)
	// Republish says that Announce has moved, once per move, Run's end
	// moving it to empty. Nil where nothing announces, which only a test does.
	Republish func()
	// Events records every pass that rewrote what the backend holds, moved
	// the announcement or failed, nil records nothing
	Events *events.Bus
}

// Status is the report every backend gives, with a detail of its own
type Status struct {
	// Backend names the backend, and Where the space it owns on the host
	Backend, Where string
	// Ready4 and Ready6 are each family's readiness. Unready says why a
	// family the backend carries is not ready, and Skipped what its readiness
	// lookups left out and why, each empty where there is nothing to say
	Ready4, Ready6   bool
	Unready, Skipped string
	// Advertise is the prefixes the capability advertises, and Announced
	// those of the families ready at the last pass
	Advertise, Announced []netip.Prefix
	// Translate and Return are the capability's translation
	Translate []Class
	Return    bool
	// PassAt is the last pass, zero before the first, and Err its error
	PassAt time.Time
	Err    string
	// Rules is the detail of a backend that installs rules in the host's
	// packet filter, nil for one that holds none
	Rules *Rules
}

// Rules is the rules a backend installed, as its last pass read them back
type Rules struct {
	Installed int
	// Flows counts the connections the rules have translated, and Bytes the
	// first packet of each, since a translation rule is consulted once per
	// connection. Untranslated counts those the rules of a class of none bound
	// to the source they carry.
	Flows, Bytes, Untranslated uint64
	// Conflicts names the other source translation on the host this node's
	// traffic can meet
	Conflicts []string
}
