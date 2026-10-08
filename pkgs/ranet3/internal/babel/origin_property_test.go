// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package babel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// originSteps is the longest run of moves one case makes, which keeps every seqno of a case within 32768 of the others
const originSteps = 12

// the moves a case draws, by index
const (
	// originStart ends the running process, where one runs, and starts the next from what the disk holds
	originStart = iota
	// originCrash ends the running process, which writes nothing, as a clean stop writes nothing
	originCrash
	// originRun runs the speaker of the running process again, as ranet3 down and up do after its first run
	originRun
	// originRequests answers a drawn number of seqno requests asking past the seqno in use, one per packet
	originRequests
	// originToLimit answers such requests until the seqno in use is the limit on the disk itself
	originToLimit
	// originStale answers a request asking for the seqno in use, which raises nothing
	originStale
	originMoves
)

var originMoveNames = [originMoves]string{"start", "crash", "run", "requests", "requests up to the limit", "stale request"}

// what a save the speaker asks for does, by index
const (
	saveWritten = iota
	// saveFailed writes nothing and says so, as a full or read-only disk does
	saveFailed
	// saveCrashedBefore ends the process before the limit reaches the disk
	saveCrashedBefore
	// saveCrashedAfter ends the process with the limit on the disk, before the seqno it covers is used
	saveCrashedAfter
	saveOutcomes
)

var (
	// originPrefix is the prefix the node originates and is asked for seqnos of
	originPrefix = netip.MustParsePrefix("fd00:5::/64")
	// originRouterID is the router id a disk drawn at the start of a case holds
	originRouterID = [8]byte{0x72, 0x61, 0x6e, 0x65, 0x74, 0x33, 0, 1}
	// errDiskFull comes back from a failed save
	errDiskFull = errors.New("no space left on device")
)

// a save that ends its process panics with crash
type crash struct{}

// before is the order of RFC 8966 section 3.2.1 as the section writes it, s < later
func before(s, later uint16) bool {
	gap := (int(later) - int(s)) & 0xffff
	return 0 < gap && gap < 32768
}

// originDisk is the state file as persist sees it, each save written, failed or crashed as the case draws
type originDisk struct {
	ht    *hegel.T
	saved *Origin
	// failed is whether a save failed during the step running, the one way a seqno past the limit on the disk comes into use
	failed bool
}

func (d *originDisk) save(origin Origin) error {
	switch hegel.Draw(d.ht, pbt.Spanning(0, saveOutcomes-1)) {
	case saveWritten:
		d.saved = &origin
	case saveFailed:
		d.failed = true
		return errDiskFull
	case saveCrashedBefore:
		panic(crash{})
	case saveCrashedAfter:
		d.saved = &origin
		panic(crash{})
	}
	return nil
}

// originProcess is one process of the node, its speaker originating originPrefix and a neighbor asking it for seqnos
type originProcess struct {
	speaker  *Speaker
	neighbor *neighborState
	ran      bool
}

// originRig is the node across its processes, with every seqno each of its router ids has had in use
type originRig struct {
	ht      *hegel.T
	disk    *originDisk
	process *originProcess
	// asker is the session the last start's speaker holds, which the next start closes
	asker *netstack.Peer
	inUse map[[8]byte][]uint16
	done  []string
}

func (r *originRig) fail(format string, args ...any) {
	r.ht.Fatalf("after %s: %s", strings.Join(r.done, ", "), fmt.Sprintf(format, args...))
}

// survives runs one step of the process, reporting false where a save ended the process inside it
func (r *originRig) survives(step func()) (survived bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if _, ended := recovered.(crash); !ended {
				panic(recovered)
			}
			r.process = nil
		}
	}()
	r.disk.failed = false
	step()
	return true
}

// start begins the next process from the disk, as the client hands SetOrigin what the file holds
func (r *originRig) start() {
	r.process = nil
	disk := r.disk.saved
	from := Origin{}
	if disk != nil {
		from = *disk
	}
	speaker, err := New(Config{}, Routes{}, Runtime{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		r.ht.Fatalf("%v", err)
	}
	speaker.Originate(originPrefix)
	if r.asker != nil {
		r.asker.Close()
	}
	r.asker = netstack.NewPeerReserved("asker", plainSealer, func([][]byte) error { return nil }, nil)
	speaker.AddPeer(r.asker)
	if !r.survives(func() { speaker.SetOrigin(from, r.disk.save, "") }) {
		return
	}
	r.process = &originProcess{speaker: speaker, neighbor: speaker.neighbors[r.asker.ID]}
	origin, seqno := speaker.Origin()
	if from.RouterID != ([8]byte{}) && origin.RouterID != from.RouterID {
		r.fail("the start advertises router id %x, and the disk holds %x", origin.RouterID, from.RouterID)
	}
	r.started(origin.RouterID, seqno, disk)
}

// run runs the speaker again with its context already done, and the run makes its start and returns
func (r *originRig) run() {
	p, disk := r.process, r.disk.saved
	_, held := p.speaker.Origin()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !r.survives(func() { _ = p.speaker.Run(ctx) }) {
		return
	}
	first := !p.ran
	p.ran = true
	origin, seqno := p.speaker.Origin()
	if first {
		if seqno != held {
			r.fail("the first run moved the seqno from %d to %d, after the start of its process", held, seqno)
		}
		return
	}
	r.started(origin.RouterID, seqno, disk)
}

// started checks the first seqno of a start against every seqno its router id had in use before
// disk is the saved origin as the start began, nil where there was none
// a seqno a failed save left past the limit on the disk is the one exception, and the start owes nothing to what came before it
func (r *originRig) started(id [8]byte, seqno uint16, disk *Origin) {
	if disk == nil || disk.RouterID != id || slices.ContainsFunc(r.inUse[id], func(s uint16) bool { return before(disk.Limit, s) }) {
		r.inUse[id] = nil
	}
	for _, s := range r.inUse[id] {
		if !before(s, seqno) {
			r.fail("a start under %x uses seqno %d after %d was in use, with the disk holding %+v", id, seqno, s, disk)
		}
	}
	r.use(id, seqno)
}

// use records a seqno a step brought into use, which the limit on the disk covers unless the save for it failed
func (r *originRig) use(id [8]byte, seqno uint16) {
	r.inUse[id] = append(r.inUse[id], seqno)
	if saved := r.disk.saved; !r.disk.failed && (saved == nil || saved.RouterID != id || before(saved.Limit, seqno)) {
		r.fail("seqno %d is in use under %x, the disk holds %+v and no save failed", seqno, id, saved)
	}
}

// request delivers one seqno request asking for the seqno in use and ahead more, reporting false where the process ended
func (r *originRig) request(ahead uint16) bool {
	p := r.process
	origin, held := p.speaker.Origin()
	packet := EncodePacket([]RawTLV{EncodeSeqnoRequest(SeqnoRequest{
		AE: AEIPv6, Prefix: originPrefix, Seqno: held + ahead, HopCount: 64, RouterID: origin.RouterID})})
	if !r.survives(func() { p.speaker.handlePacket(p.neighbor, packet) }) {
		return false
	}
	_, seqno := p.speaker.Origin()
	if want := held + min(ahead, 1); seqno != want {
		r.fail("a request for seqno %d moved the seqno from %d to %d, want %d", held+ahead, held, seqno, want)
	}
	if seqno != held {
		r.use(origin.RouterID, seqno)
	}
	return true
}

// toLimit asks until the seqno in use is the limit on the disk, where the disk covers it
func (r *originRig) toLimit() {
	for range seqnoLimitAhead + 1 {
		origin, seqno := r.process.speaker.Origin()
		saved := r.disk.saved
		if saved == nil || saved.RouterID != origin.RouterID || !before(seqno, saved.Limit) {
			return
		}
		if !r.request(1) {
			return
		}
	}
}

// for any run of starts, crashes, runs and seqno requests, each save written, failed or ending the process before or after its write
// the first seqno of each start is past every seqno its router id had in use before, unless a failed save left one past the disk
// a seqno in use is never past the limit on the disk, unless the save for it failed
// a start from the disk advertises the router id it holds
func TestSeqnoOutlivesEveryStartAndCrash(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		r := &originRig{ht: ht, disk: &originDisk{ht: ht}, inUse: map[[8]byte][]uint16{}}
		if hegel.Draw(ht, pbt.Spanning(0, 1)) == 1 {
			r.disk.saved = &Origin{RouterID: originRouterID, Limit: uint16(hegel.Draw(ht, pbt.Spanning(0, 65535)))}
		}
		r.start()
		defer func() { r.asker.Close() }()
		for range hegel.Draw(ht, pbt.Spanning(1, originSteps)) {
			move := hegel.Draw(ht, pbt.Spanning(0, originMoves-1))
			if r.process == nil {
				move = originStart
			}
			r.done = append(r.done, originMoveNames[move])
			switch move {
			case originStart:
				r.start()
			case originCrash:
				r.process = nil
			case originRun:
				r.run()
			case originRequests:
				for range hegel.Draw(ht, pbt.Spanning(1, 2*seqnoLimitAhead)) {
					if !r.request(1) {
						break
					}
				}
			case originToLimit:
				r.toLimit()
			case originStale:
				r.request(0)
			}
		}
	})
}
