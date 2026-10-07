// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package transport

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

type roamingFamily struct {
	local  []string
	peers  []string
	header int
}

var roamingFamilies = map[bool]roamingFamily{
	true: {
		local:  []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		peers:  []string{"198.51.100.1:4500", "198.51.100.1:4501", "198.51.100.2:4500"},
		header: 20 + 8,
	},
	false: {
		local:  []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"},
		peers:  []string{"[2001:db8:7::1]:4500", "[2001:db8:7::1]:4501", "[2001:db8:7::2]:4500"},
		header: 40 + 8,
	},
}

var roamingLinks = []int{2, 3}

// only the largest exceeds a 1280 path once segmented
// it comes first, since SampledFrom leans toward its first element
var roamingSizes = []int{1400, 64, 1200}

var roamingMTUs = []int{1280, defaultPathMTU, 9000}

// roamingWaits are whole minutes, so a wait lands a minute either side of a stop's lapse or on it
var roamingWaits = []time.Duration{time.Minute, unsegmentedFor - time.Minute, unsegmentedFor}

// roamingRun is datagrams start to end of a batch, adjacent and of one size
// a send may carry them in one segmented message
type roamingRun struct{ start, end, size int }

// roamingMachine drives a dialed and an accepted mux on the fake kernel beside a model of each
type roamingMachine struct {
	kernel *fakeKernel
	events *eventLog
	bind   *udpBind
	family roamingFamily
	ipv4   bool

	dialed, accepted *Mux
	// dialedTo models where the dialed mux sends, which never names a source
	dialedTo netip.AddrPort

	// dest, pin and pinIndex model the accepted mux's endpoint, and pinned whether its sends still carry the pin
	dest     netip.AddrPort
	pin      netip.Addr
	pinIndex int
	pinned   bool
	// clock models how far the bind's clock was moved, and dialedUntil and acceptedUntil when each endpoint segments again
	clock, dialedUntil, acceptedUntil time.Duration

	// next numbers datagrams across rules, so each that went out names its send
	next uint32
}

// held lists the addresses of the family the host holds, lowest first
func (m *roamingMachine) held() []netip.Addr {
	m.kernel.mu.Lock()
	defer m.kernel.mu.Unlock()
	var addresses []netip.Addr
	for _, local := range m.family.local {
		address := netip.MustParseAddr(local)
		if _, ok := m.kernel.local[address]; ok {
			addresses = append(addresses, address)
		}
	}
	return addresses
}

// RuleToggle releases an address the host holds, or gives it one it lacks on a drawn link
// one rule doing both leaves no case that only ever takes addresses away
func (m *roamingMachine) RuleToggle(tc hegel.TestCase) {
	address := hegel.Draw(tc, hegel.SampledFrom(m.family.local))
	if slices.Contains(m.held(), netip.MustParseAddr(address)) {
		m.kernel.release(address)
		return
	}
	m.kernel.hold(address, hegel.Draw(tc, hegel.SampledFrom(roamingLinks)))
}

func (m *roamingMachine) RuleUnplug(tc hegel.TestCase) {
	m.kernel.unplug(hegel.Draw(tc, hegel.SampledFrom(roamingLinks)))
}

// RuleWait moves the bind's clock on, which the model reads as waiting that long
func (m *roamingMachine) RuleWait(tc hegel.TestCase) {
	wait := hegel.Draw(tc, hegel.SampledFrom(roamingWaits))
	m.clock += wait
	m.bind.started = m.bind.started.Add(-wait)
}

func (m *roamingMachine) RuleCarry(tc hegel.TestCase) {
	peer := netip.MustParseAddrPort(hegel.Draw(tc, hegel.SampledFrom(m.family.peers)))
	mtu := hegel.Draw(tc, hegel.SampledFrom(roamingMTUs))
	m.kernel.mu.Lock()
	m.kernel.pathMTU[peer.Addr()] = mtu
	m.kernel.mu.Unlock()
}

// RuleAdopt hands a mux a datagram's endpoint, which can only arrive on an address the host holds
// the accepted mux gets its last endpoint back half the time, as from a peer whose request arrives on an address the host holds again
func (m *roamingMachine) RuleAdopt(tc hegel.TestCase) {
	dialedMux := hegel.Draw(tc, hegel.Booleans())
	peer, arrival, index := m.dest, m.pin, m.pinIndex
	if !dialedMux && hegel.Draw(tc, hegel.Booleans()) {
		m.kernel.hold(arrival.String(), index)
	} else {
		held := m.held()
		tc.Assume(len(held) > 0)
		arrival = hegel.Draw(tc, hegel.SampledFrom(held))
		m.kernel.mu.Lock()
		index = m.kernel.local[arrival]
		m.kernel.mu.Unlock()
		peer = netip.MustParseAddrPort(hegel.Draw(tc, hegel.SampledFrom(m.family.peers)))
	}
	endpoint := arrivedFrom(peer.String(), arrival.String(), index)

	if dialedMux {
		if moved := m.dialed.AdoptEndpoint(endpoint); moved != (peer != m.dialedTo) {
			tc.Errorf("adopting %s on %s reported moved %v for the dialed mux, the model sends to %s", peer, arrival, moved, m.dialedTo)
			return
		}
		if peer != m.dialedTo {
			m.dialedTo, m.dialedUntil = peer, 0
		}
		return
	}
	same := m.pinned && m.dest == peer && m.pin == arrival && m.pinIndex == index
	if moved := m.accepted.AdoptEndpoint(endpoint); moved == same {
		tc.Errorf("adopting %s on %s at interface %d reported moved %v, the model says %v from %s on %s at %d pinned %v",
			peer, arrival, index, moved, !same, m.dest, m.pin, m.pinIndex, m.pinned)
		return
	}
	if !same {
		m.dest, m.pin, m.pinIndex, m.pinned, m.acceptedUntil = peer, arrival, index, true, 0
	}
}

// RuleSend sends one IKE message, or a batch of runs that do not adjoin one another, through either mux
// a batch through the pinned accepted mux loses the pin's address once a drawn number of messages went to the kernel, if it has that many
func (m *roamingMachine) RuleSend(tc hegel.TestCase) {
	dialedMux := hegel.Draw(tc, hegel.Booleans())
	ike := hegel.Draw(tc, hegel.WeightedBooleans(1.0/4))
	first := m.next
	runs := []roamingRun{{0, 1, 0}}
	var packets [][]byte
	after := 0
	if !ike {
		runs = nil
		for range hegel.Draw(tc, pbt.Spanning(1, 4)) {
			length, size := hegel.Draw(tc, pbt.Spanning(1, 20)), hegel.Draw(tc, hegel.SampledFrom(roamingSizes))
			runs = append(runs, roamingRun{len(packets), len(packets) + length, size})
			packets = append(packets, numbered(length, size)...)
		}
		for i := range packets {
			binary.BigEndian.PutUint32(packets[i], first+uint32(i))
		}
		after = hegel.Draw(tc, pbt.Spanning(0, 4))
	}
	count := runs[len(runs)-1].end
	m.next += uint32(count)

	mux, to, until := m.accepted, m.dest, &m.acceptedUntil
	if dialedMux {
		mux, to, until = m.dialed, m.dialedTo, &m.dialedUntil
	}
	pinned := !dialedMux && m.pinned
	sentBefore, recordedBefore := len(m.kernel.datagrams()), len(m.events.recorded())
	m.kernel.mu.Lock()
	var refusal unix.Errno
	if pinned {
		refusal = m.kernel.pinRefusal(to.Addr(), m.pin, m.pinIndex)
	}
	_, reachable := m.kernel.choose(m.ipv4)
	armed := pinned && refusal == 0 && !ike
	if armed {
		m.kernel.releasing, m.kernel.releaseAfter = m.pin, after
	}
	m.kernel.mu.Unlock()

	var err error
	if ike {
		err = mux.SendIKE(binary.BigEndian.AppendUint32(nil, first))
	} else {
		err = mux.SendESPBatch(packets)
	}

	// the first kept datagrams leave as the endpoint is
	// and the rest from the kernel's choice once linux refuses the pin
	m.kernel.mu.Lock()
	kept := count
	if pinned && refusal != 0 {
		kept = 0
	} else if armed && !m.kernel.releasing.IsValid() {
		kept = m.kernel.releasedAt - sentBefore
	}
	m.kernel.releasing = netip.Addr{}
	fellBack := pinned && kept < count
	if fellBack {
		refusal = m.kernel.pinRefusal(to.Addr(), m.pin, m.pinIndex)
	}
	chosen, reachableAfter := m.kernel.choose(m.ipv4)
	mtu := m.kernel.mtu(to.Addr())
	m.kernel.mu.Unlock()
	wantSent := count
	if !pinned && !reachable {
		wantSent = 0
	} else if fellBack && !reachableAfter {
		wantSent = kept
	}

	var want []string
	var segmented []bool
	stopped := *until != 0 && m.clock < *until
	// walk follows datagrams from to upto of each run
	// a run a refused pin cut short went one datagram to a message and stopped nothing
	// and its rest goes on from where it was cut
	walk := func(from, upto int) {
		for _, run := range runs {
			start, end := max(run.start, from), min(run.end, upto)
			if start >= end {
				continue
			}
			together := !stopped && end == run.end && end-start > 1
			if together && run.size+m.family.header > mtu {
				stopped, together = true, false
				*until = m.clock + unsegmentedFor
				want = append(want, fmt.Sprintf("transport.endpoint.unsegmented endpoint=%s errno=%s", to, unix.ErrnoName(m.kernel.gsoErrno)))
			}
			for range end - start {
				segmented = append(segmented, together)
			}
		}
	}
	walk(0, min(kept, wantSent))
	if fellBack && reachableAfter {
		walk(kept, count)
		want = append(want, fmt.Sprintf("transport.endpoint.unpinned endpoint=%s errno=%s", to, unix.ErrnoName(refusal)))
		m.pinned = false
	}

	if (err == nil) != (wantSent == count) {
		tc.Errorf("a send of %d datagrams, %d of which the model has go out, answered %v", count, wantSent, err)
		return
	}
	sent := m.kernel.datagrams()[sentBefore:]
	if len(sent) != wantSent {
		tc.Errorf("%d datagrams went out of a send of %d, the model says %d", len(sent), count, wantSent)
		return
	}
	for i, datagram := range sent {
		number := datagram.payload
		if ike {
			number = number[nonESPMarkerLen:]
		}
		if got := binary.BigEndian.Uint32(number); got != first+uint32(i) {
			tc.Errorf("datagram %d of the send carried number %d, want %d", i, got, first+uint32(i))
		}
		if datagram.to != to {
			tc.Errorf("a datagram went to %s, the model says %s", datagram.to, to)
		}
		from := chosen
		if pinned && i < kept {
			from = m.pin
		}
		if datagram.pinned != (pinned && i < kept) || datagram.from != from {
			tc.Errorf("datagram %d went from %s pinned %v, the model says from %s pinned %v", i, datagram.from, datagram.pinned, from, pinned && i < kept)
		}
		if datagram.segmented != segmented[i] {
			tc.Errorf("datagram %d of runs %v went segmented %v, the model says %v", i, runs, datagram.segmented, segmented[i])
		}
	}
	if got := m.events.recorded()[recordedBefore:]; !slices.Equal(got, want) {
		tc.Errorf("the send recorded %q, the model %q", got, want)
	}
}

func (m *roamingMachine) InvariantDialedLeavesTheSourceToTheKernel(tc hegel.TestCase) {
	endpoint := m.dialed.Endpoint().(*udpEndpoint)
	if endpoint.AddrPort() != m.dialedTo || endpoint.control != nil {
		tc.Errorf("the dialed mux holds %s with control %x, want %s with none", endpoint.AddrPort(), endpoint.control, m.dialedTo)
	}
}

// both muxes send where they last moved, a dialed one from the kernel's choice and an accepted one pinned until refused
// each stops segmenting for as long as linux keeps a path MTU once its path refuses segments, and nothing is lost while a source exists
// a pin refused partway through a batch leaves the rest of it to the kernel's choice
// and every datagram goes out once
func TestRoamingSendsAgreeWithTheModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		ipv4 := hegel.Draw(ht, hegel.Booleans())
		family := roamingFamilies[ipv4]
		kernel := newFakeKernel()
		kernel.gsoErrno = hegel.Draw(ht, hegel.SampledFrom([]unix.Errno{unix.EINVAL, unix.EMSGSIZE, unix.EIO}))
		// the pin, and the other addresses of its family on another link
		// where a send that loses the pin goes on from
		kernel.hold(family.local[0], roamingLinks[0])
		for _, local := range family.local[1:] {
			kernel.hold(local, roamingLinks[1])
		}
		for _, peer := range family.peers {
			kernel.pathMTU[netip.MustParseAddrPort(peer).Addr()] = hegel.Draw(ht, hegel.SampledFrom(roamingMTUs))
		}
		events := &eventLog{}
		hub := kernelHub(kernel, events)

		configured := netip.MustParseAddrPort(hegel.Draw(ht, hegel.SampledFrom(family.peers)))
		dialedMux, err := hub.NewMux(configured.Addr().AsSlice(), int(configured.Port()))
		if err != nil {
			ht.Fatal(err)
		}
		opener := netip.MustParseAddrPort(hegel.Draw(ht, hegel.SampledFrom(family.peers)))
		acceptedMux, err := hub.NewMuxTo(arrivedFrom(opener.String(), family.local[0], roamingLinks[0]))
		if err != nil {
			ht.Fatal(err)
		}
		m := &roamingMachine{kernel: kernel, events: events, bind: hub.bind.(*udpBind), family: family, ipv4: ipv4,
			dialed: dialedMux, accepted: acceptedMux, dialedTo: configured,
			dest: opener, pin: netip.MustParseAddr(family.local[0]), pinIndex: roamingLinks[0], pinned: true}
		hegel.RunStateful(ht, m, hegel.WithAlwaysCheckInvariants("InvariantDialedLeavesTheSourceToTheKernel"))
	})
}
