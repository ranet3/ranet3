// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

const (
	// flowsStatusAt is the function whose waits on a lock the tests read
	flowsStatusAt = "(*Exit).flowsStatus("
	// starveAttempts bounds the attempts at starving the status's locks, each
	// undone where the scheduler runs the status between the test's release
	// of a lock and its taking the lock back, a window of a few instructions,
	// so the bound runs out only after that many preemptions there in a row
	starveAttempts = 8
)

// Past each state at rest, which TestStatusCountsHeldSocketsSharingAFlow
// reads, the status counts the flows the exit counts against Flows and the
// hold of their instant while a sweep has the held slots out of its list,
// and once the hold's clock has given the holds back while their connections
// still close, with no hold left shared
func TestStatusCountsTheFlowsTheExitCounts(t *testing.T) {
	for _, state := range flowsStates() {
		if state.host == nil {
			continue
		}
		t.Run(state.name, func(t *testing.T) {
			h := state.reach(t)
			check := func(when string, want egress.HostHold) {
				t.Helper()
				f := h.x.Status().Flows
				if exit := h.x.counted(); f.Counted != exit {
					t.Errorf("%s the status counts %d flows, the exit %d", when, f.Counted, exit)
				}
				if f.TCP != [2]int{1 + state.closing, 0} || f.Dialing != 1 {
					t.Errorf("%s the status counts TCP %v and %d dialing, want [%d 0] and 1", when, f.TCP, f.Dialing, 1+state.closing)
				}
				if f.Host == nil || *f.Host != want {
					t.Errorf("%s the status counts the hold %+v, want %+v", when, f.Host, want)
				}
			}
			held := state.closed + state.closing
			holds := h.x.tcp.holds
			holds.mu.Lock()
			sockets := holds.sockets
			holds.sockets = nil
			holds.mu.Unlock()
			check("with the held sockets out of the list as a sweep takes them", egress.HostHold{Held: held, Ports: 2 + held, Bound: 6, Shared: state.closing})
			holds.mu.Lock()
			holds.sockets = append(sockets, holds.sockets...)
			holds.mu.Unlock()
			// the first sweep aborts the TIME_WAIT holds, the second gives
			// their slots back past the margin
			h.advance(later)
			h.advance(later)
			check("with the holds given back", egress.HostHold{Ports: 2, Bound: 6})
		})
	}
}

// A sweep that reads a watched host socket closed while its leaf's connection
// still closes gives the hold back, and the status counts the connection
// alone, its hold neither held nor shared, and once the leaf's connection has
// ended after its hold nothing
func TestStatusCountsAWatchedHoldReadClosedWhileItsLeafCloses(t *testing.T) {
	fake := newFakeHostSockets(hostClosed)
	h, _, _ := holdHarness(t, fake.platform())
	c := h.open(t, netip.AddrPortFrom(leaf4, 41970), tcpServer(t, netip.MustParseAddr("127.0.0.1"), readsToTheEnd))
	f := listedFlow(t, h)
	fake.set(f.conn, hostLastAck)
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK|tcpFIN, nil))
	c.seq++
	c.ack = h.stackFIN(t, c)
	waitFor(t, "the watched hold and the admission's return", func() bool {
		host := h.x.Status().Flows.Host
		return host.Held == 1 && host.Shared == 1 && host.Ports == 1
	})
	fake.set(f.conn, hostClosed)
	h.advance(time.Second)
	if s := h.x.Status().Flows; s.TCP != [2]int{1, 0} || s.Host.Held != 0 || s.Host.Shared != 0 || s.Counted != h.x.counted() {
		t.Errorf("past the sweep that read the socket closed the status counts TCP %v, the hold %+v and %d flows, the exit %d, want the closing connection alone", s.TCP, *s.Host, s.Counted, h.x.counted())
	}
	h.x.link.deliver(tcpSegment(c.leaf, c.server, c.seq, c.ack, tcpACK, nil))
	h.waitConnections(t, 0)
	if s := h.x.Status().Flows; s.TCP != [2]int{} || s.Host.Held != 0 || s.Host.Shared != 0 || s.Counted != h.x.counted() {
		t.Errorf("past the leaf's end after its hold the status counts TCP %v, the hold %+v and %d flows, the exit %d, want no connection and no hold", s.TCP, *s.Host, s.Counted, h.x.counted())
	}
}

// waitReleased is where a goroutine of a test stands once its work is done,
// which the test reads from the goroutines' stacks and so orders nothing
// between that work and what the test does next, and runs then once the test
// gives release up
func waitReleased(release *sync.Mutex, then func()) {
	release.Lock()
	defer release.Unlock()
	then()
}

// The status reads the flows counted, held and shared in one section under
// the flows' lock while it holds the relay's lock, so no flow starts or ends
// between its read of the TCP connections and the host admissions and its
// read of the flows. A read while a UDP flow is admitted, as the status waits
// for the relay's lock, reads the flows counted under the flows' lock, which
// the race detector holds. A second read waits for the flows' lock with the
// relay's lock held, and once it has given both up it waits for neither again
// while a holder queued behind it on each holds it, so it reads the TCP
// connections and the flows in that one section.
func TestStatusReadsTheFlowsUnderTheRelaysLock(t *testing.T) {
	// one processor, so the test takes the relay's lock and the flows' lock
	// back each before the status it wakes on that lock runs, unless the
	// scheduler preempts the test in between, which starve reports
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	h := newRelayHarness(t, nil)
	allowLoopback(t, h.x.stack)
	server := loopbackServer(t, netip.MustParseAddr("127.0.0.1"))
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	const mutex = "sync.Mutex.Lock"
	var relay []string
	readAtTheRelaysLock := func() chan *egress.Flows {
		h.x.tcp.mu.Lock()
		read := make(chan *egress.Flows, 1)
		go func() { read <- h.x.Status().Flows }()
		waitFor(t, "the status read at the relay's lock", func() bool {
			relay = lockWaiters(flowsStatusAt, mutex)
			return len(relay) == 1
		})
		return read
	}

	read := readAtTheRelaysLock()
	var release sync.Mutex
	release.Lock()
	admitted := make(chan struct{})
	go func() {
		h.x.udp.take(udpDatagram(leaf, serverAt(server), []byte("admitted while the status waits")), false)
		waitReleased(&release, func() { close(admitted) })
	}()
	waitFor(t, "the UDP flow admitted", func() bool { return len(lockWaiters("waitReleased(", mutex)) == 1 })
	h.x.tcp.mu.Unlock()
	<-read
	release.Unlock()
	<-admitted

	// A holder queued on each lock behind the status takes it as soon as the
	// status gives it up, each lock starved first so that it passes to its
	// waiters in turn. This rests on the starvation mode of sync.Mutex, which
	// its source states and its API does not promise: a waiter that wakes to
	// find the lock held after waiting more than mutexStarving puts the lock
	// in that mode and queues again at the head, Unlock then hands the lock to
	// the head waiter, a goroutine that calls Lock queues at the tail, and the
	// mode ends once a waiter takes the lock that waited less than
	// mutexStarving or is the last in the queue.
	attempt := func() bool {
		read = readAtTheRelaysLock()
		free := make(chan struct{})
		var holders sync.WaitGroup
		hold := func(mu *sync.Mutex, waiters int) chan struct{} {
			holding := make(chan struct{})
			holders.Add(1)
			go func() {
				defer holders.Done()
				mu.Lock()
				close(holding)
				<-free
				mu.Unlock()
			}()
			waitFor(t, "a holder queued behind the status", func() bool { return len(lockWaiters(t.Name(), mutex)) == waiters })
			return holding
		}
		// starve wakes the status at the head of mu's queue past mutexStarving
		// of waiting, takes mu back before the status runs, and waits until the
		// status has run, found mu held and queued again at the place at, which
		// leaves mu starving whichever goroutine the scheduler ran first. Where
		// the scheduler ran the status between the release and the taking back,
		// so that the status no longer stands woken at the place at, the status
		// took mu itself, and starve ends the attempt once the status and the
		// holders are done and reports false. A read that finishes after a
		// TryLock that succeeded is such a hand-off, since the status ran whole
		// through mu in the gap and gave it up, so the attempt is tried again.
		starve := func(mu *sync.Mutex, at string) bool {
			time.Sleep(starveWait)
			mu.Unlock()
			taken := mu.TryLock()
			if !taken || !slices.Equal(lockWaiters(flowsStatusAt, "runnable"), []string{at}) {
				if taken {
					mu.Unlock()
				}
				close(free)
				<-read
				holders.Wait()
				return false
			}
			waitFor(t, "the status woken to the lock held and queued again", func() bool {
				places := lockWaiters(flowsStatusAt, mutex)
				return len(places) == 1 && places[0] == at
			})
			return true
		}
		relayHolding := hold(&h.x.tcp.mu, 2)
		if !starve(&h.x.tcp.mu, relay[0]) {
			return false
		}
		h.x.flows.mu.Lock()
		h.x.tcp.mu.Unlock()
		var flows []string
		waitFor(t, "the status read at the flows' lock", func() bool {
			flows = lockWaiters(flowsStatusAt, mutex)
			return len(flows) == 1 && flows[0] != relay[0]
		})
		select {
		case <-relayHolding:
			t.Error("the status waits for the flows' lock with the relay's lock given up")
			close(free)
			h.x.flows.mu.Unlock()
			<-read
			return true
		default:
		}
		hold(&h.x.flows.mu, 3)
		if !starve(&h.x.flows.mu, flows[0]) {
			return false
		}
		h.x.flows.mu.Unlock()
		// a status that takes a lock again waits for it behind that lock's holder
		var done *egress.Flows
		waitingAgain := func() bool { return len(lockWaiters(flowsStatusAt, mutex)) == 1 }
		waitFor(t, "the relay's holder holding or the status waiting for a lock again", func() bool {
			select {
			case <-relayHolding:
				return true
			default:
				return waitingAgain()
			}
		})
		if !waitingAgain() {
			waitFor(t, "the status read done or waiting for a lock again", func() bool {
				select {
				case done = <-read:
					return true
				default:
					return waitingAgain()
				}
			})
		}
		close(free)
		if done == nil {
			t.Error("the status waits for the flows' lock or the relay's again past its one section under both")
			<-read
		}
		return true
	}
	for range starveAttempts {
		if attempt() {
			return
		}
	}
	t.Errorf("the status took the lock it waited for between its release and its taking back in each of %d attempts to starve it", starveAttempts)
}

// A status read while flows move past its read of the TCP connections and of
// the flows counted, and before its read of the UDP flows: a relayed
// connection closes from the leaf and its host socket is held, sharing its
// flow, and a UDP flow opens. The status counts the flows the exit counted,
// the TCP connections, the held and shared holds and the host ports of the
// instant it read the TCP connections, and the UDP flows of its own. Once a
// closing connection that shares its flow has ended, a read counts its hold
// alone.
func TestStatusReadAsFlowsMove(t *testing.T) {
	fake := newFakeHostSockets(hostClosed)
	h := newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		rt.Platform.hostSockets = fake.platform()
		rt.Limits.Flows = 6
		cfg.FlowsPerSource = 6
	})
	allowLoopback(t, h.x.stack)
	loopback := netip.MustParseAddr("127.0.0.1")
	port := freeUDPPort(t, leaf4)
	destination := func(i int) {
		udp := loopbackServer(t, loopback)
		payload := fmt.Appendf(nil, "destination %d", i)
		h.x.udp.take(udpDatagram(netip.AddrPortFrom(leaf4, port), serverAt(udp), payload), false)
		readDatagramFrom(t, udp, payload)
	}
	for i := range 3 {
		destination(i)
	}
	server := tcpServer(t, loopback, readsToTheEnd)
	seen := map[*tcpFlow]bool{}
	closing := h.open(t, netip.AddrPortFrom(leaf4, 41960), server)
	fake.set(nextFlow(t, h, seen).conn, hostTimeWait)
	h.x.link.deliver(tcpSegment(closing.leaf, closing.server, closing.seq, closing.ack, tcpACK|tcpFIN, nil))
	closing.seq++
	closing.ack = h.stackFIN(t, closing)
	relayed := h.open(t, netip.AddrPortFrom(leaf4, 41961), server)
	fake.set(nextFlow(t, h, seen).conn, hostTimeWait)
	waitFor(t, "the shared hold, the relayed connection and the admissions' return", func() bool {
		f := h.x.Status().Flows
		return f.TCP == [2]int{2, 0} && f.Host.Held == 1 && f.Host.Shared == 1 && f.Host.Ports == 2
	})
	counted := h.x.counted()

	// the read stands at the TIME_WAIT endpoints' lock, which a relay's end
	// takes only once its leaf has closed
	h.x.tcp.closed.mu.Lock()
	read := make(chan *egress.Flows, 1)
	go func() { read <- h.x.Status().Flows }()
	waitFor(t, "the status read at the TIME_WAIT endpoints' lock", func() bool {
		return len(lockWaiters("(*closedEndpoints).waiting(", "sync.Mutex.Lock")) == 1
	})
	destination(3)
	h.x.link.deliver(tcpSegment(relayed.leaf, relayed.server, relayed.seq, relayed.ack, tcpACK|tcpFIN, nil))
	relayed.seq++
	relayed.ack = h.stackFIN(t, relayed)
	waitFor(t, "the relayed connection's hold", func() bool { return h.x.flows.heldCount() == 2 })
	h.x.tcp.closed.mu.Unlock()
	torn := <-read
	if want := (egress.HostHold{Held: 1, Ports: 2, Bound: torn.Host.Bound, Shared: 1}); torn.Counted != counted || torn.TCP != [2]int{2, 0} || *torn.Host != want || torn.UDP != [2]int{4, 0} {
		t.Errorf("the status read as flows moved counts %d flows, TCP %v, the hold %+v and UDP %v, want the %d flows, the TCP connections and the hold %+v the exit counted at its read and the 4 UDP flows", torn.Counted, torn.TCP, *torn.Host, torn.UDP, counted, want)
	}

	h.x.link.deliver(tcpSegment(closing.leaf, closing.server, closing.seq, closing.ack, tcpACK, nil))
	h.waitConnections(t, 1)
	after := h.x.Status().Flows
	if exit := h.x.counted(); after.TCP != [2]int{1, 0} || after.Counted != exit || after.Host.Held != 2 || after.Host.Shared != 1 {
		t.Errorf("the status read after the closing connection ended counts TCP %v, %d flows and the hold %+v, the exit %d, want the relayed connection sharing its hold and the ended one's hold alone", after.TCP, after.Counted, *after.Host, exit)
	}
}
