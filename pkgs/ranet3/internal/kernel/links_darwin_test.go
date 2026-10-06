// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// The lookup has to name an interface this host really has, and not the
// loopback: the use of the answer is to take the underlay socket off the
// forwarding table and onto the link the machine reaches its peers through.
//
// It needs no privilege and writes nothing, so it runs in the ordinary suite
// rather than behind RANET3_DARWIN_NETTEST. A host with no default route
// is the one honest reason to skip.
func TestDefaultInterfaceNamesALinkThisHostHas(t *testing.T) {
	links, err := WatchLinks(nil, 0)
	if err != nil {
		t.Fatalf("open the link watcher: %v", err)
	}
	t.Cleanup(func() { _ = links.Close() })

	index, err := links.DefaultInterface()
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no default route, so there is nothing to bind to")
	}
	if err != nil {
		t.Fatalf("look up the default interface: %v", err)
	}
	device, err := net.InterfaceByIndex(index)
	if err != nil {
		t.Fatalf("the lookup returned index %d, which names no interface: %v", index, err)
	}
	t.Logf("the host's own traffic leaves by %s (index %d, flags %s)", device.Name, index, device.Flags)
	if device.Flags&net.FlagUp == 0 {
		t.Errorf("%s is not up, so the underlay would be bound to a dead link", device.Name)
	}
	if device.Flags&net.FlagLoopback != 0 {
		t.Errorf("%s is the loopback, so nothing bound to it would reach a peer", device.Name)
	}
}

// the lookup the underlay is bound through names the next hop of the default route beside its interface
// the scoped default is written under that next hop, so a lookup that left it out leaves the underlay with no default of its own
// the answer is held against the same request read raw, which carries the gateway the kernel named
// it needs no privilege and writes nothing
func TestLookupNamesTheNextHopOfTheDefaultRoute(t *testing.T) {
	family := netip.IPv4Unspecified()
	answer, err := runningKernel{}.Lookup(family, zeroMaskOf(family))
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no IPv4 default route")
	}
	if err != nil {
		t.Fatalf("ask for the IPv4 default: %v", err)
	}
	raw, err := routeRequest(family, zeroMaskOf(family))
	if err != nil {
		t.Fatalf("ask for the IPv4 default again: %v", err)
	}
	if len(raw.Addrs) <= unix.RTAX_GATEWAY {
		t.Fatal("the answer carries no gateway at all")
	}
	gateway, ok := raw.Addrs[unix.RTAX_GATEWAY].(*route.Inet4Addr)
	if !ok {
		t.Skip("this host's default leaves through a link rather than a next hop")
	}
	if want := netip.AddrFrom4(gateway.IP); answer.Gateway != want {
		t.Errorf("the lookup names the next hop %v, and the kernel's own answer holds %v", answer.Gateway, want)
	}
	if answer.Index != raw.Index {
		t.Errorf("the lookup names interface %d, and the kernel's own answer holds %d", answer.Index, raw.Index)
	}
}

// lookups running at once each read their own answer
// the routing socket carries every reply the machine's routing makes, so a reply taken for its arrival alone names whichever lookup asked first
// the loopback and the default route leave by different interfaces, and each answer names the one its own destination leaves by
// a lookup that stops reading after a fixed count or loses its reply to a full queue passes here more often than not
// the tests of readAnswer and of the receive queue hold those on every run
// it needs no privilege and writes nothing
func TestLookupsRunningAtOnceEachReadTheirOwnAnswer(t *testing.T) {
	toLoopback, toDefault := netip.MustParseAddr("127.0.0.1"), netip.IPv4Unspecified()
	// asked one at a time first, with nothing else in the way of the answers
	want := make(map[netip.Addr]int)
	for _, destination := range []netip.Addr{toLoopback, toDefault} {
		answer, err := routeRequest(destination, netip.Addr{})
		if errors.Is(err, ErrNoDefaultRoute) {
			t.Skip("this host has no IPv4 default route")
		}
		if err != nil {
			t.Fatalf("ask for the route to %s: %v", destination, err)
		}
		want[destination] = answer.Index
	}
	if want[toLoopback] == want[toDefault] {
		t.Skipf("both destinations leave by interface %d, so no two answers differ", want[toLoopback])
	}

	const workers, lookupsEach = 8, 100
	// the first failure is written by the one worker that raises the count to 1, and read after Wait
	var wrong atomic.Int32
	var first string
	var running sync.WaitGroup
	for worker := range workers {
		running.Go(func() {
			for lookup := range lookupsEach {
				destination := toLoopback
				if (worker+lookup)%2 == 1 {
					destination = toDefault
				}
				answer, err := routeRequest(destination, netip.Addr{})
				var problem string
				switch {
				case err != nil:
					problem = fmt.Sprintf("the route to %s failed: %v", destination, err)
				case answer.Index != want[destination]:
					problem = fmt.Sprintf("the route to %s was answered with interface %d, want %d", destination, answer.Index, want[destination])
				}
				if problem != "" && wrong.Add(1) == 1 {
					first = problem
				}
			}
		})
	}
	running.Wait()
	if wrong.Load() > 0 {
		t.Errorf("%d of %d lookups read another lookup's answer or failed, the first %s", wrong.Load(), workers*lookupsEach, first)
	}
}

// the socket a lookup asks on holds a receive queue of at least the size it asked for
// a routing socket that overflows drops the excess without telling its reader, and a lookup running beside others has their replies queued ahead of its own
// the size is read back from the kernel, which grants what was asked for or more
// it needs no privilege and writes nothing
func TestLookupSocketIsGivenTheReceiveQueueItAsksFor(t *testing.T) {
	fd, err := lookupSocket()
	if err != nil {
		t.Fatalf("open the lookup socket: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	granted, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		t.Fatalf("read the receive queue back: %v", err)
	}
	if granted < routeReceiveBuffer {
		t.Errorf("the lookup socket holds a receive queue of %d bytes, want at least %d", granted, routeReceiveBuffer)
	}
}

const (
	// ownSeq is the sequence number of the request whose answer a test reads
	ownSeq = 7
	// repliesAhead is how many replies for other lookups wait ahead of a lookup's own
	// it is far more than a loop that stops after a few reads would take
	repliesAhead = 40
	// replyGap is the pause between two replies that keep arriving while a lookup waits
	replyGap = lookupTimeout / 32
	// replySpan is how long they keep arriving, which leaves the last read an eighth of the deadline
	replySpan = lookupTimeout * 7 / 8
	// latestEnd is how long after it began a lookup nobody answers may run, a quarter past its deadline
	latestEnd = lookupTimeout * 5 / 4
)

// replySockets is a datagram socket pair standing in for a routing socket
// a message written to the second descriptor is read from the first, one message per read as on a routing socket
// the first descriptor holds the receive queue a lookup socket holds, which fits every reply a test queues ahead of a read
func replySockets(t *testing.T) (reader, writer int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("open a socket pair: %v", err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_RCVBUF, routeReceiveBuffer); err != nil {
		t.Fatalf("size the receive queue of the reading end: %v", err)
	}
	return fds[0], fds[1]
}

// writeReply queues one RTM_GET reply of this process for one sequence number, as the kernel answers a lookup
func writeReply(t *testing.T, fd, seq int) {
	t.Helper()
	addrs := make([]route.Addr, unix.RTAX_MAX)
	addrs[unix.RTAX_DST] = routeAddr(netip.IPv4Unspecified())
	reply := &route.RouteMessage{
		Version: unix.RTM_VERSION,
		Type:    unix.RTM_GET,
		ID:      uintptr(os.Getpid()),
		Seq:     seq,
		Addrs:   addrs,
	}
	raw, err := reply.Marshal()
	if err != nil {
		t.Fatalf("encode a reply: %v", err)
	}
	if _, err := unix.Write(fd, raw); err != nil {
		t.Fatalf("queue a reply: %v", err)
	}
}

// a lookup finds its reply behind many that other lookups made
// the replies other lookups make queue ahead of a lookup's own, and a read loop that stops after a fixed count never reaches it
// the queue is a socket pair's and holds the replies this test writes, whatever the machine's routing is doing
// it needs no privilege and writes no route
func TestLookupFindsItsReplyBehindManyOthers(t *testing.T) {
	reader, writer := replySockets(t)
	for i := range repliesAhead {
		writeReply(t, writer, ownSeq+1+i)
	}
	writeReply(t, writer, ownSeq)
	answer, err := readAnswer(reader, ownSeq, netip.IPv4Unspecified())
	if err != nil {
		t.Fatalf("a reply behind %d others was not found: %v", repliesAhead, err)
	}
	if answer.Seq != ownSeq {
		t.Errorf("the lookup took the reply to request %d, want the reply to request %d", answer.Seq, ownSeq)
	}
}

// a lookup nobody answers ends at its deadline while replies for other lookups keep arriving
// they keep arriving for most of the deadline and the last read starts late in it
// a read given the whole timeout rather than what is left runs a long way past the deadline, and a loop with no deadline never ends
// a read that times out early is asked again, and the lookup ends as unanswered and not as a failed read
// a timer bounds the wait, and a lookup that never ends fails the test instead of holding it
// it needs no privilege and writes no route
func TestUnansweredLookupEndsAtItsDeadlineWhileOthersAreAnswered(t *testing.T) {
	reader, writer := replySockets(t)
	type ending struct {
		answer *route.RouteMessage
		err    error
		after  time.Duration
	}
	start := time.Now()
	ended := make(chan ending, 1)
	go func() {
		answer, err := readAnswer(reader, ownSeq, netip.IPv4Unspecified())
		ended <- ending{answer, err, time.Since(start)}
	}()
	for time.Since(start) < replySpan {
		writeReply(t, writer, ownSeq+1)
		time.Sleep(replyGap)
	}
	var end ending
	select {
	case end = <-ended:
	case <-time.After(time.Until(start.Add(latestEnd))):
		t.Fatalf("a lookup nobody answered was still reading %s after it began, and its deadline is %s", latestEnd, lookupTimeout)
	}
	if end.err == nil || !strings.Contains(end.err.Error(), "was not answered") {
		t.Fatalf("a lookup nobody answered ended with the error %v and the answer %v", end.err, end.answer)
	}
	if end.after < lookupTimeout || end.after > latestEnd {
		t.Errorf("a lookup nobody answered ended %s after it began, want between %s and %s", end.after, lookupTimeout, latestEnd)
	}
}

// Every lookup carries its own sequence number, so two running at once cannot
// read each other's answers off a socket the whole machine shares.
func TestRouteLookupsCarryDistinctSequenceNumbers(t *testing.T) {
	first, err := routeRequest(netip.IPv4Unspecified(), netip.Addr{})
	if errors.Is(err, ErrNoDefaultRoute) {
		t.Skip("this host has no IPv4 default route")
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := routeRequest(netip.IPv4Unspecified(), netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Seq == second.Seq {
		t.Errorf("two lookups both answered sequence %d", first.Seq)
	}
}
