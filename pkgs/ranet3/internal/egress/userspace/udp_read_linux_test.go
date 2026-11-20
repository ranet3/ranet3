// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/internal/egress"
)

// A reader whose receive fails, as a destination's does once an ICMP error
// about its datagram reached its socket, gives its buffer back before it waits
// for dst.mu: a port unreachable about the destination's datagram reaches its
// socket while the test holds dst.mu, the live heap does not grow by a buffer
// once the reader waits on dst.mu, which its wait reason shows
// (lockWaiters), and the error reaches the leaf once dst.mu is free, which
// shows the reader took the failed receive. Root alone sends the error.
func TestReaderWaitingPastAReceiveErrorHoldsNoBuffer(t *testing.T) {
	onLoopback(t, rigServer4)
	h := newRelayHarness(t, nil)
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	server := rigLoopbackServer(t, rigServer4.Addr())
	to := serverAt(server)
	leaf := netip.AddrPortFrom(leaf4, freeUDPPort(t, leaf4))
	payload := []byte("before the error")
	h.x.udp.take(udpDatagram(leaf, to, payload), false)
	outside := readDatagramFrom(t, server, payload)
	dst := destinationOf(t, h, leaf, to)
	dst.mu.Lock()
	held := true
	defer func() {
		if held {
			dst.mu.Unlock()
		}
	}()
	time.Sleep(10 * time.Millisecond)
	before := collected().HeapAlloc
	sendICMP(t, outside.Addr(), append([]byte{3, 3, 0, 0, 0, 0, 0, 0}, udpDatagram(outside, to, payload)...))
	for deadline := time.Now().Add(exitWait); len(lockWaiters("userspace.(*udpRelay).read(", "sync.Mutex.Lock")) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the destination's reader never waited on dst.mu past the failed receive")
		}
	}
	grown := int64(collected().HeapAlloc) - int64(before)
	dst.mu.Unlock()
	held = false
	if grown >= datagramBuffer {
		t.Errorf("the live heap grew by %d bytes while the reader waited for dst.mu past a failed receive, %.1f buffers of %d", grown, float64(grown)/datagramBuffer, datagramBuffer)
	}
	h.waitLaid(t, "port unreachable", func(raw []byte) bool {
		p, ok := parse(raw)
		return ok && p.protocol == protoICMP && p.kind == 3 && p.code == 3
	})
}

// destinationOf is the destination of leaf's one mapping toward to
func destinationOf(t *testing.T, h *relayHarness, leaf, to netip.AddrPort) *destination {
	t.Helper()
	mappings := h.mappingsOf(leaf)
	if len(mappings) != 1 {
		t.Fatalf("the leaf holds %d mappings, want 1", len(mappings))
	}
	mappings[0].mu.RLock()
	defer mappings[0].mu.RUnlock()
	dst := mappings[0].destinations[to]
	if dst == nil {
		t.Fatalf("the mapping holds no destination toward %s", to)
	}
	return dst
}

// flowCost names the process of its own that
// TestFlowHoldsAtMostItsBoundsAtRestAndRelayed measures in, and holds the
// family it measures
const flowCost = "USERSPACE_FLOW_COST"

// flowAtRest bounds what a UDP flow that carries its mapping holds before
// its readers relayed, and flowHeld what it holds once each relayed, the
// figures the limits page states. flowHeld is twice the flow's share
// (perFlow), what the page says mappings that fill their eighth hold at
// most. flowAtRest is the share and 3 KiB of room for what the runtime's
// spans and the stack's buffers add from one process to the next, so one
// buffer a reader at rest held (datagramBuffer) passes it many times over.
const (
	flowAtRest = 11 << 10
	flowHeld   = 16 << 10
)

// What a flow that carries a mapping holds in Go's heap and in its stacks,
// the mapping's, its destination's, their two sockets' and the two readers'
// goroutines', is flowAtRest at most before its readers relayed and flowHeld
// at most once each relayed, in each family: the destination's reader a reply
// and a port unreachable, the receiving socket's reader a datagram from the
// server's address at another port. A leaf sending from a new port for each
// flow makes each the first destination of its own mapping, which holds more
// than a later destination of a mapping does. Each family is measured over
// 200 such flows, since the runtime takes stacks in spans of 32 KiB, in a
// process of its own in a network namespace of its own, since a process that
// ran other tests hands new goroutines the stacks of ended ones and the error
// needs a raw socket, after two collections. Prepare records nothing and the
// test's own slices are made before the first measure, so what is counted is
// what the exit holds. The race detector's runtime holds more for each
// goroutine than the exit does, and its build skips.
func TestFlowHoldsAtMostItsBoundsAtRestAndRelayed(t *testing.T) {
	if raceBuild {
		t.Skip("the race detector's runtime holds more for each goroutine and object than the exit does")
	}
	family := os.Getenv(flowCost)
	if family == "" {
		for _, family := range []string{"ipv4", "ipv6"} {
			cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.count=1", "-test.v")
			cmd.Env = append(os.Environ(), flowCost+"="+family)
			cmd.SysProcAttr = &syscall.SysProcAttr{
				Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
			}
			out, err := cmd.CombinedOutput()
			if _, exited := err.(*exec.ExitError); err != nil && !exited {
				t.Skipf("no process of its own in a user and network namespace: %v", err)
			}
			_, logged, _ := bytes.Cut(out, []byte("flow cost: "))
			var restHeap, restStack, heap, stack int64
			if _, scanned := fmt.Sscanf(string(logged), "at rest heap %d stack %d, relayed heap %d stack %d", &restHeap, &restStack, &heap, &stack); err != nil || scanned != nil {
				t.Fatalf("%s: the measuring process ended with %v and logged no cost:\n%s", family, err, out)
			}
			t.Logf("%s: a flow carrying a mapping holds at rest %d bytes of heap and %d of stack, %d in all, and once its readers relayed %d and %d, %d in all",
				family, restHeap, restStack, restHeap+restStack, heap, stack, heap+stack)
			if restHeap+restStack > flowAtRest || heap+stack > flowHeld {
				t.Errorf("%s: a flow carrying a mapping holds %d bytes at rest and %d once its readers relayed, want at most %d and %d", family, restHeap+restStack, heap+stack, flowAtRest, flowHeld)
			}
		}
		return
	}
	const flows = 200
	prefix, leafAddress, network := rigServer4, leaf4, "udp4"
	unreachable := []byte{3, 3, 0, 0, 0, 0, 0, 0}
	if family == "ipv6" {
		prefix, leafAddress, network = rigServer6, leaf6, "udp6"
		unreachable = []byte{1, 4, 0, 0, 0, 0, 0, 0}
	}
	onLoopback(t, prefix)
	h := newRelayHarness(t, func(rt *Runtime, cfg *egress.Egress) {
		rt.Limits.Flows = 2 * flows
		cfg.FlowsPerSource = 2 * flows
	})
	h.x.rt.Platform.Prepare = func(string, netip.AddrPort, syscall.RawConn) error { return nil }
	server := rigLoopbackServer(t, prefix.Addr())
	other, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(prefix.Addr(), 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	to := serverAt(server)
	leaves, outsides := make([]netip.AddrPort, flows), make([]netip.AddrPort, flows)
	// the pool empties at two collections
	held := func(readers int) (heap, stack int64) {
		waitReadersInPoller(t, readers)
		s := collected()
		return int64(s.HeapAlloc), int64(s.StackInuse)
	}
	heap, stack := held(0)
	payload := []byte("opens")
	for i := range outsides {
		leaves[i] = netip.AddrPortFrom(leafAddress, freeUDPPort(t, leafAddress))
		h.x.udp.take(udpDatagram(leaves[i], to, payload), false)
		outsides[i] = readDatagramFrom(t, server, payload)
	}
	h.x.flows.mu.Lock()
	open := h.x.flows.open
	h.x.flows.mu.Unlock()
	if open != flows {
		t.Fatalf("%d flows held, want %d", open, flows)
	}
	// each flow's two readers, its mapping's receiving socket's and its destination's
	restHeap, restStack := held(2 * flows)
	reply := []byte("reply")
	for i, outside := range outsides {
		for _, from := range []*net.UDPConn{server, other} {
			if _, err := from.WriteToUDPAddrPort(reply, outside); err != nil {
				t.Fatal(err)
			}
			h.waitLaid(t, "reply", func(raw []byte) bool { return isDatagram(raw, serverAt(from), leaves[i], reply) })
		}
		sendICMP(t, outside.Addr(), append(slices.Clone(unreachable), udpDatagram(outside, to, payload)...))
		h.waitLaid(t, "port unreachable", func(raw []byte) bool {
			p, ok := parse(raw)
			return ok && (p.protocol == protoICMP || p.protocol == protoICMPv6)
		})
	}
	h.drainLaid()
	relayedHeap, relayedStack := held(2 * flows)
	t.Logf("flow cost: at rest heap %d stack %d, relayed heap %d stack %d", (restHeap-heap)/flows, (restStack-stack)/flows, (relayedHeap-heap)/flows, (relayedStack-stack)/flows)
}
