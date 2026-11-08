// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

const (
	// benchRun names, with any value, that the measurements below run, each
	// of which skips otherwise
	benchRun = "RANET3_EXIT_BENCH"
	// benchSpan is how long a rate is read over, benchFlows how many flows a
	// per-flow figure is read across, and benchSettle how long the exit is
	// given to reach a state the reading waits for
	benchSpan   = 10 * time.Second
	benchFlows  = 512
	benchSettle = 30 * time.Second
	// benchPort and the ports after it are the measurements' servers
	benchPort = 9300
	// benchChunk is each write of a bulk copy
	benchChunk = 64 << 10
	// benchProfile names a directory the resident measurement writes its heap
	// profile and goroutine dumps into, where set
	benchProfile = "RANET3_EXIT_BENCH_PROFILE"
	// benchShown is how many stuck connections the measurement describes, and
	// benchSegments how many of each one's segments it logs
	benchShown    = 4
	benchSegments = 60
	// benchQuiet is how long a writer is given to return once the load
	// stops: twice the longest retransmission timeout of gVisor's TCP and of
	// Linux's, 120 seconds each, so a connection backing off after the load's
	// drops retransmits at least once in it
	benchQuiet = 4 * time.Minute
	// benchHeap is the Go memory one connection of the bench's own leaf and
	// server holds, its goroutines' stacks and buffers, which stands for the
	// node's heap beside the exit: h10 measured 220 MB over 983 connections
	benchHeap = 224 << 10
)

// benchServerCount is how many server addresses the full rate's connections
// spread over, so their address pairs pick most of the exit's workers, as many
// leaves and servers do. One pair puts every segment on one worker's queue
// (`workerOf`).
const benchServerCount = 16

var benchServersOnce sync.Once

// benchServers puts benchServerCount server addresses on this namespace's
// loopback, once, and serves serve at port on each
func benchServers(t *testing.T, r *leafRig, port uint16, serve func(net.Conn)) []netip.AddrPort {
	t.Helper()
	addresses := make([]netip.Prefix, benchServerCount)
	for i := range addresses {
		addresses[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(16 + i)}), 32)
	}
	var err error
	benchServersOnce.Do(func() {
		var netlink netnstest.Netlink
		if netlink, err = netnstest.OpenNetlink(); err != nil {
			return
		}
		defer netlink.Close()
		err = netlink.AddAddresses("lo", addresses...)
	})
	if err != nil {
		t.Fatalf("add the servers' addresses: %v", err)
	}
	servers := make([]netip.AddrPort, len(addresses))
	for i, address := range addresses {
		servers[i] = r.listen(address.Addr(), port, serve)
	}
	return servers
}

// benchBound bounds conn's buffers each way to window, the exit's own, as a
// leaf or a server of the exit's size holds. The kernel charges a socket's
// buffers to the process's memory group, which holds the exit too, and
// autotunes them up to net.ipv4.tcp_wmem and tcp_rmem, which reach 64 MiB on
// a host tuned for throughput. A thousand such sockets would fill the group,
// whose bound puts every socket in it under memory pressure.
func benchBound(conn net.Conn, window int) {
	c := conn.(*net.TCPConn)
	_ = c.SetReadBuffer(window)
	_ = c.SetWriteBuffer(window)
}

// benchRig is the leaf rig with the exit sized as the daemon sizes it, from
// the host's memory and descriptors, under the Go limit the daemon sets on
// the host path, 2B + N, the bench's own leaf and server standing for N
func benchRig(t *testing.T) (*leafRig, Limits) {
	t.Helper()
	if os.Getenv(benchRun) == "" {
		t.Skipf("%s names no measurement", benchRun)
	}
	memory, err := HostMemory()
	if err != nil {
		t.Fatalf("read the host's memory: %v", err)
	}
	// N is the bench's own heap at the connections the exit may hold, which
	// on the Go-limit path the node's heap then lowers
	limits, err := Within(memory, Files())
	if err == nil {
		memory.Node = int64(limits.Connections) * benchHeap
		limits, err = Within(memory, Files())
	}
	if err != nil {
		t.Fatalf("size the exit: %v", err)
	}
	if limits.From == FromHost {
		found := debug.SetMemoryLimit(limits.MemoryLimit(memory.Node))
		t.Cleanup(func() { debug.SetMemoryLimit(found) })
	}
	t.Logf("bench: limits budget %d from %s, window %d, connections %d, flows %d, time_wait %d", limits.Budget, limits.From, limits.Window, limits.Connections, limits.Flows, limits.TimeWait)
	var debugEgress strings.Builder
	limit := debug.SetMemoryLimit(-1)
	control.RenderEgress(&debugEgress, control.EgressInfo{Enabled: true, Memory: &control.EgressMemory{Limit: limit, Given: limits.From == FromGoLimit, Node: memory.Node, Room: limit - limits.MemoryLimit(0)}})
	t.Logf("bench: debug egress, L %d and N %d:\n%s", limit, memory.Node, debugEgress.String())
	r := newLeafRig(t, func(rt Runtime) (*Exit, error) {
		rt.Limits = limits
		// the rig's mesh keeps no copy of what the exit lays, which would
		// grow with every packet and count against the exit's figures
		rt.Mesh.(*fakeMesh).unrecorded = true
		return New(exitConfig(), rt)
	})
	return r, limits
}

// sink reads a connection to its end
func sink(conn net.Conn) {
	defer conn.Close()
	_, _ = io.Copy(io.Discard, conn)
}

// echoOnce answers one read with what it read and then holds the connection
// open until the leaf closes it
func echoOnce(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	_, _ = conn.Write(buf[:n])
	_, _ = io.Copy(io.Discard, conn)
}

// heap is the live heap after a collection
func heap() uint64 {
	runtime.GC()
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

// residentBytes is the process's figure field of /proc/self/status in bytes,
// VmRSS its resident set and VmHWM the most it has held
func residentBytes(t *testing.T, field string) uint64 {
	t.Helper()
	file, err := os.Open("/proc/self/status")
	if err != nil {
		t.Fatalf("read the resident set: %v", err)
	}
	defer file.Close()
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		if rest, ok := strings.CutPrefix(lines.Text(), field+":"); ok {
			kib, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err != nil {
				t.Fatalf("read %s from %q: %v", field, rest, err)
			}
			return kib << 10
		}
	}
	t.Fatalf("no %s line in /proc/self/status", field)
	return 0
}

// one connection's throughput leaf to server through the exit, its window the
// one Within gives
func TestBenchOneFlowAtTheWindow(t *testing.T) {
	r, limits := benchRig(t)
	server := r.listen(rigServer4.Addr(), benchPort, sink)
	conn, err := r.dial(netip.AddrPortFrom(rigLeaf4.Addr(), 0), server, rigSettle)
	if err != nil {
		t.Fatalf("dial %s: %v", server, err)
	}
	defer conn.Close()
	chunk := make([]byte, benchChunk)
	var sent int64
	start := time.Now()
	for time.Since(start) < benchSpan {
		n, err := conn.Write(chunk)
		sent += int64(n)
		if err != nil {
			t.Fatalf("write after %d bytes: %v", sent, err)
		}
	}
	elapsed := time.Since(start)
	t.Logf("bench: one flow %.1f MB/s over %s at window %d", float64(sent)/elapsed.Seconds()/1e6, elapsed.Round(time.Millisecond), limits.Window)
}

// the heap one established connection holds while idle, beyond its buffers'
// contents, against perConnection
func TestBenchBytesPerConnection(t *testing.T) {
	r, limits := benchRig(t)
	server := r.listen(rigServer4.Addr(), benchPort+1, echoOnce)
	flows := min(benchFlows, limits.Connections)
	before := heap()
	conns := make([]*net.TCPConn, 0, flows)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for i := range flows {
		conn, err := r.dial(netip.AddrPortFrom(rigLeaf4.Addr(), 0), server, rigSettle)
		if err != nil {
			t.Fatalf("dial connection %d: %v", i, err)
		}
		conns = append(conns, conn)
		_, err = conn.Write([]byte("hello"))
		if err == nil {
			_, err = io.ReadFull(conn, make([]byte, 5))
		}
		if err != nil {
			t.Fatalf("exchange on connection %d: %v", i, err)
		}
	}
	after := heap()
	t.Logf("bench: per connection %d bytes of heap over %d idle connections, perConnection %d", int64(after-before)/int64(flows), flows, perConnection)
}

// the heap one UDP mapping and its destination hold, against perFlow
func TestBenchBytesPerUDPFlow(t *testing.T) {
	r, limits := benchRig(t)
	at := netip.AddrPortFrom(rigServer4.Addr(), benchPort+2)
	server, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(at))
	if err != nil {
		t.Fatalf("listen on %s: %v", at, err)
	}
	defer server.Close()
	var received atomic.Int64
	go func() {
		buf := make([]byte, 64)
		for {
			if _, _, err := server.ReadFromUDP(buf); err != nil {
				return
			}
			received.Add(1)
		}
	}()
	flows := min(benchFlows, limits.Flows-limits.Connections)
	before := heap()
	var leaves []*net.UDPConn
	defer func() {
		for _, leaf := range leaves {
			_ = leaf.Close()
		}
	}()
	if err := r.leaf.Do(func() error {
		for range flows {
			leaf, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(at))
			if err != nil {
				return err
			}
			leaves = append(leaves, leaf)
			if _, err := leaf.Write([]byte("mapping")); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("send from the leaf: %v", err)
	}
	for deadline := time.Now().Add(benchSettle); received.Load() < int64(flows); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the server read %d of %d datagrams", received.Load(), flows)
		}
	}
	after := heap()
	t.Logf("bench: per udp flow %d bytes of heap over %d mappings, perFlow %d", int64(after-before)/int64(flows), flows, perFlow)
}

// the heap one leaf-side endpoint in TIME_WAIT holds, against perTimeWait
func TestBenchBytesPerTimeWait(t *testing.T) {
	r, limits := benchRig(t)
	// the server closes first, so the exit's leaf-side endpoint sends the
	// first FIN and waits in TIME_WAIT once the leaf closes too
	server := r.listen(rigServer4.Addr(), benchPort+3, func(conn net.Conn) { _ = conn.Close() })
	flows := min(benchFlows, limits.TimeWait)
	before := heap()
	for i := range flows {
		conn, err := r.dial(netip.AddrPortFrom(rigLeaf4.Addr(), 0), server, rigSettle)
		if err != nil {
			t.Fatalf("dial connection %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, conn)
		_ = conn.Close()
	}
	var waiting int
	for deadline := time.Now().Add(benchSettle); ; time.Sleep(10 * time.Millisecond) {
		if waiting = r.exit.Status().Flows.TimeWait; waiting >= flows || time.Now().After(deadline) {
			break
		}
	}
	if waiting == 0 {
		t.Fatalf("no endpoint waited in TIME_WAIT after %d connections the server closed first", flows)
	}
	after := heap()
	t.Logf("bench: per time_wait endpoint %d bytes of heap over %d endpoints, perTimeWait %d", int64(after-before)/int64(waiting), waiting, perTimeWait)
}

// the resident set while the exit holds as many connections as it may, each
// copying both ways, against the budget. Every connection opens before any
// copies, so no dial waits behind the copies' segments.
func TestBenchResidentAtFullRate(t *testing.T) {
	benchFullRate(t, benchPort+4, true)
}

// as the resident measurement, each connection copying from its dial on while
// the next ones are dialed, the load under which connections were seen to
// stop for good on an exit the load had left
func TestBenchCopiesWhileDialing(t *testing.T) {
	benchFullRate(t, benchPort+6, false)
}

// one connection whose server writes a byte at a time while the leaf reads
// nothing, so its window closes: what the exit's heap grew by once the
// endpoint refuses its writes, the stack holding a segment and its chunks for
// each read of the host's socket, against the window its send queue is
// counted against in memory
func TestBenchTrickleIntoClosedWindow(t *testing.T) {
	r, limits := benchRig(t)
	servers := benchServers(t, r, benchPort+8, func(conn net.Conn) {
		defer conn.Close()
		_ = conn.(*net.TCPConn).SetNoDelay(true)
		one := []byte{0}
		for {
			if _, err := conn.Write(one); err != nil {
				return
			}
		}
	})
	before := heap()
	conn, err := r.dial(netip.AddrPortFrom(rigLeaf4.Addr(), 0), servers[0], rigSettle)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// atBuffer is whether the flow's send queue counts its buffer in memory,
	// and refused whether the exit's copy toward the leaf waits on a write the
	// endpoint refused. Once refused, the queue may rest just under its buffer:
	// a merge of queued segments lowers the count with no wake, and the writer
	// is woken only below half the buffer.
	atBuffer := func() bool {
		r.exit.tcp.mu.Lock()
		defer r.exit.tcp.mu.Unlock()
		for flow := range r.exit.tcp.flows {
			if flow.ep.Readiness(waiter.WritableEvents) == 0 {
				return true
			}
		}
		return false
	}
	start := time.Now()
	for time.Since(start) < benchSettle && writersRefused() == 0 && !atBuffer() {
		time.Sleep(time.Second)
	}
	grew := int64(heap()) - int64(before)
	t.Logf("bench: trickle: the exit's write refused %t and the send queue at its buffer of %d bytes %t after %s, the heap grew %d, %.1f bytes a byte of the buffer", writersRefused() > 0, limits.Window, atBuffer(), time.Since(start).Round(time.Second), grew, float64(grew)/float64(limits.Window))
	benchQueues(t, r.exit, "trickling")
}

// writersRefused counts the TCP flows whose copy toward the leaf waits in
// write, which waits only once the endpoint refused a write with
// ErrWouldBlock, read from the goroutines' stacks
func writersRefused() int {
	var stacks strings.Builder
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
		return 0
	}
	n := 0
	for _, g := range strings.Split(stacks.String(), "\n\n") {
		if strings.Contains(g, "[chan receive") && strings.Contains(g, ".(*tcpFlow).write(") {
			n++
		}
	}
	return n
}

// benchFullRate opens as many connections as the exit may hold to an echoing
// server at port, all before any copies where dialFirst, else each copying
// from its dial on, copies both ways for benchSpan, and then reads which
// connections still move once the load stops
func benchFullRate(t *testing.T, port uint16, dialFirst bool) {
	r, limits := benchRig(t)
	servers := benchServers(t, r, port, func(conn net.Conn) {
		defer conn.Close()
		benchBound(conn, limits.Window)
		_, _ = io.Copy(conn, conn)
	})
	before := residentBytes(t, "VmRSS")
	t.Logf("bench: memory group before: %s", groupMemory())
	stop := make(chan struct{})
	moved := make([]atomic.Int64, limits.Connections)
	writing := make([]atomic.Bool, limits.Connections)
	var copying sync.WaitGroup
	copyFrom := func(i int, conn *net.TCPConn) {
		writing[i].Store(true)
		copying.Go(func() {
			defer writing[i].Store(false)
			go func() { _, _ = io.Copy(io.Discard, conn) }()
			chunk := make([]byte, benchChunk)
			for {
				select {
				case <-stop:
					return
				default:
				}
				n, err := conn.Write(chunk)
				moved[i].Add(int64(n))
				if err != nil {
					return
				}
			}
		})
	}
	var conns []*net.TCPConn
	for i := range limits.Connections {
		conn, err := r.dial(netip.AddrPortFrom(rigLeaf4.Addr(), 0), servers[i%len(servers)], rigSettle)
		if err != nil {
			t.Logf("bench: connection %d of %d refused: %v", i, limits.Connections, err)
			break
		}
		benchBound(conn, limits.Window)
		conns = append(conns, conn)
		if !dialFirst {
			copyFrom(i, conn)
		}
	}
	if dialFirst {
		for i, conn := range conns {
			copyFrom(i, conn)
		}
	}
	moved, writing = moved[:len(conns)], writing[:len(conns)]
	cpuBefore := readCPU()
	// a connection that moved no byte over the span's second half is stalled
	time.Sleep(benchSpan / 2)
	half := make([]int64, len(conns))
	for i := range moved {
		half[i] = moved[i].Load()
	}
	linkHalf, dropsHalf := r.exit.link.dropped.Load(), flowDrops(r.exit)
	time.Sleep(benchSpan / 2)
	linkEnd, dropsEnd := r.exit.link.dropped.Load(), flowDrops(r.exit)
	cpu := readCPU().since(cpuBefore)
	during, peak := residentBytes(t, "VmRSS"), residentBytes(t, "VmHWM")
	t.Logf("bench: resident %d bytes against Go's limit of %d; the collector took %.1f%% of the CPU time the process used over %s, %.1f%% of all CPUs'", during, debug.SetMemoryLimit(-1), 100*cpu.gc/max(cpu.used, 1e-9), benchSpan, 100*cpu.gc/max(cpu.total, 1e-9))
	status := r.exit.Status()
	stalled, still := 0, make([]bool, len(conns))
	for i := range moved {
		if moved[i].Load() == half[i] {
			stalled++
			still[i] = true
		}
	}
	t.Logf("bench: resident %d bytes, at most %d, over %d before with %d connections copying, %d of them stalled over the last %s, buffered %d, budget %d", during, peak, before, len(conns), stalled, benchSpan/2, status.Flows.Buffered, limits.Budget)
	t.Logf("bench: dropped %v, ipv4 %d, ipv6 %d", status.Flows.Dropped, status.Dropped4, status.Dropped6)
	benchSpread(t, conns, still, linkEnd-linkHalf, dropsHalf, dropsEnd)
	benchQueues(t, r.exit, "at full rate")
	benchMemory(t, "at full rate")
	benchDump(t, "goroutines-full-rate.txt", "goroutine", 1)
	benchDump(t, "heap-full-rate.pb.gz", "heap", 0)
	close(stop)
	// each writer returns once the exit takes its last write, so a writer
	// still waiting once the load has stopped is a connection that no longer
	// moves on an idle exit
	drained := make(chan struct{})
	go func() {
		copying.Wait()
		close(drained)
	}()
	quiet := time.Now()
	waiting := func() int {
		n := 0
		for i := range writing {
			if writing[i].Load() {
				n++
			}
		}
		return n
	}
	select {
	case <-drained:
	case <-time.After(benchSettle):
		t.Logf("bench: after the load, %d of %d connections still waiting to write after %s", waiting(), len(conns), benchSettle)
		t.Logf("bench: memory group after %s: %s", benchSettle, groupMemory())
		select {
		case <-drained:
		case <-time.After(benchQuiet - benchSettle):
		}
	}
	var stuck []int
	for i := range writing {
		if writing[i].Load() {
			stuck = append(stuck, i)
		}
	}
	t.Logf("bench: after the load, %d of %d connections still waiting to write, the last returning after %s", len(stuck), len(conns), time.Since(quiet).Round(time.Second))
	shapes := map[string]int{}
	for _, i := range stuck {
		shapes[r.stuckShape(conns[i])]++
	}
	t.Logf("bench: after the load, by shape: %d with %s, %d behind %s, %d %s", shapes[shapeUnread], shapeUnread, shapes[shapeServerShut], shapeServerShut, shapes[shapeNeither], shapeNeither)
	if len(stuck) > 0 {
		benchQueues(t, r.exit, "after the load")
		benchDump(t, "goroutines-after-load.txt", "goroutine", 1)
		for _, i := range stuck[:min(len(stuck), benchShown)] {
			// the first is watched past the longest retransmission
			// timeout, so each TCP on it retransmits while watched
			watch := benchSettle
			if i == stuck[0] {
				watch = 150 * time.Second
			}
			r.describeStuck(conns[i], watch)
		}
	}
	// a write into a window that never opens returns only once its
	// connection closes
	for _, conn := range conns {
		_ = conn.Close()
	}
	<-drained
}

// benchQueues logs each of the exit's queues against its bound: the lanes'
// bytes and the workers' packets, the link's bytes and packets, the copy
// buffers out, and the TCP endpoints' received bytes and full send buffers
func benchQueues(t *testing.T, x *Exit, when string) {
	t.Helper()
	l := x.rt.Limits
	queued, most := 0, 0
	for _, w := range x.workers {
		queued += len(w.queue)
		most = max(most, len(w.queue))
	}
	var received, fullReceive, fullSend, flows int
	x.tcp.mu.Lock()
	for flow := range x.tcp.flows {
		flows++
		n, _ := flow.ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		received += n
		if n >= l.Window {
			fullReceive++
		}
		if flow.ep.Readiness(waiter.WritableEvents) == 0 {
			fullSend++
		}
	}
	x.tcp.mu.Unlock()
	t.Logf("bench: queues %s: lanes %d of %d bytes, workers %d packets (most %d) of %d each over %d, link %d of %d bytes and %d of %d packets, copy buffers out %d",
		when, x.laneHeld.Load(), l.Lanes, queued, most, workerQueuePackets, len(x.workers), x.link.held.Load(), l.Link, len(x.link.queue), linkQueuePackets, x.tcp.copies.out.Load())
	t.Logf("bench: endpoints %s: %d connections, %d bytes received unread (%d at the window %d), %d with a full send buffer",
		when, flows, received, fullReceive, l.Window, fullSend)
}

// flowDrops reads each TCP flow's writes toward the leaf that the link
// refused past its bound, by the flow's leaf port. gVisor counts each refused
// packet, a segment or a frame of several, on the endpoint that wrote it.
func flowDrops(x *Exit) map[int]uint64 {
	drops := make(map[int]uint64)
	x.tcp.mu.Lock()
	defer x.tcp.mu.Unlock()
	for flow := range x.tcp.flows {
		info, ok := flow.ep.Info().(*stack.TransportEndpointInfo)
		s, counted := flow.ep.Stats().(*tcp.Stats)
		if ok && counted {
			drops[int(info.ID.RemotePort)] = s.SendErrors.SegmentSendToNetworkFailed.Value() + s.SendErrors.SynSendToNetworkFailed.Value()
		}
	}
	return drops
}

// benchSpread logs how the link's drops between two readings of flowDrops
// spread over the connections, and how many fell on the connections still
// over that span
func benchSpread(t *testing.T, conns []*net.TCPConn, still []bool, linkFull uint64, before, after map[int]uint64) {
	t.Helper()
	per := make([]uint64, len(conns))
	var counted, onStill uint64
	hit, stillHit, stillCount := 0, 0, 0
	for i, conn := range conns {
		port := conn.LocalAddr().(*net.TCPAddr).Port
		per[i] = after[port] - min(before[port], after[port])
		counted += per[i]
		if per[i] > 0 {
			hit++
		}
		if still[i] {
			stillCount++
			onStill += per[i]
			if per[i] > 0 {
				stillHit++
			}
		}
	}
	if len(per) == 0 {
		return
	}
	slices.Sort(per)
	tenth := max(len(per)/10, 1)
	var top uint64
	for _, n := range per[len(per)-tenth:] {
		top += n
	}
	t.Logf("bench: link full %d over the last %s, %d of them counted at %d of %d connections; drops a connection: median %d, 90th percentile %d, most %d; the %d with the most took %d",
		linkFull, benchSpan/2, counted, hit, len(conns), per[len(per)/2], per[len(per)*9/10], per[len(per)-1], tenth, top)
	t.Logf("bench: of the %d connections that moved no byte over the last %s, %d took drops, %d in all",
		stillCount, benchSpan/2, stillHit, onStill)
}

// cpuSeconds is the runtime's CPU time: the collector's, what the process
// used, all but its idle time, and every CPU's
type cpuSeconds struct{ gc, used, total float64 }

// readCPU reads the runtime's CPU time now
func readCPU() cpuSeconds {
	samples := []metrics.Sample{{Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}, {Name: "/cpu/classes/total:cpu-seconds"}}
	metrics.Read(samples)
	total := samples[2].Value.Float64()
	return cpuSeconds{gc: samples[0].Value.Float64(), used: total - samples[1].Value.Float64(), total: total}
}

// since is the CPU time from before to c
func (c cpuSeconds) since(before cpuSeconds) cpuSeconds {
	return cpuSeconds{gc: c.gc - before.gc, used: c.used - before.used, total: c.total - before.total}
}

// benchMemory logs the runtime's figures: what the heap holds in use, what a
// collection leaves live, what it holds idle and gave back, the stacks, and
// the goroutines
func benchMemory(t *testing.T, when string) {
	t.Helper()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	inUse := stats.HeapInuse
	live := heap()
	runtime.ReadMemStats(&stats)
	t.Logf("bench: memory %s: sys %d, heap in use %d before a collection and %d live after it, heap idle %d of which released %d, stacks %d, other %d, goroutines %d",
		when, stats.Sys, inUse, live, stats.HeapIdle, stats.HeapReleased, stats.StackInuse, stats.OtherSys+stats.GCSys+stats.MSpanSys+stats.MCacheSys+stats.BuckHashSys, runtime.NumGoroutine())
	t.Logf("bench: memory group %s: %s", when, groupMemory())
}

// groupMemory reads the charges of the memory cgroup the process runs in,
// against its bound: its socket buffers among them, which the kernel stops
// charging at the bound, treating every socket in the group as under memory
// pressure from then on
func groupMemory() string {
	body, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err.Error()
	}
	_, path, _ := strings.Cut(strings.TrimSpace(string(body)), "::")
	dir := filepath.Join("/sys/fs/cgroup", path)
	read := func(file string) string {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return err.Error()
		}
		return strings.TrimSpace(string(b))
	}
	stat := map[string]string{}
	for line := range strings.Lines(read("memory.stat")) {
		if key, value, ok := strings.Cut(strings.TrimSpace(line), " "); ok {
			stat[key] = value
		}
	}
	var events []string
	for line := range strings.Lines(read("memory.events")) {
		events = append(events, strings.TrimSpace(line))
	}
	for up := filepath.Dir(dir); read("memory.max") == "max" && up != "/sys/fs/cgroup"; up = filepath.Dir(up) {
		dir = up
	}
	return fmt.Sprintf("current %s of max %s at %s, anon %s, sock %s, kernel %s, events %s", read("memory.current"), read("memory.max"), dir, stat["anon"], stat["sock"], stat["kernel"], strings.Join(events, ", "))
}

// benchDump writes the named runtime profile into the directory benchProfile
// names, where it names one
func benchDump(t *testing.T, file, profile string, debug int) {
	t.Helper()
	dir := os.Getenv(benchProfile)
	if dir == "" {
		return
	}
	if profile == "heap" {
		runtime.GC()
	}
	out, err := os.Create(filepath.Join(dir, t.Name()+"-"+file))
	if err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
	defer out.Close()
	if err := pprof.Lookup(profile).WriteTo(out, debug); err != nil {
		t.Fatalf("write %s: %v", file, err)
	}
}

// kernelCounts is the calling thread's namespace's TCP counts that tell why a
// segment was dropped or held, each that is not zero
func kernelCounts() string {
	names := map[string]bool{
		"InErrs": true, "InCsumErrors": true, "RetransSegs": true, "TCPZeroWindowDrop": true, "PAWSEstab": true, "TCPOFODrop": true, "TCPOFOQueue": true,
		"TCPRcvQDrop": true, "TCPRcvPruned": true, "OfoPruned": true, "TCPBacklogDrop": true, "TCPWantZeroWindowAdv": true, "TCPToZeroWindowAdv": true,
		"TCPFromZeroWindowAdv": true, "TCPTimeouts": true, "TCPDSACKRecv": true, "TCPDSACKOldSent": true, "TCPACKSkippedSeq": true,
		"TCPMemoryPressures": true, "TCPRcvCollapsed": true, "TCPOrigDataSent": true,
	}
	var counts []string
	for _, file := range []string{"/proc/thread-self/net/snmp", "/proc/thread-self/net/netstat"} {
		body, err := os.ReadFile(file)
		if err != nil {
			return err.Error()
		}
		lines := strings.Split(string(body), "\n")
		for i := 0; i+1 < len(lines); i += 2 {
			keys, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
			for j := 1; j < len(keys) && j < len(values); j++ {
				if names[keys[j]] && values[j] != "0" {
					counts = append(counts, keys[0]+keys[j]+"="+values[j])
				}
			}
		}
	}
	return strings.Join(counts, " ")
}

// socketInfo is conn's TCP state as its kernel reads it, and the bytes it
// holds unread and unacknowledged or unsent
func socketInfo(conn *net.TCPConn) (info *unix.TCPInfo, unread, unsent int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, 0, 0, err
	}
	var failed error
	if err := raw.Control(func(fd uintptr) {
		if info, failed = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); failed != nil {
			return
		}
		if unread, failed = unix.IoctlGetInt(int(fd), unix.SIOCINQ); failed != nil {
			return
		}
		unsent, failed = unix.IoctlGetInt(int(fd), unix.SIOCOUTQ)
	}); err != nil {
		return nil, 0, 0, err
	}
	return info, unread, unsent, failed
}

// The shapes of a connection still waiting once the load stops, read from the
// host's socket toward the server: the exit not reading the server, where that
// socket holds bytes unread behind a receive window of 0, or the server's
// window shut, where it holds bytes unsent at a send window of 0, the server
// taking none
const (
	shapeUnread     = "the exit not reading the server"
	shapeServerShut = "the server's window shut"
	shapeNeither    = "neither"
)

// stuckShape is the shape of conn's relay, the leaf's connection to the exit
func (r *leafRig) stuckShape(conn *net.TCPConn) string {
	flow := r.flowOf(conn.LocalAddr().(*net.TCPAddr).Port)
	if flow == nil {
		return shapeNeither
	}
	info, unread, unsent, err := socketInfo(flow.conn)
	switch {
	case err != nil:
		return shapeNeither
	case unread > 0 && info.Rcv_wnd == 0:
		return shapeUnread
	case unsent > 0 && info.Snd_wnd == 0:
		return shapeServerShut
	}
	return shapeNeither
}

// flowOf is the TCP flow of the leaf's port leafPort, nil where none is
func (r *leafRig) flowOf(leafPort int) *tcpFlow {
	r.exit.tcp.mu.Lock()
	defer r.exit.tcp.mu.Unlock()
	for f := range r.exit.tcp.flows {
		if info, ok := f.ep.Info().(*stack.TransportEndpointInfo); ok && int(info.ID.RemotePort) == leafPort {
			return f
		}
	}
	return nil
}

// socketState is conn's TCP state as its kernel reads it: the bytes it holds
// unread and unsent, its windows and what it retransmits
func socketState(conn *net.TCPConn) string {
	info, unread, unsent, err := socketInfo(conn)
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("state %d, %d bytes unread, %d unacknowledged or unsent, receive window %d (space %d, ssthresh %d), %d packets out of order, send window %d, cwnd %d, unacked %d, lost %d, retrans %d, backoff %d, unanswered tries %d, rto %d us, last data received %d ms ago, last ack received %d ms ago, segments in %d out %d",
		info.State, unread, unsent, info.Rcv_wnd, info.Rcv_space, info.Rcv_ssthresh, info.Rcv_ooopack, info.Snd_wnd, info.Snd_cwnd, info.Unacked, info.Lost, info.Retrans, info.Backoff, info.Probes, info.Rto, info.Last_data_recv, info.Last_ack_recv, info.Segs_in, info.Segs_out)
}

// describeStuck logs what each end of conn's relay holds, twice, watch apart:
// the leaf's socket and the host's toward the server as their kernel reads
// them, and the stack's endpoint, so a retransmission or a segment taken
// shows, and the segments between the leaf and the stack meanwhile
func (r *leafRig) describeStuck(conn *net.TCPConn, watch time.Duration) {
	t := r.t
	t.Helper()
	leafPort := conn.LocalAddr().(*net.TCPAddr).Port
	flow := r.flowOf(leafPort)
	if flow == nil {
		t.Logf("bench: stuck leaf port %d holds no flow", leafPort)
		return
	}
	describe := func() {
		_ = r.leaf.Do(func() error {
			t.Logf("bench: stuck leaf port %d, the leaf's kernel counts %s", leafPort, kernelCounts())
			return nil
		})
		t.Logf("bench: stuck leaf port %d, the leaf's socket: %s", leafPort, socketState(conn))
		t.Logf("bench: stuck leaf port %d, the host's socket toward the server: %s", leafPort, socketState(flow.conn))
		var info tcpip.TCPInfoOption
		_ = flow.ep.GetSockOpt(&info)
		received, _ := flow.ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		s, ok := flow.ep.Stats().(*tcp.Stats)
		if !ok {
			return
		}
		t.Logf("bench: stuck leaf port %d, the stack's endpoint: state %s, writable %t, %d bytes received unread, rto %s, cwnd %d, cc state %d, segments sent %d received %d, retransmits %d, timeouts %d, send failures %d, segment queue drops %d, checksum errors %d, zero windows %d",
			leafPort, tcp.EndpointState(flow.ep.State()), flow.ep.Readiness(waiter.WritableEvents) != 0, received, info.RTO, info.SndCwnd, info.CcState,
			s.SegmentsSent.Value(), s.SegmentsReceived.Value(), s.SendErrors.Retransmits.Value(), s.SendErrors.Timeouts.Value(), s.SendErrors.SegmentSendToNetworkFailed.Value(),
			s.ReceiveErrors.SegmentQueueDropped.Value(), s.ReceiveErrors.ChecksumErrors.Value(), s.ReceiveErrors.ZeroRcvWindowState.Value())
	}
	// the first segments each way between the leaf and the stack while the
	// connection is described
	var shown atomic.Int32
	show := func(way string) func([]byte) {
		return func(raw []byte) {
			if summary, ok := segmentOf(raw, leafPort); ok && shown.Add(1) <= benchSegments {
				t.Logf("bench: stuck leaf port %d, %s %s", leafPort, way, summary)
			}
		}
	}
	tap, back := show("leaf to stack"), show("stack to leaf")
	r.tap.Store(&tap)
	r.back.Store(&back)
	defer r.tap.Store(nil)
	defer r.back.Store(nil)
	describe()
	time.Sleep(watch)
	describe()
}

// segmentOf summarizes raw, an IPv4 TCP segment from or to port: its ports,
// sequence and acknowledgment numbers, flags, window and payload length
func segmentOf(raw []byte, port int) (string, bool) {
	if len(raw) < 20 || raw[0]>>4 != 4 || raw[9] != 6 {
		return "", false
	}
	header := int(raw[0]&0x0f) * 4
	segment := raw[header:]
	if len(segment) < 20 {
		return "", false
	}
	from, to := int(binary.BigEndian.Uint16(segment[0:2])), int(binary.BigEndian.Uint16(segment[2:4]))
	if from != port && to != port {
		return "", false
	}
	offset := int(segment[12]>>4) * 4
	return fmt.Sprintf("%d>%d seq %d ack %d flags %#02x window %d length %d at %s", from, to, binary.BigEndian.Uint32(segment[4:8]), binary.BigEndian.Uint32(segment[8:12]),
		segment[13], binary.BigEndian.Uint16(segment[14:16]), len(segment)-offset, time.Now().Format("15:04:05.000")), true
}

// connections per second, each from the leaf's one port of its worker to one
// server port whose server answers and closes first, so each next SYN meets
// the last connection's endpoint in TIME_WAIT
func TestBenchConnectionRate(t *testing.T) {
	r, _ := benchRig(t)
	server := r.listen(rigServer4.Addr(), benchPort+5, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 1)
		if _, err := conn.Read(buf); err == nil {
			_, _ = conn.Write(buf)
		}
	})
	for _, workers := range []int{1, 16} {
		var done atomic.Int64
		var failed atomic.Int64
		var running sync.WaitGroup
		start := time.Now()
		for w := range workers {
			local := netip.AddrPortFrom(rigLeaf4.Addr(), uint16(40000+100*workers+w))
			running.Go(func() {
				buf := make([]byte, 1)
				for time.Since(start) < benchSpan {
					conn, err := r.dial(local, server, rigSettle)
					if err != nil {
						failed.Add(1)
						continue
					}
					_, err = conn.Write(buf)
					if err == nil {
						_, err = io.ReadFull(conn, buf)
					}
					_ = conn.Close()
					if err != nil {
						failed.Add(1)
						continue
					}
					done.Add(1)
				}
			})
		}
		running.Wait()
		elapsed := time.Since(start)
		t.Logf("bench: %d workers %.0f connections per second, %d failed, reused %d", workers, float64(done.Load())/elapsed.Seconds(), failed.Load(), r.exit.counts.reused.Load())
	}
}
