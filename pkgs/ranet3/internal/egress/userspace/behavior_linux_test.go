// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/egresstest"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
)

const (
	// terminatesTCP is why the exit owes no inbound TCP
	terminatesTCP = "the exit ends the leaf's TCP and opens its own toward the server, so no connection from outside reaches a leaf"
	// carriesThree is why the exit refuses every other protocol
	carriesThree = "the exit carries TCP, UDP and echo through its own sockets and answers every other protocol with code 13"
	// socketWatch spaces the reads of the namespace's sockets that find one
	// opened past Prepare
	watchInterval = 50 * time.Millisecond
	// untimed is Flow.Left for a flow the exit keeps with no idle timer,
	// until an end closes or resets it
	untimed = time.Duration(1 << 62)
)

// linuxLimits holds the limits the userspace exit declares on Linux and on
// darwin
func linuxLimits() map[egresstest.Limit]egresstest.Declared {
	return map[egresstest.Limit]egresstest.Declared{
		egresstest.NoInboundTCP: {
			Reason: terminatesTCP,
			Row:    "RFC 5382 section 4.3 (REQ-3), RFC 5382 section 7.2 (REQ-8), RFC 5382 section 4.2 (REQ-2a)",
		},
		egresstest.RefusesOtherProtocols: {
			Reason: carriesThree,
			Row:    "RFC 6888 section 3 (REQ-1), RFC 5508 section 6 (REQ-8), RFC 4443 section 3.1",
		},
		egresstest.ResetsUnsolicitedSYN: {
			Reason: "a SYN from outside meets the host's own TCP, which resets a port no socket holds",
			Row:    "RFC 5382 section 4.3 (REQ-4), RFC 5382 section 4.2 (REQ-2a)",
		},
	}
}

// the userspace exit meets the exit behavior suite in both families under
// auto and the address class, on a mesh that carries only what its nodes own,
// with every socket it opens readied by Prepare and the leaf's own errors
// relayed through raw sockets
func TestUserspaceExitPassesTheExitBehaviorSuite(t *testing.T) {
	claim(t)
	egresstest.Run(t, egresstest.Owned, egresstest.Arm{
		Classes:    []egresstest.Class{egresstest.Auto, egresstest.Address},
		Limits:     linuxLimits(),
		Terminates: true,
		New: func(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks) egress.Exit {
			memory, err := HostMemory()
			if err != nil {
				t.Fatalf("read the host's memory: %v", err)
			}
			sockets, err := raw.New()
			if err != nil {
				t.Fatalf("open the raw sockets: %v", err)
			}
			return newArmExit(t, host, cfg, hooks, memory, sockets)
		},
		Holds: armHolds,
		Flows: armFlows,
	})
}

// armExits finds the exit an arm built on a host, which Holds and Flows read
var armExits sync.Map

// newArmExit builds the exit as the daemon does, over the host's mesh and the
// namespace's routes, within memory, its sockets readied by a Prepare that
// records each and a watch that fails the test on any socket of the
// namespace's that no Prepare saw, its leaf's errors sent through sockets,
// nil where the platform opens none
func newArmExit(t testing.TB, host egresstest.Host, cfg egress.Egress, hooks egress.Hooks, memory Memory, sockets Raw) *Exit {
	t.Helper()
	limits, err := Within(memory, Files())
	if err != nil {
		t.Fatalf("size the exit: %v", err)
	}
	// a new namespace lets no group open an ICMP datagram socket, and the
	// daemon's group is one the host's range admits
	if err := os.WriteFile("/proc/sys/net/ipv4/ping_group_range", fmt.Appendf(nil, "%d %d\n", os.Getegid(), os.Getegid()), 0o644); err != nil {
		t.Fatalf("admit this process's group to echo sockets: %v", err)
	}
	w := newSocketWatch(host)
	x, err := New(cfg, Runtime{
		Mesh:          MeshLanes(host.Lanes),
		Platform:      Platform{Prepare: w.prepare, Route: namespaceRoute(host.TUN), Held: namespaceHolds, Raw: sockets},
		Limits:        limits,
		MeshAddresses: host.Mesh,
		Hooks:         hooks,
	})
	if err != nil {
		if sockets != nil {
			_ = sockets.Close()
		}
		t.Fatalf("build the userspace exit: %v", err)
	}
	armExits.Store(host.TUN, x)
	w.run(t)
	return x
}

// namespaceRoute is Platform.Route from this namespace's routes, which never
// reach an address over the mesh's own tun
func namespaceRoute(mesh string) func(netip.Addr) (Link, bool, error) {
	return func(address netip.Addr) (Link, bool, error) {
		answers, err := client.RouteLookups([]kernelexit.Lookup{{Destination: address}})
		if err != nil {
			return Link{}, false, err
		}
		if len(answers) != 1 || answers[0].Err != nil || answers[0].Route.Type != "unicast" {
			return Link{}, false, nil
		}
		for _, hop := range answers[0].Route.Hops {
			if hop.Dead || hop.LinkDown || hop.Device == mesh {
				continue
			}
			link, err := net.InterfaceByName(hop.Device)
			if err != nil {
				return Link{}, false, err
			}
			return Link{Name: link.Name, MTU: link.MTU}, true, nil
		}
		return Link{}, false, nil
	}
}

// namespaceHolds is Platform.Held from this namespace's addresses
func namespaceHolds(address netip.Addr) bool {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(addresses, func(a net.Addr) bool {
		prefix, err := netip.ParsePrefix(a.String())
		return err == nil && prefix.Addr() == address
	})
}

// socketWatch records the inode of each socket Prepare readies, and reads the
// namespace's sockets for any other, the suite's own from the exit's mesh
// addresses aside
type socketWatch struct {
	mesh []netip.Addr

	mu         sync.Mutex
	prepared   map[uint64]bool
	unprepared []string
}

func newSocketWatch(host egresstest.Host) *socketWatch {
	return &socketWatch{mesh: host.Mesh, prepared: map[uint64]bool{}}
}

func (w *socketWatch) prepare(_ string, _ netip.AddrPort, c syscall.RawConn) error {
	var stat unix.Stat_t
	var statErr error
	if err := c.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &stat) }); err != nil {
		return err
	}
	if statErr != nil {
		return statErr
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.prepared[stat.Ino] = true
	return nil
}

// run reads the namespace's sockets until the test ends, then fails it on
// each one Prepare never saw
func (w *socketWatch) run(t testing.TB) {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(watchInterval)
		defer ticker.Stop()
		for {
			w.read()
			select {
			case <-ticker.C:
			case <-stop:
				return
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		<-done
		w.mu.Lock()
		defer w.mu.Unlock()
		if len(w.unprepared) != 0 {
			t.Errorf("the exit opened %d sockets past Prepare: %v", len(w.unprepared), w.unprepared)
		}
	})
}

// read lists the sockets of the process's namespace, which an unlocked
// goroutine's thread is in, the inode and local address of
// each, skipping a socket closed and waiting, which holds no inode
func (w *socketWatch) read() {
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6", "icmp", "icmp6"} {
		file, err := os.Open("/proc/thread-self/net/" + table)
		if err != nil {
			continue
		}
		lines := bufio.NewScanner(file)
		lines.Scan()
		for lines.Scan() {
			fields := strings.Fields(lines.Text())
			if len(fields) < 10 {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 {
				continue
			}
			local, ok := procAddress(fields[1])
			if !ok || slices.Contains(w.mesh, local) {
				continue
			}
			w.mu.Lock()
			if !w.prepared[inode] {
				w.prepared[inode] = true
				w.unprepared = append(w.unprepared, table+" "+fields[1])
			}
			w.mu.Unlock()
		}
		_ = file.Close()
	}
}

// procAddress reads a /proc/net address, its words in the host's order
func procAddress(field string) (netip.Addr, bool) {
	hex, _, ok := strings.Cut(field, ":")
	if !ok || len(hex)%8 != 0 {
		return netip.Addr{}, false
	}
	var b []byte
	for i := 0; i < len(hex); i += 8 {
		word, err := strconv.ParseUint(hex[i:i+8], 16, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		b = append(b, byte(word), byte(word>>8), byte(word>>16), byte(word>>24))
	}
	address, ok := netip.AddrFromSlice(b)
	return address, ok
}

// armHolds names what the exit holds: its lanes while they take packets, each
// TCP connection, each UDP destination and each echo mapping
func armHolds(host egresstest.Host) ([]string, error) {
	x, ok := armExit(host)
	if !ok {
		return nil, errors.New("no exit was built on the host")
	}
	var held []string
	if x.taking.Load() {
		held = append(held, "lanes taking packets")
	}
	for _, f := range tableOf(x) {
		held = append(held, fmt.Sprintf("protocol %d from %s to %s", f.Protocol, f.From, f.To))
	}
	slices.Sort(held)
	return held, nil
}

func armExit(host egresstest.Host) (*Exit, bool) {
	x, ok := armExits.Load(host.TUN)
	if !ok {
		return nil, false
	}
	return x.(*Exit), true
}

// armFlows reads the exit's own table
func armFlows(host egresstest.Host) ([]egresstest.Flow, error) {
	x, ok := armExit(host)
	if !ok {
		return nil, errors.New("no exit was built on the host")
	}
	return tableOf(x), nil
}

// tableOf is each connection being dialed and relayed, each UDP
// destination with its time left, and each echo mapping with its time left,
// an echo's identifier in place of both ports
func tableOf(x *Exit) []egresstest.Flow {
	now := time.Now()
	var flows []egresstest.Flow
	x.tcp.mu.Lock()
	for id := range x.tcp.dialing {
		flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_TCP, From: leafEnd(id), To: serverEnd(id), Phase: egresstest.Opening, Left: untimed})
	}
	for f := range x.tcp.flows {
		info, ok := f.ep.Info().(*stack.TransportEndpointInfo)
		if !ok {
			continue
		}
		phase, left := tcpPhase(tcp.EndpointState(f.ep.State()))
		flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_TCP, From: leafEnd(info.ID), To: serverEnd(info.ID), Phase: phase, Left: left})
	}
	x.tcp.mu.Unlock()
	x.udp.mu.RLock()
	for _, m := range x.udp.mappings {
		m.mu.RLock()
		for to, dst := range m.destinations {
			flows = append(flows, egresstest.Flow{Protocol: syscall.IPPROTO_UDP, From: m.leaf, To: to, Left: time.Unix(0, dst.deadline.Load()).Sub(now).Truncate(time.Second)})
		}
		m.mu.RUnlock()
	}
	x.udp.mu.RUnlock()
	x.echo.mu.Lock()
	for key, m := range x.echo.mappings {
		protocol := byte(syscall.IPPROTO_ICMP)
		if key.leaf.Is6() {
			protocol = syscall.IPPROTO_ICMPV6
		}
		left := time.Unix(0, m.last.Load()).Add(echoIdle).Sub(now).Truncate(time.Second)
		flows = append(flows, egresstest.Flow{Protocol: protocol, From: netip.AddrPortFrom(key.leaf, key.id), Left: left})
	}
	x.echo.mu.Unlock()
	return flows
}

func leafEnd(id stack.TransportEndpointID) netip.AddrPort {
	return netip.AddrPortFrom(addrOf(id.RemoteAddress), id.RemotePort)
}

func serverEnd(id stack.TransportEndpointID) netip.AddrPort {
	return netip.AddrPortFrom(addrOf(id.LocalAddress), id.LocalPort)
}

// tcpPhase is RFC 5382 section 5's phase of a leaf's endpoint, which the
// exit keeps with no idle timer until an end closes or resets it
func tcpPhase(state tcp.EndpointState) (egresstest.Phase, time.Duration) {
	switch state {
	case tcp.StateSynRecv:
		return egresstest.Opening, untimed
	case tcp.StateEstablished, tcp.StateCloseWait, tcp.StateFinWait1, tcp.StateFinWait2:
		return egresstest.Established, untimed
	case tcp.StateLastAck, tcp.StateClosing:
		return egresstest.Closing, untimed
	}
	return egresstest.NoPhase, 0
}
