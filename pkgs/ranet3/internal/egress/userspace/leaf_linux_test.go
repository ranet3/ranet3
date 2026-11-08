// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package userspace

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

const (
	leafLink = "leaf0"
	// leafMTU is the leaf's tun, a session's
	leafMTU = 1420
	// leafRedial spaces the leaf's connects its kernel refused for a
	// four-tuple still closing
	leafRedial = 100 * time.Microsecond
	// rigSettle bounds a state change the stack makes on its own goroutines
	rigSettle = 2 * time.Second
)

var (
	rigLeaf4   = netip.MustParsePrefix("192.0.2.2/24")
	rigLeaf6   = netip.MustParsePrefix("2001:db8:1::2/64")
	rigMesh4   = netip.MustParseAddr("192.0.2.1")
	rigMesh6   = netip.MustParseAddr("2001:db8:1::1")
	rigServer4 = netip.MustParsePrefix("203.0.113.5/32")
	rigServer6 = netip.MustParsePrefix("2001:db8:3::5/128")
	// rigOthers4 and rigOthers6 are two more servers' addresses of each
	// family, on loopback beside the first
	rigOthers4 = [2]netip.Prefix{netip.MustParsePrefix("203.0.113.6/32"), netip.MustParsePrefix("203.0.113.7/32")}
	rigOthers6 = [2]netip.Prefix{netip.MustParsePrefix("2001:db8:3::6/128"), netip.MustParsePrefix("2001:db8:3::7/128")}
)

var (
	claimOnce sync.Once
	claimSkip string
	claimErr  error

	serversOnce sync.Once
	serversErr  error
)

// addServers brings this namespace's loopback up with the servers'
// addresses on it
func addServers() error {
	if err := netnstest.BringUp("lo"); err != nil {
		return err
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	return netlink.AddAddresses("lo", rigServer4, rigServer6, rigOthers4[0], rigOthers4[1], rigOthers6[0], rigOthers6[1])
}

// claim skips the test without root and refuses it in a namespace that held
// anything, since the exit dials from this process's namespace
func claim(t *testing.T) {
	t.Helper()
	claimOnce.Do(func() { claimSkip, claimErr = netnstest.ClaimProcess() })
	if claimSkip != "" {
		t.Skip(claimSkip)
	}
	if claimErr != nil {
		t.Fatal(claimErr)
	}
}

// leafRig is an exit whose sessions are a leaf's tun in a namespace of its
// own, the leaf's own kernel sending and answering, and whose servers listen
// on this namespace's loopback
type leafRig struct {
	t    *testing.T
	exit *Exit
	mesh *fakeMesh
	leaf *netnstest.Thread
	tun  *os.File
	// tap sees each packet from the leaf before the exit takes it, back each
	// packet the exit lays toward the leaf, and before runs on the leaf's
	// packet before Egress
	tap, back atomic.Pointer[func(raw []byte)]
	before    atomic.Pointer[func(raw []byte)]
	reading   sync.WaitGroup
	// prepared records each socket the exit's Prepare readied
	mu       sync.Mutex
	prepared []netip.AddrPort
}

// newLeafRig is the rig, the exit built by build over its runtime
func newLeafRig(t *testing.T, build func(Runtime) (*Exit, error)) *leafRig {
	t.Helper()
	claim(t)
	r := &leafRig{t: t, mesh: newFakeMesh()}
	r.mesh.laidTo = func(raw []byte) {
		if back := r.back.Load(); back != nil {
			(*back)(raw)
		}
		_, _ = r.tun.Write(raw)
	}
	serversOnce.Do(func() { serversErr = addServers() })
	if serversErr != nil {
		t.Fatalf("address the servers on loopback: %v", serversErr)
	}
	r.leaf = netnstest.StartThread(t)
	if err := r.leaf.Do(r.makeLeaf); err != nil {
		t.Fatalf("make the leaf's tun: %v", err)
	}
	p := &fakePlatform{routes4: true, routes6: true}
	rt := Runtime{Mesh: r.mesh, Platform: p.platform(), Limits: testLimits()}
	rt.Platform.Prepare = func(network string, to netip.AddrPort, _ syscall.RawConn) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.prepared = append(r.prepared, to)
		return nil
	}
	h := &exitHarness{mesh: r.mesh, runErr: make(chan error, 1)}
	rt.Ready = func(v4, v6, serves bool) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.ready = append(h.ready, readyCall{v4, v6, serves})
	}
	x, err := build(rt)
	if err != nil {
		t.Fatal(err)
	}
	r.exit, h.exit = x, x
	h.run(t)
	r.reading.Go(r.readLeaf)
	t.Cleanup(func() {
		h.stopRun(t)
		_ = r.tun.Close()
		r.reading.Wait()
	})
	return r
}

func (r *leafRig) makeLeaf() error {
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/default/accept_dad", []byte("0\n"), 0o644); err != nil {
		return err
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	ifr, err := unix.NewIfreq(leafLink)
	if err == nil {
		ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr)
	}
	if err != nil {
		_ = unix.Close(fd)
		return err
	}
	r.tun = os.NewFile(uintptr(fd), leafLink)
	link, err := net.InterfaceByName(leafLink)
	if err != nil {
		return err
	}
	if err := netnstest.SetLinkMTU(link.Index, leafMTU); err != nil {
		return err
	}
	netlink, err := netnstest.OpenNetlink()
	if err != nil {
		return err
	}
	defer netlink.Close()
	if err := netlink.AddAddresses(leafLink, rigLeaf4, rigLeaf6); err != nil {
		return err
	}
	if err := netlink.RouteVia(link.Index, netip.MustParsePrefix("0.0.0.0/0"), rigMesh4); err != nil {
		return err
	}
	return netlink.RouteVia(link.Index, netip.MustParsePrefix("::/0"), rigMesh6)
}

// readLeaf hands the exit each packet the leaf sends from its own addresses,
// as a session delivers it
func (r *leafRig) readLeaf() {
	buf := make([]byte, 1<<16)
	for {
		n, err := r.tun.Read(buf)
		if err != nil {
			return
		}
		raw := buf[:n]
		if version := raw[0] >> 4; version != 4 && version != 6 || !leafSource(raw) {
			continue
		}
		if tap := r.tap.Load(); tap != nil {
			(*tap)(raw)
		}
		if before := r.before.Load(); before != nil {
			(*before)(raw)
		}
		r.exit.Egress(frames(raw), nil)
	}
}

// leafSource is whether raw comes from one of the leaf's addresses
func leafSource(raw []byte) bool {
	if raw[0]>>4 == 4 {
		return len(raw) >= 20 && netip.AddrFrom4([4]byte(raw[12:16])) == rigLeaf4.Addr()
	}
	return len(raw) >= 40 && netip.AddrFrom16([16]byte(raw[8:24])) == rigLeaf6.Addr()
}

// listen serves each connection to server's address at port with serve, on
// this namespace's loopback
func (r *leafRig) listen(server netip.Addr, port uint16, serve func(net.Conn)) netip.AddrPort {
	r.t.Helper()
	at := netip.AddrPortFrom(server, port)
	listener, err := net.Listen("tcp", at.String())
	if err != nil {
		r.t.Fatalf("listen on %s: %v", at, err)
	}
	r.t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go serve(conn)
		}
	}()
	return at
}

// dial opens a TCP connection from the leaf's local to remote within wait,
// taking the local port with SO_REUSEADDR as a leaf reusing a port takes it.
// A connect the leaf's kernel refuses with EADDRNOTAVAIL, its socket of the
// last connection on the four-tuple still in LAST_ACK for the ACK on its way,
// sent no segment and is tried again.
func (r *leafRig) dial(local, remote netip.AddrPort, wait time.Duration) (*net.TCPConn, error) {
	deadline := time.Now().Add(wait)
	for {
		conn, err := r.dialOnce(local, remote, time.Until(deadline))
		if !errors.Is(err, unix.EADDRNOTAVAIL) || time.Now().After(deadline) {
			return conn, err
		}
		time.Sleep(leafRedial)
	}
}

func (r *leafRig) dialOnce(local, remote netip.AddrPort, wait time.Duration) (*net.TCPConn, error) {
	var conn net.Conn
	err := r.leaf.Do(func() error {
		dialer := net.Dialer{
			LocalAddr: net.TCPAddrFromAddrPort(local),
			Timeout:   wait,
			Control: func(_, _ string, raw syscall.RawConn) error {
				var set error
				if err := raw.Control(func(fd uintptr) { set = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1) }); err != nil {
					return err
				}
				return set
			},
		}
		var err error
		conn, err = dialer.Dial("tcp", remote.String())
		return err
	})
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}
