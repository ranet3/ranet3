// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package netstack

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// unprivilegedSend names, in the environment of this test binary run again as a child, the source the child sends from
const unprivilegedSend = "RANET3_TEST_UNPRIVILEGED_SEND"

// unprivilegedPort is the UDP port every send of the test below goes to
const unprivilegedPort = 5000

// the host's own kernel hands the tun a packet from ::1 that a process with no capability over the namespace sends, and the mesh on that tun counts it martian and sends it to no peer
// a send from the tun's own address reaches the peer first, which shows the path to it works, and the IPv4 subtest sends from 127.0.0.1 with route_localnet set in the namespace
// the sender is this binary run again from the namespace's thread, under a real root with its user and group 65534 and no capability left
// under a mapped root, as unshare -rn gives, in a user namespace of its own, which holds no capability over the namespace a user namespace above it owns
// the child shows it is in the test's namespace, that no capability it holds reaches that namespace and that a raw socket is refused there, then sends, and the send must succeed
// the mesh is closed before its peer is read, so every packet its readers took has met its peer
func TestTunReadFromLoopbackOfAProcessWithNoCapabilityReachesNoPeer(t *testing.T) {
	if source := os.Getenv(unprivilegedSend); source != "" {
		unprivilegedChild(netip.MustParseAddr(source))
		return
	}
	for _, c := range []struct {
		name                  string
		own, loopback, target netip.Prefix
		route                 netip.Prefix
	}{
		{"IPv6", netip.MustParsePrefix("3fff::1/64"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("3fff:9::9/128"), netip.MustParsePrefix("3fff:9::/64")},
		{"IPv4 with route_localnet", netip.MustParsePrefix("192.0.2.1/24"), netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("198.51.100.9/32"), netip.MustParsePrefix("198.51.100.0/24")},
	} {
		t.Run(c.name, func(t *testing.T) {
			netnstest.EnterEmpty(t)
			m, err := NewNamed(DefaultMTU, "refused0", false, nil)
			if err != nil {
				t.Fatalf("open the mesh: %v", err)
			}
			t.Cleanup(m.Close)
			recorder := &recordingPeer{}
			m.Routes.Set(netip.Prefix{}, c.route, recorder.peer(t, "peer"))
			m.Routes.Set(netip.Prefix{}, hostPrefix(c.own.Addr()), Local)
			nl, err := netnstest.OpenNetlink()
			if err != nil {
				t.Fatal(err)
			}
			defer nl.Close()
			if err := nl.AddAddresses(m.Name, c.own); err != nil {
				t.Fatalf("give %s %s: %v", m.Name, c.own, err)
			}
			if err := netnstest.BringUp(m.Name); err != nil {
				t.Fatal(err)
			}
			link, err := net.InterfaceByName(m.Name)
			if err != nil {
				t.Fatal(err)
			}
			if err := nl.RouteVia(link.Index, c.route, netip.Addr{}); err != nil {
				t.Fatalf("route %s into %s: %v", c.route, m.Name, err)
			}
			if c.own.Addr().Is4() {
				for _, path := range []string{"/proc/sys/net/ipv4/conf/all/route_localnet", "/proc/sys/net/ipv4/conf/" + m.Name + "/route_localnet"} {
					if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
						t.Fatalf("write %s: %v", path, err)
					}
				}
			}
			waitUntil(t, "the tun's own address to send from", func() bool { return sendBound(c.own.Addr(), c.target.Addr()) == nil })
			waitUntil(t, "the send from the tun's own address to reach the peer", func() bool { return len(recorder.packets(t)) != 0 })
			ownSent := recorder.packets(t)
			for _, p := range ownSent {
				if src, dst, _, _ := addrsOf(p); src != c.own.Addr() || dst != c.target.Addr() {
					t.Fatalf("the peer took a packet from %s to %s, want only the send from %s", src, dst, c.own.Addr())
				}
			}
			before := m.TransitCounters().Martian
			report := runUnprivileged(t, c.loopback.Addr(), c.target.Addr())
			t.Logf("the child's effective capabilities %s, the owner of the test's namespace %s, capable there %s", report["capeff"], report["owner"], report["capable"])
			if report["netns"] != namespaceOf(t, "/proc/thread-self/ns/net") {
				t.Fatalf("the child ran in the network namespace %s, want the test's", report["netns"])
			}
			if report["capable"] != "false" {
				t.Fatalf("the child holds capabilities %s that reach the test's namespace, its owner %s", report["capeff"], report["owner"])
			}
			if report["raw"] != syscall.EPERM.Error() {
				t.Fatalf("the child's raw socket was refused with %q, want %q", report["raw"], syscall.EPERM.Error())
			}
			if report["send"] != "ok" {
				t.Fatalf("the child's send from %s failed: %s", c.loopback.Addr(), report["send"])
			}
			waitUntil(t, "the read from "+c.loopback.Addr().String()+" to reach the mesh", func() bool {
				return m.TransitCounters().Martian != before || len(recorder.packets(t)) != len(ownSent)
			})
			m.Close()
			if got := m.TransitCounters().Martian - before; got != 1 {
				t.Errorf("the mesh counted %d reads martian, want the one from %s", got, c.loopback.Addr())
			}
			if got := recorder.packets(t); len(got) != len(ownSent) {
				t.Errorf("the peer took %d packets past the send from the tun's own address, want none", len(got)-len(ownSent))
			}
		})
	}
}

// sendBound sends one UDP datagram from a socket bound to source to target's unprivilegedPort
func sendBound(source, target netip.Addr) error {
	family, bind, to := unix.AF_INET6, unix.Sockaddr(&unix.SockaddrInet6{Addr: source.As16()}), unix.Sockaddr(&unix.SockaddrInet6{Addr: target.As16(), Port: unprivilegedPort})
	if source.Is4() {
		family, bind, to = unix.AF_INET, &unix.SockaddrInet4{Addr: source.As4()}, &unix.SockaddrInet4{Addr: target.As4(), Port: unprivilegedPort}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, bind); err != nil {
		return err
	}
	return unix.Sendto(fd, []byte("datagram"), 0, to)
}

// namespaceOf is the inode of the namespace file at path, as a decimal string
func namespaceOf(t testing.TB, path string) string {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return strconv.FormatUint(st.Ino, 10)
}

// runUnprivileged runs this binary again from the calling thread, which holds the test's namespace, to send from source to target as unprivilegedChild does
// a real root drops to user and group 65534, a mapped root starts the child in a user namespace of its own, and it returns the child's report by key
func runUnprivileged(t *testing.T, source, target netip.Addr) map[string]string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestTunReadFromLoopbackOfAProcessWithNoCapabilityReachesNoPeer$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), unprivilegedSend+"="+source.String(), unprivilegedSend+"_TO="+target.String())
	mapping, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		t.Fatal(err)
	}
	if fields := strings.Fields(string(mapping)); len(fields) == 3 && fields[0] == "0" && fields[1] == "0" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the child exited with %v:\n%s", err, out)
	}
	report := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		if key, value, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "="); ok && strings.HasPrefix(key, "child.") {
			report[strings.TrimPrefix(key, "child.")] = value
		}
	}
	for _, key := range []string{"netns", "capable", "raw", "send"} {
		if _, ok := report[key]; !ok {
			t.Fatalf("the child reported no %s:\n%s", key, out)
		}
	}
	return report
}

// unprivilegedChild is the child's side: it reports its network namespace, whether a capability it holds reaches that namespace
// the error a raw socket meets, and the result of a UDP send from source to the target its environment names
func unprivilegedChild(source netip.Addr) {
	target := netip.MustParseAddr(os.Getenv(unprivilegedSend + "_TO"))
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/net", &st); err == nil {
		fmt.Printf("child.netns=%d\n", st.Ino)
	}
	capEff := effectiveCapabilities()
	inScope, err := ownerInScope()
	fmt.Printf("child.capeff=%x\nchild.owner=in scope %t, %v\n", capEff, inScope, err)
	fmt.Printf("child.capable=%t\n", capEff != 0 && inScope)
	raw := "ok"
	if fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW); err != nil {
		raw = err.Error()
	} else {
		unix.Close(fd)
	}
	fmt.Printf("child.raw=%s\n", raw)
	send := "ok"
	if err := sendBound(source, target); err != nil {
		send = err.Error()
	}
	fmt.Printf("child.send=%s\n", send)
}

// effectiveCapabilities is CapEff of this process's status, all ones where it cannot be read
func effectiveCapabilities() uint64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ^uint64(0)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if value, ok := strings.CutPrefix(line, "CapEff:"); ok {
			if n, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64); err == nil {
				return n
			}
		}
	}
	return ^uint64(0)
}

// ownerInScope reports whether the user namespace owning this process's network namespace is its own or one below it, the scope a capability it holds reaches
// NS_GET_USERNS refuses with EPERM an owner outside that scope, and any other failure counts as in scope, so the test fails rather than pass on it
func ownerInScope() (bool, error) {
	netns, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, err
	}
	defer unix.Close(netns)
	fd, err := unix.IoctlRetInt(netns, unix.NS_GET_USERNS)
	switch {
	case errors.Is(err, unix.EPERM):
		return false, nil
	case err != nil:
		return true, err
	}
	unix.Close(fd)
	return true, nil
}
