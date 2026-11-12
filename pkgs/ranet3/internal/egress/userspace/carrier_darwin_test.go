// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package userspace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

const (
	// rigNetTest names the environment variable that must be set before a rig
	// test changes the host's network
	rigNetTest = "RANET3_DARWIN_NETTEST"
	// utunControl is the kernel control a utun is made through, and
	// sysprotoControl and utunOptIfname SYSPROTO_CONTROL and UTUN_OPT_IFNAME
	utunControl     = "com.apple.net.utun_control"
	sysprotoControl = 2
	utunOptIfname   = 2
	// utunHeader is the address family a utun's descriptor puts before each
	// packet
	utunHeader = 4
	// dadWait bounds the wait for a new IPv6 address to end its duplicate
	// detection
	dadWait = 10 * time.Second
)

// the userspace exit's host on the Mac, as root: the exit the suite on the
// rig's Linux host asks for, built with the daemon's platform over a test
// selection naming the rig's utun for every address, so every socket of the
// exit's is scoped to the utun as the daemon's Bound path scopes it
func TestUserspaceExitHostOverTheCarrier(t *testing.T) {
	if os.Getenv(rigNetTest) == "" {
		t.Skipf("%s is unset, so no rig runs this host", rigNetTest)
	}
	ethernet, peer, port, controlPort := rigVariables(t)
	link, err := net.InterfaceByName(ethernet)
	if err != nil {
		t.Fatalf("rig: carrier not on %s: %v", ethernet, err)
	}
	carrier := rigCarrier(t, link, peer, port)
	listener := rigListener(t, link, controlPort)
	awaitPeer(t, carrier, peer)
	memory, err := HostMemory()
	if err != nil {
		t.Fatalf("read the host's memory: %v", err)
	}
	limits, err := Within(memory, Files())
	if err != nil {
		t.Fatalf("size the exit: %v", err)
	}
	if err := classesOnLoopback(true); err != nil {
		t.Fatalf("give lo0 the class addresses: %v", err)
	}
	var current atomic.Int64
	selection := func(netip.Addr) (int, uint64) { return int(current.Load()), 1 }
	uplink := &carriedUplink{carrier: carrier, open: func() (io.ReadWriteCloser, error) { return openRigUTUN(t, &current) }}
	uplink.start()
	control := acceptFrom(t, listener, peer)
	h := newExitHost(control, func() (Platform, error) {
		sockets, err := raw.New(underlay.Bound(selection))
		if err != nil {
			return Platform{}, err
		}
		return Darwin(selection, rigHolds(&current), sockets), nil
	}, limits, uplink)
	if err := h.serve(); err != nil && !errors.Is(err, errWireEnded) {
		t.Errorf("the wire: %v", err)
	}
	uplink.stop()
	if err := classesOnLoopback(false); err != nil {
		t.Errorf("take the class addresses off lo0: %v", err)
	}
	t.Log("rig: utun and routes removed")
}

// rigCarrier is the carrier's datagram socket on port, scoped to link, read
// back, with the route to peer naming link too
func rigCarrier(t *testing.T, link *net.Interface, peer netip.Addr, port uint16) *net.UDPConn {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return underlay.Scope(raw, false, link.Index) }}
	conn, err := config.ListenPacket(context.Background(), "udp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("open the carrier: %v", err)
	}
	carrier := conn.(*net.UDPConn)
	t.Cleanup(func() { _ = carrier.Close() })
	if got := boundIndex(t, carrier); got != link.Index {
		t.Fatalf("rig: carrier not on %s: scoped to interface %d", link.Name, got)
	}
	if routed, err := routeInterface(peer); err != nil || routed != link.Name {
		t.Fatalf("rig: carrier not on %s: the route to the peer names %q: %v", link.Name, routed, err)
	}
	t.Logf("rig: carrier bound to %s index %d", link.Name, link.Index)
	return carrier
}

// rigListener is the wire's listener on port, scoped to link
func rigListener(t *testing.T, link *net.Interface, port uint16) net.Listener {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error { return underlay.Scope(raw, false, link.Index) }}
	listener, err := config.Listen(context.Background(), "tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatalf("listen for the wire: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// boundIndex is the interface conn is scoped to
func boundIndex(t *testing.T, conn *net.UDPConn) int {
	t.Helper()
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var index int
	if controlErr := raw.Control(func(fd uintptr) { index, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF) }); controlErr != nil {
		t.Fatal(controlErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return index
}

// routeInterface is the interface the host's routes send to address by, as
// route get reads the routing socket
func routeInterface(address netip.Addr) (string, error) {
	out, err := exec.Command("route", "-n", "get", address.String()).Output()
	if err != nil {
		return "", err
	}
	for line := range strings.Lines(string(out)) {
		if name, ok := strings.CutPrefix(strings.TrimSpace(line), "interface: "); ok {
			return strings.TrimSpace(name), nil
		}
	}
	return "", errors.New("route get names no interface")
}

// rigHolds is Platform.Held on the rig, by link as the watch reads them: the
// utun's addresses, the IPv4 class among them, on the utun of index current,
// and the IPv6 class on lo0
func rigHolds(current *atomic.Int64) func(netip.Addr, string) bool {
	return func(address netip.Addr, link string) bool {
		utun := []netip.Prefix{rigAddresses[0], rigAddresses[1], rigClasses[0]}
		loopback := []netip.Prefix{rigClasses[1]}
		var on []netip.Prefix
		switch ifi, err := net.InterfaceByIndex(int(current.Load())); {
		case link == "":
			on = append(utun, loopback...)
		case link == "lo0":
			on = loopback
		case err == nil && link == ifi.Name:
			on = utun
		}
		return slices.ContainsFunc(on, func(p netip.Prefix) bool { return p.Addr() == address })
	}
}

// classesOnLoopback gives lo0 the IPv6 class address where add is set and
// takes it off where it is not: on the utun, it would win the source address
// of a socket bound to none under auto (RFC 6724), as it did on the Linux
// host's uplink. The IPv4 class goes on the utun (openRigUTUN): from lo0, every
// IPv4 flow of the address class's was refused at once, its sockets scoped to
// the utun, while the IPv6 class on lo0 carried its flows.
func classesOnLoopback(add bool) error {
	var err error
	for _, class := range rigClasses {
		if !class.Addr().Is6() {
			continue
		}
		args := []string{"lo0", "inet6", class.String(), "alias"}
		if !add {
			args = []string{"lo0", "inet6", class.Addr().String(), "-alias"}
		}
		if out, runErr := exec.Command("ifconfig", args...).CombinedOutput(); runErr != nil {
			err = errors.Join(err, fmt.Errorf("ifconfig %s: %v: %s", strings.Join(args, " "), runErr, out))
		}
	}
	return err
}

// openRigUTUN makes the exit host's uplink, a utun with the rig's addresses,
// MTU and routes scoped to it, and the IPv4 class address after the routes, so
// they keep the uplink's address as theirs, and names it the selection's
// interface for every address. Closing it removes the utun with its addresses
// and routes.
func openRigUTUN(t *testing.T, current *atomic.Int64) (io.ReadWriteCloser, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, err
	}
	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControl)
	err = unix.IoctlCtlInfo(fd, info)
	if err == nil {
		// unit 0 takes the first free utun, never one another program holds
		err = unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0})
	}
	var name string
	if err == nil {
		name, err = unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	}
	if err == nil {
		// non-blocking, so the poller holds it and its close ends a read
		err = unix.SetNonblock(fd, true)
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	unix.CloseOnExec(fd)
	u := &utun{file: os.NewFile(uintptr(fd), name)}
	v4, v6 := rigAddresses[0], rigAddresses[1]
	commands := [][]string{
		{"ifconfig", name, "inet", v4.String(), rigRoutes[0].via.String(), "mtu", strconv.Itoa(rigMTU), "up"},
		{"ifconfig", name, "inet6", v6.Addr().String(), "prefixlen", strconv.Itoa(v6.Bits())},
	}
	for _, route := range rigRoutes {
		family := "-inet"
		if route.to.Addr().Is6() {
			family = "-inet6"
		}
		commands = append(commands, []string{"route", "-n", "add", family, "-net", route.to.String(), "-interface", name, "-ifscope", name})
	}
	// a point-to-point alias, its own address its far end
	class4 := rigClasses[0]
	commands = append(commands, []string{"ifconfig", name, "inet", class4.String(), class4.Addr().String(), "alias"})
	for _, command := range commands {
		if out, err := exec.Command(command[0], command[1:]...).CombinedOutput(); err != nil {
			_ = u.Close()
			return nil, fmt.Errorf("%s: %v: %s", strings.Join(command, " "), err, out)
		}
		if command[0] == "ifconfig" && command[2] == "inet6" {
			if err := awaitDAD(name, v6.Addr()); err != nil {
				_ = u.Close()
				return nil, err
			}
		}
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		_ = u.Close()
		return nil, err
	}
	current.Store(int64(ifi.Index))
	t.Logf("rig: utun %s up", name)
	return u, nil
}

// awaitDAD waits for address on name to end its duplicate detection
func awaitDAD(name string, address netip.Addr) error {
	deadline := time.Now().Add(dadWait)
	for {
		out, err := exec.Command("ifconfig", name, "inet6").Output()
		if err != nil {
			return err
		}
		for line := range strings.Lines(string(out)) {
			if strings.Contains(line, address.String()) && !strings.Contains(line, "tentative") {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s on %s still tentative after %s", address, name, dadWait)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// utun is a utun's descriptor as one IP packet a read or write, the address
// family XNU puts before each taken off and put back
type utun struct {
	file *os.File
}

func (u *utun) Read(b []byte) (int, error) {
	buf := make([]byte, utunHeader+len(b))
	for {
		n, err := u.file.Read(buf)
		if err != nil {
			return 0, err
		}
		if n > utunHeader {
			return copy(b, buf[utunHeader:n]), nil
		}
	}
}

func (u *utun) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	family := uint32(unix.AF_INET)
	if b[0]>>4 == 6 {
		family = unix.AF_INET6
	}
	n, err := u.file.Write(append(binary.BigEndian.AppendUint32(nil, family), b...))
	return max(n-utunHeader, 0), err
}

func (u *utun) Close() error { return u.file.Close() }
