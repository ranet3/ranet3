// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package userspace

import (
	"context"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// for any sequence of dials, each readying a new socket through the dial's
// Control for each connect that failed with EADDRNOTAVAIL, as Go does up to
// twice, and ending in a connection, a refusal, a cancellation or a third
// EADDRNOTAVAIL, the process holds, once each dial's error queue is read and
// closed, one descriptor of each connection left open and none of any other
// socket a dial readied, counted over the sockets the case readied and no other
// descriptor of the process
func TestDialHoldsNoDescriptorPastItsConnections(t *testing.T) {
	x := dialingExit(t, egress.Egress{}, func(string, netip.AddrPort, syscall.RawConn) error { return nil })
	r := &tcpRelay{x: x}
	server := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 80)
	unbound := func(int) error { return nil }
	pbt.Check(t, func(ht *hegel.T) {
		var open []*os.File
		defer func() {
			for _, socket := range open {
				_ = socket.Close()
			}
		}()
		// each socket the dials readied, and whether its connection stays open
		readied := map[socketID]bool{}
		mark, unmarked := firstMark, 0
		// a failed case takes its marks off what it left open, closing nothing, so the next case and the engine's replay start where no descriptor carries one and fail on their own line
		failing := &notingCase{T: ht}
		defer func() {
			if failing.failed {
				unmarkSockets(readied, unmarked)
			}
		}()
		// a socket the case did not ready that carries a mark of its range would count as one of the case's, so the case starts where none does
		for id, count := range heldSockets(failing) {
			if id.mark >= firstMark && id.mark <= lastMark {
				failing.Fatalf("%d descriptors the case did not ready carry mark %d of its range at its start, foreign ones or ones an earlier case left open", count, id.mark)
			}
		}
		for range hegel.Draw(ht, hegel.Integers(1, 3)) {
			notAvailable := hegel.Draw(ht, hegel.Integers(0, 3))
			end := []error{nil, syscall.ECONNREFUSED, context.Canceled}[hegel.Draw(ht, hegel.Integers(0, 2))]
			queue := x.icmp.queue()
			control := r.control(server, unbound, &queue)
			var failure error
			for attempt := range min(notAvailable, 2) + 1 {
				if mark > lastMark {
					failing.Fatalf("a case readies more sockets than the %d marks it has", lastMark-firstMark+1)
				}
				socket := streamSocket(failing)
				var id socketID
				id, unmarked = markSocket(failing, socket, mark)
				mark++
				readied[id] = false
				raw, err := socket.SyscallConn()
				if err != nil {
					failing.Fatal(err)
				}
				if err := control("tcp4", server.String(), raw); err != nil {
					_ = socket.Close()
					failing.Fatalf("the dial's control refused socket %d: %v", attempt, err)
				}
				failure = end
				if attempt < notAvailable {
					failure = syscall.EADDRNOTAVAIL
				}
				if failure == nil {
					readied[id] = true
					open = append(open, socket)
				} else {
					_ = socket.Close()
				}
			}
			queue.read(failure)
			queue.close()
			// the count is of the sockets the dials readied alone, so a descriptor the rest of the process opens or closes meanwhile is not in it
			held := heldSockets(failing)
			for socket, kept := range readied {
				want := 0
				if kept {
					want = 1
				}
				if held[socket] != want {
					failing.Fatalf("the process holds %d descriptors of the socket of mark %d a dial readied with %d connections open, want %d", held[socket], socket.mark, len(open), want)
				}
			}
		}
	})
}

// notingCase is a case that notes its failure before it fails, so what it defers sees the failure
type notingCase struct {
	*hegel.T
	failed bool
}

func (c *notingCase) Fatalf(format string, args ...any) {
	c.failed = true
	c.T.Fatalf(format, args...)
}

func (c *notingCase) Fatal(args ...any) {
	c.failed = true
	c.T.Fatal(args...)
}

// openFiles is how many descriptors the process holds open
func openFiles(t fataler) int {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the process's descriptors: %v", err)
	}
	return len(entries)
}

// socketID names a socket by its device, its inode and the mark the case gave it, which each of its descriptors shares
// darwin reads every socket's device and inode as 0, so there the mark alone tells the case's sockets apart
type socketID struct {
	device, inode uint64
	mark          int
}

// the marks are IPv4 TTLs a case gives its sockets, one each, apart from the defaults 64 and 255
// streamSocket readies IPv4 sockets alone, and a case readies at most three tries of three dials
const (
	firstMark = 101
	lastMark  = 109
)

// identityOf is the identity of what fd names, false where it names nothing
// a descriptor that answers no IPv4 TTL has mark 0, and a Linux IPv6 socket answers one
func identityOf(fd int) (socketID, bool) {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return socketID{}, false
	}
	id := socketID{device: uint64(stat.Dev), inode: uint64(stat.Ino)}
	if ttl, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL); err == nil {
		id.mark = ttl
	}
	return id, true
}

// heldSockets is how many descriptors of the process name each file
// a descriptor closed between the listing and its stat is in no count, since it names nothing by then
func heldSockets(t fataler) map[socketID]int {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the process's descriptors: %v", err)
	}
	held := map[socketID]int{}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			t.Fatalf("read the process's descriptors: %v", err)
		}
		if id, ok := identityOf(fd); ok {
			held[id]++
		}
	}
	return held
}

// markSocket gives socket the mark and is its identity with the TTL it had before, failing where the mark does not read back
func markSocket(t fataler, socket *os.File, mark int) (socketID, int) {
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatalf("reach a socket: %v", err)
	}
	var id socketID
	var before int
	var set error
	ok := false
	if err := raw.Control(func(fd uintptr) {
		if before, set = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL); set != nil {
			return
		}
		if set = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, mark); set == nil {
			id, ok = identityOf(int(fd))
		}
	}); err != nil || set != nil || !ok {
		t.Fatalf("mark a socket: %v %v", err, set)
	}
	if id.mark != mark {
		t.Fatalf("a socket given mark %d reads mark %d", mark, id.mark)
	}
	return id, before
}

// unmarkSockets sets each descriptor of a socket the case readied back to the TTL ttl, closing none
// a descriptor that cannot be read or set keeps its mark, and the next case's census names it
func unmarkSockets(readied map[socketID]bool, ttl int) {
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if id, ok := identityOf(fd); ok && id.mark >= firstMark && id.mark <= lastMark {
			if _, ours := readied[id]; ours {
				_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
			}
		}
	}
}

// streamSocket is a new TCP socket of IPv4, as Go's dial makes for each try
func streamSocket(t fataler) *os.File {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("open a socket: %v", err)
	}
	unix.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), "dial")
}
