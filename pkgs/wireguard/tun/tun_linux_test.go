/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package tun

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const testMTU = 1420

func requireNetAdmin(tb testing.TB) {
	// These tests create real IFF_MULTI_QUEUE tun interfaces, which needs
	// CAP_NET_ADMIN.
	tb.Helper()
	if _, err := os.Stat(cloneDevicePath); err != nil {
		tb.Skipf("%s is unavailable: %v", cloneDevicePath, err)
	}
	file, err := openTUNFile(testTUNName(tb), unix.IFF_TUN|unix.IFF_NO_PI|unix.IFF_MULTI_QUEUE)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			tb.Skip("needs CAP_NET_ADMIN to create a tun interface")
		}
		tb.Fatalf("failed to create a probe tun interface: %v", err)
	}
	file.Close()
}

var testTUNSeq atomic.Uint32

func testTUNName(tb testing.TB) string {
	tb.Helper()
	return fmt.Sprintf("wgt%dx%d", os.Getpid()%10000, testTUNSeq.Add(1))
}

func openQueueFiles(tb testing.TB, queues int) []*os.File {
	tb.Helper()
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR)
	if queues > 1 {
		flags |= unix.IFF_MULTI_QUEUE
	}
	first, err := openTUNFile(testTUNName(tb), flags)
	if err != nil {
		tb.Fatalf("openTUNFile: %v", err)
	}
	files := []*os.File{first}
	closeAll := func() {
		for _, f := range files {
			f.Close()
		}
	}
	name, err := tunNameOf(first)
	if err != nil {
		closeAll()
		tb.Fatalf("tunNameOf: %v", err)
	}
	for i := 1; i < queues; i++ {
		f, err := openTUNFile(name, flags)
		if err != nil {
			closeAll()
			tb.Fatalf("openTUNFile queue %d: %v", i, err)
		}
		files = append(files, f)
	}
	tb.Cleanup(closeAll)
	return files
}

func tunFlags(tb testing.TB, tun *NativeTun) uint16 {
	tb.Helper()
	var ifr [ifReqSize]byte
	var errno unix.Errno
	sc, err := tun.File().SyscallConn()
	if err != nil {
		tb.Fatalf("SyscallConn: %v", err)
	}
	err = sc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd,
			uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	})
	if err != nil {
		tb.Fatalf("TUNGETIFF: %v", err)
	}
	if errno != 0 {
		tb.Fatalf("TUNGETIFF: %v", errno)
	}
	return *(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ]))
}

func TestTUNLifecycle(t *testing.T) {
	requireNetAdmin(t)
	constructors := []struct {
		name   string
		create func(tb testing.TB, queues int) (Device, []*os.File)
	}{{
		name: "CreateTUN",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			name := testTUNName(tb)
			dev, err := CreateTUN(name, testMTU, WithQueues(queues))
			if err != nil {
				tb.Fatalf("CreateTUN(%q, %d queues): %v", name, queues, err)
			}
			return dev, nil
		},
	}, {
		name: "CreateTUN/wildcardName",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			name := testTUNName(tb) + "%d"
			dev, err := CreateTUN(name, testMTU, WithQueues(queues))
			if err != nil {
				tb.Fatalf("CreateTUN(%q, %d queues): %v", name, queues, err)
			}
			return dev, nil
		},
	}, {
		// Only the first queue may refuse an existing interface, or no
		// exclusive device would get a second queue.
		name: "CreateTUN/exclusive",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			name := testTUNName(tb)
			dev, err := CreateTUN(name, testMTU, WithQueues(queues), Exclusive())
			if err != nil {
				tb.Fatalf("CreateTUN(%q, %d queues, Exclusive): %v", name, queues, err)
			}
			return dev, nil
		},
	}, {
		name: "CreateTUNFromFiles",
		create: func(tb testing.TB, queues int) (Device, []*os.File) {
			tb.Helper()
			files := openQueueFiles(tb, queues)
			if len(files) == 1 {
				// Cover the single-file wrapper as well.
				dev, err := CreateTUNFromFile(files[0], testMTU)
				if err != nil {
					tb.Fatalf("CreateTUNFromFile: %v", err)
				}
				return dev, files
			}
			dev, err := CreateTUNFromFiles(files, testMTU)
			if err != nil {
				tb.Fatalf("CreateTUNFromFiles(%d files): %v", len(files), err)
			}
			return dev, files
		},
	}}

	for _, ctor := range constructors {
		for _, queues := range []int{1, 4} {
			t.Run(fmt.Sprintf("%s/%dqueues", ctor.name, queues), func(t *testing.T) {
				dev, want := ctor.create(t, queues)
				t.Cleanup(func() { dev.Close() })

				qs := QueuesOf(dev)
				if len(qs) != queues {
					t.Fatalf("QueuesOf returned %d queues, want %d", len(qs), queues)
				}

				name, err := dev.Name()
				if err != nil {
					t.Fatalf("Name: %v", err)
				}

				fds := make([]uintptr, 0, queues)
				seen := make(map[uintptr]bool, queues)
				for i, q := range qs {
					f := q.File()
					if f == nil {
						t.Fatalf("queue %d has no file", i)
					}
					// Every queue has to be on the same interface.
					if got, err := tunNameOf(f); err != nil {
						t.Errorf("queue %d name: %v", i, err)
					} else if got != name {
						t.Errorf("queue %d is on interface %q, want %q", i, got, name)
					}
					// Each queue must wrap the file it was given, in order.
					if want != nil && f != want[i] {
						t.Errorf("queue %d wraps %v, want %v", i, f, want[i])
					}
					// And each must be its own descriptor.
					fd := f.Fd()
					if seen[fd] {
						t.Errorf("queue %d reuses fd %d", i, fd)
					}
					seen[fd] = true
					fds = append(fds, fd)
				}

				// Every member of a multiqueue group has to declare
				// IFF_MULTI_QUEUE, and a single-queue device must not.
				flags := tunFlags(t, dev.(*NativeTun))
				if got, want := flags&unix.IFF_MULTI_QUEUE != 0, queues > 1; got != want {
					t.Errorf("IFF_MULTI_QUEUE set = %v, want %v (flags = %#x)", got, want, flags)
				}

				if err := dev.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				for i, fd := range fds {
					if _, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", fd)); err == nil {
						t.Errorf("queue %d fd %d still open after Close", i, fd)
					}
				}
				// Close is idempotent: device.Device.Close and the embedder
				// both call it.
				if err := dev.Close(); err != nil {
					t.Errorf("second Close: %v", err)
				}
			})
		}
	}
}

func TestCreateTUNExclusive(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	held, err := CreateTUN(name, testMTU, WithQueues(2))
	if err != nil {
		t.Fatalf("CreateTUN(%q, 2 queues): %v", name, err)
	}
	t.Cleanup(func() { held.Close() })

	// A multiqueue interface takes more queues, so only Exclusive refuses it.
	joined, err := CreateTUN(name, testMTU, WithQueues(2))
	if err != nil {
		t.Fatalf("CreateTUN(%q, 2 queues) on the existing interface: %v", name, err)
	}
	joined.Close()

	dev, err := CreateTUN(name, testMTU, WithQueues(2), Exclusive())
	if err == nil {
		dev.Close()
		t.Fatalf("CreateTUN(%q, Exclusive) attached to the existing interface", name)
	}
	if !errors.Is(err, unix.EBUSY) {
		t.Errorf("CreateTUN(%q, Exclusive) = %v, want EBUSY", name, err)
	}
}

func TestCreateTUNSingleQueueAttachesToMultiQueue(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	held, err := CreateTUN(name, testMTU, WithQueues(2))
	if err != nil {
		t.Fatalf("CreateTUN(%q, 2 queues): %v", name, err)
	}
	t.Cleanup(func() { held.Close() })

	dev, err := CreateTUN(name, testMTU)
	if err != nil {
		t.Fatalf("CreateTUN(%q, 1 queue) on a multiqueue interface: %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })
	if flags := tunFlags(t, dev.(*NativeTun)); flags&unix.IFF_MULTI_QUEUE == 0 {
		t.Errorf("the attached queue does not declare IFF_MULTI_QUEUE (flags = %#x)", flags)
	}
}

func TestCreateTUNMultiQueue(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU, MultiQueue())
	if err != nil {
		t.Fatalf("CreateTUN(%q, MultiQueue): %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })
	if n := len(QueuesOf(dev)); n != 1 {
		t.Errorf("QueuesOf returned %d queues, want 1", n)
	}
	if flags := tunFlags(t, dev.(*NativeTun)); flags&unix.IFF_MULTI_QUEUE == 0 {
		t.Errorf("the interface does not declare IFF_MULTI_QUEUE (flags = %#x)", flags)
	}

	// A single-queue interface would refuse a second queue.
	joined, err := CreateTUN(name, testMTU, WithQueues(2))
	if err != nil {
		t.Fatalf("CreateTUN(%q, 2 queues) on the interface: %v", name, err)
	}
	joined.Close()
}

func TestCreateTUNMultiQueueAttachesToSingleQueue(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	persistTUN(t, name, unix.IFF_TUN|unix.IFF_NO_PI|unix.IFF_VNET_HDR)

	dev, err := CreateTUN(name, testMTU, MultiQueue())
	if err != nil {
		t.Fatalf("CreateTUN(%q, MultiQueue) on a single-queue interface: %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })
	if flags := tunFlags(t, dev.(*NativeTun)); flags&unix.IFF_MULTI_QUEUE != 0 {
		t.Errorf("the interface declares IFF_MULTI_QUEUE (flags = %#x)", flags)
	}
}

// persistTUN creates an interface that outlives its file, as a network manager
// does, and removes it when the test ends.
func persistTUN(tb testing.TB, name string, flags uint16) {
	tb.Helper()
	persist := func(value int) error {
		file, err := openTUNFile(name, flags)
		if err != nil {
			return err
		}
		defer file.Close()
		return unix.IoctlSetInt(int(file.Fd()), unix.TUNSETPERSIST, value)
	}
	if err := persist(1); err != nil {
		tb.Fatalf("persisting %q: %v", name, err)
	}
	tb.Cleanup(func() {
		if err := persist(0); err != nil {
			tb.Errorf("removing %q: %v", name, err)
		}
	})
}

// eventSettle is how long a device that watches its interface takes to send
// the events of a link change.
const eventSettle = 500 * time.Millisecond

func TestCreateTUNUnmonitored(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU, WithQueues(2), Unmonitored())
	if err != nil {
		t.Fatalf("CreateTUN(%q, Unmonitored): %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })

	setLinkUp(t, name)
	time.Sleep(eventSettle)
	select {
	case ev := <-dev.Events():
		t.Errorf("an unmonitored device sent event %d", ev)
	default:
	}

	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case ev, ok := <-dev.Events():
		if ok {
			t.Errorf("an unmonitored device sent event %d after Close", ev)
		}
	case <-time.After(eventSettle):
		t.Error("Close did not close the Events channel")
	}
}

func TestCreateTUNUnmonitoredHoldsOnlyItsQueues(t *testing.T) {
	requireNetAdmin(t)
	const queues = 2
	before := openFiles(t)
	dev, err := CreateTUN(testTUNName(t), testMTU, WithQueues(queues), Unmonitored())
	if err != nil {
		t.Fatalf("CreateTUN(Unmonitored): %v", err)
	}
	during := openFiles(t)
	if err := dev.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := openFiles(t)

	// No route socket, and no pipe to cancel a read of one.
	tuns := 0
	for fd, file := range during {
		if before[fd] == file {
			continue
		}
		if file == cloneDevicePath {
			tuns++
		} else {
			t.Errorf("an unmonitored device holds fd %s on %s", fd, file)
		}
	}
	if tuns != queues {
		t.Errorf("an unmonitored device holds %d fds on %s, want %d", tuns, cloneDevicePath, queues)
	}
	for fd, file := range after {
		if before[fd] != file {
			t.Errorf("fd %s on %s outlived Close", fd, file)
		}
	}
}

// openFiles maps each open fd of the process to the file it refers to.
func openFiles(tb testing.TB) map[string]string {
	tb.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		tb.Fatalf("ReadDir: %v", err)
	}
	files := make(map[string]string, len(entries))
	for _, entry := range entries {
		file, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			// The fd ReadDir read the directory through, closed since.
			continue
		}
		files[entry.Name()] = file
	}
	return files
}

func TestSetGSOMaxSegs(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	dev, err := CreateTUN(name, testMTU, Unmonitored())
	if err != nil {
		t.Fatalf("CreateTUN(%q): %v", name, err)
	}
	t.Cleanup(func() { dev.Close() })
	before := gsoMaxSegs(t, name)
	want := uint32(dev.BatchSize())
	if before == want {
		t.Fatalf("gso_max_segs is already %d, so this proves nothing", before)
	}

	if err := dev.(*NativeTun).SetGSOMaxSegs(dev.BatchSize()); err != nil {
		t.Fatalf("SetGSOMaxSegs(%d): %v", want, err)
	}
	if got := gsoMaxSegs(t, name); got != want {
		t.Errorf("gso_max_segs = %d, want %d", got, want)
	}
}

// gsoMaxSegs reads the interface's gso_max_segs from a link dump, which,
// unlike sysfs, shows the caller's network namespace.
func gsoMaxSegs(tb testing.TB, name string) uint32 {
	tb.Helper()
	index, err := getIFIndex(name)
	if err != nil {
		tb.Fatalf("getIFIndex(%q): %v", name, err)
	}
	rib, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		tb.Fatalf("NetlinkRIB: %v", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		tb.Fatalf("ParseNetlinkMessage: %v", err)
	}
	for i := range msgs {
		msg := &msgs[i]
		if msg.Header.Type != unix.RTM_NEWLINK || len(msg.Data) < unix.SizeofIfInfomsg {
			continue
		}
		if int32(binary.NativeEndian.Uint32(msg.Data[4:])) != index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(msg)
		if err != nil {
			tb.Fatalf("ParseNetlinkRouteAttr: %v", err)
		}
		for _, attr := range attrs {
			if attr.Attr.Type == unix.IFLA_GSO_MAX_SEGS && len(attr.Value) == 4 {
				return binary.NativeEndian.Uint32(attr.Value)
			}
		}
	}
	tb.Fatalf("no IFLA_GSO_MAX_SEGS for %q", name)
	return 0
}

func TestTooManyQueues(t *testing.T) {
	requireNetAdmin(t)
	name := testTUNName(t)
	const queues = 1000
	dev, err := CreateTUN(name, testMTU, WithQueues(queues))
	if err == nil {
		dev.Close()
		t.Fatalf("CreateTUN with %d queues succeeded, want an error", queues)
	}
	if !strings.Contains(err.Error(), "attaching extra tun queue") {
		t.Errorf("error = %q, want it to mention the failing queue", err)
	}
}

func TestTooFewQueues(t *testing.T) {
	for _, queues := range []int{0, -1} {
		dev, err := CreateTUN(testTUNName(t), testMTU, WithQueues(queues))
		if err == nil {
			dev.Close()
			t.Fatalf("CreateTUN with %d queues succeeded, want an error", queues)
		}
		if !strings.Contains(err.Error(), "must be at least 1") {
			t.Errorf("error = %q, want it to mention the minimum", err)
		}
	}
}

func TestCreateTUNFromFilesErrorClosesFiles(t *testing.T) {
	requireNetAdmin(t)
	files := openQueueFiles(t, 4)
	dev, err := CreateTUNFromFiles(files, 1)
	if err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles with MTU 1 succeeded, want an error")
	}
	for i, f := range files {
		if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("queue %d not closed by a failed CreateTUNFromFiles: err = %v", i, err)
		}
	}
}

func TestCreateTUNFromFilesNonTUNClosesFile(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("Open %s: %v", os.DevNull, err)
	}
	defer f.Close()

	if dev, err := CreateTUNFromFiles([]*os.File{f}, testMTU); err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles on a non-TUN file succeeded, want an error")
	}
	if _, err := f.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("file not closed by a failed CreateTUNFromFiles: err = %v", err)
	}
}

func setLinkUp(tb testing.TB, name string) {
	tb.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		tb.Fatalf("socket: %v", err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		tb.Fatalf("NewIfreq: %v", err)
	}
	ifr.SetUint16(unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		tb.Fatalf("SIOCSIFFLAGS: %v", err)
	}
}

func TestWriteAllocs(t *testing.T) {
	requireNetAdmin(t)
	dev, err := CreateTUN(testTUNName(t), testMTU)
	if err != nil {
		t.Fatalf("CreateTUN: %v", err)
	}
	t.Cleanup(func() { dev.Close() })
	tun := dev.(*NativeTun)
	if !tun.vnetHdr {
		t.Skip("the tun has no virtio header, so writes take the plain path")
	}
	name, err := dev.Name()
	if err != nil {
		t.Fatalf("Name: %v", err)
	}
	// a tun that is down refuses writes with EIO
	setLinkUp(t, name)

	segments := make([][]byte, 46)
	for i := range segments {
		segments[i] = tcp4Packet(ip4PortA, ip4PortB, header.TCPFlagAck, 100, uint32(1+100*i))
	}
	acks := make([][]byte, 8)
	for i := range acks {
		acks[i] = tcp4Packet(ip4PortA, netip.AddrPortFrom(ip4PortB.Addr(), uint16(i+1)), header.TCPFlagAck, 0, 1)
	}
	tests := []struct {
		name    string
		packets [][]byte
	}{
		{"one packet", acks[:1]},
		{"packets that do not coalesce", acks},
		{"segments that coalesce into one frame", segments},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// GRO rewrites the packets it coalesces, so each write gets a fresh copy
			bufs := make([][]byte, len(tt.packets))
			for i, p := range tt.packets {
				bufs[i] = make([]byte, len(p))
			}
			var werr error
			allocs := testing.AllocsPerRun(100, func() {
				for i, p := range tt.packets {
					copy(bufs[i], p)
				}
				if _, err := dev.Write(bufs, offset); err != nil {
					werr = err
				}
			})
			if werr != nil {
				t.Fatalf("Write: %v", werr)
			}
			if allocs != 0 {
				t.Errorf("Write allocated %v times per call, want 0", allocs)
			}
			q := tun.queues[0]
			for i, v := range q.wvIovecs[:cap(q.wvIovecs)] {
				if v.Base != nil {
					t.Errorf("iovec %d still points into a written packet", i)
				}
			}
		})
	}
}

func TestReadError(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		closed  bool
		invalid bool
	}{
		{"EINVAL", &os.PathError{Op: "read", Path: "/dev/net/tun", Err: unix.EINVAL}, false, true},
		{"EBADFD", &os.PathError{Op: "read", Path: "/dev/net/tun", Err: unix.EBADFD}, true, false},
		{"closed file", os.ErrClosed, true, false},
		{"EFAULT", &os.PathError{Op: "read", Path: "/dev/net/tun", Err: unix.EFAULT}, false, false},
		{"EIO", &os.PathError{Op: "read", Path: "/dev/net/tun", Err: unix.EIO}, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := readError(tt.err)
			if got := errors.Is(err, os.ErrClosed); got != tt.closed {
				t.Errorf("errors.Is(readError(%v), os.ErrClosed) = %v, want %v", tt.err, got, tt.closed)
			}
			if got := errors.Is(err, ErrInvalidFrame); got != tt.invalid {
				t.Errorf("errors.Is(readError(%v), ErrInvalidFrame) = %v, want %v", tt.err, got, tt.invalid)
			}
		})
	}
}

// TestQueueReadEINVALIsInvalidFrame reads an eventfd into a buffer shorter
// than its 8-byte counter, which fails with EINVAL as a tun read of a packet
// the kernel cannot copy out does.
func TestQueueReadEINVALIsInvalidFrame(t *testing.T) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "eventfd")
	defer file.Close()
	q := &tunQueue{tun: &NativeTun{}, file: file}
	slab := make([]byte, 2*ReadPacketSpacing+4)
	n, err := q.Read(slab, make([]ReadPacket, 1))
	if !errors.Is(err, ErrInvalidFrame) || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Read = %d, %v, want ErrInvalidFrame wrapping EINVAL", n, err)
	}
}

func TestCreateTUNFromFilesRejectsEmpty(t *testing.T) {
	dev, err := CreateTUNFromFiles(nil, testMTU)
	if err == nil {
		dev.Close()
		t.Fatal("CreateTUNFromFiles(nil) succeeded, want an error")
	}
	if err.Error() == "" {
		t.Error("CreateTUNFromFiles(nil) returned an error with an empty message")
	}
}
