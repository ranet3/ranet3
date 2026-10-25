// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package dnstest

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// initialNamespace is the link of each initial namespace, whose inode Linux
// fixes from 6.17 on (include/uapi/linux/nsfs.h)
var initialNamespace = map[string]string{"net": "net:[4026531833]", "mnt": "mnt:[4026531832]"}

// QueryTimeout is how long Go's resolver waits for each nameserver, the timeout
// the resolv.conf Start binds names
const QueryTimeout = time.Second

const (
	// resolverWait bounds the wait for Go's resolver to read the resolv.conf
	// Start binds, past its reread of the file at most every 5 seconds
	resolverWait = 10 * time.Second
	// awaitLookup bounds each lookup of that wait
	awaitLookup = time.Second
	// awaitStep is the pause between those lookups
	awaitStep = 100 * time.Millisecond
)

// Query is one query the nameserver read: the address it was sent to and the
// mark it arrived with, all ones where the kernel handed no mark
type Query struct {
	To   netip.Addr
	Mark uint32
}

// Nameserver answers every query on port 53 of its addresses with SERVFAIL, so
// Go's resolver asks each nameserver resolv.conf lists in turn, and records each
// query it reads
type Nameserver struct {
	mu      sync.Mutex
	queries []Query
}

// Start skips the test without root and refuses it in init's network or mount
// namespace. It brings lo up, listens on port 53 of each nameserver's address
// there, binds a resolv.conf listing the nameservers as written over
// /etc/resolv.conf until the test ends, and returns once Go's resolver reads it.
// Each nameserver is an address on lo, in any spelling resolv.conf takes, and
// Go's resolver reads the first 3.
func Start(t testing.TB, nameservers ...string) *Nameserver {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("binding a resolv.conf and a nameserver on lo needs root, as unshare -rmn gives in namespaces of the process's own")
	}
	requireOwnNamespaces(t)
	if err := loopbackUp(); err != nil {
		t.Fatalf("bring lo up: %v", err)
	}
	n := &Nameserver{}
	var addresses []netip.Addr
	for _, nameserver := range nameservers {
		address := netip.MustParseAddr(nameserver).Unmap().WithZone("")
		if !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
			n.listen(t, address)
		}
	}
	bindResolvConf(t, nameservers)
	n.awaitResolver(t, addresses)
	return n
}

// Take is every query read since the last Take
func (n *Nameserver) Take() []Query {
	n.mu.Lock()
	defer n.mu.Unlock()
	queries := n.queries
	n.queries = nil
	return queries
}

// requireOwnNamespaces refuses a process sharing init's network or mount
// namespace, by its links. From a user namespace of its own /proc/1 is out of
// reach, and the fixed link of the initial namespace stands in. A kernel older
// than 6.17 fixes none, but a process there holds no capability over init's
// namespaces, so the kernel itself refuses lo, port 53 and the mount.
func requireOwnNamespaces(t testing.TB) {
	t.Helper()
	for _, kind := range []string{"net", "mnt"} {
		own, err := os.Readlink("/proc/self/ns/" + kind)
		if err != nil {
			t.Fatalf("read this process's %s namespace: %v", kind, err)
		}
		initial, err := os.Readlink("/proc/1/ns/" + kind)
		switch {
		case errors.Is(err, fs.ErrPermission):
			initial = initialNamespace[kind]
		case err != nil:
			t.Fatalf("read init's %s namespace: %v", kind, err)
		}
		if own == initial {
			t.Fatalf("refusing to start: this process shares init's %s namespace, %s, and the nameserver changes it, so run it under unshare -rmn", kind, own)
		}
	}
}

// loopbackUp brings lo up, which a network namespace unshare made holds down
func loopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// listen reads queries on port 53 of address with SO_RCVMARK set, so each
// carries its mark
func (n *Nameserver) listen(t testing.TB, address netip.Addr) {
	t.Helper()
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		if err := raw.Control(func(fd uintptr) {
			setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVMARK, 1)
		}); err != nil {
			return err
		}
		return setErr
	}}
	conn, err := config.ListenPacket(context.Background(), "udp", netip.AddrPortFrom(address, 53).String())
	if err != nil {
		t.Fatalf("listen on %s port 53: %v", address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go n.serve(conn.(*net.UDPConn), address)
}

func (n *Nameserver) serve(conn *net.UDPConn, address netip.Addr) {
	buf, oob := make([]byte, 4096), make([]byte, 512)
	for {
		size, oobSize, _, from, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return
		}
		query := Query{To: address, Mark: ^uint32(0)}
		if messages, err := unix.ParseSocketControlMessage(oob[:oobSize]); err == nil {
			for _, message := range messages {
				if message.Header.Level == unix.SOL_SOCKET && message.Header.Type == unix.SO_MARK && len(message.Data) >= 4 {
					query.Mark = binary.NativeEndian.Uint32(message.Data)
				}
			}
		}
		n.mu.Lock()
		n.queries = append(n.queries, query)
		n.mu.Unlock()
		if size < 12 {
			continue
		}
		// the query back with QR and RA set and rcode 2, SERVFAIL
		reply := append([]byte(nil), buf[:size]...)
		reply[2] |= 0x80
		reply[3] = 0x80 | 2
		_, _ = conn.WriteToUDPAddrPort(reply, from)
	}
}

// bindResolvConf binds a resolv.conf naming the nameservers over
// /etc/resolv.conf in this mount namespace, each asked once with a timeout of
// QueryTimeout, until the test ends
func bindResolvConf(t testing.TB, nameservers []string) {
	t.Helper()
	var text strings.Builder
	for _, nameserver := range nameservers {
		fmt.Fprintf(&text, "nameserver %s\n", nameserver)
	}
	fmt.Fprintf(&text, "options timeout:%d attempts:1\n", int(QueryTimeout/time.Second))
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(text.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(path, "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		t.Fatalf("bind a resolv.conf over /etc/resolv.conf: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount("/etc/resolv.conf", 0) })
}

// awaitResolver looks a name up until one lookup reaches every address, then
// forgets the queries it took. Go's resolver reads /etc/resolv.conf again at
// most every 5 seconds, so a lookup earlier in the process leaves the host's
// file in force a while, and the host's may name a nameserver here too, as
// systemd-resolved's 127.0.0.53.
func (n *Nameserver) awaitResolver(t testing.TB, addresses []netip.Addr) {
	t.Helper()
	resolver := &net.Resolver{PreferGo: true}
	deadline := time.Now().Add(resolverWait)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), awaitLookup)
		_, _ = resolver.LookupHost(ctx, "dnstest.example.")
		cancel()
		queries := n.Take()
		if !slices.ContainsFunc(addresses, func(address netip.Addr) bool {
			return !slices.ContainsFunc(queries, func(query Query) bool { return query.To == address })
		}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no lookup through Go's resolver reached every nameserver within resolverWait, %v, of the resolv.conf naming them, the last reaching %v", resolverWait, queries)
		}
		time.Sleep(awaitStep)
	}
}
