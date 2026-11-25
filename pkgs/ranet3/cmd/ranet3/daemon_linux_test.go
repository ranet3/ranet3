// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/kernel/kerneltest"
	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/registry"
	"ranet3.com/pkgs/ranet3/sadr"
	"ranet3.com/pkgs/ranet3/schema"
)

// the tests in this file start the daemon as runDaemon does, its tun, its sockets, its nftables and its netlink opened from
// whatever thread a goroutine runs on, so they run as root in a network namespace the whole process started in and that held
// nothing, which unshare -rn starts, and skip anywhere without root

const (
	// daemonTUN is the tun of the daemon these tests start
	daemonTUN = "start0"
	// daemonQuiet is how long a test watches for what must not happen, long past a dial or a reload that would
	daemonQuiet = 500 * time.Millisecond
	// daemonPrompt bounds what the daemon does at once on a signal, well inside the first pass's wait it must not sit out
	daemonPrompt = firstPassWait / 5
	// daemonPort, daemonPprofPort and daemonMetricsPort are outside the namespace's automatic range, never handed to a bind of port 0
	// the tests run only in a network namespace the process owns, and no other test of the package binds these three
	daemonPort        = 20001
	daemonPprofPort   = 20002
	daemonMetricsPort = 20003
)

var (
	claimOnce sync.Once
	claimSkip string
	claimErr  error
	// unreturned counts the daemons runAsync started that have not returned, which a test that failed before their stop
	// leaves running
	unreturned atomic.Int32
)

// claimNamespace skips the test without root, refuses it in a namespace that held anything, and brings the loopback up. It
// skips the test where a daemon an earlier test started still runs, whose table, tun, port and goroutines the test would
// report as its own leftovers.
func claimNamespace(t *testing.T) {
	t.Helper()
	claimOnce.Do(func() {
		claimSkip, claimErr = netnstest.ClaimProcess()
		// the first registration starts os/signal's own goroutine, which outlives every start
		notifySignals().close()
	})
	if claimSkip != "" {
		t.Skip(claimSkip)
	}
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	if left := unreturned.Load(); left != 0 {
		t.Skipf("%d daemons an earlier test started still run, holding what this test would read as its own start's", left)
	}
}

// daemonFiles is a node's files and flags in a directory of the test's own, and the socket its one peer's endpoint is, which
// counts each datagram the node sends it
type daemonFiles struct {
	opts  options
	peer  net.PacketConn
	dials atomic.Int64
}

// leafCaps is a node under cap.exit fallback = "none", whose start waits for the reconciler's first pass
const leafCaps = `
  exit:
    fallback: none
`

// exitCaps is a node with cap.egress, whose start builds the exit
const exitCaps = `
  egress:
    advertise: [198.51.100.0/24]
`

// writeDaemon writes the key, the trust document and the file of a node that dials one peer, with overlay, cap.table and
// caps, and the flags that name them, pprof and metrics on the loopback and the control socket in the directory
func writeDaemon(t *testing.T, caps string) *daemonFiles {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	f := &daemonFiles{}
	if f.peer, err = net.ListenPacket("udp4", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.peer.Close() })
	go func() {
		buf := make([]byte, 1<<16)
		for {
			if _, _, err := f.peer.ReadFrom(buf); err != nil {
				return
			}
			f.dials.Add(1)
		}
	}()
	loopback := "127.0.0.1"
	org := registry.Organization{PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), Organization: "example"}
	for name, port := range map[string]int{"start": daemonPort, "peer": f.peer.LocalAddr().(*net.UDPAddr).Port} {
		org.Nodes = append(org.Nodes, registry.Node{CommonName: name,
			Endpoints: []registry.Endpoint{{SerialNumber: "0", AddressFamily: "ip4", Address: &loopback, Port: uint16(port)}}})
	}
	raw, err := json.Marshal(registry.Registry{org})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trust, key := filepath.Join(dir, "trust.json"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(trust, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`node: example/start
auth:
  key: %s
  trust: %s
link:
  port: %d
  tun: %s
  endpoints:
    - serial: "0"
      family: ip4
dial:
  to: [example/peer:0]
overlay: [203.0.113.0/24, 3fff:a::/36]
cap:
  table:
    addresses: [203.0.113.10/32, 3fff:a::10/128]
%s`, key, trust, daemonPort, daemonTUN, caps)
	f.opts = options{
		configPath:  filepath.Join(dir, "config.yaml"),
		pprofAddr:   fmt.Sprintf("127.0.0.1:%d", daemonPprofPort),
		metricsAddr: fmt.Sprintf("127.0.0.1:%d", daemonMetricsPort),
		controlPath: filepath.Join(shortDir(t), "control.sock"),
		stateDir:    filepath.Join(dir, "state"),
		level:       slog.LevelInfo,
	}
	pprofAddr, metricsAddr := netip.MustParseAddrPort(f.opts.pprofAddr), netip.MustParseAddrPort(f.opts.metricsAddr)
	netnstest.OutsideAutomaticRange(t, daemonPort, pprofAddr.Port(), metricsAddr.Port())
	if err := os.WriteFile(f.opts.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(f.opts.configPath); err != nil {
		t.Fatalf("the test's node file is refused: %v", err)
	}
	return f
}

// unforced is s with a second signal's forced exit taken out, so a daemon whose stop hangs is reported by the test that
// started it and does not end the test binary
func unforced(s stages) stages {
	s.force = func() {}
	return s
}

// watched is production, unforced, with the node's bus kept, so a test reads what the daemon recorded
func watched(bus *atomic.Pointer[events.Bus]) stages {
	s := unforced(production)
	s.node = func(cfg *config.Config, b *events.Bus) (*client.Client, error) {
		bus.Store(b)
		return client.New(cfg, b)
	}
	return s
}

// recorded is the events of kind the bus holds, none where the start built no bus yet
func recorded(bus *atomic.Pointer[events.Bus], kind string) int {
	b := bus.Load()
	if b == nil {
		return 0
	}
	return len(b.Recorded(func(k, _ string, _ []slog.Attr) bool { return k == kind }, 0))
}

// stopInTheBuild sends sig from a part of the start's build and holds the build daemonQuiet after it, long past the
// daemon's watcher taking it: the watcher reads it on a goroutine of its own, which a loaded host can run only after a short
// build has ended, and the start would then stop as one that ran its parts. The only handle on the watcher taking it is the
// watcher's own frame in a goroutine dump, which moves from its first select to its second once asked is closed, since the
// context and the node's stop mark come once the build has ended. A wait on that frame would tie these tests to the layout
// of watchSignals' selects, so they sleep instead, and on a host slower than daemonQuiet they fail by name.
func stopInTheBuild(t *testing.T, sig syscall.Signal) {
	t.Helper()
	signalSelf(t, sig)
	time.Sleep(daemonQuiet)
}

// beforeStart counts the goroutines and the open files, sockets among them, of the process before a start
type beforeStart struct{ goroutines, files int }

// before reads what the process runs and holds now
func before(t *testing.T) beforeStart {
	t.Helper()
	return beforeStart{runtime.NumGoroutine(), openFiles(t)}
}

// openFiles counts the process's open file descriptors
func openFiles(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// leftNothing fails t for any goroutine of the start still running once it settled, and for anything of the start's still
// bound or held: a listener, a socket or file open, the control socket, the node's port, the tun, an nftables table or a rule
// or route of the reconciler's protocol but the down set its stop leaves. The start's tun is one it made, which goes with the mesh, so an exit's shutdown
// withdraws its chains. One that outlives the daemon keeps the exit's stopped rules, which the exit nodes page tells.
func leftNothing(t *testing.T, f *daemonFiles, was beforeStart) {
	t.Helper()
	// the listeners are read before any wait, since the collector closes one the start leaked once it finalizes it
	for _, address := range []string{f.opts.pprofAddr, f.opts.metricsAddr} {
		listener, err := net.Listen("tcp4", address)
		if err != nil {
			t.Errorf("%s is still bound: %v", address, err)
			continue
		}
		_ = listener.Close()
	}
	if _, err := os.Stat(f.opts.controlPath); err == nil {
		t.Errorf("the control socket %s is still there", f.opts.controlPath)
	}
	deadline := time.Now().Add(daemonSettle)
	for (runtime.NumGoroutine() > was.goroutines || openFiles(t) > was.files) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if now := runtime.NumGoroutine(); now > was.goroutines {
		var stacks strings.Builder
		_ = pprof.Lookup("goroutine").WriteTo(&stacks, 1)
		t.Errorf("%d goroutines run, %d before the start:\n%s", now, was.goroutines, stacks.String())
	}
	if now := openFiles(t); now > was.files {
		t.Errorf("%d files are open, %d before the start", now, was.files)
	}
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", daemonPort))
	if err != nil {
		t.Errorf("the node's port %d is still bound: %v", daemonPort, err)
	} else {
		_ = conn.Close()
	}
	if _, err := net.InterfaceByName(daemonTUN); err == nil {
		t.Errorf("the tun %s is still there", daemonTUN)
	}
	nft, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer nft.Close()
	if held, err := nftables.Tables(nft, nftables.Table); err != nil || len(held) != 0 {
		t.Errorf("the table %s is held in the families %v (%v)", nftables.Table, held, err)
	}
	rules, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	// the tests of one binary share its namespace, so the down set an earlier test's stop left may be there or not
	extra, _ := kerneltest.NotDownSet(rules, daemonOverlay)
	for _, rule := range extra {
		t.Errorf("the rule %+v is still there", rule)
	}
	if routes := ownRoutes(t); routes != 0 {
		t.Errorf("%d routes of the reconciler's protocol are still there", routes)
	}
}

// daemonOverlay is the overlay writeDaemon writes
var daemonOverlay = []schema.Prefix{schema.MustPrefix("203.0.113.0/24"), schema.MustPrefix("3fff:a::/36")}

// ownRoutes counts the routes of the reconciler's protocol in every table
func ownRoutes(t *testing.T) int {
	t.Helper()
	rib, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_UNSPEC)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := syscall.ParseNetlinkMessage(rib)
	if err != nil {
		t.Fatal(err)
	}
	owned := 0
	for _, message := range messages {
		// rtm_protocol is the sixth byte of struct rtmsg
		if message.Header.Type == syscall.RTM_NEWROUTE && len(message.Data) > 5 && message.Data[5] == kernel.DefaultProtocol {
			owned++
		}
	}
	return owned
}

// A refusal at each part of the start, the first and the last of them included, is logged as that part's, closes what the
// start built before it, logs none of it started and returns 1 with no goroutine of the start running and nothing of it
// bound: the listeners, the control socket, the node's port, the tun, the antispoof filter's chains and the exit's chains. The
// listeners and the control socket refuse on an address already held and a path under a file.
func TestDaemonRefusedAtEachPartLeavesNothingRunningOrBound(t *testing.T) {
	claimNamespace(t)
	for _, part := range []string{"config", "pprof", "metrics", "control", "node", "state", "antispoof", "exit", "kernel"} {
		t.Run(part, func(t *testing.T) {
			refused := fmt.Errorf("refused at %s for the test", part)
			// the refusal the start logs, which names the part that refused rather than one before it
			want := refused.Error()
			var logged lockedLog
			defer slog.SetDefault(slog.Default())
			slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
			f := writeDaemon(t, exitCaps)
			s := unforced(production)
			// what holds an address the start binds until the start returns
			var taken net.Listener
			switch part {
			case "config":
				s.load = func(string) (*config.Config, error) { return nil, refused }
			case "pprof", "metrics":
				address := map[string]string{"pprof": f.opts.pprofAddr, "metrics": f.opts.metricsAddr}[part]
				var err error
				if taken, err = net.Listen("tcp4", address); err != nil {
					t.Fatal(err)
				}
				want = part + ": listen tcp " + address
			case "control":
				// a file where the socket's directory goes, which a real start refuses
				dir := filepath.Dir(f.opts.controlPath)
				if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
				f.opts.controlPath = filepath.Join(dir, "file", "control.sock")
				want = filepath.Join(dir, "file") + "/"
			case "node":
				s.node = func(*config.Config, *events.Bus) (*client.Client, error) { return nil, refused }
			case "state":
				// a file where the state directory goes, which a real start refuses
				if err := os.WriteFile(f.opts.stateDir, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				want = "state: "
			case "antispoof":
				s.border = func(*egress.Border, egress.BorderRuntime) (*kernelexit.BorderFilter, error) { return nil, refused }
			case "exit":
				s.exit = func(*config.Config, *client.Client, *events.Bus) (egress.Exit, error) { return nil, refused }
			case "kernel":
				s.kernel = func(kernel.Table, kernel.Runtime, kernel.RouteSource) (*kernel.Reconciler, error) {
					return nil, refused
				}
			}
			was := before(t)
			if code := startDaemon(f.opts, s); code != 1 {
				t.Errorf("a start refused at %s exited %d", part, code)
			}
			if taken != nil {
				_ = taken.Close()
			}
			if !strings.Contains(logged.String(), want) {
				t.Errorf("a start refused at %s logged\n%s\nwant a refusal holding %q", part, logged.String(), want)
			}
			if strings.Contains(logged.String(), "started") {
				t.Errorf("a start refused at %s logged a part started:\n%s", part, logged.String())
			}
			leftNothing(t, f, was)
			if dials := f.dials.Load(); dials != 0 {
				t.Errorf("a start refused at %s sent its peer %d datagrams", part, dials)
			}
		})
	}
}

// An exit's start hands its route reconciler the antispoof filter's route source over the mesh's table, which the
// reconciler tells what each pass may have left in the kernel, and not the mesh's table itself
func TestDaemonHandsItsReconcilerTheAntispoofFiltersRouteSource(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, exitCaps)
	s := production
	var node *client.Client
	s.node = func(cfg *config.Config, bus *events.Bus) (*client.Client, error) {
		c, err := production.node(cfg, bus)
		node = c
		return c, err
	}
	var handed kernel.RouteSource
	lan := netip.MustParsePrefix("2001:db8:76:9::/64")
	var followed bool
	s.kernel = func(_ kernel.Table, _ kernel.Runtime, source kernel.RouteSource) (*kernel.Reconciler, error) {
		handed = source
		// an entry the mesh's table comes to hold reaches the reconciler through the source, itself or as a hold at its key
		node.Mesh.Routes.Set(netip.Prefix{}, lan, &netstack.Peer{ID: "example/router"})
		followed = slices.ContainsFunc(source.Snapshot(), func(entry sadr.Route[*netstack.Peer]) bool { return entry.Destination == lan })
		node.Mesh.Routes.Remove(netip.Prefix{}, lan)
		return nil, errors.New("refused at kernel for the test")
	}
	was := before(t)
	if code := startDaemon(f.opts, s); code != 1 {
		t.Errorf("a start refused at its reconciler exited %d", code)
	}
	if _, told := handed.(kernel.InstalledSink); !told {
		t.Errorf("the reconciler was handed %T, want the antispoof filter's route source", handed)
	}
	if !followed {
		t.Errorf("the source handed the reconciler did not hand %s once the mesh's table held it", lan)
	}
	leftNothing(t, f, was)
}

// SIGTERM or SIGINT while the start builds ends it there: it closes what it built as a refusal does and exits 0, with no
// goroutine of the start running, nothing of it bound, nothing dialed, and none of its parts run or logged as started
func TestDaemonStoppedWhileItBuildsStartsNothing(t *testing.T) {
	claimNamespace(t)
	for name, stop := range map[string]syscall.Signal{"SIGTERM": syscall.SIGTERM, "SIGINT": syscall.SIGINT} {
		t.Run(name, func(t *testing.T) {
			var logged lockedLog
			defer slog.SetDefault(slog.Default())
			slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
			f := writeDaemon(t, leafCaps)
			var bus atomic.Pointer[events.Bus]
			s := watched(&bus)
			s.load = func(path string) (*config.Config, error) {
				stopInTheBuild(t, stop)
				return config.Load(path)
			}
			was := before(t)
			if code := exited(t, runAsync(f, s)); code != 0 {
				t.Errorf("a start stopped while it built exited %d", code)
			}
			leftNothing(t, f, was)
			if dials, started := f.dials.Load(), recorded(&bus, "daemon.started"); dials != 0 || started != 0 {
				t.Errorf("a start stopped while it built sent its peer %d datagrams and recorded %d starts", dials, started)
			}
			// daemon.stopping is the stop of a start that ran its parts, which this one never did
			if stops := recorded(&bus, "daemon.stopping"); stops != 0 {
				t.Errorf("a start stopped while it built ran its parts and recorded %d stops", stops)
			}
			if strings.Contains(logged.String(), "started") {
				t.Errorf("a start stopped while it built logged a part started:\n%s", logged.String())
			}
		})
	}
}

// A second SIGTERM while the start builds forces the exit there, as one during the stop does, and so does one a part's close
// sends while the start undoes a build the first stopped. The build's needs no root.
func TestDaemonForcedOutOfItsBuildByASecondSignal(t *testing.T) {
	t.Run("in the build", func(t *testing.T) {
		forced := make(chan struct{})
		s := production
		s.force = sync.OnceFunc(func() { close(forced) })
		refused := errors.New("refused once forced for the test")
		s.load = func(string) (*config.Config, error) {
			signalSelf(t, syscall.SIGTERM)
			signalSelf(t, syscall.SIGTERM)
			awaitForced(t, forced, "while the start built")
			return nil, refused
		}
		if code := startDaemon(options{configPath: "unread", stateDir: t.TempDir()}, s); code != 1 {
			t.Errorf("the start forced out of its build exited %d", code)
		}
	})
	t.Run("in the undo", func(t *testing.T) {
		claimNamespace(t)
		f := writeDaemon(t, exitCaps)
		forced := make(chan struct{})
		s := production
		s.force = sync.OnceFunc(func() { close(forced) })
		s.load = func(path string) (*config.Config, error) {
			stopInTheBuild(t, syscall.SIGTERM)
			return config.Load(path)
		}
		// the exit's Close runs only in the undo, a start that ran its parts stopping the exit through Run
		var undone atomic.Bool
		s.exit = func(cfg *config.Config, node *client.Client, bus *events.Bus) (egress.Exit, error) {
			exit, err := newExit(cfg, node, bus)
			if err != nil {
				return nil, err
			}
			return closingExit{exit, func() {
				undone.Store(true)
				signalSelf(t, syscall.SIGTERM)
				awaitForced(t, forced, "while the start undid its build")
			}}, nil
		}
		was := before(t)
		// the test's force returns, so the undo goes on and leaves nothing
		if code := exited(t, runAsync(f, s)); code != 0 {
			t.Errorf("the start forced out of its undo exited %d", code)
		}
		if !undone.Load() {
			t.Error("the start never undid its build, so the second signal was not sent in the undo")
		}
		leftNothing(t, f, was)
	})
}

// awaitForced fails t where forced is not closed within daemonSettle of a second SIGTERM sent when says
func awaitForced(t *testing.T, forced <-chan struct{}, when string) {
	t.Helper()
	select {
	case <-forced:
	case <-time.After(daemonSettle):
		t.Errorf("the second SIGTERM %s did not force the exit", when)
	}
}

// closingExit is an exit whose Close runs closing first
type closingExit struct {
	egress.Exit
	closing func()
}

func (e closingExit) Close() error {
	e.closing()
	return e.Exit.Close()
}

// A start refused after the antispoof filter's first pass, or stopped while it builds, leaves the antispoof filter's chains
// and the kill switch's that an earlier instance left, the antispoof filter's as that pass rewrote them, and withdraws
// neither, the filter's both where it found either. Where the earlier instance left the kill switch's chain alone, the
// filter's chains are the pass's, and go.
func TestDaemonEndedInItsBuildLeavesTheChainsItFound(t *testing.T) {
	claimNamespace(t)
	// empty, as no start writes them, so the antispoof filter's first pass rewrites its own
	switchChain := nftables.Chain{Table: nftables.Table, Name: "fallback", Type: "filter", Hook: unix.NF_INET_POST_ROUTING, Priority: 2147483646}
	entryChain := nftables.Chain{Table: nftables.Table, Name: kernelexit.EntryChain, Hook: nftables.NoHook}
	found := []struct {
		what   string
		chains []nftables.Chain
		left   []string
	}{
		{"the kill switch's chain alone", []nftables.Chain{switchChain}, []string{"fallback"}},
		{"the kill switch's chain and the antispoof filter's entry chain", []nftables.Chain{switchChain, entryChain}, []string{kernelexit.BorderChain, "fallback", kernelexit.EntryChain}},
	}
	for name, arm := range map[string]struct {
		end  func(*stages)
		code int
	}{
		"refused at the reconciler": {func(s *stages) {
			s.kernel = func(kernel.Table, kernel.Runtime, kernel.RouteSource) (*kernel.Reconciler, error) {
				return nil, errors.New("refused at kernel for the test")
			}
		}, 1},
		"stopped while it builds": {func(s *stages) {
			s.load = func(path string) (*config.Config, error) {
				stopInTheBuild(t, syscall.SIGTERM)
				return config.Load(path)
			}
		}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			nft, err := nftables.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer nft.Close()
			for _, earlier := range found {
				f := writeDaemon(t, leafCaps)
				requests := []nftables.Request{nftables.NewTable(unix.NFPROTO_INET, nftables.Table)}
				for _, chain := range earlier.chains {
					requests = append(requests, chain.Create(unix.NFPROTO_INET))
				}
				if err := nft.Batch(requests); err != nil {
					t.Fatal(err)
				}
				was := before(t)
				s := unforced(production)
				arm.end(&s)
				if code := exited(t, runAsync(f, s)); code != arm.code {
					t.Errorf("a start %s over %s exited %d, want %d", name, earlier.what, code, arm.code)
				}
				chains, err := nftables.TableChains(nft, unix.NFPROTO_INET, nftables.Table)
				slices.Sort(chains)
				want := slices.Sorted(slices.Values(earlier.left))
				if err != nil || !slices.Equal(chains, want) {
					t.Errorf("a start %s over %s left the chains %q in the table %s (%v), want %q", name, earlier.what, chains, nftables.Table, err, want)
				}
				if err := nft.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)}); err != nil {
					t.Errorf("delete the table %s: %v", nftables.Table, err)
				}
				leftNothing(t, f, was)
			}
		})
	}
}

// held is watched with the reconciler's passes held at their first read of the sessions until release is called, which
// the test's end calls too, and asked closed at the first pass's
func held(t *testing.T, bus *atomic.Pointer[events.Bus]) (s stages, asked <-chan struct{}, release func()) {
	s = watched(bus)
	ask, released := make(chan struct{}), make(chan struct{})
	release = sync.OnceFunc(func() { close(released) })
	t.Cleanup(release)
	var once sync.Once
	s.kernel = func(table kernel.Table, rt kernel.Runtime, src kernel.RouteSource) (*kernel.Reconciler, error) {
		sessions := rt.Sessions
		rt.Sessions = func() int {
			once.Do(func() { close(ask) })
			<-released
			return sessions()
		}
		return kernel.New(table, rt, src)
	}
	return s, ask, release
}

// runAsync starts the daemon on a goroutine and answers its exit status once it returns
func runAsync(f *daemonFiles, s stages) <-chan int {
	code := make(chan int, 1)
	unreturned.Add(1)
	go func() {
		got := startDaemon(f.opts, s)
		// before the answer, so a test that read it finds the daemon gone
		unreturned.Add(-1)
		code <- got
	}()
	return code
}

// exited is the daemon's exit status once code answers it. Where that takes longer than daemonSettle it fails t at once,
// before it sends anything, then sends a SIGTERM, which ends a daemon that never took the first and which the tests'
// unforced stages take as no forced exit, and where the daemon has not returned daemonSettle after that either it answers
// -1 and leaves the daemon running, so the test reports by its name and the binary goes on
func exited(t *testing.T, code <-chan int) int {
	t.Helper()
	select {
	case got := <-code:
		return got
	case <-time.After(daemonSettle):
	}
	t.Errorf("the daemon did not return within %s", daemonSettle)
	signalSelf(t, syscall.SIGTERM)
	select {
	case got := <-code:
		return got
	case <-time.After(daemonSettle):
		t.Errorf("the daemon did not return within %s of a SIGTERM more either, and is left running", daemonSettle)
		return -1
	}
}

// A stop while the start waits for the reconciler's first pass under fallback = "none" ends the wait: the start answers nothing
// on the control socket in the wait, dials nothing, records no start, and exits 0 once the reconciler has withdrawn, leaving
// nothing running or bound
func TestDaemonStoppedInTheFirstPassWaitDialsNothing(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, leafCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s, asked, release := held(t, &bus)
	code := runAsync(f, s)
	select {
	case <-asked:
	case <-time.After(daemonSettle):
		t.Fatal("the reconciler's first pass did not start")
	}
	within, cancel := context.WithTimeout(context.Background(), daemonQuiet)
	defer cancel()
	if _, err := control.Dial(f.opts.controlPath).StatusWithin(within); err == nil {
		t.Error("the control socket answered while the start waited for the first pass")
	}
	signalSelf(t, syscall.SIGTERM)
	waitWithin(t, "the stop", daemonPrompt, func() bool { return recorded(&bus, "daemon.stopping") != 0 })
	release()
	if got := exited(t, code); got != 0 {
		t.Errorf("the start stopped in its wait exited %d", got)
	}
	leftNothing(t, f, was)
	time.Sleep(daemonQuiet)
	if dials, started := f.dials.Load(), recorded(&bus, "daemon.started"); dials != 0 || started != 0 {
		t.Errorf("the start stopped in its wait sent its peer %d datagrams and recorded %d starts", dials, started)
	}
}

// A node with an exit stopped in the first pass's wait, which never dials, closes its mesh in the stop, so the exit's
// withdrawal, which waits for the mesh to close, ends and the daemon returns 0 leaving nothing
func TestDaemonExitStoppedInTheFirstPassWaitReturns(t *testing.T) {
	claimNamespace(t)
	leaf := writeDaemon(t, leafCaps)
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s, asked, release := held(t, &bus)
	// the exit's file under cap.exit's fallback = "none", which the loader refuses beside cap.egress, so the start waits
	s.load = func(path string) (*config.Config, error) {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		mode, err := config.Load(leaf.opts.configPath)
		if err != nil {
			return nil, err
		}
		cfg.Cap.Exit = mode.Cap.Exit
		return cfg, nil
	}
	code := runAsync(f, s)
	select {
	case <-asked:
	case <-time.After(daemonSettle):
		t.Fatal("the reconciler's first pass did not start")
	}
	signalSelf(t, syscall.SIGTERM)
	waitWithin(t, "the stop", daemonPrompt, func() bool { return recorded(&bus, "daemon.stopping") != 0 })
	release()
	if got := exited(t, code); got != 0 {
		t.Errorf("the exit stopped in its wait exited %d", got)
	}
	leftNothing(t, f, was)
	if dials := f.dials.Load(); dials != 0 {
		t.Errorf("the exit stopped in its wait sent its peer %d datagrams", dials)
	}
}

// A stop keeps every chain of the exit's in place, its translation among them, until the mesh has closed: with the
// reconciler's pass held its withdrawal waits, and the mesh's close after it, while the exit reads the stop under way and
// holds the chains it wrote, and once the pass is let go the daemon returns 0 leaving nothing
func TestDaemonKeepsTheExitsChainsUntilTheMeshHasClosed(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s, asked, release := held(t, &bus)
	code := runAsync(f, s)
	select {
	case <-asked:
	case <-time.After(daemonSettle):
		t.Fatal("the reconciler's first pass did not start")
	}
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	nft, closeNft := dialTable(t)
	// held is the chains of the table, the antispoof filter's beside the exit's
	held := func() []string {
		t.Helper()
		chains, err := nftables.TableChains(nft, unix.NFPROTO_INET, nftables.Table)
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(chains)
		return chains
	}
	waitTill(t, "the exit's chains", func() bool { return slices.Contains(held(), kernelexit.ChainName) })
	wrote := held()
	signalSelf(t, syscall.SIGTERM)
	waitTill(t, "the exit's stop", func() bool { return unready(t, f) == "the translator is stopping" })
	// past a withdrawal that would not wait
	time.Sleep(daemonQuiet)
	if got := held(); !slices.Equal(got, wrote) {
		t.Errorf("with the mesh open the stop left the chains %q, want those the exit wrote, %q", got, wrote)
	}
	closeNft()
	release()
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}

// A SIGHUP and a SIGUSR1 that came while the start built are read once the reconciler's first pass has ended, and reload
// and dump the routes then: nothing reloads, dumps or dials while the pass is held, and each happens once it ends
func TestDaemonActsOnTheSignalsOfTheStartOnceItDials(t *testing.T) {
	claimNamespace(t)
	var logged lockedLog
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	// the dump's first line, with no route installed and with some
	dumped := func() bool {
		text := logged.String()
		return strings.Contains(text, `msg="routes: (none installed)"`) || strings.Contains(text, "msg=routes:\n")
	}
	f := writeDaemon(t, leafCaps)
	var bus atomic.Pointer[events.Bus]
	s, asked, release := held(t, &bus)
	load := s.load
	s.load = func(path string) (*config.Config, error) {
		signalSelf(t, syscall.SIGHUP)
		signalSelf(t, syscall.SIGUSR1)
		return load(path)
	}
	code := runAsync(f, s)
	select {
	case <-asked:
	case <-time.After(daemonSettle):
		t.Fatal("the reconciler's first pass did not start")
	}
	time.Sleep(daemonQuiet)
	if reloads, dials := recorded(&bus, "daemon.reload"), f.dials.Load(); reloads != 0 || dials != 0 || dumped() {
		t.Errorf("while the first pass was held the start reloaded %d times, sent its peer %d datagrams and dumped the routes %v", reloads, dials, dumped())
	}
	release()
	waitTill(t, "the reload", func() bool { return recorded(&bus, "daemon.reload") == 1 })
	waitTill(t, "the route dump", dumped)
	waitTill(t, "a dial", func() bool { return f.dials.Load() != 0 })
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	if reloads := recorded(&bus, "daemon.reload"); reloads != 1 {
		t.Errorf("the daemon reloaded %d times, want the one SIGHUP of the start", reloads)
	}
}

// A SIGHUP whose file the node refuses leaves a warning with the reason, which a log at warn keeps, and the node runs on
func TestDaemonWarnsOfTheReloadItRefuses(t *testing.T) {
	claimNamespace(t)
	var logged lockedLog
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	f := writeDaemon(t, leafCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&bus))
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	if err := os.WriteFile(f.opts.configPath, []byte("overlay: [not a prefix]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signalSelf(t, syscall.SIGHUP)
	waitTill(t, "the refusal's warning", func() bool {
		return strings.Contains(logged.String(), `level=WARN msg="reload failed" err=`)
	})
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon that refused a reload exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}

// A running sourced node refuses an oversized reload before changing any
// policy, then removes its own sourced rules when only that key leaves.
func TestDaemonSourcedReloadRefusalAndKeyOnlyRemoval(t *testing.T) {
	claimNamespace(t)
	const destination = "fd5e:db8:10:2::/96"
	const named = "    sourced:\n      to: [" + destination + "]\n"
	f := writeDaemon(t, named+leafCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&bus))
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		select {
		case <-code:
		default:
			signalSelf(t, syscall.SIGTERM)
			_ = exited(t, code)
		}
	})
	waitTill(t, "the sourced start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	original, err := os.ReadFile(f.opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	startRules, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	standing := 0
	for _, rule := range startRules {
		if rule.To.String() == destination && (rule.Priority == 5401 || rule.Priority == 5404) &&
			rule.Protocol == kernel.DefaultProtocol {
			standing++
		}
	}
	if standing < 2 {
		t.Fatalf("the daemon did not install sourced protection before starting: %v", startRules)
	}
	routesBefore := ownRoutes(t)
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("fd5e:db8:%x::/64", 0x100+i)
	}
	oversized := strings.Replace(string(original), named, "    sourced:\n      to: ["+strings.Join(many, ", ")+"]\n", 1)
	if oversized == string(original) {
		t.Fatal("the sourced key was missing from the fixture")
	}
	if err := os.WriteFile(f.opts.configPath, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathReload, &control.Request{}); status != http.StatusBadRequest ||
		!strings.Contains(answer, "16 destinations") {
		t.Fatalf("oversized sourced reload answered %d %q", status, answer)
	}
	after, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	routesAfter := ownRoutes(t)
	if !slices.Equal(startRules, after) || routesAfter != routesBefore {
		t.Fatalf("refused reload changed kernel policy: rules before %v, after %v; routes before %d, after %d",
			startRules, after, routesBefore, routesAfter)
	}
	keyless := strings.Replace(string(original), named, "", 1)
	if err := os.WriteFile(f.opts.configPath, []byte(keyless), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathReload, &control.Request{}); status != http.StatusOK {
		t.Fatalf("key-only removal answered %d %q", status, answer)
	}
	held, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range startRules {
		if rule.Protocol != kernel.DefaultProtocol || rule.Priority == 5400 || rule.Priority < 5399 || rule.Priority > 5404 {
			continue
		}
		if slices.Contains(held, rule) {
			t.Fatalf("key-only removal left sourced rule %+v", rule)
		}
	}
	signalSelf(t, syscall.SIGTERM)
	got := exited(t, code)
	stopped = got >= 0
	if got != 0 {
		t.Errorf("the sourced daemon exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}

// Capacity from the accepted file must refuse a first start before client.New
// can create a tun, not merely before kernel.New can write its first rule.
func TestDaemonSourcedOversizeRefusesBeforeConstructingTheTun(t *testing.T) {
	claimNamespace(t)
	many := make([]string, 17)
	for i := range many {
		many[i] = fmt.Sprintf("fd5e:db8:%x::/64", 0x100+i)
	}
	f := writeDaemon(t, "    sourced:\n      to: ["+strings.Join(many, ", ")+"]\n"+leafCaps)
	was := before(t)
	prior, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	routes := ownRoutes(t)
	s := unforced(production)
	s.node = func(cfg *config.Config, bus *events.Bus) (*client.Client, error) {
		t.Error("oversized sourced config constructed a tun before refusal")
		return client.New(cfg, bus)
	}
	if code := startDaemon(f.opts, s); code != 1 {
		t.Errorf("oversized sourced start returned exit code %d", code)
	}
	after, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prior, after) || ownRoutes(t) != routes {
		t.Errorf("oversized first start changed rule or route policy: before %v, after %v", prior, after)
	}
	if _, err := net.InterfaceByName(daemonTUN); err == nil {
		t.Error("oversized sourced start created a tun")
	}
	leftNothing(t, f, was)
}

// Disable retires standing policy. Synchronous enable rearms it. Graceful
// stop retains only the standing protection, which the next daemon adopts
// before an explicit key-only removal retires it.
func TestDaemonSourcedDisableEnableStopRestartAndKeyRemoval(t *testing.T) {
	claimNamespace(t)
	const named = "    sourced:\n      to: [fd5e:db8:10:2::/96]\n"
	f := writeDaemon(t, named+leafCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&bus))
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		select {
		case <-code:
		default:
			signalSelf(t, syscall.SIGTERM)
			_ = exited(t, code)
		}
	})
	waitTill(t, "sourced daemon start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	owned := func() []kernel.DumpedRule {
		t.Helper()
		rules, err := kernel.DumpRules()
		if err != nil {
			t.Fatal(err)
		}
		return slices.DeleteFunc(rules, func(rule kernel.DumpedRule) bool {
			return rule.Protocol != kernel.DefaultProtocol || rule.Priority == 5400 ||
				rule.Priority < 5399 || rule.Priority > 5404
		})
	}
	if len(owned()) == 0 {
		t.Fatal("the daemon did not install sourced protection")
	}
	request := &control.Request{Subsystem: control.SubsystemReconciler}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathDisable, request); status != http.StatusOK {
		t.Fatalf("disable reconciler answered %d %q", status, answer)
	}
	waitTill(t, "retire sourced rules after disable", func() bool { return len(owned()) == 0 })
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathEnable, request); status != http.StatusOK {
		t.Fatalf("enable reconciler answered %d %q", status, answer)
	}
	restored := owned()
	if !slices.ContainsFunc(restored, func(rule kernel.DumpedRule) bool { return rule.Priority == 5399 }) ||
		!slices.ContainsFunc(restored, func(rule kernel.DumpedRule) bool { return rule.Priority == 5401 }) ||
		!slices.ContainsFunc(restored, func(rule kernel.DumpedRule) bool { return rule.Priority == 5404 }) {
		t.Errorf("enable replied before restoring sourced ingress and standing rules: %v", restored)
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("sourced daemon exited %d after SIGTERM", got)
	}
	stopped = true
	standing := owned()
	if !slices.ContainsFunc(standing, func(rule kernel.DumpedRule) bool { return rule.Priority == 5401 }) ||
		!slices.ContainsFunc(standing, func(rule kernel.DumpedRule) bool { return rule.Priority == 5404 }) ||
		slices.ContainsFunc(standing, func(rule kernel.DumpedRule) bool {
			return rule.Priority == 5399 || rule.Priority == 5403
		}) || ownRoutes(t) != 0 {
		t.Errorf("stopped daemon did not retain only sourced refusal and main exception: %v", standing)
	}
	bus.Store(nil)
	code = runAsync(f, watched(&bus))
	stopped = false
	waitTill(t, "restart with adopted sourced protection", func() bool { return recorded(&bus, "daemon.started") != 0 })
	if !slices.ContainsFunc(owned(), func(rule kernel.DumpedRule) bool { return rule.Priority == 5399 }) {
		t.Error("the restarted daemon did not rearm its ingress rule")
	}
	original, err := os.ReadFile(f.opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.opts.configPath, []byte(strings.Replace(string(original), named, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathReload, &control.Request{}); status != http.StatusOK {
		t.Errorf("key-only removal after restart answered %d %q", status, answer)
	}
	if left := owned(); len(left) != 0 {
		t.Errorf("key-only removal after restart left sourced rules: %v", left)
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("keyless daemon exited %d after SIGTERM", got)
	}
	stopped = true
	leftNothing(t, f, was)
}

// A foreign 201 entry makes enable refuse before restoring any rule or route.
// Removing that entry permits the same daemon to enable on its next request.
func TestDaemonSourcedEnableRefusesForeignMirrorBeforeWrites(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, "    sourced:\n      to: [fd5e:db8:10:2::/96]\n"+leafCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	var reconciler atomic.Pointer[kernel.Reconciler]
	s := watched(&bus)
	s.kernel = func(table kernel.Table, runtime kernel.Runtime, source kernel.RouteSource) (*kernel.Reconciler, error) {
		value, err := production.kernel(table, runtime, source)
		reconciler.Store(value)
		return value, err
	}
	code := runAsync(f, s)
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		select {
		case <-code:
		default:
			signalSelf(t, syscall.SIGTERM)
			_ = exited(t, code)
		}
	})
	waitTill(t, "sourced daemon start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	request := &control.Request{Subsystem: control.SubsystemReconciler}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathDisable, request); status != http.StatusOK {
		t.Fatalf("disable reconciler answered %d %q", status, answer)
	}
	waitTill(t, "sourced withdrawal", func() bool {
		rules, err := kernel.DumpRules()
		if err != nil {
			t.Fatal(err)
		}
		return !slices.ContainsFunc(rules, func(rule kernel.DumpedRule) bool {
			return rule.Protocol == kernel.DefaultProtocol && rule.Priority >= 5399 && rule.Priority <= 5404 &&
				rule.Priority != 5400
		})
	})
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, netlink.Options{Timeout: daemonPrompt})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = conn.Close()
		}
	})
	destination := netip.MustParsePrefix("fd5e:db8:10:2::/96")
	foreign := []byte{unix.AF_INET6, 96, 0, 0, 201, unix.RTPROT_STATIC, unix.RT_SCOPE_UNIVERSE, unix.RTN_THROW, 0, 0, 0, 0}
	foreign = netlink.PutAttr(foreign, unix.RTA_DST, netlink.AddressBytes(destination.Addr()))
	if _, err := conn.Execute(unix.RTM_NEWROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL, foreign); err != nil {
		t.Fatalf("seed foreign table-201 throw: %v", err)
	}
	seeded := true
	t.Cleanup(func() {
		if seeded {
			_, _ = conn.Execute(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, foreign)
		}
	})
	prior, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	routes := ownRoutes(t)
	watch, err := netlink.Subscribe("sourced-enable", unix.NETLINK_ROUTE,
		uint32(unix.RTMGRP_IPV4_RULE|1<<(unix.RTNLGRP_IPV6_RULE-1)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	watching := true
	t.Cleanup(func() {
		if watching {
			_ = watch.Close()
		}
	})
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathEnable, request); status != http.StatusBadRequest ||
		!strings.Contains(answer, "foreign routes") {
		t.Fatalf("enable with foreign 201 replied %d %q", status, answer)
	}
	active := reconciler.Load()
	if active == nil {
		t.Fatal("the daemon did not construct its reconciler")
	}
	active.NetworkChanged(kernel.NetworkChange{})
	time.Sleep(daemonQuiet)
	var message [64 << 10]byte
	for {
		n, _, err := unix.Recvfrom(int(watch.Fd()), message[:], unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		updates, err := netlink.ParseMessages(message[:n])
		if err != nil {
			t.Fatal(err)
		}
		for _, update := range updates {
			if update.Kind == unix.RTM_NEWRULE || update.Kind == unix.RTM_DELRULE {
				t.Fatalf("refused enable changed a kernel rule: %v", update)
			}
		}
	}
	if err := watch.Close(); err != nil {
		t.Fatal(err)
	}
	watching = false
	after, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(prior, after) || ownRoutes(t) != routes {
		t.Fatalf("refused enable wrote policy: rules before %v, after %v; owned routes before %d, after %d",
			prior, after, routes, ownRoutes(t))
	}
	if _, err := conn.Execute(unix.RTM_DELROUTE, unix.NLM_F_REQUEST|unix.NLM_F_ACK, foreign); err != nil {
		t.Fatalf("remove foreign table-201 throw: %v", err)
	}
	seeded = false
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathEnable, request); status != http.StatusOK {
		t.Fatalf("enable after removing foreign 201 replied %d %q", status, answer)
	}
	restored, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(restored, func(rule kernel.DumpedRule) bool {
		return rule.Protocol == kernel.DefaultProtocol && rule.Priority == 5404 && rule.To == destination
	}) {
		t.Fatalf("successful enable replied before sourced refusal readback: %v", restored)
	}
	if status, answer := ask(t, f.opts.controlPath, http.MethodPost, control.PathDisable, request); status != http.StatusOK {
		t.Fatalf("second disable answered %d %q", status, answer)
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("sourced daemon exited %d after SIGTERM", got)
	}
	stopped = true
	leftNothing(t, f, was)
}

// A start with no cap.table over the down set an earlier start's stop left warns once naming each of its rules with the command
// that deletes it, and leaves it, since no reconciler runs to take it
func TestDaemonWithNoReconcilerWarnsOfTheDownSetLeft(t *testing.T) {
	claimNamespace(t)
	var logged lockedLog
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	f := writeDaemon(t, "")
	was := before(t)
	var first atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&first))
	waitTill(t, "the start", func() bool { return recorded(&first, "daemon.started") != 0 })
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Fatalf("the start with a reconciler exited %d after SIGTERM", got)
	}
	rules, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	if extra, missing := kerneltest.NotDownSet(rules, daemonOverlay); len(extra)+len(missing) != 0 {
		t.Fatalf("the stop left %+v beside the down set and lacks %+v of it", extra, missing)
	}
	var second atomic.Pointer[events.Bus]
	s := watched(&second)
	s.load = func(path string) (*config.Config, error) {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, err
		}
		cfg.Cap.Table = nil
		return cfg, nil
	}
	code = runAsync(f, s)
	waitTill(t, "the start with no reconciler", func() bool { return recorded(&second, "daemon.started") != 0 })
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the start with no reconciler exited %d after SIGTERM", got)
	}
	text := logged.String()
	if n := strings.Count(text, "kernel found rules an earlier instance left to hold overlay prefixes"); n != 1 {
		t.Errorf("the start with no reconciler warned of the down set %d times, want once:\n%s", n, text)
	}
	for _, want := range []string{"ip -4 rule del priority 32765 to 203.0.113.0/24 protocol 155", "ip -6 rule del priority 32764 to 3fff:a::/36 protocol 155"} {
		if !strings.Contains(text, want) {
			t.Errorf("the warning does not name %q:\n%s", want, text)
		}
	}
	if rules, err = kernel.DumpRules(); err != nil {
		t.Fatal(err)
	}
	if extra, missing := kerneltest.NotDownSet(rules, daemonOverlay); len(extra)+len(missing) != 0 {
		t.Errorf("the start with no reconciler left %+v beside the down set and lacks %+v of it", extra, missing)
	}
	leftNothing(t, f, was)
}

// failingExit withdraws as the exit does and then reports the withdrawal failed
type failingExit struct{ egress.Exit }

func (e failingExit) Run(ctx context.Context) error {
	return errors.Join(e.Exit.Run(ctx), errors.New("withdrawal failed for the test"))
}

// a part that fails while the daemon stops exits 1 with an error line naming the part, which a log at warn keeps
func TestDaemonPartFailureSurvivesALogAtWarn(t *testing.T) {
	claimNamespace(t)
	var logged lockedLog
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s := watched(&bus)
	s.exit = func(cfg *config.Config, node *client.Client, b *events.Bus) (egress.Exit, error) {
		exit, err := newExit(cfg, node, b)
		if err != nil {
			return nil, err
		}
		return failingExit{exit}, nil
	}
	code := runAsync(f, s)
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 1 {
		t.Errorf("the daemon whose exit failed its withdrawal exited %d, want 1", got)
	}
	if want := `level=ERROR msg="daemon part failed, so the exit status is 1" part=egress`; !strings.Contains(logged.String(), want) {
		t.Errorf("a log at warn kept %q, want it to carry %q", logged.String(), want)
	}
	leftNothing(t, f, was)
}

// budgetedExit is an exit sized within a memory budget, as darwin's userspace exit is, holding Go's limit at limit beside any
// node heap
type budgetedExit struct {
	egress.Exit
	limit int64
}

func (e budgetedExit) MemoryLimit(node int64) int64 { return e.limit + node }

// a node that set Go's memory limit for a budgeted exit puts it back to none once the exit's Run has returned in the stop, so
// the process outlives the exit with no limit sized for it
func TestDaemonStopPutsTheLimitForItsExitBack(t *testing.T) {
	claimNamespace(t)
	given := debug.SetMemoryLimit(-1)
	if given != math.MaxInt64 {
		t.Skipf("this process was given Go's memory limit %d, beside which the node sets none", given)
	}
	t.Cleanup(func() { debug.SetMemoryLimit(given) })
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s := watched(&bus)
	const limit = 3 << 30
	s.exit = func(cfg *config.Config, node *client.Client, b *events.Bus) (egress.Exit, error) {
		exit, err := newExit(cfg, node, b)
		if err != nil {
			return nil, err
		}
		return budgetedExit{exit, limit}, nil
	}
	code := runAsync(f, s)
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	if set := debug.SetMemoryLimit(-1); set < limit || set == math.MaxInt64 {
		t.Errorf("the running node holds Go's memory limit at %d, want its exit's %d and its own heap", set, int64(limit))
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	if set := debug.SetMemoryLimit(-1); set != math.MaxInt64 {
		t.Errorf("Go's memory limit is %d once the daemon stopped, want none", set)
	}
	leftNothing(t, f, was)
}

// ask sends the daemon's control socket one request on a connection of its own, which closes once answered so nothing of
// the exchange outlives it, and answers the status and the body
func ask(t *testing.T, socket, method, path string, request *control.Request) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: daemonSettle, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}}
	var body io.Reader
	if request != nil {
		raw, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(raw)
	}
	asked, err := http.NewRequest(method, "http://control"+path, body)
	if err != nil {
		t.Fatal(err)
	}
	asked.Header.Set("Content-Type", "application/json")
	answer, err := client.Do(asked)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer answer.Body.Close()
	text, err := io.ReadAll(answer.Body)
	if err != nil {
		t.Fatal(err)
	}
	return answer.StatusCode, string(text)
}

// unready is why the status f's daemon answers says its exit does not serve
func unready(t *testing.T, f *daemonFiles) string {
	t.Helper()
	return daemonEgressStatus(t, f).Unready
}

func daemonEgressStatus(t *testing.T, f *daemonFiles) control.EgressStatus {
	t.Helper()
	answered, body := ask(t, f.opts.controlPath, http.MethodGet, control.PathStatus, nil)
	var status control.Status
	if err := json.Unmarshal([]byte(body), &status); answered != http.StatusOK || err != nil {
		t.Fatalf("status answered %d %q (%v)", answered, body, err)
	}
	return status.Egress
}

// dialTable opens the socket a test reads the table by, and answers its close, which the test calls before leftNothing
// counts the files open and which runs at the test's end where it did not
func dialTable(t *testing.T) (*nftables.Conn, func()) {
	t.Helper()
	nft, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	closeNft := sync.OnceFunc(func() { _ = nft.Close() })
	t.Cleanup(closeNft)
	return nft, closeNft
}

// heldExit is the exit a start builds with its run held from the stop's start until release is closed, so the stop waits
type heldExit struct {
	egress.Exit
	release <-chan struct{}
}

func (e heldExit) Run(ctx context.Context) error {
	<-ctx.Done()
	<-e.release
	return e.Exit.Run(ctx)
}

// Once the stop has begun, up, reload and redial over the control socket are refused as the node stopping and a read still
// answers, while the stop waits for the exit's withdrawal
func TestDaemonRefusesUpReloadAndRedialOnceItStops(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	s := watched(&bus)
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	t.Cleanup(release)
	s.exit = func(cfg *config.Config, node *client.Client, b *events.Bus) (egress.Exit, error) {
		exit, err := newExit(cfg, node, b)
		if err != nil {
			return nil, err
		}
		return heldExit{exit, released}, nil
	}
	code := runAsync(f, s)
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	signalSelf(t, syscall.SIGTERM)
	waitTill(t, "the stop", func() bool { return recorded(&bus, "daemon.stopping") != 0 })
	for path, request := range map[string]control.Request{control.PathUp: {}, control.PathReload: {}, control.PathRedial: {All: true}} {
		if code, answer := ask(t, f.opts.controlPath, http.MethodPost, path, &request); code != http.StatusBadRequest || !strings.Contains(answer, "is stopping") {
			t.Errorf("%s once the stop began answered %d %q, want the node stopping", path, code, answer)
		}
	}
	if code, answer := ask(t, f.opts.controlPath, http.MethodGet, control.PathStatus, nil); code != http.StatusOK {
		t.Errorf("status once the stop began answered %d %q", code, answer)
	}
	release()
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}

// The mesh failing, its tun deleted under it, stops the daemon for that cause with 1, leaving the antispoof filter's chains
// and the kill switch's: the next start takes the antispoof filter's over without a write, and its SIGTERM withdraws both with the table
func TestDaemonStoppedForTheMeshsFailureLeavesTheAntispoofChains(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, leafCaps)
	was := before(t)
	var failed atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&failed))
	waitTill(t, "the start", func() bool { return recorded(&failed, "daemon.started") != 0 })
	if err := netnstest.DelLink(daemonTUN); err != nil {
		t.Fatalf("delete the tun: %v", err)
	}
	if got := exited(t, code); got != 1 {
		t.Errorf("the daemon whose mesh failed exited %d", got)
	}
	nft, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	chains, err := nftables.TableChains(nft, unix.NFPROTO_INET, nftables.Table)
	for _, chain := range []string{kernelexit.EntryChain, "fallback", "output"} {
		if err != nil || !slices.Contains(chains, chain) {
			t.Errorf("the stop for the mesh's failure left the chains %q in the table %s (%v), want %s among them", chains, nftables.Table, err, chain)
		}
	}
	_ = nft.Close()
	var again atomic.Pointer[events.Bus]
	code = runAsync(f, watched(&again))
	waitTill(t, "the next start", func() bool { return recorded(&again, "daemon.started") != 0 })
	if passes := recorded(&again, "antispoof.pass"); passes != 0 {
		t.Errorf("the next start wrote the antispoof filter's chains in %d passes, want them taken over as they were left", passes)
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the next start exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}

// A node with an exit over a tun made before its start, left persistent with its maker's descriptor closed as
// systemd-networkd leaves the device a netdev of kind tun makes, exits 0 on SIGTERM, and the device outlives its mesh.
// The exit leaves its stopped rules over it, the table holding nothing else, and warns why, and the rest of the daemon
// leaves nothing: once the table and the device are deleted, as whoever retires the device deletes them, no listener,
// socket, file, goroutine, route or rule of the start is left.
func TestDaemonShutdownOverATunMadeBeforeIt(t *testing.T) {
	claimNamespace(t)
	persistentTUN(t, daemonTUN)
	var logged lockedLog
	defer slog.SetDefault(slog.Default())
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	f := writeDaemon(t, exitCaps)
	// opened before the count of open files the start is held to
	nft, err := nftables.Dial()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if chains, err := nftables.TableChains(nft, unix.NFPROTO_INET, nftables.Table); err == nil && len(chains) != 0 {
			_ = nft.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)})
		}
		_ = nft.Close()
	})
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&bus))
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	if _, err := net.InterfaceByName(daemonTUN); err != nil {
		t.Fatalf("the tun made before the start is gone after the stop: %v", err)
	}
	// The form below is the one place this test says what a shutdown leaves over a tun that outlives the mesh. The
	// table holds the exit's chains, its sets of flows and of untranslated sources and its timeouts and nothing of the
	// antispoof filter's. Among its
	// rules are the hold in place of the limit and each family's labelled drop, and none of them is a limit of the
	// running pass. The log holds the warning that names why.
	left := tableContents{
		chains:  []string{kernelexit.LimitChain, "forward6", kernelexit.ChainName},
		sets:    []string{"flows4", "untranslated4"},
		objects: []string{"icmp4", "tcp4", "udp4"},
	}
	stopped := []string{
		kernelexit.LimitChain + ": out via " + daemonTUN + " ipv4 dropped while stopped",
		kernelexit.LimitChain + ": translated via " + daemonTUN + " ipv4 leaving by another link dropped while stopped",
		"forward6: translated via " + daemonTUN + " ipv6 leaving by another link dropped while stopped",
	}
	line := `level=WARN msg="egress left its stopped rules at shutdown" why="the mesh device ` + daemonTUN + ` outlives the mesh"`
	held := readTable(t, nft)
	if !slices.Equal(held.chains, left.chains) || !slices.Equal(held.sets, left.sets) || !slices.Equal(held.objects, left.objects) {
		t.Errorf("the shutdown left the chains %q, the sets %q and the objects %q in the table %s, want %q, %q and %q",
			held.chains, held.sets, held.objects, nftables.Table, left.chains, left.sets, left.objects)
	}
	for _, rule := range stopped {
		if !slices.Contains(held.rules, rule) {
			t.Errorf("the shutdown left the rules %q, want %q among them", held.rules, rule)
		}
	}
	if i := slices.IndexFunc(held.rules, func(rule string) bool { return strings.Contains(rule, " limit ") }); i >= 0 {
		t.Errorf("the shutdown left the running pass's limit %q among the rules %q", held.rules[i], held.rules)
	}
	if !strings.Contains(logged.String(), line) {
		t.Errorf("the shutdown logged no line %s:\n%s", line, logged.String())
	}
	if len(held.chains) != 0 {
		if err := nft.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, nftables.Table)}); err != nil {
			t.Fatalf("delete the table the shutdown left: %v", err)
		}
	}
	if err := netnstest.DelLink(daemonTUN); err != nil {
		t.Fatalf("delete the tun: %v", err)
	}
	leftNothing(t, f, was)
}

// persistentTUN makes the tun name as systemd-networkd makes a netdev of kind tun with MultiQueue and VNetHeader, the
// flags the mesh attaches with, persistent, and closes its descriptor, so the device stays with no queue until the
// test deletes it, which a cleanup does where the test has not
func persistentTUN(t *testing.T, name string) {
	t.Helper()
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatal(err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		t.Fatalf("make the tun %s: %v", name, err)
	}
	t.Cleanup(func() { _ = netnstest.DelLink(name) })
	if err := unix.IoctlSetInt(fd, unix.TUNSETPERSIST, 1); err != nil {
		t.Fatalf("make the tun %s persistent: %v", name, err)
	}
}

// tableContents holds, of the inet table named nftables.Table, the name of each chain, named set and object, each
// sorted, and each rule as its chain and its comment, in the order of its chain
type tableContents struct {
	chains, sets, objects, rules []string
}

// readTable reads what the table holds through nft, none where the table is not there
func readTable(t *testing.T, nft *nftables.Conn) tableContents {
	t.Helper()
	var out tableContents
	if held, err := nftables.Tables(nft, nftables.Table); err != nil {
		t.Fatal(err)
	} else if _, there := held[unix.NFPROTO_INET]; !there {
		return out
	}
	chains, err := nftables.TableChains(nft, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		t.Fatal(err)
	}
	out.chains = slices.Sorted(slices.Values(chains))
	sets, err := nft.Dump(nftables.Command(unix.NFT_MSG_GETSET), netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_SET_TABLE, nftables.Table))
	if err != nil {
		t.Fatalf("dump the sets of the table %s: %v", nftables.Table, err)
	}
	for _, reply := range sets {
		if set := nftables.DecodeSet(reply); set.Table == nftables.Table && set.Flags&unix.NFT_SET_ANONYMOUS == 0 {
			out.sets = append(out.sets, set.Name)
		}
	}
	slices.Sort(out.sets)
	objects, err := nft.Dump(nftables.Command(unix.NFT_MSG_GETOBJ), netlink.PutAttrString(nftables.PutNfgenmsg(nil, unix.NFPROTO_INET), unix.NFTA_OBJ_TABLE, nftables.Table))
	if err != nil {
		t.Fatalf("dump the objects of the table %s: %v", nftables.Table, err)
	}
	for _, reply := range objects {
		var table, name string
		for kind, value := range reply.Attributes(nftables.SizeofNfgenmsg) {
			switch kind {
			case unix.NFTA_OBJ_TABLE:
				table = unix.ByteSliceToString(value)
			case unix.NFTA_OBJ_NAME:
				name = unix.ByteSliceToString(value)
			}
		}
		if table == nftables.Table {
			out.objects = append(out.objects, name)
		}
	}
	slices.Sort(out.objects)
	rules, err := nftables.TableRules(nft, unix.NFPROTO_INET, nftables.Table)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		out.rules = append(out.rules, rule.Chain+": "+rule.Spec)
	}
	return out
}

// A reload while the node is down leaves the chains of its stopped exit, the translation's chain kept beside the stop's
// drops, as the stop wrote them: the node takes a file whose cap.egress is unchanged and refuses one that changes it as a
// restart's to apply, and for neither does the exit write or read anything but stopped
func TestDaemonReloadWhileDownLeavesTheStoppedExitsChains(t *testing.T) {
	claimNamespace(t)
	f := writeDaemon(t, exitCaps)
	was := before(t)
	var bus atomic.Pointer[events.Bus]
	code := runAsync(f, watched(&bus))
	waitTill(t, "the start", func() bool { return recorded(&bus, "daemon.started") != 0 })
	nft, closeNft := dialTable(t)
	held := func() []string {
		t.Helper()
		rules, err := nftables.TableRules(nft, unix.NFPROTO_INET, nftables.Table)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, rule := range rules {
			lines = append(lines, rule.Chain+": "+rule.Spec)
		}
		return lines
	}
	const stopped = "the translator is stopped"
	if answered, body := ask(t, f.opts.controlPath, http.MethodPost, control.PathDown, &control.Request{}); answered != http.StatusOK {
		t.Fatalf("down answered %d %q", answered, body)
	}
	var status control.EgressStatus
	waitTill(t, "the stop", func() bool {
		status = daemonEgressStatus(t, f)
		return status.Unready == stopped
	})
	// the stopped layout drops more running rules than it adds in this fixture
	installed := fmt.Sprint(status.Installed)
	waitTill(t, "the recorded stop", func() bool {
		passes := bus.Load().Recorded(func(kind, _ string, _ []slog.Attr) bool { return kind == "egress.pass" }, 0)
		return slices.ContainsFunc(passes, func(pass control.Event) bool {
			return pass.Attrs["installed"] == installed && pass.Attrs["err"] == ""
		})
	})
	lines, passes := held(), recorded(&bus, "egress.pass")
	for _, line := range []string{
		kernelexit.ChainName + ": out via " + daemonTUN + " ipv4 masquerade",
		kernelexit.LimitChain + ": out via " + daemonTUN + " ipv4 dropped while stopped",
		kernelexit.LimitChain + ": translated via " + daemonTUN + " ipv4 leaving by another link dropped while stopped",
	} {
		if !slices.Contains(lines, line) {
			t.Errorf("the stopped exit's table holds %q, want %q among them", lines, line)
		}
	}
	file, err := os.ReadFile(f.opts.configPath)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(file), "198.51.100.0/24", "198.51.100.0/25", 1)
	for _, reload := range []struct {
		what, file string
		answered   int
		answer     string
	}{
		{"the same file", string(file), http.StatusOK, ""},
		{"a file changing cap.egress", changed, http.StatusBadRequest, "cap.egress changed, restart to apply"},
	} {
		if err := os.WriteFile(f.opts.configPath, []byte(reload.file), 0o600); err != nil {
			t.Fatal(err)
		}
		if answered, body := ask(t, f.opts.controlPath, http.MethodPost, control.PathReload, &control.Request{}); answered != reload.answered || !strings.Contains(body, reload.answer) {
			t.Errorf("a reload of %s while down answered %d %q, want %d holding %q", reload.what, answered, body, reload.answered, reload.answer)
		}
		// past any pass a wake would run
		time.Sleep(daemonQuiet)
		if got, wrote, why := held(), recorded(&bus, "egress.pass")-passes, unready(t, f); !slices.Equal(got, lines) || wrote != 0 || why != stopped {
			t.Errorf("after a reload of %s while down the table holds %q after %d writes of the exit, which reads %q, want %q after none and %q",
				reload.what, got, wrote, why, lines, stopped)
		}
	}
	// the test's own socket is no file of the start's
	closeNft()
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the daemon exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}
