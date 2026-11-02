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
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
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
	"ranet3.com/pkgs/ranet3/internal/netnstest"
	"ranet3.com/pkgs/ranet3/internal/nftables"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

// the tests in this file start the daemon as runDaemon does, its tun, its sockets, its nftables and its netlink opened from
// whatever thread a goroutine runs on, so they run as root in a network namespace the whole process started in and that held
// nothing, which unshare -rn starts, and skip anywhere without root

const (
	// daemonTUN is the tun of the daemon these tests start
	daemonTUN = "start0"
	// daemonQuiet is how long a test watches for what must not happen, long past a dial or a reload that would
	daemonQuiet = 500 * time.Millisecond
	// daemonSettle bounds a wait for what the daemon does once asked, and for the goroutines of a start to end
	daemonSettle = 10 * time.Second
	// daemonPrompt bounds what the daemon does at once on a signal, well inside the first pass's wait it must not sit out
	daemonPrompt = firstPassWait / 5
)

var (
	claimOnce sync.Once
	claimSkip string
	claimErr  error
)

// claimNamespace skips the test without root and refuses it in a namespace that held anything, and brings the loopback up
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
}

// daemonFiles is a node's files and flags in a directory of the test's own, and the socket its one peer's endpoint is, which
// counts each datagram the node sends it
type daemonFiles struct {
	opts  options
	port  int
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
	f := &daemonFiles{port: freePort(t, "udp")}
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
	for name, port := range map[string]int{"start": f.port, "peer": f.peer.LocalAddr().(*net.UDPAddr).Port} {
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
%s`, key, trust, f.port, daemonTUN, caps)
	f.opts = options{
		configPath:  filepath.Join(dir, "config.yaml"),
		pprofAddr:   fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		metricsAddr: fmt.Sprintf("127.0.0.1:%d", freePort(t, "tcp")),
		controlPath: filepath.Join(shortDir(t), "control.sock"),
		stateDir:    filepath.Join(dir, "state"),
		level:       slog.LevelInfo,
	}
	if err := os.WriteFile(f.opts.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(f.opts.configPath); err != nil {
		t.Fatalf("the test's node file is refused: %v", err)
	}
	return f
}

// shortDir is a directory of the test's own directly under the temporary directory, whose path leaves a socket in it within
// the 103 bytes a unix socket's path holds, which t.TempDir's, named after the test, can pass
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ranet3-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// freePort is a port of network on the loopback that nothing holds now
func freePort(t *testing.T, network string) int {
	t.Helper()
	if network == "udp" {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// watched is production with the node's bus kept, so a test reads what the daemon recorded
func watched(bus *atomic.Pointer[events.Bus]) stages {
	s := production
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

// signalSelf sends sig to this process and returns once os/signal has handed it to a channel of the test's own, which it hands
// the daemon's in the same delivery
func signalSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	seen := make(chan os.Signal, 1)
	signal.Notify(seen, sig)
	defer signal.Stop(seen)
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	select {
	case <-seen:
	case <-time.After(daemonSettle):
		t.Fatalf("%s was not delivered", sig)
	}
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
// or route of the reconciler's protocol
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
	conn, err := net.ListenPacket("udp4", fmt.Sprintf(":%d", f.port))
	if err != nil {
		t.Errorf("the node's port %d is still bound: %v", f.port, err)
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
	for _, name := range []string{kernelexit.TableName, kernel.FallbackTable} {
		if held, err := nftables.Tables(nft, name); err != nil || len(held) != 0 {
			t.Errorf("the table %s is held in the families %v (%v)", name, held, err)
		}
	}
	rules, err := kernel.DumpRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Protocol == kernel.DefaultProtocol {
			t.Errorf("the rule %+v is still there", rule)
		}
	}
	if routes := ownRoutes(t); routes != 0 {
		t.Errorf("%d routes of the reconciler's protocol are still there", routes)
	}
}

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

// lockedLog keeps what a log writes from any goroutine
type lockedLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

// A refusal at each part of the start, the first and the last of them included, is logged as that part's, closes what the
// start built before it, logs none of it started and returns 1 with no goroutine of the start running and nothing of it
// bound: the listeners, the control socket, the node's port, the tun, the antispoof filter's table and the exit's tables. The
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
			s := production
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

// A start refused after the antispoof filter's first pass, or stopped while it builds, leaves the antispoof filter's table
// and the kill switch's that an earlier instance left, the antispoof filter's as that pass rewrote it, and withdraws neither
func TestDaemonEndedInItsBuildLeavesTheTablesItFound(t *testing.T) {
	claimNamespace(t)
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
			f := writeDaemon(t, leafCaps)
			nft, err := nftables.Dial()
			if err != nil {
				t.Fatal(err)
			}
			defer nft.Close()
			// empty, as no start writes them, so the antispoof filter's first pass rewrites its own
			tables := []string{kernelexit.TableName, kernel.FallbackTable}
			for _, table := range tables {
				if err := nft.Batch([]nftables.Request{nftables.NewTable(unix.NFPROTO_INET, table)}); err != nil {
					t.Fatal(err)
				}
			}
			was := before(t)
			s := production
			arm.end(&s)
			if code := exited(t, runAsync(f, s)); code != arm.code {
				t.Errorf("a start %s exited %d, want %d", name, code, arm.code)
			}
			for _, table := range tables {
				if held, err := nftables.Tables(nft, table); err != nil || len(held) == 0 {
					t.Errorf("a start %s left the table %s it found in the families %v (%v), want it held", name, table, held, err)
				}
				if err := nft.Batch([]nftables.Request{nftables.DeleteTable(unix.NFPROTO_INET, table)}); err != nil {
					t.Errorf("delete the table %s: %v", table, err)
				}
			}
			leftNothing(t, f, was)
		})
	}
}

// held is production with the reconciler's passes held at their first read of the sessions until release is called, which
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
	go func() { code <- startDaemon(f.opts, s) }()
	return code
}

// exited is the daemon's exit status once code answers it, failing t where it takes longer than daemonSettle, after which
// a SIGTERM stops the daemon so the next test finds nothing of it
func exited(t *testing.T, code <-chan int) int {
	t.Helper()
	select {
	case got := <-code:
		return got
	case <-time.After(daemonSettle):
		t.Error("the daemon did not return")
		signalSelf(t, syscall.SIGTERM)
		return <-code
	}
}

// waitTill polls done until it holds, failing t after daemonSettle
func waitTill(t *testing.T, what string, done func() bool) {
	t.Helper()
	waitWithin(t, what, daemonSettle, done)
}

// waitWithin polls done until it holds, failing t after within
func waitWithin(t *testing.T, what string, within time.Duration, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, within)
		}
		time.Sleep(10 * time.Millisecond)
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

// The mesh failing, its tun deleted under it, stops the daemon for that cause with 1, leaving the antispoof filter's table
// and the kill switch's: the next start takes the antispoof filter's over without a write, and its SIGTERM withdraws both
func TestDaemonStoppedForTheMeshsFailureLeavesTheAntispoofTable(t *testing.T) {
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
	for _, name := range []string{kernelexit.TableName, kernel.FallbackTable} {
		if held, err := nftables.Tables(nft, name); err != nil || len(held) == 0 {
			t.Errorf("the stop for the mesh's failure left the table %s in the families %v (%v), want it held", name, held, err)
		}
	}
	_ = nft.Close()
	var again atomic.Pointer[events.Bus]
	code = runAsync(f, watched(&again))
	waitTill(t, "the next start", func() bool { return recorded(&again, "daemon.started") != 0 })
	if passes := recorded(&again, "antispoof.pass"); passes != 0 {
		t.Errorf("the next start wrote the antispoof filter's table in %d passes, want it taken over as it was left", passes)
	}
	signalSelf(t, syscall.SIGTERM)
	if got := exited(t, code); got != 0 {
		t.Errorf("the next start exited %d after SIGTERM", got)
	}
	leftNothing(t, f, was)
}
