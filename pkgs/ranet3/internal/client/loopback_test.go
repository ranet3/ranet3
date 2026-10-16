// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/ike"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

var meshCounter atomic.Uint64

// loopbackNode is one end of a two-node mesh standing on 127.0.0.1.
type loopbackNode struct {
	name       string
	port       uint16
	prefix     netip.Prefix
	client     *Client
	cfg        *config.Config
	configPath string
	events     *events.Bus
}

// freeUDPPort asks the kernel for a port and gives it straight back, the only way to name one in a config before the hub binds it
// it binds as the hub does, udp4 and then udp6 on the wildcard
// it asks again while udp6 refuses the port udp4 was handed
// a socket on any of the host's own addresses keeps the hub off that port for as long as the socket lives
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	for range portAttempts {
		v4, err := net.ListenUDP("udp4", &net.UDPAddr{})
		if err != nil {
			t.Fatal(err)
		}
		port := v4.LocalAddr().(*net.UDPAddr).Port
		v6, err := net.ListenUDP("udp6", &net.UDPAddr{Port: port})
		switch {
		case err == nil:
			err = v6.Close()
		case errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT):
			// the hub binds udp4 alone on a host without IPv6
			err = nil
		}
		if closeErr := v4.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if err == nil {
			return uint16(port)
		}
		t.Logf("udp6 refused port %d, which udp4 was handed: %v", port, err)
	}
	t.Fatalf("%d ports in a row that udp4 was handed were refused on udp6", portAttempts)
	return 0
}

const (
	// portAttempts is how often a test asks for a port the kernel had just handed back
	portAttempts = 10
	// portBackoff is the wait after the first failed ask, and each later wait is one step longer
	portBackoff = 20 * time.Millisecond
)

// retryPort runs try until it succeeds, for a port the kernel had just handed back
// a port is chosen by binding zero, reading it back and giving it up, and anything else on the machine can take it in between
// on a loaded machine several tests do this at once, and the wait makes a run of losses unlikely rather than merely improbable
// without it a busy machine lost every attempt in the same handful of microseconds
func retryPort(t testing.TB, what string, try func() error) {
	t.Helper()
	for attempt := range portAttempts {
		err := try()
		if err == nil {
			return
		}
		t.Logf("attempt %d could not %s the port the kernel had just handed back: %v", attempt, what, err)
		time.Sleep(time.Duration(attempt+1) * portBackoff)
	}
	t.Fatalf("%d attempts in a row could not %s a port the kernel had just handed back", portAttempts, what)
}

// newLoopbackMesh builds two clients that know about each other, each on its
// own UDP port, sharing one organization key. Neither owns a TUN: babel
// intercepts its own traffic before delivery, so nothing reaches one.
//
// It retries. freeUDPPort asks the kernel for a port and gives it straight
// back, because naming one in a config file is the only way these nodes can
// find each other, so anything else on the machine can take it in the gap.
// Retrying with fresh ports is the difference between a rare unexplained
// failure somewhere in this package and none.
func newLoopbackMesh(t *testing.T) (alpha, bravo *loopbackNode) {
	t.Helper()
	return newLoopbackMeshOn(t, netstack.NewRoutesOnly())
}

// newLoopbackMeshOn is newLoopbackMesh with bravo on mesh, which bravo's client closes with itself
// an attempt that fails leaves mesh open for the next
func newLoopbackMeshOn(t *testing.T, mesh *netstack.Mesh) (alpha, bravo *loopbackNode) {
	t.Helper()
	retryPort(t, "bind", func() (err error) {
		alpha, bravo, err = tryLoopbackMesh(t, mesh)
		return err
	})
	return alpha, bravo
}

func tryLoopbackMesh(t *testing.T, bravoMesh *netstack.Mesh) (_, _ *loopbackNode, err error) {
	t.Helper()
	nodes, private, reg := writeMesh(t, [2]uint16{freeUDPPort(t), freeUDPPort(t)}, [2]string{"127.0.0.1", "127.0.0.1"})
	meshes := []*netstack.Mesh{netstack.NewRoutesOnly(), bravoMesh}
	for i, node := range nodes {
		client, err := newClient(node.cfg, private, trust(t, reg), meshes[i], nil, node.events)
		if err != nil {
			for _, built := range nodes[:i] {
				built.client.Close()
			}
			return nil, nil, fmt.Errorf("%s: %w", node.name, err)
		}
		node.client = client
	}
	return nodes[0], nodes[1], nil
}

// writeMesh makes the organization key of a two node mesh, alpha and bravo, and the files their clients read
// each node takes its port from ports
// it has one endpoint in the registry, at its address in addresses and its port
// it writes the registry and the key to a directory of the test's own
// it then writes and loads each node's config, which dials the other node
// it returns the nodes without their clients, and the organization's private key and registry a client is built from
func writeMesh(t *testing.T, ports [2]uint16, addresses [2]string) ([]*loopbackNode, ed25519.PrivateKey, registry.Registry) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	// Names are unique per mesh, not per role. A port the kernel handed back
	// can be handed out again once a hub closes, and a node another test left
	// retransmitting would otherwise authenticate against its replacement:
	// same organization key, same common name, same port.
	mesh := meshCounter.Add(1)
	nodes := []*loopbackNode{
		{name: fmt.Sprintf("alpha-%d", mesh), port: ports[0], prefix: netip.MustParsePrefix("fd00:a::/64")},
		{name: fmt.Sprintf("bravo-%d", mesh), port: ports[1], prefix: netip.MustParsePrefix("fd00:b::/64")},
	}
	org := registry.Organization{PublicKey: publicPEM, Organization: "example"}
	for i, node := range nodes {
		org.Nodes = append(org.Nodes, registry.Node{
			CommonName: node.name,
			Endpoints: []registry.Endpoint{{
				SerialNumber: "0", AddressFamily: "ip4", Address: &addresses[i], Port: node.port,
			}},
		})
	}
	reg := registry.Registry{org}

	// Written to disk as well, because Reload reads the file rather than
	// taking a struct, and that is the path a SIGHUP takes.
	dir := t.TempDir()
	registryPath := filepath.Join(dir, "registry.json")
	raw, err := json.Marshal(reg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	for i, node := range nodes {
		peer := nodes[1-i]
		node.configPath = filepath.Join(dir, node.name+".yaml")
		node.cfg = writeLoopbackConfig(t, node, peer, keyPath, registryPath, []string{node.prefix.String()})
		node.events = events.New()
	}
	return nodes, private, reg
}

// writeLoopbackConfig writes one node's config file and loads it back, so the
// running client and the file a reload reads can never drift apart.
func writeLoopbackConfig(t *testing.T, node, peer *loopbackNode, keyPath, registryPath string, originate []string) *config.Config {
	t.Helper()
	var body strings.Builder
	fmt.Fprintf(&body, `node: example/%s
auth:
  key: %s
  trust: %s
link:
  port: %d
  endpoints:
    - serial: "0"
      family: ip4
  # Both ends answer as well as dial, which is the full mesh shape and the one
  # that produces a simultaneous open.
  listen: true
dial:
  to:
    - example/%s:0
cap:
  babel:
    hello: 200ms
    update: 400ms
  route:
    announce:
`, node.name, keyPath, registryPath, node.port, peer.name)
	for _, prefix := range originate {
		fmt.Fprintf(&body, "      - %q\n", prefix)
	}
	if err := os.WriteFile(node.configPath, []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(node.configPath)
	if err != nil {
		t.Fatalf("%s: %v", node.name, err)
	}
	return cfg
}

// Two nodes dialing and answering each other is the shape a full mesh has, and
// no other test in this package executes Run, acceptPeers, connectPeer,
// serveSession or closeSession at all: the resolution rules are exercised
// against a model of sessionSet with its own close and liveness stubbed out.
func TestTwoNodesConvergeOverLoopback(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	_, stop := run(t, alpha, bravo)

	// Both ends settle on exactly one session, which is the thing the
	// preference rule decides and which diverges if the two ends disagree.
	waitFor(t, convergeBudget, "one established session at each end", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// And the route each announces reaches the other, which means the session
	// is carrying ESP, babel is running inside it and the forwarding table was
	// written.
	waitFor(t, convergeBudget, "each node forwarding to the other's prefix", func() bool {
		return reaches(alpha, bravo) && reaches(bravo, alpha)
	})

	// One session at each end is not the same thing as the same session at
	// both ends. Two nodes evicting each other hold one apiece and still carry
	// traffic, so neither check above can tell that apart from convergence.
	// The preference bit is a property of the SA rather than of the node that
	// holds it, so the two ends agree on it exactly when they are holding the
	// same SA.
	waitFor(t, convergeBudget, "both ends holding the same session", func() bool {
		a, aok := preferenceOf(alpha)
		b, bok := preferenceOf(bravo)
		return aok && bok && a == b
	})

	stop()
}

// reaches is whether from forwards to an address in to's prefix through the mesh
func reaches(from, to *loopbackNode) bool {
	peer, ok := from.client.Mesh.Routes.Lookup(netip.Addr{}, to.prefix.Addr().Next())
	return ok && peer != nil
}

// preferenceOf reads the preference bit of the one session a node is holding.
func preferenceOf(node *loopbackNode) (bool, bool) {
	set := node.client.sessions
	set.mu.Lock()
	defer set.mu.Unlock()
	if len(set.live) != 1 {
		return false, false
	}
	for _, live := range set.live {
		return live.preferred, true
	}
	return false, false
}

func isCanceled(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// run starts each node and returns a stop that cancels and waits for every one
// of them. Waiting matters: a client left unwinding keeps its dialers retrying
// and its hub bound, and the next test would then be sharing a port with it.
func run(t *testing.T, nodes ...*loopbackNode) (context.Context, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, len(nodes))
	for _, node := range nodes {
		go func() { stopped <- node.client.Run(ctx) }()
	}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			for range nodes {
				select {
				case err := <-stopped:
					if err != nil && !isCanceled(err) {
						t.Errorf("a node stopped with %v", err)
					}
				case <-time.After(convergeBudget):
					t.Error("a node did not stop after its context was canceled")
				}
			}
		})
	}
	t.Cleanup(stop)
	return ctx, stop
}

// convergeBudget is how long these tests wait for something they expect to
// happen. It is generous because a loaded machine is not a failing
// implementation: a convergence that never happens still fails the test, just
// later, while a budget tuned to an idle machine turns load into a false red.
// Every one of these is a positive assertion, so nothing is weakened by
// waiting longer.
const convergeBudget = 60 * time.Second

func waitFor(t testing.TB, limit time.Duration, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// SIGHUP announcing a new prefix has to reach the peer's forwarding table.
// The existing reload test sets Originate and asserts peer and registry
// counts, so deleting the SetOriginated call passes it.
func TestReloadAnnouncesNewPrefixToPeer(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, alpha, bravo)
	added := netip.MustParsePrefix("fd00:aa::/64")
	waitFor(t, convergeBudget, "the initial route", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, alpha.prefix.Addr().Next())
		return ok && peer != nil
	})

	writeLoopbackConfig(t, alpha, bravo, alpha.cfg.Auth.Key, alpha.cfg.Auth.Trust,
		[]string{alpha.prefix.String(), added.String()})
	if err := alpha.client.ReloadFrom(alpha.configPath); err != nil {
		t.Fatalf("adding an originated prefix was refused: %v", err)
	}

	waitFor(t, convergeBudget, "the reloaded prefix to reach the peer", func() bool {
		peer, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, added.Addr().Next())
		return ok && peer != nil
	})
}

// A stopped responder refuses the handshakes it answers, and starting it again
// lets the next one through. No other test executes acceptPeers, so a gate
// checked anywhere but there passes every unit test and leaves a node still
// answering every dial an operator told it to stop answering.
func TestStoppedResponderRefusesLiveHandshakes(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// Bravo answers and never dials, so the only session that can exist is the
	// one alpha opens through the gate under test. With bravo dialing too, a
	// session would form in the other direction whatever the gate did.
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	// Short enough that alpha comes round several times inside the budget
	// below, since each refused handshake sends it back to the delay.
	alpha.client.dialRetry = 200 * time.Millisecond
	if _, err := bravo.client.SetSubsystem(context.Background(), control.SubsystemResponder, false); err != nil {
		t.Fatal(err)
	}
	run(t, alpha, bravo)

	// Alpha keeps dialing and bravo keeps refusing, so neither end settles.
	// Time rather than an event, because what is asserted is that nothing
	// happens. The delay above bounds how many attempts that covers.
	time.Sleep(3 * time.Second)
	if held := len(bravo.client.sessions.paths()); held != 0 {
		t.Errorf("a stopped responder is holding %d sessions", held)
	}
	if held := len(alpha.client.sessions.paths()); held != 0 {
		t.Errorf("the dialer settled on %d sessions against a stopped responder", held)
	}

	if _, err := bravo.client.SetSubsystem(context.Background(), control.SubsystemResponder, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, convergeBudget, "the responder started again to answer a dial", func() bool {
		return len(bravo.client.sessions.paths()) == 1 && len(alpha.client.sessions.paths()) == 1
	})
}

// Shutting down closes the hub, which ends every dialed session at once. See
// Client.stopping for what the dialers have to read that as.
func TestShutdownSaysNothingAboutReconnecting(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// closeAll runs before c.cancel, deliberately, and on a full mesh it takes
	// long enough for a dialer to reach its own check while the context is
	// still alive. Held open here so the window is the same size every time
	// rather than whatever the scheduler gives, and set before either node
	// runs because adoptFor reads this outside the set's own lock.
	closeSession := alpha.client.sessions.close
	alpha.client.sessions.close = func(sess *ike.Session) {
		closeSession(sess)
		time.Sleep(200 * time.Millisecond)
	}
	run(t, bravo)
	_, stopAlpha := run(t, alpha)

	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	written := &syncBuffer{}
	previous := log.Writer()
	log.SetOutput(written)
	t.Cleanup(func() { log.SetOutput(previous) })
	stopAlpha()
	// Only alpha is stopping, and both nodes write to the one logger this
	// captures, so the lines that count are the ones naming alpha's own peer.
	// bravo stays up, loses the node it was dialing and says it will retry,
	// which is the correct thing for a node whose peer went away: counting its
	// line as well failed this test in about one run in thirty.
	dialingBravo := "peer " + bravo.cfg.Node.String()
	var got []string
	for _, line := range written.lines("reconnecting in") {
		if strings.Contains(line, dialingBravo) {
			got = append(got, line)
		}
	}
	if len(got) != 0 {
		t.Errorf("shutdown wrote %d reconnect lines, want none: %s", len(got), strings.Join(got, " | "))
	}
}

// Shutdown tells every peer the SA is gone rather than leaving it sending ESP
// into an SPI we no longer accept until its own dead peer detection expires,
// which is over a minute. closeAll and the Delete inside closeSession are both
// unreachable from anything else in this package.
//
// closeAll is driven directly rather than through the whole client stop,
// because a node that is canceled while it is dialing leaves the other end
// holding a session it was never told about: the responder commits at
// IKE_AUTH and the initiator confirms a message later, so an initiator that
// goes between the two has nothing to send a Delete on. That is the exchange's
// own shape, not this sweep's, and the peer clears it on liveness. Driving the
// sweep makes this deterministic. The redial that follows a resolved
// simultaneous open is otherwise in flight whenever the machine is slow.
func TestShutdownTellsPeerBeforeGoing(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	run(t, bravo)
	_, stopAlpha := run(t, alpha)
	t.Cleanup(stopAlpha)

	waitFor(t, convergeBudget, "both ends established", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})

	// Only alpha's sessions go, while its hub is still open to carry the
	// Delete. bravo has to notice through that rather than through its own
	// liveness timer, which is far slower than this.
	alpha.client.sessions.closeAll()
	deadline := time.Now().Add(convergeBudget)
	for len(bravo.client.sessions.paths()) != 0 {
		if time.Now().After(deadline) {
			bravo.client.sessions.mu.Lock()
			for path, live := range bravo.client.sessions.live {
				t.Logf("bravo still holds %s: mux closed=%v preferred=%v active=%v",
					path, live.session.Mux().IsClosed(), live.preferred, live.session.Active())
			}
			bravo.client.sessions.mu.Unlock()
			t.Fatal("the peer kept a session it was told to drop")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// each end of a session searches its path up to the link.mtu its own node names, which a loopback path carries
// the reader holds every packet for that peer to it
// and the inbound clamp lowers the MSS of a SYN from that peer to what it carries
// the ends name a value under the default a session starts at and one the search reaches only by probes
func TestSessionsCarryTheLinkMTUOfTheirOwnNode(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	ends := []struct {
		node, peer *loopbackNode
		mtu        uint16
	}{{alpha, bravo, 1300}, {bravo, alpha, 2000}}
	for _, end := range ends {
		cfg := *end.node.client.config()
		cfg.Link.MTU = end.mtu
		end.node.client.cfg.Store(&cfg)
	}
	run(t, alpha, bravo)
	for _, end := range ends {
		var peer *netstack.Peer
		waitFor(t, convergeBudget, end.node.name+" forwarding to "+end.peer.name+"'s prefix", func() bool {
			found, ok := end.node.client.Mesh.Routes.Lookup(netip.Addr{}, end.peer.prefix.Addr().Next())
			peer = found
			return ok && found != nil
		})
		waitFor(t, convergeBudget, fmt.Sprintf("%s's session to %s to carry its link.mtu of %d", end.node.name, end.peer.name, end.mtu), func() bool {
			return peer.MTU() == int(end.mtu)
		})
	}
}

// a reload hands every session a node holds the new link.mtu, as a session made after it gets, and the search carries it there over a loopback path
// bravo starts at link.mtu 1300 with nothing steered and holds the one session alpha dials
// a reload to the default link.mtu with a two segment list through alpha's prefix applies
// a session kept at 1300 would answer a steered IPv6 packet past 1220 bytes with a packet too big naming 1220
// and RFC 8201 section 4 keeps its sender's path MTU at 1280 or more, past what the session carries
func TestReloadHandsALiveSessionTheNewLinkMTU(t *testing.T) {
	const started = 1300
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so the one session is the one alpha dials and no resolution replaces it
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	quiet.Link.MTU = started
	bravo.client.cfg.Store(&quiet)
	run(t, alpha, bravo)
	var peer *netstack.Peer
	waitFor(t, convergeBudget, "bravo forwarding to alpha's prefix", func() bool {
		found, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, alpha.prefix.Addr().Next())
		peer = found
		return ok && found != nil
	})
	if got := peer.MTU(); got != started {
		t.Fatalf("bravo's session to alpha carries %d byte packets before the reload, want its link.mtu of %d", got, started)
	}
	next := quiet
	next.Link.MTU = 0
	first := alpha.prefix.Addr().Next()
	next.Cap.Segment = steering(first.String(), first.Next().String())
	writeConfig(t, bravo.configPath, &next)
	if err := bravo.client.ReloadFrom(bravo.configPath); err != nil {
		t.Fatalf("a reload to the default link.mtu with a two segment list was refused: %v", err)
	}
	waitFor(t, convergeBudget, fmt.Sprintf("bravo's session to alpha to carry the new link.mtu of %d", netstack.DefaultMTU), func() bool {
		return peer.MTU() == netstack.DefaultMTU
	})
}

// a session whose handshake ends while a reload runs takes the link.mtu that reload stores
// the test holds bravo's session set, so bravo's first session waits in adopt with its handshake done
// it then stores the default link.mtu as a reload does, while the session is outside the set the reload sweeps, and lets go
// a session that read link.mtu before adopt keeps 1300 for its life
func TestSessionAdoptedDuringAReloadTakesTheStoredLinkMTU(t *testing.T) {
	const started = 1300
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so its first session is the one alpha dials
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	quiet.Link.MTU = started
	bravo.client.cfg.Store(&quiet)
	set := bravo.client.sessions
	set.mu.Lock()
	held := true
	defer func() {
		if held {
			set.mu.Unlock()
		}
	}()
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "bravo's first session waiting for its session set in adopt", waitingInAdopt)
	if len(set.live) != 0 {
		t.Fatalf("bravo holds %d sessions while its first waits in adopt, want none for a sweep to reach", len(set.live))
	}
	next := quiet
	next.Link.MTU = 0
	bravo.client.cfg.Store(&next)
	set.mu.Unlock()
	held = false
	var peer *netstack.Peer
	waitFor(t, convergeBudget, "bravo forwarding to alpha's prefix", func() bool {
		found, ok := bravo.client.Mesh.Routes.Lookup(netip.Addr{}, alpha.prefix.Addr().Next())
		peer = found
		return ok && found != nil
	})
	if got := peer.MTU(); got != netstack.DefaultMTU {
		t.Errorf("the session adopted during the reload carries %d byte packets, want the stored link.mtu of %d", got, netstack.DefaultMTU)
	}
}

// stackDumpSize is the bytes waitingInAdopt and dialerStandingDown read every goroutine's stack into, room for the running nodes of one test many times over
const stackDumpSize = 4 << 20

// waitingInAdopt reports whether a session a node answered waits for its session set's lock inside adoptFor
// a dialed session of the other node passes through adoptFor too, and it holds no lock a test holds
func waitingInAdopt() bool {
	stacks := make([]byte, stackDumpSize)
	n := runtime.Stack(stacks, true)
	for goroutine := range strings.SplitSeq(string(stacks[:n]), "\n\n") {
		if strings.Contains(goroutine, "sync.(*Mutex).Lock") && strings.Contains(goroutine, "(*sessionSet).adoptFor") && strings.Contains(goroutine, "(*Client).acceptPeers") {
			return true
		}
	}
	return false
}

// dialerStandingDown reports whether a dialer waits for its wake or its reconnect delay with no dial in flight
// a dialer serving its session waits inside connectPeer
func dialerStandingDown() bool {
	stacks := make([]byte, stackDumpSize)
	n := runtime.Stack(stacks, true)
	for goroutine := range strings.SplitSeq(string(stacks[:n]), "\n\n") {
		if strings.Contains(goroutine, " [select") && strings.Contains(goroutine, "(*Client).runPeer") && !strings.Contains(goroutine, "(*Client).connectPeer") {
			return true
		}
	}
	return false
}
