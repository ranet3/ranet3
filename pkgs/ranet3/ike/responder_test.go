// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/logtest"
	"ranet3.com/pkgs/ranet3/transport"
)

type responderHarness struct {
	responder  *Responder
	initiator  *transport.Hub
	remotePort int
	public     ed25519.PublicKey
	private    ed25519.PrivateKey
	sessions   chan *Session
	identities chan Accepted
	// aliases holds the table the responder's Aliases gives the next handshake, none until a test stores some
	aliases *atomic.Pointer[Aliases]
	// lists holds the cap.crypto lists the responder and each session it answers read
	lists *atomic.Pointer[Suites]
}

// newResponderHarness runs a Responder on one hub and hands back everything
// needed to dial it from another, so a handshake in these tests is a real
// exchange over loopback rather than hand-built messages.
// answerBudget is how long a test waits for an answer it expects to arrive. It
// is generous because a loaded machine is not a failing implementation: an
// answer that never comes still fails, just later, while a budget tuned to an
// idle machine turns load into a false red. An assertion that expects silence
// uses a short wait instead, where the only cost of being wrong is a spurious
// pass rather than a spurious failure.
const answerBudget = 30 * time.Second

// quietPeriod is how long a test waits to see that something it expects not to happen does not
// what it watches for would follow the event before it within milliseconds
// and a machine too slow to show it in time lets the test pass rather than fail
const quietPeriod = 300 * time.Millisecond

type trustFunc func(identity.Identity) (ed25519.PublicKey, Family, error)

func (f trustFunc) Key(id identity.Identity) (ed25519.PublicKey, Family, error) { return f(id) }

// errUntrusted is the refusal of a trust that admits nobody a test asks about
var errUntrusted = errors.New("not in the trust")

var trustsNobody = trustFunc(func(identity.Identity) (ed25519.PublicKey, Family, error) { return nil, 0, errUntrusted })

// trustIn admits under key each endpoint families holds, in its family
// key is read on each question, which lets a test store it after the harness that makes it
func trustIn(key *atomic.Pointer[ed25519.PublicKey], families map[identity.Identity]Family) trustFunc {
	return func(id identity.Identity) (ed25519.PublicKey, Family, error) {
		family, ok := families[id]
		if !ok {
			return nil, 0, errUntrusted
		}
		return *key.Load(), family, nil
	}
}

// newResponderHarness answers as testorg/server:1
func newResponderHarness(t *testing.T, trust Trust, events ...Recorder) *responderHarness {
	t.Helper()
	return newResponderHarnessAs(t, []identity.Identity{identity.MustParse("testorg/server:1")}, trust, events...)
}

// newResponderHarnessAs answers as each endpoint in local, all of them in IPv4
// events, where a test passes one, is the responder's Recorder
// a nil trust admits testorg/client:2 in IPv4 and testorg/client:3 in IPv6, under the harness's key
func newResponderHarnessAs(t *testing.T, local []identity.Identity, trust Trust, events ...Recorder) *responderHarness {
	t.Helper()
	families := make(map[identity.Identity]Family, len(local))
	for _, id := range local {
		families[id] = IPv4
	}
	return newResponderHarnessIn(t, families, trust, events...)
}

// newResponderHarnessIn is newResponderHarnessAs with each endpoint in its own family, on a hub listening in both
func newResponderHarnessIn(t *testing.T, local map[identity.Identity]Family, trust Trust, events ...Recorder) *responderHarness {
	t.Helper()
	return newConfiguredResponderHarness(t, local, trust, func(*ResponderConfig) {}, events...)
}

func newConfiguredResponderHarness(t *testing.T, local map[identity.Identity]Family, trust Trust, configure func(*ResponderConfig), events ...Recorder) *responderHarness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responderHub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { responderHub.Close() })
	initiatorHub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { initiatorHub.Close() })

	if trust == nil {
		key := new(atomic.Pointer[ed25519.PublicKey])
		key.Store(&public)
		trust = trustIn(key, map[identity.Identity]Family{
			identity.MustParse("testorg/client:2"): IPv4, identity.MustParse("testorg/client:3"): IPv6,
		})
	}
	aliases := new(atomic.Pointer[Aliases])
	lists := new(atomic.Pointer[Suites])
	lists.Store(&Suites{})
	cfg := ResponderConfig{
		Hub:              responderHub,
		Local:            local,
		LocalPrivateKey:  private,
		Trust:            trust,
		HandshakeTimeout: 10 * time.Second,
		Aliases: func() Aliases {
			if stored := aliases.Load(); stored != nil {
				return *stored
			}
			return Aliases{}
		},
		Suites: func() Suites { return *lists.Load() },
	}
	if len(events) == 1 {
		cfg.Events = events[0]
	}
	configure(&cfg)
	responder, err := NewResponder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := &responderHarness{
		responder:  responder,
		initiator:  initiatorHub,
		remotePort: responderHub.LocalAddr().(*net.UDPAddr).Port,
		public:     public,
		private:    private,
		sessions:   make(chan *Session, 1),
		identities: make(chan Accepted, 1),
		aliases:    aliases,
		lists:      lists,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Serve turns delivery on when its goroutine first runs
	// and the hub drops an unclaimed datagram until then
	// several tests here send one request and wait for its answer without retransmitting
	// and on a loaded machine that goroutine can start after the request has arrived
	// so delivery is on before the harness is returned
	// and Serve's own call gets the same queue
	responderHub.Listen()
	go responder.Serve(ctx, func(s *Session, accepted Accepted) {
		h.sessions <- s
		h.identities <- accepted
	})
	return h
}

func (h *responderHarness) dial(t *testing.T) (*Session, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return InitiateContext(ctx, h.peerConfig())
}

// Initiate is the blocking form, and the one the package documents its whole
// profile on. Only the cmd test binaries call it, so without this no test
// reaches it and it could stop compiling to the same thing.
func TestInitiateIsInitiateContextWithNoDeadline(t *testing.T) {
	h := newResponderHarness(t, nil)
	session, err := Initiate(h.peerConfig())
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer session.Mux().Close()
	responder := <-h.sessions
	defer responder.Mux().Close()
	if accepted := <-h.identities; accepted.Peer != identity.MustParse("testorg/client:2") {
		t.Fatalf("the responder accepted %s", accepted.Peer)
	}
}

// a cancel that lands while the responder handles IKE_AUTH still lets the answer in and deletes the SA it established
// the responder's session ends on that Delete instead of holding the SA until its liveness check expires
// the Delete follows the answer that completes the initial exchanges, and is an exchange that takes its own answer
func TestCanceledInitiatorDeletesTheSAItsResponderEstablished(t *testing.T) {
	ctx, h := canceledHarness(t, func() bool { return true })
	var answered, early, deleteAnswered atomic.Bool
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		switch {
		case header == nil:
		case !fromInitiator && header.ExchangeType == IKE_AUTH:
			answered.Store(true)
		case !fromInitiator && header.ExchangeType == INFORMATIONAL && header.IsResponse():
			deleteAnswered.Store(true)
		case fromInitiator && header.ExchangeType == INFORMATIONAL && !answered.Load():
			early.Store(true)
		}
		return true
	})
	ended := serveResponder(t, h)
	refused := h.initiator.Refused()

	if _, err := InitiateContext(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled handshake returned %v, want the cancel", err)
	}
	select {
	case <-ended:
	case <-time.After(answerBudget):
		t.Fatal("the responder still held the SA its canceled initiator asked for when the budget ran out")
	}
	time.Sleep(quietPeriod)
	if !deleteAnswered.Load() {
		t.Error("the responder's session ended without answering a Delete from its canceled initiator")
	}
	if n := h.initiator.Refused() - refused; n != 0 {
		t.Errorf("%d datagrams reached the initiator's hub after its exchanges ended, which the Delete's answer does when nothing waits for it", n)
	}
	if early.Load() {
		t.Error("the canceled initiator sent its Delete before the IKE_AUTH answer it had time to take")
	}
}

func serveResponder(t *testing.T, h *responderHarness) <-chan struct{} {
	t.Helper()
	ended := make(chan struct{})
	run, stop := context.WithCancel(context.Background())
	go func() {
		defer close(ended)
		select {
		case held := <-h.sessions:
			<-h.identities
			_ = held.Run(run)
		case <-run.Done():
		}
	}()
	t.Cleanup(func() {
		stop()
		<-ended
	})
	return ended
}

// lateAnswer is how long the responder takes over IKE_AUTH after the cancel, past the initiator's wait for it
const lateAnswer = canceledAuthWait + 500*time.Millisecond

// RFC 7296 section 2.3: "The window size is always one until the initial exchanges complete."
// a canceled initiator whose IKE_AUTH goes unanswered for the whole wait therefore sends no request past it, before the late answer or after
func TestCanceledInitiatorSendsNothingPastAnUnansweredIKEAuth(t *testing.T) {
	ctx, h := canceledHarness(t, func() bool {
		time.Sleep(lateAnswer)
		return true
	})
	var past atomic.Int32
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.MessageID > 1 {
			past.Add(1)
		}
		return true
	})

	if _, err := InitiateContext(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled handshake returned %v, want the cancel", err)
	}
	select {
	case held := <-h.sessions:
		defer held.Mux().Close()
		<-h.identities
	case <-time.After(answerBudget):
		t.Fatal("the responder never sent its late answer")
	}
	time.Sleep(quietPeriod)
	if n := past.Load(); n != 0 {
		t.Errorf("the canceled initiator sent %d requests past the IKE_AUTH it never had answered", n)
	}
}

// cancelInAuthTimer cancels a dial this long after its IKE_AUTH request, so the request's first retransmission falls inside the wait
const cancelInAuthTimer = requestTimeout / 2

// RFC 7296 section 2.1: "A retransmission from the initiator MUST be bitwise identical to the original request."
// a cancel keeps the IKE_AUTH exchange for the wait, so with its answer withheld the request goes out again unchanged and nothing past it does
func TestCanceledInitiatorRetransmitsItsIKEAuthUnchanged(t *testing.T) {
	if canceledAuthWait+cancelInAuthTimer <= retransmitDelay(requestTimeout, 1) {
		t.Fatalf("a wait of %s from a cancel %s into IKE_AUTH ends before its first retransmission at %s", canceledAuthWait, cancelInAuthTimer, retransmitDelay(requestTimeout, 1))
	}
	h := newResponderHarness(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var (
		mu     sync.Mutex
		copies [][]byte
		past   int
	)
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, raw []byte) bool {
		if header == nil {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		switch {
		case !fromInitiator:
			return header.ExchangeType != IKE_AUTH
		case header.MessageID > 1:
			past++
		case header.ExchangeType == IKE_AUTH:
			if len(copies) == 0 {
				time.AfterFunc(cancelInAuthTimer, cancel)
			}
			copies = append(copies, bytes.Clone(raw))
		}
		return true
	})

	if _, err := InitiateContext(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled handshake returned %v, want the cancel", err)
	}
	time.Sleep(quietPeriod)
	mu.Lock()
	defer mu.Unlock()
	if len(copies) < 2 {
		t.Fatalf("the canceled initiator sent its IKE_AUTH request %d times inside the wait, want it retransmitted", len(copies))
	}
	for i, again := range copies[1:] {
		if !bytes.Equal(again, copies[0]) {
			t.Errorf("IKE_AUTH copy %d differs from the request it retransmits", i+2)
		}
	}
	if past != 0 {
		t.Errorf("the canceled initiator sent %d requests past the IKE_AUTH it never had answered", past)
	}
}

// a responder that refused IKE_AUTH in an answer that decrypted holds no SA, so its canceled initiator sends it no Delete
func TestCanceledInitiatorSendsNoDeleteToAResponderThatRefusedIt(t *testing.T) {
	ctx, h := canceledHarness(t, func() bool { return false })
	var informational atomic.Int32
	cfg := h.peerConfig()
	cfg.RemotePort = relay(t, h.remotePort, func(fromInitiator bool, header *Header, _ []byte) bool {
		if fromInitiator && header != nil && header.ExchangeType == INFORMATIONAL {
			informational.Add(1)
		}
		return true
	})

	if _, err := InitiateContext(ctx, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("the canceled handshake returned %v, want the cancel", err)
	}
	time.Sleep(quietPeriod)
	if n := informational.Load(); n != 0 {
		t.Errorf("the canceled initiator sent %d INFORMATIONAL requests to a responder that refused it", n)
	}
}

// a canceled initiator whose responder never answers IKE_AUTH gives up after canceledAuthWait instead of its whole retransmission budget
func TestCanceledInitiatorStopsWaitingForAnAnswerThatNeverComes(t *testing.T) {
	release := make(chan struct{})
	ctx, h := canceledHarness(t, func() bool {
		<-release
		return false
	})
	t.Cleanup(func() { close(release) })

	done := make(chan error, 1)
	go func() {
		_, err := InitiateContext(ctx, h.peerConfig())
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the canceled handshake returned %v, want the cancel", err)
		}
	case <-time.After(answerBudget):
		t.Fatal("the canceled initiator still waited for an answer when the budget ran out")
	}
}

// canceledHarness cancels the returned context once testorg/client:2's IKE_AUTH request has arrived and before its answer is sent
// then answer's true admits the initiator under the harness's key and its false refuses it
func canceledHarness(t *testing.T, answer func() bool) (context.Context, *responderHarness) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	var public atomic.Pointer[ed25519.PublicKey]
	h := newResponderHarness(t, trustFunc(func(id identity.Identity) (ed25519.PublicKey, Family, error) {
		if id != identity.MustParse("testorg/client:2") {
			return nil, 0, errUntrusted
		}
		cancel()
		if !answer() {
			return nil, 0, errUntrusted
		}
		return *public.Load(), IPv4, nil
	}))
	public.Store(&h.public)
	return ctx, h
}

// relay carries UDP between an initiator and the responder at responderPort, forwards what pass reports, and returns the port to dial
// pass sees each datagram's IKE header, nil for none, and its message, which it clones to keep
func relay(t *testing.T, responderPort int, pass func(fromInitiator bool, header *Header, raw []byte) bool) int {
	t.Helper()
	conn := listenPeer(t)
	responder := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: responderPort}
	go func() {
		var initiator *net.UDPAddr
		buf := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			fromInitiator := from.Port != responderPort
			to := responder
			if fromInitiator {
				initiator = from
			} else {
				to = initiator
			}
			if to == nil {
				continue
			}
			var header *Header
			if n > 4 {
				header, _ = decodeHeader(buf[4:n])
			}
			if pass(fromInitiator, header, buf[min(n, 4):n]) {
				_, _ = conn.WriteToUDP(buf[:n], to)
			}
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func (h *responderHarness) peerConfig() PeerConfig {
	return PeerConfig{
		Local:           identity.MustParse("testorg/client:2"),
		LocalPrivateKey: h.private,
		Remote:          identity.MustParse("testorg/server:1"),
		RemotePublicKey: h.public,
		RemoteAddr:      net.ParseIP("127.0.0.1"),
		RemotePort:      h.remotePort,
		Hub:             h.initiator,
	}
}

func idBody(text string) []byte {
	body, err := encodeID(identity.MustParse(text))
	if err != nil {
		panic(err)
	}
	return body
}

// Two ranet3 nodes could never reach each other before the responder
// existed, so this is the case the whole feature is for.
func TestResponderCompletesHandshakeWithInitiator(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()

	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("responder produced no session")
	}
	defer responder.Mux().Close()

	accepted := <-h.identities
	if accepted.Peer != identity.MustParse("testorg/client:2") {
		t.Fatalf("authenticated identity = %s", accepted.Peer)
	}
	if accepted.Local != identity.MustParse("testorg/server:1") {
		t.Fatalf("local identity = %s", accepted.Local)
	}
	if !accepted.Key.Equal(h.public) {
		t.Fatalf("the responder reports %x as the key that verified the initiator, want the trust's %x", accepted.Key, h.public)
	}
	// Each side's outbound key must be the other's inbound key, or the first
	// ESP packet decrypts to nothing on a tunnel both ends believe is up.
	if !bytes.Equal(initiator.Child.OutboundKey, responder.Child.InboundKey) {
		t.Error("initiator outbound key does not match responder inbound key")
	}
	if !bytes.Equal(initiator.Child.InboundKey, responder.Child.OutboundKey) {
		t.Error("responder outbound key does not match initiator inbound key")
	}
	if initiator.Child.LocalSPI != responder.Child.RemoteSPI || initiator.Child.RemoteSPI != responder.Child.LocalSPI {
		t.Errorf("child SPIs do not mirror: %08x/%08x against %08x/%08x",
			initiator.Child.LocalSPI, initiator.Child.RemoteSPI, responder.Child.LocalSPI, responder.Child.RemoteSPI)
	}
	if initiator.Child.EncrID != responder.Child.EncrID || initiator.Child.EncrKeyBits != responder.Child.EncrKeyBits {
		t.Error("the two sides selected different child encryption")
	}
	if !responder.current.responder || initiator.current.responder {
		t.Error("session roles do not match the part each side played")
	}
	if responder.current.nextPeerMID != 2 || responder.current.nextLocalMID != 0 {
		t.Errorf("responder message ids = peer %d, local %d; want 2 and 0",
			responder.current.nextPeerMID, responder.current.nextLocalMID)
	}
	// A retransmitted IKE_AUTH has to be answerable from Run onwards.
	if responder.current.lastPeerResponseID != 1 || len(responder.current.lastPeerResponse) == 0 {
		t.Error("responder did not retain its IKE_AUTH response for retransmission")
	}
}

// the initiator refuses an IDr other than the endpoint it dialed, so the responder answers as the one asked for
func TestResponderAnswersAsTheEndpointDialed(t *testing.T) {
	second := identity.MustParse("testorg/server:2")
	h := newResponderHarnessAs(t, []identity.Identity{identity.MustParse("testorg/server:1"), second}, nil)
	cfg := h.peerConfig()
	cfg.Remote = second
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	initiator, err := InitiateContext(ctx, cfg)
	if err != nil {
		t.Fatalf("initiate to %s: %v", second, err)
	}
	defer initiator.Mux().Close()
	responder := <-h.sessions
	defer responder.Mux().Close()
	if accepted := <-h.identities; accepted.Local != second {
		t.Errorf("the responder answered as %s, want %s", accepted.Local, second)
	}
}

func TestResponderRejectsUnknownIdentity(t *testing.T) {
	h := newResponderHarness(t, trustsNobody)
	session, err := h.dial(t)
	if err == nil {
		session.Mux().Close()
		t.Fatal("handshake succeeded against a responder that knows no peers")
	}
	if want := fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED); !strings.Contains(err.Error(), want) {
		t.Errorf("the initiator was refused with %q, want %q", err, want)
	}
	select {
	case <-h.sessions:
		t.Fatal("responder produced a session for an unknown identity")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResponderRejectsWrongKey(t *testing.T) {
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newResponderHarness(t, trustFunc(func(identity.Identity) (ed25519.PublicKey, Family, error) { return other, IPv4, nil }))
	session, err := h.dial(t)
	if err == nil {
		session.Mux().Close()
		t.Fatal("handshake succeeded with an AUTH the responder could not verify")
	}
	if want := fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED); !strings.Contains(err.Error(), want) {
		t.Errorf("the initiator was refused with %q, want %q", err, want)
	}
}

// an IDi naming the responder's own node at another serial is refused with AUTHENTICATION_FAILED before the trust is asked
// the trust here admits anyone under the key both ends hold, as an organization's shared key does for each of its nodes
func TestResponderRefusesItsOwnNode(t *testing.T) {
	var key atomic.Pointer[ed25519.PublicKey]
	h := newResponderHarness(t, trustFunc(func(identity.Identity) (ed25519.PublicKey, Family, error) { return *key.Load(), IPv4, nil }))
	key.Store(&h.public)
	cfg := h.peerConfig()
	cfg.Local = identity.MustParse("testorg/server:2")
	ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
	defer cancel()
	session, err := InitiateContext(ctx, cfg)
	if err == nil {
		session.Mux().Close()
		t.Fatal("the responder admitted a peer claiming its own node")
	}
	if want := fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED); !strings.Contains(err.Error(), want) {
		t.Fatalf("the initiator was refused with %q, want %q", err, want)
	}
	select {
	case <-h.sessions:
		t.Fatal("the responder produced a session for a peer claiming its own node")
	case <-time.After(quietPeriod):
	}
}

// The initiator's side of the same check, through InitiateContext against a
// real responder. A responder that signs with a key other than the one
// configured for it fails on the signature. One asked under a name it does not
// hold refuses to answer under it, and the initiator reports that refusal.
// The first responder established its SA, and RFC 7296 section 2.21.2 has it told: "If the error occurs on the initiator, the notification MAY be returned in a separate INFORMATIONAL exchange, usually with no other payloads."
// its session answers the AUTHENTICATION_FAILED that follows IKE_AUTH and ends
func TestInitiatorRefusesResponderItCannotAuthenticate(t *testing.T) {
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		change func(*PeerConfig)
		want   string
		told   bool // the responder established an SA, which its session ends on the initiator's refusal
	}{
		"a public key the responder does not sign with": {
			func(cfg *PeerConfig) { cfg.RemotePublicKey = other }, "AUTH signature verification failed", true},
		"a common name the responder does not hold": {
			func(cfg *PeerConfig) { cfg.Remote = identity.MustParse("testorg/elsewhere:1") }, fmt.Sprintf("notify type %d", N_AUTHENTICATION_FAILED), false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newResponderHarness(t, nil)
			ended := serveResponder(t, h)
			cfg := h.peerConfig()
			test.change(&cfg)
			ctx, cancel := context.WithTimeout(context.Background(), answerBudget)
			defer cancel()
			session, err := InitiateContext(ctx, cfg)
			if err == nil {
				session.Mux().Close()
				t.Fatal("the initiator completed a handshake it should have refused")
			}
			if !strings.Contains(err.Error(), test.want) || strings.Contains(err.Error(), "additionally failed") {
				t.Fatalf("the initiator refused with %q, which does not name %q alone", err, test.want)
			}
			if !test.told {
				return
			}
			select {
			case <-ended:
			case <-time.After(answerBudget):
				t.Fatal("the responder still held the SA its initiator refused when the budget ran out")
			}
		})
	}
}

func TestSelectIKEProposalPrefersOurOrderAndReportsGroup(t *testing.T) {
	offer := func(transforms ...Transform) []byte {
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: transforms}})
	}
	t.Run("prefers the stronger cipher we offer, not the peer's order", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		_, suite, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false)
		if err != nil {
			t.Fatal(err)
		}
		if suite.EncrKeyBits != 256 || suite.PRFID != PRF_HMAC_SHA2_384 {
			t.Fatalf("selected %d-bit encryption with prf %d", suite.EncrKeyBits, suite.PRFID)
		}
	})
	t.Run("reports the group when only the KE payload is wrong", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_ECP_256},
		)
		_, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false)
		var wrongGroup *invalidKEError
		if !errors.As(err, &wrongGroup) || wrongGroup.group != DH_ECP_256 {
			t.Fatalf("err = %v, want a request for group %d", err, DH_ECP_256)
		}
	})
	t.Run("rejects a proposal carrying a transform type we cannot name", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_CURVE25519},
			Transform{Type: TransformType(15), ID: 1},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false); err == nil {
			t.Fatal("an unknown transform type was accepted")
		}
	})
	// an AEAD cipher needs no integrity algorithm
	// and strongSwan and libreswan both write out the NONE omitting it says
	t.Run("takes an offer that spells out INTEG NONE and echoes it", func(t *testing.T) {
		integ := Transform{Type: TransInteg, ID: INTEG_NONE}
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			integ,
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		selected, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false)
		if err != nil {
			t.Fatalf("an offer naming INTEG NONE was refused: %v", err)
		}
		// RFC 7296 section 2.7: "The accepted cryptographic suite MUST contain exactly one transform of each type included in the proposal."
		if !slices.Contains(selected.Transforms, integ) {
			t.Errorf("the answer is %v, which drops a transform type the offer included", selected.Transforms)
		}
	})
	t.Run("rejects an integrity transform it cannot use", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransInteg, ID: 12},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false); err == nil {
			t.Fatal("an integrity transform this implementation has no key for was accepted")
		}
	})
	t.Run("rejects an offer with no cipher in common", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: 12, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519, Suites{}, false); err == nil {
			t.Fatal("an offer with no shared cipher was accepted")
		}
	})
}

// The control loop used to poll its own request queue ten times a second. With
// the poll gone, a local exchange has to be picked up because the loop selects
// on the queue, not because a timer happened to fire. If that regressed, this
// would wait out the DPD interval instead.
func TestLocalRequestIsPickedUpWithoutPolling(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	ctx := t.Context()
	go initiator.Run(ctx)
	go responder.Run(ctx)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := initiator.request(INFORMATIONAL, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("informational exchange: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("local request was not picked up within 2s, dpd interval is %s", defaultDPDInterval)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("local request took %s", elapsed)
	}
}

// A responder under cookie pressure is useless if the initiator cannot answer
// the challenge, and a mesh of these nodes then partitions: every dial gets
// N(COOKIE) on all its retransmissions and fails. RFC 7296 section 2.6 requires the
// initiator to retry with the cookie as its first payload.
func TestInitiatorAnswersCookieChallenge(t *testing.T) {
	h := newResponderHarness(t, nil)
	// Above the threshold every IKE_SA_INIT is challenged, which is the
	// condition an unauthenticated flood produces.
	h.responder.mu.Lock()
	h.responder.halfOpen = cookieThreshold
	h.responder.mu.Unlock()

	session, err := h.dial(t)
	if err != nil {
		t.Fatalf("a dial into a responder issuing cookies failed: %v", err)
	}
	t.Cleanup(func() { session.Mux().Close() })
	select {
	case accepted := <-h.identities:
		if accepted.Peer != identity.MustParse("testorg/client:2") {
			t.Fatalf("the responder accepted %s", accepted.Peer)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the responder never reported the accepted session")
	}
}

// The retransmission path must not answer a datagram that merely names a live
// SPIi. Anyone who has opened an SA of their own knows one, so answering a
// bare header would turn a 28 byte datagram with a forged source address into
// the full IKE_SA_INIT response delivered wherever it pointed.
func TestResponderDoesNotReflectOnSPIAlone(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	request, spiI := buildTestSAInit(t)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	first, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("the responder did not answer a valid IKE_SA_INIT: %v", err)
	}
	// The session is now parked in awaitAuthRequest, which is the only place
	// the retransmission answer is reachable from.

	bare := (&Message{Header: Header{
		SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0,
	}}).Encode()
	if len(bare) >= len(request) {
		t.Fatalf("the probe is %d bytes against a %d byte request, so it would not amplify", len(bare), len(request))
	}
	if err := mux.SendIKE(bare); err != nil {
		t.Fatal(err)
	}
	if reply, err := mux.RecvIKEUntil(time.Now().Add(time.Second)); err == nil {
		t.Fatalf("a %d byte header drew a %d byte response, which is an amplifier", len(bare), len(reply))
	}

	// A real retransmission is still answered, or a lost response would strand
	// every handshake that hits one.
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	again, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("an identical retransmission was not answered: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Error("the retransmission drew a different response than the original")
	}
}

// The slot has to come before the key exchange rather than after it, for the
// reason enterHalfOpen's call site gives.
//
// The observable is the last stateless answer before the key exchange: an
// offer this responder cannot accept draws NO_PROPOSAL_CHOSEN, so receiving
// one proves execution reached selectIKEProposal. With every slot taken that
// answer must not come, because the refusal happens first.
func TestResponderTakesSlotBeforeKeyExchange(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// AES-GCM with a 192 bit key is a transform this responder never offers,
	// so the proposal parses and is then refused.
	unacceptable := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	// drain clears anything an earlier attempt left in the queue, so a late
	// reply is never read as the answer to the next request.
	drain := func() {
		for {
			if _, err := mux.RecvIKEUntil(time.Now()); err != nil {
				return
			}
		}
	}
	// offer sends the request and answers a cookie challenge if one comes,
	// which it does above cookieThreshold and may do at any time, so whether
	// the responder demanded return routability is outside this test. It
	// retries, because these are datagrams on a loopback socket shared with
	// every other test in this package and one of them can be dropped.
	offer := func(wait time.Duration, attempts int) (Notify, bool) {
		t.Helper()
		send := func(ahead []RawPayload) ([]byte, bool) {
			if err := mux.SendIKE(encodeTestSAInit(t, spiI, ni, unacceptable, ahead)); err != nil {
				t.Fatal(err)
			}
			reply, err := mux.RecvIKEUntil(time.Now().Add(wait))
			return reply, err == nil
		}
		for range attempts {
			drain()
			reply, ok := send(nil)
			if !ok {
				continue
			}
			answer := firstTestNotify(t, reply)
			if answer.Type != N_COOKIE {
				return answer, true
			}
			cookie := []RawPayload{{Type: PayloadN, Body: EncodeNotify(answer)}}
			if reply, ok := send(cookie); ok {
				return firstTestNotify(t, reply), true
			}
		}
		return Notify{}, false
	}

	// With the slots free the responder does answer, which gives the silence
	// below its meaning.
	answer, answered := offer(answerBudget, 4)
	if !answered {
		t.Fatal("an unacceptable offer drew no answer at all")
	}
	if answer.Type != N_NO_PROPOSAL_CHOSEN {
		t.Fatalf("an unacceptable offer drew notify %d, want NO_PROPOSAL_CHOSEN", answer.Type)
	}
	// The answer goes out before the handshake that sent it gives its slot
	// back, and the fill below would take the last slot from under it. It
	// waits for the release instead.
	for deadline := time.Now().Add(answerBudget); ; time.Sleep(time.Millisecond) {
		h.responder.mu.Lock()
		held := h.responder.halfOpen
		h.responder.mu.Unlock()
		if held == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the responder still holds %d half-open slots after answering", held)
		}
	}

	// Filled from enough distinct addresses that the global cap runs out
	// rather than any one source's share.
	for i := range halfOpenLimit {
		if !h.responder.enterHalfOpen(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i/halfOpenPerSource))) {
			t.Fatal("the responder refused a slot below its own limit")
		}
	}

	if answer, answered := offer(2*time.Second, 2); answered {
		t.Fatalf("with every half-open slot taken the responder still answered notify %d, so it parsed the offer before it checked whether it had room for one",
			answer.Type)
	}
}

// statelessAnswer sends one request and returns the answer, retrying the send
// these are datagrams on a loopback socket shared with every other test in the package
// and one of them can be dropped
// the answers reached this way are stateless or retransmission-safe
// so a repeat draws another
// without the retry a loaded machine turns them into false reds
// and the VM arm of the flake check has done that twice
func statelessAnswer(t testing.TB, mux *transport.Mux, request []byte, why string) []byte {
	t.Helper()
	for range 4 {
		if err := mux.SendIKE(request); err != nil {
			t.Fatal(err)
		}
		if reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget)); err == nil {
			return reply
		}
	}
	t.Fatalf("%s after four attempts", why)
	return nil
}

// firstTestNotify reads the single notify out of a stateless answer
func firstTestNotify(t testing.TB, raw []byte) Notify {
	t.Helper()
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	payload := message.find(PayloadN)
	if payload == nil {
		t.Fatal("the response carried no notify")
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatalf("decode the notify: %v", err)
	}
	return notify
}

// RFC 7296 section 2.5: "If the critical flag is set and the payload type is unrecognized, the message MUST be rejected and the response to the IKE request containing that payload MUST include a Notify payload UNSUPPORTED_CRITICAL_PAYLOAD, indicating an unsupported critical payload was included. In that Notify payload, the Notification Data contains the one-octet payload type."
// The answer is stateless and costs nothing, which is the only reason it can
// be given before anything about the peer is known.
func TestResponderRefusesCriticalPayloadItDoesNotImplement(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// SKF, which RFC 7383 defines and this end does not implement, and nothing
	// else about the request is wrong.
	critical := []RawPayload{{Type: 53, Critical: true, Body: []byte{0}}}
	reply := statelessAnswer(t, mux, encodeTestSAInit(t, spiI, ni, ikeProposal(), critical),
		"a critical payload we do not implement drew no answer")
	notify := firstTestNotify(t, reply)
	if notify.Type != N_UNSUPPORTED_CRITICAL_PAYLOAD {
		t.Fatalf("the responder answered notify %d, want UNSUPPORTED_CRITICAL_PAYLOAD", notify.Type)
	}
	if len(notify.Data) != 1 || notify.Data[0] != 53 {
		t.Errorf("the notify named %v, want the payload type that was refused", notify.Data)
	}
	select {
	case sess := <-h.sessions:
		sess.Mux().Close()
		t.Error("the responder carried the exchange forward anyway")
	default:
	}
}

// Our AUTH signs the IDr we send. Answering under a name we do not own would
// hand the initiator a signature over an identity of its choosing, made with
// this node's key, which is the whole of what authentication here rests on.
func TestResponderRefusesIdentityItDoesNotAnswerTo(t *testing.T) {
	h := newResponderHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Everything is as the working dial except the name asked for, which this
	// responder is not configured with.
	session, err := InitiateContext(ctx, PeerConfig{
		Local:           identity.MustParse("testorg/client:2"),
		LocalPrivateKey: h.private,
		Remote:          identity.MustParse("testorg/someone-else:1"),
		RemotePublicKey: h.public,
		RemoteAddr:      net.ParseIP("127.0.0.1"),
		RemotePort:      h.remotePort,
		Hub:             h.initiator,
	})
	if err == nil {
		session.Mux().Close()
		t.Fatal("the responder authenticated under a name it does not answer to")
	}
	select {
	case sess := <-h.sessions:
		sess.Mux().Close()
		t.Error("the responder produced a session for an identity it does not own")
	case <-time.After(time.Second):
	}
}

// buildTestSAInit produces a well-formed IKE_SA_INIT request, the shape
// the responder needs before it will park in awaitAuthRequest.
func buildTestSAInit(t *testing.T) ([]byte, uint64) {
	t.Helper()
	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	return encodeTestSAInit(t, spiI, ni, ikeProposal(), nil), spiI
}

// encodeTestSAInit is buildTestSAInit with the parts a test may want to vary
// they are the SPI and nonce a cookie is bound to, the proposal offered and the payloads ahead of the rest
// ahead holds an echoed cookie, which RFC 7296 section 2.6 includes "as the first payload"
func encodeTestSAInit(t testing.TB, spiI uint64, ni []byte, proposal Proposal, ahead []RawPayload) []byte {
	t.Helper()
	return encodeTestSAInitOffer(t, spiI, ni, []Proposal{proposal}, ahead)
}

func encodeTestSAInitOffer(t testing.TB, spiI uint64, ni []byte, offer []Proposal, ahead []RawPayload) []byte {
	t.Helper()
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	hashAlgos := make([]byte, 2)
	binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
	payloads := slices.Concat(ahead, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA(offer)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: natDetectionHash(spiI, 0, net.IPv4(10, 0, 0, 1), 0)})},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: natDetectionHash(spiI, 0, net.ParseIP("127.0.0.1"), 0)})},
	})
	header := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
	return (&Message{Header: header, Payloads: payloads}).Encode()
}

// A session that is resolved away the moment it is established is closed
// before anything ever serves it, so its Run loop never starts. Routing the
// Delete through that loop's request queue sends nothing at all, and the peer
// is left holding an SA it keeps transmitting into until its own dead peer
// detection expires.
func TestDeleteIKEReachesPeerWithoutRunLoop(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	// Deliberately no Run on either side, which is the state adopt closes a
	// session in. DeleteIKE has to notice that and send directly, because
	// routing the Delete through the run loop's request queue blocks forever, so
	// the deadline is its own goroutine rather than an elapsed-time check that
	// is only reached if the call returns at all.
	deleted := make(chan error, 1)
	go func() { deleted <- initiator.DeleteIKE() }()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("DeleteIKE: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DeleteIKE never returned, so it is waiting on a run loop that does not exist")
	}

	raw, err := responder.Mux().RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("the peer never received the Delete: %v", err)
	}
	header, err := decodeHeader(raw)
	if err != nil {
		t.Fatalf("decode what arrived: %v", err)
	}
	if header.ExchangeType != INFORMATIONAL {
		t.Errorf("the peer received exchange type %d, want INFORMATIONAL", header.ExchangeType)
	}
}

// A link that carries nothing but babel hellos and DPD has no ESP to refresh
// the liveness clock, so an answered exchange has to count as proof on its
// own. Without it Active()'s window silently becomes a function of
// babel.hello_interval, which nothing validates against it.
func TestAnsweredExchangeRefreshesLivenessClock(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	ctx := t.Context()
	go func() { _ = initiator.Run(ctx) }()
	go func() { _ = responder.Run(ctx) }()

	// Run refreshes the clock once when it starts, so wait for that to settle
	// before taking the baseline. Nothing else touches it here: no ESP flows,
	// and the exchange below is the only thing on the wire.
	deadline := time.Now().Add(10 * time.Second)
	var before int64
	for stable := 0; stable < 20; {
		if time.Now().After(deadline) {
			t.Fatal("the responder's liveness clock never settled")
		}
		time.Sleep(5 * time.Millisecond)
		if now := responder.lastActive.Load(); now != before || !responder.serving.Load() {
			before, stable = now, 0
			continue
		}
		stable++
	}
	if before == 0 {
		t.Fatal("the responder's control loop never started")
	}

	if _, err := initiator.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("liveness exchange: %v", err)
	}
	answered := time.Now().Add(5 * time.Second)
	for responder.lastActive.Load() <= before {
		if time.Now().After(answered) {
			t.Fatal("an answered exchange left the responder's liveness clock untouched")
		}
	}
	if !responder.Active() {
		t.Error("the responder reads as dead after answering")
	}
}

func listenHub(t *testing.T) *transport.Hub {
	t.Helper()
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	return hub
}

// observedEndpoint returns the endpoint a hub reports for a datagram from one
// UDP socket. transport.Endpoint cannot be implemented outside its package, so
// a test that needs two distinct peer addresses has to observe two.
func observedEndpoint(t *testing.T, hub *transport.Hub, spi uint64) transport.Endpoint {
	return observedEndpointFrom(t, hub, spi, net.IPv4(127, 0, 0, 1))
}

// observedEndpointFrom is the same with the peer's own source address chosen,
// so a test can put two addresses rather than two ports through a record keyed
// on the address. Both loopback addresses exist on both platforms, while
// 127.0.0.2 is assigned on linux and not on darwin.
func observedEndpointFrom(t *testing.T, hub *transport.Hub, spi uint64, source net.IP) transport.Endpoint {
	t.Helper()
	endpoint, _ := observedPeerFrom(t, hub, spi, source)
	return endpoint
}

// observedPeerFrom is observedEndpointFrom with the socket behind the endpoint, which reads what the hub sends there
func observedPeerFrom(t *testing.T, hub *transport.Hub, spi uint64, source net.IP) (transport.Endpoint, *net.UDPConn) {
	t.Helper()
	mux, err := hub.NewMux(source, 4500)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: source})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request[:8], spi)
	dst := &net.UDPAddr{IP: source, Port: hub.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	_, endpoint, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	return endpoint, peer
}

// Under pressure a request without a currently valid cookie must be answered
// with one and dropped. RFC 7296 section 2.6 asks for exactly that: without
// it an off-path source can make the responder allocate for an address it
// never has to receive at.
func TestResponderDemandsCookieUnderPressure(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	endpoint := observedEndpoint(t, hub, 0x1111)

	r := &Responder{halfOpen: cookieThreshold}
	r.cfg.Hub = hub
	required, err := r.cookieRequired(&Message{}, bytes.Repeat([]byte{7}, 32), 1, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("a request under pressure was carried forward with no cookie at all")
	}

	// Below the threshold it does nothing at all, keeping the
	// ordinary case a two-message exchange.
	quiet := &Responder{}
	quiet.cfg.Hub = hub
	required, err = quiet.cookieRequired(&Message{}, bytes.Repeat([]byte{7}, 32), 1, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Error("an idle responder demanded a cookie, which costs every handshake a round trip")
	}
}

func TestResponderRefusesCookieItDidNotIssue(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	endpoint, peer := observedPeerFrom(t, hub, 0x2222, net.IPv4(127, 0, 0, 1))
	elsewhere := observedEndpoint(t, hub, 0x3333)

	r := &Responder{halfOpen: cookieThreshold}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	r.cookieRotated = time.Now()
	nonce := bytes.Repeat([]byte{7}, 32)
	valid := cookieValue(r.cookieSecret, r.cookieVersion, nonce, 1, endpoint)
	// RFC 7296 section 2.6: "The data associated with this notification MUST be between 1 and 64 octets in length (inclusive), and its generation is described later in this section."
	if len(valid) < 1 || len(valid) > 64 {
		t.Fatalf("the responder issues a cookie of %d octets", len(valid))
	}

	withCookie := func(data []byte) *Message {
		return &Message{Payloads: []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: data})},
		}}
	}
	accepted := func(t *testing.T, request *Message, ni []byte, spi uint64, ep transport.Endpoint) bool {
		t.Helper()
		required, err := r.cookieRequired(request, ni, spi, ep)
		if err != nil {
			t.Fatal(err)
		}
		return !required
	}

	if !accepted(t, withCookie(valid), nonce, 1, endpoint) {
		t.Fatal("the responder refused a cookie it had just issued")
	}
	// RFC 7296 section 2.6: "When one party receives an IKE_SA_INIT request containing a cookie whose contents do not match the value expected, that party MUST ignore the cookie and process the message as if no cookie had been included"
	// under pressure that is an answer with the cookie a request without one draws
	buf := make([]byte, 2048)
	for name, forged := range map[string][]byte{
		"empty":            {},
		"version only":     valid[:1],
		"wrong version":    append([]byte{valid[0] + 1}, valid[1:]...),
		"flipped last bit": append(append([]byte{}, valid[:len(valid)-1]...), valid[len(valid)-1]^1),
		"right length":     bytes.Repeat([]byte{0}, len(valid)),
	} {
		t.Run(name, func(t *testing.T) {
			if accepted(t, withCookie(forged), nonce, 1, endpoint) {
				t.Error("the responder took a cookie it never issued, which is worse than issuing none")
			}
			_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
			n, _, err := peer.ReadFromUDP(buf)
			if err != nil || n <= 4 {
				t.Fatalf("the cookie it never issued drew no answer: %d bytes, %v", n, err)
			}
			if notify := firstTestNotify(t, buf[4:n]); notify.Type != N_COOKIE || !bytes.Equal(notify.Data, valid) {
				t.Errorf("the cookie it never issued drew notify %d carrying %x, want the cookie a request without one draws, %x", notify.Type, notify.Data, valid)
			}
		})
	}
	// an idle responder ignores it the same way, and goes on with the request
	quiet := &Responder{}
	quiet.cfg.Hub = hub
	if required, err := quiet.cookieRequired(withCookie(valid[:1]), nonce, 1, endpoint); err != nil || required {
		t.Errorf("an idle responder held back a request carrying a cookie it never issued (%v)", err)
	}

	// Bound to the attempt, so a cookie is useless for another nonce, another
	// SPI, or another address: that binding stops an off-path source
	// collecting one and spending it on addresses it cannot receive at.
	for name, replay := range map[string]func() bool{
		"another nonce":   func() bool { return accepted(t, withCookie(valid), bytes.Repeat([]byte{8}, 32), 1, endpoint) },
		"another SPI":     func() bool { return accepted(t, withCookie(valid), nonce, 2, endpoint) },
		"another address": func() bool { return accepted(t, withCookie(valid), nonce, 1, elsewhere) },
	} {
		t.Run(name, func(t *testing.T) {
			if replay() {
				t.Error("a cookie issued for one attempt was accepted for another")
			}
		})
	}
}

// RFC 7296 section 2.6.1: "Implementations SHOULD support this shorter exchange, but MUST NOT fail if other implementations do not support this shorter exchange."
// section 2.6.1 on a responder that does not: "For instance, if the responder includes the KEi payloads in cookie calculation, it will reject the request by sending a new cookie."
// under pressure the cookie a request draws is taken back in the request repeated and in the retry an INVALID_KE_PAYLOAD asks for, whose KE payload is in another group
func TestResponderTakesItsCookieInTheRetryWithAnotherGroup(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	endpoint, peer := observedPeerFrom(t, hub, 0x4444, net.IPv4(127, 0, 0, 1))

	r := &Responder{halfOpen: cookieThreshold}
	r.cfg.Hub = hub
	nonce := bytes.Repeat([]byte{7}, 32)
	groups := []uint16{DH_ECP_256, DH_CURVE25519}
	ke := map[uint16][]byte{}
	for _, group := range groups {
		dh, err := GenerateDH(group)
		if err != nil {
			t.Fatal(err)
		}
		ke[group] = EncodeKE(group, dh.PublicBytes())
	}
	request := func(ahead []RawPayload, group uint16) *Message {
		return &Message{
			Header: Header{SPIInitiator: 1, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator},
			Payloads: slices.Concat(ahead, []RawPayload{
				{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
				{Type: PayloadKE, Body: ke[group]},
				{Type: PayloadNonce, Body: EncodeNonce(nonce)},
			}),
		}
	}
	required, err := r.cookieRequired(request(nil, groups[0]), nonce, 1, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("a request under pressure was carried forward with no cookie at all")
	}
	buf := make([]byte, 2048)
	_ = peer.SetReadDeadline(time.Now().Add(answerBudget))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || n <= 4 {
		t.Fatalf("the request without a cookie drew no answer: %d bytes, %v", n, err)
	}
	cookie := firstTestNotify(t, buf[4:n])
	if cookie.Type != N_COOKIE {
		t.Fatalf("the request without a cookie drew notify %d, want COOKIE", cookie.Type)
	}
	echoed := []RawPayload{{Type: PayloadN, Body: EncodeNotify(cookie)}}
	for _, group := range groups {
		required, err := r.cookieRequired(request(echoed, group), nonce, 1, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		if required {
			t.Errorf("the cookie drew a new one in a request with its KE payload in group %d", group)
		}
	}
}

// RFC 7296 section 2.6: "Each endpoint chooses one of the two SPIs and MUST choose them so as to be unique identifiers of an IKE SA."
// two IKE_SA_INIT exchanges at one responder are answered with two nonzero responder SPIs that differ
func TestResponderGivesEachIKESAItsOwnSPI(t *testing.T) {
	h := newResponderHarness(t, nil)
	var spis []uint64
	for range 2 {
		request, spiI := buildTestSAInit(t)
		mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mux.Close() })
		if err := mux.RegisterIKE(spiI); err != nil {
			t.Fatal(err)
		}
		header, err := decodeHeader(statelessAnswer(t, mux, request, "an IKE_SA_INIT drew no answer"))
		if err != nil {
			t.Fatal(err)
		}
		spis = append(spis, header.SPIResponder)
	}
	if spis[0] == 0 || spis[1] == 0 || spis[0] == spis[1] {
		t.Errorf("the responder answered two IKE SAs with SPIs %016x and %016x", spis[0], spis[1])
	}
}

// halfOpenLimit caps what a flood can allocate even with valid cookies, which
// is the second half of RFC 7296 section 2.6: the cookie makes the source
// prove an address, the cap bounds what one proven address can hold.
func TestResponderCapsHalfOpenExchanges(t *testing.T) {
	r := &Responder{}
	source := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i/halfOpenPerSource)) }
	for i := range halfOpenLimit {
		if !r.enterHalfOpen(source(i)) {
			t.Fatalf("the responder refused half-open exchange %d, below its own limit", i)
		}
	}
	if r.enterHalfOpen(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("the responder allocated past its half-open limit, so a flood is bounded by nothing")
	}
	r.leaveHalfOpen(source(0))
	if !r.enterHalfOpen(source(0)) {
		t.Error("a completed exchange did not free its slot")
	}
}

// The cap is also per address, or it is first come from one: an initiator that
// sends IKE_SA_INIT and never IKE_AUTH holds a slot for the whole handshake
// timeout, so one address parks all of them and every legitimate peer is then
// refused after answering its cookie correctly.
func TestOneAddressCannotHoldEveryHalfOpenSlot(t *testing.T) {
	r := &Responder{}
	flood := netip.MustParseAddr("198.51.100.1")
	for i := range halfOpenPerSource {
		if !r.enterHalfOpen(flood) {
			t.Fatalf("one address was refused its %dth exchange, below its own share", i)
		}
	}
	if r.enterHalfOpen(flood) {
		t.Error("one address took more than its share, so it can park every slot")
	}
	if !r.enterHalfOpen(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("a peer at another address was refused while the node was nowhere near its limit")
	}
	// And the share is given back, or an address that once flooded is locked
	// out for the life of the process.
	for range halfOpenPerSource {
		r.leaveHalfOpen(flood)
	}
	if !r.enterHalfOpen(flood) {
		t.Error("an address that finished its exchanges never got its share back")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.halfOpenBySource) != 2 {
		t.Errorf("the responder is tracking %d addresses, want only the two still holding slots", len(r.halfOpenBySource))
	}
}

// RFC 7296 section 3.3.5 forbids the Key Length attribute on a fixed-key
// transform, and section 3.3.6 requires a selected transform to come back with
// the attributes it was offered with. ChaCha20-Poly1305 is offered without
// one, so the answer must carry none either. Getting this wrong is a silent
// interop break: charon and this fork's own initiator both reject the result,
// and AES-GCM being first in the proposal is why no handshake ever shows it.
func TestChaChaChildResponseEchoesNoKeyLength(t *testing.T) {
	child := responderChild{
		number:     1,
		encryption: Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256},
	}
	proposal := child.proposal(binary.BigEndian.AppendUint32(nil, 0x11223344))
	for _, transform := range proposal.Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 0 {
			t.Errorf("the IKE_AUTH response offered ChaCha20-Poly1305 with Key Length %d, which RFC 7296 section 3.3.5 forbids",
				transform.KeyLengthBits)
		}
	}

	// An attributed cipher keeps its key length, or the answer would be
	// proposing something different from what was selected.
	child.encryption = Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}
	proposal = child.proposal(binary.BigEndian.AppendUint32(nil, 0x11223344))
	for _, transform := range proposal.Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 128 {
			t.Errorf("AES-GCM came back with Key Length %d, want 128", transform.KeyLengthBits)
		}
	}
}

// A session that has just been established has to read as live before it has
// carried anything. A peer that reboots leaves an SA here that looks
// established for a full dead-peer-detection window, and the rule that sorts
// that out asks whether a session has recently proved the peer is there. A
// handshake that just completed is exactly that proof. Without it a fresh
// session reads as dead, the path is reported unheld, and the dialer opens
// another SA over a perfectly good one on every reconnect delay.
func TestFreshlyEstablishedSessionReadsAsLive(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	if !initiator.Active() {
		t.Error("the dialer's own session reads as dead the moment it is established")
	}
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	if !responder.Active() {
		t.Error("the answering side of the same handshake reads as dead")
	}
}

// Dead peer detection asks a peer that has gone quiet whether it is still
// there. A peer sending continuously is not quiet, and ESP is the only thing
// that says so on a link carrying nothing but data: without the loop consuming
// that edge, a busy session is probed every ten seconds forever, and each
// probe is a round trip the peer has to answer while it is already saturating
// the link.
func TestTrafficPostponesDeadPeerDetection(t *testing.T) {
	probed := func(t *testing.T, traffic bool) bool {
		t.Helper()
		h := newResponderHarness(t, nil)
		initiator, err := h.dial(t)
		if err != nil {
			t.Fatalf("initiate: %v", err)
		}
		t.Cleanup(func() { initiator.Mux().Close() })
		var peer *Session
		select {
		case peer = <-h.sessions:
		case <-time.After(10 * time.Second):
			t.Fatal("the responder produced no session")
		}
		t.Cleanup(func() { peer.Mux().Close() })

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = initiator.Run(ctx) }()
		if traffic {
			go func() {
				for ctx.Err() == nil {
					initiator.NoteTraffic()
					time.Sleep(200 * time.Millisecond)
				}
			}()
		}
		// Nothing runs the responder's own loop, so whatever arrives here is
		// what the initiator sent unprompted.
		_, err = peer.Mux().RecvIKEUntil(time.Now().Add(defaultDPDInterval + 3*time.Second))
		return err == nil
	}
	// The quiet session is the positive control: without it, a busy session
	// that is never probed proves nothing about why.
	t.Run("a quiet session", func(t *testing.T) {
		t.Parallel()
		if !probed(t, false) {
			t.Error("a session that carried nothing was never probed, so dead peer detection is not running at all")
		}
	})
	t.Run("a session carrying traffic", func(t *testing.T) {
		t.Parallel()
		if probed(t, true) {
			t.Error("a session carrying traffic was probed anyway, so the traffic edge reaches nothing")
		}
	})
}

// The share is per address, not per flow. Keyed by the whole endpoint it
// bounds one UDP flow instead, and a second source port from the same address
// takes another sixteen slots, which is the partition the share exists to
// prevent: sixteen ports from one address hold all 256.
func TestHalfOpenShareIsPerAddressNotPerFlow(t *testing.T) {
	h := newResponderHarness(t, nil)
	loopback := netip.MustParseAddr("127.0.0.1")
	// Everything one address is allowed, spent before either dial.
	for range halfOpenPerSource {
		if !h.responder.enterHalfOpen(loopback) {
			t.Fatal("the responder refused a slot below one address's share")
		}
	}

	dial := func(hub *transport.Hub) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cfg := h.peerConfig()
		cfg.Hub = hub
		session, err := InitiateContext(ctx, cfg)
		if err == nil {
			session.Mux().Close()
		}
		return err
	}
	if err := dial(h.initiator); err == nil {
		t.Error("a dial from an address that had spent its share was answered")
	}
	// A second hub on the same machine is the same address and a different
	// source port, which is all an attacker has to vary.
	other, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := dial(other); err == nil {
		t.Error("a second source port from the same address took another share, so sixteen ports hold every slot")
	}
	h.responder.mu.Lock()
	defer h.responder.mu.Unlock()
	if got := len(h.responder.halfOpenBySource); got != 1 {
		t.Errorf("the responder is tracking %d sources for one address", got)
	}
}

// An initiator that does not advertise the Ed25519 Identity hash is offering
// an authentication method this responder cannot use, which RFC 7296 section
// 3.10.1 calls NO_PROPOSAL_CHOSEN: "any case where the offered proposals
// (including but not limited to SA payload values, USE_TRANSPORT_MODE notify,
// IPCOMP_SUPPORTED notify) are not acceptable for the responder".
// AUTHENTICATION_FAILED is defined there as
// the answer to an IKE_AUTH message, and this exchange has not reached one.
func TestResponderRefusesOfferItCannotAuthenticate(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// Everything a working IKE_SA_INIT carries except the signature hash
	// notify, which declares that this initiator can verify an Ed25519 AUTH.
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	request := (&Message{
		Header: Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator},
		Payloads: []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
		},
	}).Encode()
	reply := statelessAnswer(t, mux, request, "an offer this responder cannot authenticate drew no answer")
	if got := firstTestNotify(t, reply).Type; got != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("the responder answered notify %d, want NO_PROPOSAL_CHOSEN", got)
	}
}

// A spoofer must not be able to spend a named peer's share while the node is
// idle. With the cookie demanded on the global count alone, an off-path source
// forging a victim's address takes the victim's whole share below the
// threshold, at sixteen packets every thirty seconds, and the victim is then
// refused in silence for as long as the attacker keeps it up.
func TestOneAddressCannotSpendItsShareWithoutCookie(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	r := &Responder{}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	r.cookieRotated = time.Now()

	victim := observedEndpoint(t, hub, randUint64Nonzero())
	source := victim.AddrPort().Addr()
	nonce := bytes.Repeat([]byte{7}, 32)
	empty := &Message{}
	// The node is idle, so the global threshold is nowhere near.
	for i := range halfOpenPerSourceWithoutCookie {
		required, err := r.cookieRequired(empty, nonce, uint64(i+1), victim)
		if err != nil {
			t.Fatal(err)
		}
		if required {
			t.Fatalf("an idle responder demanded a cookie for slot %d, which costs every handshake a round trip", i)
		}
		if !r.enterHalfOpen(source) {
			t.Fatal("the responder refused a slot below one address's share")
		}
	}
	required, err := r.cookieRequired(empty, nonce, 99, victim)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("one address took more of its share without proving it can receive, so a spoofer can spend a named peer's")
	}
	if r.halfOpen >= cookieThreshold {
		t.Fatalf("the global threshold was reached at %d, so this proves nothing about the per-address one", r.halfOpen)
	}
}

// A cookie is issued and echoed a round trip apart. Rotating the secret in
// between refused every cookie in flight, and RFC 7296 section 2.6's retry
// carries the one cookie the initiator was given, so the exchange then failed
// on a cookie that could never be accepted. The per-address pressure term
// makes "under pressure" the ordinary state for any address holding two
// half-open exchanges, so the rotation is no longer a load condition.
func TestCookieSurvivesRotationThatFollowsIt(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	r := &Responder{}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	endpoint := observedEndpoint(t, hub, randUint64Nonzero())
	nonce := bytes.Repeat([]byte{7}, 32)
	// Enough half-open exchanges from this address that a cookie is demanded.
	r.halfOpenBySource = map[netip.Addr]int{endpoint.AddrPort().Addr(): halfOpenPerSourceWithoutCookie}
	r.cookieRotated = time.Now()

	issued := cookieValue(r.cookieSecret, r.cookieVersion, nonce, 1, endpoint)
	echoed := &Message{Payloads: []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: issued})},
	}}
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || required {
		t.Fatalf("the responder refused the cookie it had just issued: required=%v err=%v", required, err)
	}

	// The secret rotates while the retry is still on the wire.
	r.cookieRotated = time.Now().Add(-2 * cookieLifetime)
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || required {
		t.Errorf("a cookie in flight through a rotation was refused: required=%v err=%v", required, err)
	}
	if !r.previousValid {
		t.Fatal("no rotation happened, so this proves nothing")
	}

	// One generation is all that is kept: a cookie two rotations old is older
	// than the lifetime it was issued under.
	r.cookieRotated = time.Now().Add(-2 * cookieLifetime)
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || !required {
		t.Errorf("a cookie two rotations old was still accepted: required=%v err=%v", required, err)
	}
}

// RFC 7296 section 2.21.2 leaves the IKE SA created when only the Child SA
// bundled into IKE_AUTH fails, and says the initiator "MAY, of course, for
// reasons of policy later delete such an IKE SA". This fork's policy is to
// delete it, and a responder holding the SA answers that Delete at once, so
// only a lost datagram leaves it unanswered. Retransmitting it to the end of
// the ordinary budget then delays the dial's failure by sixty-two seconds.
func TestTearingDownUnusableIKESADoesNotSpendTheWholeBudget(t *testing.T) {
	if teardownRetransmits >= maxRetransmits {
		t.Fatalf("the teardown budget is %d of %d attempts, so nothing is bounded", teardownRetransmits, maxRetransmits)
	}
	var budget time.Duration
	for attempt := range teardownRetransmits {
		budget += retransmitDelay(requestTimeout, attempt+1)
	}
	var full time.Duration
	for attempt := range maxRetransmits {
		full += retransmitDelay(requestTimeout, attempt+1)
	}
	// runPeer redials every ten seconds, so a teardown that outlasts that
	// delays the next attempt rather than the failed one.
	if budget > 10*time.Second {
		t.Errorf("a Delete nobody answers costs %s, out of the %s an exchange that matters gets", budget, full)
	}
}

// RFC 7296 section 1.2 leaves the IKE SA created when the Child SA in IKE_AUTH fails, so the responder answers with its AUTH and the Child SA's error
// then it deletes the IKE SA in a request at its own first Message ID, which the answer ends
// an IKE_AUTH retransmitted while that Delete is outstanding draws the answer it had
func TestResponderDeletesTheIKESAWhoseChildSAItRefused(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	mux := childRefusedMux(t, h)
	held, authRequest := dialRefusedChild(t, h, mux)

	header, inner, answer := responderMessage(t, mux, held)
	if header.ExchangeType != IKE_AUTH || !header.IsResponse() || findType(inner, PayloadAUTH) == nil || findType(inner, PayloadSA) != nil {
		t.Fatalf("the responder first sent exchange %d response %v carrying %v, want its IKE_AUTH answer with AUTH and no Child SA",
			header.ExchangeType, header.IsResponse(), inner)
	}
	header, inner, deleteRequest := responderMessage(t, mux, held)
	wantIKEDelete(t, header, inner)
	if err := mux.SendIKE(authRequest); err != nil {
		t.Fatal(err)
	}
	for {
		header, _, again := responderMessage(t, mux, held)
		if header.ExchangeType == IKE_AUTH {
			if !bytes.Equal(again, answer) {
				t.Error("a retransmitted IKE_AUTH drew an answer other than the one it had")
			}
			break
		}
		if !bytes.Equal(again, deleteRequest) {
			t.Fatal("the responder sent something other than its Delete again while the retransmitted IKE_AUTH waited for its answer")
		}
	}
	response, err := EncryptMessage(held.suite, held.skei, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR,
		ExchangeType: INFORMATIONAL, Flags: FlagResponse | FlagInitiator, MessageID: 0}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(response); err != nil {
		t.Fatal(err)
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
}

// RFC 7296 section 2.25.2: "If a peer receives a request to close an IKE SA that it is currently trying to close, it SHOULD reply as usual, and forget about its own close request."
// a ranet3 initiator deletes the IKE SA after the same refusal, so the two Deletes cross, and the initiator's is answered and ends the responder's
func TestResponderAnswersTheDeleteCrossingItsOwn(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	mux := childRefusedMux(t, h)
	held, _ := dialRefusedChild(t, h, mux)

	if header, _, _ := responderMessage(t, mux, held); header.ExchangeType != IKE_AUTH || !header.IsResponse() {
		t.Fatalf("the responder first sent exchange %d response %v, want its IKE_AUTH answer", header.ExchangeType, header.IsResponse())
	}
	header, inner, _ := responderMessage(t, mux, held)
	wantIKEDelete(t, header, inner)
	request, err := EncryptMessage(held.suite, held.skei, Header{SPIInitiator: held.spiI, SPIResponder: held.spiR,
		ExchangeType: INFORMATIONAL, Flags: FlagInitiator, MessageID: 2}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	for {
		header, inner, _ := responderMessage(t, mux, held)
		if header.IsResponse() {
			if header.ExchangeType != INFORMATIONAL || header.MessageID != 2 || len(inner) != 0 {
				t.Errorf("the initiator's Delete was answered with exchange %d at Message ID %d carrying %v, want an empty INFORMATIONAL at 2",
					header.ExchangeType, header.MessageID, inner)
			}
			break
		}
		// the responder's own Delete again, retransmitted before the initiator's reached it
		wantIKEDelete(t, header, inner)
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
}

// a responder whose Delete goes unanswered sends it teardownRetransmits times and then lets the IKE SA go, well inside the ordinary budget
func TestResponderGivesUpItsUnansweredDeleteAfterTheTeardownBudget(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	mux := childRefusedMux(t, h)
	held, _ := dialRefusedChild(t, h, mux)

	if header, _, _ := responderMessage(t, mux, held); header.ExchangeType != IKE_AUTH || !header.IsResponse() {
		t.Fatalf("the responder first sent exchange %d response %v, want its IKE_AUTH answer", header.ExchangeType, header.IsResponse())
	}
	var first []byte
	for range teardownRetransmits {
		header, inner, raw := responderMessage(t, mux, held)
		wantIKEDelete(t, header, inner)
		if first == nil {
			first = raw
		} else if !bytes.Equal(raw, first) {
			t.Error("the Delete was sent again changed")
		}
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
	if raw, err := mux.RecvIKEUntil(time.Now().Add(quietPeriod)); err == nil {
		t.Errorf("the responder sent %d more bytes after it let the IKE SA go", len(raw))
	}
}

// a responder that refuses IKE_AUTH itself creates no IKE SA, so a peer that never authenticated gets nothing after the refusal, a Delete least of all
// it refuses an AUTH the trust's key does not verify, an IDi naming an endpoint of the other family, and an IDr naming none of its own
func TestResponderRefusingIKEAuthSendsNoDelete(t *testing.T) {
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, refusal := range []struct {
		name     string
		key      func(*responderHarness) ed25519.PrivateKey
		idi, idr string
	}{
		{"unverified", func(*responderHarness) ed25519.PrivateKey { return other }, "testorg/client:2", "testorg/server:1"},
		{"other family", func(h *responderHarness) ed25519.PrivateKey { return h.private }, "testorg/client:3", "testorg/server:1"},
		{"not ours", func(h *responderHarness) ed25519.PrivateKey { return h.private }, "testorg/client:2", "testorg/server:2"},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			refused := &recorder{}
			h := childRefusedHarness(t, refused.record)
			mux := childRefusedMux(t, h)
			held, _ := dialSignedBy(t, h, mux, refusal.key(h), refusal.idi, refusal.idr)

			header, inner, _ := responderMessage(t, mux, held)
			if header.ExchangeType != IKE_AUTH || !header.IsResponse() || len(inner) != 1 || inner[0].Type != PayloadN {
				t.Fatalf("the responder first sent exchange %d response %v carrying %v, want its IKE_AUTH refusal", header.ExchangeType, header.IsResponse(), inner)
			}
			if notify, err := DecodeNotify(inner[0].Body); err != nil || notify.Type != N_AUTHENTICATION_FAILED {
				t.Fatalf("the responder refused IKE_AUTH with %+v (%v), want AUTHENTICATION_FAILED", notify, err)
			}
			if raw, err := mux.RecvIKEUntil(time.Now().Add(quietPeriod)); err == nil {
				t.Errorf("the responder sent %d more bytes after refusing IKE_AUTH, want nothing", len(raw))
			}
			awaitHandshakeEnd(t, h, refused, held.spiI)
		})
	}
}

// childRefusedHarness answers testorg/client:2 with a handshake timeout of twice answerBudget, so a handshake that ends within answerBudget was not ended by its timeout
func childRefusedHarness(t *testing.T, events Recorder) *responderHarness {
	t.Helper()
	return newConfiguredResponderHarness(t, map[identity.Identity]Family{identity.MustParse("testorg/server:1"): IPv4}, nil,
		func(cfg *ResponderConfig) { cfg.HandshakeTimeout = 2 * answerBudget }, events)
}

func childRefusedMux(t *testing.T, h *responderHarness) *transport.Mux {
	t.Helper()
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	return mux
}

// dialRefusedChild signs IKE_AUTH as the trust expects, so the bundled Child SA is all the responder refuses
func dialRefusedChild(t *testing.T, h *responderHarness, mux *transport.Mux) (*ikeContext, []byte) {
	t.Helper()
	return dialSignedBy(t, h, mux, h.private, "testorg/client:2", "testorg/server:1")
}

// the IKE_AUTH request names idi and idr, and its Child SA offer names a DH group, which a Child SA in IKE_AUTH cannot negotiate
func dialSignedBy(t *testing.T, h *responderHarness, mux *transport.Mux, key ed25519.PrivateKey, idi, idr string) (*ikeContext, []byte) {
	t.Helper()
	held, message1, nr := initHalfOpen(t, mux, nil)
	child := espProposal([]byte{0, 0, 0, 9})
	child.Transforms = append(child.Transforms, Transform{Type: TransDH, ID: DH_ECP_256})
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(held.suite, held.skei, header, nil, ikeAuthPayloads(key, held, message1, nr, child, idi, idr))
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	return held, request
}

// ikeAuthPayloads is the IKE_AUTH request of idi to idr under the half-open SA held, which message1 opened and nr answered, offering child and signed by key
func ikeAuthPayloads(key ed25519.PrivateKey, held *ikeContext, message1, nr []byte, child Proposal, idi, idr string) []RawPayload {
	idiBody := idBody(idi)
	return []RawPayload{
		{Type: PayloadIDi, Body: idiBody},
		{Type: PayloadIDr, Body: idBody(idr)},
		{Type: PayloadAUTH, Body: BuildAuth(key, concat(message1, nr, prf(held.suite.PRFID, held.skpi, idiBody)))},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{child})},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
}

// initHalfOpen runs IKE_SA_INIT on mux and returns the half-open SA the responder answered with, the request that opened it and the responder's nonce
// shape, when given, makes the request's payloads of the ones initHalfOpen would send
// RFC 7296 section 2.5, which the answer is held to: "Payloads sent in IKE response messages MUST NOT have the critical flag set."
// section 2.5 on the order: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
func initHalfOpen(t *testing.T, mux *transport.Mux, shape func([]RawPayload) []RawPayload) (*ikeContext, []byte, []byte) {
	t.Helper()
	spiI := randUint64Nonzero()
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	ni := make([]byte, nonceLen)
	rand.Read(ni)
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: binary.BigEndian.AppendUint16(nil, HashIdentity)})},
	}
	if shape != nil {
		payloads = shape(payloads)
	}
	message1 := (&Message{Header: Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, Payloads: payloads}).Encode()
	message2 := statelessAnswer(t, mux, message1, "the responder did not answer IKE_SA_INIT")
	answer, err := DecodeMessage(message2)
	if err != nil {
		t.Fatal(err)
	}
	sa, ke, nonce := answer.find(PayloadSA), answer.find(PayloadKE), answer.find(PayloadNonce)
	if sa == nil || ke == nil || nonce == nil {
		t.Fatalf("the responder answered IKE_SA_INIT with notify %d", firstTestNotify(t, message2).Type)
	}
	for _, payload := range answer.Payloads {
		if payload.Critical {
			t.Errorf("the IKE_SA_INIT answer marks payload type %d critical", payload.Type)
		}
	}
	// the figure of section 1.2: "HDR, SAr1, KEr, Nr, [CERTREQ]"
	// the notifies follow Nr
	if got, want := payloadTypes(answer.Payloads), []PayloadType{PayloadSA, PayloadKE, PayloadNonce, PayloadN, PayloadN, PayloadN}; !slices.Equal(got, want) {
		t.Errorf("the IKE_SA_INIT answer carries payload types %v, want %v", got, want)
	}
	selected, err := DecodeSA(sa.Body)
	if err != nil || len(selected) != 1 {
		t.Fatalf("the IKE_SA_INIT answer selects %v: %v", selected, err)
	}
	suite, err := suiteFromProposal(selected[0], []Proposal{ikeProposal()}, false)
	if err != nil {
		t.Fatal(err)
	}
	group, public, err := DecodeKE(ke.Body)
	if err != nil {
		t.Fatal(err)
	}
	// section 3.4 on the KE payload: "This Diffie-Hellman Group Num MUST match a Diffie-Hellman group specified in a proposal in the SA payload that is sent in the same message"
	if group != suite.DHGroup {
		t.Errorf("the IKE_SA_INIT answer has its KE payload in group %d and selects group %d", group, suite.DHGroup)
	}
	shared, err := dh.SharedSecret(public)
	if err != nil {
		t.Fatal(err)
	}
	nr, spiR := DecodeNonce(nonce.Body), answer.Header.SPIResponder
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		t.Fatal(err)
	}
	held := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR}
	return held, message1, nr
}

// responderMessage reads the next message the responder sends under the IKE SA held, past any repeat of its IKE_SA_INIT answer
func responderMessage(t *testing.T, mux *transport.Mux, held *ikeContext) (Header, []RawPayload, []byte) {
	t.Helper()
	for {
		raw, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatalf("the responder sent nothing more: %v", err)
		}
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		if message.Header.ExchangeType == IKE_SA_INIT {
			continue
		}
		inner, err := DecryptMessage(held.suite, held.sker, raw, message)
		if err != nil {
			t.Fatal(err)
		}
		return message.Header, inner, raw
	}
}

func wantIKEDelete(t *testing.T, header Header, inner []RawPayload) {
	t.Helper()
	if header.ExchangeType != INFORMATIONAL || header.IsResponse() || header.IsInitiator() || header.MessageID != 0 {
		t.Fatalf("the responder sent exchange %d response %v initiator %v at Message ID %d, want its own first request",
			header.ExchangeType, header.IsResponse(), header.IsInitiator(), header.MessageID)
	}
	if len(inner) != 1 || inner[0].Type != PayloadD {
		t.Fatalf("the request carries %v, want one Delete", inner)
	}
	if deleted, err := DecodeDelete(inner[0].Body); err != nil || deleted.Protocol != ProtoIKE {
		t.Fatalf("the request deletes %+v (%v), want the IKE SA", deleted, err)
	}
}

// awaitHandshakeEnd waits for the responder to record the failed handshake, which comes once its state for spiI has gone
func awaitHandshakeEnd(t *testing.T, h *responderHarness, refused *recorder, spiI uint64) {
	t.Helper()
	for deadline := time.Now().Add(answerBudget); recordedKind(refused, "ike.handshake.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("the responder still held the IKE SA when the budget ran out")
		}
	}
	h.responder.mu.Lock()
	halfOpen := h.responder.halfOpen
	h.responder.mu.Unlock()
	if halfOpen != 0 {
		t.Errorf("the responder holds %d half-open SAs after the handshake ended", halfOpen)
	}
	other, err := h.responder.cfg.Hub.NewMux(net.ParseIP("127.0.0.1"), 4500)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.RegisterIKE(spiI); err != nil {
		t.Errorf("the responder still routes the IKE SA's SPI: %v", err)
	}
}

// RFC 7296 section 2.10 is two rules, and the second needs the PRF: a nonce
// "MUST be at least 128 bits in size, and MUST be at least half the key size
// of the negotiated pseudorandom function". IKE_SA_INIT is the one exchange
// where the nonce arrives before the PRF is chosen, and it is the surface an
// unauthenticated peer reaches first, so checking only the length there left
// it as the one place a short nonce was taken.
func TestResponderChecksTheNonceAgainstTheNegotiatedPRF(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	spiI := randUint64Nonzero()
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// Sixteen bytes: past the flat 128 bit floor, half the key size of
	// HMAC-SHA2-256 and a third of HMAC-SHA2-384's.
	short := bytes.Repeat([]byte{3}, 16)
	withPRF := func(prf uint16) Proposal {
		p := ikeProposal()
		p.Transforms = slices.Clone(p.Transforms)
		p.Transforms = slices.DeleteFunc(p.Transforms, func(t Transform) bool { return t.Type == TransPRF })
		return Proposal{Number: p.Number, Protocol: p.Protocol,
			Transforms: append(p.Transforms, Transform{Type: TransPRF, ID: prf})}
	}
	// offer retries, because these are datagrams on a loopback socket shared
	// with every other test in this package, and answers a cookie challenge if
	// one comes: whether return routability was demanded is not under test.
	offer := func(t *testing.T, proposal Proposal) Notify {
		t.Helper()
		for range 4 {
			for {
				if _, err := mux.RecvIKEUntil(time.Now()); err != nil {
					break
				}
			}
			send := func(ahead []RawPayload) (Notify, bool) {
				if err := mux.SendIKE(encodeTestSAInit(t, spiI, short, proposal, ahead)); err != nil {
					t.Fatal(err)
				}
				reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
				if err != nil {
					return Notify{}, false
				}
				return firstTestNotify(t, reply), true
			}
			answer, ok := send(nil)
			if !ok {
				continue
			}
			if answer.Type != N_COOKIE {
				return answer
			}
			if answer, ok := send([]RawPayload{{Type: PayloadN, Body: EncodeNotify(answer)}}); ok {
				return answer
			}
		}
		t.Fatal("the responder never answered")
		return Notify{}
	}

	if got := offer(t, withPRF(PRF_HMAC_SHA2_384)).Type; got != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("a 16 byte nonce under HMAC-SHA2-384 drew notify %d, want NO_PROPOSAL_CHOSEN", got)
	}
	// The same nonce is long enough for the other PRF this responder offers,
	// so what the first case proves is the PRF rule and not the flat floor.
	if got := offer(t, withPRF(PRF_HMAC_SHA2_256)).Type; got == N_NO_PROPOSAL_CHOSEN {
		t.Error("a 16 byte nonce under HMAC-SHA2-256 was refused, which is the length rule rather than the PRF one")
	}
}

// a datagram with the right IKE_AUTH header and contents this end cannot decrypt, which anyone who sees the responder SPI can send, ends no handshake
// acting on one would end a handshake this end paid a key exchange for, the cheapest way to stop every session a node opens
// the deadline alone ends the wait
func TestUndecryptableDatagramDoesNotEndTheHandshake(t *testing.T) {
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	peerHub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer peerHub.Close()
	port := func(h *transport.Hub) int { return h.LocalAddr().(*net.UDPAddr).Port }
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), port(peerHub))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := peerHub.NewMux(net.IPv4(127, 0, 0, 1), port(hub))
	if err != nil {
		t.Fatal(err)
	}

	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	key := bytes.Repeat([]byte{9}, 20)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: key, sker: key, responder: true}
	s := &Session{mux: mux, current: ctx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH,
		Flags: FlagInitiator, MessageID: 1}
	good, err := EncryptMessage(suite, key, header, nil, []RawPayload{{Type: PayloadN,
		Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}})
	if err != nil {
		t.Fatal(err)
	}
	// the same header with the ciphertext replaced decodes and fails the AEAD
	bad := append([]byte(nil), good...)
	for i := len(bad) - 16; i < len(bad); i++ {
		bad[i] ^= 0xff
	}
	if err := peer.SendIKE(bad); err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(good); err != nil {
		t.Fatal(err)
	}

	got, _, err := s.awaitAuthRequest(nil, nil, nil, nil, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("an undecryptable datagram ended the handshake: %v", err)
	}
	if !bytes.Equal(got.raw, good) {
		t.Error("the request returned is not the one that authenticated")
	}
}

// RFC 7296 section 2.21.2: "request messages that contain an unsupported critical payload, or where the whole message is malformed (rather than just bad payload contents), MUST be rejected in their entirety, and MUST only lead to an UNSUPPORTED_CRITICAL_PAYLOAD or INVALID_SYNTAX Notification sent as a response."
// section 2.11: "MUST respond to the address and port from which the request was received."
// an IKE_AUTH that decrypts, from another port than IKE_SA_INIT, with a payload chain that does not parse draws INVALID_SYNTAX at Message ID 1 there
// the half-open SA then goes with nothing more sent
func TestResponderAnswersAMalformedIKEAuthWithInvalidSyntax(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	held, _, _ := initHalfOpen(t, childRefusedMux(t, h), nil)
	moved, err := listenHub(t).NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { moved.Close() })
	if err := moved.RegisterIKE(held.spiI); err != nil {
		t.Fatal(err)
	}

	// a payload header whose stated length is shorter than the header itself, then no padding
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	malformed, err := encryptMessagePlaintextIV(held.suite, held.skei, header, nil, PayloadIDi, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	if err := moved.SendIKE(malformed); err != nil {
		t.Fatal(err)
	}
	answer, inner, _ := responderMessage(t, moved, held)
	if answer.ExchangeType != IKE_AUTH || !answer.IsResponse() || answer.MessageID != 1 || !notified(inner, N_INVALID_SYNTAX, nil) {
		t.Fatalf("the malformed IKE_AUTH drew exchange %d response %v at Message ID %d carrying %v, want INVALID_SYNTAX at 1",
			answer.ExchangeType, answer.IsResponse(), answer.MessageID, inner)
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
	if raw, err := moved.RecvIKEUntil(time.Now().Add(quietPeriod)); err == nil {
		t.Errorf("the responder sent %d more bytes after it let the half-open SA go", len(raw))
	}
}

// RFC 7296 section 2.21.2: "All errors that occur in an IKE_AUTH exchange, causing the authentication to fail for whatever reason (invalid shared secret, invalid ID, untrusted certificate issuer, revoked or expired certificate, etc.) SHOULD result in an AUTHENTICATION_FAILED notification."
// an IKE_AUTH whose IDi holds no distinguished name draws AUTHENTICATION_FAILED at Message ID 1, and the half-open SA then goes
func TestResponderAnswersAnIDiItCannotReadWithAuthenticationFailed(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	mux := childRefusedMux(t, h)
	held, _, _ := initHalfOpen(t, mux, nil)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(held.suite, held.skei, header, nil, []RawPayload{
		{Type: PayloadIDi, Body: EncodeID(ID_DER_ASN1_DN, []byte{0x04, 0x00})},
		{Type: PayloadAUTH, Body: BuildAuth(h.private, []byte("signed octets the responder never reaches"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	answer, inner, _ := responderMessage(t, mux, held)
	if answer.ExchangeType != IKE_AUTH || !answer.IsResponse() || answer.MessageID != 1 || !notified(inner, N_AUTHENTICATION_FAILED, nil) {
		t.Fatalf("the IKE_AUTH drew exchange %d response %v at Message ID %d carrying %v, want AUTHENTICATION_FAILED at 1",
			answer.ExchangeType, answer.IsResponse(), answer.MessageID, inner)
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
}

// RFC 7296 section 2.21.4: "A node needs to limit the rate at which it will send messages in response to unprotected messages."
// with the one limit spent, the IKE_SA_INITs that draw an error notify in the clear that ends the exchange draw nothing: one at major version 3, one marking an unsupported payload critical and one offering only a cipher this end does not implement
// section 2.6: "When a responder detects a large number of half-open IKE SAs, it SHOULD reply to IKE_SA_INIT requests with a response containing the COOKIE notification."
// section 2.6.1: "There are two common reasons why the initiator may have to retry the IKE_SA_INIT exchange: the responder requests a cookie or wants a different Diffie-Hellman group than was included in the KEi payload."
// the COOKIE that answers such a flood, the INVALID_KE_PAYLOAD that answers a KE in a group the offer leaves out and the answer that carries an IKE_SA_INIT forward are outside the limit
func TestStatelessErrorAnswersShareOneLimit(t *testing.T) {
	h := newResponderHarness(t, nil)
	spendStatelessErrors(t)
	request := func(proposal Proposal, ahead []RawPayload) (*transport.Mux, []byte) {
		t.Helper()
		mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mux.Close() })
		spi := randUint64Nonzero()
		if err := mux.RegisterIKE(spi); err != nil {
			t.Fatal(err)
		}
		return mux, encodeTestSAInit(t, spi, bytes.Repeat([]byte{1}, 32), proposal, ahead)
	}
	withCipher := func(cipher, group uint16) Proposal {
		return Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
			{Type: TransEncr, ID: cipher, KeyLengthBits: 256},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransDH, ID: group},
		}}
	}
	for name, refused := range map[string]struct {
		proposal Proposal
		ahead    []RawPayload
		version  uint8
	}{
		"at major version 3":                      {ikeProposal(), nil, 0x30},
		"marking an unsupported payload critical": {ikeProposal(), []RawPayload{unsupportedCritical}, 0x20},
		// ENCR_3DES, which this end does not implement
		"offering only a cipher this end does not implement": {withCipher(3, DH_CURVE25519), nil, 0x20},
	} {
		mux, raw := request(refused.proposal, refused.ahead)
		if err := mux.SendIKE(atVersion(raw, refused.version)); err != nil {
			t.Fatal(err)
		}
		if reply, err := mux.RecvIKEUntil(time.Now().Add(quietPeriod)); err == nil {
			t.Errorf("the IKE_SA_INIT %s drew notify %d with the limit spent", name, firstTestNotify(t, reply).Type)
		}
	}

	h.responder.mu.Lock()
	h.responder.halfOpen = cookieThreshold
	h.responder.mu.Unlock()
	mux, raw := request(ikeProposal(), nil)
	if notify := firstTestNotify(t, statelessAnswer(t, mux, raw, "an IKE_SA_INIT under pressure drew no answer")); notify.Type != N_COOKIE {
		t.Errorf("an IKE_SA_INIT under pressure drew notify %d with the limit spent, want COOKIE", notify.Type)
	}
	h.responder.mu.Lock()
	h.responder.halfOpen = 0
	h.responder.mu.Unlock()
	// encodeTestSAInit writes its KE in X25519
	mux, raw = request(withCipher(ENCR_AES_GCM_16, DH_ECP_256), nil)
	if notify := firstTestNotify(t, statelessAnswer(t, mux, raw, "an IKE_SA_INIT with KE in a group its offer leaves out drew no answer")); notify.Type != N_INVALID_KE_PAYLOAD ||
		!bytes.Equal(notify.Data, invalidKENotifyData(DH_ECP_256)) {
		t.Errorf("an IKE_SA_INIT with KE in a group its offer leaves out drew notify %d naming %x with the limit spent, want INVALID_KE_PAYLOAD naming ECP_256", notify.Type, notify.Data)
	}
	mux, raw = request(ikeProposal(), nil)
	if answer, err := DecodeMessage(statelessAnswer(t, mux, raw, "an IKE_SA_INIT drew no answer")); err != nil || answer.find(PayloadSA) == nil {
		t.Errorf("an IKE_SA_INIT drew %+v (%v) with the limit spent, want the answer that carries it forward", answer, err)
	}
}

// reconnectDelay is how long a dialer waits between attempts, internal/client's defaultReconnectDelay
const reconnectDelay = 10 * time.Second

// the limit holds a fleet's redial after an outage, as many dials as there are half-open slots, and refills before the next one
func TestStatelessErrorLimitHoldsAFleetRedial(t *testing.T) {
	if statelessErrorBurst < halfOpenLimit {
		t.Errorf("the limit holds %d answers, fewer than the %d half-open SAs a redial can open", statelessErrorBurst, halfOpenLimit)
	}
	if refill := time.Duration(statelessErrorBurst * float64(time.Second) / statelessErrorsPerSecond); refill > reconnectDelay {
		t.Errorf("the limit refills in %s, after the %s a dialer waits to redial", refill, reconnectDelay)
	}
}

// RFC 7296 section 3.9: "Nonce values MUST NOT be reused."
// two IKE_SA_INIT requests are answered with different nonces
func TestEachIKESAInitAnswerDrawsItsOwnNonce(t *testing.T) {
	h := newResponderHarness(t, nil)
	var nonces [][]byte
	for range 2 {
		mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mux.Close() })
		spi := randUint64Nonzero()
		if err := mux.RegisterIKE(spi); err != nil {
			t.Fatal(err)
		}
		answer, err := DecodeMessage(statelessAnswer(t, mux, encodeTestSAInit(t, spi, bytes.Repeat([]byte{1}, 32), ikeProposal(), nil), "an IKE_SA_INIT drew no answer"))
		if err != nil {
			t.Fatal(err)
		}
		nonce := answer.find(PayloadNonce)
		if nonce == nil {
			t.Fatalf("the IKE_SA_INIT drew %v and no nonce", payloadTypes(answer.Payloads))
		}
		nonces = append(nonces, DecodeNonce(nonce.Body))
	}
	if bytes.Equal(nonces[0], nonces[1]) {
		t.Errorf("two IKE_SA_INIT requests were answered with the same nonce %x", nonces[0])
	}
}

// spendStatelessErrors empties the one limit on error answers in the clear and stops its refill until the test ends
func spendStatelessErrors(t *testing.T) {
	t.Helper()
	statelessErrors.mu.Lock()
	perSecond := statelessErrors.perSecond
	statelessErrors.tokens, statelessErrors.perSecond = 0, 0
	statelessErrors.mu.Unlock()
	t.Cleanup(func() {
		statelessErrors.mu.Lock()
		statelessErrors.tokens, statelessErrors.perSecond, statelessErrors.filled = statelessErrors.burst, perSecond, time.Now()
		statelessErrors.mu.Unlock()
	})
}

// a limit spent holds every answer back until it refills, one line an interval tells how many it held since the line before, and a refill stops at the burst
func TestAnswerLimitHoldsAnswersBackAndSaysSoOnceAnInterval(t *testing.T) {
	lines := recordLines(t)
	held := func() []int64 {
		var counts []int64
		for _, count := range lines.said(slog.LevelWarn, "ike held back error answers to unprotected messages", "held") {
			counts = append(counts, count.Int64())
		}
		return counts
	}
	limit := newAnswerLimit(2, 0)
	for range 2 {
		if !limit.take() {
			t.Fatal("an answer within the burst was held back")
		}
	}
	for range 5 {
		if limit.take() {
			t.Fatal("an answer went out with the burst spent and no refill")
		}
	}
	if got := held(); !slices.Equal(got, []int64{1}) {
		t.Fatalf("five answers held back wrote lines telling of %v, want one line, for the first", got)
	}
	// backdating the last line is the same as an interval passing, and does not make the test wait for it
	limit.mu.Lock()
	limit.said = limit.said.Add(-statelessHeldReport)
	limit.mu.Unlock()
	if limit.take() {
		t.Fatal("an answer went out with the burst spent and no refill")
	}
	if got := held(); !slices.Equal(got, []int64{1, 5}) {
		t.Errorf("the lines told of %v, want the next to tell of the four held since and this one", got)
	}
	limit.mu.Lock()
	limit.perSecond, limit.filled = 1, limit.filled.Add(-time.Second)
	limit.mu.Unlock()
	if !limit.take() || limit.take() {
		t.Error("a second of refill at one answer a second let other than one answer out")
	}
	idle := newAnswerLimit(2, 1)
	idle.mu.Lock()
	idle.filled = idle.filled.Add(-time.Hour)
	idle.mu.Unlock()
	taken := 0
	for range 3 {
		if idle.take() {
			taken++
		}
	}
	if taken != 2 {
		t.Errorf("an hour of refill at one answer a second let %d of 3 answers out, want the burst of two", taken)
	}
}

// lineRecorder keeps every line logged while it is the default, from any goroutine
type lineRecorder struct {
	mu      sync.Mutex
	records []slog.Record
}

// recordLines makes a new lineRecorder the default until the test ends
func recordLines(t *testing.T) *lineRecorder {
	t.Helper()
	lines := &lineRecorder{}
	logtest.SetDefault(t, slog.New(lines))
	return lines
}

// said is the value of the attribute key in each line logged at level with message, in the order they were logged
func (l *lineRecorder) said(level slog.Level, message, key string) []slog.Value {
	l.mu.Lock()
	defer l.mu.Unlock()
	var values []slog.Value
	for _, record := range l.records {
		if record.Level != level || record.Message != message {
			continue
		}
		var value slog.Value
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == key {
				value = attr.Value
			}
			return attr.Key != key
		})
		values = append(values, value)
	}
	return values
}

func (l *lineRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (l *lineRecorder) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	l.records = append(l.records, r.Clone())
	l.mu.Unlock()
	return nil
}
func (l *lineRecorder) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *lineRecorder) WithGroup(string) slog.Handler      { return l }

// RFC 7296 section 2.5: "If an endpoint receives a message with a higher major version number, it MUST drop the message and SHOULD send an unauthenticated Notify message of type INVALID_MAJOR_VERSION containing the highest (closest) version number it supports."
// an unclaimed request at major version 3 is answered so whatever its exchange
// section 3.1 on the minor version: "They MUST ignore the minor version number of received messages."
// section 3.1 on the X bits: "'X' bits MUST be cleared when sending and MUST be ignored on receipt."
// section 3.1 on the V bit: "Implementations of IKEv2 MUST clear this bit when sending and MUST ignore it in incoming messages."
// so an IKE_SA_INIT at version 2.1 with the V bit and every X bit set is answered as one at 2.0 is
func TestResponderAnswersOnlyAHigherMajorVersionWithInvalidMajorVersion(t *testing.T) {
	h := newResponderHarness(t, nil)
	// one mux for each SPI, so a late copy of one answer cannot be read as the next
	muxFor := func(spi uint64) *transport.Mux {
		mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mux.Close() })
		if err := mux.RegisterIKE(spi); err != nil {
			t.Fatal(err)
		}
		return mux
	}

	saInit, _ := buildTestSAInit(t)
	informational := encodeTestMessage(t, Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(), ExchangeType: INFORMATIONAL, MessageID: 7}, nil)
	for _, request := range [][]byte{saInit, informational} {
		header, err := decodeHeader(request)
		if err != nil {
			t.Fatal(err)
		}
		reply := statelessAnswer(t, muxFor(header.SPIInitiator), atVersion(request, 0x30), "a request at major version 3 drew no answer")
		wantMajorVersionRefusal(t, reply, *header)
	}

	minor, spiI := buildTestSAInit(t)
	ignoring := atVersion(minor, 0x21)
	ignoring[19] |= FlagVersion | 0xc7
	reply := statelessAnswer(t, muxFor(spiI), ignoring, "an IKE_SA_INIT at version 2.1 drew no answer")
	if answer, err := DecodeMessage(reply); err != nil || answer.find(PayloadSA) == nil {
		t.Fatalf("an IKE_SA_INIT at version 2.1 drew notify %d, want the answer one at 2.0 draws", firstTestNotify(t, reply).Type)
	}
	// section 2.5: "If it receives a message with a major version that it supports, it MUST respond with that version number."
	if reply[17] != 0x20 {
		t.Errorf("the answer's version octet is %#x, want 2.0", reply[17])
	}
	// section 3.1 on the I bit: "This bit MUST be set in messages sent by the original initiator of the IKE SA and MUST be cleared in messages sent by the original responder."
	if reply[19] != FlagResponse {
		t.Errorf("the answer's flags are %#x, want the Response bit alone", reply[19])
	}
}

// RFC 7296 section 2.5: "If an endpoint receives a message with a higher major version number, it MUST drop the message and SHOULD send an unauthenticated Notify message of type INVALID_MAJOR_VERSION containing the highest (closest) version number it supports."
// section 3.1 on the minor version: "They MUST ignore the minor version number of received messages."
// section 2.21.4: "If a response is sent, the response MUST be sent to the IP address and port from where it came with the same IKE SPIs and the Message ID copied."
// an IKE_AUTH at major version 3 that authenticates under the half-open SA is answered so and not taken for the IKE_AUTH, and one in the clear from another address is answered at that address, so the half-open SA answers the one at version 2.1 with the V bit and every X bit set after them
func TestResponderAnswersAHigherMajorVersionWhileItWaitsForIKEAuth(t *testing.T) {
	refused := &recorder{}
	h := childRefusedHarness(t, refused.record)
	mux := childRefusedMux(t, h)
	held, _, _ := initHalfOpen(t, mux, nil)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	if err := mux.SendIKE(sealedEdited(t, held.suite, held.skei, header, nil, atMajorVersion3)); err != nil {
		t.Fatal(err)
	}
	for {
		reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatalf("the IKE_AUTH at major version 3 drew no answer: %v", err)
		}
		// a late copy of the IKE_SA_INIT answer, which initHalfOpen may have asked for twice
		if repeat, err := decodeHeader(reply); err == nil && repeat.ExchangeType == IKE_SA_INIT {
			continue
		}
		wantMajorVersionRefusal(t, reply, header)
		break
	}
	elsewhere := listenPeer(t)
	if _, err := elsewhere.WriteToUDP(withNonESPMarker(atVersion(encodeTestMessage(t, header, nil), 0x30)), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.remotePort}); err != nil {
		t.Fatal(err)
	}
	if err := elsewhere.SetReadDeadline(time.Now().Add(answerBudget)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := elsewhere.ReadFromUDP(buf)
	if err != nil || n <= 4 {
		t.Fatalf("the IKE_AUTH at major version 3 from another address drew no answer there: %d bytes, %v", n, err)
	}
	wantMajorVersionRefusal(t, slices.Clone(buf[4:n]), header)

	// section 3.1 on the X bits: "'X' bits MUST be cleared when sending and MUST be ignored on receipt."
	// section 3.1 on the V bit: "Implementations of IKEv2 MUST clear this bit when sending and MUST ignore it in incoming messages."
	header.Flags |= FlagVersion | 0xc7
	// an IKE_AUTH carrying no IDi or AUTH, which the half-open SA refuses
	if err := mux.SendIKE(sealedEdited(t, held.suite, held.skei, header, nil, atMinorVersion1)); err != nil {
		t.Fatal(err)
	}
	answer, inner, raw := responderMessage(t, mux, held)
	if answer.ExchangeType != IKE_AUTH || answer.MessageID != 1 || !notified(inner, N_AUTHENTICATION_FAILED, nil) {
		t.Fatalf("the IKE_AUTH at version 2.1 after it drew exchange %d at Message ID %d carrying %v, want AUTHENTICATION_FAILED at 1", answer.ExchangeType, answer.MessageID, inner)
	}
	// section 2.5: "If it receives a message with a major version that it supports, it MUST respond with that version number."
	if raw[17] != 0x20 {
		t.Errorf("the answer's version octet is %#x, want 2.0", raw[17])
	}
	// section 3.1 on the I bit: "This bit MUST be set in messages sent by the original initiator of the IKE SA and MUST be cleared in messages sent by the original responder."
	if raw[19] != FlagResponse {
		t.Errorf("the answer's flags are %#x, want the Response bit alone", raw[19])
	}
	awaitHandshakeEnd(t, h, refused, held.spiI)
}

// RFC 7296 section 3.2 on the critical bit: "MUST be ignored by the recipient if the recipient understands the payload type code."
// section 2.5: "If the critical flag is not set and the payload type is unsupported, that payload MUST be ignored."
// section 3.12: "Unfamiliar Vendor IDs MUST be ignored."
// section 2.5: "Payloads sent in IKE response messages MUST NOT have the critical flag set."
// an initiator marking every payload of both its requests critical, the SK payload and the CERTREQ, CP, EAP and Vendor ID this end skips among them, and adding one of a type nothing assigns unmarked, is answered and taken as one marking none, and the answers mark nothing
func TestResponderIgnoresTheCriticalBitOnPayloadsItUnderstands(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	marked := func(payloads []RawPayload) []RawPayload {
		payloads = append(payloads, RawPayload{Type: PayloadV, Body: []byte("a vendor this end does not know")})
		for i := range payloads {
			payloads[i].Critical = true
		}
		return append(payloads, RawPayload{Type: PayloadType(250), Body: []byte{1}})
	}
	held, message1, nr := initHalfOpen(t, mux, marked)
	inner := marked(append(ikeAuthPayloads(h.private, held, message1, nr, espProposal([]byte{0, 0, 0, 9}), "testorg/client:2", "testorg/server:1"),
		// an X.509 certificate request naming one authority by the hash of its key
		RawPayload{Type: PayloadCERTREQ, Body: append([]byte{4}, make([]byte, 20)...)},
		// a CFG_REQUEST for an IPv4 address
		RawPayload{Type: PayloadCP, Body: []byte{1, 0, 0, 0, 0, 1, 0, 0}},
		// an EAP Response carrying an Identity
		RawPayload{Type: PayloadEAP, Body: []byte{2, 0, 0, 6, 1, 'c'}},
	))
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	if err := mux.SendIKE(sealedEdited(t, held.suite, held.skei, header, inner, criticalSK)); err != nil {
		t.Fatal(err)
	}
	answer, answered, raw := responderMessage(t, mux, held)
	if answer.ExchangeType != IKE_AUTH || answer.MessageID != 1 || findType(answered, PayloadAUTH) == nil || findType(answered, PayloadSA) == nil {
		t.Fatalf("the IKE_AUTH request marking every payload critical drew exchange %d at Message ID %d carrying %v, want the responder's AUTH and Child SA at 1",
			answer.ExchangeType, answer.MessageID, answered)
	}
	if raw[HeaderLen+1]&0x80 != 0 {
		t.Error("the IKE_AUTH answer marks its SK payload critical")
	}
	for _, payload := range answered {
		if payload.Critical {
			t.Errorf("the IKE_AUTH answer marks payload type %d critical", payload.Type)
		}
	}
	carriedForward(t, h)
}

// RFC 7296 section 3.10.1: "Unrecognized error types in a request and status types in a request or response MUST be ignored, and they should be logged."
// an initiator adding an error notify and a status notify of types nothing assigns to both its requests is answered and taken as one adding none
func TestResponderIgnoresNotifiesItDoesNotRecognize(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	added := func(payloads []RawPayload) []RawPayload {
		return append(payloads, unrecognizedError, unrecognizedStatus)
	}
	held, message1, nr := initHalfOpen(t, mux, added)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(held.suite, held.skei, header, nil, added(ikeAuthPayloads(h.private, held, message1, nr, espProposal([]byte{0, 0, 0, 9}), "testorg/client:2", "testorg/server:1")))
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	answer, answered, _ := responderMessage(t, mux, held)
	if answer.ExchangeType != IKE_AUTH || answer.MessageID != 1 || findType(answered, PayloadAUTH) == nil || findType(answered, PayloadSA) == nil {
		t.Fatalf("the IKE_AUTH request carrying the notifies drew exchange %d at Message ID %d carrying %v, want the responder's AUTH and Child SA at 1",
			answer.ExchangeType, answer.MessageID, answered)
	}
	carriedForward(t, h)
}

// carriedForward waits for the session the responder carries forward from the half-open SA and checks whose it is
func carriedForward(t *testing.T, h *responderHarness) {
	t.Helper()
	select {
	case session := <-h.sessions:
		session.Mux().Close()
		if accepted := <-h.identities; accepted.Peer != identity.MustParse("testorg/client:2") {
			t.Errorf("the responder took the session for %s", accepted.Peer)
		}
	case <-time.After(answerBudget):
		t.Fatal("the responder never carried the session forward")
	}
}

// RFC 7296 section 2.5: "implementations MUST NOT reject as invalid a message with those payloads in any other order."
// section 2.5: "implementations SHOULD send the payloads defined in this specification in the order shown in the figures in Sections 1 and 2"
// an initiator sending the payloads of both its requests in reverse is answered and taken as one sending them in order, and the answers keep the order of the figures
func TestResponderTakesPayloadsInAnyOrderAndAnswersInTheFiguresOrder(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	reversed := func(payloads []RawPayload) []RawPayload {
		slices.Reverse(payloads)
		return payloads
	}
	held, message1, nr := initHalfOpen(t, mux, reversed)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(held.suite, held.skei, header, nil, reversed(ikeAuthPayloads(h.private, held, message1, nr, espProposal([]byte{0, 0, 0, 9}), "testorg/client:2", "testorg/server:1")))
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	answer, answered, _ := responderMessage(t, mux, held)
	if answer.ExchangeType != IKE_AUTH || answer.MessageID != 1 || findType(answered, PayloadAUTH) == nil {
		t.Fatalf("the IKE_AUTH request in reverse drew exchange %d at Message ID %d carrying %v, want the responder's AUTH at 1", answer.ExchangeType, answer.MessageID, answered)
	}
	// the figure of section 1.2: "HDR, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}"
	if got, want := payloadTypes(answered), []PayloadType{PayloadIDr, PayloadAUTH, PayloadSA, PayloadTSi, PayloadTSr}; !slices.Equal(got, want) {
		t.Errorf("the IKE_AUTH answer carries payload types %v, want %v", got, want)
	}
	carriedForward(t, h)
}

// RFC 7296 section 1.2: "Thus, the SA payloads in the IKE_AUTH exchange cannot contain Transform Type 4 (Diffie-Hellman group) with any value other than NONE. Implementations SHOULD omit the whole transform substructure instead of sending value NONE."
// the Child SA the IKE_AUTH answer selects from an offer naming no Diffie-Hellman transform names none either
func TestResponderSelectsNoDiffieHellmanTransformInIKEAuth(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	held, message1, nr := initHalfOpen(t, mux, nil)
	header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	request, err := EncryptMessage(held.suite, held.skei, header, nil, ikeAuthPayloads(h.private, held, message1, nr, espProposal([]byte{0, 0, 0, 9}), "testorg/client:2", "testorg/server:1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	_, answered, _ := responderMessage(t, mux, held)
	sa := findType(answered, PayloadSA)
	if sa == nil {
		t.Fatalf("the IKE_AUTH answer carries %v", answered)
	}
	selected, err := DecodeSA(sa.Body)
	if err != nil || len(selected) != 1 {
		t.Fatalf("the IKE_AUTH answer selects %v: %v", selected, err)
	}
	for _, transform := range selected[0].Transforms {
		if transform.Type == TransDH {
			t.Errorf("the IKE_AUTH answer names Diffie-Hellman group %d", transform.ID)
		}
	}
	carriedForward(t, h)
}

// RFC 7296 section 2.21.2: "request messages that contain an unsupported critical payload, or where the whole message is malformed (rather than just bad payload contents), MUST be rejected in their entirety, and MUST only lead to an UNSUPPORTED_CRITICAL_PAYLOAD or INVALID_SYNTAX Notification sent as a response."
// section 2.5: "In that Notify payload, the Notification Data contains the one-octet payload type."
// an IKE_AUTH carrying a critical payload of a type nothing assigns, in the clear ahead of SK or inside it, draws UNSUPPORTED_CRITICAL_PAYLOAD naming the type at Message ID 1, and the half-open SA then goes
func TestResponderRefusesAnIKEAuthMarkingAnUnsupportedPayloadCritical(t *testing.T) {
	for placement, request := range map[string]struct{ cleartext, inner []RawPayload }{
		"inside SK":    {nil, []RawPayload{unsupportedCritical}},
		"in the clear": {[]RawPayload{unsupportedCritical}, nil},
	} {
		t.Run(placement, func(t *testing.T) {
			refused := &recorder{}
			h := childRefusedHarness(t, refused.record)
			mux := childRefusedMux(t, h)
			held, _, _ := initHalfOpen(t, mux, nil)
			header := Header{SPIInitiator: held.spiI, SPIResponder: held.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
			raw, err := EncryptMessage(held.suite, held.skei, header, request.cleartext, request.inner)
			if err != nil {
				t.Fatal(err)
			}
			if err := mux.SendIKE(raw); err != nil {
				t.Fatal(err)
			}
			answer, inner, _ := responderMessage(t, mux, held)
			if answer.ExchangeType != IKE_AUTH || !answer.IsResponse() || answer.MessageID != 1 ||
				!notified(inner, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupportedCritical.Type)}) {
				t.Fatalf("the IKE_AUTH drew exchange %d response %v at Message ID %d carrying %v, want UNSUPPORTED_CRITICAL_PAYLOAD for type %d at 1",
					answer.ExchangeType, answer.IsResponse(), answer.MessageID, inner, unsupportedCritical.Type)
			}
			awaitHandshakeEnd(t, h, refused, held.spiI)
		})
	}
}

// Anyone who can reach the port can make a handshake fail, so the line has to
// be rare, but at debug it was invisible at the default level, and an operator
// looking at "that peer cannot connect" had nothing on this side to read. Both
// halves matter: the first failure from a source is said at warn, and the ones
// behind it drop to debug rather than being repeated.
//
// The limit is per source. See handshakeFailureInterval for the measurement
// that decides the shape.
func TestFailedInboundHandshakeIsSaidOncePerSource(t *testing.T) {
	hub := listenHub(t)
	first := observedEndpoint(t, hub, 0x11)
	samePort := observedEndpoint(t, hub, 0x22)
	other := observedEndpointFrom(t, hub, 0x33, net.IPv6loopback)

	var levels []slog.Level
	logtest.SetDefault(t, slog.New(&levelRecorder{levels: &levels}))
	r := newFailureRecorder()
	// the event goes with the warn line, so a source failing over and over costs the recorder what it costs the log
	failures := &recorder{}
	r.cfg.Events = failures.record
	recordedAsWarned := func(warned int) {
		t.Helper()
		if recorded := len(failures.recorded()); recorded != warned {
			t.Errorf("%d warn lines so far went with %d recorded failures", warned, recorded)
		}
	}
	for range 4 {
		r.noteHandshakeFailure(first, errors.New("no registry entry"))
	}
	recordedAsWarned(1)
	if len(levels) != 4 {
		t.Fatalf("four failures wrote %d lines", len(levels))
	}
	if levels[0] != slog.LevelWarn {
		t.Errorf("the first failure from a source is at %v, want warn: at debug an operator sees nothing", levels[0])
	}
	for _, level := range levels[1:] {
		if level != slog.LevelDebug {
			t.Errorf("a repeat inside the interval is at %v, want debug: anyone who can reach the port can drive these", level)
		}
	}

	// Another port on the same address is the same source. The record is keyed
	// on the address, which is the part a peer cannot change for free.
	levels = nil
	r.noteHandshakeFailure(samePort, errors.New("no registry entry"))
	if len(levels) != 1 || levels[0] != slog.LevelDebug {
		t.Errorf("a second port from one address wrote %v, want one debug line", levels)
	}
	recordedAsWarned(1)

	// A different address is a different peer and is said at once, as long as
	// the floor that bounds the lines whatever their source has passed.
	levels = nil
	r.noteHandshakeFailure(other, errors.New("no registry entry"))
	if len(levels) != 1 || levels[0] != slog.LevelDebug {
		t.Errorf("a second address inside the floor wrote %v, want one debug line", levels)
	}
	recordedAsWarned(1)
	levels = nil
	r.failureSaid -= handshakeFloor
	r.noteHandshakeFailure(other, errors.New("no registry entry"))
	if len(levels) != 1 || levels[0] != slog.LevelWarn {
		t.Errorf("a second address past the floor wrote %v, want one warn line", levels)
	}
	recordedAsWarned(2)
}

// RFC 7296 section 2.21.4: "If the message is marked as a response, the node ... MUST NOT respond."
// the answer to a Delete whose exchange has ended reaches the responder this way, and it is no failed handshake
func TestResponderDropsAResponseNoExchangeWaitsFor(t *testing.T) {
	failures := &recorder{}
	h := newResponderHarness(t, nil, failures.record)
	peer := listenPeer(t)
	to := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.remotePort}
	header := Header{SPIInitiator: randUint64Nonzero(), SPIResponder: randUint64Nonzero(), ExchangeType: INFORMATIONAL,
		Flags: FlagResponse | FlagInitiator, MessageID: 2}
	send := func() {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(encodeTestMessage(t, header, nil)), to); err != nil {
			t.Fatal(err)
		}
	}

	send()
	_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Error("the responder answered a response")
	}
	if n := recordedKind(failures, "ike.handshake.failed"); n != 0 {
		t.Fatalf("a response no exchange waits for was recorded as %d failed handshakes", n)
	}

	// the same datagram marked as a request is a failed handshake, so the record would have shown the response as one
	header.Flags = FlagInitiator
	send()
	for deadline := time.Now().Add(answerBudget); recordedKind(failures, "ike.handshake.failed") == 0; time.Sleep(recordPoll) {
		if time.Now().After(deadline) {
			t.Fatal("a request no SA holds was not recorded as a failed handshake either")
		}
	}
	// section 2.21.4 on a message marked as a request: "MAY send a response."
	// this end sends none, which also holds it to section 1.5 on the message a node sends about a packet no SA of its own takes: "This message is not part of an INFORMATIONAL exchange, and the receiving node MUST NOT respond to it because doing so could cause a message loop."
	_ = peer.SetReadDeadline(time.Now().Add(quietPeriod))
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Error("the responder answered a request no SA holds")
	}
}

// The record is bounded, because the sources in it are unauthenticated, and a
// source arriving to a full one is spaced by the floor rather than silenced:
// otherwise a host cycling addresses keeps every legitimate peer's first
// failure at debug for as long as it likes.
func TestHandshakeFailureRecordIsBounded(t *testing.T) {
	r := newFailureRecorder()
	for i := range handshakeFailureSources {
		r.failureReported[netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)})] = time.Since(r.started)
	}
	hub := listenHub(t)
	if !r.failureIsDue(observedEndpoint(t, hub, 0x44)) {
		t.Error("a full record swallowed a source it had never seen")
	}
	if len(r.failureReported) > handshakeFailureSources {
		t.Errorf("the record holds %d sources, want at most %d", len(r.failureReported), handshakeFailureSources)
	}
}

// A node that has never said anything says its first failure. The floor spaces
// repeats against the last line written, and an unprimed zero means "at the
// start of this process", which silences everything in the first second of a
// node's life.
func TestFirstHandshakeFailureOfANodesLifeIsSaid(t *testing.T) {
	responder, err := NewResponder(ResponderConfig{
		Hub: listenHub(t), LocalPrivateKey: make(ed25519.PrivateKey, ed25519.PrivateKeySize),
		Local: map[identity.Identity]Family{identity.MustParse("example/node:0"): IPv4}, Trust: trustsNobody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !responder.failureIsDue(observedEndpoint(t, listenHub(t), 0x55)) {
		t.Error("the first failure of this node's life was spaced against its own start")
	}
}

// The floor bounds the lines whatever their sources, which the per-source
// record alone does not: every address a host holds is a fresh entry.
func TestHandshakeFailuresAreSpacedWhateverTheirSource(t *testing.T) {
	r := newFailureRecorder()
	hub := listenHub(t)
	said := 0
	for i := range 64 {
		// One address, a fresh record entry each time, standing in for a host
		// spending a range of them. The floor bounds that.
		r.failureReported = make(map[netip.Addr]time.Duration, handshakeFailureSources)
		if r.failureIsDue(observedEndpointFrom(t, hub, uint64(i)+1, net.IPv4(127, 0, 0, 1))) {
			said++
		}
	}
	if said != 1 {
		t.Errorf("64 fresh sources inside one floor wrote %d lines, want 1", said)
	}
}

// newFailureRecorder builds the failure record the way NewResponder does,
// priming included.
func newFailureRecorder() *Responder {
	return &Responder{started: time.Now(),
		failureReported: make(map[netip.Addr]time.Duration, handshakeFailureSources),
		failureSaid:     -handshakeFloor}
}

// levelRecorder keeps the level of every record and discards the rest.
type levelRecorder struct{ levels *[]slog.Level }

func (h *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	*h.levels = append(*h.levels, r.Level)
	return nil
}
func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelRecorder) WithGroup(string) slog.Handler      { return h }
