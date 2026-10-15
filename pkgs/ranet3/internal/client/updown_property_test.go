// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/internal/registry"
)

const (
	// upDownSteps is the longest run of moves one case makes
	upDownSteps = 10
	// stopBudget is how long a stopped node may take to return from Run
	stopBudget = 30 * time.Second
	// startBudget is how long a started node may take to agree with the model, a local start whose dials nothing answers
	startBudget = 5 * time.Second
)

// the moves a case draws, by index
const (
	moveDown = iota
	moveUp
	moveReload
	moveRestart
	// moveCrashDown writes the flag a down writes first and ends the process before the down acts
	moveCrashDown
	// moveCrashUp removes the flag an up removes first and ends the process before the up acts
	moveCrashUp
	moveDisable
	moveEnable
	// moveSession lands a session with its Babel neighbor, as a dial or an answer would
	moveSession
	moves
)

var moveNames = [moves]string{"down", "up", "reload", "restart", "crash after a down's flag", "crash after an up's flag", "disable", "enable", "session"}

// upDownModel holds where a node should stand on the mesh after the moves so far
type upDownModel struct {
	down  bool
	since time.Time
	// disabled is the reconciler's, stopped over the socket, which a restart starts again
	disabled bool
	// peers is how many dialers the file last read asks for while the node is up
	peers int
	// sessions is how many landed since the node last came up
	sessions int
}

// upDownRig is one node as a process holds it, which a case takes down and up, reloads and restarts
// it dials peers nothing answers for, so a dialer runs and never lands a session, and moveSession lands them instead
type upDownRig struct {
	ht    *hegel.T
	dir   string
	files [2]string
	// file is the one the node last started or reloaded from, and peerCounts is how many peers each names
	file       int
	peerCounts [2]int
	key        ed25519.PrivateKey
	reg        registry.Registry
	client     *Client
	stop       func()
	reconciler *switchRecord
	translator *switchRecord
	sessions   *heldSessions
	landed     int
}

func newUpDownRig(ht *hegel.T) *upDownRig {
	t := ht.T
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		ht.Fatalf("%v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		ht.Fatalf("%v", err)
	}
	mesh := meshCounter.Add(1)
	loopback := "127.0.0.1"
	org := registry.Organization{Organization: "example", PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
	local := fmt.Sprintf("local-%d", mesh)
	names := []string{local, fmt.Sprintf("p1-%d", mesh), fmt.Sprintf("p2-%d", mesh), fmt.Sprintf("p3-%d", mesh)}
	ports := make([]uint16, len(names))
	for i, name := range names {
		ports[i] = freeUDPPort(t)
		org.Nodes = append(org.Nodes, registry.Node{CommonName: name, Endpoints: []registry.Endpoint{{
			SerialNumber: "0", AddressFamily: "ip4", Address: &loopback, Port: ports[i],
		}}})
	}
	dir := t.TempDir()
	r := &upDownRig{ht: ht, dir: filepath.Join(dir, "state"), key: private, reg: registry.Registry{org}, peerCounts: [2]int{2, 3}}
	keyPath, trustPath := filepath.Join(dir, "key.pem"), filepath.Join(dir, "registry.json")
	writeKey(t, keyPath, private)
	writeRegistry(t, trustPath, r.reg)
	for i, count := range r.peerCounts {
		cfg := &config.Config{
			Node: identity.MustParse("example/" + local),
			Auth: config.Auth{Key: keyPath, Trust: trustPath},
			Link: config.Link{Port: ports[0], Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}}, Listen: true},
		}
		for _, peer := range names[1 : 1+count] {
			cfg.Dial.To = append(cfg.Dial.To, identity.MustParse("example/"+peer+":0"))
		}
		r.files[i] = filepath.Join(dir, fmt.Sprintf("config-%d.yaml", i))
		writeConfig(t, r.files[i], cfg)
	}
	return r
}

// open builds the node's client from the file it last started or reloaded from, on the port that file names
func (r *upDownRig) open() error {
	cfg, err := config.Load(r.files[r.file])
	if err != nil {
		r.ht.Fatalf("%v", err)
	}
	r.client, err = newClient(cfg, r.key, trust(r.ht.T, r.reg), netstack.NewRoutesOnly(), nil, events.New())
	return err
}

// start runs the client open built with its state directory as the daemon does, the two switches new and running
// it returns once the node agrees with the model, at once for a node starting down, which starts nothing for a wait to see
func (r *upDownRig) start(model upDownModel) {
	c := r.client
	if err := c.SetStateDir(r.dir); err != nil {
		r.ht.Fatalf("%v", err)
	}
	flag := filepath.Join(r.dir, downFlag)
	r.reconciler, r.translator = &switchRecord{flag: flag}, &switchRecord{flag: flag}
	c.SetReconcilerEnable(r.reconciler.set)
	c.SetEgressEnable(r.translator.set)
	r.sessions = holdSessions(c)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()
	r.stop = func() {
		cancel()
		select {
		case <-done:
		case <-time.After(stopBudget):
			r.ht.Fatalf("the node did not return from Run within %s of its stop", stopBudget)
		}
	}
	waitFor(r.ht, startBudget, "the start", func() bool { return r.check(model) == "" })
}

// restart ends the process and starts the next one on the port it held, which reads the flag the moves left
func (r *upDownRig) restart(model upDownModel) {
	r.stop()
	retryPort(r.ht, "bind again", r.open)
	r.start(model)
}

// effective is where a switch stands, a new one standing on as kernel.New and egress.New leave theirs
func effective(s *switchRecord) bool {
	on, _ := s.calls()
	return len(on) == 0 || on[len(on)-1]
}

// check says how the node differs from the model, empty where it agrees
func (r *upDownRig) check(model upDownModel) string {
	c := r.client
	var problems []string
	body, err := os.ReadFile(filepath.Join(r.dir, downFlag))
	switch {
	case model.down && err != nil:
		problems = append(problems, fmt.Sprintf("the flag is gone from a node that should be down (%v)", err))
	case model.down && strings.TrimSpace(string(body)) != model.since.Format(time.RFC3339Nano):
		problems = append(problems, fmt.Sprintf("the flag holds %q, want %s", body, model.since.Format(time.RFC3339Nano)))
	case !model.down && err == nil:
		problems = append(problems, "the flag is there on a node that should be up")
	}
	status := c.Status().Down
	switch {
	case model.down && (status == nil || !status.Since.Equal(model.since)):
		problems = append(problems, fmt.Sprintf("the status reports %+v, want down since %s", status, model.since))
	case !model.down && status != nil:
		problems = append(problems, fmt.Sprintf("the status reports %+v on a node that should be up", status))
	}
	reconciler, translator := effective(r.reconciler), effective(r.translator)
	if model.down {
		if what := offTheMesh(c); what != "" {
			problems = append(problems, "down runs "+what)
		}
		if reconciler || translator {
			problems = append(problems, fmt.Sprintf("down leaves the reconciler at %v and the translator at %v", reconciler, translator))
		}
		return strings.Join(problems, ", ")
	}
	c.dialersMu.Lock()
	dialers, responder, speaking := len(c.dialers), c.responder != nil, c.speakerRun != nil
	c.dialersMu.Unlock()
	if dialers != model.peers || !responder || !speaking {
		problems = append(problems, fmt.Sprintf("up runs %d dialers, responder %v and speaker %v, want %d, true and true", dialers, responder, speaking, model.peers))
	}
	if sessions, neighbors := len(c.sessions.paths()), len(c.speaker.Stats().Neighbors); sessions != model.sessions || neighbors != model.sessions {
		problems = append(problems, fmt.Sprintf("up holds %d sessions and %d neighbors, want %d of each", sessions, neighbors, model.sessions))
	}
	if reconciler != !model.disabled || !translator {
		problems = append(problems, fmt.Sprintf("up leaves the reconciler at %v and the translator at %v with the reconciler disabled %v", reconciler, translator, model.disabled))
	}
	return strings.Join(problems, ", ")
}

// every run of down, up, reload, restart, disable, enable, a session landing and a crash between a flag and the act it records agrees with the model
// the flag is there exactly when the last request was down, and holds the moment it went down
// a restart comes up as the flag says, with the same moment, and a reload never moves the node between the two
// while down nothing dials, answers or speaks Babel, no session or neighbor is held and neither switch holds anything in the host
// while up every peer the file names is dialed, the responder and the speaker run, and only a disable keeps the reconciler stopped
// a down or an up asked twice says so, and an enable while down is refused
func TestDownAndUpAgreeWithTheirModel(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		// each attempt draws a rig of its own and with it every port, as tryLoopbackMesh does
		var r *upDownRig
		retryPort(ht, "bind", func() error {
			r = newUpDownRig(ht)
			return r.open()
		})
		model := upDownModel{peers: r.peerCounts[0]}
		r.start(model)
		defer func() { r.stop() }()
		var done []string
		for range hegel.Draw(ht, pbt.Spanning(1, upDownSteps)) {
			move := hegel.Draw(ht, pbt.Spanning(0, moves-1))
			done = append(done, moveNames[move])
			model = r.make(move, model, done)
			if problem := r.check(model); problem != "" {
				ht.Fatalf("after %s: %s", strings.Join(done, ", "), problem)
			}
		}
	})
}

// make takes one move on the node and returns the model after it, failing the case where the node answers otherwise
func (r *upDownRig) make(move int, model upDownModel, done []string) upDownModel {
	ctx, c := context.Background(), r.client
	after := strings.Join(done, ", ")
	switch move {
	case moveDown:
		result, err := c.Down(ctx)
		if err != nil {
			r.ht.Fatalf("after %s: down failed: %v", after, err)
		}
		if model.down != strings.Contains(result.Detail, "already down") {
			r.ht.Fatalf("after %s: down answered %q with the node down %v", after, result.Detail, model.down)
		}
		if !model.down {
			model.down, model.since, model.sessions = true, c.Status().Down.Since, 0
		}
	case moveUp:
		result, err := c.Up(ctx)
		if err != nil {
			r.ht.Fatalf("after %s: up failed: %v", after, err)
		}
		if model.down == strings.Contains(result.Detail, "already up") {
			r.ht.Fatalf("after %s: up answered %q with the node down %v", after, result.Detail, model.down)
		}
		model.down = false
	case moveReload:
		r.file = 1 - r.file
		if err := c.ReloadFrom(r.files[r.file]); err != nil {
			r.ht.Fatalf("after %s: the reload was refused: %v", after, err)
		}
		model.peers = r.peerCounts[r.file]
	case moveRestart, moveCrashDown, moveCrashUp:
		switch {
		case move == moveCrashDown && !model.down:
			model.down, model.since = true, time.Now().UTC()
			if err := writeDownFlag(r.dir, model.since); err != nil {
				r.ht.Fatalf("after %s: %v", after, err)
			}
		case move == moveCrashUp && model.down:
			model.down = false
			if err := os.Remove(filepath.Join(r.dir, downFlag)); err != nil {
				r.ht.Fatalf("after %s: %v", after, err)
			}
		}
		model.disabled, model.sessions = false, 0
		r.restart(model)
	case moveDisable:
		if _, err := c.SetSubsystem(ctx, control.SubsystemReconciler, false); err != nil {
			r.ht.Fatalf("after %s: the disable was refused: %v", after, err)
		}
		model.disabled = true
	case moveEnable:
		_, err := c.SetSubsystem(ctx, control.SubsystemReconciler, true)
		if model.down != (err != nil) {
			r.ht.Fatalf("after %s: the enable answered %v with the node down %v", after, err, model.down)
		}
		if !model.down {
			model.disabled = false
		}
	case moveSession:
		if !model.down {
			r.landed++
			r.sessions.adopt(r.ht, c, fmt.Sprintf("example/held-%d:0@0", r.landed))
			model.sessions++
		}
	}
	return model
}
