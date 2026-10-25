// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package transport

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Underlay is how this node keeps the UDP sockets carrying IKE and ESP out of
// the reach of the routes the mesh installs, on darwin where Bind is set.
// linux keeps them out with a mark and no setting, as below, within the scope
// routing.md's "Where a lookup ends on Linux" states.
//
// It holds darwin's setting alone. A node that holds an address an exit
// announces ends up with a route out of its own tun covering the peers it
// reaches that tun through, and an underlay that follows it is a tunnel running
// inside itself. linux needs no setting: every underlay socket carries
// schema.UnderlayMark where the process may set it, as underlayMark says, which
// the reconciler's derived rules read (routing.md, where a lookup ends on
// Linux). darwin has no marks, no rules and one forwarding table, and answers
// by binding the socket to the interface the host's own default route leaves
// by, which scopes its route lookups to that interface. On that platform the
// interface also needs a default of its own scoped to it while an unscoped
// route out of another interface holds its family's zero address, and
// internal/kernel writes it then, and before the reconciler installs such a
// route of its own. See UnderlayDefaults there for the measurement and for the
// ownership rules that keep it off the host's own default.
//
// Either one makes a real default out of the tun safe, on linux within that
// scope, and an exit-node client installs a real default. On darwin without
// Bind the route has to go where no ordinary socket can see it, scoped to the
// tun, leaving a node that can hold a mesh address and cannot send its traffic
// through a mesh exit.
//
// Bind is refused by name on a platform that has no meaning for it, rather
// than accepted and ignored: a configuration written to keep the underlay out
// that quietly does nothing is the failure this exists to stop.
type Underlay struct {
	// Bind sets IP_BOUND_IF and IPV6_BOUND_IF to the interface the host's own
	// default route leaves by, darwin only. It needs Runtime.Links to say
	// which interface that is and to say when it changes, because a laptop
	// moves between wifi, ethernet, a dock and a VPN of its own, and a binding
	// left on the interface that is gone costs the machine every network it
	// has rather than only the mesh.
	//
	// It is not always enough on its own: while an unscoped route out of
	// another interface holds a family's zero address, or the reconciler is
	// about to install one, that interface also needs a default route scoped
	// to it, which macOS writes for every interface but the primary one.
	// internal/kernel writes the missing one while a family needs it, through
	// Runtime.Routes before this socket is bound to an interface and on each
	// reconciler pass after. It writes nothing for a family that needs none,
	// and the socket moves either way.
	Bind bool `yaml:"bind,omitempty" json:"bind,omitempty" toml:"bind,omitempty"`
}

// Runtime carries what the caller resolves at startup rather than writes in a
// file. It is separate from Underlay so the setting stays a value that a
// config file, a control plane and a test can each produce whole.
type Runtime struct {
	// Links answers which interface the host's own traffic leaves by. Nil is
	// allowed only where Underlay.Bind is unset.
	Links LinkSource
	// Routes writes whatever the host needs before a socket bound to an
	// interface can reach anything off it. Nil leaves that to the operator,
	// and the probe after each binding says so.
	Routes UnderlayRoutes
	// Events records each move of the socket onto another interface, on linux each fallback a send to a peer took
	// and each socket connected to one peer that opens or closes
	// nil records nothing
	Events func(kind string, attrs ...slog.Attr)
}

// UnderlayRoutes is the seam onto the routing this socket depends on.
// internal/kernel implements it on darwin, where a socket bound to an
// interface still reads the shared forwarding table and therefore can need
// that interface to carry a default of its own.
//
// The two calls exist separately so a move leaves no window: Prepare makes the
// interface usable, then the socket moves onto it, then Settle takes down what
// the interface it left needed. Doing it in one call would either strand the
// socket on an interface whose route has gone, or leave the route behind.
type UnderlayRoutes interface {
	// Prepare makes index usable by a socket bound to it.
	Prepare(index int) error
	// Settle removes what was prepared for every interface but index.
	Settle(index int) error
}

// LinkSource is the seam onto the host's own routing. internal/kernel
// implements it on darwin over the PF_ROUTE socket it already reads, which
// keeps the route socket in the one package that speaks it: this one owns a
// socket, not a routing table.
type LinkSource interface {
	// DefaultInterface is the index of the interface the host's own default
	// route leaves by. A host with no default route at all is an ordinary
	// state on a laptop, and is reported as an error rather than as index
	// zero, which would read as "unbind".
	DefaultInterface() (int, error)
	// Changed carries one coalesced wake-up per batch of changes to the
	// host's routing, so a binding can follow the interface it named.
	Changed() <-chan struct{}
}

// refuse reports why this platform cannot apply u, or nil. Binding is a
// platform facility and is refused by name where it does not exist, rather
// than accepted and ignored: a node configured to keep its underlay out of the
// mesh's routing and silently not doing it is a tunnel running inside itself,
// which reads as a peer that will not connect.
func (u Underlay) refuse() error {
	if u.Bind && !bindsSockets {
		return errors.New("binding the underlay socket to an interface is a darwin facility and is set on no other platform")
	}
	return nil
}

// interfaceBinder is implemented by the bind on a platform that can move a
// live socket from one interface to another. Rebinding rather than reopening
// is deliberate: the socket carries every SA this node holds, and a new
// descriptor would drop all of them to follow a link change that the peers
// never saw.
type interfaceBinder interface {
	// bindInterface sets the socket's interface index, where zero unbinds.
	// routed says the caller had Runtime.Routes prepare that interface first,
	// not that a default was written, which decides what an unreachable socket
	// is reported as.
	bindInterface(index int, routed bool) error
}

// bindUnderlay resolves the interface a bound socket starts on. An error is
// reported and the socket is left unbound rather than refusing to start: a
// laptop with no network yet is the ordinary way this happens, and Hub.follow
// binds as soon as the host has a default route. Hub.UnderlayReady is how a
// caller tells the two apart.
func bindUnderlay(underlay Underlay, rt Runtime) (int, error) {
	if err := underlay.refuse(); err != nil {
		return 0, err
	}
	if !underlay.Bind {
		return 0, nil
	}
	if rt.Links == nil {
		return 0, errors.New("binding the underlay socket needs a link source")
	}
	index, err := rt.Links.DefaultInterface()
	if err != nil {
		slog.Warn("transport left the underlay socket unbound", "err", err,
			"detail", "the host has no default route yet, so the socket is bound once it has one")
		return 0, nil
	}
	return index, nil
}

// follow rebinds the socket whenever the host's default route moves to another
// interface. It runs for the life of the hub.
func (h *Hub) follow(links LinkSource, routes UnderlayRoutes) {
	changed := links.Changed()
	for {
		select {
		case <-h.done:
			return
		case <-changed:
		}
		if !h.settleLinks(changed) {
			return
		}
		index, err := links.DefaultInterface()
		if err != nil {
			// Left where it is rather than unbound. A host between two
			// networks has no default for a moment, and unbinding for that
			// moment hands the socket back to a forwarding table that may
			// carry a default out of our own tun.
			slog.Warn("transport cannot tell which interface the host's traffic leaves by", "err", err)
			continue
		}
		if err := h.moveUnderlay(index, routes); err != nil {
			slog.Warn("transport could not follow the host's default route", "interface_index", index, "err", err)
		}
	}
}

// settleLinks waits out a fixed window, discarding further wake-ups, and
// reports whether the hub is still open.
func (h *Hub) settleLinks(changed <-chan struct{}) bool {
	timer := time.NewTimer(linkSettle)
	defer timer.Stop()
	for {
		select {
		case <-h.done:
			return false
		case <-changed:
		case <-timer.C:
			return true
		}
	}
}

// moveUnderlay puts the socket on one interface in the order that leaves it
// usable throughout: the interface it is going to is prepared first, then the
// socket moves, then whatever the interface it left needed comes down.
//
// A Prepare that fails stops the move, because a move onto an interface whose
// routing could not be written is one this node cannot undo. What it does not
// do is refuse an interface that simply needs nothing written, or one whose
// family the host reaches another way: the socket still belongs there, since
// that is where the host's own traffic goes, and the alternative is leaving it
// bound to an interface that may be gone. Whether a capture may then be
// installed is a separate question, asked separately, and UnderlayRoutes
// answers it per family rather than here.
func (h *Hub) moveUnderlay(index int, routes UnderlayRoutes) error {
	if routes != nil {
		// Unconditionally, even where the index has not changed. The kernel
		// drops the route this depends on when an interface goes down and
		// does not restore it when the interface comes back, so a wake that
		// finds the same index is exactly the case that needs the repair.
		if err := routes.Prepare(index); err != nil {
			return fmt.Errorf("transport: prepare interface %d: %w", index, err)
		}
	}
	if err := h.bindUnderlayTo(index, routes != nil); err != nil {
		return err
	}
	if routes != nil {
		if err := routes.Settle(index); err != nil {
			return fmt.Errorf("transport: settle on interface %d: %w", index, err)
		}
	}
	return nil
}

// BindUnderlay moves the socket carrying IKE and ESP onto one interface, where
// zero unbinds it. A binding that would change nothing costs no syscall, so a
// link notification about some other interface is free.
func (h *Hub) BindUnderlay(index int) error {
	return h.bindUnderlayTo(index, false)
}

// bindUnderlayTo is BindUnderlay with what the caller knows about the routing.
// routed says the caller had Runtime.Routes prepare the interface first, which
// writes a scoped default only for a family that needs one. It changes the
// probe afterward from advice to add a default into a pointer at the routing
// this node manages.
func (h *Hub) bindUnderlayTo(index int, routed bool) error {
	binder, ok := h.bind.(interfaceBinder)
	if !ok {
		return fmt.Errorf("transport: this platform cannot bind a socket to an interface")
	}
	h.mu.Lock()
	unchanged := h.boundTo == index
	h.mu.Unlock()
	if unchanged {
		return nil
	}
	if err := binder.bindInterface(index, routed); err != nil {
		// A move that failed partway leaves the socket on no one interface,
		// so the binding is recorded as unknown rather than as the index it
		// did not reach. UnderlayReady then answers false, which stops a
		// capture being installed over half a move.
		h.mu.Lock()
		h.boundTo = 0
		h.mu.Unlock()
		return err
	}
	h.mu.Lock()
	h.boundTo = index
	h.mu.Unlock()
	// a socket connected to one peer reopens bound where the listener now is
	h.dropPairs(pairUnderlayClose)
	slog.Info("transport bound the underlay socket", "interface_index", index)
	if h.events != nil {
		h.events("transport.underlay.bound", slog.Int("interface_index", index))
	}
	return nil
}

// UnderlayReady reports whether the socket is where the configuration says it
// should be. A hub that was asked to bind and could not, because the host had
// no default route when it opened, answers false, and the route reconciler
// reads that before it hands this machine's own traffic to the mesh: an
// unbound socket under a real default out of the tun is the tunnel inside
// itself this whole block exists to prevent.
func (h *Hub) UnderlayReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.underlay.Bind || h.boundTo != 0
}
