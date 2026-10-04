// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"time"
)

// PathDebug is the prefix every debug path sits under
const PathDebug = "/v0/debug/"

// DebugAccess is who may use the debug paths, which the daemon's --debug-access sets
type DebugAccess string

const (
	// DebugRoot keeps the root class to uid 0 and the daemon's own user
	DebugRoot DebugAccess = "root"
	// DebugGroup opens the root class to everyone who can open the socket
	DebugGroup DebugAccess = "group"
	// DebugOff refuses every debug path
	DebugOff DebugAccess = "off"
)

// DebugAccesses is every --debug-access value, the one list the parser, the flag and the tests read
var DebugAccesses = []DebugAccess{DebugRoot, DebugGroup, DebugOff}

// DebugAccessNames is the same set as plain strings, for a usage line and for shell completion
func DebugAccessNames() []string {
	out := make([]string, 0, len(DebugAccesses))
	for _, access := range DebugAccesses {
		out = append(out, string(access))
	}
	return out
}

// UnmarshalText reads a --debug-access value
func (a *DebugAccess) UnmarshalText(text []byte) error {
	if access := DebugAccess(text); slices.Contains(DebugAccesses, access) {
		*a = access
		return nil
	}
	return fmt.Errorf("debug access is one of %s", strings.Join(DebugAccessNames(), ", "))
}

// DebugAccessor is a Source that chooses its debug access
// one that does not implement it serves under DebugRoot
type DebugAccessor interface {
	DebugAccess() DebugAccess
}

// debugClass sorts debug paths by what they disclose or do, which decides who may call them
type debugClass int

const (
	// classRead is a snapshot without key material, or the event stream
	// status and sessions already disclose that kind of thing to the socket's group
	classRead debugClass = iota
	// classRoot is profiles, goroutine dumps, logs, captures, the trust document and every action
	classRoot
)

// debugRoute is one debug path
// wire is the type its answer carries, which the key material check walks
type debugRoute struct {
	class debugClass
	wire  reflect.Type
	serve func(*debugServer, http.ResponseWriter, *http.Request)
}

// debugRoutes is every debug path, each registered from the init of the file defining its view
// registration ends before main starts, so a server reads the map without a lock
var debugRoutes = map[string]debugRoute{}

func registerDebug(path string, class debugClass, wire reflect.Type, serve func(*debugServer, http.ResponseWriter, *http.Request)) {
	if _, taken := debugRoutes[path]; taken {
		panic("control: two debug views registered " + path)
	}
	debugRoutes[path] = debugRoute{class: class, wire: wire, serve: serve}
}

// debugRead registers a read the source answers through its debug interface I
func debugRead[I, T any](path string, class debugClass, view string, read func(I) T) {
	registerDebug(path, class, reflect.TypeFor[T](), func(d *debugServer, w http.ResponseWriter, r *http.Request) {
		if !reading(w, r) {
			return
		}
		if source, ok := implements[I](d, w, view); ok {
			writeJSON(w, read(source))
		}
	})
}

// implements finds a view's debug interface on the source
// a source without it is told so by name rather than by a missing route
func implements[I any](d *debugServer, w http.ResponseWriter, view string) (I, bool) {
	source, ok := d.src.(I)
	if !ok {
		http.Error(w, "this node does not serve the "+view+" view", http.StatusNotImplemented)
	}
	return source, ok
}

// debugServer serves the paths under PathDebug for one source
type debugServer struct {
	src    Source
	access DebugAccess
	// euid is the daemon's own user, which the root class admits beside uid 0
	euid uint32
	// streams holds a place for every stream open, see stream
	streams           chan struct{}
	budget, heartbeat time.Duration
}

func newDebugServer(src Source) *debugServer {
	access := DebugRoot
	if accessor, ok := src.(DebugAccessor); ok {
		access = accessor.DebugAccess()
	}
	return &debugServer{src: src, access: access, euid: uint32(os.Geteuid()),
		streams: make(chan struct{}, maxStreams), budget: streamBudget, heartbeat: streamHeartbeat}
}

func (d *debugServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, found := debugRoutes[r.URL.Path]
	if !found && d.access != DebugOff {
		http.Error(w, "no debug path is called "+r.URL.Path+" on this daemon", http.StatusNotFound)
		return
	}
	caller, known := CallerOf(r.Context())
	if why := refusal(d.access, route.class, caller, known, d.euid); why != "" {
		http.Error(w, why, http.StatusForbidden)
		return
	}
	if route.class == classRoot {
		slog.Info("control debug call", "path", r.URL.Path, "uid", caller.UID, "pid", caller.PID)
	}
	route.serve(d, w, r)
}

// refusal is why caller may not use a path of class, or empty where it may
// a connection without credentials reaches the read class alone
func refusal(access DebugAccess, class debugClass, caller Caller, known bool, euid uint32) string {
	who := "the connection carries no credentials to name the caller"
	if known {
		who = fmt.Sprintf("the caller is uid %d", caller.UID)
	}
	switch {
	case access == DebugOff:
		return "this daemon runs with --debug-access off, which refuses every debug path, and " + who
	case class == classRead:
		return ""
	case !known:
		return "this debug path is for a caller the socket can name, and " + who
	case access == DebugGroup || caller.UID == 0 || caller.UID == euid:
		return ""
	}
	return fmt.Sprintf("this debug path is for uid 0 or the daemon's own uid %d under --debug-access root, and %s", euid, who)
}

// DebugPaths is every debug path this build serves
func DebugPaths() iter.Seq[string] { return maps.Keys(debugRoutes) }
