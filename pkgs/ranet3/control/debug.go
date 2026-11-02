// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"iter"
	"log/slog"
	"maps"
	"net/http"
	"reflect"
	"time"
)

// PathDebug is the prefix every debug path sits under
const PathDebug = "/v0/debug/"

// debugRoute is one debug path
// wire is the type its answer carries, which the key material check walks
type debugRoute struct {
	wire  reflect.Type
	serve func(*debugServer, http.ResponseWriter, *http.Request)
}

// debugRoutes is every debug path, each registered from the init of the file defining its view
// registration ends before main starts, so a server reads the map without a lock
var debugRoutes = map[string]debugRoute{}

func registerDebug(path string, wire reflect.Type, serve func(*debugServer, http.ResponseWriter, *http.Request)) {
	if _, taken := debugRoutes[path]; taken {
		panic("control: two debug views registered " + path)
	}
	debugRoutes[path] = debugRoute{wire: wire, serve: serve}
}

// debugRead registers a read the source answers through its debug interface I
func debugRead[I, T any](path string, view string, read func(I) T) {
	registerDebug(path, reflect.TypeFor[T](), func(d *debugServer, w http.ResponseWriter, r *http.Request) {
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
	src Source
	// streams holds a place for every stream open, see place
	streams                 chan struct{}
	budget, heartbeat, tick time.Duration
}

func newDebugServer(src Source) *debugServer {
	return &debugServer{src: src, streams: make(chan struct{}, maxStreams), budget: streamBudget, heartbeat: streamHeartbeat, tick: streamTick}
}

func (d *debugServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, found := debugRoutes[r.URL.Path]
	if !found {
		http.Error(w, "no debug path is called "+r.URL.Path+" on this daemon", http.StatusNotFound)
		return
	}
	route.serve(d, w, r)
}

// journal logs a verb, a probe or a trace request as message with its path and its caller where the socket names one
// the log outlives the event ring, which a restart clears and the caller's own verbs can push the record out of
func journal(r *http.Request, message string, attrs ...any) {
	line := []any{"path", r.URL.Path}
	if caller, known := CallerOf(r.Context()); known {
		line = append(line, "uid", caller.UID, "pid", caller.PID)
	}
	slog.Info(message, append(line, attrs...)...)
}

// DebugPaths is every debug path this build serves
func DebugPaths() iter.Seq[string] { return maps.Keys(debugRoutes) }
