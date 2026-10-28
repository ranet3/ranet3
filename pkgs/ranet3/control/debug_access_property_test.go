// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package control

import (
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// every debug path refuses exactly the callers the access rule refuses
// under every --debug-access mode, for any caller and any daemon user
// off refuses everything and a read path is open to whoever reached the socket
// a root path takes a caller the socket names as uid 0 or the daemon's own user
// --debug-access group lets every named caller onto a root path
// a plaintext path takes a caller the socket names as uid 0 and nobody else, under root and group alike
// a refusal names the caller's uid
// only the two users are drawn, and each pair meets every path, mode and credential in turn
func TestDebugAccessFollowsTheRule(t *testing.T) {
	paths := append(slices.Sorted(maps.Keys(debugRoutes)), PathDebug+"nothing-registered")
	pbt.Check(t, func(ht *hegel.T) {
		euid := hegel.Draw(ht, pbt.Spanning[uint32](0, math.MaxUint32))
		uid := hegel.Draw(ht, hegel.OneOf(hegel.Just(uint32(0)), hegel.Just(euid), pbt.Spanning[uint32](0, math.MaxUint32)))
		for _, path := range paths {
			for _, access := range DebugAccesses {
				for _, known := range []bool{false, true} {
					request := httptest.NewRequest(http.MethodGet, path, nil)
					if known {
						request = request.WithContext(withCaller(request.Context(), Caller{UID: uid}))
					}
					answer := httptest.NewRecorder()
					server := &debugServer{src: debugSource{access: access}, access: access, euid: euid}
					server.ServeHTTP(answer, request)

					route, registered := debugRoutes[path]
					var refused bool
					switch {
					case access == DebugOff:
						refused = true
					case registered && route.class == classRoot:
						refused = !known || access != DebugGroup && uid != 0 && uid != euid
					case registered && route.class == classPlaintext:
						refused = !known || uid != 0
					}
					if got := answer.Code == http.StatusForbidden; got != refused {
						ht.Fatalf("%s under %s for uid %d (known %v) with the daemon at uid %d answered %d %q, want refused %v",
							path, access, uid, known, euid, answer.Code, answer.Body, refused)
					}
					if refused && known && !strings.Contains(answer.Body.String(), fmt.Sprintf("uid %d", uid)) {
						ht.Fatalf("the refusal of uid %d reads %q, which does not name it", uid, answer.Body)
					}
				}
			}
		}
	})
}

// accessSink takes every verb under the --debug-access it names
type accessSink struct {
	writingSource
	access DebugAccess
}

func (s *accessSink) DebugAccess() DebugAccess { return s.access }

// every verb reaches the node for whoever reached the socket, down and up as redial does
// under every --debug-access mode, for any caller and for a connection that names none
// the classes are the debug paths' own, and the socket's mode is a verb's whole authorization
func TestVerbsAnswerWhoeverReachedTheSocket(t *testing.T) {
	bodies := map[string]string{
		PathDisable: `{"subsystem":"steering"}`, PathEnable: `{"subsystem":"steering"}`,
		PathRedial: `{"all":true}`, PathRekey: `{"all":true}`,
		PathReload: "", PathDown: "", PathUp: "",
	}
	pbt.Check(t, func(ht *hegel.T) {
		uid := hegel.Draw(ht, pbt.Spanning[uint32](0, math.MaxUint32))
		for _, path := range slices.Sorted(maps.Keys(bodies)) {
			for _, access := range DebugAccesses {
				for _, known := range []bool{false, true} {
					request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(bodies[path]))
					if known {
						request = request.WithContext(withCaller(request.Context(), Caller{UID: uid}))
					}
					sink := &accessSink{access: access}
					answer := httptest.NewRecorder()
					Handler(sink).ServeHTTP(answer, request)
					if answer.Code != http.StatusOK || sink.verb == "" {
						ht.Fatalf("%s under %s for uid %d (known %v) answered %d %q and reached the node as %q",
							path, access, uid, known, answer.Code, answer.Body, sink.verb)
					}
				}
			}
		}
	})
}
