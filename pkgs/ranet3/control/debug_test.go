// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"ranet3.com/pkgs/ranet3/esp"
)

// probe views stand in for a read view, a root view and a view no source serves
type probeView struct {
	Name string `json:"name"`
}

type (
	probeReader interface{ ProbeRead() probeView }
	probeRooter interface{ ProbeRoot() probeView }
	probeAbsent interface{ ProbeAbsent() probeView }
)

const (
	pathProbeRead   = PathDebug + "probe-read"
	pathProbeRoot   = PathDebug + "probe-root"
	pathProbeAbsent = PathDebug + "probe-absent"
)

func init() {
	debugRead(pathProbeRead, classRead, "probe read", probeReader.ProbeRead)
	debugRead(pathProbeRoot, classRoot, "probe root", probeRooter.ProbeRoot)
	debugRead(pathProbeAbsent, classRead, "probe absent", probeAbsent.ProbeAbsent)
}

// debugSource serves the probe views it implements under the access it names
type debugSource struct {
	fakeSource
	access DebugAccess
}

func (debugSource) ProbeRead() probeView { return probeView{Name: "read"} }

func (debugSource) ProbeRoot() probeView { return probeView{Name: "root"} }

func (s debugSource) DebugAccess() DebugAccess { return s.access }

// get answers one GET with its status and body
func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	response, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}

// injected serves src as a daemon would, with every connection reporting caller
func injected(t *testing.T, src Source, caller Caller) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(Handler(src))
	server.Config.ConnContext = func(ctx context.Context, _ net.Conn) context.Context { return withCaller(ctx, caller) }
	server.Start()
	t.Cleanup(server.Close)
	return server
}

// the caller is this test's own process, which is the daemon's own user to the server
// so both classes answer over a real socket
func TestDebugPathsTakeRootOrTheDaemonsOwnUser(t *testing.T) {
	path := socketPath(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go Serve(listener, debugSource{access: DebugRoot})

	client := Dial(path).http
	for want, debugPath := range map[string]string{"read": pathProbeRead, "root": pathProbeRoot} {
		status, body := get(t, client, "http://control"+debugPath)
		if status != http.StatusOK || !strings.Contains(body, `"name":"`+want+`"`) {
			t.Errorf("%s answered %d %q to the daemon's own user", debugPath, status, body)
		}
	}
}

// uid 0 reaches the root class of a daemon that runs as another user
func TestDebugAdmitsRootToADaemonOfAnotherUser(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, pathProbeRoot, nil)
	request = request.WithContext(withCaller(request.Context(), Caller{UID: 0}))
	answer := httptest.NewRecorder()
	server := &debugServer{src: debugSource{access: DebugRoot}, access: DebugRoot, euid: 4242}
	server.ServeHTTP(answer, request)
	if answer.Code != http.StatusOK {
		t.Errorf("uid 0 was refused a root path of a daemon at uid 4242 with %d %q", answer.Code, answer.Body)
	}
}

// a source that names no access serves its debug paths under root
func TestDebugAccessDefaultsToRoot(t *testing.T) {
	if access := newDebugServer(fakeSource{}).access; access != DebugRoot {
		t.Errorf("a source naming no access serves under %q", access)
	}
}

// another user is refused the root class with the rule and its own uid
// it still reads what the socket's group reads
// a root call let in by --debug-access group is logged with its uid and pid
func TestDebugRefusesAnotherUserTheRootClass(t *testing.T) {
	server := injected(t, debugSource{access: DebugRoot}, Caller{UID: 4242, PID: 77})
	status, body := get(t, server.Client(), server.URL+pathProbeRoot)
	if status != http.StatusForbidden {
		t.Fatalf("uid 4242 reached a root path with %d %q", status, body)
	}
	for _, want := range []string{"uid 4242", "--debug-access root"} {
		if !strings.Contains(body, want) {
			t.Errorf("the refusal reads %q, want it to carry %q", body, want)
		}
	}
	if status, body := get(t, server.Client(), server.URL+pathProbeRead); status != http.StatusOK {
		t.Errorf("uid 4242 was refused a read path with %d %q", status, body)
	}

	logged := &lockedBuffer{}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, nil)))
	group := injected(t, debugSource{access: DebugGroup}, Caller{UID: 4242, PID: 77})
	if status, body := get(t, group.Client(), group.URL+pathProbeRoot); status != http.StatusOK {
		t.Fatalf("--debug-access group refused uid 4242 a root path with %d %q", status, body)
	}
	for _, want := range []string{"path=" + pathProbeRoot, "uid=4242", "pid=77"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("the root call logged %q, want it to carry %q", logged.String(), want)
		}
	}
}

// a connection without credentials cannot be told from anybody
// so it reads what the group reads and nothing more
func TestDebugRefusesTheRootClassWithoutCredentials(t *testing.T) {
	for _, access := range []DebugAccess{DebugRoot, DebugGroup} {
		server := httptest.NewServer(Handler(debugSource{access: access}))
		defer server.Close()
		status, body := get(t, server.Client(), server.URL+pathProbeRoot)
		if status != http.StatusForbidden || !strings.Contains(body, "no credentials") {
			t.Errorf("under %s a connection without credentials reached a root path with %d %q", access, status, body)
		}
		if status, body := get(t, server.Client(), server.URL+pathProbeRead); status != http.StatusOK {
			t.Errorf("under %s a connection without credentials was refused a read with %d %q", access, status, body)
		}
	}
}

// a view the source does not serve is named, which a 404 would not do
func TestDebugNamesAViewTheSourceDoesNotServe(t *testing.T) {
	server := injected(t, debugSource{access: DebugRoot}, Caller{UID: 0})
	status, body := get(t, server.Client(), server.URL+pathProbeAbsent)
	if status != http.StatusNotImplemented || !strings.Contains(body, "probe absent view") {
		t.Errorf("a missing view answered %d %q", status, body)
	}
	status, body = get(t, server.Client(), server.URL+PathDebug+"nothing-here")
	if status != http.StatusNotFound || !strings.Contains(body, "nothing-here") {
		t.Errorf("an unknown debug path answered %d %q", status, body)
	}
}

// --debug-access off refuses every path under the prefix, an unknown one too
// root is no exception
func TestDebugAccessOffRefusesEveryPath(t *testing.T) {
	server := injected(t, debugSource{access: DebugOff}, Caller{UID: 0})
	for _, path := range []string{pathProbeRead, pathProbeRoot, PathDebug + "nothing-here"} {
		status, body := get(t, server.Client(), server.URL+path)
		if status != http.StatusForbidden || !strings.Contains(body, "--debug-access off") {
			t.Errorf("%s answered %d %q under --debug-access off", path, status, body)
		}
	}
	if status, _ := get(t, server.Client(), server.URL+PathStatus); status != http.StatusOK {
		t.Errorf("--debug-access off reached past the debug paths: status answered %d", status)
	}
}

// lockedBuffer takes what a server goroutine logs while the test reads it
type lockedBuffer struct {
	mu   sync.Mutex
	text strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.text.String()
}

// keyMaterialRoom says where under typ key material could sit, or nothing
func keyMaterialRoom(typ reflect.Type, seen map[reflect.Type]bool) string {
	switch {
	case seen[typ]:
		return ""
	case typ == reflect.TypeFor[esp.ChildSA]():
		return "holds an esp.ChildSA"
	case typ.Kind() == reflect.Interface:
		return "holds an interface, which can carry anything"
	case (typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array) && typ.Elem().Kind() == reflect.Uint8:
		return "holds bytes"
	}
	seen[typ] = true
	switch typ.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return keyMaterialRoom(typ.Elem(), seen)
	case reflect.Map:
		if why := keyMaterialRoom(typ.Key(), seen); why != "" {
			return why
		}
		return keyMaterialRoom(typ.Elem(), seen)
	case reflect.Struct:
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() {
				continue
			}
			if why := keyMaterialRoom(field.Type, seen); why != "" {
				return field.Name + " " + why
			}
		}
	}
	return ""
}

// no debug answer has room for key material
// an esp.ChildSA carries its keys as exported fields
// bytes or an interface could carry them as well
func TestDebugWireTypesCarryNoKeyMaterial(t *testing.T) {
	for path, route := range debugRoutes {
		if why := keyMaterialRoom(route.wire, map[reflect.Type]bool{}); why != "" {
			t.Errorf("%s answers with %s, which %s", path, route.wire, why)
		}
	}
	for _, bad := range []any{
		struct{ Key []byte }{},
		struct{ SA *esp.ChildSA }{},
		map[string][]struct{ Nonce [32]byte }{},
		struct{ Attrs map[string]any }{},
	} {
		if keyMaterialRoom(reflect.TypeOf(bad), map[reflect.Type]bool{}) == "" {
			t.Errorf("%T passed as a type without room for key material", bad)
		}
	}
}
