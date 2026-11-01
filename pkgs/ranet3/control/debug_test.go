// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"cmp"
	"context"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/esp"
	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// probeView stands in for a view no source serves
type probeView struct {
	Name string `json:"name"`
}

type probeAbsent interface{ ProbeAbsent() probeView }

const pathProbeAbsent = PathDebug + "probe-absent"

func init() {
	debugRead(pathProbeAbsent, "probe absent", probeAbsent.ProbeAbsent)
}

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

// served serves src as a daemon would, to connections that name no caller
func served(t *testing.T, src Source) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(Handler(src))
	t.Cleanup(server.Close)
	return server
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

// egressSource and segmentsSource serve their views empty
type (
	egressSource   struct{ fakeSource }
	segmentsSource struct{ fakeSource }
)

func (egressSource) DebugEgress() EgressInfo { return EgressInfo{} }

func (segmentsSource) DebugSegments() SegmentsInfo { return SegmentsInfo{} }

// debugCall is how a test asks one debug path, of a source that serves it
type debugCall struct {
	src                 Source
	method, query, body string
}

// whoever can open the socket reaches every debug path, so a caller other than root is refused none
// each path the daemon serves answers it from its source, and a path this package's tests register answers anything but a refusal or a 404
// a registered path that is neither fails, so a new daemon path joins the map
func TestEveryDebugPathAnswersACallerOtherThanRoot(t *testing.T) {
	daemon := map[string]debugCall{
		PathDebugEgress:   {src: egressSource{}},
		PathDebugEvents:   {src: &eventSource{}},
		PathDebugNetmon:   {src: &netmonSource{}},
		PathDebugPMTU:     {src: pmtuSource{asked: make(chan string, 1)}, query: "peer=example%2Fbravo"},
		PathDebugProbe:    {src: &netmonSource{}, method: http.MethodPost, body: `{"all":true}`},
		PathDebugRoute:    {src: &routeSource{}, query: "src=0.0.0.0&dst=203.0.113.1&iif=lan0"},
		PathDebugRules:    {src: &rulesSource{}},
		PathDebugRuntime:  {src: plainRuntime{}},
		PathDebugSegments: {src: segmentsSource{}},
		PathDebugTrace:    {src: newTraceSource()},
		PathDebugUpDown:   {src: upDownSource{}},
	}
	paths := maps.Clone(daemon)
	for path := range DebugPaths() {
		switch _, listed := paths[path]; {
		case listed:
		case path == pathProbeAbsent || path == pathProbeStream:
			paths[path] = debugCall{src: fakeSource{}}
		default:
			t.Errorf("%s is registered, and the walk lists it neither as a daemon path nor as a test's", path)
		}
	}
	for path, call := range paths {
		server := injected(t, call.src, Caller{UID: 4242})
		ctx, cancel := context.WithCancel(t.Context())
		url := server.URL + path
		if call.query != "" {
			url += "?" + call.query
		}
		request, err := http.NewRequestWithContext(ctx, cmp.Or(call.method, http.MethodGet), url, strings.NewReader(call.body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		cancel()
		_, daemonPath := daemon[path]
		switch {
		case response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusNotFound:
			t.Errorf("%s refused uid 4242 with %s", path, response.Status)
		case daemonPath && response.StatusCode != http.StatusOK:
			t.Errorf("%s answered uid 4242 with %s", path, response.Status)
		}
	}
}

// probingTraceSource opens traces as traceSource does and takes netmonSource's probe beside them
// it hands over what the log held when the probe reached it
type probingTraceSource struct {
	*traceSource
	probe  *netmonSource
	logged *lockedBuffer
	held   chan string
}

func newProbingTraceSource(logged *lockedBuffer) probingTraceSource {
	return probingTraceSource{traceSource: newTraceSource(), probe: &netmonSource{}, logged: logged, held: make(chan string, 1)}
}

func (s probingTraceSource) DebugProbe(ctx context.Context, peer string, all bool) (Result, error) {
	select {
	case s.held <- s.logged.String():
	default:
	}
	return s.probe.DebugProbe(ctx, peer, all)
}

// journaling sends the default logger to a buffer for the test's span
func journaling(t *testing.T) *lockedBuffer {
	t.Helper()
	logged := &lockedBuffer{}
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(logged, nil)))
	return logged
}

// journaledLine is the last logged line that names path, or empty
func journaledLine(logged *lockedBuffer, path string) string {
	var line string
	for candidate := range strings.Lines(logged.String()) {
		if slices.Contains(strings.Fields(candidate), "path="+path) {
			line = candidate
		}
	}
	return line
}

// a probe and a trace are each journaled with their path and the caller's uid and pid, and a trace with its query too
// the probe's line is written by the time the source is asked
func TestProbeAndTraceAreJournaledWithTheirCaller(t *testing.T) {
	logged := journaling(t)
	src := newProbingTraceSource(logged)
	server := injected(t, src, Caller{UID: 4242, PID: 77})
	if answer := post(t, server.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusOK || !src.probe.all {
		t.Errorf("uid 4242 asking for a probe was answered %s and reached the source as %+v", answer.Status, src.probe)
	}
	select {
	case held := <-src.held:
		if !strings.Contains(held, "path="+PathDebugProbe) {
			t.Errorf("the probe reached its source while the log held %q", held)
		}
	case <-time.After(testWait):
		t.Error("the probe never reached its source")
	}
	if response := open(t, server, PathDebugTrace+"?dst=192.0.2.0/24&payload=64"); response.StatusCode != http.StatusOK {
		t.Fatalf("uid 4242 opening a trace was answered %s", response.Status)
	}
	src.nextTrace(t)
	for path, wants := range map[string][]string{
		PathDebugProbe: {"uid=4242", "pid=77"},
		PathDebugTrace: {"uid=4242", "pid=77", "dst=192.0.2.0/24&payload=64"},
	} {
		line := journaledLine(logged, path)
		for _, want := range wants {
			if !strings.Contains(line, want) {
				t.Errorf("%s was journaled as %q, want it to carry %q", path, line, want)
			}
		}
	}
}

// a probe or a trace is journaled before the route's own checks, so one refused for its method or its query leaves its line too
func TestProbeAndTraceAreJournaledBeforeTheirChecks(t *testing.T) {
	logged := journaling(t)
	server := injected(t, newProbingTraceSource(logged), Caller{UID: 4242, PID: 77})
	if status, _ := get(t, server.Client(), server.URL+PathDebugProbe); status != http.StatusMethodNotAllowed {
		t.Errorf("a GET of the probe was answered %d", status)
	}
	if status, _ := get(t, server.Client(), server.URL+PathDebugTrace+"?dst=nowhere"); status != http.StatusBadRequest {
		t.Errorf("a trace of dst=nowhere was answered %d", status)
	}
	for path, want := range map[string]string{PathDebugProbe: "uid=4242", PathDebugTrace: "dst=nowhere"} {
		if line := journaledLine(logged, path); !strings.Contains(line, want) {
			t.Errorf("%s, refused, was journaled as %q, want it to carry %q", path, line, want)
		}
	}
}

// a request on a connection that named no caller is journaled with its path, and a trace's query, and no uid or pid, rather than as uid 0
func TestUnnamedCallerIsJournaledWithoutUIDOrPID(t *testing.T) {
	logged := journaling(t)
	src := newProbingTraceSource(logged)
	server := served(t, src)
	if answer := post(t, server.URL+PathDebugProbe, `{"all":true}`); answer.StatusCode != http.StatusOK {
		t.Errorf("an unnamed caller asking for a probe was answered %s", answer.Status)
	}
	if response := open(t, server, PathDebugTrace+"?dst=192.0.2.0/24"); response.StatusCode != http.StatusOK {
		t.Fatalf("an unnamed caller opening a trace was answered %s", response.Status)
	}
	src.nextTrace(t)
	for path, want := range map[string]string{PathDebugProbe: "path=" + PathDebugProbe, PathDebugTrace: "dst=192.0.2.0/24"} {
		line := journaledLine(logged, path)
		if !strings.Contains(line, want) || strings.Contains(line, "uid=") || strings.Contains(line, "pid=") {
			t.Errorf("%s from an unnamed caller was journaled as %q, want it to carry %q and no uid or pid", path, line, want)
		}
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

// a view the source does not serve is named, which a 404 would not do
func TestDebugNamesAViewTheSourceDoesNotServe(t *testing.T) {
	server := served(t, fakeSource{})
	status, body := get(t, server.Client(), server.URL+pathProbeAbsent)
	if status != http.StatusNotImplemented || !strings.Contains(body, "probe absent view") {
		t.Errorf("a missing view answered %d %q", status, body)
	}
	status, body = get(t, server.Client(), server.URL+PathDebug+"nothing-here")
	if status != http.StatusNotFound || !strings.Contains(body, "nothing-here") {
		t.Errorf("an unknown debug path answered %d %q", status, body)
	}
}

// a raw call hands back the daemon's own answer, a redirect included, rather than the answer it leads to
func TestRawHandsBackARedirect(t *testing.T) {
	path := socketPath(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go Serve(listener, fakeSource{})
	response, err := Dial(path).Raw(t.Context(), http.MethodGet, strings.TrimSuffix(PathDebug, "/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode/100 != 3 {
		t.Errorf("a path the daemon redirects answered %s through a raw call", response.Status)
	}
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
		for field := range typ.Fields() {
			// a trace's payload is the bytes of the packets it asked for, which hold none of this node's keys
			// it is exempt by name, so any other field of bytes still fails
			if !field.IsExported() || typ == reflect.TypeFor[TracePacket]() && field.Name == "Payload" {
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
		struct{ Payload []byte }{},
	} {
		if keyMaterialRoom(reflect.TypeOf(bad), map[reflect.Type]bool{}) == "" {
			t.Errorf("%T passed as a type without room for key material", bad)
		}
	}
}
