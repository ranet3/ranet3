// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package control

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/statefile"
)

// MaxSocketPath is the shortest of the platform limits this tree builds for:
// linux allows 108 bytes in sun_path and darwin 104, both including the
// terminator. Binding a longer one fails as "invalid argument", which names
// neither the path nor the limit, so the check is here instead.
const MaxSocketPath = 103

// lockSuffix names the file whose lock says which process owns the socket.
const lockSuffix = ".lock"

// Listen binds the control socket at path, creating its parent directory and
// clearing a socket a previous instance left behind.
//
// Which process owns the path is settled by an exclusive lock on a sibling
// file rather than by dialing the socket to see whether anything answers.
// Dialing answers "is something accepting at this instant", which is a
// different question: a live daemon out of descriptors, one whose backlog is
// full, and one whose socket this user cannot open all fail to answer, and
// unlinking on any of those takes a running node's socket away. The lock also
// closes the window between deciding a socket is stale and binding the
// replacement, where two starting instances could each remove the other's.
//
// A path that is not a socket is refused by name rather than removed: it is
// not this daemon's to take away from whoever put it there.
//
// The lock file outlives the process on purpose. Unlinking it at exit races:
// a second instance can open it and block on the lock, and an unlink between
// those two steps leaves that instance holding a lock on an unlinked inode
// while a third creates the path afresh and locks that, so both believe they
// own the socket. An empty file is the cheaper end of that trade, and a unit
// with RuntimeDirectory set clears it anyway.
func Listen(path string) (net.Listener, error) {
	if len(path)+bindPathExtra > MaxSocketPath {
		return nil, fmt.Errorf("control: socket path is %d bytes, and the directory it is bound in first adds %d, over the %d a unix socket holds: %s", len(path), bindPathExtra, MaxSocketPath, path)
	}
	if err := MakeDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := takeOwnership(path)
	if err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		lock.Close()
		return nil, err
	}
	socket, err := bind(path)
	if err != nil {
		lock.Close()
		return nil, err
	}
	return &ownedListener{Listener: socket, path: path, lock: lock}, nil
}

// bind keeps the socket where only the daemon can reach it until its group
// and mode are set, since a socket bound at path sits there at the mode the
// umask of whoever started the process gives it until the chmod, on linux and
// darwin alike.
func bind(path string) (*net.UnixListener, error) {
	dir, err := os.MkdirTemp(filepath.Dir(path), bindPattern)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	private := filepath.Join(dir, filepath.Base(path))
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: private, Net: "unix"})
	if err == nil {
		// the name it was bound at is gone once it is at path
		socket.SetUnlinkOnClose(false)
		if err = place(private, path); err != nil {
			socket.Close()
		}
	}
	if removed := os.RemoveAll(dir); removed != nil && err == nil {
		socket.Close()
		err = errors.Join(removed, os.Remove(path))
	}
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return socket, nil
}

// place gives the socket at private the daemon's group before the mode that lets a group in
// BSD hands a new socket the group of its directory rather than the process's
func place(private, path string) error {
	if err := os.Lchown(private, -1, os.Getegid()); err != nil {
		return err
	}
	if err := os.Chmod(private, socketMode); err != nil {
		return err
	}
	return os.Rename(private, path)
}

// MakeDirectory creates dir at a mode the daemon's group can traverse. Mkdir
// takes the process umask off the mode it is given, so a unit with a
// restrictive one would otherwise leave a directory nobody but the daemon can
// enter and a socket inside it that says it is group readable. A directory
// that already exists is left exactly as it is.
//
// each missing directory above it is made the same way
// BSD hands a new directory the group of the one above it rather than the process's
// a directory starts with no access and takes the daemon's group before its mode lets that group in
func MakeDirectory(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	if parent := filepath.Dir(dir); parent != dir {
		if err := MakeDirectory(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if err := os.Lchown(dir, -1, os.Getegid()); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("control: %w", err)
	}
	return nil
}

// takeOwnership holds the lock that says this process owns the socket path,
// for as long as it holds the descriptor. A lock another process holds is
// reported rather than waited for, because a second daemon on one path is a
// configuration mistake rather than a queue to join.
func takeOwnership(path string) (*os.File, error) {
	lock, err := statefile.Flock(path + lockSuffix)
	switch {
	case errors.Is(err, unix.EWOULDBLOCK):
		return nil, fmt.Errorf("control: another daemon is already listening on %s, which is why it holds %s", path, path+lockSuffix)
	case err != nil:
		return nil, fmt.Errorf("control: %w", err)
	}
	return lock, nil
}

// clearStale removes the socket a dead instance left behind, and refuses
// anything else at that path. Its caller holds the lock, so nothing is serving
// this path and a socket here is nobody's.
func clearStale(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control: %s exists and is not a socket, so it is not this daemon's to remove", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("control: removing the stale socket: %w", err)
	}
	return nil
}

// ownedListener ties the lock to the socket. Closing unlinks the socket first
// and releases the lock after, so the path is never free for another daemon to
// bind while this one is still unlinking. Only the first Close unlinks, since
// past it the path may be another daemon's.
type ownedListener struct {
	net.Listener
	path   string
	lock   *os.File
	closed sync.Once
	err    error
}

func (l *ownedListener) Close() error {
	l.closed.Do(func() {
		l.err = errors.Join(l.Listener.Close(), os.Remove(l.path), l.lock.Close())
	})
	return l.err
}

// Handler serves src. Every answer is built whole before anything reaches the
// socket, JSON and the scrape alike, because a slow reader must not be able to
// hold the dataplane's lock open.
//
// The reads are always served. The writes are served when src also implements
// [Sink], and refused by name when it does not, rather than answering 404 on a
// path this build does have.
//
// a stream under PathDebug is the exception, written batch by batch as its subscription delivers
// the subscription's queue holds no lock of the node, so a slow reader still holds none open
func Handler(src Source) http.Handler {
	mux := http.NewServeMux()
	answer(mux, PathStatus, func() any { return src.Status() })
	answer(mux, PathNeighbors, func() any { return src.Neighbors() })
	answer(mux, PathRoutes, func() any { return src.Routes() })
	answer(mux, PathSessions, func() any { return src.Sessions() })
	answer(mux, PathPeers, func() any { return src.Peers() })
	scrape(mux, PathMetrics, src)
	sink, _ := src.(Sink)
	act(mux, PathDisable, sink, func(ctx context.Context, s Sink, r Request) (Result, error) {
		return s.SetSubsystem(ctx, r.Subsystem, false)
	})
	act(mux, PathEnable, sink, func(ctx context.Context, s Sink, r Request) (Result, error) {
		return s.SetSubsystem(ctx, r.Subsystem, true)
	})
	act(mux, PathRedial, sink, func(ctx context.Context, s Sink, r Request) (Result, error) { return s.Redial(ctx, r.Peer, r.All) })
	act(mux, PathRekey, sink, func(ctx context.Context, s Sink, r Request) (Result, error) { return s.Rekey(ctx, r.Peer, r.All) })
	act(mux, PathReload, sink, func(ctx context.Context, s Sink, r Request) (Result, error) { return s.Reload(ctx) })
	act(mux, PathDown, sink, func(ctx context.Context, s Sink, r Request) (Result, error) { return s.Down(ctx) })
	act(mux, PathUp, sink, func(ctx context.Context, s Sink, r Request) (Result, error) { return s.Up(ctx) })
	mux.Handle(PathDebug, newDebugServer(src))
	return mux
}

// answer registers one read. The method check is explicit rather than implied
// by there being nothing on this path to write: a POST that falls through to a
// reader looks like a write that succeeded.
func answer(mux *http.ServeMux, path string, read func() any) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if reading(w, r) {
			writeJSON(w, read())
		}
	})
}

// reading lets GET and HEAD through and refuses every other method
func reading(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "this is a read, so it takes a GET", http.StatusMethodNotAllowed)
	return false
}

// writeJSON writes one answer, marshaled whole before anything reaches the socket
func writeJSON(w http.ResponseWriter, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(append(body, '\n'))
}

// scrape registers the one read that is not JSON. A scrape belongs on this
// socket because a node nobody can ask is a node nobody can diagnose, and
// binding a port to read one's own counters is a listener a fleet then has to
// firewall. The render goes into a buffer before anything reaches the socket,
// for the reason [Source] gives.
func scrape(mux *http.ServeMux, path string, src Source) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if !reading(w, r) {
			return
		}
		var body bytes.Buffer
		src.Metrics(&body)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(body.Bytes())
	})
}

// act registers one write.
//
// POST rather than GET, and the method carries the whole separation between
// the two halves of this surface: a reader that reaches one of these paths
// with a GET is refused instead of acting, and none of the reads answers
// anything but GET and HEAD. POST rather than PUT because none of the verbs is
// idempotent, a second rekey being a second exchange rather than the same one
// restated.
func act(mux *http.ServeMux, path string, sink Sink, run func(context.Context, Sink, Request) (Result, error)) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		journal(r, "control verb")
		if !writing(w, r) {
			return
		}
		if sink == nil {
			http.Error(w, "this node serves the reads only, so there is nothing here to ask", http.StatusNotImplemented)
			return
		}
		if request, ok := readRequest(w, r); ok {
			result, err := run(r.Context(), sink, request)
			answerResult(w, result, err)
		}
	})
}

// writing lets POST through and refuses every other method, the counterpart of reading
func writing(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodPost {
		return true
	}
	w.Header().Set("Allow", "POST")
	http.Error(w, "this is a write, so it takes a POST", http.StatusMethodNotAllowed)
	return false
}

// readRequest decodes the body of a write, and answers the caller itself where it cannot
func readRequest(w http.ResponseWriter, r *http.Request) (Request, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequest))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return Request{}, false
	}
	var request Request
	// An empty body is the zero request rather than a decode failure, so
	// reload, which reads no field, is asked with nothing at all.
	if len(body) > 0 {
		if err := jsonv2.Unmarshal(body, &request, jsonv2.RejectUnknownMembers(true)); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return Request{}, false
		}
	}
	return request, true
}

// answerResult writes what a write came to
func answerResult(w http.ResponseWriter, result Result, err error) {
	if err != nil {
		// every refusal is a 400 whatever its cause, a node-side failure such
		// as an unwritable state directory too, and the body says why
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, result)
}

// Serve runs the control surface on listener until it is closed, and closes
// every connection it still holds before it returns. It returns nil for an
// ordinary close so a caller can tell a shutdown from a failure.
func Serve(listener net.Listener, src Source) error {
	server := newServer(src)
	err := server.Serve(&boundedListener{Listener: listener, places: make(chan struct{}, maxConnections)})
	if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
		err = nil
	}
	return errors.Join(err, server.Close())
}

// newServer is the configured server, apart so that a test can assert on the
// bounds rather than wait out the ones a live node needs.
func newServer(src Source) *http.Server {
	return &http.Server{
		Handler:     Handler(src),
		ConnContext: connCaller,
		// A unix socket has no network in front of it, so these bound a local
		// client that stops reading rather than an attacker.
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		// A connection that finished a request and went quiet is bounded by
		// this and by nothing else. net/http clears the read deadline between
		// requests and starts ReadHeaderTimeout only once the next request's
		// first byte has arrived, so without this a client holds a goroutine
		// and a descriptor for as long as it likes.
		IdleTimeout: idleTimeout,
		// a handler's panic the server recovers is one of its own errors
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
}

// boundedListener hands out at most cap(places) connections at a time and
// closes the rest as it accepts them.
//
// Closing rather than waiting for a place keeps the accept loop answering
// its own listener: waiting for one would park this goroutine on a
// channel that closing the listener does not wake, so a client holding every
// place would hold up the shutdown for as long as the idle timeout. It is also
// the better answer to give, since a diagnostic that is refused says so at
// once where one that waits looks like a node that has stopped responding.
type boundedListener struct {
	net.Listener
	places chan struct{}
}

func (l *boundedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.places <- struct{}{}:
			return &boundedConn{Conn: conn, places: l.places}, nil
		default:
			conn.Close()
		}
	}
}

type boundedConn struct {
	net.Conn
	places chan struct{}
	closed sync.Once
}

func (c *boundedConn) Close() error {
	err := c.Conn.Close()
	c.closed.Do(func() { <-c.places })
	return err
}
