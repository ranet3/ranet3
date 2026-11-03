// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/config"
)

// configured is a file the config names, by its field
type configured struct{ field, path string }

// wait is the start's wait for the key and the trust document its config names. Each look reads the config again, so the
// build takes the file as the wait last read it.
type wait struct {
	path string
	load func(string) (*config.Config, error)
	mu   sync.Mutex
	cfg  *config.Config
	// files holds each file of the last look, true while it is missing and false once its stat failed otherwise
	files map[configured]bool
	ended bool
}

// await waits until no file the config names is missing, and reports false where asked ends the wait first. The control
// socket, bound before it, answers through the wait meanwhile and stays bound for the node's server.
func (d *daemon) await(load func(string) (*config.Config, error), asked <-chan struct{}) (bool, error) {
	w := &wait{path: d.opts.configPath, load: load, cfg: d.cfg}
	if !w.look() {
		return true, nil
	}
	if d.control != nil {
		h := newHandover(d.control)
		d.control = h
		defer serveWait(h, w)()
	}
	tick := time.NewTicker(authPoll)
	defer tick.Stop()
	for {
		select {
		case <-asked:
			slog.Info("stopping in the wait for a file the config names")
			return false, nil
		case <-tick.C:
		}
		if ended, err := w.next(); ended {
			d.cfg = w.cfg
			return true, err
		}
	}
}

// look stats each file w.cfg names and reports whether one is missing. It warns as the wait for a file begins and as a stat
// fails otherwise, which ends the wait for that file so the build reports it, and logs a file that came once it was missing.
func (w *wait) look() (missing bool) {
	was := w.files
	w.files = map[configured]bool{}
	for _, f := range []configured{{"auth.key", w.cfg.Auth.Key}, {"auth.trust", w.cfg.Auth.Trust}} {
		waiting, looked := was[f]
		if looked && !waiting {
			w.files[f] = false
			continue
		}
		_, err := os.Stat(f.path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if !waiting {
				slog.Warn("waiting for a file the config names to exist", "field", f.field, "path", f.path)
			}
			w.files[f] = true
			missing = true
		case err != nil:
			slog.Warn("the stat of a file the config names failed, so the start waits for it no longer", "field", f.field, "path", f.path, "err", err)
			w.files[f] = false
		case waiting:
			slog.Info("a file the start waited for exists", "field", f.field, "path", f.path)
		}
	}
	return missing
}

// next reads the config again and looks on the paths of the last config the loader took, and reports whether the wait
// ended and the read's refusal, which refuses the start where the wait ends
func (w *wait) next() (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	cfg, err := w.load(w.path)
	if err == nil {
		w.cfg = cfg
	}
	w.ended = !w.look()
	return w.ended, err
}

// ServeHTTP answers the control socket while the start waits. A reload reads the config as a look does and answers as the
// node's does, with the file's refusal or success, and every other request is refused with the files the start waits for.
func (w *wait) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.ended:
		http.Error(rw, "the daemon's wait for the files "+w.path+" names has ended, so ask the node once it serves", http.StatusServiceUnavailable)
	case r.URL.Path != control.PathReload || r.Method != http.MethodPost:
		var waited []string
		for f, missing := range w.files {
			if missing {
				waited = append(waited, f.field+" "+f.path)
			}
		}
		slices.Sort(waited)
		http.Error(rw, "the daemon waits for "+strings.Join(waited, " and ")+" to exist, and answers only a reload until then", http.StatusServiceUnavailable)
	default:
		if _, err := w.load(w.path); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(control.Result{Acted: []string{w.path},
			Detail: "Re-read " + w.path + ", which the daemon builds from once the files it names exist"})
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(append(body, '\n'))
	}
}

// serveWait serves w on h until the stop it returns, which waits for the answers under way
func serveWait(h *handover, w *wait) (stop func()) {
	server := &http.Server{Handler: w, ReadTimeout: control.ReadTimeout, WriteTimeout: control.ReadTimeout,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn)}
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(&turn{handover: h, ended: make(chan struct{})})
	}()
	return func() {
		_ = server.Shutdown(context.Background())
		<-served
	}
}

// handover is the control socket from its bind to the daemon's close. One goroutine accepts on it for the wait's server
// and then the node's, so the socket stays bound between the two and a connection that comes between them waits for the
// node's.
type handover struct {
	net.Listener
	accepted chan accepted
	closed   chan struct{}
	once     sync.Once
}

type accepted struct {
	conn net.Conn
	err  error
}

func newHandover(socket net.Listener) *handover {
	h := &handover{Listener: socket, accepted: make(chan accepted), closed: make(chan struct{})}
	go func() {
		for {
			conn, err := socket.Accept()
			select {
			case h.accepted <- accepted{conn, err}:
			case <-h.closed:
				if conn != nil {
					_ = conn.Close()
				}
				return
			}
		}
	}()
	return h
}

// Accept is the node's turn, which lasts until the socket closes
func (h *handover) Accept() (net.Conn, error) { return h.take(nil) }

// take hands over the next connection, until ended or the socket closes. A turn ended before take takes nothing, where the
// select alone picks at random between ended and a connection that waits.
func (h *handover) take(ended <-chan struct{}) (net.Conn, error) {
	select {
	case <-ended:
		return nil, net.ErrClosed
	default:
	}
	select {
	case a := <-h.accepted:
		return a.conn, a.err
	case <-ended:
	case <-h.closed:
	}
	return nil, net.ErrClosed
}

func (h *handover) Close() error {
	h.once.Do(func() { close(h.closed) })
	return h.Listener.Close()
}

// turn is the wait's turn at the handover, which its close ends with the socket still bound
type turn struct {
	*handover
	ended chan struct{}
	once  sync.Once
}

func (t *turn) Accept() (net.Conn, error) { return t.take(t.ended) }

func (t *turn) Close() error {
	t.once.Do(func() { close(t.ended) })
	return nil
}
