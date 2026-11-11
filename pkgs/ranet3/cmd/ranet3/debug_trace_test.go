// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

// serveTrace answers a trace with a stream.live note and one record, then where held holds the stream open until its
// reader goes, and otherwise ends it
// it keeps the query of each trace it was asked
func serveTrace(t *testing.T, held bool) (string, chan url.Values) {
	t.Helper()
	path := socketPath(t)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	asked := make(chan url.Values, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked <- r.URL.Query()
		fmt.Fprintln(w, `{"note":{"at":"2026-10-28T19:30:00Z","kind":"stream.live"}}`)
		fmt.Fprintln(w, `{"packet":{"time":"2026-10-28T19:30:00.001Z","arrival":"session","from":"example/gateway:0@1","decision":"forward","next":"example/relay:1@0","src":"192.0.2.1","dst":"192.0.2.3","proto":17,"hop_limit":64,"length":48,"payload":"RQAAMA=="}}`)
		w.(http.Flusher).Flush()
		if held {
			<-r.Context().Done()
		}
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return path, asked
}

// debug trace prints what the daemon streams until --for has passed, then exits 0, and under --json the wire lines
// its flags reach the daemon as the query they spell
func TestDebugTracePrintsUntilItsBound(t *testing.T) {
	socket, asked := serveTrace(t, true)
	out, err := executeBounded(t, "--for", answerBound, "debug", "trace", "--control", socket,
		"--src", "192.0.2.1", "--dst", "192.0.2.0/24", "--proto", "udp", "--decision", "forward", "--peer", "gateway", "--rate", "5", "--payload", "64")
	if err != nil || !strings.Contains(out, "stream.live") ||
		!strings.Contains(out, "forward udp 192.0.2.1 > 192.0.2.3 arrival=session from=example/gateway:0@1 next=example/relay:1@0 hop_limit=64 length=48") {
		t.Errorf("debug trace printed %q and ended with %v", out, err)
	}
	want := url.Values{"src": {"192.0.2.1/32"}, "dst": {"192.0.2.0/24"}, "proto": {"17"}, "decision": {"forward"}, "peer": {"gateway"}, "rate": {"5"}, "payload": {"64"}}
	if got := <-asked; got.Encode() != want.Encode() {
		t.Errorf("the daemon was asked %v, want %v", got, want)
	}
	ending, asked := serveTrace(t, false)
	out, err = execute(t, "debug", "trace", "--for", waitLong.String(), "--json", "--control", ending)
	if err != nil {
		t.Fatalf("debug trace --json ended with %v", err)
	}
	var lines []control.TraceLine
	for text := range strings.Lines(out) {
		var line control.TraceLine
		if err := json.Unmarshal([]byte(text), &line); err != nil {
			t.Fatalf("debug trace --json printed %q: %v", text, err)
		}
		lines = append(lines, line)
	}
	if len(lines) != 2 || lines[0].Note == nil || lines[1].Packet == nil || lines[1].Packet.Next != "example/relay:1@0" {
		t.Errorf("debug trace --json printed %q", out)
	}
	if got := <-asked; got.Encode() != "rate=1000" {
		t.Errorf("a trace naming nothing asked the daemon for %v", got)
	}
}

// --pcap writes the records to its file, made at mode 0600, and the stream's notes to stderr
// under - the same bytes to stdout, and to a file of the caller's of mode 0600 the same bytes and nothing after
func TestDebugTracePcapWritesItsFileOrStdout(t *testing.T) {
	socket, _ := serveTrace(t, false)
	path := filepath.Join(t.TempDir(), "trace.pcapng")
	stdout, stderr, err := executeApart(t, "debug", "trace", "--for", waitLong.String(), "--control", socket, "--payload", "64", "--pcap", path)
	if err != nil || stdout != "" || !strings.Contains(stderr, "stream.live") || strings.Contains(stderr, "forward") {
		t.Fatalf("debug trace --pcap printed %q and %q to stderr, and ended with %v", stdout, stderr, err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the file --pcap wrote is %v, %v, want readable by its owner alone", info, err)
	}
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(file, []byte{0x0a, 0x0d, 0x0d, 0x0a}) || !bytes.Contains(file, []byte("forward udp 192.0.2.1 > 192.0.2.3 arrival=session")) || !bytes.Contains(file, []byte{0x45, 0, 0, 0x30}) {
		t.Errorf("--pcap wrote %x, want a section holding the record and its payload", file)
	}
	stdout, _, err = executeApart(t, "debug", "trace", "--for", waitLong.String(), "--control", socket, "--payload", "64", "--pcap", "-")
	if err != nil || stdout != string(file) {
		t.Errorf("debug trace --pcap - printed %x and ended with %v, want the file's %x", stdout, err, file)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xff}, 2*len(file)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := executeApart(t, "debug", "trace", "--for", waitLong.String(), "--control", socket, "--payload", "64", "--pcap", path); err != nil {
		t.Fatalf("debug trace --pcap of a file of the caller's of mode 0600 ended with %v", err)
	}
	if again, err := os.ReadFile(path); err != nil || !bytes.Equal(again, file) {
		t.Errorf("--pcap wrote %x over a file of the caller's, %v, want %x", again, err, file)
	}
}

// --pcap refuses by name a path that holds anything but a regular file, before the command dials
// and leaves the path and what it names as they were
func TestDebugTracePcapRefusesWhatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	held := []byte("an earlier capture")
	target := filepath.Join(dir, "target.pcapng")
	if err := os.WriteFile(target, held, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pcapng")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "trace.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(filepath.Dir(socketPath(t)), "gone.sock")
	for _, c := range []struct {
		name, path string
		mode       fs.FileMode
	}{
		{"a symbolic link to a file of the caller's of mode 0600", link, fs.ModeSymlink},
		{"a FIFO of the caller's of mode 0600 with a reader", fifo, fs.ModeNamedPipe},
		{"an empty directory of the caller's", sub, fs.ModeDir},
	} {
		_, _, err := executeApart(t, "debug", "trace", "--control", gone, "--payload", "64", "--pcap", c.path)
		if err == nil || !strings.Contains(err.Error(), c.path) || !strings.Contains(err.Error(), "not a regular file") || strings.Contains(err.Error(), "daemon") {
			t.Errorf("debug trace --pcap of %s ended with %v, want a refusal naming it as not a regular file", c.name, err)
		}
		if info, err := os.Lstat(c.path); err != nil || info.Mode().Type() != c.mode {
			t.Errorf("a refused --pcap left %s as %v, %v, want it as it was", c.path, info, err)
		}
	}
	if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, held) {
		t.Errorf("a refused --pcap left the symbolic link's target holding %q, %v, want %q", got, err, held)
	}
}

// --pcap writes a new file of mode 0600 at the path, in place of a file of the caller's of mode 0644
// or of a hard link to one, whose other name keeps what it held, and where the path was missing
// a file it replaces still holds what it held for whoever has it open
func TestDebugTracePcapWritesANewFileAtThePath(t *testing.T) {
	dir := t.TempDir()
	held := []byte("an earlier capture")
	open := filepath.Join(dir, "open.pcapng")
	if err := os.WriteFile(open, held, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o644); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked.pcapng")
	if err := os.WriteFile(linked, held, 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.pcapng")
	if err := os.Link(linked, hard); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.pcapng")
	for _, path := range []string{open, hard, missing} {
		// the file at the path stays open across the call, so its inode stays allocated and the new file cannot take its number
		old, err := os.Open(path)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		var before fs.FileInfo
		if old != nil {
			defer old.Close()
			if before, err = old.Stat(); err != nil {
				t.Fatal(err)
			}
		}
		w, done, err := openPcap(path, nil)
		if err != nil {
			t.Errorf("--pcap of %s ended with %v", path, err)
			continue
		}
		if _, err := w.Write([]byte("packets")); err != nil {
			t.Fatal(err)
		}
		if err := done(); err != nil {
			t.Fatal(err)
		}
		after, err := os.Lstat(path)
		got, readErr := os.ReadFile(path)
		if err != nil || after.Mode() != 0o600 || (before != nil && os.SameFile(before, after)) || readErr != nil || string(got) != "packets" {
			t.Errorf("--pcap of %s left it as %v holding %q, %v %v, want a new file of mode 0600 holding what it wrote", path, after, got, err, readErr)
		}
		if old != nil {
			if kept, err := io.ReadAll(old); err != nil || !bytes.Equal(kept, held) {
				t.Errorf("--pcap of %s left the file it replaced holding %q, %v, want %q", path, kept, err, held)
			}
		}
	}
	if info, err := os.Stat(linked); err != nil || info.Sys().(*syscall.Stat_t).Nlink != 1 {
		t.Errorf("the file the hard link named is %v, %v, want it left with its other name alone", info, err)
	}
	if got, err := os.ReadFile(linked); err != nil || !bytes.Equal(got, held) {
		t.Errorf("--pcap left the file the hard link named holding %q, %v, want %q", got, err, held)
	}
}

// --pcap refuses a FIFO no one reads at once, rather than waiting for a reader
func TestDebugTracePcapRefusesAFifoWithoutWaiting(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "trace.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	refused := make(chan error, 1)
	go func() {
		_, _, err := openPcap(fifo, nil)
		refused <- err
	}()
	select {
	case err := <-refused:
		if err == nil || !strings.Contains(err.Error(), fifo) {
			t.Errorf("--pcap of a FIFO no one reads ended with %v, want a refusal naming it", err)
		}
	case <-time.After(waitLong):
		// a reader lets the open that waits on the FIFO return
		if reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0); err == nil {
			defer reader.Close()
		}
		t.Errorf("--pcap of a FIFO no one reads waited past %v, then ended with %v", waitLong, <-refused)
	}
}

// pcapRaceOpens is how many opens race the planted name, past where the race's measured hit rate under -race leaves a miss negligible
const pcapRaceOpens = 20000

// --pcap never writes a file of the caller's whose name elsewhere a racer links at the path and removes again around the open
func TestDebugTracePcapNeverWritesALinkPlantedAroundTheOpen(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep")
	if err := os.Mkdir(keep, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(keep, "linked.pcapng")
	held := []byte("an earlier capture")
	if err := os.WriteFile(linked, held, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "trace.pcapng")
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Link(linked, path)
			os.Remove(path)
		}
	}()
	defer func() {
		close(stop)
		<-stopped
	}()
	for i := range pcapRaceOpens {
		w, done, err := openPcap(path, nil)
		if err != nil {
			continue
		}
		_, err = w.Write([]byte("packets"))
		if err := errors.Join(err, done()); err != nil {
			t.Fatal(err)
		}
		if got, err := os.ReadFile(linked); err != nil || !bytes.Equal(got, held) {
			t.Fatalf("open %d of %d wrote through the path into %s, which holds %q, %v, want %q", i+1, pcapRaceOpens, linked, got, err, held)
		}
	}
}

// pcapDirRaceOpens is how many opens race the swapped directory, past where the race's measured hit rate without -race leaves a miss negligible
const pcapDirRaceOpens = 100000

// --pcap never removes an empty directory a racer swaps in for the file at the path between the open's look at the path and its removal of the name
func TestDebugTracePcapNeverRemovesADirectorySwappedIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.pcapng")
	var removed atomic.Bool
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-stop:
				return
			default:
			}
			syscall.Unlink(path)
			if os.Mkdir(path, 0o700) != nil {
				continue
			}
			// only the racer and the open remove anything at the path, so a directory already gone was removed by the open
			if err := syscall.Rmdir(path); errors.Is(err, fs.ErrNotExist) {
				removed.Store(true)
			}
		}
	}()
	defer func() {
		close(stop)
		<-stopped
	}()
	for i := range pcapDirRaceOpens {
		if _, done, err := openPcap(path, nil); err == nil {
			if err := done(); err != nil {
				t.Fatal(err)
			}
		}
		if removed.Load() {
			t.Fatalf("by open %d of %d, an open removed a directory swapped in at %s", i+1, pcapDirRaceOpens, path)
		}
	}
}

// a regular file of mode 0600 is refused for an owner other than the caller, named by uid
func TestDebugTracePcapRefusesAnotherUsersFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.pcapng")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := pcapRefusal(path, info); err != nil {
		t.Fatalf("a file of the caller's of mode 0600 was refused: %v", err)
	}
	if err := pcapRefusal(path, ownedByNext{info}); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("uid %d", os.Geteuid()+1)) {
		t.Errorf("a file of uid %d of mode 0600 was answered %v, want a refusal naming its owner", os.Geteuid()+1, err)
	}
}

// ownedByNext is a file's status as if the user of the next uid owned it
type ownedByNext struct{ fs.FileInfo }

func (o ownedByNext) Sys() any {
	st := *o.FileInfo.Sys().(*syscall.Stat_t)
	st.Uid++
	return &st
}

// a flag out of bounds or that does not parse is refused with its value before the command dials
func TestDebugTraceRefusesItsFlagsOutOfBounds(t *testing.T) {
	gone := filepath.Join(filepath.Dir(socketPath(t)), "gone.sock")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--for", "0s"}, "--for"},
		{[]string{"--src", "192.0.2.0/33"}, "192.0.2.0/33"},
		{[]string{"--dst", "example.org"}, "example.org"},
		{[]string{"--proto", "ospf"}, "ospf"},
		{[]string{"--proto", "256"}, "256"},
		{[]string{"--decision", "accept"}, "accept"},
		{[]string{"--rate", "0"}, "rate"},
		{[]string{"--rate", "10001"}, "10001"},
		{[]string{"--payload", "-1"}, "payload"},
		{[]string{"--payload", "65536"}, "65536"},
	} {
		args := append([]string{"debug", "trace", "--control", gone}, c.args...)
		if out, err := execute(t, args...); err == nil || !strings.Contains(err.Error(), c.want) || strings.Contains(err.Error(), "daemon") {
			t.Errorf("%q printed %q and ended with %v, want a refusal naming %q", args, out, err, c.want)
		}
	}
}
