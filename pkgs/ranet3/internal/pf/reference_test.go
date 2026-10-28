// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package pf

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"ranet3.com/pkgs/ranet3/internal/logtest"
)

// fakeReferences is pf's list of references as -X and -s References see it,
// and the calls made to it in order, DIOCSTARTREF among them
type fakeReferences struct {
	held  []Enabler
	calls []string
	// refuse makes -X fail for a token pf still holds
	refuse bool
	next   uint64
	// again is a freed value the next DIOCSTARTREF hands back, as pf gives a
	// freed token's value to a later reference, zero for a new value
	again uint64
	// stopped counts the releases that left pf no reference, which stop it
	stopped int
}

func (f *fakeReferences) ctl() Ctl {
	return Ctl{run: func(stdin string, args ...string) (string, error) {
		f.calls = append(f.calls, strings.Join(args, " "))
		switch {
		case len(args) == 2 && args[0] == "-X":
			token, err := strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return "", err
			}
			i := slices.IndexFunc(f.held, func(e Enabler) bool { return e.Token == token })
			if i < 0 || f.refuse {
				return "", errors.New("pf: pfctl -X: exit status 1: pfctl: pf: token invalid")
			}
			f.held = slices.Delete(f.held, i, i+1)
			if len(f.held) == 0 {
				f.stopped++
			}
			return "", nil
		case slices.Equal(args, []string{"-s", "References"}):
			if len(f.held) == 0 {
				return "No pf starter references held\n", nil
			}
			out := "TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n"
			for _, e := range f.held {
				out += fmt.Sprintf("%-8d %-28s %-24d 0 days 00:00:01\n", e.PID, e.Name, e.Token)
			}
			return out, nil
		case len(args) == 4 && args[0] == "-a" && args[2] == "-F":
			return "", nil
		}
		return "", fmt.Errorf("pf: the fake has no answer to pfctl %v", args)
	}}
}

func (f *fakeReferences) start() (uint64, error) {
	f.calls = append(f.calls, "DIOCSTARTREF")
	f.next++
	token := 1<<63 + f.next
	if f.again != 0 {
		token, f.again = f.again, 0
	}
	f.held = append(f.held, Enabler{PID: os.Getpid(), Name: "ranet3", Token: token})
	return token, nil
}

func (f *fakeReferences) holds(token uint64) bool {
	return slices.ContainsFunc(f.held, func(e Enabler) bool { return e.Token == token })
}

func recorded(t *testing.T, path string) []held {
	t.Helper()
	references, err := loadReference(path)
	if err != nil {
		t.Fatal(err)
	}
	return references
}

// ours is r's reference as the record holds it
func ours(r *Reference) held { return held{Token: r.Token(), PID: os.Getpid()} }

func writeRecord(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// the token is on disk under this process's pid when take returns, and the
// release gives it back and empties the record
func TestReferenceIsRecordedBeforeTakeReturnsAndEmptiedOnRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	if got := recorded(t, path); !slices.Equal(got, []held{ours(r)}) || r.PID() != os.Getpid() || !f.holds(r.Token()) {
		t.Fatalf("take returned token %d under %d with %+v recorded and pf holding %+v", r.Token(), r.PID(), got, f.held)
	}
	token := r.Token()
	if err := r.Release(); err != nil {
		t.Fatal(err)
	}
	if f.holds(token) || len(recorded(t, path)) != 0 {
		t.Errorf("after the release pf holds %+v and the record %+v", f.held, recorded(t, path))
	}
}

// a close keeps the token held and recorded, and lets the next take claim the
// record
func TestClosedReferenceStaysHeldAndRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	token := r.Token()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.holds(token) || !slices.Equal(recorded(t, path), []held{ours(r)}) || slices.Contains(f.calls, fmt.Sprintf("-X %d", token)) {
		t.Fatalf("after the close pf holds %+v, the record %+v, and take ran %q", f.held, recorded(t, path), f.calls)
	}
	next, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatalf("the next take over a closed record: %v", err)
	}
	t.Cleanup(func() { _ = next.Release() })
	if f.holds(token) {
		t.Errorf("the next take left the closed reference's token held: %+v", f.held)
	}
}

// a renewal after another program ended this process's reference takes a new
// one under this process and records it alone, one after another process came
// to hold the ended token's value leaves that process's reference, and one
// that pf hands the ended value back to, as P14 (a) saw it do, gives back
// nothing it just took
func TestRenewalTakesAndRecordsANewReference(t *testing.T) {
	for name, test := range map[string]struct {
		other []Enabler
		again bool
	}{
		"the value gone":                       {},
		"the value another process's now":      {other: []Enabler{{PID: 99999, Name: "othervpn"}}},
		"the value given back to this process": {again: true},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pf.json")
			f := &fakeReferences{}
			r, err := take(f.ctl(), path, f.start)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Release() })
			ended := r.Token()
			f.held = nil
			for _, e := range test.other {
				e.Token = ended
				f.held = append(f.held, e)
			}
			if test.again {
				f.again = ended
			}
			if err := r.Renew(); err != nil {
				t.Fatal(err)
			}
			if !slices.Contains(f.held, Enabler{PID: os.Getpid(), Name: "ranet3", Token: r.Token()}) || !slices.Equal(recorded(t, path), []held{ours(r)}) || slices.Contains(f.calls, fmt.Sprintf("-X %d", ended)) {
				t.Errorf("the renewal holds token %d, ended %d, with %+v recorded, pf holding %+v, after %q", r.Token(), ended, recorded(t, path), f.held, f.calls)
			}
			if len(test.other) != 0 && !f.holds(ended) {
				t.Errorf("the renewal released another process's reference: %+v", f.held)
			}
		})
	}
}

// a take over a record whose reference pf still lists under its pid takes its
// place, and one over a record pf lists nothing of, or over no record, takes
// none
func TestTakeSaysWhetherItTookAnEarlierRunsPlace(t *testing.T) {
	for name, test := range map[string]struct {
		record string
		held   []Enabler
		want   bool
	}{
		"no record":                   {"", nil, false},
		"a reference pf lists":        {`{"held":[{"token":"42","pid":7}]}`, []Enabler{{PID: 7, Name: "ranet3", Token: 42}}, true},
		"a reference pf ended":        {`{"held":[{"token":"42","pid":7}]}`, nil, false},
		"its value another process's": {`{"held":[{"token":"42","pid":7}]}`, []Enabler{{PID: 8, Name: "othervpn", Token: 42}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pf.json")
			if test.record != "" {
				writeRecord(t, path, test.record)
			}
			f := &fakeReferences{held: test.held}
			r, err := take(f.ctl(), path, f.start)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = r.Release() })
			if r.Inherited() != test.want {
				t.Errorf("the take reads inherited %v, want %v", r.Inherited(), test.want)
			}
		})
	}
}

// a start that takes no reference over the record a crash left empties the
// anchor, gives back the recorded reference pf lists under its pid and empties
// the record, keeps one pf lists under another pid, over no record runs no
// pfctl at all, and over a record pf lists nothing of reads nothing given back
func TestClearGivesBackWhatAnEarlierRunLeft(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{held: []Enabler{{PID: 7, Name: "ranet3", Token: 42}, {PID: 8, Name: "othervpn", Token: 43}}}
	writeRecord(t, path, `{"held":[{"token":"42","pid":7},{"token":"43","pid":7}]}`)
	cleared, err := Clear(f.ctl(), path, "com.apple/ranet3")
	if err != nil || !cleared {
		t.Fatalf("the clear reads cleared %v (%v)", cleared, err)
	}
	flushed := slices.Index(f.calls, "-a com.apple/ranet3 -F rules")
	if flushed < 0 || !slices.Contains(f.calls, "-a com.apple/ranet3 -F Tables") || flushed > slices.Index(f.calls, "-X 42") {
		t.Errorf("the clear ran %q, want the anchor emptied before the release", f.calls)
	}
	if f.holds(42) || !f.holds(43) || slices.Contains(f.calls, "-X 43") || len(recorded(t, path)) != 0 {
		t.Errorf("after the clear pf holds %+v and the record %+v", f.held, recorded(t, path))
	}
	f.calls = nil
	if cleared, err := Clear(f.ctl(), filepath.Join(t.TempDir(), "pf.json"), "com.apple/ranet3"); err != nil || cleared || len(f.calls) != 0 {
		t.Errorf("a clear over no record reads cleared %v (%v) after %q", cleared, err, f.calls)
	}
	// after a reboot pf lists none of the record's references, so nothing is
	// given back, though the anchor and the record are emptied
	ended := filepath.Join(t.TempDir(), "pf.json")
	writeRecord(t, ended, `{"held":[{"token":"44","pid":7}]}`)
	f.calls = nil
	if cleared, err := Clear(f.ctl(), ended, "com.apple/ranet3"); err != nil || cleared || !slices.Contains(f.calls, "-a com.apple/ranet3 -F rules") || len(recorded(t, ended)) != 0 {
		t.Errorf("a clear over an ended reference reads cleared %v (%v) after %q, the record %+v", cleared, err, f.calls, recorded(t, ended))
	}
}

// a clear over a record another process holds is refused by the record's lock
// before it runs pfctl, leaving the record and pf's references as they were
func TestClearIsRefusedTheRecordAnotherHolds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Release() })
	f.calls = nil
	if cleared, err := Clear(f.ctl(), path, "com.apple/ranet3"); err == nil || cleared || len(f.calls) != 0 {
		t.Errorf("a clear of the record a take holds read cleared %v (%v) after %q", cleared, err, f.calls)
	}
	if !f.holds(r.Token()) || !slices.Equal(recorded(t, path), []held{ours(r)}) {
		t.Errorf("after the refused clear pf holds %+v and the record %+v", f.held, recorded(t, path))
	}
}

// a release pf refuses for a recorded token it still lists under the recorded
// pid fails the clear and keeps the token held and recorded, so a later clear,
// once pf gives it back, empties the record
func TestClearKeepsAReferencePfRefusedToGiveBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{held: []Enabler{{PID: 7, Name: "ranet3", Token: 42}}, refuse: true}
	writeRecord(t, path, `{"held":[{"token":"42","pid":7}]}`)
	if _, err := Clear(f.ctl(), path, "com.apple/ranet3"); err == nil {
		t.Fatal("a clear went on past a release pf refused")
	}
	if !f.holds(42) || !slices.Equal(recorded(t, path), []held{{Token: 42, PID: 7}}) {
		t.Errorf("after the refusal pf holds %+v and the record %+v", f.held, recorded(t, path))
	}
	f.refuse = false
	if cleared, err := Clear(f.ctl(), path, "com.apple/ranet3"); err != nil || !cleared || f.holds(42) || len(recorded(t, path)) != 0 {
		t.Errorf("the second clear read cleared %v (%v), pf holding %+v and the record %+v", cleared, err, f.held, recorded(t, path))
	}
}

// a token an earlier run recorded is given back after the new one is taken,
// so pf stays enabled throughout, and the record holds both until it is
func TestEarlierRunsReferenceIsGivenBackAfterTheNewOneIsTaken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{held: []Enabler{{PID: 7, Name: "ranet3", Token: 13143444398357651665}}}
	writeRecord(t, path, `{"held":[{"token":"13143444398357651665","pid":7}]}`)
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Release() })
	if f.holds(13143444398357651665) || f.stopped != 0 {
		t.Errorf("the earlier run's token is still held, or pf stopped %d times: %+v", f.stopped, f.held)
	}
	taken, released := slices.Index(f.calls, "DIOCSTARTREF"), slices.Index(f.calls, "-X 13143444398357651665")
	if taken < 0 || released < taken {
		t.Errorf("take ran %q, want the new reference taken before the earlier one goes back", f.calls)
	}
	if got := recorded(t, path); !slices.Equal(got, []held{ours(r)}) {
		t.Errorf("the record holds %+v, want the new token alone", got)
	}
}

// a recorded token pf refuses and no longer lists, after a reboot or another
// program's pfctl -d, is dropped unreleased and a new reference taken
func TestRecordOfATokenPfNoLongerHoldsIsDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	writeRecord(t, path, `{"held":[{"token":"10568795862022687003","pid":7}]}`)
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Release() })
	if got := recorded(t, path); !slices.Equal(got, []held{ours(r)}) || slices.Contains(f.calls, "-X 10568795862022687003") {
		t.Errorf("the record holds %+v after take ran %q", got, f.calls)
	}
}

// a recorded token pf lists under another pid than the record's is another
// process's reference, since pf gives a freed token's value to later ones:
// it is never released, and the record drops it
func TestRecordedTokenListedUnderAnotherPidIsNeverReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{held: []Enabler{{PID: 8, Name: "othervpn", Token: 42}}}
	writeRecord(t, path, `{"held":[{"token":"42","pid":7}]}`)
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	if !f.holds(42) || slices.Contains(f.calls, "-X 42") || !slices.Equal(recorded(t, path), []held{ours(r)}) {
		t.Errorf("take ran %q, leaving pf holding %+v and the record %+v", f.calls, f.held, recorded(t, path))
	}
	// and this process's own token, once ended and its value given to another, is not released by a stop
	token := r.Token()
	f.held = []Enabler{{PID: 8, Name: "othervpn", Token: token}}
	if err := r.Release(); err != nil || !f.holds(token) || slices.Contains(f.calls, fmt.Sprintf("-X %d", token)) || len(recorded(t, path)) != 0 {
		t.Errorf("the release returned %v, leaving pf holding %+v and the record %+v", err, f.held, recorded(t, path))
	}
}

// a release pf refuses for a token it still lists under the recorded pid
// stops the start and keeps both tokens recorded, so nothing leaks unrecorded
func TestRefusedReleaseOfAHeldTokenKeepsTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{held: []Enabler{{PID: 7, Name: "ranet3", Token: 42}}, refuse: true}
	writeRecord(t, path, `{"held":[{"token":"42","pid":7}]}`)
	if r, err := take(f.ctl(), path, f.start); err == nil {
		_ = r.Release()
		t.Fatal("take went on past a release pf refused for a token it holds")
	}
	got := recorded(t, path)
	if len(got) != 2 || got[1] != (held{Token: 42, PID: 7}) || !f.holds(got[0].Token) || got[0].PID != os.Getpid() {
		t.Errorf("the record holds %+v, pf %+v, after take ran %q", got, f.held, f.calls)
	}
}

// a record that will not parse yields no token, a warning, and a start that
// goes on
func TestCorruptRecordYieldsNoTokenAndAWarning(t *testing.T) {
	var logged bytes.Buffer
	logtest.SetDefault(t, slog.New(slog.NewTextHandler(&logged, nil)))
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	writeRecord(t, path, `{"held":`)
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Release() })
	if want := []string{"DIOCSTARTREF"}; !slices.Equal(f.calls, want) {
		t.Errorf("take ran %q, want %q", f.calls, want)
	}
	if !strings.Contains(logged.String(), "could not read the reference an earlier run recorded") {
		t.Errorf("no warning of the corrupt record in %q", logged.String())
	}
}

// a token no record holds is never released, however its name and pid look:
// one listed under the daemon's name for a process that has gone stays held
func TestUnrecordedTokenIsNeverReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	gone := Enabler{PID: 99999, Name: filepath.Base(os.Args[0]), Token: 9}
	f := &fakeReferences{held: []Enabler{gone}}
	r, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Release(); err != nil {
		t.Fatal(err)
	}
	if !f.holds(9) || slices.Contains(f.calls, "-X 9") {
		t.Errorf("a token no record holds was released: %q", f.calls)
	}
}

// a second process does not take the record a running one holds
func TestSecondTakeOfOneRecordIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pf.json")
	f := &fakeReferences{}
	first, err := take(f.ctl(), path, f.start)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Release() })
	if second, err := take(f.ctl(), path, f.start); err == nil {
		_ = second.Release()
		t.Fatal("a second take claimed a record the first holds")
	}
	if got := recorded(t, path); !slices.Equal(got, []held{ours(first)}) {
		t.Errorf("the record holds %+v, want the first's %d", got, first.Token())
	}
}
