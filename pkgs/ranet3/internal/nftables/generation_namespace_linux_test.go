// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package nftables

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netnstest"
)

// The generation moves by one at each committed transaction, however many
// requests it carries and whichever socket sent it, and stays where a
// transaction commits nothing or the kernel refuses it. Each read asks for no
// ack, and the next request on the socket is answered as its own. A read on a
// closed socket answers 0 with its error.
func TestNftablesGenerationMovesByOneACommittedTransaction(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the real nftables path needs root on linux")
	}
	netnstest.EnterEmptyLoopbackDown(t)
	conn, other := dial(t), dial(t)
	generation := func() uint32 {
		t.Helper()
		g, err := conn.Generation()
		if err != nil {
			t.Fatalf("read the generation: %v", err)
		}
		return g
	}
	start := generation()
	if g, err := other.Generation(); err != nil || g != start {
		t.Fatalf("another socket of the namespace read %d (err %v), want %d", g, err, start)
	}
	table := NewTable(unix.NFPROTO_INET, Table)
	chain := Chain{Table: Table, Name: "forward", Type: "filter", Hook: unix.NF_INET_FORWARD}
	for _, step := range []struct {
		what     string
		via      *Conn
		requests []Request
		fails    bool
		moved    uint32
	}{
		{"a table and a chain in one transaction", conn, []Request{table, chain.Create(unix.NFPROTO_INET)}, false, 1},
		{"another socket's chain", other, []Request{Chain{Table: Table, Name: "other", Type: "filter", Hook: unix.NF_INET_LOCAL_IN}.Create(unix.NFPROTO_INET)}, false, 1},
		{"the table again, which changes nothing", conn, []Request{table}, false, 0},
		{"a chain in a table that is not there", conn, []Request{Chain{Table: "absent", Name: "forward", Type: "filter", Hook: unix.NF_INET_FORWARD}.Create(unix.NFPROTO_INET)}, true, 0},
	} {
		was := generation()
		err := step.via.Batch(step.requests)
		if (err != nil) != step.fails {
			t.Fatalf("%s answered %v", step.what, err)
		}
		if got := generation() - was; got != step.moved {
			t.Errorf("%s moved the generation by %d, want %d", step.what, got, step.moved)
		}
	}
	closed := dial(t)
	_ = closed.Close()
	if g, err := closed.Generation(); err == nil || g != 0 {
		t.Errorf("a read on a closed socket answered %d with %v, want 0 and an error", g, err)
	}
}
