// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/schema"
)

type fakeExit struct {
	status   egress.Status
	announce func() []netip.Prefix
	enable   func(bool)
	write    func(frames [][]byte)
}

var _ egress.Exit = (*fakeExit)(nil)

func (f *fakeExit) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (f *fakeExit) SetEnabled(on bool) {
	if f.enable != nil {
		f.enable(on)
	}
}

func (f *fakeExit) Egress(frames [][]byte) {
	if f.write != nil {
		f.write(frames)
	}
}

func (f *fakeExit) Announce() []netip.Prefix {
	if f.announce == nil {
		return nil
	}
	return f.announce()
}

func (f *fakeExit) Status() egress.Status { return f.status }

// The status renders an exit's Status field for field, its families ready
// from the exit's own word rather than from what the capability advertises,
// and the rules' counters from the backend's detail, zero where it has none
func TestStatusRendersTheExitsStatusFieldForField(t *testing.T) {
	passAt := time.Date(2026, 10, 25, 7, 0, 0, 0, time.UTC)
	advertise := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	status := egress.Status{
		Backend: "nftables", Where: "nftables table ip and ip6 ranet3 chain egress",
		Ready4: true, Unready: "ipv6 is not forwarded", Skipped: "ipv6 has no member to read from",
		Advertise: advertise, Announced: advertise[:1],
		Translate: []egress.Class{
			{From: schema.MustPrefix("0.0.0.0/0"), To: egress.Translation{Addr: netip.MustParseAddr("198.51.100.7")}},
			{From: schema.MustPrefix("198.51.100.0/24"), To: egress.Translation{None: true}},
		},
		Return: true,
		PassAt: passAt, Err: "list rules: no",
		Rules: &egress.Rules{Installed: 3, Flows: 5, Bytes: 420, Untranslated: 2, Conflicts: []string{"ip table nat chain POSTROUTING at priority 100"}},
	}
	want := control.EgressStatus{
		Enabled: true, Where: status.Where,
		Ready: []string{"ipv4"}, Unready: status.Unready, Skipped: status.Skipped,
		Translate: []control.EgressClass{
			{From: netip.MustParsePrefix("0.0.0.0/0"), To: "198.51.100.7"},
			{From: netip.MustParsePrefix("198.51.100.0/24"), To: "none"},
		},
		Return:    true,
		Advertise: advertise, Announced: advertise[:1],
		PassAt: passAt, Installed: 3, Flows: 5, Bytes: 420, Untranslated: 2,
		Conflicts: status.Rules.Conflicts, Err: status.Err,
	}
	c := writable(t)
	if got := c.exitStatus(); !reflect.DeepEqual(got, control.EgressStatus{}) {
		t.Errorf("a node with no exit reports %+v, want the capability off", got)
	}
	exit := &fakeExit{status: status}
	c.SetExit(exit)
	if got := c.exitStatus(); !reflect.DeepEqual(got, want) {
		t.Errorf("the status renders\n%+v\nwant\n%+v", got, want)
	}
	exit.status.Ready4, exit.status.Ready6, exit.status.Rules = false, true, nil
	want.Ready, want.Installed, want.Flows, want.Bytes, want.Untranslated, want.Conflicts = []string{"ipv6"}, 0, 0, 0, 0, nil
	if got := c.exitStatus(); !reflect.DeepEqual(got, want) {
		t.Errorf("an exit holding no rules renders\n%+v\nwant\n%+v", got, want)
	}
}
