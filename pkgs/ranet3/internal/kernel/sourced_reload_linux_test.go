// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"context"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"ranet3.com/pkgs/ranet3/internal/netlink"
	"ranet3.com/pkgs/ranet3/internal/netstack"
	"ranet3.com/pkgs/ranet3/schema"
)

type sourcedTransactionPlatform struct {
	ordinary          *fakeKernel
	source            *netlinkPlatform
	restorePrefix     netip.Prefix
	failRestoreRead   bool
	unexpectedAddress netip.Prefix
}

func (p *sourcedTransactionPlatform) Routes() ([]Route, error)       { return p.ordinary.Routes() }
func (p *sourcedTransactionPlatform) AddRoute(route Route) error     { return p.ordinary.AddRoute(route) }
func (p *sourcedTransactionPlatform) DelRoute(route Route) error     { return p.ordinary.DelRoute(route) }
func (p *sourcedTransactionPlatform) Addrs() ([]netip.Prefix, error) { return p.ordinary.Addrs() }
func (p *sourcedTransactionPlatform) AddAddr(addr netip.Prefix) error {
	return p.ordinary.AddAddr(addr)
}
func (p *sourcedTransactionPlatform) DelAddr(addr netip.Prefix) error {
	return p.ordinary.DelAddr(addr)
}
func (p *sourcedTransactionPlatform) Rules() ([]Rule, error) { return p.ordinary.Rules() }
func (p *sourcedTransactionPlatform) AddRule(rule Rule) error {
	if err := p.ordinary.AddRule(rule); err != nil {
		return err
	}
	conn := p.source.conn.(*sourcedMirrorConn)
	conn.rules = append(conn.rules, netlink.Message{Kind: unix.RTM_NEWRULE, Data: p.source.ruleMessage(rule)})
	return nil
}
func (p *sourcedTransactionPlatform) DelRule(rule Rule) error {
	if err := p.ordinary.DelRule(rule); err != nil {
		return err
	}
	conn := p.source.conn.(*sourcedMirrorConn)
	for i, message := range conn.rules {
		held, ok := decodeDumpedRule(message)
		if ok && sourcedExactShape(held, rule, p.source.table.Proto) {
			conn.rules = slices.Delete(conn.rules, i, i+1)
			break
		}
	}
	return nil
}
func (p *sourcedTransactionPlatform) where(table Table) string { return p.ordinary.where(table) }
func (p *sourcedTransactionPlatform) Notify() <-chan struct{}  { return nil }
func (p *sourcedTransactionPlatform) Close() error             { return nil }
func (p *sourcedTransactionPlatform) retable(table Table)      { p.source.retable(table) }
func (p *sourcedTransactionPlatform) SourcedRules() ([]DumpedRule, error) {
	return p.source.SourcedRules()
}
func (p *sourcedTransactionPlatform) SourcedRoutes(id schema.TableID) ([]Route, int, error) {
	return p.source.SourcedRoutes(id)
}
func (p *sourcedTransactionPlatform) preflightSourcedOccupancy(table Table, tun string) error {
	return p.source.preflightSourcedOccupancy(table, tun)
}
func (p *sourcedTransactionPlatform) preflightSourcedRemoval() error {
	return p.source.preflightSourcedRemoval()
}
func (p *sourcedTransactionPlatform) removeSourcedKey(r *Reconciler) error {
	return p.source.removeSourcedKey(r)
}
func (p *sourcedTransactionPlatform) standSourced(r *Reconciler, network passNetwork) error {
	return p.source.standSourced(r, network)
}
func (p *sourcedTransactionPlatform) retireSourced(r *Reconciler, routes []Route, staged bool) error {
	return p.source.retireSourced(r, routes, staged)
}
func (p *sourcedTransactionPlatform) mirrorSourced(r *Reconciler, routes []Route) error {
	return p.source.mirrorSourced(r, routes)
}
func (p *sourcedTransactionPlatform) armSourced(r *Reconciler, routes []Route) error {
	return p.source.armSourced(r, routes)
}
func (p *sourcedTransactionPlatform) releaseSourcedGuards(r *Reconciler) error {
	return p.source.releaseSourcedGuards(r)
}
func (p *sourcedTransactionPlatform) retireSourcedStanding(r *Reconciler) error {
	return p.source.retireSourcedStanding(r)
}
func (p *sourcedTransactionPlatform) withdrawSourcedAdmission(r *Reconciler) (bool, error) {
	return p.source.withdrawSourcedAdmission(r)
}
func (p *sourcedTransactionPlatform) clearSourcedStanding() error {
	return p.source.clearSourcedStanding()
}
func (p *sourcedTransactionPlatform) sourcedObserved(r *Reconciler, routes []Route) (SourcedStatus, error) {
	status, err := p.source.sourcedObserved(r, routes)
	if err == nil && r.activeReload != nil && r.table.Sourced != nil &&
		r.table.Sourced.To[0].Prefix == p.restorePrefix {
		if p.failRestoreRead {
			p.ordinary.mu.Lock()
			p.ordinary.failAddrs = unix.EIO
			p.ordinary.mu.Unlock()
		}
		if p.unexpectedAddress.IsValid() {
			p.ordinary.byHand(p.unexpectedAddress, true)
		}
	}
	return status, err
}

func sourcedTransactionHarness(t *testing.T) (*Reconciler, *fakeKernel, *sourcedMirrorConn, func()) {
	t.Helper()
	source, raw := writePlatform(t)
	conn := &sourcedMirrorConn{fakeNetlink: raw}
	source.conn = conn
	old := netip.MustParsePrefix("2001:db8:aa::1/128")
	table := (Table{ID: 200, Proto: DefaultProtocol, Sourced: &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:2::/96")}, ID: 201},
		Addresses: []schema.Prefix{schema.PrefixFrom(old)}, Reconcile: schema.Duration(time.Minute)}).Normalized()
	source.retable(table)
	conn.view = source.sourcedRouteView(201)
	ordinary := newFakeKernel(t)
	plat := &sourcedTransactionPlatform{ordinary: ordinary, source: source}
	mesh := netstack.NewRouteTable()
	mesh.Set(netip.Prefix{}, table.Sourced.To[0].Prefix, &netstack.Peer{ID: "synthetic"})
	mesh.Set(netip.Prefix{}, netip.MustParsePrefix("fd5e:db8:10:3::/96"), &netstack.Peer{ID: "synthetic-next"})
	r := newReconciler(table, Runtime{Interface: "tun7", Overlay: []schema.Prefix{schema.MustPrefix("fd5e:db8:10::/48")}},
		table.Assigned(nil), mesh, plat)
	ctx, cancel := context.WithCancel(context.Background())
	ended := make(chan error, 1)
	go func() { ended <- r.Run(ctx) }()
	select {
	case <-r.FirstPass():
		if err := r.FirstPassError(); err != nil {
			cancel()
			<-ended
			t.Fatalf("initial synthetic policy: %v", err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		<-ended
		t.Fatal("initial synthetic policy did not complete")
	}
	return r, ordinary, conn, func() {
		cancel()
		select {
		case <-ended:
		case <-time.After(3 * time.Second):
			t.Error("synthetic reconciler did not stop")
		}
	}
}

func TestSourcedReloadRestoresOwnedKernelStateAfterFailedAddressWrite(t *testing.T) {
	r, ordinary, _, stop := sourcedTransactionHarness(t)
	defer stop()
	before, err := r.readSourcedReloadState(201)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.routes) == 0 || len(before.rules) == 0 || len(before.addresses) == 0 || len(before.admission) == 0 {
		t.Fatalf("initial owned kernel state did not exercise every reader: %+v", before)
	}
	previous := r.Table()
	next := previous
	other := netip.MustParsePrefix("2001:db8:bb::1/128")
	next.Addresses = []schema.Prefix{schema.PrefixFrom(other)}
	ordinary.failAssign[other] = unix.EIO
	if err := r.SetTable(next, []schema.Prefix{schema.MustPrefix("fd5e:db8:11::/48")}, nil); !errors.Is(err, unix.EIO) {
		t.Fatalf("failed address write returned %v", err)
	}
	after, err := r.readSourcedReloadState(201)
	if err != nil || before.table != after.table ||
		!sameSourcedMembers(before.addresses, after.addresses) ||
		!sameSourcedMembers(before.routes, after.routes) ||
		!sameSourcedMembers(before.rules, after.rules) ||
		!sameSourcedMembers(before.mirror, after.mirror) ||
		!sameSourcedMembers(before.admission, after.admission) ||
		!maps.Equal(before.owned, after.owned) || !reflect.DeepEqual(r.Table(), previous) {
		t.Fatalf("rejected reload changed kernel state or table: read %v", err)
	}
}

func TestSourcedNotificationSurvivesRemovalAndFailedFirstKey(t *testing.T) {
	r, ordinary, _, stop := sourcedTransactionHarness(t)
	defer stop()
	changed := r.SourcedChanges()
	if changed == nil {
		t.Fatal("first key allocated no notification channel")
	}
	select {
	case <-changed:
	default:
		t.Fatal("initial sourced observation did not signal")
	}
	keyed := r.Table()
	keyless := keyed
	keyless.Sourced = nil
	overlay := []schema.Prefix{schema.MustPrefix("fd5e:db8:10::/48")}
	if err := r.SetTable(keyless, overlay, nil); err != nil {
		t.Fatalf("remove key: %v", err)
	}
	if _, present := r.SourcedStatus(); present || r.SourcedChanges() != changed {
		t.Fatal("key removal did not publish absent status on the same channel")
	}
	select {
	case <-changed:
	default:
		t.Fatal("key withdrawal produced no notification")
	}
	before, err := r.readSourcedReloadState(201)
	if err != nil {
		t.Fatal(err)
	}
	other := netip.MustParsePrefix("2001:db8:cc::1/128")
	keyed.Addresses = []schema.Prefix{schema.PrefixFrom(other)}
	ordinary.failAssign[other] = unix.EIO
	if err := r.SetTable(keyed, overlay, nil); !errors.Is(err, unix.EIO) {
		t.Fatalf("failed first key answered %v", err)
	}
	after, err := r.readSourcedReloadState(201)
	if err != nil || !sameSourcedMembers(before.addresses, after.addresses) ||
		!sameSourcedMembers(before.routes, after.routes) ||
		!sameSourcedMembers(before.rules, after.rules) ||
		!sameSourcedMembers(before.mirror, after.mirror) ||
		!sameSourcedMembers(before.admission, after.admission) ||
		!maps.Equal(before.owned, after.owned) || !reflect.DeepEqual(r.Table(), keyless) {
		t.Fatalf("rejected first key left kernel policy or table changed: %v", err)
	}
	if _, present := r.SourcedStatus(); present || r.SourcedChanges() != changed {
		t.Fatal("failed first key published a tentative answer or replaced the channel")
	}
	select {
	case <-changed:
		t.Fatal("rejected first key signaled an uncommitted status")
	default:
	}
}

func TestSourcedReloadConfirmsKernelAfterLostAcknowledgmentOrMainRead(t *testing.T) {
	cases := []struct {
		name    string
		inject  func(*sourcedMirrorConn)
		wantErr error
	}{
		{"lost mirror acknowledgment", func(c *sourcedMirrorConn) { c.failAckOnce = true }, unix.ENOBUFS},
		{"lost main read", func(c *sourcedMirrorConn) { c.failMainOnce = true }, unix.EIO},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, conn, stop := sourcedTransactionHarness(t)
			defer stop()
			before, err := r.readSourcedReloadState(201)
			if err != nil {
				t.Fatal(err)
			}
			status, present := r.SourcedStatus()
			if !present {
				t.Fatal("old kernel policy has no answer")
			}
			changed := r.SourcedChanges()
			<-changed
			previous := r.Table()
			next := previous
			next.Sourced = &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:3::/96")}, ID: 201}
			tc.inject(conn)
			if err := r.SetTable(next, []schema.Prefix{schema.MustPrefix("fd5e:db8:10::/48")}, nil); !errors.Is(err, tc.wantErr) {
				t.Fatalf("uncertain kernel write or read returned %v", err)
			}
			after, err := r.readSourcedReloadState(201)
			current, present := r.SourcedStatus()
			if err != nil || !sameSourcedMembers(before.addresses, after.addresses) ||
				!sameSourcedMembers(before.routes, after.routes) ||
				!sameSourcedMembers(before.rules, after.rules) ||
				!sameSourcedMembers(before.mirror, after.mirror) ||
				!sameSourcedMembers(before.admission, after.admission) ||
				!maps.Equal(before.owned, after.owned) || !reflect.DeepEqual(r.Table(), previous) ||
				!present || !reflect.DeepEqual(status, current) {
				t.Fatalf("uncertain reload published or retained unconfirmed policy: read %v", err)
			}
			select {
			case <-changed:
				t.Fatal("failed reload published tentative answers")
			default:
			}
		})
	}
}

func TestSourcedReloadReportsDegradedWhenMainReadCannotRecover(t *testing.T) {
	r, _, conn, stop := sourcedTransactionHarness(t)
	defer stop()
	previous := r.Table()
	next := previous
	next.Sourced = &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:3::/96")}, ID: 201}
	conn.failMain = true
	err := r.SetTable(next, []schema.Prefix{schema.MustPrefix("fd5e:db8:10::/48")}, nil)
	status, present := r.SourcedStatus()
	if !errors.Is(err, unix.EIO) || err == nil ||
		!strings.Contains(err.Error(), "could not be restored") ||
		!present || status.State != "failing" || !reflect.DeepEqual(r.Table(), previous) {
		t.Fatalf("persistent readback failure claimed a settled policy: error %v, status %+v", err, status)
	}
}

func TestSourcedReloadRejectsUnverifiedRestorationReadback(t *testing.T) {
	cases := []struct {
		name   string
		inject func(*sourcedTransactionPlatform)
		detail string
	}{
		{"unreadable addresses", func(p *sourcedTransactionPlatform) { p.failRestoreRead = true }, "read tun addresses"},
		{"unexpected address", func(p *sourcedTransactionPlatform) {
			p.unexpectedAddress = netip.MustParsePrefix("2001:db8:dd::1/128")
		}, "owned routes, rules, mirror or tun addresses differ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _, conn, stop := sourcedTransactionHarness(t)
			defer stop()
			previous := r.Table()
			next := previous
			next.Sourced = &Sourced{To: []schema.Prefix{schema.MustPrefix("fd5e:db8:10:3::/96")}, ID: 201}
			platform := r.plat.(*sourcedTransactionPlatform)
			platform.restorePrefix = previous.Sourced.To[0].Prefix
			tc.inject(platform)
			conn.failMainOnce = true
			err := r.SetTable(next, []schema.Prefix{schema.MustPrefix("fd5e:db8:10::/48")}, nil)
			status, present := r.SourcedStatus()
			if !errors.Is(err, unix.EIO) || err == nil ||
				!strings.Contains(err.Error(), "could not be restored") ||
				!strings.Contains(err.Error(), tc.detail) ||
				!present || status.State != "failing" || !reflect.DeepEqual(r.Table(), previous) {
				t.Fatalf("unverified kernel readback claimed unchanged policy: error %v, status %+v", err, status)
			}
		})
	}
}
