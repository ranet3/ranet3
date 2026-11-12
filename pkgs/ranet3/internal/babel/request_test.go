// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package babel

import (
	"net/netip"
	"testing"
)

// RFC 8966 section 3.8.1.2 forwards a seqno request only "if the hop count is 2 or more, and the node is advertising the prefix to its neighbours", and a node with cap.transit off advertises no prefix it learns
// b, a leaf that selects c's prefix, forwards nothing to c for a request from a it cannot satisfy
func TestTransitOffForwardsNoSeqnoRequest(t *testing.T) {
	fabric := newRoutedFabric(t, Config{}, Routes{}, true, "a-b", "b-c")
	dest := netip.MustParsePrefix("2001:db8:b4::/48")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c")
	if got := fabric.nextHop("b", key); got != "c" {
		t.Fatalf("b reaches the prefix via %q, want c", got)
	}
	sel := fabric.selected("b", key)
	fabric.reset()
	fabric.inject("b", "a", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: sel.seqno + 1, HopCount: 64, RouterID: routerID("c")}))
	if got := seqnoRequestsFor(t, fabric.tlvs("b", "c"), dest); len(got) != 0 {
		t.Errorf("b, with transit off, forwarded %+v for a prefix it does not advertise", got)
	}
}

// with cap.transit off a node answers a route request and a satisfiable seqno request for a prefix it learned with a retraction, which the protocol deviations page lists under sections 3.7.1, 3.8.1.1 and 3.8.1.2
func TestTransitOffAnswersRequestsForALearnedPrefixWithARetraction(t *testing.T) {
	fabric := newRoutedFabric(t, Config{}, Routes{}, true, "a-b", "b-c")
	dest := netip.MustParsePrefix("2001:db8:b2::/48")
	key := routeKey{dest: dest}
	fabric.speakers["c"].Originate(dest)
	fabric.flush("c")
	if got := fabric.nextHop("b", key); got != "c" {
		t.Fatalf("b reaches the prefix via %q, want c", got)
	}
	sel := fabric.selected("b", key)
	for _, request := range []struct {
		name string
		tlv  RawTLV
	}{
		{"route request", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: dest})},
		{"satisfiable seqno request", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: dest, Seqno: sel.seqno, HopCount: 64, RouterID: routerID("c")})},
	} {
		fabric.reset()
		fabric.inject("b", "a", request.tlv)
		if got := updatesFor(t, fabric.tlvs("b", "a"), dest); len(got) != 1 || got[0].Metric != MetricInfinity {
			t.Errorf("b answered a %s with %+v, want 1 retraction", request.name, got)
		}
	}
}
