// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package config

import (
	"strings"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/identity"
	"ranet3.com/pkgs/ranet3/internal/babel"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/pbt"
	"ranet3.com/pkgs/ranet3/schema"
	"ranet3.com/pkgs/ranet3/srv6"
)

// exitPrefix is a prefix a node may advertise or announce, with whether it
// makes its node an exit under exitOverlay, read off routing.md's floors by
// hand: shorter than /8 for IPv4 or /16 for IPv6 outside the overlay, or
// holding the unspecified address
type exitPrefix struct {
	prefix schema.Prefix
	exit   bool
}

// exitOverlay is the overlay every drawn node writes
var exitOverlay = []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff::/20")}

// the loader refuses cap.exit exactly where the model finds the node an exit,
// over drawn cap.egress advertisements, cap.route announcements and an egress
// segment, and refuses it with the refusal's message, while every other drawn
// node loads
func TestExitIsRefusedExactlyOnAnExit(t *testing.T) {
	advertised := []exitPrefix{
		{schema.MustPrefix("0.0.0.0/0"), true}, {schema.MustPrefix("::/0"), true},
		{schema.MustPrefix("64.0.0.0/2"), true}, {schema.MustPrefix("fc00::/7"), true},
		// one bit under the floor and at it, in each family
		{schema.MustPrefix("8.0.0.0/7"), true}, {schema.MustPrefix("8.0.0.0/8"), false},
		{schema.MustPrefix("2000::/15"), true}, {schema.MustPrefix("2000::/16"), false},
		{schema.MustPrefix("198.51.100.0/24"), false}, {schema.MustPrefix("2001:db8:5::/48"), false},
	}
	announced := []exitPrefix{
		{schema.MustPrefix("0.0.0.0/0"), true}, {schema.MustPrefix("2000::/3"), true}, {schema.MustPrefix("fd00::/8"), true},
		{schema.MustPrefix("203.0.113.0/24"), false}, {schema.MustPrefix("2001:db8:300::/64"), false},
		// inside the overlay, which counts nothing however short
		{schema.MustPrefix("192.0.2.128/25"), false}, {schema.MustPrefix("3fff:0:0:2::/64"), false},
	}
	pbt.Check(t, func(ht *hegel.T) {
		var advertise, announce []schema.Prefix
		exit := false
		for _, drawn := range pbt.Subset(ht, advertised, 0, 2) {
			advertise, exit = append(advertise, drawn.prefix), exit || drawn.exit
		}
		for _, drawn := range pbt.Subset(ht, announced, 0, 2) {
			announce, exit = append(announce, drawn.prefix), exit || drawn.exit
		}
		c := Config{
			Node: identity.MustParse("example/laptop"),
			Auth: Auth{Key: "key.pem", Trust: "trust.json"},
			Link: Link{Port: 13000, Endpoints: []Endpoint{{Serial: "0", Family: "ip6"}}},
			Dial: Dial{All: true},
			Cap: Caps{
				Table:  &kernel.Table{},
				Border: &egress.Border{Overlay: exitOverlay},
				Exit:   &kernel.ExitMode{},
			},
		}
		for _, prefix := range announce {
			if c.Cap.Route == nil {
				c.Cap.Route = &babel.Routes{}
			}
			c.Cap.Route.Announce = append(c.Cap.Route.Announce, schema.Announce{Prefix: prefix})
		}
		segment := hegel.Draw(ht, hegel.Booleans())
		if segment {
			allow := []schema.Prefix{schema.MustPrefix("192.0.2.0/24"), schema.MustPrefix("3fff:a::/36")}
			c.Cap.Segment = &srv6.Segments{Local: []srv6.Segment{{SID: schema.MustAddr("3fff:b:0:306::3"), Behavior: srv6.BehaviorEndDT46, Deliver: srv6.DeliverEgress, Allow: allow}}}
			exit = true
		}
		if segment || len(advertise) > 0 {
			c.Cap.Egress = &egress.Egress{Advertise: advertise}
		}
		err := c.Validate()
		switch {
		case exit && (err == nil || !strings.Contains(err.Error(), "and this node is an exit (")):
			ht.Fatalf("advertising %v, announcing %v and an egress segment %v, an exit, loaded with %v, want cap.exit refused", advertise, announce, segment, err)
		case !exit && err != nil:
			ht.Fatalf("advertising %v, announcing %v and an egress segment %v, no exit, was refused: %v", advertise, announce, segment, err)
		}
	})
}
