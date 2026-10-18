// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package kernel

import (
	"errors"
	"maps"
	"net/netip"
	"testing"

	"hegel.dev/go/hegel"

	"ranet3.com/pkgs/ranet3/internal/pbt"
)

// raceKeys are the unscoped keys the property moves between this process
// and another program, members' keys and others alike.
var raceKeys = []netip.Prefix{
	netip.MustParsePrefix("128.0.0.0/1"), netip.MustParsePrefix("64.0.0.0/2"),
	netip.MustParsePrefix("1.0.0.0/8"), netip.MustParsePrefix("198.51.100.0/24"),
}

// Over any passes in which this process adds and deletes routes and members
// while another program takes keys, releases them, or releases one right
// after the first add there is refused, even when this process then adds
// there again in the same pass, every dump reads back as this
// process's exactly the keys it holds, each as a member when a member holds
// it, and nothing another program holds.
func TestDarwinDumpReadsBackTheKeysThisProcessHolds(t *testing.T) {
	pbt.Check(t, func(ht *hegel.T) {
		plat, _ := testPlatform(t, Table{}, Runtime{BoundUnderlay: true})
		rib := &raceRIB{t: t, held: map[occupiedKey]int{}, release: map[occupiedKey]bool{}}
		plat.sock, plat.host = rib, rib
		// the routes of this process the fake holds, true for a member
		ours := map[netip.Prefix]bool{}
		check := func(pass int) {
			actual, err := plat.Routes()
			if err != nil {
				ht.Fatalf("pass %d: %v", pass, err)
			}
			got := map[netip.Prefix]bool{}
			for _, r := range actual {
				got[r.Destination] = r.Cover
			}
			if !maps.Equal(got, ours) {
				ht.Fatalf("pass %d reads back %v as this process's, want %v\nheld %v", pass, got, ours, rib.held)
			}
		}
		passes := hegel.Draw(ht, pbt.Spanning(1, 6))
		for pass := range passes {
			check(pass)
			for range hegel.Draw(ht, pbt.Spanning(0, 8)) {
				destination := raceKeys[hegel.Draw(ht, pbt.Spanning(0, len(raceKeys)-1))]
				key := occupiedKey{destination: destination}
				add := func() {
					member := hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
					err := plat.AddRoute(Route{Destination: destination, Cover: member})
					switch {
					case err == nil:
						ours[destination] = member
					case !errors.Is(err, errRouteSkipped):
						ht.Fatalf("pass %d: add at %s: %v", pass, destination, err)
					}
				}
				switch hegel.Draw(ht, pbt.Spanning(0, 4)) {
				case 0:
					// another program takes a free key, and either keeps it or
					// gives it up right after the first add there is refused
					if _, held := rib.held[key]; !held {
						rib.held[key] = raceForeignIndex
						rib.release[key] = hegel.Draw(ht, pbt.Spanning(0, 1)) == 1
					}
				case 1:
					if rib.held[key] == raceForeignIndex {
						delete(rib.held, key)
						delete(rib.release, key)
					}
				case 2:
					add()
				case 3:
					if member, held := ours[destination]; held {
						if err := plat.DelRoute(Route{Destination: destination, Cover: member}); err != nil {
							ht.Fatalf("pass %d: delete at %s: %v", pass, destination, err)
						}
						delete(ours, destination)
					}
				case 4:
					// the race: another program holds a free key until the
					// first add there is refused, and this process adds there
					// twice in the same pass, a route or a member each time
					if _, held := rib.held[key]; !held {
						rib.held[key], rib.release[key] = raceForeignIndex, true
						add()
						add()
					}
				}
			}
		}
		check(passes)
	})
}
