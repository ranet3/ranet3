// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Package version carries the build's own version string. The control surface
// reports it so a fleet can be asked what it is running without reading a nix
// store path off every node.
package version

import (
	"runtime/debug"
	"strings"
)

// Value is set at link time from version.txt by the nix build, and a plain
// `go build` leaves it at "dev", which is the honest answer for one. Revision
// is the commit the build came from where the build passes one at link time,
// as a nix build of a git checkout does with the short revision, ending in
// -dirty for a modified tree. Otherwise the revision and whether the tree was
// modified come from the toolchain's build info.
var (
	Value    = "dev"
	Revision = ""
)

// String is Value with the revision the build came from, which tells two nodes
// apart during a migration: version.txt moves once per release and the fleet
// converts one node at a time in between.
func String() string {
	revision, modified := VCS()
	if len(revision) > shortRevision {
		revision = revision[:shortRevision]
	}
	switch {
	case revision == "":
		return Value
	case modified:
		return Value + "+" + revision + "-dirty"
	default:
		return Value + "+" + revision
	}
}

// VCS is the revision the build came from and whether its tree had uncommitted changes
func VCS() (revision string, modified bool) {
	if Revision != "" {
		return strings.CutSuffix(Revision, "-dirty")
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	return revision, modified
}
