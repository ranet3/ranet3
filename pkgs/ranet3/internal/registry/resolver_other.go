// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build (!linux && !darwin) || android || ios

package registry

import (
	"net"

	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/schema"
)

// PrefersGo is whether endpoint names are looked up through Go's own resolver
// whatever the build, and never through the C library
const PrefersGo = false

// resolverFor prepares no query socket of an endpoint lookup, and never calls
// the Prepare it is handed.
func resolverFor([]schema.Prefix, underlay.Prepare) *net.Resolver { return net.DefaultResolver }
