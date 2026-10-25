// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package registry

import (
	"net"

	"ranet3.com/pkgs/ranet3/schema"
)

// PrefersGo is whether endpoint names are looked up through Go's own resolver
// whatever the build, and never through the C library
const PrefersGo = false

// resolverFor looks endpoint names up as the host does, with no mark. On
// android that is bionic's resolver, which Go's net package defers to since
// android has no /etc/resolv.conf for its own.
func resolverFor([]schema.Prefix) *net.Resolver { return net.DefaultResolver }
