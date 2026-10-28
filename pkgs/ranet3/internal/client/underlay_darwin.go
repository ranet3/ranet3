// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"log/slog"
	"path/filepath"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayStatePath is where the record of the routes this process wrote
// outlives it, beside the control socket's lock: the two are the files in that
// directory saying what this process owns, and a RuntimeDirectory= unit clears
// both on a clean boot.
//
// It is a variable rather than a constant because the record is an ownership
// claim over routes on an interface the whole machine shares, and a test that
// took the real one would reclaim a running daemon's. Nothing in the daemon
// writes it.
var underlayStatePath = filepath.Join(filepath.Dir(control.DefaultSocket), "underlay.json")

// underlayRuntime opens the selection the hub names each underlay datagram's
// interface from, and under link.underlay.bind the defaults the reconciler
// scopes to the interface the host's own default leaves by at the start, while
// an unscoped route out of another interface holds a family's zero address or
// the reconciler is about to install one.
//
// mesh is this node's own tun, which no selection and no lookup may answer
// with. host is the machine they read and write, nil for the one this process
// is running on.
//
// The returned close is always safe to call.
func underlayRuntime(underlay transport.Underlay, mesh string, host kernel.Host) (transport.Runtime, kernel.CaptureRoutes, func(), error) {
	selection, err := kernel.OpenSelection(host, mesh)
	if err != nil {
		return transport.Runtime{}, nil, func() {}, err
	}
	rt := transport.Runtime{Selection: selection}
	if !underlay.Bind {
		return rt, nil, func() { _ = selection.Close() }, nil
	}
	links, err := kernel.WatchLinksOn(host, mesh)
	if err != nil {
		_ = selection.Close()
		return transport.Runtime{}, nil, func() {}, err
	}
	routes, err := kernel.NewUnderlayDefaults(host, links, links.Mesh(), underlayStatePath)
	if err != nil {
		_ = links.Close()
		_ = selection.Close()
		return transport.Runtime{}, nil, func() {}, err
	}
	close := func() {
		// The routes first: they are withdrawn through the route socket this
		// owns, and the link watcher is only a notification channel.
		_ = routes.Close()
		_ = links.Close()
		_ = selection.Close()
	}
	index, err := links.DefaultInterface()
	if err != nil {
		slog.Warn("client scopes no default to an uplink", "err", err, "detail", "the host has no default route at the start")
		return rt, routes, close, nil
	}
	if err := routes.Prepare(index); err != nil {
		close()
		return transport.Runtime{}, nil, func() {}, err
	}
	return rt, routes, close, nil
}
