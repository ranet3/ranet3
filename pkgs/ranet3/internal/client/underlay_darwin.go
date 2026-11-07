// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package client

import (
	"ranet3.com/pkgs/ranet3/internal/kernel"
	"ranet3.com/pkgs/ranet3/internal/underlay"
	"ranet3.com/pkgs/ranet3/transport"
)

// underlayRuntime opens the host's one watcher of every interface but the
// mesh, and the selection the hub names each underlay datagram's interface
// from and scopes each socket by, which follows it through a reader of its
// own. It returns a second reader of the same watcher for the network watch,
// which takes it over.
//
// mesh is this node's own tun, which no selection may answer with, and empty
// on a node without one. host is the machine it reads, nil for the one this
// process is running on.
//
// The returned close shuts the selection and then the watcher, and is always
// safe to call.
func underlayRuntime(mesh string, host kernel.Host) (transport.Runtime, kernel.Watcher, func(), error) {
	watcher, err := kernel.ShareWatcher(host, mesh)
	if err != nil {
		return transport.Runtime{}, nil, func() {}, err
	}
	selection, err := kernel.OpenSelection(host, mesh, watcher.Reader())
	if err != nil {
		_ = watcher.Close()
		return transport.Runtime{}, nil, func() {}, err
	}
	closeAll := func() {
		_ = selection.Close()
		_ = watcher.Close()
	}
	return transport.Runtime{Prepare: underlay.Bound(selection.Interface), Selection: selection}, watcher.Reader(), closeAll, nil
}
