// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin && !ios

package main

import (
	"errors"
	"log/slog"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/egress/userspace"
	"ranet3.com/pkgs/ranet3/internal/egress/userspace/raw"
	"ranet3.com/pkgs/ranet3/internal/events"
	"ranet3.com/pkgs/ranet3/internal/underlay"
)

// newExit builds the userspace exit, which ends other nodes' connections in
// gVisor's stack and dials each destination from sockets of its own, scoped
// by the node's underlay selection to leave outside the mesh. Its limits fit
// within Go's memory limit as the node's start found it beside the node's own
// heap, else a share of the host's memory, and the descriptors the process
// may open. A process that may open no raw socket, any but root, runs it
// without, and a leaf's own ICMP errors then reach no server.
func newExit(cfg *config.Config, node *client.Client, bus *events.Bus) (egress.Exit, error) {
	selection := node.UnderlaySelection()
	if selection == nil {
		return nil, errors.New("egress: the userspace exit scopes its sockets by the underlay's selection, and this node's transport selects none")
	}
	host, err := userspace.HostMemory()
	if err != nil {
		return nil, err
	}
	limits, err := userspace.Within(userspace.Memory{GoLimit: node.GivenMemoryLimit(), Physical: host.Physical, Node: node.NodeHeap()}, userspace.Files())
	if err != nil {
		return nil, err
	}
	var sockets userspace.Raw
	if opened, err := raw.New(underlay.Bound(selection.Interface)); err != nil {
		slog.Warn("egress: the userspace exit opened no raw socket, so a leaf's own ICMP error about a datagram reaches no server", "err", err)
	} else {
		sockets = opened
	}
	exit, err := userspace.New(*cfg.Egress(), userspace.Runtime{
		Mesh:          userspace.MeshLanes(node.Mesh),
		Platform:      userspace.Darwin(selection.Interface, node.HeldAddress, sockets),
		Limits:        limits,
		MeshAddresses: client.MeshAddresses(cfg),
		Overlay:       cfg.Overlay,
		Steered:       len(cfg.Segments().Egress()) != 0,
		Hooks:         egress.Hooks{Ready: node.SetEgressReady, Republish: node.Republish, Events: bus},
	})
	if err != nil {
		if sockets != nil {
			_ = sockets.Close()
		}
		return nil, err
	}
	return exit, nil
}
