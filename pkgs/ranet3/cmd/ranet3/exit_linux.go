// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package main

import (
	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	kernelexit "ranet3.com/pkgs/ranet3/internal/egress/kernel"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// newExit builds the kernel exit, which writes what it carries to the mesh's
// tun and translates it with nftables on the way out of the host
func newExit(cfg *config.Config, node *client.Client, bus *events.Bus) (egress.Exit, error) {
	mesh := node.Mesh
	exit, err := kernelexit.New(*cfg.Egress(), kernelexit.Runtime{
		Interface:     mesh.Name,
		Write:         mesh.WriteHost,
		MeshAddresses: client.MeshAddresses(cfg),
		Forwarding:    client.Forwarding,
		Lookup:        client.RouteLookups,
		Sysctl:        client.Sysctl,
		Members:       node.EgressMembers,
		Steered:       len(cfg.Segments().Egress()) != 0,
		// The exit publishes its announcement rather than the config, which
		// is how an exit whose chain does not read back as written withholds
		// its advertisement instead of attracting traffic it would drop.
		// Republish reads it back from the exit.
		Hooks: egress.Hooks{Ready: node.SetEgressReady, Republish: node.Republish, Events: bus},
	})
	if err != nil {
		return nil, err
	}
	return exit, nil
}
