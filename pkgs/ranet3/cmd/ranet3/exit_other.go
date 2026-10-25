// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build !linux || android

package main

import (
	"fmt"
	"runtime"

	"ranet3.com/pkgs/ranet3/internal/client"
	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/internal/egress"
	"ranet3.com/pkgs/ranet3/internal/events"
)

// newExit refuses cap.egress by name, since this build carries no exit, and a
// node that accepted the capability and carried nothing would advertise itself
// as an exit and drop every flow that took it.
func newExit(*config.Config, *client.Client, *events.Bus) (egress.Exit, error) {
	return nil, fmt.Errorf("egress: cap.egress asks this node to carry other nodes' traffic out of the mesh, and this build for %s carries no exit", runtime.GOOS)
}
