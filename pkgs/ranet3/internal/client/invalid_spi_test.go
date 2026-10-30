// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

const (
	// meshRuns is how many meshes TestConvergedMeshReportsNoInvalidSPI builds, since whether ESP on a new SA beats its install varies from run to run
	meshRuns = 5
	// meshSettle is how long that test waits past convergence for a report
	meshSettle = time.Second
)

// two nodes dialing each other converge on one session and send ESP only on SPIs their SAs hold, so neither tells the other of an SPI
// ESP on a new SA that reaches a node before it installs the SA, and ESP on the SA of the session the preference rule ended, draw no report
func TestConvergedMeshReportsNoInvalidSPI(t *testing.T) {
	for mesh := range meshRuns {
		t.Run(fmt.Sprint(mesh), func(t *testing.T) {
			alpha, bravo := newLoopbackMesh(t)
			_, stop := run(t, alpha, bravo)
			waitFor(t, convergeBudget, "both ends holding the same session and forwarding to each other", func() bool {
				a, aok := preferenceOf(alpha)
				b, bok := preferenceOf(bravo)
				return aok && bok && a == b && reaches(alpha, bravo) && reaches(bravo, alpha)
			})
			time.Sleep(meshSettle)
			stop()
			for _, node := range []*loopbackNode{alpha, bravo} {
				if got := recorded(node.events, "ike.notify.invalid_spi"); len(got) != 0 {
					t.Errorf("%s told its peer of an SPI it holds no SA for: %v", node.name, got)
				}
			}
		})
	}
}

// ESP from alpha's end of the one session on an SPI bravo holds no Child SA for draws bravo's INVALID_SPI report over that session
// bravo's control socket counts it under the session, which both ends keep
// alpha sends again on each look, since a datagram that reached bravo within an interval of another look draws none
func TestSessionsCountTheInvalidSPIReportsSent(t *testing.T) {
	alpha, bravo := newLoopbackMesh(t)
	// bravo answers and never dials, so the one session is alpha's and no resolution replaces it
	quiet := *bravo.cfg
	quiet.Dial.To = nil
	bravo.client.cfg.Store(&quiet)
	run(t, alpha, bravo)
	waitFor(t, convergeBudget, "one session at each end", func() bool {
		return len(alpha.client.sessions.paths()) == 1 && len(bravo.client.sessions.paths()) == 1
	})
	dialed, answered := alpha.client.sessions.snapshot()[0].session, bravo.client.sessions.snapshot()[0].session
	held, _ := answered.ChildSPIs()
	// the complement of the one SPI bravo holds
	stray := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(nil, ^held), 1)
	waitFor(t, convergeBudget, "bravo to record a report and its control socket to count it under the one session", func() bool {
		if err := dialed.Mux().SendESP(stray); err != nil {
			t.Fatal(err)
		}
		reported := bravo.client.Sessions()
		return len(recorded(bravo.events, "ike.notify.invalid_spi")) > 0 && len(reported) == 1 && reported[0].InvalidSPIReports > 0
	})
	if len(alpha.client.sessions.paths()) != 1 || len(bravo.client.sessions.paths()) != 1 || alpha.client.sessions.snapshot()[0].session != dialed {
		t.Error("a report ended the session it went over")
	}
}
