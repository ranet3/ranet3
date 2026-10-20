// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux || darwin

package client

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// the host's default TTL is the TTL the host sends its own datagrams with, read here off one it sent over loopback
func TestHostDefaultTTLIsTheTTLTheHostSendsWith(t *testing.T) {
	ttl, err := hostDefaultTTL()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetReadDeadline(time.Now().Add(convergeBudget)); err != nil {
		t.Fatal(err)
	}
	received := ipv4.NewPacketConn(listener)
	if err := received.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		t.Fatal(err)
	}
	sender, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err := sender.Write([]byte("ttl")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_, control, _, err := received.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if control == nil || control.TTL != int(ttl) {
		t.Errorf("the host's default TTL reads %d, and a datagram it sent arrived with %+v", ttl, control)
	}
}
