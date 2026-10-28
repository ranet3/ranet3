// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux && !android

package kernel

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// resolvedSocket is systemd-resolved's varlink socket
const resolvedSocket = "/run/systemd/resolve/io.systemd.Resolve"

// ResolvedLinkServers asks systemd-resolved for the DNS servers it queries
// through one link each, through its varlink method DumpDNSConfiguration. A
// host where it does not run has none.
func ResolvedLinkServers() ([]LinkResolver, error) {
	conn, err := net.DialTimeout("unix", resolvedSocket, resolvedWait)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kernel: reach systemd-resolved: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(resolvedWait)); err != nil {
		return nil, err
	}
	// a varlink message is a JSON object ended by a NUL byte
	if _, err := conn.Write(append([]byte(`{"method":"io.systemd.Resolve.DumpDNSConfiguration"}`), 0)); err != nil {
		return nil, fmt.Errorf("kernel: ask systemd-resolved for its DNS servers: %w", err)
	}
	reply, err := bufio.NewReader(conn).ReadBytes(0)
	if err != nil {
		return nil, fmt.Errorf("kernel: read systemd-resolved's DNS servers: %w", err)
	}
	return linkServers(reply[:len(reply)-1])
}

// linkServers reads DumpDNSConfiguration's reply: each link's servers, the
// global ones left out, since resolved binds a query to its server's link
// only for a server of a link
func linkServers(reply []byte) ([]LinkResolver, error) {
	var answer struct {
		Error      string `json:"error"`
		Parameters struct {
			Configuration []struct {
				Ifname  string `json:"ifname"`
				Servers []struct {
					Raw []int `json:"address"`
				} `json:"servers"`
			} `json:"configuration"`
		} `json:"parameters"`
	}
	if err := json.Unmarshal(reply, &answer); err != nil {
		return nil, fmt.Errorf("kernel: read systemd-resolved's DNS servers: %w", err)
	}
	if answer.Error != "" {
		return nil, fmt.Errorf("kernel: systemd-resolved answered %s", answer.Error)
	}
	var out []LinkResolver
	for _, link := range answer.Parameters.Configuration {
		if link.Ifname == "" {
			continue
		}
		for _, server := range link.Servers {
			raw := make([]byte, 0, len(server.Raw))
			for _, octet := range server.Raw {
				if octet < 0 || octet > 255 {
					return nil, fmt.Errorf("kernel: systemd-resolved names a server of %s by the octet %d", link.Ifname, octet)
				}
				raw = append(raw, byte(octet))
			}
			address, ok := netip.AddrFromSlice(raw)
			if !ok {
				return nil, fmt.Errorf("kernel: systemd-resolved names a server of %s by %d octets", link.Ifname, len(raw))
			}
			out = append(out, LinkResolver{Link: link.Ifname, Address: address})
		}
	}
	return out, nil
}
