// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import (
	"time"

	"ranet3.com/pkgs/ranet3/control"
	"ranet3.com/pkgs/ranet3/internal/kernel"
)

// DebugNetmon reads the network watch's latest reading and the last change it signaled
func (c *Client) DebugNetmon() control.NetmonInfo {
	if c.network == nil {
		return control.NetmonInfo{}
	}
	current, last := c.network.State()
	info := control.NetmonInfo{Watching: true, Families: []control.NetmonFamily{
		{Family: string(kernel.FamilyIPv4), Default: netmonDefault(current.IPv4.Default), Addresses: current.IPv4.Addresses},
		{Family: string(kernel.FamilyIPv6), Default: netmonDefault(current.IPv6.Default), Addresses: current.IPv6.Addresses},
	}}
	if last.At.IsZero() {
		return info
	}
	change := &control.NetmonChange{At: last.At.UTC(), Ago: control.Duration(time.Since(last.At))}
	for _, family := range last.Families() {
		moved := control.NetmonFamilyChange{Family: string(family.Family), Added: family.Added, Removed: family.Removed}
		if family.DefaultMoved() {
			was, now := netmonDefault(family.DefaultBefore), netmonDefault(family.DefaultAfter)
			moved.DefaultWas, moved.Default = &was, &now
		}
		change.Families = append(change.Families, moved)
	}
	info.LastChange = change
	return info
}

func netmonDefault(route kernel.DefaultRoute) control.NetmonDefault {
	return control.NetmonDefault{Interface: route.Interface, Gateway: route.Gateway}
}
