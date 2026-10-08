// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build darwin

package netstack

import "golang.org/x/sys/unix"

// tunMTUSettable is true, a utun taking a new MTU while the mesh has it open
const tunMTUSettable = true

// setTUNMTU sets the MTU of the utun name with SIOCSIFMTU
// wireguard-go sets it only when it creates the utun and exports no setter
func setTUNMTU(name string, mtu int) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	ifr := unix.IfreqMTU{MTU: int32(mtu)}
	copy(ifr.Name[:], name)
	return unix.IoctlSetIfreqMTU(fd, &ifr)
}
