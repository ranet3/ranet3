// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package packet

import "testing"

// what decapsulating one inner header costs: reading its field, the cell, and for a cell that differs the write with the IPv4 checksum
// the ce arms put the octet holding the field back as it arrived with one store after each, so every iteration writes
func BenchmarkDecapsulateECN(b *testing.B) {
	for _, arm := range []struct {
		name  string
		outer ECN
	}{
		{"not-ect", NotECT},
		{"ect0", ECT0},
		{"ce", CE},
	} {
		for _, header := range ecnHeaders(ECT0) {
			version := "ipv4"
			if header[0]>>4 == 6 {
				version = "ipv6"
			}
			b.Run(arm.name+"/"+version, func(b *testing.B) {
				arrived := header[1]
				for b.Loop() {
					inner := ECNOf(header)
					out, drop, _ := Decapsulate(inner, arm.outer)
					if !drop && out != inner {
						SetECN(header, out)
						header[1] = arrived
					}
				}
			})
		}
	}
}
