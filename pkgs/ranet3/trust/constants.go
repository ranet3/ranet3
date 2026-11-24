// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

const (
	MaxSignedBytes       = 64 << 20
	MaxJSONBytes         = 256 << 20
	MaxEntries           = 131072
	MaxHeight            = 1<<53 - 1
	maxAuthorityPEMBytes = 64 << 10 // Whole signing-key file cap before parsing, above unpadded PKCS8 PEMs for the three key types.
	algorithmEd25519     = -19
	algorithmESP256      = -9
	algorithmESP384      = -51
)
