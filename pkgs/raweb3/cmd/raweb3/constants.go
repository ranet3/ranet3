// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import "time"

const (
	// defaultRoot is the package directory, where the command runs from while writing
	defaultRoot = "."
	// defaultTailwind finds the tailwind binary on PATH, as the dev shell and the build put it there
	defaultTailwind = "tailwindcss"
	// defaultResvg finds resvg on PATH the same way
	defaultResvg = "resvg"
	// fontEnv names the font file, which the dev shell sets, as a font has no PATH
	fontEnv = "RAWEB3_FONT"
	// defaultListen keeps the server on this host, since it renders unreviewed sources
	defaultListen = "localhost:8080"
	// readHeaderTimeout bounds a request's headers, so a client that stalls holds no connection
	readHeaderTimeout = 10 * time.Second
)
