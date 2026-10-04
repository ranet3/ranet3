// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package client

import "time"

// espDropReportInterval bounds how often refused ESP packets are said out
// loud. The counter behind it is exact, and an operator reads that. The log
// line only has to point at it.
const espDropReportInterval = 10 * time.Second
