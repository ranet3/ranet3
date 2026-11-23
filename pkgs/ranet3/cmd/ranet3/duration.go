// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"errors"
	"time"

	"ranet3.com/pkgs/ranet3/control"
)

type durationValue time.Duration

func (d *durationValue) Type() string { return "duration" }

func (d *durationValue) String() string {
	// pflag does not recognize 0s as a custom value's zero default
	if *d == 0 {
		return "0"
	}
	return time.Duration(*d).String()
}

func (d *durationValue) Set(text string) error {
	parsed, err := control.ParseInputDuration(text)
	if err != nil {
		return errors.New(`must be a duration in range, such as "30s", "5m" or "1d2h"`)
	}
	*d = durationValue(parsed)
	return nil
}
