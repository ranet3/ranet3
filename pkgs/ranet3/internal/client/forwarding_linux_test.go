// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build linux

package client

import (
	"os"
	"path/filepath"
	"testing"
)

// a setting that reads 0 is off and any other value on, and one the node cannot read is neither
func TestForwardingSettingThatCannotBeReadIsUnknown(t *testing.T) {
	dir := t.TempDir()
	for value, want := range map[string]string{"0\n": "false", "1\n": "true", "2\n": "true"} {
		path := filepath.Join(dir, "forwarding")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := onOffUnread(sysctlIsOne(path)); got != want {
			t.Errorf("a setting reading %q is read as %s, want %s", value, got, want)
		}
	}
	if got := onOffUnread(sysctlIsOne(filepath.Join(dir, "absent"))); got != "unread" {
		t.Errorf("a setting that does not exist is read as %s, want it unread", got)
	}
}

// a path that is absolute or rises above /proc/sys reads nothing, though a file exists where it would end
func TestSysctlReadsNothingOutsideProcSys(t *testing.T) {
	if Sysctl("kernel/ostype") == "" {
		t.Fatal("kernel/ostype was not read, so nothing below is shown")
	}
	for _, path := range []string{"../self/stat", "kernel/../../self/stat", "/kernel/ostype"} {
		if got := Sysctl(path); got != "" {
			t.Errorf("%q read %q, want nothing", path, got)
		}
	}
}
