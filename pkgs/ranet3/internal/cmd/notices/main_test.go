// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A module go.mod replaces with a directory ships under its own path, and
// its license is in that directory rather than in the module cache.
func TestDirectoryReplacementShipsUnderThePathItReplaces(t *testing.T) {
	listed := "/tmp/ranet3-notices-subject: go1.26.8\n" +
		"\tpath\tranet3.com/pkgs/ranet3/cmd/ranet3\n" +
		"\tmod\tranet3.com/pkgs/ranet3\t(devel)\t\n" +
		"\tdep\tgithub.com/BurntSushi/toml\tv1.6.0\th1:dRaEfpa2VI55EwlIW72hMRHdWouJeRF7TPYhI+AUQjk=\n" +
		"\tdep\tranet3.com/pkgs/wireguard\tv0.0.0-00010101000000-000000000000\n" +
		"\t=>\t../wireguard\t(devel)\t\n" +
		"\tbuild\t-buildmode=exe\n"
	modules, err := modulesOf(listed)
	if err != nil {
		t.Fatal(err)
	}
	want := []module{
		{path: "github.com/BurntSushi/toml", version: "v1.6.0"},
		{path: "ranet3.com/pkgs/wireguard", version: "v0.0.0-00010101000000-000000000000", dir: "../wireguard"},
	}
	if !slices.Equal(modules, want) {
		t.Errorf("modules %+v, want %+v", modules, want)
	}
}

// A copy's LICENSE names no holder, so its notice carries each holder that
// REUSE.toml gives a file under LICENSE's license, once and in the order the
// file names them, and no holder of a file under another license.
func TestCopiedModuleCarriesTheHoldersOfItsLicense(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte("Permission is hereby granted.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reuse := `version = 1

[[annotations]]
path = ["LICENSE", "go.mod"]
SPDX-FileCopyrightText = "2017-2025 Upstream LLC"
SPDX-License-Identifier = "MIT"

[[annotations]]
path = "tun/fork.go"
SPDX-FileCopyrightText = "Fork Inc"
SPDX-License-Identifier = "MIT"

[[annotations]]
path = ["tun/both.go", "tun/both_test.go"]
SPDX-FileCopyrightText = ["2017-2025 Upstream LLC", "Both Ltd"]
SPDX-License-Identifier = "MIT"

[[annotations]]
path = "gomod2nix.toml"
SPDX-FileCopyrightText = "2026 Builder"
SPDX-License-Identifier = "FSL-1.1-ALv2"
`
	if err := os.WriteFile(filepath.Join(dir, "REUSE.toml"), []byte(reuse), 0o644); err != nil {
		t.Fatal(err)
	}
	text, from, err := license("", module{path: "example.com/copy", version: "v0.0.0-00010101000000-000000000000", dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := "Copyright (c) 2017-2025 Upstream LLC\nCopyright (c) Fork Inc\nCopyright (c) Both Ltd\n\nPermission is hereby granted.\n"
	if text != want {
		t.Errorf("text\n%s\nwant\n%s", text, want)
	}
	if want := "example.com/copy in `" + dir + "`, from `LICENSE` and the holders `REUSE.toml` names"; from != want {
		t.Errorf("from %q, want %q", from, want)
	}
}
