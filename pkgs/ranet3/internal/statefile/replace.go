// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Stage names the operation that failed while replacing a synced file.
type Stage string

// ReplaceError reports whether a complete image is visible at the path.
// A renamed image still needs directory sync before it is known durable.
type ReplaceError struct {
	Stage   Stage
	Renamed bool
	Err     error
}

func (e *ReplaceError) Error() string { return fmt.Sprintf("%s failed: %v", e.Stage, e.Err) }
func (e *ReplaceError) Unwrap() error { return e.Err }

type replaceOps struct {
	write    func(*os.File, []byte) (int, error)
	fileSync func(*os.File) error
	rename   func(string, string) error
	dirSync  func(*os.File) error
}

// ReplaceSynced replaces a file whole and syncs its containing directory.
// On error, ReplaceError identifies the failing stage and whether rename passed.
func ReplaceSynced(path string, raw []byte) error {
	return replaceSynced(path, raw, replaceOps{})
}

func replaceSynced(path string, raw []byte, ops replaceOps) error {
	stage, renamed, err := writeStaged(path, raw, true, ops)
	if err != nil {
		return &ReplaceError{Stage: stage, Renamed: renamed, Err: err}
	}
	return syncDirectory(path, ops)
}

// SyncDirectory retries only the directory sync for an already renamed image.
func SyncDirectory(path string) error { return syncDirectory(path, replaceOps{}) }

func syncDirectory(path string, ops replaceOps) error {
	if path == "" {
		return &ReplaceError{Stage: StageDirectorySync, Renamed: true, Err: errNoPath}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return &ReplaceError{Stage: StageDirectorySync, Renamed: true, Err: err}
	}
	if ops.dirSync != nil {
		err = ops.dirSync(dir)
	} else {
		err = dir.Sync()
	}
	if err = errors.Join(err, dir.Close()); err != nil {
		return &ReplaceError{Stage: StageDirectorySync, Renamed: true, Err: err}
	}
	return nil
}

func writeStaged(path string, raw []byte, sync bool, ops replaceOps) (Stage, bool, error) {
	if path == "" {
		return StageWrite, false, errNoPath
	}
	temp := path + tempSuffix
	file, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return StageWrite, false, err
	}
	stage := StageWrite
	err = file.Chmod(mode)
	if err == nil {
		var n int
		if ops.write != nil {
			n, err = ops.write(file, raw)
		} else {
			n, err = file.Write(raw)
		}
		if err == nil && n != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil && sync {
		stage = StageFileSync
		if ops.fileSync != nil {
			err = ops.fileSync(file)
		} else {
			err = file.Sync()
		}
	}
	if err = errors.Join(err, file.Close()); err == nil {
		stage = StageRename
		if ops.rename != nil {
			err = ops.rename(temp, path)
		} else {
			err = os.Rename(temp, path)
		}
	}
	if err != nil {
		_ = os.Remove(temp)
		return stage, false, err
	}
	return "", true, nil
}
