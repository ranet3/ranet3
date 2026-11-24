// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unix

package statefile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// PublishNew writes a complete file at an absent path without replacing any directory entry.
func PublishNew(path string, raw []byte, mode fs.FileMode) error {
	return publishNew(path, raw, mode, publishOps{})
}

type publishOps struct {
	write    func(*os.File, []byte) (int, error)
	fileSync func(*os.File) error
	link     func(string, string) error
	dirSync  func(*os.File) error
}

func publishNew(path string, raw []byte, mode fs.FileMode, ops publishOps) (err error) {
	if path == "" {
		return errNoPath
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporary := file.Name()
	defer func() {
		if temporary != "" {
			err = errors.Join(err, os.Remove(temporary))
		}
	}()
	if err = file.Chmod(mode); err != nil {
		return errors.Join(fmt.Errorf("set output mode: %w", err), file.Close())
	}
	var n int
	var writeErr error
	if ops.write != nil {
		n, writeErr = ops.write(file, raw)
	} else {
		n, writeErr = file.Write(raw)
	}
	if writeErr == nil && n != len(raw) {
		writeErr = fs.ErrInvalid
	}
	if writeErr != nil {
		return errors.Join(fmt.Errorf("write output: %w", writeErr), file.Close())
	}
	if ops.fileSync != nil {
		err = ops.fileSync(file)
	} else {
		err = file.Sync()
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	link := os.Link
	if ops.link != nil {
		link = ops.link
	}
	if err := link(temporary, path); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		return fmt.Errorf("remove temporary name: %w", err)
	}
	temporary = ""
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open output directory: %w", err)
	}
	if ops.dirSync != nil {
		err = ops.dirSync(dir)
	} else {
		err = dir.Sync()
	}
	if err = errors.Join(err, dir.Close()); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}
	return nil
}
