// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package singleton

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Lock holds an exclusive claim on a state directory.
type Lock struct {
	handle windows.Handle
	path   string
}

// Acquire takes an exclusive lock, failing immediately if another agent holds it.
//
// Windows has no flock, so exclusivity comes from opening the file with no
// sharing: a second process attempting the same open fails outright.
func Acquire(stateDir string) (*Lock, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}

	path := filepath.Join(stateDir, "agent.lock")

	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // no sharing: this is the lock
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"another glpi-osquery-agent is already running with state directory %s: %w",
			stateDir, err)
	}

	return &Lock{handle: handle, path: path}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l == nil || l.handle == 0 {
		return
	}
	_ = windows.CloseHandle(l.handle)
}
