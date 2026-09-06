// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

// Package singleton stops two agents sharing one state directory.
package singleton

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Lock holds an exclusive claim on a state directory.
type Lock struct {
	file *os.File
}

// Acquire takes an exclusive lock, failing immediately if another agent holds it.
//
// Two supervisors sharing a state directory both start their own osqueryd
// against the same RocksDB, which is single-writer: the result is not a clean
// failure but erratic behaviour — queries that intermittently do not run and
// results that never arrive, with nothing in the log to explain it. Observed in
// the field when a manually-started agent was left running alongside the
// service.
//
// The lock is advisory (flock) and released automatically if the process dies,
// so a crash never leaves an agent unable to start.
func Acquire(stateDir string) (*Lock, error) {
	if err := os.MkdirAll(stateDir, 0o750); err != nil {
		return nil, err
	}

	path := filepath.Join(stateDir, "agent.lock")

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf(
			"another glpi-osquery-agent is already running with state directory %s "+
				"(remove it or stop the other instance): %w", stateDir, err)
	}

	// Record who holds it, purely so the situation is diagnosable.
	_ = file.Truncate(0)
	_, _ = file.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0)

	return &Lock{file: file}, nil
}

// Release drops the lock.
func (l *Lock) Release() {
	if l == nil || l.file == nil {
		return
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
}
