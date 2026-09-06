// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package supervisor

import (
	"os"
	"syscall"
)

// pidfileHeld reports whether a previous osqueryd still owns its pidfile.
//
// osquery locks the file rather than merely writing a pid into it, so asking
// for the lock is a direct answer. Checking whether the recorded pid is alive
// would answer a different and weaker question: pids are recycled, so an
// unrelated process inheriting the number reads as "osqueryd still running"
// and stalls the restart for the full timeout.
func pidfileHeld(path string) bool {
	// The mode is inert here — without O_CREATE the file is never created, and
	// osqueryd owns this pidfile — but it is written 0600 so nothing reads this
	// line as a licence to create a world-readable file in the state directory.
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return false // no pidfile, or not ours to read: nothing to wait for
	}
	defer file.Close()

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true
	}

	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	return false
}
