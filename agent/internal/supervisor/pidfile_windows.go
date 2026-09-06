// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package supervisor

import (
	"os"

	"golang.org/x/sys/windows"
)

// pidfileHeld reports whether a previous osqueryd still owns its pidfile.
//
// Windows has no flock; osqueryd keeps the handle open, so an exclusive open
// failing with a sharing violation is the equivalent signal.
func pidfileHeld(path string) bool {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}

	handle, err := windows.CreateFile(
		pathp,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // no sharing
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return os.IsPermission(err) || err == windows.ERROR_SHARING_VIOLATION
	}

	windows.CloseHandle(handle)

	return false
}
