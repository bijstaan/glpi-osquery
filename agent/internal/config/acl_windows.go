// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package config

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// dataRootSDDL grants SYSTEM and Administrators full control, inherited by
// everything beneath, and nothing to anyone else. "P" protects the DACL, so
// ProgramData's own entries stop flowing in.
const dataRootSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// SecureDataRoot restricts %ProgramData%\GLPIOsqueryAgent to SYSTEM and
// Administrators.
//
// The Unix modes passed to MkdirAll mean nothing on Windows, so the directory
// otherwise inherits ProgramData's ACL — under which every local user can read
// files and create new ones. That exposed agent.json, with the enrolment
// secret in it, and the agent token to any user on the machine. It also made
// state\extensions writable, and osqueryd, running as SYSTEM, autoloads every
// .ext.exe in that folder. Any user could therefore run code as SYSTEM.
//
// SetNamedSecurityInfo re-propagates to what already exists beneath, so
// calling this on every start also repairs an installation made before it
// existed. Idempotent.
func SecureDataRoot() error {
	root := filepath.Dir(defaultStateDir())
	if err := os.MkdirAll(root, 0o750); err != nil {
		return err
	}

	sd, err := windows.SecurityDescriptorFromString(dataRootSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}

	return windows.SetNamedSecurityInfo(
		root,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}
