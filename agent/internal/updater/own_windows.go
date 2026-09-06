// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package updater

// ownForOsquery is a no-op on Windows.
//
// osquery's ownership check is a POSIX one; on Windows the protection that
// matters is the ACL on the install and state directories, which the installer
// sets and this agent does not alter per file.
func ownForOsquery(string) error { return nil }
