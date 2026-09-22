// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package config

// SecureDataRoot is a no-op on Unix, where the 0750/0600 modes the agent
// creates its files with already do the job. See acl_windows.go.
func SecureDataRoot() error { return nil }
