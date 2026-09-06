// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package main

// installerSubcommands is empty here: the msi-* pair drives the Windows service
// control manager and a directory junction, neither of which exists on Unix.
var installerSubcommands = map[string]func([]string) error{}
