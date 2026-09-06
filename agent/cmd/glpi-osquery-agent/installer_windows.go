// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package main

var installerSubcommands = map[string]func([]string) error{
	"msi-install":   msiInstall,
	"msi-uninstall": msiUninstall,
}
