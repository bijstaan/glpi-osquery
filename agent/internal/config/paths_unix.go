// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package config

import "path/filepath"

func runtimeIsWindows() bool { return false }

func defaultStateDir() string { return "/var/lib/glpi-osquery-agent" }

func defaultInstallRoot() string { return "/opt/glpi-osquery-agent" }

// extensionSocket is an ordinary Unix domain socket, created on demand beside
// the rest of the agent's state.
func extensionSocket(stateDir string) string {
	return filepath.Join(stateDir, "osquery.em")
}

func osquerydName() string { return "osqueryd" }

func extensionName() string { return "glpi-edid.ext" }
