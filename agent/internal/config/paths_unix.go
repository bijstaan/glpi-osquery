// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package config

import (
	"path/filepath"
	"runtime"
)

func runtimeIsWindows() bool { return false }

func defaultStateDir() string { return "/var/lib/glpi-osquery-agent" }

// defaultInstallRoot is where the packages lay the versioned tree down.
//
// macOS differs because /opt is not a place a Mac installer writes to: the
// .pkg, install-macos.sh and the launchd plist all use /usr/local. With /opt
// as the default everywhere, a Mac agent looked for osqueryd in a directory
// nothing had created, failed to start it on every launch, and staged its
// self-updates into that same empty tree while launchd kept running the old
// binary.
func defaultInstallRoot() string {
	if runtime.GOOS == "darwin" {
		return "/usr/local/glpi-osquery-agent"
	}
	return "/opt/glpi-osquery-agent"
}

// extensionSocket is an ordinary Unix domain socket, created on demand beside
// the rest of the agent's state.
func extensionSocket(stateDir string) string {
	return filepath.Join(stateDir, "osquery.em")
}

func osquerydName() string { return "osqueryd" }

func extensionName() string { return "glpi-edid.ext" }
