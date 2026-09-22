// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package config

import (
	"os"
	"path/filepath"
)

func runtimeIsWindows() bool { return true }

func defaultStateDir() string {
	return filepath.Join(os.Getenv("ProgramData"), "GLPIOsqueryAgent", "state")
}

func defaultInstallRoot() string {
	return filepath.Join(os.Getenv("ProgramFiles"), "GLPI osquery Agent")
}

// extensionSocket is a named pipe, and the state directory has nothing to do
// with it.
//
// Windows has no Unix domain sockets for this purpose, so osquery uses a named
// pipe and requires the name to start with \\.\pipe\ — anything else is
// rejected outright. Handing it a filesystem path, as the Unix side does, left
// the extension manager unable to start: every extension table was silently
// absent, with one line about the socket buried in osqueryd's log.
//
// osquery.em is osqueryd's own default name, which is what an extension built
// against osquery's SDK expects to find. The consequence worth knowing is that
// a stock osquery service installed alongside this agent wants the same pipe,
// and the second daemon to start does not get it.
func extensionSocket(_ string) string {
	return `\\.\pipe\osquery.em`
}

func osquerydName() string { return "osqueryd.exe" }

func extensionName() string { return "glpi-edid.ext.exe" }
