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
// Not osquery's default, \\.\pipe\osquery.em: a stock osquery service
// installed alongside this agent — common where an MSP's client already runs
// one — claims that pipe too, and whichever daemon starts second loses its
// extension manager and every extension table with it. A name of our own
// costs nothing, because osqueryd passes the socket to every extension it
// autoloads as --socket, bundled or published alike; nothing needs to guess
// it.
func extensionSocket(_ string) string {
	return `\\.\pipe\glpi-osquery.em`
}

func osquerydName() string { return "osqueryd.exe" }

func extensionName() string { return "glpi-edid.ext.exe" }
