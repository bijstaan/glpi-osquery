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

func osquerydName() string { return "osqueryd.exe" }

func extensionName() string { return "glpi-edid.ext.exe" }
