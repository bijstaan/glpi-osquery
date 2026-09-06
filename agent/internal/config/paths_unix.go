// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package config

func runtimeIsWindows() bool { return false }

func defaultStateDir() string { return "/var/lib/glpi-osquery-agent" }

func defaultInstallRoot() string { return "/opt/glpi-osquery-agent" }

func osquerydName() string { return "osqueryd" }

func extensionName() string { return "glpi-edid.ext" }
