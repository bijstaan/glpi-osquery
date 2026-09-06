// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package hostinfo

import (
	"os/exec"
	"strings"
)

// hardwareUUID reads the SMBIOS UUID, which is what osquery reports in
// system_info.uuid on Windows.
func hardwareUUID() string {
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID").Output()
	if err != nil {
		return ""
	}

	return firstNonEmpty(strings.TrimSpace(string(out)))
}
