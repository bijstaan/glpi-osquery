// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package hostinfo

import (
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

var uuidPattern = regexp.MustCompile(`[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}`)

// hardwareUUID reads the machine's stable identifier.
//
// Sources are tried in order of how closely they track the physical machine.
// The DMI product UUID is the same value osquery reports in system_info.uuid,
// so agreeing with it keeps the supervisor and osqueryd pointing at one asset
// rather than creating two.
func hardwareUUID() string {
	if runtime.GOOS == "darwin" {
		return darwinUUID()
	}

	for _, path := range []string{
		"/sys/class/dmi/id/product_uuid",
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if s := strings.TrimSpace(string(raw)); s != "" {
			return s
		}
	}

	return ""
}

func darwinUUID() string {
	out, err := exec.Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		if match := uuidPattern.FindString(line); match != "" {
			return match
		}
	}

	return ""
}
