// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package hostinfo identifies the machine to the server.
package hostinfo

import (
	"os"
	"runtime"
	"strings"
)

// Identity is what the supervisor reports at enrollment.
type Identity struct {
	HostIdentifier string
	HardwareUUID   string
	Platform       string
	Arch           string
}

// Collect gathers the machine's identity.
//
// The hardware UUID matters more than the hostname: the server derives a stable
// device id from it, so a renamed machine stays the same asset instead of
// appearing as a second one.
func Collect() Identity {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}

	return Identity{
		HostIdentifier: host,
		HardwareUUID:   hardwareUUID(),
		Platform:       platform(),
		Arch:           arch(),
	}
}

func arch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func platform() string {
	switch runtime.GOOS {
	case "darwin":
		return "darwin"
	case "windows":
		return "windows"
	default:
		return "linux"
	}
}

func firstNonEmpty(candidates ...string) string {
	for _, c := range candidates {
		if s := strings.TrimSpace(c); s != "" {
			return s
		}
	}
	return ""
}
