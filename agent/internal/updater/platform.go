// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import "runtime"

// runtimeArch reports the architecture in the vocabulary the server publishes
// packages under.
func runtimeArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "amd64"
	case "arm64":
		return "arm64"
	default:
		return runtime.GOARCH
	}
}

func agentBinaryName() string {
	if runtime.GOOS == "windows" {
		return "glpi-osquery-agent.exe"
	}
	return "glpi-osquery-agent"
}
