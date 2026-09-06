// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
)

// FlipCurrent repoints `current` at a version directory.
//
// A directory junction rather than a symlink. The service happens to run as
// LocalSystem and would hold SeCreateSymbolicLinkPrivilege, but the installer
// and any manual intervention would not — and the installer creates a junction,
// so an updater that created a symlink would leave two different kinds of link
// on disk depending on how the machine last changed version. A junction works
// for any administrator and keeps all paths identical.
//
// Unlike the POSIX path this cannot be atomic: Windows will not rename over an
// existing directory, so the old junction is removed first. The gap only occurs
// while the agent is deliberately on its way out to restart, and a failure is
// reported rather than silently leaving `current` missing.
func FlipCurrent(link, target string) error {
	if _, err := os.Lstat(link); err == nil {
		// Remove, not RemoveAll: RemoveAll follows the junction on some Windows
		// versions, and deleting the link must never delete the version it names.
		if err := os.Remove(link); err != nil {
			return fmt.Errorf("remove the existing current link: %w", err)
		}
	}

	// mklink is a cmd builtin, so it cannot be exec'd directly.
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create junction %s -> %s: %w (%s)", link, target, err, out)
	}

	return nil
}
