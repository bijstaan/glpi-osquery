// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package updater

import "os"

// ownForOsquery makes a staged extension owned by the user osqueryd runs as.
//
// A no-op unless the agent is root, which is the only case where the two can
// differ: a non-root agent's downloads already belong to the account osqueryd
// will be started under, since the agent starts it.
func ownForOsquery(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}

	return os.Chown(path, 0, 0)
}
