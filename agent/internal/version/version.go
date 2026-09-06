// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package version carries the build identity, set at link time.
package version

// Version is overridden with -ldflags "-X .../internal/version.Version=1.2.3".
var Version = "0.0.0-dev"
