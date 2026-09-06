// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package config holds the agent's on-disk configuration and installation
// layout.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is written once at install time and then only read.
//
// The enrollment secret lives here rather than being passed on the command
// line, because a command line is world-readable through /proc on Linux and the
// process list everywhere else.
type Config struct {
	// ServerURL is the GLPI base URL, e.g. https://glpi.example.com. It must be
	// HTTPS: osquery 5.x refuses anything else and there is no override.
	ServerURL string `json:"server_url"`

	// EnrollSecret is the shared bootstrap credential. It buys exactly one
	// thing — a per-agent token — and is not used again after enrollment.
	EnrollSecret string `json:"enroll_secret"`

	// CACertPath is an optional PEM bundle for a private CA. Empty means use
	// the system trust store.
	CACertPath string `json:"ca_cert_path,omitempty"`

	// OsquerydPath is the bundled osqueryd this agent supervises.
	OsquerydPath string `json:"osqueryd_path,omitempty"`

	// ExtensionPath is our EDID extension, autoloaded by osqueryd.
	ExtensionPath string `json:"extension_path,omitempty"`

	// StateDir holds the agent token, osquery's database and update markers.
	StateDir string `json:"state_dir,omitempty"`

	// InstallRoot is the versioned install tree used for self-update.
	InstallRoot string `json:"install_root,omitempty"`

	// UpdatesEnabled lets an administrator refuse self-update on this host
	// regardless of what the server offers.
	UpdatesEnabled bool `json:"updates_enabled"`

	// ListenPort is the local status listener GLPI's device page queries.
	// Zero uses osquery/GLPI's conventional 62354.
	ListenPort int `json:"listen_port,omitempty"`

	// TrustedAddresses may contact the status listener, in addition to the
	// GLPI server itself and loopback. Hostnames, IPs and CIDRs are accepted.
	TrustedAddresses []string `json:"trusted_addresses,omitempty"`

	// ListenDisabled turns the status listener off entirely, at the cost of
	// the device page's live status and "request inventory" controls.
	ListenDisabled bool `json:"listen_disabled,omitempty"`
}

// DefaultPath is where the package installs the configuration.
func DefaultPath() string {
	if runtimeIsWindows() {
		return filepath.Join(os.Getenv("ProgramData"), "GLPIOsqueryAgent", "agent.json")
	}
	return "/etc/glpi-osquery-agent/agent.json"
}

// DefaultStateDir and DefaultInstallRoot expose the platform defaults to the
// installer subcommands, which have to agree with what the service will read.
func DefaultStateDir() string    { return defaultStateDir() }
func DefaultInstallRoot() string { return defaultInstallRoot() }

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = defaultStateDir()
	}
	if c.InstallRoot == "" {
		c.InstallRoot = defaultInstallRoot()
	}
	if c.OsquerydPath == "" {
		c.OsquerydPath = filepath.Join(c.InstallRoot, "current", "bin", osquerydName())
	}
	if c.ExtensionPath == "" {
		c.ExtensionPath = filepath.Join(c.InstallRoot, "current", "bin", extensionName())
	}
}

// Load reads and validates the configuration.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	cfg.applyDefaults()

	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("config %s: server_url is required", path)
	}

	return &cfg, nil
}

// Save writes the configuration with restrictive permissions, because it holds
// the enrollment secret.
func Save(path string, cfg *Config) error {
	if path == "" {
		path = DefaultPath()
	}
	// 0750, not 0755: this directory holds agent.json — the enrolment secret —
	// and on some installs the private CA bundle beside it. Only root and the
	// agent's own group ever read either, and the packaging lays the state
	// directory down at 0750 for the same reason.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, body, 0o600)
}

// TokenPath is where the per-agent credential is cached between runs.
func (c *Config) TokenPath() string {
	return filepath.Join(c.StateDir, "agent.token")
}

// OsqueryDBPath is osqueryd's RocksDB directory.
func (c *Config) OsqueryDBPath() string {
	return filepath.Join(c.StateDir, "osquery.db")
}

// FlagfilePath is the generated osquery flagfile.
func (c *Config) FlagfilePath() string {
	return filepath.Join(c.StateDir, "osquery.flags")
}

// SecretPath is where the enrollment secret is materialised for osqueryd, which
// can only read it from a file.
func (c *Config) SecretPath() string {
	return filepath.Join(c.StateDir, "enroll.secret")
}

// ExtensionsLoadPath lists extensions for osqueryd to autoload.
func (c *Config) ExtensionsLoadPath() string {
	return filepath.Join(c.StateDir, "extensions.load")
}

// ExtensionsDir holds extensions published from GLPI, as opposed to the one
// this agent bundles.
//
// Deliberately under StateDir and not under InstallRoot. A self-update replaces
// the whole versioned tree and repoints `current` at it, so anything installed
// beside the bundled extension would be silently deleted by the next agent
// upgrade — and an administrator would see extensions disappearing from a
// fraction of the fleet with nothing connecting it to the upgrade that did it.
func (c *Config) ExtensionsDir() string {
	return filepath.Join(c.StateDir, "extensions")
}

// ExtensionStatePath records which published extensions are installed here.
//
// Kept as a file rather than inferred from the directory listing because the
// version that produced a binary is not recoverable from the binary, and the
// server is told what is installed on every check-in.
func (c *Config) ExtensionStatePath() string {
	return filepath.Join(c.StateDir, "extensions.json")
}

// ExtensionSocketPath is the osquery extension manager socket.
//
// Deliberately inside our state directory rather than osquery's default
// /var/osquery, which does not exist unless osquery's own package created it —
// and this agent bundles osqueryd instead of installing that package.
func (c *Config) ExtensionSocketPath() string {
	return filepath.Join(c.StateDir, "osquery.em")
}
