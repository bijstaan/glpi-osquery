// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package supervisor

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bijstaan/glpi-osquery-agent/internal/config"
)

// The flag these tests are about is the one nothing else can substitute for:
// osqueryd reads no operating-system trust store, so a flagfile that does not
// name a CA bundle produces a daemon that trusts nothing and an enrolment that
// fails against an ordinary publicly trusted certificate.
func flagfile(t *testing.T, cfg *config.Config) string {
	t.Helper()

	s := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := s.WriteFlagfile(); err != nil {
		t.Fatalf("WriteFlagfile: %v", err)
	}

	body, err := os.ReadFile(cfg.FlagfilePath())
	if err != nil {
		t.Fatalf("read flagfile: %v", err)
	}

	return string(body)
}

func baseConfig(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()

	return &config.Config{
		ServerURL:    "https://glpi.example.com",
		EnrollSecret: "secret",
		StateDir:     filepath.Join(dir, "state"),
		InstallRoot:  filepath.Join(dir, "root"),
	}
}

func TestFlagfileNamesTheBundledCertificates(t *testing.T) {
	cfg := baseConfig(t)

	certs := cfg.BundledCertsPath()
	if err := os.MkdirAll(filepath.Dir(certs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certs, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if want := "--tls_server_certs=" + certs; !strings.Contains(flagfile(t, cfg), want) {
		t.Errorf("flagfile does not name the bundled CA store (%s)", want)
	}
}

// An administrator's own CA replaces the bundle rather than joining it:
// osqueryd takes a single file, so naming both is not an option the flag has.
func TestFlagfilePrefersAnAdministratorsCA(t *testing.T) {
	cfg := baseConfig(t)
	cfg.CACertPath = filepath.Join(t.TempDir(), "corp-ca.pem")

	body := flagfile(t, cfg)

	if want := "--tls_server_certs=" + cfg.CACertPath; !strings.Contains(body, want) {
		t.Errorf("flagfile does not name the configured CA (%s)", want)
	}
	if strings.Contains(body, cfg.BundledCertsPath()) {
		t.Error("flagfile names both the configured CA and the bundle; osqueryd reads only one")
	}
}

// The bundle missing is a deployment fault, not a reason to refuse to start:
// osqueryd still runs, every local table still works, and only TLS is broken —
// so the flag is left off and the warning in WriteFlagfile carries the news.
func TestFlagfileOmitsTheFlagWhenNothingIsThere(t *testing.T) {
	cfg := baseConfig(t)

	if strings.Contains(flagfile(t, cfg), "--tls_server_certs=") {
		t.Error("flagfile names a CA store that does not exist")
	}
}
