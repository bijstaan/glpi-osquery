// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bijstaan/glpi-osquery-agent/internal/client"
	"github.com/bijstaan/glpi-osquery-agent/internal/config"
)

// harness builds an updater pointed at a throwaway state directory and a server
// that serves the supplied bodies by path.
func harness(t *testing.T, bodies map[string][]byte) (*Updater, *httptest.Server) {
	t.Helper()

	// TLS, because the client refuses a plain-HTTP server outright — the same
	// refusal that stops an enrollment secret being sent in the clear.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cfg := &config.Config{
		StateDir:       t.TempDir(),
		InstallRoot:    t.TempDir(),
		ServerURL:      srv.URL,
		CACertPath:     caPath,
		UpdatesEnabled: true,
	}

	api, err := client.New(srv.URL, caPath)
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	return New(cfg, api, log, "token", func() string { return "5.19.0" }), srv
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestReconcileInstallsAndReports(t *testing.T) {
	body := []byte("#!/bin/true\nacme")
	up, srv := harness(t, map[string][]byte{"/acme.ext": body})

	changed, err := up.reconcileExtensions([]client.Extension{{
		Name: "acme-inventory", Version: "1.0.0",
		URL: srv.URL + "/acme.ext", SHA256: digest(body), Size: int64(len(body)),
	}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed {
		t.Fatal("expected the first install to report a change")
	}

	path := filepath.Join(up.cfg.ExtensionsDir(), extensionFilename("acme-inventory"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("extension not installed: %v", err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("extension is not executable: %v", info.Mode())
	}

	got := up.InstalledExtensions()
	if len(got) != 1 || got[0].Name != "acme-inventory" || got[0].Version != "1.0.0" {
		t.Errorf("check-in should report the install, got %+v", got)
	}
}

// An unchanged desired set must not re-download or report a change, or every
// check-in would restart osqueryd.
func TestReconcileIsIdempotent(t *testing.T) {
	body := []byte("acme")
	up, srv := harness(t, map[string][]byte{"/acme.ext": body})

	spec := []client.Extension{{
		Name: "acme-inventory", Version: "1.0.0",
		URL: srv.URL + "/acme.ext", SHA256: digest(body), Size: int64(len(body)),
	}}

	if _, err := up.reconcileExtensions(spec); err != nil {
		t.Fatalf("first: %v", err)
	}

	changed, err := up.reconcileExtensions(spec)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if changed {
		t.Error("an unchanged set must not report a change")
	}
}

// The whole reason the manifest is a desired set: withdrawing an extension has
// to delete it, not merely stop offering it.
func TestReconcileRemovesWithdrawn(t *testing.T) {
	body := []byte("acme")
	up, srv := harness(t, map[string][]byte{"/acme.ext": body})

	if _, err := up.reconcileExtensions([]client.Extension{{
		Name: "acme-inventory", Version: "1.0.0",
		URL: srv.URL + "/acme.ext", SHA256: digest(body), Size: int64(len(body)),
	}}); err != nil {
		t.Fatalf("install: %v", err)
	}

	changed, err := up.reconcileExtensions(nil)
	if err != nil {
		t.Fatalf("withdraw: %v", err)
	}
	if !changed {
		t.Error("removing the last extension is a change")
	}

	path := filepath.Join(up.cfg.ExtensionsDir(), extensionFilename("acme-inventory"))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("withdrawn extension is still on disk")
	}
	if got := up.InstalledExtensions(); len(got) != 0 {
		t.Errorf("nothing should be reported installed, got %+v", got)
	}
}

// A binary that does not match its checksum must never reach the directory
// osqueryd autoloads from — it would be executed as root on the next start.
func TestReconcileRefusesBadChecksum(t *testing.T) {
	up, srv := harness(t, map[string][]byte{"/acme.ext": []byte("not what was published")})

	changed, err := up.reconcileExtensions([]client.Extension{{
		Name: "acme-inventory", Version: "1.0.0",
		URL: srv.URL + "/acme.ext", SHA256: digest([]byte("the real thing")), Size: 22,
	}})
	if err != nil {
		t.Fatalf("reconcile should skip, not fail: %v", err)
	}
	if changed {
		t.Error("a refused package is not a change")
	}

	entries, _ := os.ReadDir(up.cfg.ExtensionsDir())
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".ext" {
			t.Errorf("unverified payload was installed: %s", entry.Name())
		}
	}
}

// The name becomes a path. A server must not be able to write outside the
// extensions directory by choosing one.
func TestReconcileRefusesTraversingName(t *testing.T) {
	body := []byte("evil")
	up, srv := harness(t, map[string][]byte{"/x.ext": body})

	if _, err := up.reconcileExtensions([]client.Extension{{
		Name: "../../bin/osqueryd", Version: "1.0.0",
		URL: srv.URL + "/x.ext", SHA256: digest(body), Size: int64(len(body)),
	}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	if _, err := os.Stat(filepath.Join(up.cfg.InstallRoot, "bin", "osqueryd.ext")); err == nil {
		t.Fatal("a traversing name escaped the extensions directory")
	}
	if got := up.InstalledExtensions(); len(got) != 0 {
		t.Errorf("nothing should have installed, got %+v", got)
	}
}

// A file left behind by an interrupted install is still autoloaded by osqueryd,
// so the sweep is driven by the directory rather than by the state file.
func TestReconcileSweepsUntrackedBinaries(t *testing.T) {
	up, _ := harness(t, nil)

	dir := up.cfg.ExtensionsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(dir, "leftover.ext")
	if err := os.WriteFile(stray, []byte("stray"), 0o755); err != nil {
		t.Fatal(err)
	}

	changed, err := up.reconcileExtensions(nil)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !changed {
		t.Error("sweeping a stray binary is a change")
	}
	if _, err := os.Stat(stray); !os.IsNotExist(err) {
		t.Error("stray binary survived")
	}
}

// nil and [] mean different things on the wire: one is an older plugin with
// nothing to say, the other is an instruction to have none installed.
func TestExtensionsNilIsDistinctFromEmpty(t *testing.T) {
	var absent, empty client.UpdateResponse

	if err := json.Unmarshal([]byte(`{"update_available":false}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.Extensions != nil {
		t.Error("a response without the field must decode to nil, not an empty list")
	}

	if err := json.Unmarshal([]byte(`{"update_available":false,"extensions":[]}`), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.Extensions == nil || len(*empty.Extensions) != 0 {
		t.Errorf("an empty list must decode as present and empty, got %v", empty.Extensions)
	}
}
