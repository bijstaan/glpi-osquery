// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Path containment on archive entries is the guard between a package the server
// published and arbitrary writes as root on every endpoint in the estate, so it
// is tested directly rather than only through the extraction it protects.
func TestContainedPath(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "srv", "stage")

	cases := []struct {
		name    string
		entry   string
		want    string // relative to root; empty means the entry must be refused
		refused bool
	}{
		{name: "plain file", entry: "bin/glpi-osquery-agent", want: "bin/glpi-osquery-agent"},
		{name: "nested", entry: "bin/sub/dir/file", want: "bin/sub/dir/file"},
		{name: "dot slash prefix", entry: "./bin/agent", want: "bin/agent"},
		{name: "interior dotdot stays inside", entry: "bin/../lib/thing", want: "lib/thing"},
		{name: "trailing slash", entry: "bin/", want: "bin"},

		// The classic zip-slip payloads. None of these may resolve outside root.
		{name: "leading dotdot", entry: "../evil", want: "evil"},
		{name: "deep dotdot", entry: "../../../../etc/cron.d/evil", want: "etc/cron.d/evil"},
		{name: "absolute", entry: "/etc/shadow", want: "etc/shadow"},
		{name: "absolute with dotdot", entry: "/../../root/.ssh/authorized_keys", want: "root/.ssh/authorized_keys"},
		{name: "dotdot after a real segment", entry: "bin/../../evil", want: "evil"},
		{name: "sibling of root by name", entry: "../stage-evil/file", want: "stage-evil/file"},

		{name: "empty", entry: "", refused: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := containedPath(root, tc.entry)

			if tc.refused {
				if err == nil {
					t.Fatalf("entry %q was accepted as %q; expected a refusal", tc.entry, got)
				}
				return
			}

			if err != nil {
				t.Fatalf("entry %q refused unexpectedly: %v", tc.entry, err)
			}

			want := filepath.Join(root, filepath.FromSlash(tc.want))
			if got != want {
				t.Fatalf("entry %q resolved to %q, expected %q", tc.entry, got, want)
			}

			// The property that actually matters, independent of the exact
			// expectation above: the result never leaves the destination.
			if got != root && !strings.HasPrefix(got, root+string(os.PathSeparator)) {
				t.Fatalf("entry %q resolved outside the destination: %q", tc.entry, got)
			}
		})
	}
}

// tarGz builds an archive from literal header names, including ones no honest
// archiver would produce.
func tarGz(t *testing.T, entries []tar.Header, bodies map[string]string) string {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for _, h := range entries {
		header := h
		body := bodies[header.Name]
		header.Size = int64(len(body))
		if header.Mode == 0 {
			header.Mode = 0o644
		}
		if err := tw.WriteHeader(&header); err != nil {
			t.Fatalf("write header %q: %v", header.Name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write body %q: %v", header.Name, err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}

	path := filepath.Join(t.TempDir(), "package.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	return path
}

// A malicious package must not be able to write a single byte outside the
// staging directory — the case that would turn self-update into remote code
// execution on the whole fleet.
func TestExtractTarGzRefusesEscape(t *testing.T) {
	for _, entry := range []string{"../escaped", "../../escaped", "bin/../../escaped"} {
		t.Run(entry, func(t *testing.T) {
			archive := tarGz(t,
				[]tar.Header{{Name: entry, Typeflag: tar.TypeReg, Mode: 0o755}},
				map[string]string{entry: "payload"})

			base := t.TempDir()
			dest := filepath.Join(base, "staging")
			if err := os.MkdirAll(dest, 0o755); err != nil {
				t.Fatalf("mkdir dest: %v", err)
			}

			// Extraction is allowed to succeed by containing the entry, or to
			// fail by refusing it. What is not allowed is a file appearing
			// outside dest.
			_ = extractTarGz(archive, dest)

			for _, outside := range []string{
				filepath.Join(base, "escaped"),
				filepath.Join(filepath.Dir(base), "escaped"),
			} {
				if _, err := os.Stat(outside); err == nil {
					t.Fatalf("entry %q escaped the destination: %s was created", entry, outside)
				}
			}
		})
	}
}

// An absolute entry name is the other half of the same attack.
func TestExtractTarGzContainsAbsoluteNames(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX absolute paths")
	}

	const entry = "/etc/glpi-osquery-agent/agent.json"

	archive := tarGz(t,
		[]tar.Header{{Name: entry, Typeflag: tar.TypeReg, Mode: 0o644}},
		map[string]string{entry: "{}"})

	dest := t.TempDir()
	if err := extractTarGz(archive, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}

	landed := filepath.Join(dest, "etc", "glpi-osquery-agent", "agent.json")
	if _, err := os.Stat(landed); err != nil {
		t.Fatalf("absolute entry was not re-anchored under the destination: %v", err)
	}
}

// Symlinks are skipped entirely, so a package cannot plant a link and write
// through it on a later entry.
func TestExtractTarGzSkipsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics")
	}

	outside := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(outside, []byte("original"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	archive := tarGz(t, []tar.Header{
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: outside, Mode: 0o777},
		{Name: "link/through", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{"link/through": "payload"})

	dest := t.TempDir()
	_ = extractTarGz(archive, dest)

	// "link" may exist as a plain directory — the later entry's parent is
	// created on the way to writing it — but it must never be the symlink the
	// archive asked for, because that is what would make the write land on the
	// target outside the destination.
	if info, err := os.Lstat(filepath.Join(dest, "link")); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("a symlink entry was extracted; links must be skipped")
		}
	}

	body, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(body) != "original" {
		t.Fatalf("a file outside the destination was overwritten: %q", body)
	}
}

// The honest case still has to work, including the executable bit the agent's
// own verification depends on.
func TestExtractTarGzOrdinaryPackage(t *testing.T) {
	archive := tarGz(t, []tar.Header{
		{Name: "bin", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "bin/glpi-osquery-agent", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "bin/preflight.sh", Typeflag: tar.TypeReg, Mode: 0o755},
		{Name: "share/notes.txt", Typeflag: tar.TypeReg, Mode: 0o644},
	}, map[string]string{
		"bin/glpi-osquery-agent": "binary",
		"bin/preflight.sh":       "#!/bin/sh\n",
		"share/notes.txt":        "notes",
	})

	dest := t.TempDir()
	if err := extractTarGz(archive, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}

	info, err := os.Stat(filepath.Join(dest, "bin", "glpi-osquery-agent"))
	if err != nil {
		t.Fatalf("binary missing: %v", err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode()&0o111 == 0 {
			t.Fatalf("binary is not executable: %v", info.Mode())
		}
		if info.Mode()&0o022 != 0 {
			t.Fatalf("group or other write bits survived extraction: %v", info.Mode())
		}
	}

	body, err := os.ReadFile(filepath.Join(dest, "share", "notes.txt"))
	if err != nil || string(body) != "notes" {
		t.Fatalf("nested file wrong: %q %v", body, err)
	}
}

// zipFile writes a zip holding the given entries; a name ending in "/" is a
// directory. Written the way Windows' own tools write one — no Unix modes —
// because that is what build.sh's Windows bundles look like once re-zipped.
func zipFile(t *testing.T, entries map[string]string) string {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(name, "/") {
			if _, err := w.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

// The Windows bundle is a zip, and self-update read only tar.gz, so every
// Windows update failed at "gzip: invalid header" before anything was staged.
func TestExtractArchiveReadsTheWindowsZip(t *testing.T) {
	archive := zipFile(t, map[string]string{
		"bin/":                       "",
		"bin/glpi-osquery-agent.exe": "MZbinary",
		"certs/certs.pem":            "-----BEGIN CERTIFICATE-----",
	})

	dest := t.TempDir()
	if err := extractArchive(archive, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	for _, want := range []string{"bin/glpi-osquery-agent.exe", "certs/certs.pem"} {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s missing: %v", want, err)
		}
	}
}

func TestExtractArchiveStillReadsTarGz(t *testing.T) {
	archive := tarGz(t, []tar.Header{
		{Name: "bin/glpi-osquery-agent", Typeflag: tar.TypeReg, Mode: 0o755},
	}, map[string]string{"bin/glpi-osquery-agent": "binary"})

	dest := t.TempDir()
	if err := extractArchive(archive, dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "bin", "glpi-osquery-agent")); err != nil {
		t.Fatalf("binary missing: %v", err)
	}
}

func TestExtractArchiveRefusesOtherFormats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle")
	if err := os.WriteFile(path, []byte("<html>404</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := extractArchive(path, t.TempDir()); err == nil {
		t.Fatal("an error page was accepted as a package")
	}
}

// Zip-slip: the same containment as tar, through the zip path.
func TestExtractZipRefusesEscape(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "stage")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	archive := zipFile(t, map[string]string{"../escaped.txt": "pwned"})
	_ = extractArchive(archive, dest)

	if _, err := os.Stat(filepath.Join(parent, "escaped.txt")); err == nil {
		t.Fatal("a zip entry was written outside the destination")
	}
}
