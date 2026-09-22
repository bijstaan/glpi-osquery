// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/bijstaan/glpi-osquery-agent/internal/client"
)

// Extensions published from GLPI, reconciled against what is on disk.
//
// This is a desired-state loop, not an update loop, and the difference matters:
// the server sends the complete set an endpoint should have, so an extension
// that was deactivated or unscoped disappears from the list and is *deleted*
// here. An install-only updater would leave a withdrawn extension running as
// root forever with nothing in GLPI to show it, which is the failure this
// design exists to avoid.
//
// osqueryd reads its autoload list once at startup, so any change to the set
// takes effect only after it is restarted — see Supervisor.Restart.

// installedExtension is one entry of the on-disk state file.
type installedExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// safeName is enforced again here even though the server validates it.
//
// The name becomes a path, and a path supplied by a remote party is exactly the
// thing not to interpolate on trust: a compromised or simply buggy server must
// not be able to write outside the extensions directory by naming a package
// `../../bin/osqueryd`.
var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$`)

// extensionFilename is what osqueryd expects to find in an autoload directory.
func extensionFilename(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".ext.exe"
	}

	return name + ".ext"
}

// runnableHere refuses a package the platform could not execute.
//
// Windows only, and deliberately: a Windows machine can run nothing but a PE
// image, so a Linux build published against the windows/amd64 row lands as
// `<name>.ext.exe`, osqueryd tries to autoload it, and the extension's tables
// are simply never there — with one line in osqueryd's log and nothing in GLPI
// to say the package was the wrong one. Two bytes turn that into a refusal
// that names the extension.
//
// Not applied to Unix, where a shebang script is a legitimate extension:
// osqueryd executes autoloaded extensions rather than dlopening them, so there
// is no magic number a Unix extension is obliged to carry.
func runnableHere(path, goos string) error {
	if goos != "windows" {
		return nil
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return fmt.Errorf("read the package header: %w", err)
	}

	if magic != [2]byte{'M', 'Z'} {
		return fmt.Errorf("not a Windows executable (header %q): check the platform it was published under", magic)
	}

	return nil
}

func (u *Updater) statePath() string {
	return u.cfg.ExtensionStatePath()
}

func (u *Updater) readState() []installedExtension {
	raw, err := os.ReadFile(u.statePath())
	if err != nil {
		return nil
	}

	var state []installedExtension
	if err := json.Unmarshal(raw, &state); err != nil {
		u.log.Warn("extension state file unreadable, treating as empty", "error", err)
		return nil
	}

	return state
}

func (u *Updater) writeState(state []installedExtension) error {
	sort.Slice(state, func(i, j int) bool { return state[i].Name < state[j].Name })

	body, err := json.Marshal(state)
	if err != nil {
		return err
	}

	return os.WriteFile(u.statePath(), body, 0o600)
}

// InstalledExtensions reports what is on disk, for the next check-in.
//
// Read from the state file and confirmed against the filesystem, so an entry
// whose binary has been removed by hand is not reported as installed. The
// server uses this to tell a rollout that is working from one that is
// downloading and failing.
func (u *Updater) InstalledExtensions() []client.InstalledExtension {
	out := []client.InstalledExtension{}

	for _, entry := range u.readState() {
		path := filepath.Join(u.cfg.ExtensionsDir(), extensionFilename(entry.Name))
		if _, err := os.Stat(path); err != nil {
			continue
		}

		out = append(out, client.InstalledExtension{Name: entry.Name, Version: entry.Version})
	}

	return out
}

// reconcileExtensions makes the extensions directory match the server's list.
//
// Returns whether anything changed, which is what decides if osqueryd has to be
// restarted. Errors on a single extension are logged and skipped rather than
// aborting: one bad package should not stop the others installing, and it
// certainly should not stop a withdrawn one being removed.
func (u *Updater) reconcileExtensions(desired []client.Extension) (bool, error) {
	dir := u.cfg.ExtensionsDir()
	// 0750, kept in step with Supervisor.WriteFlagfile, which creates the same
	// directory. It sits inside the 0750 state directory and only osqueryd
	// reads from it.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return false, fmt.Errorf("create extensions directory: %w", err)
	}

	state := u.readState()
	have := make(map[string]installedExtension, len(state))
	for _, entry := range state {
		have[entry.Name] = entry
	}

	changed := false
	next := make([]installedExtension, 0, len(desired))
	keep := make(map[string]bool, len(desired))

	for _, ext := range desired {
		name := strings.ToLower(strings.TrimSpace(ext.Name))
		if !safeName.MatchString(name) {
			u.log.Warn("refusing an extension with an unusable name", "name", ext.Name)
			continue
		}

		keep[extensionFilename(name)] = true
		path := filepath.Join(dir, extensionFilename(name))

		current, known := have[name]
		_, statErr := os.Stat(path)
		if known && statErr == nil &&
			current.Version == ext.Version &&
			strings.EqualFold(current.SHA256, ext.SHA256) {
			next = append(next, current)
			continue
		}

		if err := u.installExtension(ext, name, path); err != nil {
			u.log.Warn("extension install failed", "extension", name, "version", ext.Version, "error", err)

			// Keep claiming whatever is genuinely still on disk. Dropping the
			// entry would report the extension as absent while its binary is
			// still there and still loading, which is worse than a stale
			// version number.
			if known && statErr == nil {
				next = append(next, current)
			}
			continue
		}

		u.log.Info("extension installed", "extension", name, "version", ext.Version)
		next = append(next, installedExtension{Name: name, Version: ext.Version, SHA256: strings.ToLower(ext.SHA256)})
		changed = true
	}

	// Anything else in the directory is no longer wanted. Driven by the
	// directory rather than by the state file so that a binary left behind by
	// an interrupted install — which osqueryd would happily keep loading — is
	// cleaned up too.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return changed, err
	}

	for _, entry := range entries {
		if entry.IsDir() || keep[entry.Name()] {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".ext") && !strings.HasSuffix(entry.Name(), ".ext.exe") {
			continue
		}

		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
			u.log.Warn("could not remove a withdrawn extension", "file", entry.Name(), "error", err)
			continue
		}

		u.log.Info("extension removed", "file", entry.Name())
		changed = true
	}

	if err := u.writeState(next); err != nil {
		u.log.Warn("could not record installed extensions", "error", err)
	}

	return changed, nil
}

// installExtension downloads one extension and puts it where osqueryd looks.
//
// The URL serves the executable itself rather than an archive. There is only
// ever one file, so unpacking would buy nothing and would mean interpreting
// attacker-influenced path names from a tar header on the way to writing a
// root-executed binary — a risk taken for no benefit.
func (u *Updater) installExtension(ext client.Extension, name, dest string) error {
	staging := dest + ".staging"
	defer os.Remove(staging)

	pkg := client.Package{
		Version: ext.Version,
		URL:     ext.URL,
		SHA256:  ext.SHA256,
		Size:    ext.Size,
	}

	// download verifies the checksum and refuses a package without one, which
	// is the whole basis on which this is allowed to run as root.
	if err := u.download(pkg, staging); err != nil {
		return err
	}

	// The checksum proves the file is the one that was published. It says
	// nothing about whether the publisher attached the right file, and the
	// server cannot tell either: packages are published by URL, so GLPI never
	// holds the bytes and has only the platform the administrator picked.
	if err := runnableHere(staging, runtime.GOOS); err != nil {
		return err
	}

	// Executable by its owner and group, readable by neither anyone else: this
	// is a binary osqueryd runs as root, and no other account on the machine
	// has any reason to read or run it. What osqueryd insists on is ownership,
	// not a particular mode (measured 2026-08-21), so 0750 loads exactly
	// as 0755 did.
	if err := os.Chmod(staging, 0o750); err != nil {
		return err
	}

	// osqueryd will not autoload an extension it does not own — measured on
	// 5.19.0, where a binary owned by anyone but the user osqueryd runs as is
	// refused with "unsafe directory permissions" and nothing else happens. A
	// downloaded file is owned by whoever the agent runs as, which is the same
	// user, so this only has to correct the case where it is not.
	if err := ownForOsquery(staging); err != nil {
		return err
	}

	return os.Rename(staging, dest)
}
