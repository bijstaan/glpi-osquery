// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package updater implements the agent's self-update.
package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/bijstaan/glpi-osquery-agent/internal/client"
	"github.com/bijstaan/glpi-osquery-agent/internal/config"
	"github.com/bijstaan/glpi-osquery-agent/internal/version"
)

// MarkerName records an update that has been staged but not yet proven good.
//
// It is read by the preflight script before the service starts, which is what
// makes rollback possible when the new binary is so broken it cannot run: the
// agent itself could not roll back in that case, because it would never
// execute.
const MarkerName = "update-pending.json"

// MaxAttempts is how many failed starts the preflight script tolerates before
// reverting to the previous version.
const MaxAttempts = 3

// Marker is the staged-update record shared with the preflight script.
type Marker struct {
	PreviousVersion string `json:"previous_version"`
	NewVersion      string `json:"new_version"`
	Attempts        int    `json:"attempts"`
	StagedAt        string `json:"staged_at"`
}

// Updater applies packages published by the server.
type Updater struct {
	cfg    *config.Config
	api    *client.Client
	log    *slog.Logger
	token  string
	osqVer func() string

	// TrustedAddresses from the most recent check-in, so the status listener's
	// trust list can follow a change made centrally in GLPI.
	TrustedAddresses []string

	// OnExtensionsChanged is called after the extensions directory has been
	// brought into line with the server's list. Set by the service to restart
	// osqueryd, which reads its autoload list only at startup; left nil by the
	// one-shot mode, where no osqueryd of ours is running to restart.
	OnExtensionsChanged func()
}

func New(cfg *config.Config, api *client.Client, log *slog.Logger, token string, osqueryVersion func() string) *Updater {
	return &Updater{cfg: cfg, api: api, log: log, token: token, osqVer: osqueryVersion}
}

func (u *Updater) markerPath() string {
	return filepath.Join(u.cfg.StateDir, MarkerName)
}

// ConfirmHealthy clears a staged-update marker once the new version has proven
// it can run and reach the server.
//
// This is the other half of rollback: without a positive confirmation, an agent
// that starts but cannot work — wrong CA, broken config parsing — would be
// treated as a successful update and the previous version eventually pruned.
func (u *Updater) ConfirmHealthy() {
	path := u.markerPath()

	raw, err := os.ReadFile(path)
	if err != nil {
		return // nothing staged
	}

	var marker Marker
	if err := json.Unmarshal(raw, &marker); err != nil {
		_ = os.Remove(path)
		return
	}

	if marker.NewVersion != "" && marker.NewVersion != version.Version {
		// We are not the version that was staged. The preflight script has
		// probably rolled back already; leave the marker for it to manage.
		u.log.Warn("running version differs from the staged one",
			"running", version.Version, "staged", marker.NewVersion)
		return
	}

	if err := os.Remove(path); err != nil {
		u.log.Warn("could not clear update marker", "error", err)
		return
	}

	u.log.Info("update confirmed healthy",
		"version", version.Version, "previous", marker.PreviousVersion)

	u.pruneOldVersions(marker.PreviousVersion)
}

// ErrCredentialRejected means the server no longer accepts this agent's token.
var ErrCredentialRejected = errors.New("server rejected the agent credential")

// SetToken swaps in a freshly issued credential after re-enrolment.
func (u *Updater) SetToken(token string) {
	u.token = token
}

// Check asks the server what should be running and applies it.
//
// Returns true when an update was staged and the process should exit so the
// service manager can restart it on the new version.
func (u *Updater) Check() (bool, error) {
	resp, err := u.api.CheckUpdate(client.UpdateRequest{
		AgentToken:     u.token,
		AgentVersion:   version.Version,
		OsqueryVersion: u.osqVer(),
		Arch:           runtimeArch(),
		Extensions:     u.InstalledExtensions(),
	})
	if err != nil {
		// The server no longer knows this agent — an operator revoked it, or
		// forced a re-enrolment. Dropping the cached token is what lets the
		// next start recover on its own; without this the supervisor would
		// keep presenting a credential that will never be accepted again.
		if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "unknown agent") {
			u.log.Warn("server rejected our credential; discarding it so we re-enrol", "error", err)
			if removeErr := os.Remove(u.cfg.TokenPath()); removeErr != nil && !os.IsNotExist(removeErr) {
				u.log.Warn("could not discard cached token", "error", removeErr)
			}
		}

		return false, err
	}

	// A 200 carrying node_invalid is still a rejection. Treating it as a
	// successful no-op check — which is exactly what a plain struct decode
	// does — leaves the agent presenting a dead credential forever while
	// looking healthy in its own logs, and the server never hears its version
	// again.
	if resp.NodeInvalid {
		u.log.Warn("server no longer recognises this agent; discarding the credential to re-enrol")
		if err := os.Remove(u.cfg.TokenPath()); err != nil && !os.IsNotExist(err) {
			u.log.Warn("could not discard cached token", "error", err)
		}

		return false, ErrCredentialRejected
	}

	u.TrustedAddresses = resp.TrustedAddresses

	// Reconciled before the agent-version check below, and independently of it.
	// An extension is a capability scoped to a set of entities, not a version of
	// this agent, so it must not be gated on a staged rollout that exists to
	// pace agent upgrades — nor skipped just because there is no new agent to
	// install, which is the ordinary case.
	//
	// A nil list means the server has nothing to say about extensions, which is
	// what an older plugin sends; an empty one means "you should have none" and
	// does uninstall. Conflating them would strip every extension from a fleet
	// the moment it talked to a plugin that predates this feature.
	if resp.Extensions != nil {
		if !u.cfg.UpdatesEnabled {
			// The same opt-out that blocks agent upgrades. A host configured to
			// refuse server-supplied binaries means it, and an extension is a
			// binary osqueryd executes as root.
			if len(*resp.Extensions) > 0 {
				u.log.Info("extensions offered but updates are disabled on this host",
					"offered", len(*resp.Extensions))
			}
		} else if changed, err := u.reconcileExtensions(*resp.Extensions); err != nil {
			u.log.Warn("could not reconcile extensions", "error", err)
		} else if changed && u.OnExtensionsChanged != nil {
			u.OnExtensionsChanged()
		}
	}

	if !resp.UpdateAvailable {
		return false, nil
	}

	pkg, ok := resp.Packages["agent"]
	if !ok || pkg.Version == "" {
		return false, nil
	}

	if !u.cfg.UpdatesEnabled {
		// The server offers updates but this host has opted out. Say so once
		// per check rather than silently ignoring the instruction.
		u.log.Info("update offered but disabled on this host",
			"offered", pkg.Version, "running", version.Version)
		return false, nil
	}

	if strings.TrimPrefix(pkg.Version, "v") == strings.TrimPrefix(version.Version, "v") {
		return false, nil
	}

	u.log.Info("update offered", "version", pkg.Version, "running", version.Version,
		"ring", resp.Ring, "rollout_percent", resp.RolloutPercent)

	if err := u.apply(pkg); err != nil {
		return false, err
	}

	return true, nil
}

// safeVersion constrains a version string before it is used as a path segment.
//
// The version arrives in the server's update manifest, and apply joins it into
// updates/agent-<v>.archive and versions/<v>. A compromised — or simply buggy —
// server must not be able to stage a tree outside the install root by
// publishing a release called "../../etc". filepath.Base is not enough on its
// own here: it leaves ".." intact, so the pattern is anchored to a leading
// alphanumeric instead, which rejects ".", ".." and every name that starts by
// climbing.
var safeVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

func (u *Updater) apply(pkg client.Package) error {
	if !safeVersion.MatchString(pkg.Version) {
		return fmt.Errorf("refusing a package with an unusable version %q", pkg.Version)
	}

	updatesDir := filepath.Join(u.cfg.StateDir, "updates")
	if err := os.MkdirAll(updatesDir, 0o750); err != nil {
		return err
	}

	// No extension on purpose: the Windows bundle is a zip and every other
	// one a tar.gz, and extractArchive reads the format from the bytes.
	archivePath := filepath.Join(updatesDir, "agent-"+pkg.Version+".archive")
	defer os.Remove(archivePath)

	if err := u.download(pkg, archivePath); err != nil {
		return err
	}

	versionsDir := filepath.Join(u.cfg.InstallRoot, "versions")
	target := filepath.Join(versionsDir, pkg.Version)
	staging := target + ".staging"

	_ = os.RemoveAll(staging)
	// 0755 on purpose, and the same for every directory extractTarGz creates
	// below. This tree is renamed into place as versions/<v>, and it must end up
	// laid out exactly as the .deb, .pkg and MSI lay it down — a machine that
	// updated itself and a machine installed from a package have to be the same
	// machine, or the update path is only ever exercised on hosts that have
	// already updated once. It holds no secret: the contents are the published
	// bundle, byte for byte, and /usr/bin/glpi-osquery-agent is a symlink into
	// it that any user may run `version` through. Everything that is sensitive —
	// the enrolment secret, the agent token, the update marker — lives in the
	// 0750 state directory instead, and nothing here is group- or world-writable.
	if err := os.MkdirAll(staging, 0o755); err != nil {
		return err
	}

	if err := extractArchive(archivePath, staging); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("extract: %w", err)
	}

	if err := u.verifyPayload(staging, pkg.Version); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("staged package rejected: %w", err)
	}

	_ = os.RemoveAll(target)
	if err := os.Rename(staging, target); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	previous, _ := filepath.EvalSymlinks(filepath.Join(u.cfg.InstallRoot, "current"))

	marker := Marker{
		PreviousVersion: filepath.Base(previous),
		NewVersion:      pkg.Version,
		Attempts:        0,
		StagedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.MarshalIndent(marker, "", "  ")
	// 0600: only this agent and the preflight script — both root — ever touch
	// the marker, and it is the record a rollback decision is made from.
	if err := os.WriteFile(u.markerPath(), body, 0o600); err != nil {
		return fmt.Errorf("write update marker: %w", err)
	}

	if err := FlipCurrent(filepath.Join(u.cfg.InstallRoot, "current"), target); err != nil {
		_ = os.Remove(u.markerPath())
		return fmt.Errorf("activate: %w", err)
	}

	u.log.Info("update staged and activated; restarting onto it",
		"version", pkg.Version, "previous", marker.PreviousVersion)

	return nil
}

// download fetches and verifies a package.
//
// Verification is the whole security model of self-update. An agent that
// installs whatever it downloads is a remote code execution channel into every
// endpoint in the estate, and TLS to the right host only proves where the bytes
// came from, not that they are the bytes the administrator published.
func (u *Updater) download(pkg client.Package, dest string) error {
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	digest := sha256.New()

	limit := pkg.Size + (1 << 20)
	if pkg.Size <= 0 {
		limit = 512 << 20
	}

	written, copyErr := u.api.Download(pkg.URL, io.MultiWriter(f, digest), limit)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}

	if pkg.Size > 0 && written != pkg.Size {
		return fmt.Errorf("size mismatch: expected %d bytes, got %d", pkg.Size, written)
	}

	got := hex.EncodeToString(digest.Sum(nil))
	want := strings.ToLower(strings.TrimSpace(pkg.SHA256))
	if want == "" {
		return fmt.Errorf("package %s has no checksum; refusing to install", pkg.Version)
	}
	if got != want {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", want, got)
	}

	u.log.Info("package verified", "version", pkg.Version, "bytes", written, "sha256", got)

	return nil
}

// verifyPayload checks a staged tree before it is allowed to become `current`.
//
// Running the new binary once here is cheap and catches the worst case — a
// package for the wrong architecture, or a truncated binary — while the old
// version is still active and recoverable.
func (u *Updater) verifyPayload(root, expected string) error {
	binary := filepath.Join(root, "bin", agentBinaryName())

	info, err := os.Stat(binary)
	if err != nil {
		return fmt.Errorf("missing %s: %w", binary, err)
	}
	// Windows has no execute bit — Go reports every regular file there as
	// 0666 — so the check would refuse every Windows update ever staged. The
	// run below is the real test on every platform anyway.
	if runtime.GOOS != "windows" && info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", binary)
	}

	out, err := exec.Command(binary, "version").Output()
	if err != nil {
		return fmt.Errorf("new binary does not run: %w", err)
	}

	reported := strings.TrimSpace(string(out))
	if reported != expected {
		return fmt.Errorf("new binary reports version %q, expected %q", reported, expected)
	}

	return nil
}

// pruneOldVersions keeps the previous version and removes anything older, so a
// long-lived machine does not accumulate every release it has ever run.
func (u *Updater) pruneOldVersions(keep string) {
	versionsDir := filepath.Join(u.cfg.InstallRoot, "versions")

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		name := entry.Name()
		if name == version.Version || name == keep || strings.HasSuffix(name, ".staging") {
			continue
		}
		path := filepath.Join(versionsDir, name)
		if err := os.RemoveAll(path); err != nil {
			u.log.Warn("could not remove old version", "path", path, "error", err)
			continue
		}
		u.log.Info("removed old version", "version", name)
	}
}

// extractArchive unpacks a published bundle, whichever of the two formats
// build.sh produced it in: a zip for Windows, where tar is not a native format,
// and a tar.gz everywhere else. Sniffed from the leading bytes rather than
// trusted from the URL, because a package is published by URL and nothing
// guarantees its name.
func extractArchive(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	magic := make([]byte, 4)
	n, _ := io.ReadFull(f, magic)
	f.Close()

	switch {
	case n >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return extractTarGz(archive, dest)
	case n == 4 && string(magic) == "PK\x03\x04":
		return extractZip(archive, dest)
	default:
		return fmt.Errorf("unrecognised archive format (expected tar.gz or zip)")
	}
}

// extractZip is extractTarGz for the Windows bundle, with the same guards:
// every entry is contained under dest, only regular files and directories are
// written, and no file is group- or world-writable.
func extractZip(archive, dest string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()

	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	for _, entry := range zr.File {
		path, err := containedPath(root, entry.Name)
		if err != nil {
			return err
		}

		info := entry.FileInfo()
		switch {
		case info.IsDir():
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		case !info.Mode().IsRegular():
			// Symlinks and the rest, as in extractTarGz.
			continue
		}

		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}

		// A zip written on Windows often carries no Unix mode at all.
		mode := info.Mode().Perm() & 0o755
		if mode == 0 {
			mode = 0o644
		}

		in, err := entry.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, io.LimitReader(in, 1<<30))
		in.Close()
		if closeErr := out.Close(); copyErr == nil {
			copyErr = closeErr
		}
		if copyErr != nil {
			return copyErr
		}
		if err := os.Chmod(path, mode); err != nil {
			return err
		}
	}

	return nil
}

// extractTarGz unpacks an archive, refusing entries that would escape the
// destination directory.
func extractTarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// Reject path traversal: an archive that unpacks outside its
		// destination would let a compromised package overwrite anything on
		// the machine, which is precisely the outcome verification exists to
		// prevent.
		path, err := containedPath(root, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// 0755 to match the layout the packages install — see the note in
			// apply. Nothing secret is unpacked here, and nothing is writable
			// by anyone but the owner.
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			// Group and other write bits are stripped, not merely defaulted.
			// osqueryd refuses to run at all — its own binary, and any extension
			// it would autoload — if either is writable by anyone but its owner,
			// on the reasonable grounds that a writable binary is a root
			// escalation waiting to happen. An archive built with a lax umask
			// would therefore produce an agent that cannot start osqueryd,
			// discovered only after the update had already replaced the working
			// version.
			mode := os.FileMode(header.Mode) & 0o755

			out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			// O_CREATE honours the umask, so a service started with a
			// restrictive one would otherwise land a non-executable binary.
			if err := os.Chmod(path, mode); err != nil {
				out.Close()
				return err
			}
			if _, err := io.Copy(out, io.LimitReader(tr, 1<<30)); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Symlinks and devices are not needed in an agent bundle, and
			// allowing them widens the attack surface for no benefit.
			continue
		}
	}
}

// containedPath resolves one archive entry name against the destination root
// and refuses anything that would land outside it.
//
// Two independent mechanisms, because this is the sink an attacker-supplied
// name reaches and one of them being subtly wrong must not be enough. First the
// name is rooted and cleaned — filepath.Clean("/"+name) resolves every ".."
// against "/" and cannot climb above it, so "../../etc/shadow" becomes
// "/etc/shadow" and joins under the destination rather than escaping it, and an
// already-absolute name is re-anchored the same way. Then the result is checked
// against the root anyway, which is what catches a future edit that changes the
// first step, and what turns a platform difference in separator handling into a
// refusal rather than a write.
//
// Symlink entries never reach this: extractTarGz skips every type but regular
// files and directories, so there is no way to plant a link and then write
// "through" it on a later entry.
func containedPath(root, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("archive entry has an empty name")
	}

	// Tar names are always slash-separated, whatever the platform reading them,
	// so a backslash in a name is a literal character on Unix and a separator on
	// Windows. Normalising here means the same archive is judged identically on
	// both, instead of "..\..\evil" being inert on one and traversal on the
	// other.
	cleaned := filepath.Clean("/" + filepath.FromSlash(name))

	path := filepath.Join(root, cleaned)
	if path != root && !strings.HasPrefix(path, root+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry %q escapes the destination", name)
	}

	return path, nil
}
