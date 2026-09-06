// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package supervisor owns the osqueryd process.
package supervisor

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bijstaan/glpi-osquery-agent/internal/config"
)

// Supervisor keeps osqueryd running with a generated flagfile.
//
// The agent deliberately holds no collection logic: what osquery gathers is
// decided by packs served from GLPI, so changing what the fleet reports never
// requires touching an endpoint. This exists to own the process lifecycle, the
// flagfile and the extension — nothing more.
type Supervisor struct {
	cfg *config.Config
	log *slog.Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{}
	version string

	// Set by Restart so the supervision loop can tell a requested stop apart
	// from osqueryd dying on its own, which are worth very different log lines.
	restarting bool
}

func New(cfg *config.Config, log *slog.Logger) *Supervisor {
	return &Supervisor{cfg: cfg, log: log}
}

// OsqueryVersion reports the version of the bundled binary, for the update
// check-in. Empty if it cannot be determined.
func (s *Supervisor) OsqueryVersion() string {
	s.mu.Lock()
	if s.version != "" {
		defer s.mu.Unlock()
		return s.version
	}
	s.mu.Unlock()

	out, err := exec.Command(s.cfg.OsquerydPath, "--version").Output()
	if err != nil {
		return ""
	}

	// "osqueryd version 5.19.0"
	fields := strings.Fields(strings.TrimSpace(string(out)))
	version := ""
	if len(fields) > 0 {
		version = fields[len(fields)-1]
	}

	s.mu.Lock()
	s.version = version
	s.mu.Unlock()

	return version
}

// WriteFlagfile generates osqueryd's configuration.
//
// Everything here is a bootstrap default: the server's /config response carries
// an `options` block that overrides these at runtime, which is what lets a
// fleet be retuned centrally without touching a single endpoint.
func (s *Supervisor) WriteFlagfile() error {
	if err := os.MkdirAll(s.cfg.StateDir, 0o750); err != nil {
		return err
	}

	// osqueryd can only read the enrollment secret from a file.
	if err := os.WriteFile(s.cfg.SecretPath(), []byte(s.cfg.EnrollSecret), 0o600); err != nil {
		return fmt.Errorf("write enrollment secret: %w", err)
	}

	base := strings.TrimPrefix(strings.TrimPrefix(s.cfg.ServerURL, "https://"), "http://")
	base = strings.TrimSuffix(base, "/")

	flags := []string{
		"--tls_hostname=" + base,
		"--enroll_secret_path=" + s.cfg.SecretPath(),
		"--enroll_tls_endpoint=/plugins/glpiosquery/front/enroll.php",

		"--config_plugin=tls",
		"--config_tls_endpoint=/plugins/glpiosquery/front/config.php",
		"--config_refresh=300",

		"--logger_plugin=tls",
		"--logger_tls_endpoint=/plugins/glpiosquery/front/log.php",
		"--logger_tls_period=10",

		"--disable_distributed=false",
		"--distributed_plugin=tls",
		"--distributed_tls_read_endpoint=/plugins/glpiosquery/front/read.php",
		"--distributed_tls_write_endpoint=/plugins/glpiosquery/front/write.php",
		"--distributed_interval=10",

		"--database_path=" + s.cfg.OsqueryDBPath(),
		"--logger_path=" + filepath.Join(s.cfg.StateDir, "logs"),
		"--pidfile=" + filepath.Join(s.cfg.StateDir, "osqueryd.pid"),

		// Keep the extension socket inside our own state directory.
		//
		// osquery defaults this to /var/osquery/osquery.em, a directory created
		// by osquery's own package — which we deliberately do not install,
		// because the bundle ships its own osqueryd. On any normal target that
		// directory is absent, so the extension manager fails to start with
		// "Extension socket directory missing" and every extension table is
		// silently unavailable.
		"--extensions_socket=" + s.cfg.ExtensionSocketPath(),

		// Evented tables are the main thing a resident daemon buys over a
		// periodic scan, so the publish/subscribe system stays on.
		"--disable_events=false",
	}

	if s.cfg.CACertPath != "" {
		flags = append(flags, "--tls_server_certs="+s.cfg.CACertPath)
	}

	// What osqueryd should autoload: our own bundled extension, named
	// explicitly, plus the directory holding whatever GLPI has published.
	//
	// The autoload file takes one path per line and a line may be a directory,
	// which osqueryd expands to every extension inside it — verified against
	// 5.19.0, including the two forms mixed in one file as they are here. That
	// is what lets published extensions come and go without this file, or the
	// flagfile, ever being rewritten.
	var autoload []string

	if s.cfg.ExtensionPath != "" {
		if _, err := os.Stat(s.cfg.ExtensionPath); err == nil {
			autoload = append(autoload, s.cfg.ExtensionPath)
		} else {
			s.log.Debug("no bundled extension present, skipping autoload", "path", s.cfg.ExtensionPath)
		}
	}

	// Created whether or not anything is in it yet: osqueryd tolerates an empty
	// autoload directory, and creating it here means the first extension to
	// arrive needs nothing but a file written into place.
	// 0750 matches the state directory this lives inside (and systemd's
	// StateDirectoryMode). osqueryd's autoload safety check is on the extension
	// *file's* ownership, not on the directory's mode — measured on 5.19.0, see
	// docs/spec.md — so tightening the directory changes nothing it cares about.
	if err := os.MkdirAll(s.cfg.ExtensionsDir(), 0o750); err != nil {
		return fmt.Errorf("create extensions directory: %w", err)
	}
	autoload = append(autoload, s.cfg.ExtensionsDir())

	if len(autoload) > 0 {
		body := strings.Join(autoload, "\n") + "\n"
		// 0640, as for the flagfile below: only osqueryd — started by this
		// process, as the same user — ever reads it.
		if err := os.WriteFile(s.cfg.ExtensionsLoadPath(), []byte(body), 0o640); err != nil {
			return fmt.Errorf("write extensions.load: %w", err)
		}
		flags = append(flags,
			"--extensions_autoload="+s.cfg.ExtensionsLoadPath(),
			"--extensions_timeout=10",
		)
	}

	if err := os.MkdirAll(filepath.Join(s.cfg.StateDir, "logs"), 0o750); err != nil {
		return err
	}

	body := strings.Join(flags, "\n") + "\n"

	return os.WriteFile(s.cfg.FlagfilePath(), []byte(body), 0o640)
}

// Run supervises osqueryd until the context is cancelled.
//
// A crashed osqueryd is restarted with a capped backoff. Giving up entirely
// would leave the machine silently uninventoried and unreachable by live query,
// which looks exactly like a switched-off computer — so it keeps trying.
func (s *Supervisor) Run(ctx context.Context) error {
	backoff := 2 * time.Second
	const maxBackoff = 2 * time.Minute

	for {
		if ctx.Err() != nil {
			return nil
		}

		started := time.Now()
		err := s.runOnce(ctx)

		if ctx.Err() != nil {
			return nil
		}

		// A process that stayed up is treated as healthy: reset the backoff so
		// an occasional crash does not permanently slow restarts.
		if time.Since(started) > 5*time.Minute {
			backoff = 2 * time.Second
		}

		s.mu.Lock()
		deliberate := s.restarting
		s.restarting = false
		s.mu.Unlock()

		if deliberate {
			// Asked for. Logging this at warning level would teach an operator
			// to ignore the one line that means osqueryd fell over on its own.
			s.log.Info("osqueryd stopped for a restart", "uptime", time.Since(started).Round(time.Second))
			backoff = 2 * time.Second
		} else {
			s.log.Warn("osqueryd exited, restarting", "error", err, "uptime", time.Since(started).Round(time.Second), "backoff", backoff)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// waitForPidfile gives a previous osqueryd time to release its pidfile.
//
// The agent restarts itself to complete an update, and the outgoing osqueryd's
// worker child can outlive its watchdog by a moment. Starting into that window
// makes the new osqueryd exit immediately with "Pidfile::Error::Busy" — which
// the backoff recovers from, but only after logging a crash on every single
// update. Waiting turns a routine restart back into a quiet one.
func (s *Supervisor) waitForPidfile(ctx context.Context) {
	path := filepath.Join(s.cfg.StateDir, "osqueryd.pid")

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if !pidfileHeld(path) {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(250 * time.Millisecond):
		}
	}

	s.log.Warn("previous osqueryd still holds the pidfile; starting anyway", "pidfile", path)
}

func (s *Supervisor) runOnce(ctx context.Context) error {
	s.waitForPidfile(ctx)

	cmd := exec.CommandContext(ctx, s.cfg.OsquerydPath, "--flagfile="+s.cfg.FlagfilePath())

	// The environment is passed through unmodified on purpose. Setting
	// OSQUERY_WORKER here (to stop osquery forking its own watchdog) makes
	// osqueryd believe it *is* the watchdog's worker child — and a worker does
	// not autoload extensions, so the EDID table silently never appears. The
	// watchdog is worth having anyway: it restarts a wedged or memory-hungry
	// worker without the supervisor needing to notice.
	cmd.Env = os.Environ()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start osqueryd: %w", err)
	}

	// Closed when cmd.Wait below returns. Stop waits on this rather than calling
	// Wait itself: a second Wait on the same child races the first, and whichever
	// loses gets ECHILD straight away — so Stop would report a clean shutdown the
	// instant it was asked for one, and its kill escalation would never fire.
	exited := make(chan struct{})

	s.mu.Lock()
	s.cmd = cmd
	s.exited = exited
	s.mu.Unlock()

	defer close(exited)

	s.log.Info("osqueryd started", "pid", cmd.Process.Pid, "path", s.cfg.OsquerydPath)

	// osqueryd logs to stderr; forward warnings and errors so they end up in
	// the service journal rather than being discarded.
	go func() {
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			switch {
			case strings.HasPrefix(line, "E"):
				s.log.Error("osqueryd", "line", line)
			case strings.HasPrefix(line, "W"):
				s.log.Warn("osqueryd", "line", line)
			default:
				s.log.Debug("osqueryd", "line", line)
			}
		}
	}()

	return cmd.Wait()
}

// Stop asks osqueryd to shut down.
// Restart brings osqueryd down so the Run loop starts it again.
//
// Needed because osqueryd reads its autoload list once, at startup: an
// extension written into the drop-in directory afterwards is simply not there
// as far as the running daemon is concerned, and one deleted from it keeps
// running until the process ends. Nothing else about the agent needs to move,
// so this is deliberately not an agent restart.
func (s *Supervisor) Restart() {
	s.mu.Lock()
	s.restarting = true
	s.mu.Unlock()

	s.log.Info("restarting osqueryd to pick up an extension change")
	s.Stop()
}

func (s *Supervisor) Stop() {
	s.mu.Lock()
	cmd := s.cmd
	done := s.exited
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil || done == nil {
		return
	}

	_ = cmd.Process.Signal(os.Interrupt)

	select {
	case <-done:
	case <-time.After(20 * time.Second):
		s.log.Warn("osqueryd did not stop in time, killing")
		_ = cmd.Process.Kill()
	}
}
