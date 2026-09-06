// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Command glpi-osquery-agent supervises osqueryd on an endpoint and keeps
// itself up to date.
//
// It deliberately contains no collection logic. What the machine reports is
// decided entirely by query packs served from GLPI, so changing the fleet's
// inventory never requires touching an endpoint. This process exists to own the
// osqueryd lifecycle, hold the credentials, and apply updates safely.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bijstaan/glpi-osquery-agent/internal/client"
	"github.com/bijstaan/glpi-osquery-agent/internal/config"
	"github.com/bijstaan/glpi-osquery-agent/internal/hostinfo"
	"github.com/bijstaan/glpi-osquery-agent/internal/httpd"
	"github.com/bijstaan/glpi-osquery-agent/internal/singleton"
	"github.com/bijstaan/glpi-osquery-agent/internal/supervisor"
	"github.com/bijstaan/glpi-osquery-agent/internal/updater"
	"github.com/bijstaan/glpi-osquery-agent/internal/version"
)

// ExitUpdated tells the service manager this process stopped on purpose to be
// restarted on a newly installed version.
const ExitUpdated = 0

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			// Printed bare: the updater runs this on a freshly staged binary
			// and compares the output to the version it expected, so the format
			// is a contract, not a display choice.
			fmt.Println(version.Version)
			return
		case "install":
			if err := runInstall(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "install failed:", err)
				os.Exit(1)
			}
			return
		case "run":
			os.Args = append(os.Args[:1], os.Args[2:]...)
		default:
			// `msi-install` and `msi-uninstall` are what the Windows installer
			// calls. They live in the binary rather than as installer custom
			// actions because an MSI cannot express most of what they do, and
			// because logic here can be tested.
			if run, ok := installerSubcommands[os.Args[1]]; ok {
				if err := run(os.Args[2:]); err != nil {
					fmt.Fprintf(os.Stderr, "%s failed: %v\n", os.Args[1], err)
					os.Exit(1)
				}
				return
			}
		}
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "agent failed:", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// runInstall writes the configuration and enrolls, so the service has
// everything it needs before it first starts.
func runInstall(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	server := fs.String("server", "", "GLPI base URL, e.g. https://glpi.example.com")
	secret := fs.String("secret", "", "enrollment secret from Setup -> osquery Inventory")
	caCert := fs.String("ca-cert", "", "PEM bundle for a private certificate authority")
	confPath := fs.String("config", config.DefaultPath(), "where to write the configuration")
	updates := fs.Bool("updates", true, "allow this host to self-update")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *server == "" || *secret == "" {
		return errors.New("--server and --secret are required")
	}

	cfg := &config.Config{
		ServerURL:      strings.TrimSuffix(*server, "/"),
		EnrollSecret:   *secret,
		CACertPath:     *caCert,
		UpdatesEnabled: *updates,
	}

	if err := config.Save(*confPath, cfg); err != nil {
		return err
	}

	// Reload so defaults are applied exactly as the service will see them.
	loaded, err := config.Load(*confPath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(loaded.StateDir, 0o750); err != nil {
		return err
	}

	log := newLogger("info")
	_, trusted, err := enroll(loaded, log)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	// Persist what the server said may query the status listener. Without this
	// the list would only arrive on the first update check-in, leaving a window
	// after every boot where GLPI's device page cannot reach the agent.
	if len(trusted) > 0 {
		cfg.TrustedAddresses = mergeTrusted(cfg.TrustedAddresses, trusted)
		if err := config.Save(*confPath, cfg); err != nil {
			return err
		}
		log.Info("trusted addresses recorded", "trusted", cfg.TrustedAddresses)
	}

	fmt.Println("enrolled successfully; configuration written to", *confPath)

	return nil
}

// enroll obtains this agent's own credential, reusing a cached one when present.
func enroll(cfg *config.Config, log *slog.Logger) (string, []string, error) {
	if raw, err := os.ReadFile(cfg.TokenPath()); err == nil {
		if token := strings.TrimSpace(string(raw)); token != "" {
			return token, nil, nil
		}
	}

	api, err := client.New(cfg.ServerURL, cfg.CACertPath)
	if err != nil {
		return "", nil, err
	}

	id := hostinfo.Collect()
	log.Info("enrolling", "host", id.HostIdentifier, "platform", id.Platform, "arch", id.Arch)

	token, trusted, err := api.Enroll(client.EnrollRequest{
		EnrollSecret:   cfg.EnrollSecret,
		HostIdentifier: id.HostIdentifier,
		HardwareUUID:   id.HardwareUUID,
		Platform:       id.Platform,
		Arch:           id.Arch,
		AgentVersion:   version.Version,
		ListenPort:     listenPort(cfg),
	})
	if err != nil {
		return "", nil, err
	}

	if err := os.WriteFile(cfg.TokenPath(), []byte(token), 0o600); err != nil {
		return "", nil, fmt.Errorf("cache token: %w", err)
	}

	return token, trusted, nil
}

func run() error {
	confPath := flag.String("config", config.DefaultPath(), "configuration file")
	logLevel := flag.String("log-level", "info", "debug, info, warn or error")
	once := flag.Bool("check-update-once", false, "check for an update, apply it, and exit")
	flag.Parse()

	log := newLogger(*logLevel)

	cfg, err := config.Load(*confPath)
	if err != nil {
		return err
	}

	log.Info("starting", "version", version.Version, "server", cfg.ServerURL)

	// Refuse to run alongside another agent on the same state directory. Both
	// would drive their own osqueryd against one RocksDB, which is
	// single-writer — the symptom is scheduled queries intermittently not
	// running, with nothing logged to explain it.
	lock, err := singleton.Acquire(cfg.StateDir)
	if err != nil {
		return err
	}
	defer lock.Release()

	token, trusted, err := enroll(cfg, log)
	if err != nil {
		return err
	}

	api, err := client.New(cfg.ServerURL, cfg.CACertPath)
	if err != nil {
		return err
	}

	osq := supervisor.New(cfg, log)
	up := updater.New(cfg, api, log, token, osq.OsqueryVersion)

	// osqueryd reads its extension autoload list once, at startup, so a change
	// to the set only takes hold when it is restarted. Left unset in one-shot
	// mode below, where the files are written but no osqueryd of ours is up.
	up.OnExtensionsChanged = osq.Restart

	if *once {
		// Nothing of ours is supervising osqueryd in this mode, so an extension
		// change is written to disk and picked up whenever the service next
		// starts, rather than being restarted into.
		up.OnExtensionsChanged = nil

		staged, err := up.Check()
		if errors.Is(err, updater.ErrCredentialRejected) {
			// The credential was discarded by the check. Re-enrol and retry so a
			// one-shot run — which is how the packaging scripts and cron-style
			// invocations drive the agent — recovers by itself rather than
			// needing a human to notice.
			fresh, _, enrollErr := enroll(cfg, log)
			if enrollErr != nil {
				return enrollErr
			}
			log.Info("re-enrolled after the server rejected our credential")
			up.SetToken(fresh)
			staged, err = up.Check()
		}
		if err != nil {
			return err
		}
		if staged {
			log.Info("update staged; exiting for restart")
		} else {
			log.Info("no update to apply")
		}
		return nil
	}

	if err := osq.WriteFlagfile(); err != nil {
		return err
	}

	// On Windows the service control manager owns the lifecycle, so the loop
	// runs under its supervision and stops when it says so. Everywhere else the
	// same loop is driven by signals. serve() is identical in both cases.
	return hostServe(func(ctx context.Context) error {
		return serve(ctx, cfg, log, api, osq, up, token, trusted)
	})
}

// serve runs the agent until the context is cancelled.
func serve(
	ctx context.Context,
	cfg *config.Config,
	log *slog.Logger,
	api *client.Client,
	osq *supervisor.Supervisor,
	up *updater.Updater,
	token string,
	trusted []string,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Supervise osqueryd for as long as we run.
	osqDone := make(chan struct{})
	go func() {
		defer close(osqDone)
		if err := osq.Run(ctx); err != nil {
			log.Error("supervisor stopped", "error", err)
		}
	}()

	// Local status listener, so GLPI's device page can ask this machine how it
	// is rather than showing "Unknown".
	var listener *httpd.Server
	if !cfg.ListenDisabled {
		listener = &httpd.Server{
			Port:    listenPort(cfg),
			Log:     log,
			Trusted: trustedSources(cfg, trusted),
			Status: func() string {
				if v := osq.OsqueryVersion(); v != "" {
					return fmt.Sprintf("waiting (agent %s, osquery %s)", version.Version, v)
				}
				return fmt.Sprintf("waiting (agent %s, osquery not running)", version.Version)
			},
			RequestInventory: func() error { return api.RequestInventory(token) },
		}

		go func() {
			// A listener that cannot bind is worth reporting but not worth
			// stopping inventory over — the port may simply be taken.
			if err := listener.Run(ctx); err != nil {
				log.Error("status listener stopped", "error", err)
			}
		}()
	}

	// The very first successful check-in on a freshly installed version is what
	// clears the rollback marker, so it is done promptly rather than after a
	// full interval.
	interval := firstCheckDelay(cfg)
	updateStaged := false

	for !updateStaged {
		select {
		case <-ctx.Done():
			log.Info("shutting down")
			cancel()
			osq.Stop()
			<-osqDone
			return nil

		case <-time.After(interval):
			staged, err := up.Check()
			if errors.Is(err, updater.ErrCredentialRejected) {
				// Re-enrol in place rather than waiting for a restart: an agent
				// whose credential was revoked is otherwise mute until someone
				// notices and intervenes on the machine itself.
				if fresh, _, enrollErr := enroll(cfg, log); enrollErr != nil {
					log.Warn("re-enrolment failed", "error", enrollErr)
				} else {
					log.Info("re-enrolled after the server rejected our credential")
					up.SetToken(fresh)
					token = fresh
				}
			} else if err != nil {
				log.Warn("update check failed", "error", err)
			} else if !staged {
				// Reaching the server on this version is the health signal the
				// staged-update marker is waiting for.
				//
				// Skipped when this very check staged an update: the marker then
				// names the version we are about to restart into, not the one
				// running, and confirming it would both clear the rollback guard
				// early and log a version mismatch that is not a fault.
				up.ConfirmHealthy()

				// The server is authoritative about who may query this agent.
				if listener != nil && len(up.TrustedAddresses) > 0 {
					listener.SetTrusted(trustedSources(cfg, up.TrustedAddresses))
				}
			}

			if staged {
				updateStaged = true
				break
			}

			interval = nextInterval(cfg)
		}
	}

	log.Info("restarting to complete update")
	cancel()
	osq.Stop()
	<-osqDone

	// Returning rather than calling os.Exit: under a service host an abrupt
	// exit skips the stop handshake and the manager reports a crash instead of
	// a clean restart.
	return nil
}

func listenPort(cfg *config.Config) int {
	if cfg.ListenPort > 0 {
		return cfg.ListenPort
	}

	return httpd.DefaultPort
}

// trustedSources is who may query the status listener.
//
// The GLPI server is always allowed, because it is the thing that asks — and
// nothing else is, unless an administrator says so. The port can trigger work
// on the endpoint, so leaving it open to the local network would hand anyone
// there a lever on every machine in the estate.
func trustedSources(cfg *config.Config, fromServer []string) []string {
	trusted := append([]string{}, cfg.TrustedAddresses...)
	trusted = append(trusted, fromServer...)

	// The host in the server URL is a sensible default, but not sufficient on
	// its own: GLPI commonly sits behind a TLS terminator, so the status
	// request arrives from the application server rather than from the name the
	// agent was handed. That is why the server can supply the real list.
	if host := serverHost(cfg.ServerURL); host != "" {
		trusted = append(trusted, host)
	}

	return trusted
}

// mergeTrusted unions two lists without duplicates, preserving order.
func mergeTrusted(existing, added []string) []string {
	seen := map[string]bool{}
	out := []string{}

	for _, list := range [][]string{existing, added} {
		for _, entry := range list {
			entry = strings.TrimSpace(entry)
			if entry == "" || seen[entry] {
				continue
			}
			seen[entry] = true
			out = append(out, entry)
		}
	}

	return out
}

func serverHost(serverURL string) string {
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}

	return parsed.Hostname()
}

// firstCheckDelay is short but not immediate: long enough for osqueryd to come
// up, short enough that a bad update is confirmed or rolled back quickly.
func firstCheckDelay(cfg *config.Config) time.Duration {
	if _, err := os.Stat(filepath.Join(cfg.StateDir, updater.MarkerName)); err == nil {
		// An update is awaiting confirmation — check in as soon as osqueryd has
		// had a moment to start.
		return 15 * time.Second
	}

	return 60 * time.Second
}

// nextInterval spreads check-ins so a fleet does not arrive together.
//
// The jitter is derived from the host's own name rather than a random source so
// a machine keeps roughly the same slot between restarts, which makes server
// load predictable instead of merely spread.
func nextInterval(cfg *config.Config) time.Duration {
	base := time.Hour

	id := hostinfo.Collect()
	var sum int
	for _, b := range []byte(id.HostIdentifier) {
		sum += int(b)
	}

	return base + time.Duration(sum%600)*time.Second
}
