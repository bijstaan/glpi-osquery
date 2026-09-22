// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bijstaan/glpi-osquery-agent/internal/config"
	"github.com/bijstaan/glpi-osquery-agent/internal/httpd"
	"github.com/bijstaan/glpi-osquery-agent/internal/updater"
	"github.com/bijstaan/glpi-osquery-agent/internal/version"
)

// The MSI's post-install and pre-uninstall work, as subcommands of the agent
// rather than as a pile of custom actions in the installer.
//
// An MSI cannot express most of what has to happen here — a directory junction,
// a service binary path that ServiceInstall refuses to let you override, service
// failure actions, an enrolment, a conditional start. Doing it with installer
// primitives means several shell-outs whose only error reporting is an exit
// code, and which no test can reach; doing it here means ordinary error
// messages and logic that `go test` can exercise.

// installTree normalises what the MSI handed us.
//
// [INSTALLFOLDER] formats with a trailing backslash and the .wxs appends a
// period to keep that backslash from escaping the closing quote, so the value
// arrives as `C:\Program Files\...\.`. Clean removes both, and a value typed
// by hand with or without a trailing separator lands on the same string — which
// matters because this path is compared, joined and handed to sc.exe.
func installTree(root string) string {
	return filepath.Clean(root)
}

func msiInstall(args []string) error {
	fs := flag.NewFlagSet("msi-install", flag.ExitOnError)
	installRoot := fs.String("install-root", config.DefaultInstallRoot(), "versioned install tree")
	server := fs.String("server", "", "GLPI base URL; enrolment is skipped when empty")
	secret := fs.String("secret", "", "enrollment secret; enrolment is skipped when empty")
	caCert := fs.String("ca-cert", "", "PEM bundle for a private certificate authority")
	noUpdates := fs.Bool("no-updates", false, "pin this host to the installed version")
	if err := fs.Parse(args); err != nil {
		return err
	}

	root := installTree(*installRoot)
	confPath := config.DefaultPath()

	// The version directory is named for what this binary reports, which is also
	// what the MSI was told to name it. If those disagree the updater's
	// comparisons go wrong in confusing ways, so it is checked where the message
	// can say so plainly.
	versionDir := filepath.Join(root, "versions", version.Version)
	if _, err := os.Stat(versionDir); err != nil {
		return fmt.Errorf("expected this version at %s: %w", versionDir, err)
	}

	if err := updater.FlipCurrent(filepath.Join(root, "current"), versionDir); err != nil {
		return fmt.Errorf("create the current junction: %w", err)
	}

	if err := os.MkdirAll(config.DefaultStateDir(), 0o750); err != nil {
		return fmt.Errorf("create the state directory: %w", err)
	}
	if err := config.SecureDataRoot(); err != nil {
		return fmt.Errorf("restrict access to the state directory: %w", err)
	}

	// ServiceInstall takes the binary path from its component's key file, which
	// is the versioned one, and offers no way to override it. Left alone the SCM
	// would keep launching the version the MSI installed however many times the
	// agent updated itself, so self-update would be silently inert on every
	// MSI-installed machine.
	//
	// No ACL work here, unlike the scanner: this service runs as LocalSystem —
	// osqueryd needs it for WMI, the registry and disk reads — and LocalSystem
	// can already write under Program Files.
	binPath := fmt.Sprintf(`"%s" run`, filepath.Join(root, "current", "bin", "glpi-osquery-agent.exe"))
	if err := sc("config", ServiceName, "binPath=", binPath); err != nil {
		return fmt.Errorf("point the service at the current junction: %w", err)
	}

	// Restart on failure, and — via failureflag — on a non-crash stop that
	// reports an error code. The agent stops deliberately after staging an
	// update, with a service-specific exit code (see exitCodeUpdateStaged), so
	// that it comes back on the new version; a stop with exit code 0 would be
	// taken as final, whatever the flag says.
	if err := sc("failure", ServiceName, "reset=", "86400",
		"actions=", "restart/5000/restart/5000/restart/30000"); err != nil {
		return fmt.Errorf("set the service failure actions: %w", err)
	}
	if err := sc("failureflag", ServiceName, "1"); err != nil {
		return fmt.Errorf("set the service failure flag: %w", err)
	}

	// GLPI's device page asks the agent for its status, and to run an
	// inventory, on this port. Windows Defender Firewall drops unsolicited
	// inbound traffic by default, so without a rule both simply time out on
	// Windows while working everywhere else. The listener refuses anyone but
	// the GLPI server and the configured trusted addresses, so opening the
	// port does not open the agent.
	if err := openFirewall(httpd.DefaultPort); err != nil {
		fmt.Fprintln(os.Stderr, "could not add the firewall rule for the status listener:", err)
	}

	if *server == "" || *secret == "" {
		// Deliberately leaves the service registered, stopped and on demand: a
		// deployment that omitted the credentials should not produce a machine
		// restart-looping against a server it was never told about.
		fmt.Println("installed without credentials; enrol with `glpi-osquery-agent install` and start the service")
		return nil
	}

	enrollArgs := []string{"--server", *server, "--secret", *secret, "--ca-cert", *caCert}
	if *noUpdates {
		enrollArgs = append(enrollArgs, "--updates=false")
	}

	// A failed enrolment is reported but not fatal: `install` writes the
	// configuration before it contacts GLPI, so a server that is briefly
	// unreachable during a rollout still leaves a machine that enrols later.
	if err := runInstall(enrollArgs); err != nil {
		fmt.Fprintln(os.Stderr, "enrolment did not complete; the agent will retry:", err)
	}

	if _, err := os.Stat(confPath); err != nil {
		return nil // nothing to start
	}

	if err := sc("config", ServiceName, "start=", "auto"); err != nil {
		return fmt.Errorf("enable the service: %w", err)
	}
	if err := sc("start", ServiceName); err != nil {
		fmt.Fprintln(os.Stderr, "could not start the service:", err)
	}

	return nil
}

func msiUninstall(args []string) error {
	fs := flag.NewFlagSet("msi-uninstall", flag.ExitOnError)
	installRoot := fs.String("install-root", config.DefaultInstallRoot(), "versioned install tree")
	if err := fs.Parse(args); err != nil {
		return err
	}

	closeFirewall()

	// os.Remove, never RemoveAll: the junction points at a real directory, and
	// following it would delete what it names rather than the link itself.
	link := filepath.Join(installTree(*installRoot), "current")
	if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the current junction: %w", err)
	}

	return nil
}

// firewallRule names the inbound rule for the status listener.
const firewallRule = "GLPI osquery agent status listener"

// openFirewall allows inbound TCP to the status listener, replacing any rule a
// previous install left so a reinstall does not stack duplicates.
func openFirewall(port int) error {
	closeFirewall()

	out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+firewallRule, "dir=in", "action=allow", "protocol=TCP",
		fmt.Sprintf("localport=%d", port), "profile=any").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// closeFirewall removes the rule; there being none is not an error.
func closeFirewall() {
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+firewallRule).Run()
}

// sc drives the service control manager.
//
// `sc config binPath= x` really is two arguments with the trailing space inside
// the first: sc.exe parses `name=` and its value separately, and `binPath=x`
// silently does nothing.
func sc(args ...string) error {
	out, err := exec.Command("sc", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
