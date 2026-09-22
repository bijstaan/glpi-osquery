// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"

	"golang.org/x/sys/windows/svc"

	"github.com/bijstaan/glpi-osquery-agent/internal/config"
)

// ServiceName is what the installer registers and the SCM addresses us by.
const ServiceName = "GLPIOsqueryAgent"

// exitCodeUpdateStaged is the service-specific exit code for "stopping to
// restart onto a newly staged version".
const exitCodeUpdateStaged = 3

// redirectServiceOutput sends stderr to a log file when running as a service.
//
// A service has no console, so under the SCM everything the agent logs — and
// the osqueryd warnings and errors it forwards — went nowhere. osqueryd's own
// glog files are written regardless; this puts the agent's log beside them, in
// state\logs, where a technician looking at osqueryd.INFO will find it. The
// previous file is kept as agent.log.1 once it passes 10 MB, so the log is
// bounded without losing the run that failed.
func redirectServiceOutput() {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return
	}

	dir := filepath.Join(config.DefaultStateDir(), "logs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}

	path := filepath.Join(dir, "agent.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 10<<20 {
		_ = os.Rename(path, path+".1")
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	os.Stderr = f
}

// hostServe runs the agent under the Windows service control manager when
// started by it, and as an ordinary console program otherwise.
//
// The distinction matters: a service that does not answer the SCM's start
// handshake within its timeout is killed as failed, however healthy it is —
// while the same binary run by hand from a console must not try to talk to the
// SCM at all. svc.IsWindowsService() tells the two apart, so one binary serves
// both without a separate "run as service" flag anyone can get wrong.
func hostServe(serve func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return err
	}

	if !isService {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt)
		go func() {
			<-signals
			cancel()
		}()

		return serve(ctx)
	}

	return svc.Run(ServiceName, &agentService{serve: serve})
}

type agentService struct {
	serve func(context.Context) error
}

func (s *agentService) Execute(args []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- request.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// Tell the SCM we heard it before doing the work: stopping
				// involves shutting osqueryd down, which is not instant, and a
				// service that goes quiet during that window is reported as
				// hung.
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}

		case err := <-done:
			if err != nil {
				return false, 1
			}
			// The agent stopped on its own: an update was staged and it wants
			// to come back on the new version. That needs a non-zero exit code.
			// The installers set failureflag so that failure actions cover
			// non-crash stops too, but the SCM still treats a service that
			// reports SERVICE_STOPPED with exit code 0 as having stopped
			// normally, and does nothing. A clean exit therefore left the
			// agent stopped until the next reboot. A service-specific code
			// makes the restart happen, and it shows in the event log as the
			// update restart it is.
			return true, exitCodeUpdateStaged
		}
	}
}
