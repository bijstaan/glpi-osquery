// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build windows

package main

import (
	"context"
	"os"
	"os/signal"

	"golang.org/x/sys/windows/svc"
)

// ServiceName is what the installer registers and the SCM addresses us by.
const ServiceName = "GLPIOsqueryAgent"

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
			// The agent stopped on its own — an update was staged and it wants
			// to come back on the new version. Exit cleanly so the SCM's
			// restart policy applies rather than recording a failure.
			if err != nil {
				return false, 1
			}
			return false, 0
		}
	}
}
