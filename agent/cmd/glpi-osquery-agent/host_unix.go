// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

//go:build !windows

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// hostServe runs the agent under signal control.
//
// systemd and launchd both stop a daemon by signalling it, so there is no
// service framework to plug into here — the signal *is* the interface.
func hostServe(serve func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signals
		cancel()
	}()

	return serve(ctx)
}
