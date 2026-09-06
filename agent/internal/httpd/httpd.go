// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Package httpd serves the agent's local status listener.
//
// GLPI's device page shows an "Agent status" field with a refresh button. That
// button does not consult the database — GLPI makes an HTTP request *to the
// endpoint*, on port 62354 by default, and displays what comes back. An agent
// with no listener therefore always reads "Unknown", which is what this fixes.
//
// The endpoints mirror the ones GLPI expects from its own agent:
//
//	GET /status  ->  "status: <text>"   (GLPI strips the "status: " prefix)
//	GET /now     ->  ask for a fresh inventory
package httpd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultPort is the port GLPI tries first (Agent::DEFAULT_PORT).
const DefaultPort = 62354

// Server is the agent's local listener.
type Server struct {
	Port    int
	Log     *slog.Logger
	Trusted []string

	// Status returns the text shown on the device page.
	Status func() string

	// RequestInventory is invoked by GET /now.
	RequestInventory func() error

	mu       sync.Mutex
	trustNet []*net.IPNet
	trustIP  []net.IP
}

// SetTrusted replaces the trust list at runtime, so a change made centrally in
// GLPI takes effect on the next check-in rather than needing the agent
// restarted on every endpoint.
func (s *Server) SetTrusted(trusted []string) {
	s.mu.Lock()
	changed := strings.Join(s.Trusted, ",") != strings.Join(trusted, ",")
	s.Trusted = trusted
	s.mu.Unlock()

	if changed {
		s.buildTrustList()
		s.Log.Info("status listener trust list updated", "trusted", trusted)
	}
}

// Run serves until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if s.Port == 0 {
		s.Port = DefaultPort
	}

	s.buildTrustList()

	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.guard(s.handleStatus))
	mux.HandleFunc("/now", s.guard(s.handleNow))
	// GLPI appends a token to /now in some versions; treat any /now/... the same.
	mux.HandleFunc("/now/", s.guard(s.handleNow))

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.Port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.Log.Info("status listener started", "port", s.Port, "trusted", s.Trusted)

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

// buildTrustList parses the configured trusted sources once.
func (s *Server) buildTrustList() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.trustNet = nil
	s.trustIP = nil

	for _, entry := range s.Trusted {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			s.trustNet = append(s.trustNet, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			s.trustIP = append(s.trustIP, ip)
			continue
		}
		// A hostname: resolve now. The GLPI server's name is the usual case.
		if addrs, err := net.LookupIP(entry); err == nil {
			s.trustIP = append(s.trustIP, addrs...)
		} else {
			s.Log.Warn("could not resolve trusted address", "entry", entry, "error", err)
		}
	}
}

func (s *Server) trusts(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	if ip.IsLoopback() {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, known := range s.trustIP {
		if known.Equal(ip) {
			return true
		}
	}
	for _, network := range s.trustNet {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// guard refuses anything not from a trusted source.
//
// This port can trigger work on the machine, so it is closed by default to
// everyone except the GLPI server that owns the agent. An open /now on every
// endpoint in the estate would be a denial-of-service lever for anyone on the
// same network.
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.trusts(r.RemoteAddr) {
			s.Log.Warn("rejected status request from untrusted address", "remote", r.RemoteAddr, "path", r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := "waiting"
	if s.Status != nil {
		if text := strings.TrimSpace(s.Status()); text != "" {
			status = text
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// The "status: " prefix is part of the contract — GLPI strips exactly this.
	fmt.Fprintf(w, "status: %s", status)
}

func (s *Server) handleNow(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if s.RequestInventory == nil {
		fmt.Fprint(w, "status: inventory not supported")
		return
	}

	if err := s.RequestInventory(); err != nil {
		s.Log.Warn("inventory request failed", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "status: inventory request failed: %v", err)
		return
	}

	s.Log.Info("inventory requested via status listener", "remote", r.RemoteAddr)
	fmt.Fprint(w, "status: inventory requested")
}
