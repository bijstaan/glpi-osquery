// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

// Command glpi-edid-ext is an osquery extension exposing monitor EDID data on
// Linux.
//
// Why this exists: osquery 5.19 has a `connected_displays` table on macOS only.
// On Windows the raw EDID block can at least be read out of the registry, but
// on Linux osquery offers neither a monitor table nor any way to read the bytes
// — there is no generic file-contents table. Without this extension, Linux
// machines report no monitors at all, which is a straight regression against
// GLPI Agent.
//
// The table is deliberately shaped like the Windows registry result — a `path`
// and a hex `data` column — so the server's existing EDID decoder and inventory
// assembler handle both platforms through exactly the same code path.
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// TableName is what the inventory pack selects from.
const TableName = "glpi_edid"

// edidGlobs are where the kernel exposes each connector's EDID.
//
// A connector with nothing plugged in exposes an empty file, which is how a
// disconnected port is distinguished from a connected one.
var edidGlobs = []string{
	"/sys/class/drm/*/edid",
}

func main() {
	socket := flag.String("socket", "", "path to osqueryd extensions socket")
	timeout := flag.Int("timeout", 10, "seconds to wait for osqueryd")
	interval := flag.Int("interval", 3, "seconds between registry pings")
	verbose := flag.Bool("verbose", false, "verbose logging")
	flag.Parse()

	if *socket == "" {
		fmt.Fprintln(os.Stderr, "--socket is required (osqueryd supplies it when autoloading)")
		os.Exit(1)
	}

	if *verbose {
		log.SetOutput(os.Stderr)
	} else {
		log.SetOutput(io_Discard{})
	}

	server, err := osquery.NewExtensionManagerServer(
		"glpi_edid",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
		osquery.ServerPingInterval(time.Duration(*interval)*time.Second),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot create extension manager:", err)
		os.Exit(1)
	}

	server.RegisterPlugin(table.NewPlugin(TableName, columns(), generate))
	server.RegisterPlugin(table.NewPlugin(BlockTableName, blockColumns(), generateBlockStack))
	server.RegisterPlugin(table.NewPlugin(BatteryTableName, batteryColumns(), generateBattery))
	server.RegisterPlugin(table.NewPlugin(ChassisTableName, chassisColumns(), generateChassis))

	if err := server.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "extension stopped:", err)
		os.Exit(1)
	}
}

func columns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		// Mirrors the Windows registry table's shape.
		table.TextColumn("path"),
		table.TextColumn("data"),
		// Convenience for anyone querying interactively; the server decodes the
		// raw block itself rather than trusting these.
		table.TextColumn("connector"),
		table.IntegerColumn("bytes"),
		// The mode the kernel selected as preferred, and the connector state.
		table.TextColumn("preferred_mode"),
		table.TextColumn("status"),
	}
}

// preferredMode reads the connector's mode list, whose first entry is the one
// the kernel prefers.
//
// This is deliberately trusted over decoding the EDID ourselves. A modern
// high-resolution panel often carries its native timing in a DisplayID
// extension block (EDID extension tag 0x70) rather than in the base or CTA
// blocks — measured on a 5120x1440 ultrawide whose EDID descriptors advertise
// only 3840x1080 and 2560x1440. Parsing DisplayID is a separate specification;
// the kernel has already done it, so ask the kernel.
func preferredMode(connectorDir string) string {
	raw, err := os.ReadFile(filepath.Join(connectorDir, "modes"))
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(raw), "\n") {
		if mode := strings.TrimSpace(line); mode != "" {
			return mode
		}
	}

	return ""
}

func connectorStatus(connectorDir string) string {
	raw, err := os.ReadFile(filepath.Join(connectorDir, "status"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

func generate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var rows []map[string]string

	for _, pattern := range edidGlobs {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			continue
		}

		for _, path := range matches {
			raw, err := os.ReadFile(path)
			if err != nil {
				// Unreadable connectors are skipped rather than failing the
				// whole query: one inaccessible port should not cost the
				// machine every monitor it does have.
				continue
			}

			// An empty file means the connector has nothing attached.
			if len(raw) < 128 {
				continue
			}

			dir := filepath.Dir(path)
			rows = append(rows, map[string]string{
				"path":           path,
				"data":           hex.EncodeToString(raw),
				"connector":      connectorName(path),
				"bytes":          fmt.Sprintf("%d", len(raw)),
				"preferred_mode": preferredMode(dir),
				"status":         connectorStatus(dir),
			})
		}
	}

	return rows, nil
}

// connectorName turns /sys/class/drm/card1-DP-2/edid into "card1-DP-2".
func connectorName(path string) string {
	dir := filepath.Base(filepath.Dir(path))
	return strings.TrimSpace(dir)
}

// io_Discard avoids pulling in io just for a discard writer.
type io_Discard struct{}

func (io_Discard) Write(p []byte) (int, error) { return len(p), nil }
