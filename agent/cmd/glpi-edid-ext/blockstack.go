// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// BlockTableName exposes the Linux block-device stack.
//
// Why this exists: osquery's `disk_encryption` table answers per-device, and on
// Linux it leaves `encrypted` BLANK for anything it cannot probe — measured on
// real hardware, that is every NVMe node and every device-mapper node. A stock
// Ubuntu install puts the root filesystem on an LVM logical volume backed by an
// NVMe partition, so the one machine layout where the answer matters most is
// exactly the one osquery declines to answer for.
//
// Blank is then indistinguishable from "not encrypted", and reporting UNKNOWN
// for it means an entirely unencrypted fleet reads as "we could not tell"
// rather than as a finding.
//
// The kernel already knows. /sys/block/<dev>/dm/uuid is prefixed CRYPT- for a
// dm-crypt target and LVM- for a logical volume, and /sys/block/<dev>/slaves/
// names the layer beneath. Walking that is what lsblk does, and it turns a
// blank into a definite yes or no.
const BlockTableName = "glpi_block_stack"

func blockColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),   // kernel name, e.g. dm-0
		table.TextColumn("device"), // /dev/dm-0
		table.TextColumn("dm_name"),
		table.TextColumn("dm_uuid"),
		// crypt | lvm | physical | other
		table.TextColumn("kind"),
		table.TextColumn("parents"),
		// 1 when this device or anything beneath it is a dm-crypt target, 0 when
		// the stack resolved with no crypt layer, empty when it could not be
		// resolved at all. The distinction is the entire point of the table.
		table.TextColumn("encrypted"),
		table.TextColumn("crypt_device"),
	}
}

// /sys/class/block rather than /sys/block: the latter lists only whole disks
// and device-mapper nodes, with partitions nested one level down inside their
// parent. slaves/ names partitions directly, so a walk based on /sys/block
// dead-ends at the first partition it meets — which on an LVM-on-partition
// layout is immediately, leaving the root volume permanently unresolved.
var sysBlock = "/sys/class/block"

// dmUUID reads a device-mapper UUID, empty for a device that is not dm.
func dmUUID(name string) string {
	raw, err := os.ReadFile(filepath.Join(sysBlock, name, "dm", "uuid"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

func dmName(name string) string {
	raw, err := os.ReadFile(filepath.Join(sysBlock, name, "dm", "name"))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

// slaves are the devices immediately beneath this one in the stack.
func slaves(name string) []string {
	entries, err := os.ReadDir(filepath.Join(sysBlock, name, "slaves"))
	if err != nil {
		return nil
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)

	return out
}

func kindOf(uuid string) string {
	switch {
	case strings.HasPrefix(uuid, "CRYPT-"):
		return "crypt"
	case strings.HasPrefix(uuid, "LVM-"):
		return "lvm"
	case uuid != "":
		return "other"
	default:
		return "physical"
	}
}

// findCrypt walks down the stack looking for a dm-crypt layer.
//
// Returns the dm name of the crypt device and whether the walk completed. An
// incomplete walk — a slaves directory that cannot be read — must not be
// reported as "no encryption found", because that is a guess presented as a
// measurement.
func findCrypt(name string, seen map[string]bool) (string, bool) {
	if seen[name] {
		return "", true // already visited; not a failure
	}
	seen[name] = true

	uuid := dmUUID(name)
	if strings.HasPrefix(uuid, "CRYPT-") {
		if n := dmName(name); n != "" {
			return n, true
		}

		return name, true
	}

	// A device with no dm/uuid is a physical device or partition: the bottom of
	// the stack, and a complete answer in itself.
	if uuid == "" {
		if _, err := os.Stat(filepath.Join(sysBlock, name)); err != nil {
			return "", false
		}

		return "", true
	}

	children := slaves(name)
	if len(children) == 0 {
		return "", false // a mapped device with no visible backing: unresolved
	}

	complete := true
	for _, child := range children {
		found, ok := findCrypt(child, seen)
		if found != "" {
			return found, true
		}
		if !ok {
			complete = false
		}
	}

	return "", complete
}

func generateBlockStack(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	entries, err := os.ReadDir(sysBlock)
	if err != nil {
		return nil, err
	}

	rows := make([]map[string]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()

		// Loop and zram devices are noise here: dozens of snap mounts would
		// swamp the handful of rows anyone is actually asking about.
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "zram") {
			continue
		}

		uuid := dmUUID(name)
		crypt, complete := findCrypt(name, map[string]bool{})

		encrypted := ""
		switch {
		case crypt != "":
			encrypted = "1"
		case complete:
			encrypted = "0"
		}

		rows = append(rows, map[string]string{
			"name":         name,
			"device":       "/dev/" + name,
			"dm_name":      dmName(name),
			"dm_uuid":      uuid,
			"kind":         kindOf(uuid),
			"parents":      strings.Join(slaves(name), ","),
			"encrypted":    encrypted,
			"crypt_device": crypt,
		})
	}

	return rows, nil
}
