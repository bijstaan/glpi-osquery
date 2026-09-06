// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/osquery/osquery-go/plugin/table"
)

// fakeSysfs builds a /sys/class/block tree. Each device is described by its
// dm uuid ("" for a physical device) and the devices beneath it.
func fakeSysfs(t *testing.T, devices map[string]struct {
	uuid, name string
	slaves     []string
}) string {
	t.Helper()

	root := t.TempDir()
	for dev, spec := range devices {
		base := filepath.Join(root, dev)
		if err := os.MkdirAll(base, 0o755); err != nil {
			t.Fatal(err)
		}

		if spec.uuid != "" {
			dm := filepath.Join(base, "dm")
			if err := os.MkdirAll(dm, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dm, "uuid"), []byte(spec.uuid+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dm, "name"), []byte(spec.name+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}

		if len(spec.slaves) > 0 {
			sl := filepath.Join(base, "slaves")
			if err := os.MkdirAll(sl, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, s := range spec.slaves {
				if err := os.MkdirAll(filepath.Join(sl, s), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	return root
}

type devSpec = struct {
	uuid, name string
	slaves     []string
}

func rowsFor(t *testing.T, root string) map[string]map[string]string {
	t.Helper()

	old := sysBlock
	sysBlock = root
	defer func() { sysBlock = old }()

	rows, err := generateBlockStack(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}

	out := map[string]map[string]string{}
	for _, r := range rows {
		out[r["name"]] = r
	}

	return out
}

// The layout measured on real hardware: LVM straight onto an NVMe partition,
// no crypt layer anywhere. osquery reports blank for every one of these
// devices, so this is precisely the case the table exists to answer.
func TestUnencryptedLVMResolvesToNo(t *testing.T) {
	root := fakeSysfs(t, map[string]devSpec{
		"dm-0":      {uuid: "LVM-abc123", name: "ubuntu--vg-ubuntu--lv", slaves: []string{"nvme0n1p3"}},
		"nvme0n1":   {},
		"nvme0n1p3": {},
	})

	rows := rowsFor(t, root)

	if got := rows["dm-0"]["encrypted"]; got != "0" {
		t.Errorf("LVM on a bare partition should resolve to not-encrypted, got %q", got)
	}
	if got := rows["dm-0"]["kind"]; got != "lvm" {
		t.Errorf("kind = %q, want lvm", got)
	}
}

// LVM on top of LUKS — the layout an encrypted Ubuntu install produces. The
// crypt layer is one level below the volume the filesystem is mounted from, so
// a check that only inspects the mounted device sees nothing.
func TestLVMOverLUKSResolvesToYes(t *testing.T) {
	root := fakeSysfs(t, map[string]devSpec{
		"dm-1":      {uuid: "LVM-abc123", name: "ubuntu--vg-ubuntu--lv", slaves: []string{"dm-0"}},
		"dm-0":      {uuid: "CRYPT-LUKS2-deadbeef", name: "dm_crypt-0", slaves: []string{"nvme0n1p3"}},
		"nvme0n1p3": {},
	})

	rows := rowsFor(t, root)

	if got := rows["dm-1"]["encrypted"]; got != "1" {
		t.Errorf("LVM over LUKS should resolve to encrypted, got %q", got)
	}
	if got := rows["dm-1"]["crypt_device"]; got != "dm_crypt-0" {
		t.Errorf("crypt_device = %q, want dm_crypt-0", got)
	}
	if got := rows["dm-0"]["encrypted"]; got != "1" {
		t.Errorf("the crypt device itself should report encrypted, got %q", got)
	}
}

// A mapped device whose backing store cannot be seen must stay blank. Reporting
// "not encrypted" here would be a guess presented as a measurement, and it is
// the exact failure this table was written to remove.
func TestUnresolvableStackStaysUnknown(t *testing.T) {
	root := fakeSysfs(t, map[string]devSpec{
		"dm-0": {uuid: "LVM-abc123", name: "orphan"},
	})

	rows := rowsFor(t, root)

	if got := rows["dm-0"]["encrypted"]; got != "" {
		t.Errorf("an unresolvable stack must stay unknown, got %q", got)
	}
}

// Snap mounts produce dozens of loop devices; they would swamp the rows anyone
// is actually asking about.
func TestLoopAndZramExcluded(t *testing.T) {
	root := fakeSysfs(t, map[string]devSpec{
		"loop0": {}, "zram0": {}, "sda": {},
	})

	rows := rowsFor(t, root)

	if _, ok := rows["loop0"]; ok {
		t.Error("loop devices should be excluded")
	}
	if _, ok := rows["zram0"]; ok {
		t.Error("zram devices should be excluded")
	}
	if _, ok := rows["sda"]; !ok {
		t.Error("real devices should be present")
	}
}
