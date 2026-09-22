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

func writeAttrs(t *testing.T, dir string, attrs map[string]string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, value := range attrs {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBatteryFromCharge(t *testing.T) {
	root := t.TempDir()
	sysPowerSupply = root
	t.Cleanup(func() { sysPowerSupply = "/sys/class/power_supply" })

	// Read from a Framework Laptop 13: the driver reports charge in µAh, so
	// energy has to come from the design voltage. 3915 mAh × 15.48 V is the
	// 61 Wh the battery is sold as.
	writeAttrs(t, filepath.Join(root, "BAT1"), map[string]string{
		"type": "Battery", "manufacturer": "NVT", "model_name": "FRANGWA",
		"serial_number": "013C", "technology": "Li-ion", "status": "Discharging",
		"cycle_count": "143", "capacity": "100",
		"charge_full_design": "3915000", "charge_full": "3650000",
		"voltage_min_design": "15480000", "voltage_now": "17523000",
	})
	// Neither of these is the computer's battery.
	writeAttrs(t, filepath.Join(root, "ACAD"), map[string]string{"type": "Mains"})
	writeAttrs(t, filepath.Join(root, "hidpp_battery_0"), map[string]string{
		"type": "Battery", "scope": "Device", "model_name": "MX Master 3",
	})

	rows, err := generateBattery(context.Background(), table.QueryContext{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want only the system battery, got %d rows: %v", len(rows), rows)
	}

	want := map[string]string{
		"name": "BAT1", "model": "FRANGWA", "serial": "013C", "technology": "Li-ion",
		"cycle_count": "143", "design_capacity_mwh": "60604", "full_capacity_mwh": "56502",
		"voltage_mv": "15480",
	}
	for k, v := range want {
		if rows[0][k] != v {
			t.Errorf("%s = %q, want %q", k, rows[0][k], v)
		}
	}
}

func TestBatteryFromEnergy(t *testing.T) {
	root := t.TempDir()
	sysPowerSupply = root
	t.Cleanup(func() { sysPowerSupply = "/sys/class/power_supply" })

	// Most ThinkPads and Dells report energy in µWh, which needs no voltage.
	writeAttrs(t, filepath.Join(root, "BAT0"), map[string]string{
		"type": "Battery", "energy_full_design": "57000000", "energy_full": "51300000",
		"voltage_min_design": "11580000",
	})

	rows, _ := generateBattery(context.Background(), table.QueryContext{})
	if len(rows) != 1 || rows[0]["design_capacity_mwh"] != "57000" || rows[0]["full_capacity_mwh"] != "51300" {
		t.Fatalf("energy not carried through: %v", rows)
	}
}

func TestBatteryChargeWithoutVoltage(t *testing.T) {
	root := t.TempDir()
	sysPowerSupply = root
	t.Cleanup(func() { sysPowerSupply = "/sys/class/power_supply" })

	// A charge with no voltage cannot become energy; a capacity off by the
	// voltage would be worse than none.
	writeAttrs(t, filepath.Join(root, "BAT0"), map[string]string{
		"type": "Battery", "charge_full_design": "3915000",
	})

	rows, _ := generateBattery(context.Background(), table.QueryContext{})
	if len(rows) != 1 || rows[0]["design_capacity_mwh"] != "" {
		t.Fatalf("capacity invented without a voltage: %v", rows)
	}
}

func TestNoPowerSupplyClass(t *testing.T) {
	sysPowerSupply = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { sysPowerSupply = "/sys/class/power_supply" })

	rows, err := generateBattery(context.Background(), table.QueryContext{})
	if err != nil || len(rows) != 0 {
		t.Fatalf("a machine with no batteries should be no rows and no error, got %v, %v", rows, err)
	}
}

func TestChassis(t *testing.T) {
	root := t.TempDir()
	sysDMI = root
	t.Cleanup(func() { sysDMI = "/sys/class/dmi/id" })

	// 0x8A: a notebook with the chassis-lock bit set.
	writeAttrs(t, root, map[string]string{
		"chassis_type": "138", "chassis_vendor": "Framework", "chassis_asset_tag": "FRANDGCPA7337400KQ",
	})

	rows, err := generateChassis(context.Background(), table.QueryContext{})
	if err != nil || len(rows) != 1 {
		t.Fatalf("got %v, %v", rows, err)
	}
	if rows[0]["chassis_type"] != "10" || rows[0]["chassis_name"] != "Notebook" {
		t.Fatalf("lock bit not masked: %v", rows[0])
	}
	if rows[0]["vendor"] != "Framework" || rows[0]["serial"] != "" {
		t.Fatalf("attributes: %v", rows[0])
	}
}
