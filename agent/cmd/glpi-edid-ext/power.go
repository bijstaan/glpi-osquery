// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package main

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// BatteryTableName exposes laptop batteries on Linux.
//
// osquery's `battery` table exists on macOS and Windows only, so a Linux
// laptop reported no battery to GLPI at all. The kernel has everything in
// /sys/class/power_supply.
const BatteryTableName = "glpi_battery"

// ChassisTableName exposes the SMBIOS chassis on Linux.
//
// osquery's `chassis_info` is Windows-only. Without a chassis type GLPI types
// the computer after its motherboard model instead — a Framework laptop
// arrived as a "FRANMDCP07".
const ChassisTableName = "glpi_chassis"

var (
	sysPowerSupply = "/sys/class/power_supply"
	sysDMI         = "/sys/class/dmi/id"
)

func batteryColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("manufacturer"),
		table.TextColumn("model"),
		table.TextColumn("serial"),
		table.TextColumn("technology"),
		table.TextColumn("status"),
		table.IntegerColumn("cycle_count"),
		table.IntegerColumn("capacity_percent"),
		// Already in GLPI's units. Converting here rather than on the server
		// because only this side can see whether the kernel reported energy
		// (µWh) or charge (µAh), and a charge needs a voltage to become energy.
		table.IntegerColumn("design_capacity_mwh"),
		table.IntegerColumn("full_capacity_mwh"),
		table.IntegerColumn("voltage_mv"),
	}
}

func chassisColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.IntegerColumn("chassis_type"),
		table.TextColumn("chassis_name"),
		table.TextColumn("vendor"),
		table.TextColumn("serial"),
		table.TextColumn("asset_tag"),
	}
}

// readAttr reads one sysfs attribute, empty when it is absent or unreadable.
func readAttr(dir, name string) string {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(raw))
}

func readInt(dir, name string) (int64, bool) {
	v, err := strconv.ParseInt(readAttr(dir, name), 10, 64)
	if err != nil {
		return 0, false
	}

	return v, true
}

func itoa(v int64) string {
	if v <= 0 {
		return ""
	}

	return strconv.FormatInt(v, 10)
}

// capacityMWh is a battery capacity in mWh, from whichever of energy or charge
// the driver exposes. prefix is "full_design" or "full".
//
// energy_* is µWh. charge_* is µAh and becomes energy only through a voltage,
// for which the design minimum is the one that means something: the present
// voltage moves with the charge level and would make the design capacity
// wander from one inventory to the next.
func capacityMWh(dir, prefix string, microvolts int64) int64 {
	if uwh, ok := readInt(dir, "energy_"+prefix); ok && uwh > 0 {
		return uwh / 1000
	}

	uah, ok := readInt(dir, "charge_"+prefix)
	if !ok || uah <= 0 || microvolts <= 0 {
		return 0
	}

	// µAh × µV = 10^-12 Wh; mWh is 10^-3 Wh.
	return uah * microvolts / 1_000_000_000
}

func generateBattery(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	entries, err := os.ReadDir(sysPowerSupply)
	if err != nil {
		// No power_supply class — a desktop, a VM, or not Linux at all. That
		// is a machine without a battery, not a failure.
		return []map[string]string{}, nil
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)

	rows := []map[string]string{}
	for _, name := range names {
		dir := filepath.Join(sysPowerSupply, name)
		if readAttr(dir, "type") != "Battery" {
			continue
		}
		// Wireless mice, keyboards and headsets register batteries too, with
		// scope Device. They are not the computer's battery.
		if readAttr(dir, "scope") == "Device" {
			continue
		}

		microvolts, _ := readInt(dir, "voltage_min_design")
		if microvolts <= 0 {
			microvolts, _ = readInt(dir, "voltage_now")
		}

		cycles, _ := readInt(dir, "cycle_count")
		percent, _ := readInt(dir, "capacity")

		rows = append(rows, map[string]string{
			"name":                name,
			"manufacturer":        readAttr(dir, "manufacturer"),
			"model":               readAttr(dir, "model_name"),
			"serial":              readAttr(dir, "serial_number"),
			"technology":          readAttr(dir, "technology"),
			"status":              readAttr(dir, "status"),
			"cycle_count":         itoa(cycles),
			"capacity_percent":    itoa(percent),
			"design_capacity_mwh": itoa(capacityMWh(dir, "full_design", microvolts)),
			"full_capacity_mwh":   itoa(capacityMWh(dir, "full", microvolts)),
			"voltage_mv":          itoa(microvolts / 1000),
		})
	}

	return rows, nil
}

// chassisNames is the SMBIOS 3.x System Enclosure type table (DSP0134 7.4.1),
// spelled as osquery spells it on Windows so the two platforms produce the
// same GLPI computer types.
var chassisNames = map[int64]string{
	1: "Other", 2: "Unknown", 3: "Desktop", 4: "Low Profile Desktop",
	5: "Pizza Box", 6: "Mini Tower", 7: "Tower", 8: "Portable", 9: "Laptop",
	10: "Notebook", 11: "Hand Held", 12: "Docking Station", 13: "All in One",
	14: "Sub Notebook", 15: "Space-saving", 16: "Lunch Box",
	17: "Main Server Chassis", 18: "Expansion Chassis", 19: "SubChassis",
	20: "Bus Expansion Chassis", 21: "Peripheral Chassis",
	22: "RAID Chassis", 23: "Rack Mount Chassis", 24: "Sealed-case PC",
	25: "Multi-system chassis", 26: "Compact PCI", 27: "Advanced TCA",
	28: "Blade", 29: "Blade Enclosure", 30: "Tablet", 31: "Convertible",
	32: "Detachable", 33: "IoT Gateway", 34: "Embedded PC", 35: "Mini PC",
	36: "Stick PC",
}

func generateChassis(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	code, ok := readInt(sysDMI, "chassis_type")
	if !ok {
		// No DMI: ARM boards without SMBIOS, most containers, not Linux.
		return []map[string]string{}, nil
	}

	// The byte's top bit is the chassis-lock flag, not part of the type.
	code &= 0x7f

	return []map[string]string{{
		"chassis_type": strconv.FormatInt(code, 10),
		"chassis_name": chassisNames[code],
		"vendor":       readAttr(sysDMI, "chassis_vendor"),
		"serial":       readAttr(sysDMI, "chassis_serial"),
		"asset_tag":    readAttr(sysDMI, "chassis_asset_tag"),
	}}, nil
}
