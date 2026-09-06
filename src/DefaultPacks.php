<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

/**
 * The query packs shipped with the plugin.
 *
 * Design rule: **one query per osquery table**, named after that table, rather
 * than one query per GLPI inventory section. Sections are then composed by the
 * assembler from whichever tables are available.
 *
 * That indirection is deliberate. A section like `bios` draws from both
 * `platform_info` and `system_info`, and joining them in SQL would mean a cross
 * join of two single-row tables — which silently yields *nothing* when one side
 * is empty (platform_info needs SMBIOS access and can come back bare). Keeping
 * the queries flat means a missing table costs one section's worth of fields
 * instead of all of them.
 *
 * Column lists are explicit, and aliased to GLPI's inventory field names where
 * they line up, because these run on every endpoint on every interval — an
 * unqualified `SELECT *` is real money at fleet scale.
 *
 * Platforms use osquery's own values: linux, darwin, windows. They are enforced
 * twice — the plugin only serves a query to a matching agent, and the served
 * schedule entry repeats the platform so osquery filters it too.
 */
final class DefaultPacks
{
    public const INVENTORY_PACK = 'glpi-inventory';

    /**
     * Seed the shipped packs.
     *
     * Idempotent, and safe on upgrade. An existing pack keeps its settings and
     * every query it already has — local edits are never overwritten — but any
     * query this version ships that the pack is *missing* is added.
     *
     * That distinction matters: without it, a query added in a later release
     * would only ever reach brand-new installations, so an upgraded server
     * would quietly collect less than a fresh one and the difference would show
     * up much later as a gap in the inventory.
     */
    public static function seed(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (self::packs() as $pack) {
            $packs_id = null;
            foreach (
                $DB->request([
                    'SELECT' => ['id'],
                    'FROM'   => 'glpi_plugin_glpiosquery_packs',
                    'WHERE'  => ['name' => $pack['name']],
                    'LIMIT'  => 1,
                ]) as $row
            ) {
                $packs_id = (int) $row['id'];
            }

            if ($packs_id !== null) {
                self::addMissingQueries($packs_id, $pack['queries']);
                continue;
            }

            $DB->insert('glpi_plugin_glpiosquery_packs', [
                'name'          => $pack['name'],
                'description'   => $pack['description'],
                'platform'      => 'all',
                'is_inventory'  => $pack['is_inventory'] ? 1 : 0,
                'is_active'     => $pack['is_active'] ? 1 : 0,
                'is_default'    => 1,
                'date_creation' => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
            ]);
            $packs_id = $DB->insertId();

            foreach ($pack['queries'] as $q) {
                $DB->insert('glpi_plugin_glpiosquery_queries', [
                    'plugin_glpiosquery_packs_id' => $packs_id,
                    'name'           => $q['name'],
                    'sql_query'      => $q['sql'],
                    'query_interval' => $q['interval'] ?? 3600,
                    'is_snapshot'    => 1,
                    'platform'       => $q['platform'] ?? 'all',
                    'min_agent_version' => $q['min_agent_version'] ?? null,
                    'glpi_section'   => $q['section'] ?? null,
                    'requires_table' => $q['requires_table'] ?? null,
                    'description'    => $q['description'] ?? null,
                    'is_active'      => 1,
                    'date_creation'  => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
                ]);
            }
        }
    }

    /**
     * Add shipped queries that an existing pack does not have yet.
     *
     * @param array<int,array<string,mixed>> $queries
     */
    private static function addMissingQueries(int $packs_id, array $queries): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $existing = [];
        foreach (
            $DB->request([
                'SELECT' => ['name'],
                'FROM'   => 'glpi_plugin_glpiosquery_queries',
                'WHERE'  => ['plugin_glpiosquery_packs_id' => $packs_id],
            ]) as $row
        ) {
            $existing[(string) $row['name']] = true;
        }

        foreach ($queries as $q) {
            if (isset($existing[$q['name']])) {
                continue;
            }

            $DB->insert('glpi_plugin_glpiosquery_queries', [
                'plugin_glpiosquery_packs_id' => $packs_id,
                'name'           => $q['name'],
                'sql_query'      => $q['sql'],
                'query_interval' => $q['interval'] ?? 3600,
                'is_snapshot'    => 1,
                'platform'       => $q['platform'] ?? 'all',
                'min_agent_version' => $q['min_agent_version'] ?? null,
                'glpi_section'   => $q['section'] ?? null,
                'requires_table' => $q['requires_table'] ?? null,
                'description'    => $q['description'] ?? null,
                'is_active'      => 1,
                'date_creation'  => $_SESSION['glpi_currenttime'] ?? date('Y-m-d H:i:s'),
            ]);
        }
    }

    /** @return array<int,array<string,mixed>> */
    public static function packs(): array
    {
        return [
            [
                'name'         => self::INVENTORY_PACK,
                'description'  => 'Feeds the GLPI inventory assembler. Disabling a query here removes that section from every inventory.',
                'is_inventory' => true,
                'is_active'    => true,
                'queries'      => self::inventoryQueries(),
            ],
            [
                'name'         => 'security-posture',
                'description'  => 'Disk encryption, firewall and antivirus state. Not part of the inventory document.',
                'is_inventory' => false,
                'is_active'    => true,
                'queries'      => self::securityQueries(),
            ],
            [
                'name'         => 'endpoint-telemetry',
                'description'  => 'Running processes and listening ports. Noisy and privacy-sensitive — off by default, enable deliberately.',
                'is_inventory' => false,
                'is_active'    => false,
                'queries'      => self::telemetryQueries(),
            ],
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private static function inventoryQueries(): array
    {
        $hour = 3600;
        $day  = 86400;

        return [
            // ------------------------------------------------ core identity
            [
                'name'    => 'inv_system_info',
                'section' => 'hardware',
                'sql'     => 'SELECT hostname, computer_name, uuid, physical_memory, '
                           . 'hardware_vendor, hardware_model, hardware_version, hardware_serial, '
                           . 'board_vendor, board_model, board_serial, '
                           . 'cpu_brand, cpu_type, cpu_physical_cores, cpu_logical_cores, cpu_sockets '
                           . 'FROM system_info;',
                'interval' => $hour,
                'description' => 'Anchor query: identity, chassis and memory total.',
            ],
            [
                'name'    => 'inv_os_version',
                'section' => 'operatingsystem',
                'sql'     => 'SELECT name, version, major, minor, patch, build, platform, '
                           . 'platform_like, codename, arch, install_date '
                           . 'FROM os_version;',
                'interval' => $hour,
            ],
            [
                'name'    => 'inv_kernel_info',
                'section' => 'operatingsystem',
                'sql'     => 'SELECT version, path, device FROM kernel_info;',
                'interval' => $hour,
            ],
            [
                'name'    => 'inv_uptime',
                'section' => 'operatingsystem',
                'sql'     => 'SELECT total_seconds FROM uptime;',
                'interval' => $hour,
                'description' => 'Converted to operatingsystem.boot_time by the assembler.',
            ],
            [
                'name'    => 'inv_platform_info',
                'section' => 'bios',
                'sql'     => 'SELECT vendor, version, date, revision, firmware_type FROM platform_info;',
                'interval' => $day,
            ],

            // -------------------------------------------------- components
            [
                'name'    => 'inv_cpu_info',
                'section' => 'cpus',
                'sql'     => 'SELECT device_id, model, manufacturer, number_of_cores, '
                           . 'logical_processors, max_clock_speed, socket_designation, address_width '
                           . 'FROM cpu_info;',
                'interval' => $day,
                'description' => 'Falls back to system_info.cpu_brand when the table is empty.',
            ],
            [
                'name'    => 'inv_memory_devices',
                'section' => 'memories',
                'sql'     => 'SELECT handle, device_locator, bank_locator, size, form_factor, '
                           . 'memory_type, memory_type_details, max_speed, configured_clock_speed, '
                           . 'manufacturer, serial_number, part_number '
                           . "FROM memory_devices WHERE size > 0;",
                'interval' => $day,
                'description' => 'Empty slots (size 0) are dropped.',
            ],
            [
                'name'    => 'inv_block_devices',
                'section' => 'storages',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT b.name, b.parent, b.vendor, b.model, b.serial, b.size, '
                           . 'b.block_size, b.type, b.label '
                           . 'FROM block_devices b '
                           . "WHERE b.name NOT LIKE '/dev/loop%' "
                           . "AND b.name NOT LIKE '/dev/ram%' "
                           . "AND b.name NOT LIKE '/dev/zram%' "
                           . "AND b.name NOT LIKE '/dev/dm-%' "
                           . "AND (b.parent = '' OR b.parent NOT IN (SELECT name FROM block_devices));",
                'interval' => $day,
                'description' => 'Whole physical disks. A disk is one whose parent is not itself a '
                               . 'block device: NVMe namespaces report their controller (/dev/nvme0) '
                               . 'as parent, so testing for an empty parent silently drops the main '
                               . 'disk of almost every modern machine. Partitions, loop, ram and '
                               . 'device-mapper nodes are excluded.',
            ],
            [
                'name'    => 'inv_disk_info',
                'section' => 'storages',
                'platform' => 'windows',
                'sql'     => 'SELECT disk_index, id, pnp_device_id, disk_size, manufacturer, '
                           . 'hardware_model, name, serial, description, type, partitions '
                           . 'FROM disk_info;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_mounts',
                'section' => 'drives',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT device, device_alias, path, type, blocks_size, blocks, blocks_free, blocks_available '
                           . 'FROM mounts '
                           . "WHERE device LIKE '/dev/%' AND type NOT IN ('squashfs','devtmpfs','tmpfs','overlay');",
                'interval' => $hour,
                'description' => 'Real block-backed filesystems only; snap/loop mounts excluded.',
            ],
            [
                'name'    => 'inv_logical_drives',
                'section' => 'drives',
                'platform' => 'windows',
                'sql'     => 'SELECT device_id, type, description, free_space, size, file_system, boot_partition '
                           . 'FROM logical_drives;',
                'interval' => $hour,
            ],

            // ----------------------------------------------------- network
            [
                'name'    => 'inv_interface_details',
                'section' => 'networks',
                'sql'     => 'SELECT interface, mac, type, mtu, flags, link_speed, speed, '
                           . 'ibytes, obytes, ierrors, oerrors, '
                           . 'description, manufacturer, connection_id, connection_status, '
                           . 'enabled, physical_adapter, dhcp_enabled, dhcp_server, pci_slot '
                           . "FROM interface_details WHERE mac != '00:00:00:00:00:00';",
                'interval' => $hour,
                'description' => 'Joined to interface_addresses by the assembler. '
                               . 'The i/o byte and error counters feed the port metrics graphs.',
            ],
            [
                'name'    => 'inv_interface_addresses',
                'section' => 'networks',
                'sql'     => 'SELECT interface, address, mask, broadcast, type '
                           . "FROM interface_addresses WHERE address NOT LIKE '127.%' AND address != '::1';",
                'interval' => $hour,
            ],

            // -------------------------------------------- extension discovery
            [
                'name'    => 'sys_extension_tables',
                'sql'     => 'SELECT e.name AS extension, e.version AS extension_version, '
                           . 'r.name AS table_name, p.name AS column_name, p.type AS column_type '
                           . 'FROM osquery_registry r '
                           . 'JOIN osquery_extensions e ON e.uuid = r.owner_uuid '
                           . 'JOIN pragma_table_info(r.name) p '
                           . "WHERE r.registry = 'table' AND r.active = 1 AND r.owner_uuid != 0 "
                           . 'ORDER BY r.name, p.name;',
                // Ten minutes rather than an hour: this is what unlocks every
                // query gated on an extension table, so the interval is also
                // the delay between an extension arriving on an endpoint and
                // that endpoint being asked to use it. The query itself reads
                // osquery's own registry and costs nothing.
                'interval' => 600,
                'description' => 'What each loaded osquery extension provides. '
                               . 'Feeds the console schema browser and decides which queries an endpoint can answer.',
            ],

            // ---------------------------------------------------- software
            [
                'name'    => 'inv_deb_packages',
                'section' => 'softwares',
                'platform' => 'linux',
                'sql'     => 'SELECT name, version, arch, maintainer, section, size FROM deb_packages;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_rpm_packages',
                'section' => 'softwares',
                'platform' => 'linux',
                'sql'     => 'SELECT name, version, release, arch, vendor, package_group, size, install_time '
                           . 'FROM rpm_packages;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_apps',
                'section' => 'softwares',
                'platform' => 'darwin',
                'sql'     => 'SELECT name, bundle_short_version, bundle_version, bundle_identifier, '
                           . 'path, category, last_opened_time '
                           . 'FROM apps;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_homebrew_packages',
                'section' => 'softwares',
                'platform' => 'darwin',
                'sql'     => 'SELECT name, version, type, prefix FROM homebrew_packages;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_programs',
                'section' => 'softwares',
                'platform' => 'windows',
                'sql'     => 'SELECT name, version, publisher, install_date, install_location, '
                           . 'install_source, identifying_number, uninstall_string, language '
                           . 'FROM programs;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_patches',
                'section' => 'softwares',
                'platform' => 'windows',
                'sql'     => 'SELECT hotfix_id, description, caption, installed_on, installed_by FROM patches;',
                'interval' => $day,
                'description' => 'Windows updates, recorded as software with a windows_update source.',
            ],

            // ------------------------------------------------------- users
            [
                'name'    => 'inv_users',
                'section' => 'local_users',
                'sql'     => 'SELECT uid, gid, username, description, directory, shell, uuid '
                           . 'FROM users WHERE uid >= 500 OR uid = 0;',
                'interval' => $hour,
                'description' => 'Real accounts: root plus non-system users.',
            ],
            [
                'name'    => 'inv_groups',
                'section' => 'local_groups',
                'sql'     => 'SELECT gid, groupname, comment FROM groups WHERE gid >= 500 OR gid = 0;',
                'interval' => $hour,
            ],
            [
                'name'    => 'inv_logged_in_users',
                'section' => 'users',
                'sql'     => "SELECT user, tty, host, time, type FROM logged_in_users WHERE type = 'user';",
                'interval' => $hour,
                'description' => 'Feeds the last-logged-user fields.',
            ],

            // ------------------------------------------------- peripherals
            [
                'name'    => 'inv_battery',
                'section' => 'batteries',
                'platform' => 'darwin,windows',
                'sql'     => 'SELECT manufacturer, model, serial_number, designed_capacity, '
                           . 'max_capacity, voltage, chemistry, cycle_count, health, manufacture_date '
                           . 'FROM battery;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_connected_displays',
                'section' => 'monitors',
                'platform' => 'darwin',
                'sql'     => 'SELECT name, product_id, serial_number, vendor_id, display_id, '
                           . 'resolution, connection_type, manufactured_year, manufactured_week '
                           . 'FROM connected_displays;',
                'interval' => $day,
                'description' => 'macOS has a first-class display table; other platforms go via EDID.',
            ],
            [
                'name'    => 'inv_monitor_edid',
                'section' => 'monitors',
                'platform' => 'windows',
                'sql'     => 'SELECT path, data FROM registry '
                           . "WHERE key LIKE 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\%\\%\\Device Parameters' "
                           . "AND name = 'EDID';",
                'interval' => $day,
                'description' => 'osquery has no monitor table on Windows, but the raw EDID block is in '
                               . 'the registry. The plugin decodes it into manufacturer, model and serial.',
            ],
            [
                'name'    => 'inv_monitor_edid_linux',
                'section' => 'monitors',
                'platform' => 'linux',
                'sql'     => 'SELECT path, data, connector, preferred_mode, status FROM glpi_edid;',
                'requires_table' => 'glpi_edid',
                'interval' => $day,
                'description' => 'Requires the glpi-edid extension shipped with the agent: osquery has '
                               . 'no monitor table on Linux and no way to read /sys/class/drm/*/edid. '
                               . 'Returns nothing on a stock osqueryd, which is harmless.',
            ],
            [
                'name'    => 'inv_chassis_info',
                'section' => 'hardware',
                'platform' => 'windows',
                'sql'     => 'SELECT chassis_types, description, manufacturer, model, serial, sku, smbios_tag '
                           . 'FROM chassis_info;',
                'interval' => $day,
                'description' => 'Chassis type (laptop / desktop / server), and a serial fallback when '
                               . 'system_info does not carry one.',
            ],
            [
                'name'    => 'inv_logon_sessions',
                'section' => 'users',
                'platform' => 'windows',
                'sql'     => 'SELECT user, logon_domain, logon_time, logon_type '
                           . "FROM logon_sessions WHERE logon_type IN ('Interactive', 'RemoteInteractive', 'CachedInteractive');",
                'interval' => $hour,
                'description' => 'Windows equivalent of logged_in_users; interactive sessions only, so '
                               . 'service and network logons are not reported as people.',
            ],
            [
                'name'    => 'inv_memory_info',
                'section' => 'hardware',
                'platform' => 'linux',
                'sql'     => 'SELECT memory_total, memory_free, swap_total FROM memory_info;',
                'interval' => $hour,
                'description' => 'Memory total from the kernel, used when SMBIOS is unavailable '
                               . '(containers, some hypervisors) and memory_devices is empty.',
            ],
            [
                'name'    => 'inv_video_info',
                'section' => 'videos',
                'platform' => 'windows',
                'sql'     => 'SELECT manufacturer, model, series, driver, driver_version, '
                           . 'driver_date, video_mode, color_depth '
                           . 'FROM video_info;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_pci_devices',
                'section' => 'controllers',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT pci_slot, pci_class, pci_subclass, driver, vendor, vendor_id, '
                           . 'model, model_id, subsystem_vendor, subsystem_model '
                           . 'FROM pci_devices;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_usb_devices',
                'section' => 'usbdevices',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT usb_address, usb_port, vendor, vendor_id, model, model_id, '
                           . 'serial, class, subclass, removable '
                           . 'FROM usb_devices;',
                'interval' => $day,
            ],
            [
                'name'    => 'inv_docker_containers',
                'section' => 'virtualmachines',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT id, name, image, state, status, pid FROM docker_containers;',
                'interval' => $hour,
            ],
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private static function securityQueries(): array
    {
        return [
            [
                'name'     => 'sec_disk_encryption',
                'platform' => 'linux,darwin',
                'sql'      => 'SELECT name, uuid, encrypted, type, encryption_status, filevault_status '
                            . 'FROM disk_encryption;',
                'interval' => 3600,
            ],
            [
                // Answers what disk_encryption cannot: osquery leaves `encrypted`
                // blank for every NVMe and device-mapper node, which is the whole
                // of a standard LVM install. Served by the bundled extension.
                'name'     => 'sec_block_stack',
                'platform' => 'linux',
                // Served only where the table actually exists. The version
                // floor stays as a cheap first cut for agents that predate the
                // extension entirely; `requires_table` is the one that still
                // holds once an administrator can publish extensions of their
                // own, since a version number cannot speak for those.
                'min_agent_version' => '1.0.4',
                'requires_table'    => 'glpi_block_stack',
                'sql'      => 'SELECT name, device, dm_name, dm_uuid, kind, parents, '
                            . 'encrypted, crypt_device FROM glpi_block_stack;',
                'interval' => 3600,
            ],
            [
                'name'     => 'sec_bitlocker',
                'platform' => 'windows',
                'sql'      => 'SELECT device_id, drive_letter, protection_status, conversion_status, '
                            . 'encryption_method, percentage_encrypted '
                            . 'FROM bitlocker_info;',
                'interval' => 3600,
            ],
            [
                'name'     => 'sec_av_products',
                'platform' => 'windows',
                'sql'      => 'SELECT type, name, state, state_timestamp, remediation_path FROM windows_security_products;',
                'interval' => 3600,
            ],
            [
                'name'     => 'sec_firewall_windows',
                'platform' => 'windows',
                'sql'      => 'SELECT firewall, antivirus, antispyware, autoupdate, '
                            . 'user_account_control, windows_security_center_service '
                            . 'FROM windows_security_center;',
                'interval' => 3600,
            ],
            [
                'name'     => 'sec_firewall_macos',
                'platform' => 'darwin',
                'sql'      => 'SELECT global_state, stealth_enabled, logging_enabled, allow_signed_enabled FROM alf;',
                'interval' => 3600,
            ],
        ];
    }

    /** @return array<int,array<string,mixed>> */
    private static function telemetryQueries(): array
    {
        return [
            [
                'name'     => 'tel_listening_ports',
                'sql'      => 'SELECT DISTINCT p.name, p.path, lp.port, lp.protocol, lp.address '
                            . 'FROM listening_ports lp LEFT JOIN processes p ON lp.pid = p.pid '
                            . 'WHERE lp.port != 0;',
                'interval' => 3600,
            ],
            [
                'name'     => 'tel_startup_items',
                'sql'      => 'SELECT name, path, args, type, source, status, username FROM startup_items;',
                'interval' => 86400,
            ],
        ];
    }
}
