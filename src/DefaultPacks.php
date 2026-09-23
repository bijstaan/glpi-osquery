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
                'name'    => 'inv_bitlocker',
                'section' => 'drives',
                'platform' => 'windows',
                // Collected again here rather than read from security-posture,
                // which says on its own tin that it is not part of the
                // inventory document — and which an administrator may disable
                // without expecting the volumes to stop reporting whether they
                // are encrypted. bitlocker_info is a handful of rows.
                'sql'     => 'SELECT device_id, drive_letter, protection_status, conversion_status, '
                           . 'encryption_method, percentage_encrypted FROM bitlocker_info;',
                'interval' => $hour,
                'description' => 'Fills the encryption fields on each Windows volume.',
            ],
            [
                'name'    => 'inv_disk_encryption',
                'section' => 'drives',
                // macOS only. On Linux disk_encryption leaves `encrypted` blank
                // for every NVMe and device-mapper node — measured on a stock
                // Ubuntu install, it answered for none of the mounted volumes —
                // and names them /dev/dm-N where mounts says /dev/mapper/…, so
                // it could not be matched even when it did answer. Linux reads
                // inv_block_stack instead.
                'platform' => 'darwin',
                'sql'     => 'SELECT name, uuid, encrypted, type, encryption_status, filevault_status '
                           . 'FROM disk_encryption;',
                'interval' => $hour,
                'description' => 'Fills the encryption fields on each macOS volume, FileVault included.',
            ],
            [
                'name'    => 'inv_block_stack',
                'section' => 'drives',
                'platform' => 'linux',
                'requires_table' => 'glpi_block_stack',
                'sql'     => 'SELECT name, device, dm_name, dm_uuid, kind, encrypted, crypt_device '
                           . 'FROM glpi_block_stack;',
                'interval' => $hour,
                'description' => 'Fills the encryption fields on each Linux volume by walking the '
                               . 'device-mapper stack, so LUKS beneath LVM is found. Requires the '
                               . 'extension bundled with the agent.',
            ],
            [
                'name'    => 'inv_interface_details',
                'section' => 'networks',
                'platform' => 'linux,darwin',
                'sql'     => 'SELECT interface, mac, type, mtu, flags, link_speed, '
                           . 'ibytes, obytes, ierrors, oerrors, pci_slot '
                           . "FROM interface_details WHERE mac != '00:00:00:00:00:00';",
                'interval' => $hour,
                'description' => 'Joined to interface_addresses by the assembler. '
                               . 'The i/o byte and error counters feed the port metrics graphs.',
            ],
            [
                'name'    => 'inv_interface_details_windows',
                'section' => 'networks',
                'platform' => 'windows',
                // Windows fills a different half of this table, and the MAC
                // filter is not enough on its own.
                //
                // Win32_NetworkAdapter reports the WAN Miniports — the pseudo
                // adapters behind PPTP, L2TP, IKEv2, SSTP and IPv6 tunnelling —
                // alongside the real ones, with MACs that pass a `mac != all
                // zeroes` test. A machine with an Ethernet port, Wi-Fi and two
                // VPN clients arrived in GLPI with eleven network cards and
                // eight ports named after interface indexes.
                //
                // NetConnectionID is set only for adapters that appear in
                // Network Connections, which is exactly the set a person would
                // name, and physical_adapter keeps a real NIC that has never
                // been given a connection name. The counters are selected but
                // not populated on Windows — see Assembler::counters(), which
                // emits them only when the driver supplies all four.
                'sql'     => 'SELECT interface, mac, type, mtu, flags, link_speed, speed, '
                           . 'ibytes, obytes, ierrors, oerrors, '
                           . 'friendly_name, description, manufacturer, connection_id, '
                           . 'connection_status, enabled, physical_adapter, '
                           . 'dhcp_enabled, dhcp_server, pci_slot '
                           . "FROM interface_details WHERE mac != '00:00:00:00:00:00' "
                           . "AND (connection_id != '' OR physical_adapter = 1);",
                'interval' => $hour,
                'description' => 'Windows equivalent of inv_interface_details: the adapters that appear '
                               . 'in Network Connections, plus any physical one that does not.',
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
                'platform' => 'darwin',
                'sql'     => 'SELECT uid, gid, username, description, directory, shell, uuid '
                           . 'FROM users WHERE uid >= 500 OR uid = 0;',
                'interval' => $hour,
                'description' => 'Real accounts: root plus non-system users.',
            ],
            [
                'name'    => 'inv_users_linux',
                'section' => 'local_users',
                'platform' => 'linux',
                // 500 is the macOS boundary, not the Linux one. Current distros
                // allocate system accounts from 999 downwards — systemd-network,
                // polkitd, fwupd-refresh, pipewire — and a stock Ubuntu desktop
                // reported thirteen of them beside its one person. Debian and
                // Red Hat alike start people at 1000; 60000 and up is nobody
                // (65534) and the packaged high ids such as libvirt-qemu.
                'sql'     => 'SELECT uid, gid, username, description, directory, shell, uuid '
                           . 'FROM users WHERE uid = 0 OR (uid >= 1000 AND uid < 60000);',
                'interval' => $hour,
                'description' => 'Linux equivalent of inv_users: root plus the accounts people log in with.',
            ],
            [
                'name'    => 'inv_users_windows',
                'section' => 'local_users',
                'platform' => 'windows',
                // Separate from inv_users because the column it filters on is
                // declared for Windows only: `type` — local, roaming or
                // special — is absent from PRAGMA table_info(users) on Linux
                // (measured on 5.19.0), where selecting it happens to yield an
                // empty string rather than an error. One query could therefore
                // carry the filter everywhere and appear to work, on undeclared
                // behaviour that costs nothing to avoid.
                //
                // The split earns its keep anyway, because the POSIX rule it
                // replaces does not describe Windows: uid there is the SID's
                // RID, so a `uid >= 500` threshold keeps the real accounts by
                // luck and drags in whatever service accounts sit above it.
                // 'special' is exactly the built-in machine accounts.
                'sql'     => 'SELECT uid, gid, username, description, directory, shell, uuid, type '
                           . "FROM users WHERE type != 'special';",
                'interval' => $hour,
                'description' => 'Windows equivalent of inv_users: the local and roaming accounts, '
                               . 'without the built-in machine ones.',
            ],
            [
                'name'    => 'inv_groups',
                'section' => 'local_groups',
                'platform' => 'darwin,windows',
                'sql'     => 'SELECT gid, groupname, comment FROM groups WHERE gid >= 500 OR gid = 0;',
                'interval' => $hour,
            ],
            [
                'name'    => 'inv_groups_linux',
                'section' => 'local_groups',
                'platform' => 'linux',
                // The same boundary as inv_users_linux, for the same reason.
                'sql'     => 'SELECT gid, groupname, comment FROM groups WHERE gid = 0 OR (gid >= 1000 AND gid < 60000);',
                'interval' => $hour,
            ],
            [
                'name'    => 'inv_logged_in_users',
                'section' => 'users',
                // Excluded types rather than a single kept one. `type` means
                // different things per platform: on POSIX it is the utmp record
                // type, where 'user' is the only one that is a person, and on
                // Windows it is the terminal session's state — 'active',
                // 'disconnected' and so on. So `type = 'user'` was not merely
                // narrow on Windows, it matched nothing ever, the machine
                // reported no users at all, and the asset was attached to
                // nobody. The list below is the utmp bookkeeping set; anything
                // else, on any platform, is treated as a person.
                'sql'     => "SELECT user, tty, host, time, type FROM logged_in_users "
                           . "WHERE user != '' AND type NOT IN "
                           . "('boot_time', 'runlevel', 'new_time', 'old_time', 'init', 'login', 'dead', 'empty');",
                'interval' => $hour,
                'description' => 'Feeds the last-logged-user fields, and the user an asset is attached to. '
                               . 'Person sessions on every platform.',
            ],

            // ------------------------------------------------- peripherals
            [
                'name'    => 'inv_session_users',
                'section' => 'users',
                'platform' => 'linux',
                // logged_in_users reads utmp, which systemd-logind and Wayland
                // sessions do not write: on a stock Ubuntu desktop it returns no
                // rows with the owner sitting at the machine, and the asset is
                // attached to nobody. What every logind session does start is
                // that user's own service manager, `systemd --user`, so its
                // owner is the person logged in — console, graphical or SSH.
                // Service accounts that merely own processes do not get one.
                'sql'     => 'SELECT DISTINCT u.username AS user FROM processes p '
                           . 'JOIN users u ON u.uid = p.uid '
                           . "WHERE p.name = 'systemd' AND p.uid >= 1000 AND p.uid < 60000;",
                'interval' => $hour,
                'description' => 'Who is logged in on Linux, where logged_in_users is empty under systemd.',
            ],
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
                'name'    => 'inv_battery_linux',
                'section' => 'batteries',
                'platform' => 'linux',
                'requires_table' => 'glpi_battery',
                'sql'     => 'SELECT name, manufacturer, model, serial, technology, cycle_count, '
                           . 'design_capacity_mwh, full_capacity_mwh, voltage_mv '
                           . 'FROM glpi_battery;',
                'interval' => $day,
                'description' => 'osquery has no battery table on Linux; read from /sys/class/power_supply '
                               . 'by the extension bundled with the agent.',
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
                'name'    => 'inv_chassis_linux',
                'section' => 'hardware',
                'platform' => 'linux',
                'requires_table' => 'glpi_chassis',
                'sql'     => 'SELECT chassis_type, chassis_name, vendor, asset_tag FROM glpi_chassis;',
                'interval' => $day,
                // Without a chassis type GLPI falls back to the motherboard
                // model for the computer type, so a Framework laptop was typed
                // "FRANMDCP07".
                'description' => 'Chassis type (laptop / desktop / server) from DMI, which osquery does not '
                               . 'expose on Linux. Requires the extension bundled with the agent.',
            ],
            [
                'name'    => 'inv_system_profiler',
                'section' => 'hardware',
                'platform' => 'darwin',
                // The value column is system_profiler's `_items` array as JSON —
                // the same thing `system_profiler -json <type>` prints under the
                // type's key. Each is read for what osquery has no table for on
                // a Mac: the model name that says what the chassis is, the GPU,
                // and memory on Apple silicon, which has no SMBIOS and so leaves
                // memory_devices empty.
                'sql'     => 'SELECT data_type, value FROM system_profiler '
                           . "WHERE data_type IN ('SPHardwareDataType', 'SPDisplaysDataType', 'SPMemoryDataType');",
                'interval' => $day,
                'description' => 'Chassis, graphics and Apple silicon memory, from system_profiler.',
            ],
            [
                'name'    => 'inv_windows_version',
                'section' => 'operatingsystem',
                'platform' => 'windows',
                // os_version names the release by its kernel build and nothing
                // else, so every cumulative update would become a new operating
                // system in GLPI. The marketing version (23H2), the product id
                // and the registered owner are where Windows keeps them.
                'sql'     => 'SELECT name, data FROM registry '
                           . "WHERE key = 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' "
                           . "AND name IN ('DisplayVersion', 'ReleaseId', 'ProductId', 'RegisteredOwner', "
                           . "'RegisteredOrganization', 'EditionID');",
                'interval' => $day,
                'description' => 'Windows version name (e.g. 23H2), product id and registered owner.',
            ],
            [
                'name'    => 'inv_ntdomains',
                'section' => 'hardware',
                'platform' => 'windows',
                'sql'     => "SELECT domain_name, dns_forest_name FROM ntdomains WHERE domain_name != '';",
                'interval' => $day,
                'description' => 'The Active Directory domain, which GLPI records as the computer\'s domain.',
            ],
            [
                'name'    => 'inv_security_products',
                'section' => 'antivirus',
                'platform' => 'windows',
                // Collected here as well as in security-posture for the reason
                // inv_bitlocker is: that pack is not part of the inventory and
                // may be switched off. Windows Security Center does not exist on
                // Windows Server, where this returns nothing.
                'sql'     => 'SELECT type, name, state, signatures_up_to_date FROM windows_security_products;',
                'interval' => $hour,
                'description' => 'Antivirus products registered with Windows Security Center.',
            ],
            [
                'name'    => 'inv_logon_sessions',
                'section' => 'users',
                'platform' => 'windows',
                // Only people's SIDs: S-1-5-21 is a local or AD account and
                // S-1-12-1 an Entra one. Windows' own Window Manager (S-1-5-90)
                // and Font Driver Host (S-1-5-96) logons are Interactive too,
                // and without this they were the user the asset was linked to.
                // upn is what matches an account named by Entra SCIM.
                'sql'     => 'SELECT user, logon_domain, logon_time, logon_type, upn, logon_sid '
                           . "FROM logon_sessions WHERE logon_type IN ('Interactive', 'RemoteInteractive', 'CachedInteractive') "
                           . "AND (logon_sid LIKE 'S-1-5-21-%' OR logon_sid LIKE 'S-1-12-1-%');",
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
                'name'    => 'inv_drivers',
                'section' => 'controllers',
                'platform' => 'windows',
                // Windows has neither pci_devices nor usb_devices — both are
                // POSIX-only in osquery — so a Windows machine reported no
                // components whatsoever: no fingerprint reader, no controllers,
                // nothing but the BIOS and the CPU that come from elsewhere.
                // `drivers` is what Windows offers instead, one row per device
                // known to SetupAPI.
                //
                // The excluded classes are the ones that describe software
                // rather than hardware; without them a laptop contributes a few
                // hundred rows, most of them meaningless in an asset list.
                'sql'     => 'SELECT device_id, device_name, description, class, manufacturer, '
                           . 'provider, version, service, signed '
                           . "FROM drivers WHERE device_name != '' AND class NOT IN "
                           . "('SoftwareComponent', 'SoftwareDevice', 'System', 'Computer', "
                           . "'LegacyDriver', 'Volume', 'VolumeSnapshot', 'PrintQueue');",
                'interval' => $day,
                'description' => 'Windows devices, in place of pci_devices and usb_devices which osquery '
                               . 'does not provide there.',
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
