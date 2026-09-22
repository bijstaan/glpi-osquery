<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery\Inventory;

use GlpiPlugin\Glpiosquery\EnrollSecret;
use GlpiPlugin\Glpiosquery\Node;

/**
 * Builds a GLPI-native inventory document from an agent's stored snapshots.
 *
 * The output validates against inventory_format's inventory.schema.json and is
 * handed to Glpi\Inventory\Inventory, which owns everything downstream: asset
 * creation, the import rules engine, entity assignment, refused equipment. This
 * class is therefore a translator and nothing more — it makes no decisions
 * about what an asset *is*.
 *
 * ## Units
 *
 * osquery is not internally consistent about sizes, and GLPI wants MiB almost
 * everywhere, so every conversion here is deliberate and commented. Verified
 * against the 5.19.0 table specs:
 *
 *   system_info.physical_memory   bytes
 *   memory_devices.size           **already megabytes** — do not convert
 *   block_devices.size            *blocks*, multiply by block_size
 *   mounts.blocks*                *blocks*, multiply by blocks_size
 *   disk_info.disk_size           bytes
 *   logical_drives.size/free      bytes, and **-1 signals failure**
 *
 * Getting one of these wrong does not fail loudly; it silently publishes an
 * asset with a 4 KB disk or 500 TB of RAM, so they are unit-tested.
 */
final class Assembler
{
    /** @var array<string,array<int,array<string,mixed>>> query name => rows */
    private array $snap;

    private array $agent;

    public function __construct(array $agent, array $snapshots)
    {
        $this->agent = $agent;
        $this->snap  = $snapshots;
    }

    /** Load an agent's snapshots and build its document, or null if there is nothing to say. */
    public static function forAgent(array $agent): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $snapshots = [];
        foreach (
            $DB->request([
                'SELECT' => ['query_name', 'data'],
                'FROM'   => 'glpi_plugin_glpiosquery_snapshots',
                'WHERE'  => ['plugin_glpiosquery_agents_id' => (int) $agent['id']],
            ]) as $row
        ) {
            $decoded = json_decode((string) $row['data'], true);
            $snapshots[(string) $row['query_name']] = is_array($decoded) ? $decoded : [];
        }

        // The anchor query is the one thing we refuse to do without: with no
        // system_info there is no hostname and no UUID, and publishing an asset
        // that cannot be identified would create a duplicate on every run.
        if (empty($snapshots['inv_system_info'])) {
            return null;
        }

        return (new self($agent, $snapshots))->build();
    }

    public function build(): array
    {
        $content = [
            'hardware'        => $this->hardware(),
            'bios'            => $this->bios(),
            'operatingsystem' => $this->operatingSystem(),
            'cpus'            => $this->cpus(),
            'memories'        => $this->memories(),
            'storages'        => $this->storages(),
            'drives'          => $this->drives(),
            'networks'        => $this->networks(),
            'softwares'       => $this->softwares(),
            'local_users'     => $this->localUsers(),
            'local_groups'    => $this->localGroups(),
            'users'           => $this->users(),
            'batteries'       => $this->batteries(),
            'monitors'        => $this->monitors(),
            'videos'          => $this->videos(),
            'controllers'     => $this->controllers(),
            'usbdevices'      => $this->usbDevices(),
            'virtualmachines' => $this->virtualMachines(),

            // Agent identity. GLPI reads the version it displays from
            // versionprovider.version (see GLPI core Agent::handleAgent), NOT from
            // versionclient — sending only the latter leaves the agent's
            // version column empty on the device page.
            'versionclient'   => 'glpi-osquery-agent_v' . $this->agentVersion(),
            'versionprovider' => [
                'name'    => 'glpi-osquery-agent',
                'version' => $this->agentVersion(),
                'comments' => [
                    'osquery ' . (string) ($this->agent['osquery_version'] ?? 'unknown'),
                    'plugin ' . PLUGIN_GLPIOSQUERY_VERSION,
                ],
            ],
        ];

        // Empty sections are dropped rather than sent as []: an empty array is
        // a positive claim that the machine has none of that thing, and would
        // make GLPI delete previously-known components when a query simply
        // failed to run on this cycle.
        $content = array_filter($content, static fn($v) => $v !== [] && $v !== null && $v !== '');

        $document = [
            'deviceid' => (string) $this->agent['deviceid'],
            'itemtype' => 'Computer',
            'action'   => 'inventory',
            'content'  => $content,
        ];

        // The tag is how an inventory says which entity it belongs to.
        //
        // GLPI decides an imported asset's entity from the entity rules alone
        // (Glpi\Inventory\MainAsset\MainAsset::handle), and when none matches
        // it uses the inventory configuration's default — the root entity on a
        // stock install. Nothing about the enrolment reaches that decision, so
        // an agent enrolled with a secret scoped to a sub-entity still landed
        // in the root, with no error anywhere to say why.
        //
        // The tag is the one criterion those rules have that we control, so
        // every inventory carries the tag of the secret the agent enrolled
        // with, and EnrollSecret::syncEntityRule keeps a rule that maps it to
        // the entity. Absent for an agent enrolled before secrets recorded
        // their id — no tag is better than an empty one, which GLPI stores on
        // the agent and would then have to be cleared by hand.
        $tag = EnrollSecret::tagFor((int) ($this->agent['plugin_glpiosquery_enrollsecrets_id'] ?? 0));
        if ($tag !== null) {
            $document['tag'] = $tag;
        }

        return $document;
    }

    /**
     * The version of the supervisor on the endpoint.
     *
     * Falls back to the plugin's version for a stock osqueryd that enrolled
     * without one of our agents — reporting the plugin version is honest there,
     * because the plugin really is what produced the inventory.
     */
    private function agentVersion(): string
    {
        $reported = trim((string) ($this->agent['agent_version'] ?? ''));

        return $reported !== '' ? $reported : PLUGIN_GLPIOSQUERY_VERSION;
    }

    // ------------------------------------------------------------------ helpers

    /** First row of a query's snapshot, or an empty array. */
    private function one(string $query): array
    {
        $rows = $this->snap[$query] ?? [];
        $first = reset($rows);

        return is_array($first) ? $first : [];
    }

    /** @return array<int,array<string,mixed>> */
    private function rows(string $query): array
    {
        $rows = $this->snap[$query] ?? [];

        return is_array($rows) ? $rows : [];
    }

    private static function str(array $row, string $key): string
    {
        return trim((string) ($row[$key] ?? ''));
    }

    private static function int(array $row, string $key): int
    {
        return (int) ($row[$key] ?? 0);
    }

    /** Bytes → MiB, which is what GLPI stores for memory and disk sizes. */
    private static function mib(float $bytes): int
    {
        return (int) round($bytes / 1048576);
    }

    /**
     * Coerce a date into the schema's `^\d{4}-\d{2}-\d{2}$` shape.
     *
     * osquery hands back whatever the underlying platform stored: SMBIOS BIOS
     * dates are US `m/d/Y`, Windows registry install dates are `Ymd`, some
     * fields are epoch seconds. The schema rejects all of them, and a rejected
     * document loses the *entire* inventory — so anything unparseable is
     * dropped rather than allowed to fail the whole submission.
     */
    private static function date(string $value, bool $with_time = false): string
    {
        $value = trim($value);
        if ($value === '') {
            return '';
        }

        $format = $with_time ? 'Y-m-d H:i:s' : 'Y-m-d';

        if (ctype_digit($value)) {
            // Epoch seconds, or a Windows YYYYMMDD.
            if (strlen($value) === 8) {
                $parsed = \DateTimeImmutable::createFromFormat('Ymd', $value);
                return $parsed !== false ? $parsed->format($format) : '';
            }
            $ts = (int) $value;
            return $ts > 0 ? date($format, $ts) : '';
        }

        foreach (['m/d/Y', 'Y-m-d H:i:s', 'Y-m-d', 'd/m/Y', 'm/d/y'] as $candidate) {
            $parsed = \DateTimeImmutable::createFromFormat($candidate, $value);
            if ($parsed !== false) {
                return $parsed->format($format);
            }
        }

        $ts = strtotime($value);

        return $ts !== false ? date($format, $ts) : '';
    }

    /**
     * Normalise a CPU architecture to the schema's permitted set.
     *
     * The pattern accepts x86_64, i?86, aarch64 and arm-prefixed values, but
     * osquery reports "64-bit" on Windows and "amd64" on some builds, either of
     * which would fail validation and take the whole document with it.
     */
    private static function arch(string $arch): string
    {
        $arch = strtolower(trim($arch));

        return match (true) {
            in_array($arch, ['x86_64', 'amd64', '64-bit', 'x64'], true)   => 'x86_64',
            in_array($arch, ['arm64', 'aarch64'], true)                   => 'aarch64',
            in_array($arch, ['i386', 'i486', 'i586', 'i686', '32-bit', 'x86'], true) => 'i686',
            str_starts_with($arch, 'arm')                                 => $arch,
            in_array($arch, ['powerpc', 'powerpc64', 'sparc', 'sparc64', 'mips', 'mips64', 'alpha', 'm68k'], true) => $arch,
            // Unknown: omit rather than risk invalidating the document.
            default                                                       => '',
        };
    }

    /** Drop empty values so GLPI does not create blank dropdown entries. */
    private static function clean(array $entry): array
    {
        return array_filter(
            $entry,
            static fn($v) => $v !== '' && $v !== null && $v !== [] && $v !== 0.0
        );
    }

    // ----------------------------------------------------------------- sections

    private function hardware(): array
    {
        $si = $this->one('inv_system_info');

        $name = self::str($si, 'hostname') ?: self::str($si, 'computer_name');

        // system_info.physical_memory reads SMBIOS and comes back 0 where that
        // is unavailable; the kernel's own figure is a sound fallback.
        $memory = self::mib((float) self::int($si, 'physical_memory'));
        if ($memory <= 0) {
            $memory = self::mib((float) self::int($this->one('inv_memory_info'), 'memory_total'));
        }

        return self::clean([
            'name'         => $name,
            'uuid'         => self::str($si, 'uuid'),
            'memory'       => $memory,
            'chassis_type' => self::str($this->one('inv_chassis_info'), 'chassis_types'),
        ]);
    }

    private function bios(): array
    {
        $si = $this->one('inv_system_info');
        $pi = $this->one('inv_platform_info');
        $ci = $this->one('inv_chassis_info');

        // platform_info reads SMBIOS and comes back empty without the
        // privileges (or the hardware) to do so — containers and some VMs. The
        // system_info-derived fields still stand on their own, which is why
        // these are separate queries rather than a SQL join.
        return self::clean([
            'bmanufacturer' => self::str($pi, 'vendor'),
            'bversion'      => self::str($pi, 'version'),
            'bdate'         => self::date(self::str($pi, 'date')),
            // Windows fills chassis_info more reliably than system_info, so it
            // stands in wherever the primary source came back blank.
            'smanufacturer' => self::str($si, 'hardware_vendor') ?: self::str($ci, 'manufacturer'),
            'smodel'        => self::str($si, 'hardware_model') ?: self::str($ci, 'model'),
            'ssn'           => self::str($si, 'hardware_serial') ?: self::str($ci, 'serial'),
            'assettag'      => self::str($ci, 'smbios_tag'),
            'skunumber'     => self::str($ci, 'sku'),
            'mmanufacturer' => self::str($si, 'board_vendor'),
            'mmodel'        => self::str($si, 'board_model'),
            'msn'           => self::str($si, 'board_serial'),
        ]);
    }

    private function operatingSystem(): array
    {
        $os     = $this->one('inv_os_version');
        $kernel = $this->one('inv_kernel_info');
        $uptime = $this->one('inv_uptime');
        $si     = $this->one('inv_system_info');

        // Without an OS name there is no operating system to report, and
        // saying so is the only safe answer: GLPI's mapper assigns the name
        // straight into a non-nullable property and fatals on null, which
        // fails the *entire* inventory rather than just this section.
        //
        // This is a normal state, not an edge case — an agent's snapshots
        // arrive over several collection cycles, so the first assemblies
        // routinely run before os_version has been reported.
        if (self::str($os, 'name') === '') {
            return [];
        }

        $entry = [
            'name'           => self::str($os, 'name'),
            'version'        => self::str($os, 'version'),
            'arch'           => self::arch(self::str($os, 'arch')),
            'kernel_name'    => self::kernelName(self::str($os, 'platform'), self::str($os, 'platform_like')),
            'kernel_version' => self::str($kernel, 'version'),
            'fqdn'           => self::str($si, 'hostname'),
        ];

        $full = trim(self::str($os, 'name') . ' ' . self::str($os, 'version'));
        if ($full !== '') {
            $entry['full_name'] = $full;
        }

        // osquery gives uptime, GLPI wants the moment of boot.
        $seconds = self::int($uptime, 'total_seconds');
        if ($seconds > 0) {
            $entry['boot_time'] = date('Y-m-d H:i:s', time() - $seconds);
        }

        $install = self::date(self::str($os, 'install_date'), true);
        if ($install !== '') {
            $entry['install_date'] = $install;
        }

        return self::clean($entry);
    }

    /**
     * GLPI wants the kernel family, not the distribution.
     *
     * osquery's `platform` is the specific distro (debian, ubuntu, rhel…), so
     * passing it straight through writes "debian" into a field that should say
     * "linux" and makes OS reporting useless across a mixed estate.
     */
    private static function kernelName(string $platform, string $platform_like): string
    {
        if ($platform === '' && $platform_like === '') {
            return '';
        }

        return match (true) {
            $platform === 'darwin' || $platform_like === 'darwin'   => 'darwin',
            $platform === 'windows' || $platform_like === 'windows' => 'windows',
            default                                                 => 'linux',
        };
    }

    private function cpus(): array
    {
        $out = [];
        $arch = self::arch(self::str($this->one('inv_os_version'), 'arch'));

        foreach ($this->rows('inv_cpu_info') as $row) {
            $out[] = self::clean([
                'name'         => self::str($row, 'model'),
                'model'        => self::str($row, 'model'),
                'manufacturer' => self::str($row, 'manufacturer'),
                'core'         => self::int($row, 'number_of_cores'),
                'thread'       => self::int($row, 'logical_processors'),
                'speed'        => self::int($row, 'max_clock_speed'),
                'arch'         => $arch,
                'id'           => self::str($row, 'socket_designation'),
            ]);
        }

        if ($out !== []) {
            return $out;
        }

        // cpu_info is unavailable in containers and on some hypervisors.
        // system_info always has the brand string and core counts, so a machine
        // still reports a processor rather than none at all.
        $si = $this->one('inv_system_info');
        $brand = self::str($si, 'cpu_brand');
        if ($brand === '') {
            return [];
        }

        $sockets = max(1, self::int($si, 'cpu_sockets'));

        return [self::clean([
            'name'      => $brand,
            'model'     => $brand,
            'core'      => self::int($si, 'cpu_physical_cores'),
            'thread'    => self::int($si, 'cpu_logical_cores'),
            'corecount' => $sockets,
            'arch'      => $arch,
        ])];
    }

    private function memories(): array
    {
        $out  = [];
        $slot = 0;

        foreach ($this->rows('inv_memory_devices') as $row) {
            $slot++;
            $size = self::int($row, 'size');
            if ($size <= 0) {
                continue;
            }

            $speed = self::int($row, 'configured_clock_speed') ?: self::int($row, 'max_speed');

            $out[] = self::clean([
                // memory_devices.size is ALREADY megabytes. This is the one
                // size field in osquery that must not be converted.
                'capacity'     => $size,
                'caption'      => self::str($row, 'device_locator'),
                'description'  => self::str($row, 'bank_locator'),
                'manufacturer' => self::str($row, 'manufacturer'),
                'serialnumber' => self::str($row, 'serial_number'),
                'model'        => self::str($row, 'part_number'),
                'type'         => self::str($row, 'memory_type'),
                'formfactor'   => self::str($row, 'form_factor'),
                'speed'        => $speed > 0 ? (string) $speed : '',
                'numslots'     => $slot,
            ]);
        }

        return $out;
    }

    private function storages(): array
    {
        $out = [];

        // POSIX: size is in blocks.
        foreach ($this->rows('inv_block_devices') as $row) {
            $bytes = (float) self::int($row, 'size') * (float) self::int($row, 'block_size');
            $disksize = self::mib($bytes);
            if ($disksize <= 0) {
                continue;
            }

            $out[] = self::clean([
                'name'         => self::str($row, 'name'),
                'description'  => self::str($row, 'label'),
                'manufacturer' => self::str($row, 'vendor'),
                'model'        => self::str($row, 'model'),
                'serial'       => self::str($row, 'serial'),
                'type'         => self::str($row, 'type'),
                'disksize'     => $disksize,
            ]);
        }

        // Windows: disk_size is in bytes.
        foreach ($this->rows('inv_disk_info') as $row) {
            $disksize = self::mib((float) self::int($row, 'disk_size'));
            if ($disksize <= 0) {
                continue;
            }

            $out[] = self::clean([
                'name'         => self::str($row, 'name'),
                'description'  => self::str($row, 'description'),
                'manufacturer' => self::str($row, 'manufacturer'),
                'model'        => self::str($row, 'hardware_model'),
                'serial'       => self::str($row, 'serial'),
                'interface'    => self::str($row, 'type'),
                'disksize'     => $disksize,
            ]);
        }

        return $out;
    }

    private function drives(): array
    {
        $out = [];

        // POSIX: block counts × block size.
        //
        // One entry per *device*, not per mount point. A single filesystem is
        // routinely mounted in several places — bind mounts, containers'
        // /etc/hosts, btrfs subvolumes — and osquery faithfully reports each
        // one. Emitting them all makes GLPI sum the same disk repeatedly and
        // report a machine with four times the storage it has. The shortest
        // mount path wins, which is the real mount rather than a bind of some
        // file inside it.
        $by_device = [];
        foreach ($this->rows('inv_mounts') as $row) {
            $device = self::str($row, 'device');
            $path   = self::str($row, 'path');
            if ($device === '') {
                continue;
            }
            if (isset($by_device[$device]) && strlen(self::str($by_device[$device], 'path')) <= strlen($path)) {
                continue;
            }
            $by_device[$device] = $row;
        }

        foreach ($by_device as $row) {
            $bs    = (float) self::int($row, 'blocks_size');
            $total = self::mib((float) self::int($row, 'blocks') * $bs);
            if ($total <= 0) {
                continue;
            }

            $out[] = self::clean([
                'volumn'     => self::str($row, 'device'),
                'type'       => self::str($row, 'path'),
                'filesystem' => self::str($row, 'type'),
                'total'      => $total,
                // blocks_available, not blocks_free: the difference is the
                // root reserve, and available is the number a user can act on.
                'free'       => self::mib((float) self::int($row, 'blocks_available') * $bs),
            ]);
        }

        // Windows: bytes, with -1 meaning the query failed for that drive.
        foreach ($this->rows('inv_logical_drives') as $row) {
            $size = self::int($row, 'size');
            $free = self::int($row, 'free_space');
            if ($size <= 0) {
                continue;
            }

            $entry = [
                'letter'      => self::str($row, 'device_id'),
                'volumn'      => self::str($row, 'device_id'),
                'type'        => self::str($row, 'description'),
                'filesystem'  => self::str($row, 'file_system'),
                'total'       => self::mib((float) $size),
                'systemdrive' => self::int($row, 'boot_partition') === 1,
            ];

            // logical_drives returns -1 when it could not read the value.
            // Reporting that as 0 would state the disk is completely full,
            // which is a specific and alarming claim to make about a drive we
            // simply failed to measure — so the field is omitted instead.
            if ($free >= 0) {
                $entry['free'] = self::mib((float) $free);
            }

            $out[] = self::clean($entry);
        }

        return $out;
    }

    private function networks(): array
    {
        $addresses = [];
        foreach ($this->rows('inv_interface_addresses') as $row) {
            $addresses[self::str($row, 'interface')][] = $row;
        }

        $out = [];
        foreach (array_merge($this->rows('inv_interface_details'), $this->rows('inv_interface_details_windows')) as $nic) {
            // Two different things, and conflating them is what produced ports
            // named "13". `interface` is the join key — an index on Windows,
            // a name on POSIX, and either way the value interface_addresses
            // carries — while the label is what a person should read.
            $key   = self::str($nic, 'interface');
            $label = self::interfaceLabel($nic);

            $speed = self::int($nic, 'link_speed') ?: self::int($nic, 'speed');
            $base  = self::clean([
                'description'  => $label,
                'mac'          => self::str($nic, 'mac'),
                'manufacturer' => self::str($nic, 'manufacturer'),
                'model'        => self::str($nic, 'description'),
                'mtu'          => self::int($nic, 'mtu'),
                'speed'        => $speed > 0 ? (string) $speed : '',
                'pcislot'      => self::str($nic, 'pci_slot'),
                'status'       => self::linkStatus($nic),
                'ipdhcp'       => self::str($nic, 'dhcp_server'),
                'virtualdev'   => self::isVirtualNic($nic, $key),
            ]);

            // Traffic counters. These are not in the `networks` part of
            // inventory.schema.json, but the schema only forbids extra keys at
            // the document root, and Asset\NetworkCard clones the whole entry
            // onto the port it builds — so they arrive as the identically-named
            // columns of glpi_networkports, which is what GLPI turns into the
            // metrics graphs. See InventorySync::refreshPortMetrics() for why
            // sending them is necessary but not sufficient.
            $base += self::counters($nic);

            $found = false;
            foreach ($addresses[$key] ?? [] as $addr) {
                $ip = self::str($addr, 'address');
                if ($ip === '') {
                    continue;
                }

                $found = true;
                // The schema carries one address per entry, so an interface
                // with several IPs becomes several entries sharing a MAC —
                // which is how GLPI's NetworkPort importer expects to receive
                // them.
                $entry = $base;
                if (str_contains($ip, ':')) {
                    $entry['ipaddress6'] = $ip;
                    $entry['ipmask6']    = self::str($addr, 'mask');
                } else {
                    $entry['ipaddress'] = $ip;
                    $entry['ipmask']    = self::str($addr, 'mask');
                }
                $out[] = $entry;
            }

            // An interface with no address is still a network port worth
            // recording (an unplugged NIC is a fact about the machine).
            if (!$found && self::str($nic, 'mac') !== '') {
                $out[] = $base;
            }
        }

        return $out;
    }

    /**
     * Interface byte and error counters, under GLPI's column names.
     *
     * Reported as osquery gives them: totals since the interface came up, the
     * same cumulative shape as the SNMP ifInOctets counters GLPI's graph was
     * built around. They are only emitted together — GLPI's own metrics writer
     * requires all four to be present before it records anything — and a NIC
     * whose driver exposes none of them is left without any, rather than
     * claiming a genuine zero.
     *
     * @return array<string,int>
     */
    private static function counters(array $nic): array
    {
        $map = [
            'ifinbytes'   => 'ibytes',
            'ifoutbytes'  => 'obytes',
            'ifinerrors'  => 'ierrors',
            'ifouterrors' => 'oerrors',
        ];

        $out = [];
        foreach ($map as $glpi => $osquery) {
            if (!array_key_exists($osquery, $nic) || self::str($nic, $osquery) === '') {
                return [];
            }
            $out[$glpi] = self::int($nic, $osquery);
        }

        return $out;
    }

    /**
     * Is the interface up?
     *
     * `enabled` is only populated on Windows, so trusting it alone reported
     * every Linux and macOS interface as Down — including ones plainly holding
     * an address. On POSIX the truth is in `flags`, where IFF_UP is bit 0.
     */
    private static function linkStatus(array $nic): string
    {
        // The schema constrains this to a lowercase enum
        // (up|down|dormant|notpresent|lowerlayerdown|unknown|testing).
        if (array_key_exists('enabled', $nic) && self::str($nic, 'enabled') !== '') {
            return self::int($nic, 'enabled') === 1 ? 'up' : 'down';
        }

        return (self::int($nic, 'flags') & 0x1) === 0x1 ? 'up' : 'down';
    }

    /**
     * What to call an interface.
     *
     * On POSIX `interface` is already the name — eth0, en0 — and the Windows
     * columns below are empty, so the fallback chain lands on it. On Windows
     * `interface` is the adapter index and the name lives in one of three
     * columns depending on the release: NetConnectionID, the friendly name, or
     * the adapter's own description. Taking the first that is populated means
     * the port is called "Ethernet" where Windows knows that name and
     * "Intel(R) Wi-Fi 6E AX211" where it only knows the hardware, rather than
     * "13" either way.
     */
    private static function interfaceLabel(array $nic): string
    {
        foreach (['connection_id', 'friendly_name', 'description'] as $column) {
            $value = self::str($nic, $column);
            if ($value !== '') {
                return $value;
            }
        }

        return self::str($nic, 'interface');
    }

    /**
     * Is this a virtual interface?
     *
     * Windows says so outright, and its interface names would defeat the
     * prefix test below — an index never starts with "veth".
     */
    private static function isVirtualNic(array $nic, string $interface): bool
    {
        if (array_key_exists('physical_adapter', $nic) && self::str($nic, 'physical_adapter') !== '') {
            return self::int($nic, 'physical_adapter') !== 1;
        }

        return self::isVirtual($interface);
    }

    private static function isVirtual(string $interface): bool
    {
        foreach (['veth', 'docker', 'br-', 'virbr', 'vmnet', 'tun', 'tap', 'lo', 'utun', 'bridge'] as $prefix) {
            if (str_starts_with($interface, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function softwares(): array
    {
        $out = [];

        foreach ($this->rows('inv_deb_packages') as $row) {
            $out[] = self::clean([
                'name'            => self::str($row, 'name'),
                'version'         => self::str($row, 'version'),
                'arch'            => self::str($row, 'arch'),
                'publisher'       => self::str($row, 'maintainer'),
                'system_category' => self::str($row, 'section'),
                'filesize'        => self::int($row, 'size'),
                'from'            => 'deb',
            ]);
        }

        foreach ($this->rows('inv_rpm_packages') as $row) {
            $version = self::str($row, 'version');
            $release = self::str($row, 'release');

            $entry = [
                'name'            => self::str($row, 'name'),
                'version'         => $release !== '' ? $version . '-' . $release : $version,
                'arch'            => self::str($row, 'arch'),
                'publisher'       => self::str($row, 'vendor'),
                'system_category' => self::str($row, 'package_group'),
                'filesize'        => self::int($row, 'size'),
                'from'            => 'rpm',
            ];
            $installed = self::date(self::str($row, 'install_time'));
            if ($installed !== '') {
                $entry['install_date'] = $installed;
            }
            $out[] = self::clean($entry);
        }

        foreach ($this->rows('inv_apps') as $row) {
            $out[] = self::clean([
                'name'            => self::str($row, 'name'),
                'version'         => self::str($row, 'bundle_short_version') ?: self::str($row, 'bundle_version'),
                'guid'            => self::str($row, 'bundle_identifier'),
                'system_category' => self::str($row, 'category'),
                'folder'          => self::str($row, 'path'),
                'from'            => 'apps',
            ]);
        }

        foreach ($this->rows('inv_homebrew_packages') as $row) {
            $out[] = self::clean([
                'name'    => self::str($row, 'name'),
                'version' => self::str($row, 'version'),
                'folder'  => self::str($row, 'prefix'),
                'from'    => 'homebrew',
            ]);
        }

        foreach ($this->rows('inv_programs') as $row) {
            $entry = [
                'name'             => self::str($row, 'name'),
                'version'          => self::str($row, 'version'),
                'publisher'        => self::str($row, 'publisher'),
                'guid'             => self::str($row, 'identifying_number'),
                'folder'           => self::str($row, 'install_location'),
                'uninstall_string' => self::str($row, 'uninstall_string'),
                'from'             => 'registry',
            ];
            // Windows registry install dates are YYYYMMDD.
            $installed = self::date(self::str($row, 'install_date'));
            if ($installed !== '') {
                $entry['install_date'] = $installed;
            }
            $out[] = self::clean($entry);
        }

        foreach ($this->rows('inv_patches') as $row) {
            $hotfix = self::str($row, 'hotfix_id');
            if ($hotfix === '') {
                continue;
            }
            $out[] = self::clean([
                'name'            => $hotfix,
                'version'         => $hotfix,
                'comments'        => self::str($row, 'description'),
                'system_category' => 'update',
                'from'            => 'windows_update',
            ]);
        }

        return $out;
    }

    private function localUsers(): array
    {
        $out  = [];
        $seen = [];

        // POSIX and Windows ask for local accounts differently — see
        // DefaultPacks — so both query names feed this one section.
        foreach (array_merge($this->rows('inv_users'), $this->rows('inv_users_windows')) as $row) {
            $login = self::str($row, 'username');
            if ($login === '' || isset($seen[$login])) {
                continue;
            }
            $seen[$login] = true;
            $out[] = self::clean([
                'login' => $login,
                'name'  => self::str($row, 'description'),
                // The schema types these ids as strings, not integers.
                'id'    => (string) self::int($row, 'uid'),
                'home'  => self::str($row, 'directory'),
                'shell' => self::str($row, 'shell'),
            ]);
        }

        return $out;
    }

    private function localGroups(): array
    {
        $out = [];
        foreach ($this->rows('inv_groups') as $row) {
            $name = self::str($row, 'groupname');
            if ($name === '') {
                continue;
            }
            $out[] = self::clean([
                'name' => $name,
                'id'   => (string) self::int($row, 'gid'),
            ]);
        }

        return $out;
    }

    private function users(): array
    {
        $out  = [];
        $seen = [];

        // POSIX via logged_in_users, Windows via logon_sessions — the same
        // question, two tables.
        foreach (['inv_logged_in_users', 'inv_logon_sessions'] as $query) {
            foreach ($this->rows($query) as $row) {
                $login = self::str($row, 'user');
                if ($login === '' || isset($seen[$login])) {
                    continue;
                }
                $seen[$login] = true;

                $out[] = self::clean([
                    'login'  => $login,
                    'domain' => self::str($row, 'logon_domain'),
                ]);
            }
        }

        return $out;
    }

    private function batteries(): array
    {
        $out = [];
        foreach ($this->rows('inv_battery') as $row) {
            $entry = [
                'name'          => self::str($row, 'model'),
                'manufacturer'  => self::str($row, 'manufacturer'),
                'serial'        => self::str($row, 'serial_number'),
                'chemistry'     => self::str($row, 'chemistry'),
                'date'          => self::date(self::str($row, 'manufacture_date')),
                // osquery reports mAh and mV; GLPI stores the same units.
                'capacity'      => self::int($row, 'designed_capacity'),
                'real_capacity' => self::int($row, 'max_capacity'),
                'voltage'       => self::int($row, 'voltage'),
            ];
            $out[] = self::clean($entry);
        }

        return $out;
    }

    private function monitors(): array
    {
        $out = [];

        // macOS: a first-class table.
        foreach ($this->rows('inv_connected_displays') as $row) {
            $out[] = self::clean([
                'name'        => self::str($row, 'name'),
                'caption'     => self::str($row, 'name'),
                'serial'      => self::str($row, 'serial_number'),
                'description' => self::str($row, 'resolution'),
                'port'        => self::str($row, 'connection_type'),
            ]);
        }

        // Windows and Linux have no monitor table, so a raw EDID block is
        // collected instead — from the registry on Windows, and from
        // /sys/class/drm via the agent's extension on Linux. Both arrive in the
        // same {path, data} shape deliberately, so one decoder serves both.
        $seen = [];
        foreach (array_merge($this->rows('inv_monitor_edid'), $this->rows('inv_monitor_edid_linux')) as $row) {
            $edid = Edid::parse(self::str($row, 'data'));
            if ($edid === null) {
                continue;
            }

            // The same panel appears under several registry paths (one per
            // instance the OS has ever enumerated). Deduplicate on the
            // identity the EDID itself carries.
            $key = $edid['manufacturer'] . '|' . $edid['product_code'] . '|' . $edid['serial'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;

            $connector = Edid::connector(self::str($row, 'path'));

            // Prefer the connector named in the sysfs path over the EDID's own
            // interface byte: the byte says what the panel supports, the path
            // says what it is actually plugged into.
            $kind = $connector['kind'] ?: (string) $edid['interface'];

            // The kernel's preferred mode beats anything we can decode, because
            // it accounts for DisplayID extension blocks that this parser does
            // not read.
            $resolution = self::str($row, 'preferred_mode') ?: (string) $edid['resolution'];

            $entry = [
                'name'         => $edid['name'] ?: ($edid['manufacturer'] . ' ' . $edid['product_code']),
                'caption'      => $edid['name'],
                'manufacturer' => $edid['manufacturer'],
                'serial'       => $edid['serial'],
                // GLPI ignores the schema's `altserial`, so the second serial
                // goes straight to the column that actually stores it.
                'otherserial'  => (string) $edid['alt_serial'],
                // Both of these are valid in the inventory format but GLPI has
                // nowhere to put them: glpi_monitors has no port or resolution
                // column, and Asset\Monitor unsets `comment` after using it
                // only as a name fallback. They are still sent so the document
                // is complete and correct — the raw EDID and the resolution
                // remain queryable live via the glpi_edid table — but do not
                // expect them on the monitor form.
                'port'         => $connector['port'],
                'description'  => trim($resolution . ' ' . ($edid['size_inches'] > 0 ? $edid['size_inches'] . '"' : '')),
                // GLPI keeps the raw block so it can re-derive anything we did
                // not decode.
                'base64'       => self::edidBase64(self::str($row, 'data')),
            ];

            if ((float) $edid['size_inches'] > 0) {
                $entry['size'] = (float) $edid['size_inches'];
            }

            // These are real columns on glpi_monitors, so they populate the
            // connection checkboxes on the monitor form.
            foreach (
                [
                    'displayport' => 'have_displayport',
                    'hdmi'        => 'have_hdmi',
                    'dvi'         => 'have_dvi',
                    'vga'         => 'have_subd',
                ] as $candidate => $column
            ) {
                if ($kind === $candidate) {
                    $entry[$column] = 1;
                }
            }

            $out[] = self::clean($entry);
        }

        return $out;
    }

    /** The raw EDID as base64, for GLPI's own records. */
    private static function edidBase64(string $raw): string
    {
        $hex = preg_replace('/\s+/', '', $raw) ?? '';
        if ($hex !== '' && preg_match('/^[0-9A-Fa-f]+$/', $hex) === 1 && strlen($hex) % 2 === 0) {
            $binary = @hex2bin(strtolower($hex));
            if ($binary !== false) {
                return base64_encode($binary);
            }
        }

        return '';
    }

    private function videos(): array
    {
        $out = [];
        foreach ($this->rows('inv_video_info') as $row) {
            $out[] = self::clean([
                'name'       => self::str($row, 'model'),
                'chipset'    => self::str($row, 'series'),
                'resolution' => self::str($row, 'video_mode'),
            ]);
        }

        return $out;
    }

    private function controllers(): array
    {
        $out = [];
        foreach ($this->rows('inv_pci_devices') as $row) {
            $name = self::str($row, 'model');
            if ($name === '') {
                continue;
            }
            $out[] = self::clean([
                'name'         => $name,
                'manufacturer' => self::str($row, 'vendor'),
                'type'         => self::str($row, 'pci_class'),
                'pcislot'      => self::str($row, 'pci_slot'),
                'vendorid'     => self::str($row, 'vendor_id'),
                'productid'    => self::str($row, 'model_id'),
                'driver'       => self::str($row, 'driver'),
            ]);
        }

        // Windows, where osquery has neither of the tables above and `drivers`
        // is the only enumeration of the machine's devices.
        foreach ($this->rows('inv_drivers') as $row) {
            $name = self::str($row, 'device_name');
            if ($name === '') {
                continue;
            }
            $out[] = self::clean([
                'name'         => $name,
                'caption'      => self::str($row, 'description'),
                'manufacturer' => self::str($row, 'manufacturer') ?: self::str($row, 'provider'),
                'type'         => self::str($row, 'class'),
                'driver'       => self::str($row, 'service'),
                'rev'          => self::str($row, 'version'),
            ]);
        }

        return $out;
    }

    private function usbDevices(): array
    {
        $out = [];
        foreach ($this->rows('inv_usb_devices') as $row) {
            $name = self::str($row, 'model');
            if ($name === '') {
                continue;
            }
            $out[] = self::clean([
                'name'         => $name,
                'caption'      => $name,
                'manufacturer' => self::str($row, 'vendor'),
                'serial'       => self::str($row, 'serial'),
                'vendorid'     => self::str($row, 'vendor_id'),
                'productid'    => self::str($row, 'model_id'),
                'class'        => self::str($row, 'class'),
                'subclass'     => self::str($row, 'subclass'),
            ]);
        }

        return $out;
    }

    /**
     * Map a container state onto the schema's VM status enum
     * (running|blocked|idle|paused|shutdown|crashed|dying|off).
     *
     * Docker's vocabulary is its own — created/restarting/exited/dead — and
     * passing it through unmapped fails validation.
     */
    private static function vmStatus(string $state): string
    {
        return match (strtolower($state)) {
            'running'            => 'running',
            'paused'             => 'paused',
            'restarting'         => 'blocked',
            'created'            => 'shutdown',
            'exited', 'stopped'  => 'off',
            'dead'               => 'crashed',
            'removing'           => 'dying',
            default              => 'off',
        };
    }

    private function virtualMachines(): array
    {
        $out = [];
        foreach ($this->rows('inv_docker_containers') as $row) {
            $name = self::str($row, 'name');
            if ($name === '') {
                continue;
            }
            $out[] = self::clean([
                'name'    => ltrim($name, '/'),
                'uuid'    => self::str($row, 'id'),
                'image'   => self::str($row, 'image'),
                'status'  => self::vmStatus(self::str($row, 'state')),
                'vmtype'  => 'docker',
                'comment' => self::str($row, 'status'),
            ]);
        }

        return $out;
    }
}
