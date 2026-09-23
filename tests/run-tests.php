<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Dependency-free unit tests for the pure parts of the plugin.
 *
 * Run:  php plugin/tests/run-tests.php
 *
 * These cover the code where a silent mistake produces plausible-looking but
 * wrong asset data — unit conversions, schema-constrained enums, and the EDID
 * decoder — rather than anything that needs a live GLPI.
 */

declare(strict_types=1);

define('PLUGIN_GLPIOSQUERY_VERSION', 'test');

// The plugin classes call GLPI's translation helpers. Stub them so the pure
// logic can be tested without booting GLPI.
if (!function_exists('__')) {
    function __(string $text, string $domain = 'glpi'): string
    {
        return $text;
    }
}

require_once __DIR__ . '/../src/Inventory/Edid.php';
require_once __DIR__ . '/../src/Inventory/Assembler.php';
require_once __DIR__ . '/../src/EnrollSecret.php';
require_once __DIR__ . '/../src/QueryCatalog.php';
require_once __DIR__ . '/../src/DefaultPacks.php';
require_once __DIR__ . '/../src/AgentUpdate.php';
require_once __DIR__ . '/../src/Compliance.php';
require_once __DIR__ . '/../src/Node.php';
require_once __DIR__ . '/../src/TicketEvidence.php';

// Entity recursion is a GLPI global. Stubbed with a fixed two-level tree so the
// scope rules can be tested without a database: 1 is a child of 0, 2 is a child
// of 1, and 9 is unrelated.
if (!function_exists('getSonsOf')) {
    function getSonsOf(string $table, $root): array
    {
        return match ((int) $root) {
            0 => [0, 1, 2],
            1 => [1, 2],
            default => [(int) $root],
        };
    }
}

require_once __DIR__ . '/../src/Extension.php';

use GlpiPlugin\Glpiosquery\AgentUpdate;
use GlpiPlugin\Glpiosquery\Compliance;
use GlpiPlugin\Glpiosquery\DefaultPacks;
use GlpiPlugin\Glpiosquery\Extension;
use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\TicketEvidence;
use GlpiPlugin\Glpiosquery\Inventory\Assembler;
use GlpiPlugin\Glpiosquery\EnrollSecret;
use GlpiPlugin\Glpiosquery\Inventory\Edid;
use GlpiPlugin\Glpiosquery\QueryCatalog;

$passed = 0;
$failed = 0;

function check(string $what, $actual, $expected): void
{
    global $passed, $failed;

    $ok = $actual === $expected;
    if ($ok) {
        $passed++;
        return;
    }

    $failed++;
    printf(
        "FAIL %s\n     expected: %s\n     actual:   %s\n",
        $what,
        var_export($expected, true),
        var_export($actual, true)
    );
}

function section(string $name): void
{
    echo "\n== $name\n";
}

/** Build an inventory document from a fake snapshot set. */
function assemble(array $snapshots): array
{
    return document($snapshots)['content'];
}

/** The whole document, envelope included. */
function document(array $snapshots, array $agent = []): array
{
    $agent += ['id' => 1, 'deviceid' => 'osquery-test-abc123'];

    return (new Assembler($agent, $snapshots))->build();
}

// ---------------------------------------------------------------------- EDID
section('EDID');

// Captured from real hardware.
$msi = '00ffffffffffff003669a83f0000000018210104b57822783b61e5af4d3cba250c5054bfcf00'
     . '714f81c08140818f9500b300d1c001011a6800a0f0381f4030203a00ad534100001af4b000a0'
     . 'f038354030203a00ad534100001a000000fd003090fafa8c010a202020202020000000fc004d'
     . '50472034393143204f4c4544';
$msi = str_pad($msi, 256, '0');

$parsed = Edid::parse($msi);
check('MSI manufacturer', $parsed['manufacturer'] ?? null, 'MSI');
check('MSI model name', $parsed['name'] ?? null, 'MPG 491C OLED');
check('MSI product code', $parsed['product_code'] ?? null, '3FA8');

$boe = '00ffffffffffff0009e5b40c0000000034210104a51d1378070aa5a7554b9f250c50540000'
     . '0001010101010101010101010101010101119140a0b0807470302036001dbe1000001a0000'
     . '00fd001e78f4f44a010a202020202020000000fe00424f45204e4a0a202020202020000000'
     . 'fc004e4531333541314d2d4e59310a';
$boe = str_pad($boe, 256, '0');

$parsed = Edid::parse($boe);
check('BOE manufacturer', $parsed['manufacturer'] ?? null, 'BOE');
check('BOE model name', $parsed['name'] ?? null, 'NE135A1M-NY1');

check('rejects a block with no EDID header', Edid::parse(str_repeat('ab', 128)), null);
check('rejects a short block', Edid::parse('00ffffffffffff00'), null);
check('rejects empty input', Edid::parse(''), null);

// ------------------------------------------------------------------- units
section('unit conversions');

// memory_devices.size is ALREADY megabytes — converting it would report 16 GB
// of RAM as 16 MB.
$content = assemble([
    'inv_system_info'    => [['hostname' => 'unit-test', 'physical_memory' => '17179869184']],
    'inv_memory_devices' => [['size' => '8192', 'device_locator' => 'DIMM A', 'memory_type' => 'DDR4']],
]);
check('hardware.memory: 16 GiB of bytes -> MiB', $content['hardware']['memory'], 16384);
check('memories.capacity: MB passed through unconverted', $content['memories'][0]['capacity'], 8192);

// block_devices.size is in BLOCKS and must be multiplied by block_size.
$content = assemble([
    'inv_system_info'   => [['hostname' => 'unit-test']],
    'inv_block_devices' => [[
        'name' => '/dev/nvme0n1', 'size' => '1000215216', 'block_size' => '512', 'model' => 'SSD',
    ]],
]);
check('storages.disksize: blocks x block_size -> MiB', $content['storages'][0]['disksize'], 488386);

// mounts uses blocks_available (what a user can actually use), not blocks_free.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_mounts'      => [[
        'device' => '/dev/sda1', 'path' => '/', 'type' => 'ext4',
        'blocks_size' => '4096', 'blocks' => '26214400',
        'blocks_free' => '13107200', 'blocks_available' => '11796480',
    ]],
]);
check('drives.total', $content['drives'][0]['total'], 102400);
check('drives.free uses blocks_available', $content['drives'][0]['free'], 46080);

// logical_drives returns -1 on failure; that must not become a negative size.
$content = assemble([
    'inv_system_info'    => [['hostname' => 'unit-test']],
    'inv_logical_drives' => [[
        'device_id' => 'C:', 'size' => '536870912000', 'free_space' => '-1',
        'file_system' => 'NTFS', 'boot_partition' => '1',
    ]],
]);
check('drives.total from bytes', $content['drives'][0]['total'], 512000);
check('drives.free clamps the -1 failure marker', $content['drives'][0]['free'] ?? null, null);
check('drives.systemdrive is boolean', $content['drives'][0]['systemdrive'], true);

// One entry per device: a filesystem mounted several times must not be summed.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_mounts'      => [
        ['device' => '/dev/sda1', 'path' => '/', 'type' => 'ext4', 'blocks_size' => '4096', 'blocks' => '26214400', 'blocks_available' => '11796480'],
        ['device' => '/dev/sda1', 'path' => '/var/lib/docker/overlay', 'type' => 'ext4', 'blocks_size' => '4096', 'blocks' => '26214400', 'blocks_available' => '11796480'],
        ['device' => '/dev/sdb1', 'path' => '/data', 'type' => 'xfs', 'blocks_size' => '4096', 'blocks' => '13107200', 'blocks_available' => '6553600'],
    ],
]);
check('drives deduplicated by device', count($content['drives']), 2);
check('drives keeps the shortest mount path', $content['drives'][0]['type'], '/');

// ------------------------------------------------------- schema constraints
section('schema constraints');

$content = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_interface_details' => [['interface' => 'eth0', 'mac' => 'aa:bb:cc:dd:ee:ff', 'flags' => '4163']],
]);
check('networks.status lowercase from POSIX flags', $content['networks'][0]['status'], 'up');

$content = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_interface_details' => [['interface' => 'eth0', 'mac' => 'aa:bb:cc:dd:ee:ff', 'flags' => '4098']],
]);
check('networks.status down when IFF_UP is clear', $content['networks'][0]['status'], 'down');

$content = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_interface_details' => [['interface' => 'Ethernet', 'mac' => 'aa:bb:cc:dd:ee:ff', 'enabled' => '1', 'flags' => '0']],
]);
check('networks.status prefers Windows enabled column', $content['networks'][0]['status'], 'up');

// The port metrics graphs are drawn from these four columns and GLPI records
// nothing unless all four are present, so they travel as a set or not at all.
$content = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_interface_details' => [[
        'interface' => 'eth0', 'mac' => 'aa:bb:cc:dd:ee:ff', 'flags' => '4163',
        'ibytes' => '123456', 'obytes' => '654321', 'ierrors' => '0', 'oerrors' => '7',
    ]],
]);
check('networks carries the traffic counters', [
    $content['networks'][0]['ifinbytes'],
    $content['networks'][0]['ifoutbytes'],
    $content['networks'][0]['ifinerrors'],
    $content['networks'][0]['ifouterrors'],
], [123456, 654321, 0, 7]);

// A zero counter is a real reading and must survive: an idle interface that
// moved no traffic is exactly the case the graph is being asked about.
check('a zero counter is kept, not dropped', array_key_exists('ifinerrors', $content['networks'][0]), true);

$content = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_interface_details' => [[
        'interface' => 'eth0', 'mac' => 'aa:bb:cc:dd:ee:ff', 'flags' => '4163',
        'ibytes' => '123456', 'obytes' => '654321',
    ]],
]);
check('a partial counter set is not reported', array_key_exists('ifinbytes', $content['networks'][0]), false);

foreach (
    [
        ['exited', 'off'], ['created', 'shutdown'], ['dead', 'crashed'],
        ['running', 'running'], ['restarting', 'blocked'],
    ] as [$docker, $glpi]
) {
    $content = assemble([
        'inv_system_info'       => [['hostname' => 'unit-test']],
        'inv_docker_containers' => [['name' => '/c1', 'id' => 'abc', 'state' => $docker]],
    ]);
    check("virtualmachines.status maps docker '$docker'", $content['virtualmachines'][0]['status'], $glpi);
}

foreach (
    [
        ['64-bit', 'x86_64'], ['amd64', 'x86_64'], ['arm64', 'aarch64'],
        ['i386', 'i686'], ['x86_64', 'x86_64'], ['something-else', null],
    ] as [$reported, $expected]
) {
    $content = assemble([
        'inv_system_info' => [['hostname' => 'unit-test']],
        'inv_os_version'  => [['name' => 'Test', 'version' => '1', 'arch' => $reported]],
    ]);
    check("operatingsystem.arch normalises '$reported'", $content['operatingsystem']['arch'] ?? null, $expected);
}

$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_os_version'  => [['name' => 'Debian', 'version' => '13', 'platform' => 'debian', 'platform_like' => 'debian']],
]);
check('kernel_name is the family, not the distribution', $content['operatingsystem']['kernel_name'], 'linux');

// Dates must match the schema's strict patterns or be dropped entirely: one
// bad value rejects the whole document.
$content = assemble([
    'inv_system_info'   => [['hostname' => 'unit-test']],
    'inv_platform_info' => [['vendor' => 'Acme', 'version' => '1.2', 'date' => '09/13/2023']],
]);
check('bios.bdate normalised from US format', $content['bios']['bdate'], '2023-09-13');

$content = assemble([
    'inv_system_info'   => [['hostname' => 'unit-test']],
    'inv_platform_info' => [['vendor' => 'Acme', 'date' => 'not a date at all']],
]);
check('unparseable date is dropped, not emitted', $content['bios']['bdate'] ?? null, null);

$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_programs'    => [['name' => 'Thing', 'version' => '1.0', 'install_date' => '20240115']],
]);
check('windows registry install date YYYYMMDD', $content['softwares'][0]['install_date'], '2024-01-15');

// One nameless entry used to make GLPI reject the entire inventory.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_programs'    => [
        ['name' => '', 'version' => '10.0', 'install_location' => 'C:\\Windows\\System32\\mstsc.exe'],
        ['name' => 'Thing', 'version' => '1.0'],
    ],
]);
check('nameless software is skipped', count($content['softwares']), 1);
check('named software survives beside it', $content['softwares'][0]['name'], 'Thing');

// NUL bytes arrive in real captures (AMD cpu_brand) and must not survive.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test', 'cpu_brand' => "AMD Ryzen 7\0\0", 'cpu_physical_cores' => '8']],
]);
check('cpu fallback strips NUL padding', $content['cpus'][0]['name'], 'AMD Ryzen 7');

// An absent section must not be emitted as [] — that reads as "this machine has
// none", and GLPI would delete components a failed query simply did not report.
$content = assemble(['inv_system_info' => [['hostname' => 'unit-test']]]);
check('empty sections are omitted entirely', array_key_exists('softwares', $content), false);
check('local ids are strings', assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_users'       => [['username' => 'root', 'uid' => '0']],
])['local_users'][0]['id'], '0');

// ------------------------------------------------- partial snapshot safety
section('partial snapshots');

// Snapshots arrive over several collection cycles, so the first assemblies
// routinely run with an incomplete set. GLPI assigns the OS name into a
// non-nullable property and fatals on null, taking the WHOLE inventory with it
// — so a nameless operating system must not be reported at all.
$content = assemble([
    'inv_system_info' => [['hostname' => 'early']],
    'inv_kernel_info' => [['version' => '6.8.0']],
    'inv_uptime'      => [['total_seconds' => '1000']],
]);
check('no operatingsystem section without an OS name', array_key_exists('operatingsystem', $content), false);
check('the rest of the document still assembles', $content['hardware']['name'], 'early');

$content = assemble([
    'inv_system_info' => [['hostname' => 'later']],
    'inv_os_version'  => [['name' => 'Ubuntu', 'version' => '26.04']],
    'inv_kernel_info' => [['version' => '6.8.0']],
]);
check('operatingsystem appears once the name is known', $content['operatingsystem']['name'], 'Ubuntu');

// ------------------------------------------------------- platform backfill
section('platform backfill');

// Windows has no monitor table; the EDID blob comes out of the registry.
$content = assemble([
    'inv_system_info'  => [['hostname' => 'win-box']],
    'inv_monitor_edid' => [
        ['path' => 'HKLM\...\DISPLAY\MSI3FA8\7&1\Device Parameters\EDID', 'data' => $msi],
        // The same panel enumerated under a second instance path.
        ['path' => 'HKLM\...\DISPLAY\MSI3FA8\7&2\Device Parameters\EDID', 'data' => $msi],
        ['path' => 'HKLM\...\DISPLAY\BOE0CB4\4&3\Device Parameters\EDID', 'data' => $boe],
    ],
]);
check('windows monitors decoded from EDID', count($content['monitors']), 2);
check('monitor manufacturer', $content['monitors'][0]['manufacturer'], 'MSI');
check('monitor name', $content['monitors'][0]['name'], 'MPG 491C OLED');
check('second monitor decoded', $content['monitors'][1]['manufacturer'], 'BOE');
check('raw EDID kept as base64', str_starts_with($content['monitors'][0]['base64'] ?? '', 'AP///////wA'), true);

$content = assemble([
    'inv_system_info'  => [['hostname' => 'win-box']],
    'inv_monitor_edid' => [['path' => 'x', 'data' => 'deadbeef']],
]);
check('undecodable EDID yields no monitor', array_key_exists('monitors', $content), false);

// chassis_info supplies the chassis type and stands in for a missing serial.
$content = assemble([
    'inv_system_info'  => [['hostname' => 'win-box', 'hardware_serial' => '']],
    'inv_chassis_info' => [[
        'chassis_types' => 'Laptop', 'manufacturer' => 'Dell Inc.',
        'model' => 'Latitude 7440', 'serial' => 'ABC1234', 'sku' => 'SKU-9', 'smbios_tag' => 'ASSET-1',
    ]],
]);
check('hardware.chassis_type from chassis_info', $content['hardware']['chassis_type'], 'Laptop');
check('bios.ssn falls back to chassis serial', $content['bios']['ssn'], 'ABC1234');
check('bios.assettag from smbios_tag', $content['bios']['assettag'], 'ASSET-1');

// system_info reports 0 bytes without SMBIOS; the kernel figure fills in.
$content = assemble([
    'inv_system_info' => [['hostname' => 'vm', 'physical_memory' => '0']],
    'inv_memory_info' => [['memory_total' => '4294967296']],
]);
check('hardware.memory falls back to memory_info', $content['hardware']['memory'], 4096);

// A real SMBIOS value must win over the fallback.
$content = assemble([
    'inv_system_info' => [['hostname' => 'vm', 'physical_memory' => '8589934592']],
    'inv_memory_info' => [['memory_total' => '4294967296']],
]);
check('SMBIOS memory preferred when present', $content['hardware']['memory'], 8192);

$content = assemble([
    'inv_system_info'    => [['hostname' => 'win-box']],
    'inv_logon_sessions' => [
        ['user' => 'jbloggs', 'logon_domain' => 'CORP'],
        ['user' => 'jbloggs', 'logon_domain' => 'CORP'],
    ],
]);
check('windows interactive users deduplicated', count($content['users']), 1);
check('windows user domain captured', $content['users'][0]['domain'], 'CORP');

// --------------------------------------------------------------- SQL guard
section('live query guard');

check('accepts a plain select', QueryCatalog::reject('SELECT * FROM system_info'), null);
check('accepts a CTE', QueryCatalog::reject('WITH x AS (SELECT 1) SELECT * FROM x'), null);
check('accepts a trailing semicolon', QueryCatalog::reject('SELECT 1;'), null);
check('rejects empty', QueryCatalog::reject('   ') !== null, true);
check('rejects DROP', QueryCatalog::reject('DROP TABLE users') !== null, true);
check('rejects ATTACH', QueryCatalog::reject('SELECT * FROM x; ATTACH DATABASE "/tmp/e" AS e') !== null, true);
check('rejects stacked statements', QueryCatalog::reject('SELECT 1; SELECT 2') !== null, true);
check('rejects PRAGMA', QueryCatalog::reject('PRAGMA table_info(x)') !== null, true);
// A keyword inside a string literal is data, not a statement.
check(
    'allows a keyword inside a string literal',
    QueryCatalog::reject("SELECT * FROM file WHERE path LIKE '%update%'"),
    null
);
check(
    'allows a keyword inside a comment',
    QueryCatalog::reject("SELECT 1 -- delete this later"),
    null
);

// -------------------------------------------------------- published extensions
section('published extensions');

// The name becomes a filename on every endpoint and a key here, so anything
// that could escape a directory or collide with the bundled extension is
// refused rather than quietly rewritten into something else.
foreach (['acme-inventory', 'acme_inv', 'a1b', 'x' . str_repeat('y', 62) . 'z'] as $name) {
    check("name accepted: $name", Extension::validName($name), true);
}
foreach (
    [
        '../../bin/osqueryd' => 'path traversal',
        'Acme'               => 'uppercase',
        'ab'                 => 'too short',
        '-acme'              => 'leading dash',
        'acme-'              => 'trailing dash',
        'acme inv'           => 'space',
        'acme.ext'           => 'dot',
        str_repeat('a', 65)  => 'too long',
    ] as $name => $why
) {
    check("name refused ($why)", Extension::validName($name), false);
}

// Scope is the whole point of the feature: an extension published for one
// entity must not reach another, and "and below" has to mean the subtree
// rather than everything.
check(
    'an extension reaches its own entity',
    Extension::covers(['entities_id' => 1, 'is_recursive' => 0], 1),
    true
);
check(
    'a non-recursive extension stops at its entity',
    Extension::covers(['entities_id' => 1, 'is_recursive' => 0], 2),
    false
);
check(
    'a recursive extension reaches a sub-entity',
    Extension::covers(['entities_id' => 1, 'is_recursive' => 1], 2),
    true
);
check(
    'a recursive extension does not reach a sibling',
    Extension::covers(['entities_id' => 1, 'is_recursive' => 1], 9),
    false
);
check(
    'the root entity, recursive, reaches everything',
    Extension::covers(['entities_id' => 0, 'is_recursive' => 1], 2),
    true
);
// The dangerous direction: an extension scoped to the root but NOT recursive
// must not leak into every child entity just because the root is 0.
check(
    'the root entity without recursion stays at the root',
    Extension::covers(['entities_id' => 0, 'is_recursive' => 0], 1),
    false
);

// What an agent reports installed is read back from free-form JSON it supplied,
// so a malformed or hostile value must produce an empty list rather than an
// error or a name that could later be used as a path.
check('installed list from an agent that reported nothing', Extension::installedOn([]), []);
check(
    'installed list ignores rubbish',
    Extension::installedOn(['extensions_json' => 'not json']),
    []
);
check(
    'installed names are read and sorted',
    Extension::installedOn(['extensions_json' => json_encode([
        ['name' => 'zeta', 'version' => '2'],
        ['name' => 'alpha', 'version' => '1'],
    ])]),
    ['alpha', 'zeta']
);

// ------------------------------------------------------------ rollout rings
section('update rollout rings');

check('ring is stable for a device id', AgentUpdate::ringFor('osquery-host-a-1234'), AgentUpdate::ringFor('osquery-host-a-1234'));

$rings = [];
for ($i = 0; $i < 2000; $i++) {
    $rings[] = AgentUpdate::ringFor('osquery-machine-' . $i . '-' . md5((string) $i));
}

check('rings stay within 0-99', min($rings) >= 0 && max($rings) <= 99, true);

// A lumpy hash would mean "roll out to 5%" silently reaching 0% or 30% of the
// fleet, which defeats the entire point of staging.
$buckets = array_count_values(array_map(static fn($r) => intdiv($r, 10), $rings));
check('all ten deciles are populated', count($buckets) === 10, true);
$largest = max($buckets);
check('no decile holds more than twice its share', $largest < (2000 / 10) * 2, true);

// Raising the percentage must only ever add machines, never swap which ones.
$at_ten    = array_filter($rings, static fn($r) => $r < 10);
$at_twenty = array_filter($rings, static fn($r) => $r < 20);
check(
    'a wave is a superset of the previous wave',
    count(array_diff_key($at_ten, $at_twenty)) === 0,
    true
);

// ------------------------------------------------------- published packages
section('package publishing');

// Every rejection below returns before touching the database, so these run
// without a live GLPI. A package that reaches the table wrong is not a cosmetic
// problem: the fleet downloads whatever it names, and an agent that stages a
// bad artifact takes itself out until preflight rolls it back.
$valid = [
    'kind'     => 'agent',
    'version'  => '1.0.1',
    'platform' => 'linux',
    'arch'     => 'amd64',
    'url'      => 'https://packages.example.com/agent_1.0.1_linux_amd64.tar.gz',
    'sha256'   => str_repeat('a', 64),
    'size'     => 35294325,
];

$rejects = [
    'plain http url'      => ['url' => 'http://packages.example.com/a.tar.gz'],
    'no url at all'       => ['url' => ''],
    'short sha'           => ['sha256' => str_repeat('a', 63)],
    'non-hex sha'         => ['sha256' => str_repeat('z', 64)],
    'zero size'           => ['size' => 0],
    'negative size'       => ['size' => -1],
    'unknown kind'        => ['kind' => 'malware'],
    'empty version'       => ['version' => ''],
    'empty arch'          => ['arch' => ''],
    'unknown platform'    => ['platform' => 'plan9'],
    'unknown arch'        => ['arch' => 'x86_64'],
];

foreach ($rejects as $what => $override) {
    check(
        'rejects ' . $what,
        AgentUpdate::publish(array_merge($valid, $override)) !== null,
        true
    );
}

// ------------------------------------------------------------- compliance
section('disk encryption verdicts');

// Captured from real hardware: a stock Ubuntu install with LVM straight onto an
// NVMe partition. osquery reports `encrypted` BLANK for every one of these
// devices, so before the extension's stack walk this machine — genuinely
// unencrypted — reported UNKNOWN, which reads as "we could not tell" rather
// than as a finding.
$lvm_plain = [
    'inv_mounts' => [
        ['path' => '/', 'device' => '/dev/mapper/ubuntu--vg-ubuntu--lv', 'device_alias' => '/dev/dm-0'],
    ],
    'sec_disk_encryption' => [
        ['name' => '/dev/dm-0', 'encrypted' => '', 'type' => ''],
    ],
    'sec_block_stack' => [
        [
            'name' => 'dm-0', 'device' => '/dev/dm-0', 'dm_name' => 'ubuntu--vg-ubuntu--lv',
            'kind' => 'lvm', 'parents' => 'nvme0n1p3', 'encrypted' => '0', 'crypt_device' => '',
        ],
    ],
];

$r = Compliance::evaluateSnapshots($lvm_plain, 'linux')['disk_encryption'];
check('unencrypted LVM root is a FAIL, not unknown', $r['state'], 'fail');

// The same layout with LUKS underneath. The crypt layer sits below the volume
// the filesystem is mounted from, so anything inspecting only the mounted
// device sees nothing.
$lvm_luks = $lvm_plain;
$lvm_luks['sec_block_stack'] = [
    [
        'name' => 'dm-1', 'device' => '/dev/dm-1', 'dm_name' => 'ubuntu--vg-ubuntu--lv',
        'kind' => 'lvm', 'parents' => 'dm-0', 'encrypted' => '1', 'crypt_device' => 'dm_crypt-0',
    ],
];
$r = Compliance::evaluateSnapshots($lvm_luks, 'linux')['disk_encryption'];
check('LVM over LUKS is a PASS', $r['state'], 'pass');
check('names the crypt layer', str_contains($r['detail'], 'dm_crypt-0'), true);

// An agent on an older bundle has no such table; the osquery flag must still be
// consulted rather than the check silently failing shut. Self-update makes a
// mixed-version fleet normal, not exceptional.
$no_ext = $lvm_plain;
unset($no_ext['sec_block_stack']);
$r = Compliance::evaluateSnapshots($no_ext, 'linux')['disk_encryption'];
check('falls back to osquery when the extension is absent', $r['state'], 'unknown');

// A stack that genuinely could not be walked must stay unknown: reporting
// "not encrypted" would be a guess presented as a measurement.
$unresolved = $lvm_plain;
$unresolved['sec_block_stack'] = [
    [
        'name' => 'dm-0', 'device' => '/dev/dm-0', 'dm_name' => 'ubuntu--vg-ubuntu--lv',
        'kind' => 'lvm', 'parents' => '', 'encrypted' => '', 'crypt_device' => '',
    ],
];
$r = Compliance::evaluateSnapshots($unresolved, 'linux')['disk_encryption'];
check('an unresolvable stack stays unknown', $r['state'], 'unknown');

// Windows keeps its BitLocker path untouched.
$bitlocker = ['sec_bitlocker' => [
    ['drive_letter' => 'C:', 'protection_status' => '1', 'encryption_method' => 'XTS-AES 128'],
]];
$r = Compliance::evaluateSnapshots($bitlocker, 'windows')['disk_encryption'];
check('BitLocker on is a PASS', $r['state'], 'pass');

// -------------------------------------------------- capability gating
section('minimum agent version');

// A query selecting from an extension table can only run on a bundle carrying
// that extension. Serving it to an older agent produces "no such table" once
// per interval, forever — noise indistinguishable from a real fault, across
// the whole fleet for the length of a rollout. Observed live before this gate.
foreach (
    [
        ['1.0.4', '1.0.4', true,  'exactly the floor'],
        ['1.0.5', '1.0.4', true,  'above the floor'],
        ['1.1.0', '1.0.4', true,  'a later minor'],
        ['1.0.3', '1.0.4', false, 'just below the floor'],
        ['0.4.0', '1.0.4', false, 'well below the floor'],
        ['v1.0.4', '1.0.4', true, 'a v prefix is tolerated'],
        ['0.4.0', '',      true,  'no floor set serves everyone'],
        ['',      '1.0.4', false, 'an agent that never reported a version'],
    ] as [$have, $min, $want, $what]
) {
    check('gate: ' . $what, Node::versionAtLeast(['agent_version' => $have], $min), $want);
}

// Inventory queries run at osqueryd start. Without startup_priority a daily
// query first ran up to ~26h after enrolment, so a new machine had no software.
$row = ['sql_query' => 'SELECT 1;', 'query_interval' => 86400, 'is_snapshot' => 1, 'platform' => 'windows'];
check('inventory query runs at startup',
    Node::scheduleEntry($row + ['glpi_section' => 'softwares'])['startup_priority'] ?? null, 1);
check('non-inventory query keeps osquery\'s schedule',
    array_key_exists('startup_priority', Node::scheduleEntry($row + ['glpi_section' => null])), false);
check('schedule entry keeps its platform',
    Node::scheduleEntry($row)['platform'] ?? null, 'windows');

// --------------------------------------------------------- ticket evidence
section('ticket evidence');

// Platform selection decides whether a machine is asked a question it can
// answer. Getting it wrong produces an empty section that looks like a healthy
// machine rather than a query that was never valid there.
$sql = ['linux' => 'L', 'windows' => 'W', 'all' => 'A'];
check('linux takes the linux form',   TicketEvidence::sqlFor($sql, 'linux'), 'L');
check('windows takes the windows form', TicketEvidence::sqlFor($sql, 'windows'), 'W');
check('darwin falls back to all',     TicketEvidence::sqlFor($sql, 'darwin'), 'A');
// osquery reports distributions, and normalisePlatform folds them to linux.
check('ubuntu is linux',              TicketEvidence::sqlFor($sql, 'ubuntu'), 'L');
check('no form for the platform',     TicketEvidence::sqlFor(['windows' => 'W'], 'linux'), null);

// Every probe must offer something for every platform we ship an agent for,
// or a whole section silently disappears on that OS.
foreach (TicketEvidence::probes() as $probe) {
    foreach (['linux', 'darwin', 'windows'] as $platform) {
        check(
            "probe {$probe['key']} has SQL for {$platform}",
            TicketEvidence::sqlFor($probe['sql'], $platform) !== null,
            true
        );
    }
}

// "The machine said nothing" and "the machine never answered" are different
// facts. Reporting the second as the first tells a technician a machine is
// healthy when nobody actually reached it.
$html = TicketEvidence::renderHtml(
    ['date_creation' => '2026-08-15 21:00:00'],
    [
        ['label' => 'Disk space', 'rows' => [['path' => '/', 'free_gb' => '12.5']], 'status' => 'complete'],
        ['label' => 'Active user', 'rows' => [], 'status' => 'complete'],
        ['label' => 'Uptime',      'rows' => [], 'status' => 'running'],
    ]
);
check('renders a table for answered probes', str_contains($html, '12.5'), true);
check('column headers come from the rows',   str_contains($html, 'free_gb'), true);
check('an empty answer is "nothing to report"', str_contains($html, 'Nothing to report for: Active user'), true);
check('an unanswered probe is "no answer"',    str_contains($html, 'No answer for: Uptime'), true);
check('the two are not conflated', str_contains($html, 'Nothing to report for: Active user, Uptime'), false);

// Values land in a technician's browser; a process name is attacker-influenced
// on a compromised machine, which is exactly when this followup gets read.
$html = TicketEvidence::renderHtml(
    [],
    [['label' => 'Top processes', 'rows' => [['name' => '<img src=x onerror=alert(1)>']], 'status' => 'complete']]
);
check('row values are escaped', str_contains($html, '<img src=x'), false);
check('escaped form is present', str_contains($html, '&lt;img'), true);

// ------------------------------------------------ evidence comparison
section('evidence comparison');

// The whole point of a second capture is to show something moved. Getting this
// wrong does not produce an obviously broken table — it produces a confident,
// plausible one that is wrong, which a technician then pastes to a client.

/** Find one change by section label and column. */
$find = static function (array $changes, string $label, string $column) {
    foreach ($changes as $c) {
        if ($c['label'] === $label && $c['column'] === $column) {
            return $c;
        }
    }
    return null;
};

// Eight processes, several sharing a name: pairing them off positionally
// compares unrelated processes to each other, and the numbers look real.
$before = [
    ['name' => 'msedge', 'pid' => '100', 'rss_mb' => '600.0'],
    ['name' => 'msedge', 'pid' => '101', 'rss_mb' => '400.0'],
    ['name' => 'claude', 'pid' => '200', 'rss_mb' => '679.4'],
];
$after = [
    ['name' => 'msedge', 'pid' => '300', 'rss_mb' => '150.0'],
    ['name' => 'msedge', 'pid' => '301', 'rss_mb' => '100.0'],
    ['name' => 'claude', 'pid' => '200', 'rss_mb' => '702.4'],
];
$changes = TicketEvidence::compare($after, $before);

$edge = $find($changes, 'msedge', 'rss_mb');
check('duplicate names are summed, not paired', $edge !== null ? $edge['delta'] : null, -750.0);
check('the summed before is shown', $edge !== null ? $edge['before'] : null, '1000');

// A PID subtracted from a PID is a number that means nothing. Left in, it sits
// next to real findings and teaches a technician to distrust all of them.
check('pids are never compared', $find($changes, 'msedge', 'pid'), null);
check('the key column is not compared against itself', $find($changes, 'msedge', 'name'), null);

// One row on each side: compared column by column, with no key.
$mem = TicketEvidence::compare(
    [['total_mb' => '30877', 'available_mb' => '25000']],
    [['total_mb' => '30877', 'available_mb' => '21359']]
);
check('single-row probes compare by column', count($mem), 1);
check('the changed column is the one reported', $mem[0]['column'], 'available_mb');
check('and its delta is right', $mem[0]['delta'], 3641.0);

// Unchanged values are not news, and a table full of them hides the one row
// that is.
$same = TicketEvidence::compare(
    [['path' => '/', 'free_gb' => '100.0']],
    [['path' => '/', 'free_gb' => '100.0']]
);
check('unchanged values are omitted', $same, []);

// A mount that appeared since the last capture has nothing to compare against;
// inventing a baseline of zero would report a brand-new USB stick as a
// 931 GB improvement.
$fresh = TicketEvidence::compare(
    [['path' => '/media/usb', 'free_gb' => '931.3']],
    [['path' => '/', 'free_gb' => '100.0']]
);
check('rows with no previous reading are skipped', $fresh, []);

// A RAM upgrade changes the leading column of the memory probe. Keying on it
// would mean the one change worth celebrating is the one silently dropped.
$upgrade = TicketEvidence::compare(
    [['total_mb' => '65536', 'available_mb' => '60000']],
    [['total_mb' => '30877', 'available_mb' => '21359']]
);
check('a RAM upgrade is reported, not keyed away', count($upgrade), 2);

check('nothing to compare against', TicketEvidence::compare([['a' => '1']], []), []);
check('nothing to compare', TicketEvidence::compare([], [['a' => '1']]), []);

// Probes whose values are labels rather than measurements opt out entirely.
$flags = [];
foreach (TicketEvidence::probes() as $probe) {
    $flags[$probe['key']] = $probe['compare'] ?? true;
}
check('os version is not compared', $flags['os'] ?? true, false);
check('uptime is not compared', $flags['uptime'] ?? true, false);
check('memory is compared', $flags['memory'] ?? true, true);
check('disk is compared', $flags['disk'] ?? true, true);

// ------------------------------------------------------ volume encryption
section('volume encryption');

// GLPI reads encrypt_status as an exact string: "Yes", "Partially", or — for
// everything else, empty included — not encrypted. So each of these is a
// statement GLPI will act on.
$win = fn(array $bitlocker) => assemble([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_logical_drives'  => [['device_id' => 'C:', 'size' => '256000000000', 'free_space' => '100000000000',
                               'file_system' => 'NTFS', 'boot_partition' => '1']],
    'inv_bitlocker'       => [$bitlocker],
])['drives'][0];

$drive = $win(['drive_letter' => 'C:', 'protection_status' => '1', 'conversion_status' => '1',
               'encryption_method' => 'XTS-AES-256', 'percentage_encrypted' => '100']);
check('an encrypted volume says Yes', $drive['encrypt_status'] ?? '', 'Yes');
check('with the tool named', $drive['encrypt_name'] ?? '', 'BitLocker');
check('and the algorithm', $drive['encrypt_algo'] ?? '', 'XTS-AES-256');
check('and the protection state', $drive['encrypt_type'] ?? '', 'Protection on');

$drive = $win(['drive_letter' => 'C:', 'protection_status' => '0', 'conversion_status' => '2',
               'encryption_method' => 'XTS-AES-256', 'percentage_encrypted' => '42']);
check('a conversion in progress is Partially', $drive['encrypt_status'] ?? '', 'Partially');

$drive = $win(['drive_letter' => 'C:', 'protection_status' => '0', 'conversion_status' => '0',
               'encryption_method' => 'None', 'percentage_encrypted' => '0']);
check('an unencrypted volume says No', $drive['encrypt_status'] ?? '', 'No');
check("and 'None' is not reported as an algorithm", array_key_exists('encrypt_algo', $drive), false);

// A suspended volume is still encrypted; GLPI has nowhere but encrypt_type for
// the difference, and getting it wrong would hide a real exposure.
$drive = $win(['drive_letter' => 'C:', 'protection_status' => '0', 'conversion_status' => '1',
               'encryption_method' => 'XTS-AES-256', 'percentage_encrypted' => '100']);
check('a suspended volume is still encrypted', $drive['encrypt_status'] ?? '', 'Yes');
check('and says protection is off', $drive['encrypt_type'] ?? '', 'Protection off');

// The letters have to line up or the fields land on the wrong volume.
$content = assemble([
    'inv_system_info'    => [['hostname' => 'unit-test']],
    'inv_logical_drives' => [
        ['device_id' => 'C:', 'size' => '256000000000', 'free_space' => '1', 'file_system' => 'NTFS'],
        ['device_id' => 'D:', 'size' => '128000000000', 'free_space' => '1', 'file_system' => 'NTFS'],
    ],
    'inv_bitlocker'      => [['drive_letter' => 'C:', 'protection_status' => '1',
                              'conversion_status' => '1', 'encryption_method' => 'AES-256']],
]);
check('only the matching volume is marked', [
    $content['drives'][0]['encrypt_status'] ?? '-',
    $content['drives'][1]['encrypt_status'] ?? '-',
], ['Yes', '-']);

// The trap the whole index exists to avoid: osquery leaves `encrypted` blank
// for device-mapper and NVMe nodes, and GLPI reads a blank as "not encrypted".
$content = assemble([
    'inv_system_info'      => [['hostname' => 'unit-test']],
    'inv_mounts'           => [['device' => '/dev/dm-0', 'path' => '/', 'type' => 'ext4',
                                'blocks' => '1000000', 'blocks_size' => '4096', 'blocks_available' => '500000']],
    'inv_disk_encryption'  => [['name' => '/dev/dm-0', 'encrypted' => '', 'type' => '']],
]);
check('an unreadable volume claims nothing',
    array_key_exists('encrypt_status', $content['drives'][0]), false);

$content = assemble([
    'inv_system_info'      => [['hostname' => 'unit-test']],
    'inv_mounts'           => [['device' => '/dev/disk1s1', 'path' => '/', 'type' => 'apfs',
                                'blocks' => '1000000', 'blocks_size' => '4096', 'blocks_available' => '500000']],
    'inv_disk_encryption'  => [['name' => '/dev/disk1s1', 'encrypted' => '1', 'type' => 'AES-XTS',
                                'filevault_status' => 'on', 'encryption_status' => 'encrypted']],
]);
check('FileVault is named as the tool', $content['drives'][0]['encrypt_name'] ?? '', 'FileVault');
check('and the volume reads as encrypted', $content['drives'][0]['encrypt_status'] ?? '', 'Yes');

// ------------------------------------------------------ platform coverage
section('platform coverage');

// Every shipped query must name only tables that exist on each platform it is
// served to. osquery refuses the whole query when a table is missing, so one
// wrong platform list silently costs that platform a section of every
// inventory — which is how Windows came to report no USB devices and Linux no
// battery. Extension tables are exempt when the query is gated on them.
$catalogue = [];
foreach (QueryCatalog::load()['tables'] as $table) {
    $catalogue[$table['name']] = $table['platforms'] ?? [];
}
$misplaced = [];
foreach (DefaultPacks::packs() as $pack) {
    foreach ($pack['queries'] as $q) {
        $platforms = ($q['platform'] ?? 'all') === 'all' ? ['linux', 'darwin', 'windows'] : explode(',', $q['platform']);
        preg_match_all('/\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)/i', $q['sql'], $m);
        foreach (array_unique($m[1]) as $table) {
            if ($table === 'pragma_table_info' || ($q['requires_table'] ?? null) === $table) {
                continue;
            }
            foreach ($platforms as $platform) {
                if (!in_array($platform, $catalogue[$table] ?? [], true)) {
                    $misplaced[] = "{$q['name']}: {$table} on {$platform}";
                }
            }
        }
    }
}
check('every shipped query reads tables its platforms have', $misplaced, []);

// Each platform has to reach every section it can; this is the list the
// packs promise, so a query dropped or re-platformed shows up here.
$sections = ['linux' => [], 'darwin' => [], 'windows' => []];
foreach (DefaultPacks::packs()[0]['queries'] as $q) {
    $platforms = ($q['platform'] ?? 'all') === 'all' ? array_keys($sections) : explode(',', $q['platform']);
    foreach ($platforms as $platform) {
        if (!empty($q['section'])) {
            $sections[$platform][$q['section']] = true;
        }
    }
}
$everywhere = ['hardware', 'bios', 'operatingsystem', 'cpus', 'memories', 'storages', 'drives', 'networks',
               'softwares', 'local_users', 'local_groups', 'users', 'batteries', 'monitors', 'controllers'];
foreach ($sections as $platform => $have) {
    check("$platform reaches every common section", array_values(array_diff($everywhere, array_keys($have))), []);
}

// Windows fills `speed` in bits per second; GLPI stores Mbit/s. An adapter
// with no link reports 2^63-1, which is not a speed at all.
$nets = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details_windows' => [
        ['interface' => '13', 'mac' => '3c:e9:f7:11:22:33', 'speed' => '1000000000', 'link_speed' => '',
         'connection_id' => 'Ethernet', 'physical_adapter' => '1', 'enabled' => '1'],
        ['interface' => '7', 'mac' => '3c:e9:f7:11:22:44', 'speed' => '9223372036854775807', 'link_speed' => '',
         'connection_id' => 'Wi-Fi', 'physical_adapter' => '1', 'enabled' => '0'],
    ],
])['networks'];
check('a gigabit Windows adapter is 1000 Mbit/s', $nets[0]['speed'] ?? null, '1000');
check('an adapter with no link has no speed', array_key_exists('speed', $nets[1]), false);
$nets = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details' => [['interface' => 'eth0', 'mac' => '00:11:22:33:44:55', 'link_speed' => '2500', 'flags' => '1']],
])['networks'];
check('POSIX link_speed is already Mbit/s', $nets[0]['speed'] ?? null, '2500');

// Battery capacity: osquery's mAh against GLPI's mWh. Windows mAh were made by
// osquery dividing Windows' mWh by an assumed 12 V; macOS mAh are real.
$bat = fn(string $platform, array $row) => document(
    ['inv_system_info' => [['hostname' => 'unit-test']], 'inv_battery' => [$row]],
    ['platform' => $platform]
)['content']['batteries'][0];
$b = $bat('windows', ['model' => 'DELL VJF3W', 'designed_capacity' => '4750', 'max_capacity' => '4300', 'voltage' => '12960']);
check('Windows capacity is multiplied back by 12 V', [$b['capacity'] ?? null, $b['real_capacity'] ?? null], [57000, 51600]);
$b = $bat('darwin', ['model' => 'bq40z651', 'designed_capacity' => '4382', 'max_capacity' => '4100', 'voltage' => '12780']);
check('macOS capacity is mAh times the pack voltage', $b['capacity'] ?? null, 56002);
$b = $bat('darwin', ['model' => 'bq40z651', 'designed_capacity' => '4382', 'voltage' => '']);
check('with no voltage the capacity is omitted, not guessed', array_key_exists('capacity', $b), false);
$b = assemble([
    'inv_system_info'   => [['hostname' => 'unit-test']],
    'inv_battery_linux' => [['name' => 'BAT1', 'model' => 'FRANGWA', 'technology' => 'Li-ion',
                             'design_capacity_mwh' => '60604', 'full_capacity_mwh' => '56502', 'voltage_mv' => '15480']],
])['batteries'][0];
check('Linux battery arrives in GLPI units', [$b['name'], $b['capacity'], $b['real_capacity'], $b['chemistry']],
      ['FRANGWA', 60604, 56502, 'Li-ion']);

// Chassis type is GLPI's computer type, and without one GLPI uses the
// motherboard model — a Framework laptop became a "FRANMDCP07".
$chassis = fn(array $snaps) => assemble(['inv_system_info' => [['hostname' => 'unit-test']]] + $snaps)['hardware']['chassis_type'] ?? '';
check('Windows: the enclosure, not the dock', $chassis(['inv_chassis_info' => [['chassis_types' => 'Notebook,Docking Station']]]), 'Notebook');
check('Linux: from DMI via the extension', $chassis(['inv_chassis_linux' => [['chassis_type' => '10', 'chassis_name' => 'Notebook']]]), 'Notebook');
check('SMBIOS "Other" is not a type', $chassis(['inv_chassis_linux' => [['chassis_type' => '1', 'chassis_name' => 'Other']]]), '');
check("osquery's unnamed code is not a type", $chassis(['inv_chassis_info' => [['chassis_types' => 'Unknown (37)']]]), '');
$profiler = fn(string $type, array $items) => ['data_type' => $type, 'value' => json_encode($items)];
check('macOS: from the model name', $chassis(['inv_system_profiler' => [
    $profiler('SPHardwareDataType', [['machine_name' => 'MacBook Pro', 'machine_model' => 'Mac15,3']])]]), 'Laptop');
check('macOS: a Mac mini', $chassis(['inv_system_profiler' => [
    $profiler('SPHardwareDataType', [['machine_name' => 'Mac mini']])]]), 'Mini PC');

// Windows naming: GLPI names the OS after full_name, and os_version's version
// is the kernel build, so leaving it in made every cumulative update a new OS.
$os = document([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_os_version'      => [['name' => 'Microsoft Windows 11 Pro', 'version' => '10.0.22631', 'platform' => 'windows', 'arch' => '64-bit']],
    'inv_kernel_info'     => [['version' => '10.0.22621.3155']],
    'inv_windows_version' => [['name' => 'DisplayVersion', 'data' => '23H2']],
])['content']['operatingsystem'];
check('Windows OS name carries no build', $os['full_name'] ?? '', 'Microsoft Windows 11 Pro');
check('the release is the version', $os['version'] ?? '', '23H2');
check('and the build stays as the kernel version', $os['kernel_version'] ?? '', '10.0.22621.3155');
$os = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_os_version'  => [['name' => 'Ubuntu', 'version' => '24.04.1 LTS (Noble Numbat)', 'platform' => 'ubuntu']],
])['operatingsystem'];
check('Linux naming is unchanged', $os['full_name'] ?? '', 'Ubuntu 24.04.1 LTS (Noble Numbat)');

check('Windows domain becomes the workgroup', assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_ntdomains'   => [['domain_name' => 'CORP']],
])['hardware']['workgroup'] ?? '', 'CORP');

// macOS: APFS containers and disk images are whole disks to osquery, and the
// system volumes under /System/Volumes each report the whole container.
$mac = assemble([
    'inv_system_info'   => [['hostname' => 'unit-test']],
    'inv_block_devices' => [
        ['name' => '/dev/disk0', 'parent' => '', 'model' => 'APPLE SSD AP0512Z', 'size' => '122138133', 'block_size' => '4096', 'label' => 'APPLE SSD AP0512Z Media'],
        ['name' => '/dev/disk3', 'parent' => '', 'model' => 'APPLE SSD AP0512Z', 'size' => '120699497', 'block_size' => '4096', 'label' => 'AppleAPFSMedia'],
        ['name' => '/dev/disk4', 'parent' => '', 'model' => 'Disk Image', 'size' => '51200', 'block_size' => '4096', 'label' => 'Apple UDIF Media'],
    ],
    'inv_mounts' => [
        ['device' => '/dev/disk3s1s1', 'path' => '/', 'type' => 'apfs', 'blocks' => '1000', 'blocks_size' => '4096', 'blocks_available' => '10'],
        ['device' => '/dev/disk3s6', 'path' => '/System/Volumes/VM', 'type' => 'apfs', 'blocks' => '1000', 'blocks_size' => '4096', 'blocks_available' => '10'],
        ['device' => '/dev/disk3s5', 'path' => '/System/Volumes/Data', 'type' => 'apfs', 'blocks' => '1000', 'blocks_size' => '4096', 'blocks_available' => '10'],
    ],
]);
check('only the physical SSD is a disk', array_column($mac['storages'], 'name'), ['/dev/disk0']);
check('only the startup and Data volumes are drives', array_column($mac['drives'], 'type'), ['/', '/System/Volumes/Data']);

// Apple silicon has no SMBIOS, so memory_devices is empty and memory comes
// from system_profiler as one package.
$mem = assemble([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_system_profiler' => [$profiler('SPMemoryDataType', [['_name' => 'Memory', 'SPMemoryDataType' => '16 GB', 'dimm_type' => 'LPDDR5', 'dimm_manufacturer' => 'Hynix']])],
])['memories'] ?? [];
check('Apple silicon memory is reported', [$mem[0]['capacity'] ?? 0, $mem[0]['type'] ?? ''], [16384, 'LPDDR5']);
$mem = assemble([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_memory_devices'  => [['size' => '8192', 'device_locator' => 'DIMM0']],
    'inv_system_profiler' => [$profiler('SPMemoryDataType', [['SPMemoryDataType' => '16 GB']])],
])['memories'];
check('SMBIOS wins where there is one', array_column($mem, 'capacity'), [8192]);

$gpu = assemble([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_system_profiler' => [$profiler('SPDisplaysDataType', [['_name' => 'Intel Iris Plus Graphics', 'sppci_model' => 'Intel Iris Plus Graphics',
        'spdisplays_vram_shared' => '1536 MB', 'spdisplays_ndrvs' => [['_spdisplays_pixels' => '2560 x 1600']]]])],
])['videos'][0];
check('macOS GPU with shared memory and resolution', [$gpu['name'], $gpu['memory'] ?? 0, $gpu['resolution'] ?? ''],
      ['Intel Iris Plus Graphics', 1536, '2560x1600']);

// Linux graphics and audio are PCI functions.
$pci = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_pci_devices' => [
        ['model' => 'Phoenix1', 'vendor' => 'AMD', 'pci_class' => 'Display controller', 'pci_subclass' => 'VGA compatible controller', 'pci_slot' => '0000:c1:00.0'],
        ['model' => 'Ryzen HD Audio Controller', 'vendor' => 'AMD', 'pci_class' => 'Multimedia controller', 'pci_subclass' => 'Audio device'],
        ['model' => 'FCH SMBus Controller', 'vendor' => 'AMD', 'pci_class' => 'Serial bus controller', 'pci_subclass' => 'SMBus'],
    ],
]);
check('Linux GPU', array_column($pci['videos'], 'name'), ['Phoenix1']);
check('Linux sound card', array_column($pci['sounds'], 'name'), ['Ryzen HD Audio Controller']);

// Windows: USB devices from the driver list, parents only, with a serial only
// where Windows did not have to invent the instance id.
$win = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_drivers'     => [
        ['device_id' => 'USB\VID_046D&PID_C52B\5&2A1B3C&0&3', 'device_name' => 'USB Composite Device', 'class' => 'USB'],
        ['device_id' => 'USB\VID_046D&PID_C52B&MI_00\6&1234&0&0000', 'device_name' => 'USB Input Device', 'class' => 'HIDClass'],
        ['device_id' => 'USB\VID_0BDA&PID_5634\200901010001', 'device_name' => 'Integrated Webcam', 'class' => 'Camera'],
        ['device_id' => 'USB\ROOT_HUB30\4&1F2E3D&0&0', 'device_name' => 'USB Root Hub (USB 3.0)', 'class' => 'USB'],
        ['device_id' => 'HDAUDIO\FUNC_01&VEN_10EC&DEV_0257', 'device_name' => 'Realtek(R) Audio', 'class' => 'MEDIA'],
    ],
]);
check('Windows USB devices, interfaces and hubs excluded', array_map(
    fn($u) => [$u['vendorid'], $u['productid'], $u['serial'] ?? ''],
    $win['usbdevices']
), [['046d', 'c52b', ''], ['0bda', '5634', '200901010001']]);
check('Windows sound card', array_column($win['sounds'], 'name'), ['Realtek(R) Audio']);

$av = assemble([
    'inv_system_info'       => [['hostname' => 'unit-test']],
    'inv_security_products' => [
        ['type' => 'Antivirus', 'name' => 'Microsoft Defender Antivirus', 'state' => 'Snoozed', 'signatures_up_to_date' => '0'],
        ['type' => 'Firewall', 'name' => 'Windows Firewall', 'state' => 'On', 'signatures_up_to_date' => ''],
    ],
])['antivirus'];
check('antivirus only, and a snoozed one is not enabled', $av,
      [['name' => 'Microsoft Defender Antivirus', 'enabled' => false, 'uptodate' => false]]);

// Linux users: logged_in_users is empty under systemd, so the session manager
// is what says who is there.
check('a Linux session user is reported', assemble([
    'inv_system_info'     => [['hostname' => 'unit-test']],
    'inv_logged_in_users' => [],
    'inv_session_users'   => [['user' => 'matthew']],
])['users'], [['login' => 'matthew']]);

// Linux encryption from the block stack, matched through either name mounts
// may use for a device-mapper volume.
$stack = [
    ['name' => 'dm-0', 'device' => '/dev/dm-0', 'dm_name' => 'vg-root', 'dm_uuid' => 'LVM-abc', 'kind' => 'lvm', 'encrypted' => '1', 'crypt_device' => 'luks-1234'],
    ['name' => 'dm-1', 'device' => '/dev/dm-1', 'dm_name' => 'luks-1234', 'dm_uuid' => 'CRYPT-LUKS2-1234-luks-1234', 'kind' => 'crypt', 'encrypted' => '1', 'crypt_device' => 'luks-1234'],
    ['name' => 'sda1', 'device' => '/dev/sda1', 'dm_name' => '', 'dm_uuid' => '', 'kind' => 'physical', 'encrypted' => '0', 'crypt_device' => ''],
    ['name' => 'dm-2', 'device' => '/dev/dm-2', 'dm_name' => 'odd', 'dm_uuid' => 'LVM-x', 'kind' => 'lvm', 'encrypted' => '', 'crypt_device' => ''],
];
$mount = fn(string $device, string $alias, string $path) => ['device' => $device, 'device_alias' => $alias, 'path' => $path,
    'type' => 'ext4', 'blocks' => '1000', 'blocks_size' => '4096', 'blocks_available' => '10'];
$drives = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_mounts'      => [$mount('/dev/mapper/vg-root', '/dev/dm-0', '/'), $mount('/dev/sda1', '/dev/sda1', '/boot'),
                          $mount('/dev/mapper/odd', '/dev/dm-2', '/srv')],
    'inv_block_stack' => $stack,
])['drives'];
check('LVM on LUKS is encrypted, and says LUKS2', [$drives[0]['encrypt_status'] ?? '', $drives[0]['encrypt_name'] ?? ''], ['Yes', 'LUKS2']);
check('a plain partition is a definite no', $drives[1]['encrypt_status'] ?? '', 'No');
check('an unresolved stack claims nothing', array_key_exists('encrypt_status', $drives[2]), false);

// And the Linux account boundary, as the pack's SQL applies it.
$linux_users = array_values(array_filter(DefaultPacks::packs()[0]['queries'], fn($q) => $q['name'] === 'inv_users_linux'));
check('Linux users skip the 9xx system range and nobody', str_contains($linux_users[0]['sql'] ?? '', 'uid >= 1000 AND uid < 60000'), true);

// ------------------------------------------------------- Windows adapters
section('Windows adapters');

// On Windows `interface` is the adapter index, not a name, and the name is in
// one of three other columns depending on the release. Reading the index as a
// name is what put ports called "13" in GLPI.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details_windows' => [[
        'interface' => '13', 'mac' => 'aa:bb:cc:dd:ee:ff', 'enabled' => '1',
        'connection_id' => 'Ethernet', 'friendly_name' => 'Ethernet 2',
        'description' => 'Intel(R) Ethernet Connection I219-LM', 'physical_adapter' => '1',
    ]],
]);
check('the port is named for its connection', $content['networks'][0]['description'], 'Ethernet');
check('the adapter itself is the model', $content['networks'][0]['model'], 'Intel(R) Ethernet Connection I219-LM');
check('a physical adapter is not virtual', $content['networks'][0]['virtualdev'], false);

// Only the hardware description populated — the case the fleet actually
// reported — must still beat the index.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details_windows' => [[
        'interface' => '13', 'mac' => 'aa:bb:cc:dd:ee:ff', 'enabled' => '1',
        'connection_id' => '', 'friendly_name' => '',
        'description' => 'Intel(R) Wi-Fi 6E AX211 160MHz', 'physical_adapter' => '0',
    ]],
]);
check('the description is used when nothing better exists',
    $content['networks'][0]['description'], 'Intel(R) Wi-Fi 6E AX211 160MHz');
check('a non-physical adapter is marked virtual', $content['networks'][0]['virtualdev'], true);

// The index is still the join key for addresses, which is the reason it cannot
// simply be replaced by the label.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details_windows' => [[
        'interface' => '13', 'mac' => 'aa:bb:cc:dd:ee:ff', 'enabled' => '1',
        'connection_id' => 'Wi-Fi', 'description' => 'Intel(R) Wi-Fi 6E AX211 160MHz',
    ]],
    'inv_interface_addresses' => [['interface' => '13', 'address' => '10.0.0.5', 'mask' => '255.255.255.0']],
]);
check('addresses still join on the interface index', $content['networks'][0]['ipaddress'] ?? '', '10.0.0.5');
check('and the joined entry keeps the readable name', $content['networks'][0]['description'], 'Wi-Fi');

// POSIX is untouched: the Windows columns are absent, so the chain falls
// through to the interface name.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_interface_details' => [['interface' => 'eth0', 'mac' => 'aa:bb:cc:dd:ee:ff', 'flags' => '4163']],
]);
check('POSIX interfaces keep their own name', $content['networks'][0]['description'], 'eth0');

// Windows has neither pci_devices nor usb_devices, so components came from
// nowhere at all until drivers was added.
$content = assemble([
    'inv_system_info' => [['hostname' => 'unit-test']],
    'inv_drivers' => [[
        'device_name' => 'Synaptics FP Sensors', 'description' => 'Biometric device',
        'class' => 'Biometric', 'manufacturer' => 'Synaptics', 'provider' => 'Synaptics',
        'service' => 'SynaFpSensor', 'version' => '6.0.1.2',
    ]],
]);
check('a Windows device becomes a controller', $content['controllers'][0]['name'] ?? '', 'Synaptics FP Sensors');
check('with its class as the type', $content['controllers'][0]['type'] ?? '', 'Biometric');
check('and its driver service', $content['controllers'][0]['driver'] ?? '', 'SynaFpSensor');

// --------------------------------------------------------- enrolment tag
section('Enrolment tag');

// The tag is the only thing in the document that says which entity the machine
// belongs to: GLPI decides that from the entity rules alone, and the rules can
// only see the tag. A document without one imports into the default entity,
// which is how an agent enrolled against a sub-entity's secret ended up in the
// root.
$tagged = document([], ['plugin_glpiosquery_enrollsecrets_id' => 7]);
check('the document carries the enrolling secret\'s tag', $tagged['tag'] ?? null, 'osq-7');

$untagged = document([], ['plugin_glpiosquery_enrollsecrets_id' => 0]);
check('an agent with no recorded secret carries no tag', isset($untagged['tag']), false);

check('the tag is derived from the id, not the name', EnrollSecret::tagFor(42), 'osq-42');
check('id 0 has no tag', EnrollSecret::tagFor(0), null);

// ------------------------------------------------------------------ summary
printf("\n%d passed, %d failed\n", $passed, $failed);

exit($failed === 0 ? 0 : 1);
