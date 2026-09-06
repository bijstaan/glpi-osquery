<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;
use Ticket;

/**
 * Compliance checks derived from the security-posture pack.
 *
 * Evaluated live from the stored snapshots rather than kept as a separate
 * result table: the snapshots already are the latest known state, and a second
 * copy would only add a way for the two to disagree.
 *
 * Every check returns one of three answers, and the third one matters. A check
 * that cannot be evaluated reports UNKNOWN, never PASS — an estate where
 * "compliant" quietly includes "we could not tell" is worse than no report at
 * all, because it is trusted.
 */
final class Compliance
{
    public const PASS    = 'pass';
    public const FAIL    = 'fail';
    public const UNKNOWN = 'unknown';

    /**
     * The checks, in the order they are displayed.
     *
     * @return array<string,array<string,mixed>>
     */
    public static function checks(): array
    {
        return [
            'disk_encryption' => [
                'label'       => __('Disk encryption', 'glpiosquery'),
                'description' => __('The filesystem holding the operating system is encrypted at rest.', 'glpiosquery'),
                'platforms'   => ['linux', 'darwin', 'windows'],
            ],
            'firewall' => [
                'label'       => __('Firewall', 'glpiosquery'),
                'description' => __('A host firewall is switched on.', 'glpiosquery'),
                'platforms'   => ['darwin', 'windows'],
            ],
            'antivirus' => [
                'label'       => __('Antivirus', 'glpiosquery'),
                'description' => __('A registered antivirus product is present and reporting healthy.', 'glpiosquery'),
                'platforms'   => ['windows'],
            ],
        ];
    }

    /**
     * Evaluate every applicable check for one agent.
     *
     * @return array<string,array{state:string,detail:string}>
     */
    public static function evaluate(array $agent): array
    {
        return self::evaluateSnapshots(
            self::snapshotsFor((int) $agent['id']),
            QueryCatalog::normalisePlatform((string) ($agent['platform'] ?? ''))
        );
    }

    /**
     * Decide every applicable check from already-collected snapshots.
     *
     * Split from evaluate() so the decisions can be tested against captured
     * data without a database. These verdicts drive tickets and an operator's
     * sense of whether a fleet is safe, so being able to pin them to known
     * inputs matters more here than in most of the plugin.
     *
     * @param array<string,array<int,array<string,mixed>>> $snapshots
     * @return array<string,array{state:string,detail:string}>
     */
    public static function evaluateSnapshots(array $snapshots, string $platform): array
    {
        $results = [];
        foreach (self::checks() as $key => $check) {
            if (!in_array($platform, $check['platforms'], true)) {
                continue;
            }

            $results[$key] = match ($key) {
                'disk_encryption' => self::diskEncryption($snapshots, $platform),
                'firewall'        => self::firewall($snapshots, $platform),
                'antivirus'       => self::antivirus($snapshots),
                default           => ['state' => self::UNKNOWN, 'detail' => ''],
            };
        }

        return $results;
    }

    /** @return array<string,array<int,array<string,mixed>>> */
    private static function snapshotsFor(int $agents_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'SELECT' => ['query_name', 'data'],
                'FROM'   => ResultIngest::SNAPSHOT_TABLE,
                'WHERE'  => ['plugin_glpiosquery_agents_id' => $agents_id],
            ]) as $row
        ) {
            $decoded = json_decode((string) $row['data'], true);
            $out[(string) $row['query_name']] = is_array($decoded) ? $decoded : [];
        }

        return $out;
    }

    /**
     * Is the operating system's own volume encrypted?
     *
     * Deliberately answered about the *root* filesystem rather than "is
     * anything encrypted": a machine with an encrypted spare partition and a
     * plaintext system disk is not protected, and a check that says otherwise
     * is actively misleading.
     */
    private static function diskEncryption(array $snapshots, string $platform): array
    {
        if ($platform === 'windows') {
            $rows = $snapshots['sec_bitlocker'] ?? [];
            if ($rows === []) {
                return ['state' => self::UNKNOWN, 'detail' => __('BitLocker status not reported yet.', 'glpiosquery')];
            }

            foreach ($rows as $row) {
                $letter = strtoupper(trim((string) ($row['drive_letter'] ?? '')));
                if ($letter !== 'C:') {
                    continue;
                }
                $protected = (int) ($row['protection_status'] ?? 0) === 1;

                return [
                    'state'  => $protected ? self::PASS : self::FAIL,
                    'detail' => sprintf(
                        __('C: protection %1$s, %2$s', 'glpiosquery'),
                        $protected ? __('on', 'glpiosquery') : __('off', 'glpiosquery'),
                        (string) ($row['encryption_method'] ?? '')
                    ),
                ];
            }

            return ['state' => self::UNKNOWN, 'detail' => __('No system drive reported.', 'glpiosquery')];
        }

        $encryption = $snapshots['sec_disk_encryption'] ?? [];
        $mounts     = $snapshots['inv_mounts'] ?? [];

        if ($encryption === []) {
            return ['state' => self::UNKNOWN, 'detail' => __('Encryption status not reported yet.', 'glpiosquery')];
        }

        // Find the device behind "/". An LVM or LUKS root is mounted by its
        // /dev/mapper name while disk_encryption reports the /dev/dm-N node, so
        // the alias is carried too and both are tried.
        $candidates = [];
        foreach ($mounts as $mount) {
            if (trim((string) ($mount['path'] ?? '')) !== '/') {
                continue;
            }
            foreach (['device', 'device_alias'] as $field) {
                $value = trim((string) ($mount[$field] ?? ''));
                if ($value !== '') {
                    $candidates[] = $value;
                }
            }
            break;
        }

        if ($candidates === []) {
            return ['state' => self::UNKNOWN, 'detail' => __('Root filesystem not identified.', 'glpiosquery')];
        }

        $root_device = $candidates[0];

        // Prefer the bundled extension's stack walk. osquery's `encrypted` flag
        // is blank for every NVMe and device-mapper node, which on a stock LVM
        // install is the root volume and everything under it — so relying on it
        // alone answers UNKNOWN precisely where the answer matters, and an
        // entirely unencrypted fleet reads as "could not tell" rather than as a
        // finding. The kernel knows: a dm-crypt layer anywhere beneath the root
        // volume is what encryption at rest actually means here.
        $stacked = self::rootFromBlockStack($snapshots, $candidates);
        if ($stacked !== null) {
            return $stacked;
        }

        foreach ($encryption as $row) {
            if (!in_array(trim((string) ($row['name'] ?? '')), $candidates, true)) {
                continue;
            }

            $flag = trim((string) ($row['encrypted'] ?? ''));

            // An empty flag is not a "no". osquery leaves it blank for device
            // types it cannot inspect — NVMe namespaces and device-mapper nodes
            // among them — and reading that as "unencrypted" would raise a
            // false alarm on every such machine, while reading it as encrypted
            // would hide a real one.
            if ($flag === '') {
                return [
                    'state'  => self::UNKNOWN,
                    'detail' => sprintf(
                        __('osquery could not determine encryption for %s (device-mapper or NVMe node).', 'glpiosquery'),
                        $root_device
                    ),
                ];
            }

            $encrypted = $flag === '1';

            return [
                'state'  => $encrypted ? self::PASS : self::FAIL,
                'detail' => sprintf(
                    __('%1$s: %2$s', 'glpiosquery'),
                    $root_device,
                    $encrypted
                        ? (trim((string) ($row['type'] ?? '')) ?: __('encrypted', 'glpiosquery'))
                        : __('not encrypted', 'glpiosquery')
                ),
            ];
        }

        return [
            'state'  => self::UNKNOWN,
            'detail' => sprintf(__('No encryption record for %s.', 'glpiosquery'), $root_device),
        ];
    }

    /**
     * Resolve the root volume's encryption from the extension's stack walk.
     *
     * Returns null when the extension has reported nothing for this device, so
     * the caller falls back to osquery — an agent may be running an older
     * bundle, which self-update makes a normal state rather than an edge case.
     *
     * @param array<string,array<int,array<string,mixed>>> $snapshots
     * @param array<int,string>                            $candidates
     * @return array{state:string,detail:string}|null
     */
    private static function rootFromBlockStack(array $snapshots, array $candidates): ?array
    {
        $rows = $snapshots['sec_block_stack'] ?? [];
        if ($rows === []) {
            return null;
        }

        foreach ($rows as $row) {
            $device = trim((string) ($row['device'] ?? ''));
            $name   = trim((string) ($row['name'] ?? ''));

            $matches = in_array($device, $candidates, true)
                || in_array($name, $candidates, true)
                || in_array('/dev/mapper/' . trim((string) ($row['dm_name'] ?? '')), $candidates, true);

            if (!$matches) {
                continue;
            }

            $flag = trim((string) ($row['encrypted'] ?? ''));

            // Still blank means the walk could not be completed — a mapped
            // device whose backing store sysfs would not show. Saying "not
            // encrypted" there would be a guess dressed as a measurement.
            if ($flag === '') {
                return [
                    'state'  => self::UNKNOWN,
                    'detail' => sprintf(
                        __('The device stack under %s could not be resolved.', 'glpiosquery'),
                        $device !== '' ? $device : $name
                    ),
                ];
            }

            if ($flag === '1') {
                return [
                    'state'  => self::PASS,
                    'detail' => sprintf(
                        __('%1$s is backed by %2$s (dm-crypt).', 'glpiosquery'),
                        $device,
                        trim((string) ($row['crypt_device'] ?? '')) ?: __('an encrypted volume', 'glpiosquery')
                    ),
                ];
            }

            $parents = trim((string) ($row['parents'] ?? ''));

            return [
                'state'  => self::FAIL,
                'detail' => sprintf(
                    __('%1$s is not encrypted: no dm-crypt layer beneath it%2$s.', 'glpiosquery'),
                    $device,
                    $parents !== '' ? sprintf(__(' (backed by %s)', 'glpiosquery'), $parents) : ''
                ),
            ];
        }

        return null;
    }

    private static function firewall(array $snapshots, string $platform): array
    {
        if ($platform === 'darwin') {
            $rows = $snapshots['sec_firewall_macos'] ?? [];
            if ($rows === []) {
                return ['state' => self::UNKNOWN, 'detail' => __('Firewall status not reported yet.', 'glpiosquery')];
            }
            $state = (int) ($rows[0]['global_state'] ?? 0);

            return [
                'state'  => $state > 0 ? self::PASS : self::FAIL,
                'detail' => $state > 0
                    ? __('Application firewall on', 'glpiosquery')
                    : __('Application firewall off', 'glpiosquery'),
            ];
        }

        $rows = $snapshots['sec_firewall_windows'] ?? [];
        if ($rows === []) {
            return ['state' => self::UNKNOWN, 'detail' => __('Firewall status not reported yet.', 'glpiosquery')];
        }

        // windows_security_center reports "Good"/"Poor"/"Snoozed"/"Not monitored".
        $status = trim((string) ($rows[0]['firewall'] ?? ''));

        return [
            'state'  => strcasecmp($status, 'Good') === 0 ? self::PASS : self::FAIL,
            'detail' => sprintf(__('Security Center reports %s', 'glpiosquery'), $status !== '' ? $status : '—'),
        ];
    }

    private static function antivirus(array $snapshots): array
    {
        $rows = $snapshots['sec_av_products'] ?? [];
        if ($rows === []) {
            return ['state' => self::UNKNOWN, 'detail' => __('No antivirus data reported yet.', 'glpiosquery')];
        }

        foreach ($rows as $row) {
            if (strcasecmp(trim((string) ($row['type'] ?? '')), 'Antivirus') !== 0) {
                continue;
            }
            $on = strcasecmp(trim((string) ($row['state'] ?? '')), 'On') === 0;

            return [
                'state'  => $on ? self::PASS : self::FAIL,
                'detail' => trim((string) ($row['name'] ?? '')) . ' — ' . trim((string) ($row['state'] ?? '')),
            ];
        }

        return ['state' => self::FAIL, 'detail' => __('No antivirus product registered.', 'glpiosquery')];
    }

    /**
     * Compliance across the fleet, in the caller's entity scope.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function fleet(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => Node::TABLE,
                'WHERE' => [
                    'is_deleted'  => 0,
                    'is_active'   => 1,
                    'entities_id' => Targeting::entityScope([]),
                ],
                'ORDER' => ['name'],
            ]) as $agent
        ) {
            $out[] = [
                'agent'   => $agent,
                'results' => self::evaluate($agent),
            ];
        }

        return $out;
    }

    // ------------------------------------------------------------- ticketing

    /**
     * Open tickets for machines that are failing a check.
     *
     * Only outright failures raise a ticket — never an UNKNOWN. An agent that
     * has simply not reported yet is not a compliance breach, and a helpdesk
     * that fills with tickets about missing data quickly gets ignored, taking
     * the real findings with it.
     *
     * @return int tickets opened
     */
    public static function raiseTickets(): int
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        if (empty($settings['compliance_tickets'])) {
            return 0;
        }

        $opened = 0;
        foreach (self::fleet() as $entry) {
            foreach ($entry['results'] as $key => $result) {
                if ($result['state'] !== self::FAIL) {
                    continue;
                }
                if (self::openTicket($entry['agent'], $key, $result)) {
                    $opened++;
                }
            }
        }

        return $opened;
    }

    private static function openTicket(array $agent, string $check, array $result): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $checks = self::checks();
        $title  = sprintf(
            __('Compliance: %1$s failing on %2$s', 'glpiosquery'),
            $checks[$check]['label'] ?? $check,
            (string) $agent['name']
        );

        // One open ticket per machine per check. Re-raising on every cron run
        // would bury the helpdesk in duplicates of a problem it already knows
        // about, so an existing unresolved ticket counts as handled.
        // Anything not yet solved or closed counts as already handled. The
        // negation has to be written as a NOT criterion — `['NOT', [...]]` as a
        // field value is not the query builder's syntax and silently matches
        // nothing, which turns "open one ticket" into "open one every run".
        $done = array_merge(Ticket::getSolvedStatusArray(), Ticket::getClosedStatusArray());

        $existing = $DB->request([
            'COUNT' => 'cpt',
            'FROM'  => 'glpi_tickets',
            'WHERE' => [
                'name'       => $title,
                'is_deleted' => 0,
                'NOT'        => ['status' => $done],
            ],
        ]);
        foreach ($existing as $row) {
            if ((int) $row['cpt'] > 0) {
                return false;
            }
        }

        $content = sprintf(
            __("The osquery agent on %1\$s reports that this check is failing.\n\nCheck: %2\$s\nDetail: %3\$s\n\n%4\$s", 'glpiosquery'),
            (string) $agent['name'],
            $checks[$check]['label'] ?? $check,
            $result['detail'] !== '' ? $result['detail'] : __('no detail reported', 'glpiosquery'),
            $checks[$check]['description'] ?? ''
        );

        $ticket = new Ticket();
        $input  = [
            'name'        => $title,
            'content'     => $content,
            'entities_id' => (int) $agent['entities_id'],
            'urgency'     => 3,
            'type'        => Ticket::INCIDENT_TYPE,
        ];

        // Attach the ticket to the inventoried asset where there is one, so it
        // shows up in the machine's own history rather than floating free.
        if (!empty($agent['itemtype']) && !empty($agent['items_id'])) {
            $input['items_id'] = [(string) $agent['itemtype'] => [(int) $agent['items_id']]];
        }

        return (bool) $ticket->add($input);
    }
}
