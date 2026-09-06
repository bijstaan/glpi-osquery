<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;

/**
 * Ingest of scheduled results and status lines from /log.
 *
 * Snapshot results are stored one row per (agent, query), overwritten each
 * time. That is correct rather than lossy: an osquery snapshot is the complete
 * current state of that table, so the newest one is the whole truth and there
 * is nothing to merge. It also bounds the table at agents × queries instead of
 * growing forever, which matters when the fleet reports every hour.
 */
final class ResultIngest
{
    public const SNAPSHOT_TABLE = 'glpi_plugin_glpiosquery_snapshots';
    public const STATUS_TABLE   = 'glpi_plugin_glpiosquery_statuslogs';

    /**
     * @param array<int,array<string,mixed>> $data osquery's result log batch
     */
    public static function results(int $agents_id, array $data): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $latest = [];

        foreach ($data as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $name = (string) ($entry['name'] ?? '');
            if ($name === '') {
                continue;
            }

            // Only snapshot queries feed inventory. A differential result
            // (added/removed rows) describes a change, not a state, and cannot
            // be assembled into an inventory document — so it is ignored here
            // rather than silently producing a half-empty asset.
            if (!array_key_exists('snapshot', $entry)) {
                continue;
            }

            $unix = (int) ($entry['unixTime'] ?? time());
            if (isset($latest[$name]) && $latest[$name]['unix'] > $unix) {
                continue;
            }

            $rows = $entry['snapshot'];
            $latest[$name] = [
                'unix' => $unix,
                'rows' => is_array($rows) ? $rows : [],
            ];
        }

        if ($latest === []) {
            return;
        }

        $now = date('Y-m-d H:i:s');
        foreach ($latest as $name => $payload) {
            $DB->doQuery(
                sprintf(
                    "INSERT INTO `%s` (`plugin_glpiosquery_agents_id`, `query_name`, `unix_time`, `row_count`, `data`, `date_mod`)
                     VALUES (%d, '%s', %d, %d, '%s', '%s')
                     ON DUPLICATE KEY UPDATE
                        `unix_time` = VALUES(`unix_time`),
                        `row_count` = VALUES(`row_count`),
                        `data`      = VALUES(`data`),
                        `date_mod`  = VALUES(`date_mod`)",
                    self::SNAPSHOT_TABLE,
                    $agents_id,
                    $DB->escape($name),
                    $payload['unix'],
                    count($payload['rows']),
                    $DB->escape((string) json_encode($payload['rows'])),
                    $now
                )
            );
        }

        // Discovery is folded in as it lands rather than on a schedule: what an
        // endpoint's extensions provide is what decides which queries it is
        // served next, so a stale answer here withholds work from a machine
        // that is ready for it.
        if (isset($latest[Extension::DISCOVERY_QUERY])) {
            Extension::recordDiscovery($agents_id, $latest[Extension::DISCOVERY_QUERY]['rows']);
        }

        if (self::touchesInventory(array_keys($latest))) {
            Node::touch($agents_id, [
                'inventory_dirty' => 1,
                'last_seen'       => $now,
            ]);
        }
    }

    /**
     * Does this batch contain anything the inventory assembler cares about?
     *
     * @param array<int,string> $query_names
     */
    private static function touchesInventory(array $query_names): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($query_names === []) {
            return false;
        }

        $rows = $DB->request([
            'COUNT'      => 'cpt',
            'FROM'       => 'glpi_plugin_glpiosquery_queries AS q',
            'INNER JOIN' => [
                'glpi_plugin_glpiosquery_packs AS p' => [
                    'ON' => ['q' => 'plugin_glpiosquery_packs_id', 'p' => 'id'],
                ],
            ],
            'WHERE'      => ['q.name' => $query_names, 'p.is_inventory' => 1],
        ]);

        foreach ($rows as $row) {
            return (int) $row['cpt'] > 0;
        }

        return false;
    }

    /**
     * Agent-side status lines.
     *
     * Only warnings and errors are kept. osquery is chatty at INFO on every
     * scheduled query, and storing all of it would mean the fleet writing more
     * log rows than inventory rows for no diagnostic gain.
     *
     * @param array<int,array<string,mixed>> $data
     */
    public static function status(int $agents_id, array $data): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach ($data as $entry) {
            if (!is_array($entry)) {
                continue;
            }

            $severity = (int) ($entry['severity'] ?? 0);
            if ($severity < 1) {
                continue;
            }

            $logged_at = isset($entry['unixTime'])
                ? date('Y-m-d H:i:s', (int) $entry['unixTime'])
                : date('Y-m-d H:i:s');

            $DB->insert(self::STATUS_TABLE, [
                'plugin_glpiosquery_agents_id' => $agents_id,
                'severity'  => $severity,
                'filename'  => mb_substr((string) ($entry['filename'] ?? ''), 0, 190),
                'line'      => (int) ($entry['line'] ?? 0),
                'message'   => (string) ($entry['message'] ?? ''),
                'logged_at' => $logged_at,
            ]);
        }
    }

    /** Drop status lines past the configured retention. Called from cron. */
    public static function pruneStatus(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $days     = max(1, (int) ($settings['statuslog_retention_days'] ?? 7));

        $DB->delete(self::STATUS_TABLE, [
            'logged_at' => ['<', date('Y-m-d H:i:s', strtotime("-$days days"))],
        ]);

        return $DB->affectedRows();
    }
}
