<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;

/**
 * Live queries.
 *
 * A campaign is one question asked of a set of agents. Its lifecycle is
 * deliberately explicit — pending → dispatched → done/failed, with a TTL —
 * because the honest answer to "what did the fleet say" is almost never "all of
 * it": machines are asleep, off the network, or slow, and a console that quietly
 * shows the 142 replies it got as though they were the whole estate is worse
 * than useless during an incident.
 */
final class Campaign
{
    public const TABLE        = 'glpi_plugin_glpiosquery_campaigns';
    public const TARGET_TABLE = 'glpi_plugin_glpiosquery_campaigntargets';
    public const ROW_TABLE    = 'glpi_plugin_glpiosquery_campaignrows';

    /** osquery gets `c<id>` as the distributed query id; the agent is known from its node key. */
    public const QUERY_ID_PREFIX = 'c';

    /**
     * Launch a campaign against a set of agents.
     *
     * @param array<int,int> $agent_ids
     * @return int the campaign id
     */
    public static function launch(string $name, string $sql, array $agent_ids, int $users_id, int $entities_id = 0): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $ttl      = max(60, (int) ($settings['campaign_ttl'] ?? 900));
        $accel    = max(10, (int) ($settings['accelerate_seconds'] ?? 60));

        $agent_ids = array_values(array_unique(array_map('intval', $agent_ids)));

        $DB->insert(self::TABLE, [
            'name'          => $name,
            'sql_query'     => $sql,
            'users_id'      => $users_id,
            'entities_id'   => $entities_id,
            'status'        => $agent_ids === [] ? 'complete' : 'running',
            'total_targets' => count($agent_ids),
            'expires_at'    => date('Y-m-d H:i:s', time() + $ttl),
            'date_creation' => date('Y-m-d H:i:s'),
        ]);
        $campaigns_id = $DB->insertId();

        foreach ($agent_ids as $agents_id) {
            $DB->insert(self::TARGET_TABLE, [
                'plugin_glpiosquery_campaigns_id' => $campaigns_id,
                'plugin_glpiosquery_agents_id'    => $agents_id,
                'state'                           => 'pending',
            ]);
        }

        if ($agent_ids !== []) {
            // Flag the targets and put them on the accelerated cadence. Both
            // are set in one statement so a fleet-wide campaign is a single
            // write regardless of size.
            $DB->update(
                Node::TABLE,
                [
                    'has_pending'      => 1,
                    'accelerate_until' => time() + $accel,
                ],
                ['id' => $agent_ids]
            );
        }

        return $campaigns_id;
    }

    /**
     * Queries owed to an agent, marking them dispatched.
     *
     * @return array<string,string> distributed query id => SQL
     */
    public static function dispatchFor(int $agents_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $now     = date('Y-m-d H:i:s');
        $queries = [];
        $target_ids = [];

        $rows = $DB->request([
            'SELECT'     => ['t.id AS target_id', 'c.id AS campaigns_id', 'c.sql_query'],
            'FROM'       => self::TARGET_TABLE . ' AS t',
            'INNER JOIN' => [
                self::TABLE . ' AS c' => [
                    'ON' => ['t' => 'plugin_glpiosquery_campaigns_id', 'c' => 'id'],
                ],
            ],
            'WHERE'      => [
                't.plugin_glpiosquery_agents_id' => $agents_id,
                't.state'                        => 'pending',
                'c.status'                       => 'running',
                'c.expires_at'                   => ['>', $now],
            ],
        ]);

        foreach ($rows as $row) {
            $queries[self::QUERY_ID_PREFIX . (int) $row['campaigns_id']] = (string) $row['sql_query'];
            $target_ids[] = (int) $row['target_id'];
        }

        if ($target_ids !== []) {
            $DB->update(
                self::TARGET_TABLE,
                ['state' => 'dispatched', 'dispatched_at' => $now],
                ['id' => $target_ids]
            );
        }

        // Nothing left owed to this agent: drop it off the pending path so its
        // heartbeat goes back to the cheap branch.
        self::refreshPendingFlag($agents_id);

        return $queries;
    }

    /**
     * Store the results of one /distributed/write.
     *
     * @param array<string,array<int,array<string,mixed>>> $queries
     * @param array<string,int|string>                     $statuses
     * @param array<string,string>                         $messages
     * @param array<string,array<string,mixed>>            $stats
     */
    public static function ingest(int $agents_id, array $queries, array $statuses, array $messages, array $stats): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $now = date('Y-m-d H:i:s');

        // The union of ids: a query that failed outright appears in statuses
        // without a corresponding rows entry.
        $ids = array_unique(array_merge(array_keys($queries), array_keys($statuses)));

        foreach ($ids as $query_id) {
            $campaigns_id = self::campaignIdFromQueryId((string) $query_id);
            if ($campaigns_id === null) {
                continue;
            }

            $rows   = is_array($queries[$query_id] ?? null) ? $queries[$query_id] : [];
            $status = (int) ($statuses[$query_id] ?? 0);
            $failed = $status !== 0;

            foreach ($rows as $row) {
                if (!is_array($row)) {
                    continue;
                }
                $DB->insert(self::ROW_TABLE, [
                    'plugin_glpiosquery_campaigns_id' => $campaigns_id,
                    'plugin_glpiosquery_agents_id'    => $agents_id,
                    'row_data'                        => (string) json_encode($row),
                ]);
            }

            $DB->update(
                self::TARGET_TABLE,
                [
                    'state'        => $failed ? 'failed' : 'done',
                    'responded_at' => $now,
                    'status_code'  => $status,
                    'message'      => (string) ($messages[$query_id] ?? ''),
                    'wall_time_ms' => isset($stats[$query_id]['wall_time_ms'])
                        ? (int) $stats[$query_id]['wall_time_ms']
                        : null,
                    'row_count'    => count($rows),
                ],
                [
                    'plugin_glpiosquery_campaigns_id' => $campaigns_id,
                    'plugin_glpiosquery_agents_id'    => $agents_id,
                ]
            );

            self::refreshCounts($campaigns_id);
        }

        self::refreshPendingFlag($agents_id);
    }

    /** `c42` → 42; anything else → null, so a stray id can never write to a campaign. */
    public static function campaignIdFromQueryId(string $query_id): ?int
    {
        if (!preg_match('/^' . self::QUERY_ID_PREFIX . '(\d+)$/', $query_id, $m)) {
            return null;
        }

        return (int) $m[1];
    }

    /** Recount responses and close the campaign once every target has answered. */
    public static function refreshCounts(int $campaigns_id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $done = 0;
        $failed = 0;
        $pending = 0;

        $rows = $DB->request([
            'SELECT'  => ['state', new \QueryExpression('COUNT(*) AS ' . $DB->quoteName('cpt'))],
            'FROM'    => self::TARGET_TABLE,
            'WHERE'   => ['plugin_glpiosquery_campaigns_id' => $campaigns_id],
            'GROUPBY' => ['state'],
        ]);

        foreach ($rows as $row) {
            switch ($row['state']) {
                case 'done':
                    $done = (int) $row['cpt'];
                    break;
                case 'failed':
                    $failed = (int) $row['cpt'];
                    break;
                default:
                    $pending += (int) $row['cpt'];
            }
        }

        $DB->update(
            self::TABLE,
            ['responded' => $done, 'failed' => $failed],
            ['id' => $campaigns_id]
        );

        // Only a *running* campaign can complete. Guarding on the current
        // status matters because expire() marks its targets expired and then
        // recounts — without this, "pending == 0" would immediately relabel a
        // campaign that timed out as though every machine had answered.
        if ($pending === 0) {
            $DB->update(
                self::TABLE,
                ['status' => 'complete'],
                ['id' => $campaigns_id, 'status' => 'running']
            );
        }
    }

    /**
     * Keep `agents.has_pending` honest.
     *
     * The flag is a cache of "this agent has work waiting" that exists purely
     * so the heartbeat can skip the join. It is recomputed whenever that could
     * have changed, because a stale 1 costs a needless query per check-in and a
     * stale 0 would strand a campaign indefinitely.
     */
    public static function refreshPendingFlag(int $agents_id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $has = 0;
        $rows = $DB->request([
            'COUNT'      => 'cpt',
            'FROM'       => self::TARGET_TABLE . ' AS t',
            'INNER JOIN' => [
                self::TABLE . ' AS c' => [
                    'ON' => ['t' => 'plugin_glpiosquery_campaigns_id', 'c' => 'id'],
                ],
            ],
            'WHERE'      => [
                't.plugin_glpiosquery_agents_id' => $agents_id,
                't.state'                        => 'pending',
                'c.status'                       => 'running',
                'c.expires_at'                   => ['>', date('Y-m-d H:i:s')],
            ],
        ]);

        foreach ($rows as $row) {
            $has = (int) $row['cpt'] > 0 ? 1 : 0;
        }

        $DB->update(Node::TABLE, ['has_pending' => $has], ['id' => $agents_id]);
    }

    /**
     * Delete finished campaigns past the retention window.
     *
     * Result rows are the only table here that grows without bound: one row per
     * result per agent per campaign, and an operator investigating an incident
     * will run dozens of fleet-wide queries in an afternoon. Left alone this
     * becomes the largest table in the database and nobody notices until it is.
     *
     * @return int campaigns removed
     */
    public static function purgeOld(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $days     = max(1, (int) ($settings['campaign_retention_days'] ?? 30));
        $cutoff   = date('Y-m-d H:i:s', time() - ($days * 86400));

        $ids = [];
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::TABLE,
                'WHERE'  => [
                    'date_creation' => ['<', $cutoff],
                    'status'        => ['complete', 'expired'],
                ],
                'LIMIT'  => 500,
            ]) as $row
        ) {
            $ids[] = (int) $row['id'];
        }

        if ($ids === []) {
            return 0;
        }

        $DB->delete(self::ROW_TABLE, ['plugin_glpiosquery_campaigns_id' => $ids]);
        $DB->delete(self::TARGET_TABLE, ['plugin_glpiosquery_campaigns_id' => $ids]);
        $DB->delete(self::TABLE, ['id' => $ids]);

        return count($ids);
    }

    /**
     * Remove data belonging to agents that no longer exist.
     *
     * Snapshots are bounded by agents × queries so they do not grow on their
     * own, but a deleted agent leaves its whole collection behind.
     *
     * @return int rows removed
     */
    public static function purgeOrphans(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $known = [];
        foreach ($DB->request(['SELECT' => ['id'], 'FROM' => Node::TABLE]) as $row) {
            $known[] = (int) $row['id'];
        }

        if ($known === []) {
            return 0;
        }

        $removed = 0;
        foreach (
            [
                ResultIngest::SNAPSHOT_TABLE,
                ResultIngest::STATUS_TABLE,
                self::ROW_TABLE,
                self::TARGET_TABLE,
            ] as $table
        ) {
            $DB->delete($table, ['NOT' => ['plugin_glpiosquery_agents_id' => $known]]);
            $removed += $DB->affectedRows();
        }

        return $removed;
    }

    /**
     * Close out campaigns past their TTL. Called from cron.
     *
     * Targets that never answered are recorded as `expired` rather than deleted
     * — "24 machines never responded" is a finding in its own right.
     */
    public static function expire(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $now = date('Y-m-d H:i:s');
        $ids = [];

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::TABLE,
                'WHERE'  => ['status' => 'running', 'expires_at' => ['<=', $now]],
            ]) as $row
        ) {
            $ids[] = (int) $row['id'];
        }

        if ($ids === []) {
            return 0;
        }

        $DB->update(
            self::TARGET_TABLE,
            ['state' => 'expired'],
            [
                'plugin_glpiosquery_campaigns_id' => $ids,
                'state'                           => ['pending', 'dispatched'],
            ]
        );
        $DB->update(self::TABLE, ['status' => 'expired'], ['id' => $ids]);

        foreach ($ids as $id) {
            self::refreshCounts($id);
        }

        return count($ids);
    }
}
