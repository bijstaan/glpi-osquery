<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Session;

/**
 * Resolves "who should answer this query" into a concrete list of agents.
 *
 * Targeting always runs through the caller's entity scope. An operator can
 * only ever reach agents in entities they are active in, regardless of what
 * the request asks for — the filters narrow that set, they never widen it.
 */
final class Targeting
{
    /**
     * @param array $filters {
     *   entities:  int[]   entity ids (empty = every entity in scope)
     *   groups:    int[]   GLPI group ids, matched against the linked asset
     *   platforms: string[] osquery platform families: linux|darwin|windows
     *   agents:    int[]   explicit plugin agent ids
     *   items:     array   [['itemtype' => 'Computer', 'items_id' => 11]]
     *   online_only: bool  skip agents that have not checked in recently
     * }
     * @return array<int,array<string,mixed>> matched agent rows
     */
    public static function resolve(array $filters): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $where = [
            'a.is_deleted' => 0,
            'a.is_active'  => 1,
        ];

        // Entity scope is not optional and not a filter the caller can remove.
        $scope = self::entityScope($filters['entities'] ?? []);
        if ($scope === []) {
            return [];
        }
        $where['a.entities_id'] = $scope;

        if (!empty($filters['agents'])) {
            $where['a.id'] = array_map('intval', $filters['agents']);
        }

        if (!empty($filters['platforms'])) {
            $families = array_map(
                static fn($p) => QueryCatalog::normalisePlatform((string) $p),
                $filters['platforms']
            );
            // Stored platforms are distributions (ubuntu, debian…), so match on
            // the family rather than the literal value.
            $or = [];
            foreach (array_unique($families) as $family) {
                if ($family === 'darwin' || $family === 'windows') {
                    $or[] = ['a.platform' => $family];
                } else {
                    $or[] = ['NOT' => ['a.platform' => ['darwin', 'windows']]];
                }
            }
            $where[] = ['OR' => $or];
        }

        if (!empty($filters['items'])) {
            $or = [];
            foreach ($filters['items'] as $item) {
                $or[] = [
                    'a.itemtype' => (string) ($item['itemtype'] ?? 'Computer'),
                    'a.items_id' => (int) ($item['items_id'] ?? 0),
                ];
            }
            $where[] = ['OR' => $or];
        }

        if (!empty($filters['online_only'])) {
            $settings = \Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
            $cutoff   = date('Y-m-d H:i:s', time() - (int) ($settings['offline_after'] ?? 900));
            $where['a.last_seen'] = ['>', $cutoff];
        }

        $criteria = [
            'SELECT' => [
                'a.id', 'a.name', 'a.platform', 'a.last_seen', 'a.entities_id',
                'a.itemtype', 'a.items_id', 'a.os_name', 'a.os_version',
            ],
            'FROM'   => Node::TABLE . ' AS a',
            'WHERE'  => $where,
            'ORDER'  => ['a.name'],
        ];

        // Groups live on the inventoried asset, not on the agent, so this only
        // joins when a group filter is actually asked for.
        if (!empty($filters['groups'])) {
            $criteria['LEFT JOIN'] = [
                'glpi_computers AS c' => [
                    'ON' => [
                        'a' => 'items_id',
                        'c' => 'id',
                        ['AND' => ['a.itemtype' => 'Computer']],
                    ],
                ],
            ];
            $criteria['WHERE']['c.groups_id'] = array_map('intval', $filters['groups']);
        }

        $out = [];
        foreach ($DB->request($criteria) as $row) {
            $out[] = $row;
        }

        return $out;
    }

    /**
     * The entity ids a campaign may reach.
     *
     * Requested entities are intersected with the session's active entities;
     * an empty request means "everything I can see", never "everything".
     *
     * @param array<int,int> $requested
     * @return array<int,int>
     */
    public static function entityScope(array $requested): array
    {
        $active = $_SESSION['glpiactiveentities'] ?? [];
        $active = array_map('intval', is_array($active) ? $active : [$active]);

        if ($requested === []) {
            return $active;
        }

        $requested = array_map('intval', $requested);

        return array_values(array_intersect($requested, $active));
    }

    /** Can the current user run live queries at all? */
    public static function canRun(): bool
    {
        return (bool) Session::haveRight('plugin_glpiosquery_livequery', UPDATE);
    }

    /** May the current user send SQL they wrote themselves, rather than a saved query? */
    public static function canRunRawSql(): bool
    {
        return (bool) Session::haveRight('plugin_glpiosquery_rawsql', UPDATE);
    }

    /**
     * Is a right granted in the database but missing from this session?
     *
     * GLPI copies a profile's rights into the session at login, so anyone who
     * was already signed in when the plugin was installed — or when an
     * administrator granted the right — keeps the old set until they sign in
     * again. The symptom is a flat 403 on an action the UI appears to offer,
     * with correct-looking permissions in the admin screens, which is a
     * genuinely difficult thing to work out from the outside.
     *
     * Detecting it costs one indexed query and turns that into an instruction.
     */
    public static function isStaleSessionFor(string $right): bool
    {
        if (Session::haveRight($right, UPDATE)) {
            return false;
        }

        return self::rightGrantedInDatabase($right);
    }

    public static function rightGrantedInDatabase(string $right, int $value = UPDATE): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $profiles_id = (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0);
        if ($profiles_id === 0) {
            return false;
        }

        foreach (
            $DB->request([
                'SELECT' => ['rights'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => ['profiles_id' => $profiles_id, 'name' => $right],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return ((int) $row['rights'] & $value) === $value;
        }

        return false;
    }

    /**
     * The message to show when a right is missing, naming the stale-session
     * case explicitly when that is what has happened.
     */
    public static function deniedReason(string $right, string $default): string
    {
        if (self::isStaleSessionFor($right)) {
            return __(
                'Your session was opened before this permission was granted, so it does not have it yet. '
                . 'Sign out and back in.',
                'glpiosquery'
            );
        }

        return $default;
    }
}
