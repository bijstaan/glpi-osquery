<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

/**
 * The osquery schema catalog, and the safety check applied to operator SQL.
 *
 * The catalog is generated from osquery's own table specs by
 * tools/build-schema.py and shipped as data/osquery-schema.json — 280 tables
 * with their columns, types, per-platform availability and upstream
 * descriptions. It backs the console's autocomplete and hover documentation.
 */
final class QueryCatalog
{
    private static ?array $catalog = null;

    public static function load(): array
    {
        if (self::$catalog !== null) {
            return self::$catalog;
        }

        $path = dirname(__DIR__) . '/data/osquery-schema.json';
        $raw  = is_readable($path) ? file_get_contents($path) : false;
        $data = $raw !== false ? json_decode($raw, true) : null;

        $catalog = is_array($data) ? $data : ['osquery_version' => '', 'tables' => []];

        // Tables our own extensions add are not in osquery's specs, so without
        // this they would be missing from the console's completion and schema
        // browser — an operator would have no way to discover that glpi_edid
        // exists, or what its columns are.
        $extras = dirname(__DIR__) . '/data/extension-schema.json';
        $raw    = is_readable($extras) ? file_get_contents($extras) : false;
        $data   = $raw !== false ? json_decode($raw, true) : null;

        if (is_array($data) && !empty($data['tables'])) {
            $known = [];
            foreach ($catalog['tables'] as $table) {
                $known[$table['name']] = true;
            }

            foreach ($data['tables'] as $table) {
                if (!isset($known[$table['name']])) {
                    $catalog['tables'][] = $table;
                }
            }

            usort(
                $catalog['tables'],
                static fn(array $a, array $b) => strcmp((string) $a['name'], (string) $b['name'])
            );
        }

        self::$catalog = $catalog;

        return self::$catalog;
    }

    /**
     * Table names contributed by the extension this project bundles.
     *
     * Used to tell "an endpoint is running our extension" apart from "an
     * endpoint is running one an administrator published", which is the only
     * way to notice that a published extension registered nothing.
     *
     * @return array<int,string>
     */
    public static function bundledExtensionTables(): array
    {
        $path = dirname(__DIR__) . '/data/extension-schema.json';
        $raw  = is_readable($path) ? file_get_contents($path) : false;
        $data = $raw !== false ? json_decode($raw, true) : null;

        $out = [];
        foreach ($data['tables'] ?? [] as $table) {
            $name = trim((string) ($table['name'] ?? ''));
            if ($name !== '') {
                $out[] = $name;
            }
        }

        return $out;
    }

    /**
     * The catalog plus whatever the fleet reports its extensions provide.
     *
     * Kept out of load(), which stays a pure read of two shipped files. The
     * tables an administrator's extension registers are not knowable from any
     * file here — they are discovered from endpoints — so this is the one entry
     * point that touches the database, and only the console calls it.
     *
     * Columns come from osquery's own `pragma_table_info`, so the console
     * offers a published extension's tables with the same fidelity as osquery's
     * built-ins. Descriptions do not exist: osquery has nowhere to put one, and
     * inventing a placeholder would put text in the schema browser that nobody
     * wrote.
     */
    public static function withDiscovered(?string $platform = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $catalog = self::forPlatform($platform);

        $known = [];
        foreach ($catalog['tables'] as $table) {
            $known[(string) $table['name']] = true;
        }

        $discovered = [];
        foreach (
            $DB->request([
                'SELECT' => ['s.data', 'a.platform'],
                'FROM'   => ResultIngest::SNAPSHOT_TABLE . ' AS s',
                'INNER JOIN' => [
                    Node::TABLE . ' AS a' => ['ON' => ['s' => 'plugin_glpiosquery_agents_id', 'a' => 'id']],
                ],
                'WHERE'  => ['s.query_name' => Extension::DISCOVERY_QUERY, 'a.is_deleted' => 0],
            ]) as $row
        ) {
            $family = self::normalisePlatform((string) ($row['platform'] ?? ''));
            if ($platform !== null && $platform !== '' && self::normalisePlatform($platform) !== $family) {
                continue;
            }

            foreach (json_decode((string) $row['data'], true) ?: [] as $entry) {
                $table  = trim((string) ($entry['table_name'] ?? ''));
                $column = trim((string) ($entry['column_name'] ?? ''));
                if ($table === '' || $column === '' || isset($known[$table])) {
                    continue;
                }

                $discovered[$table]['name'] = $table;
                $discovered[$table]['platforms'][$family] = true;
                $discovered[$table]['columns'][$column] = (string) ($entry['column_type'] ?? 'TEXT');
            }
        }

        foreach ($discovered as $table) {
            $columns = [];
            foreach ($table['columns'] as $name => $type) {
                $columns[] = ['name' => $name, 'type' => $type, 'description' => ''];
            }

            $catalog['tables'][] = [
                'name'        => $table['name'],
                'description' => __('Provided by a published osquery extension.', 'glpiosquery'),
                'platforms'   => array_keys($table['platforms']),
                'evented'     => false,
                'extension'   => true,
                'columns'     => $columns,
            ];
        }

        usort(
            $catalog['tables'],
            static fn(array $a, array $b) => strcmp((string) $a['name'], (string) $b['name'])
        );

        return $catalog;
    }

    /**
     * The catalog, optionally narrowed to one platform.
     *
     * Narrowing matters for the per-computer console: offering a Linux box
     * completions for `registry` or `bitlocker_info` teaches the operator
     * something false about the machine in front of them.
     */
    public static function forPlatform(?string $platform = null): array
    {
        $catalog = self::load();
        if ($platform === null || $platform === '') {
            return $catalog;
        }

        $platform = self::normalisePlatform($platform);
        $tables   = array_values(array_filter(
            $catalog['tables'],
            static fn(array $t) => in_array($platform, $t['platforms'] ?? [], true)
        ));

        return ['osquery_version' => $catalog['osquery_version'], 'tables' => $tables];
    }

    /** osquery reports distributions; the catalog is keyed by kernel family. */
    public static function normalisePlatform(string $platform): string
    {
        return match (true) {
            $platform === 'darwin'  => 'darwin',
            $platform === 'windows' => 'windows',
            $platform === ''        => '',
            default                 => 'linux',
        };
    }

    /**
     * Reject anything that is not a single read-only SELECT.
     *
     * osquery's virtual tables are read-only, so this is not the last line of
     * defence against damage — it is there to stop an operator accidentally
     * shipping a statement that does something surprising on thousands of
     * machines, and to keep one campaign to one question. Rejecting is cheap;
     * explaining a fleet-wide mistake is not.
     *
     * @return string|null null when acceptable, otherwise the reason
     */
    public static function reject(string $sql): ?string
    {
        $trimmed = trim($sql);
        if ($trimmed === '') {
            return __('The query is empty.', 'glpiosquery');
        }

        // Strip comments and string literals before looking for keywords, so a
        // value like 'update the thing' cannot trip the check.
        $stripped = preg_replace('/--[^\n]*/', ' ', $trimmed) ?? $trimmed;
        $stripped = preg_replace('#/\*.*?\*/#s', ' ', $stripped) ?? $stripped;
        $stripped = preg_replace("/'(?:[^'\\\\]|\\\\.)*'/", "''", $stripped) ?? $stripped;
        $stripped = preg_replace('/"(?:[^"\\\\]|\\\\.)*"/', '""', $stripped) ?? $stripped;

        $normalised = strtolower(trim($stripped));

        if (!str_starts_with($normalised, 'select') && !str_starts_with($normalised, 'with')) {
            return __('Only SELECT queries can be sent to agents.', 'glpiosquery');
        }

        foreach (
            [
                'attach', 'detach', 'insert', 'update', 'delete', 'drop', 'create',
                'alter', 'replace', 'vacuum', 'reindex', 'pragma',
            ] as $keyword
        ) {
            if (preg_match('/\b' . $keyword . '\b/', $normalised) === 1) {
                return sprintf(__('The %s statement is not allowed in a live query.', 'glpiosquery'), strtoupper($keyword));
            }
        }

        // One statement per campaign: a trailing semicolon is fine, an
        // embedded one means two questions and only one result set.
        if (str_contains(rtrim($normalised, "; \t\n\r"), ';')) {
            return __('Send one statement at a time.', 'glpiosquery');
        }

        return null;
    }

    /**
     * Tables referenced by a query that are evented.
     *
     * Worth surfacing in the UI: an evented table only holds what osqueryd
     * observed while it was running, so live-querying `process_events` on a
     * machine that just restarted returns an empty set that looks like a
     * clean bill of health but is not.
     *
     * @return array<int,string>
     */
    public static function eventedTablesIn(string $sql): array
    {
        $found = [];
        foreach (self::load()['tables'] as $table) {
            if (empty($table['evented'])) {
                continue;
            }
            if (preg_match('/\b' . preg_quote($table['name'], '/') . '\b/i', $sql) === 1) {
                $found[] = $table['name'];
            }
        }

        return $found;
    }
}
