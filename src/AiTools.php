<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use DBmysql;
use GlpiPlugin\Glpiai\Tool;
use Session;

/**
 * osquery, offered to glpi-ai's troubleshooting assistant as tools.
 *
 * This is the reason that plugin has a tool registry at all. A model asked why
 * a laptop is slow produces a competent list of general causes, which the
 * technician already knew; the same model able to run `SELECT * FROM processes
 * ORDER BY resident_size DESC LIMIT 10` against that laptop looks at it.
 *
 * Three tools, and they are three because a model that cannot see the schema
 * writes SQL against tables that do not exist on that platform, and a model
 * that cannot list agents guesses at machine names. Neither failure is
 * recoverable from inside a single tool.
 *
 * **Nothing here grants anything a technician did not already have.** The rights
 * are the ones the console uses, including `plugin_glpiosquery_rawsql` — which
 * this plugin grants to nobody by default, precisely because free-form SQL is
 * an open window onto every endpoint in the estate. Somebody who cannot type a
 * query into the console cannot have the assistant type one either, and every
 * call is written to glpi-ai's tool log under the technician's own name.
 *
 * Registered through the `glpiai_tools` hook, so an instance without glpi-ai is
 * entirely unaffected — this file is never loaded.
 */
final class AiTools
{
    /** How long a live query is waited on before reporting what came back. */
    private const WAIT_SECONDS = 25;

    /** Poll interval while waiting. Agents answer on their own schedule. */
    private const POLL_MS = 750;

    /** Rows returned to the model. Enough to reason about, not a data dump. */
    private const MAX_ROWS = 40;

    /** @return Tool[] */
    public static function all(): array
    {
        return [
            self::agents(),
            self::tables(),
            self::live(),
            self::compliance(),
        ];
    }

    // --------------------------------------------------------------- agents

    // ------------------------------------------------------------ compliance

    private static function compliance(): Tool
    {
        return new Tool(
            name: 'osquery_compliance',
            description: 'Whether machines are actually encrypted, firewalled and running '
                . 'antivirus, judged from what the agent last reported rather than from what '
                . 'anybody configured. Give a machine for one verdict, or ask for the fleet. '
                . 'Use it before answering a security questionnaire, when somebody asks '
                . 'whether their laptops are encrypted, and after a loss or theft. Report '
                . '"unknown" as unknown: a check that could not be evaluated is not a pass, '
                . 'and this is the one place where saying so matters.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'agent'        => [
                        'type'        => 'string',
                        'description' => 'Hostname or agent id, from osquery_agents. Omit for '
                            . 'the whole fleet.',
                    ],
                    'failing_only' => [
                        'type'        => 'string',
                        'enum'        => ['yes', 'no'],
                        'description' => 'Only machines failing at least one check. Defaults '
                            . 'to no.',
                    ],
                ],
            ],
            handler: [self::class, 'runCompliance'],
            right: 'plugin_glpiosquery_agent',
            source: 'glpiosquery',
            pinned: false
        );
    }

    /**
     * @param array<string,mixed> $arguments
     * @return array<string,mixed>
     */
    public static function runCompliance(array $arguments = [], mixed $context = null): array
    {
        $wanted  = trim((string) ($arguments['agent'] ?? ''));
        $failing = strtolower((string) ($arguments['failing_only'] ?? 'no')) === 'yes';

        $machines = [];
        $tally    = ['pass' => 0, 'fail' => 0, 'unknown' => 0];

        // `Compliance::fleet()` is already restricted to the caller's entity
        // scope, and evaluating one machine goes through the same rows —
        // which is why the single-agent case filters that list rather than
        // reading the agent table itself. One scope, one answer.
        foreach (Compliance::fleet() as $row) {
            $agent = $row['agent'];

            if ($wanted !== '' && !self::matchesAgent($agent, $wanted)) {
                continue;
            }

            $checks = [];
            $worst  = Compliance::PASS;

            foreach ($row['results'] as $key => $result) {
                $state = (string) $result['state'];
                $tally[$state] = ($tally[$state] ?? 0) + 1;

                if ($state === Compliance::FAIL) {
                    $worst = Compliance::FAIL;
                } elseif ($state === Compliance::UNKNOWN && $worst !== Compliance::FAIL) {
                    $worst = Compliance::UNKNOWN;
                }

                $checks[] = array_filter([
                    'check'  => (string) (Compliance::checks()[$key]['label'] ?? $key),
                    'state'  => $state,
                    'detail' => trim((string) ($result['detail'] ?? '')),
                ], static fn($v): bool => $v !== '');
            }

            if ($checks === []) {
                // No check applies to this platform. Reported as unknown
                // rather than dropped: "there is nothing we can check on
                // Linux" and "Linux passed" are different sentences, and only
                // one of them is true.
                $worst = Compliance::UNKNOWN;
            }

            if ($failing && $worst !== Compliance::FAIL) {
                continue;
            }

            $machines[] = array_filter([
                'machine'  => (string) ($agent['name'] ?? ''),
                'agent_id' => (int) ($agent['id'] ?? 0),
                'platform' => (string) ($agent['platform'] ?? ''),
                'last_seen' => (string) ($agent['last_seen'] ?? '') ?: null,
                'verdict'  => $worst,
                'checks'   => $checks,
            ], static fn($v): bool => $v !== null && $v !== '');
        }

        if ($wanted !== '' && $machines === []) {
            return ['error' => sprintf('No enrolled machine matching "%s" that you can see.', $wanted)];
        }

        return array_filter([
            'machines' => array_slice($machines, 0, self::MAX_ROWS),
            'checks_by_state' => $tally,
            'note'     => $tally['unknown'] > 0
                ? 'Some checks could not be evaluated — the agent has not reported the data '
                    . 'they need. Those are unknown, not compliant, and must be said that way '
                    . 'in any answer that reaches an entity.'
                : ($machines === []
                    ? 'Nothing is failing.'
                    : 'Judged from the last snapshot each agent sent, so a machine that has '
                        . 'been offline for a week is being reported as it was a week ago.'),
        ], static fn($v): bool => $v !== null && $v !== []);
    }

    /** @param array<string,mixed> $agent */
    private static function matchesAgent(array $agent, string $wanted): bool
    {
        if (ctype_digit($wanted) && (int) $agent['id'] === (int) $wanted) {
            return true;
        }

        return stripos((string) ($agent['name'] ?? ''), $wanted) !== false
            || stripos((string) ($agent['hostname'] ?? ''), $wanted) !== false;
    }

    private static function agents(): Tool
    {
        return new Tool(
            name: 'osquery_agents',
            description: 'Find machines that have an osquery agent, by hostname, serial or the '
                . 'GLPI computer they are linked to. Returns the agent id, platform, OS version '
                . 'and when it was last seen. Do this first: osquery_live needs agent ids, and '
                . 'the platform decides which tables exist.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'search' => [
                        'type'        => 'string',
                        'description' => 'Hostname, serial or part of one. Empty lists recently '
                            . 'seen agents.',
                    ],
                    'computers_id' => [
                        'type'        => 'integer',
                        'description' => 'A GLPI computer id, to find the agent on that machine.',
                    ],
                ],
            ],
            handler: [self::class, 'runAgents'],
            right: 'plugin_glpiosquery_agent',
            source: 'glpiosquery'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runAgents(array $arguments): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $search   = trim((string) ($arguments['search'] ?? ''));
        $computer = (int) ($arguments['computers_id'] ?? 0);

        $where = [
            'is_deleted' => 0,
            'is_active'  => 1,
        ] + getEntitiesRestrictCriteria(Agent::getTable(), 'entities_id', '', true);

        if ($computer > 0) {
            $where['itemtype'] = 'Computer';
            $where['items_id'] = $computer;
        } elseif ($search !== '') {
            $where['OR'] = [
                ['name'            => ['LIKE', '%' . $search . '%']],
                ['host_identifier' => ['LIKE', '%' . $search . '%']],
                ['hardware_serial' => ['LIKE', '%' . $search . '%']],
            ];
        }

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => Agent::getTable(),
                'WHERE' => $where,
                'ORDER' => 'last_seen DESC',
                'LIMIT' => 20,
            ]) as $row
        ) {
            $out[] = [
                'agent_id'  => (int) $row['id'],
                'name'      => (string) $row['name'],
                'platform'  => (string) $row['platform'],
                'os'        => trim($row['os_name'] . ' ' . $row['os_version']),
                'last_seen' => (string) $row['last_seen'],
                'computer'  => (string) $row['itemtype'] === 'Computer'
                    ? (int) $row['items_id']
                    : null,
            ];
        }

        return [
            'agents' => $out,
            'note'   => $out === []
                ? 'No agent matched. The machine may not be enrolled.'
                : 'last_seen matters: an agent that has not checked in recently will not answer '
                  . 'a live query.',
        ];
    }

    // --------------------------------------------------------------- schema

    private static function tables(): Tool
    {
        return new Tool(
            name: 'osquery_tables',
            description: 'List the osquery tables available on a platform, or the columns of one '
                . 'table. Use this before writing a query: the tables differ by platform, and a '
                . 'query against a table the machine does not have returns an error rather than '
                . 'an empty result.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'platform' => [
                        'type'        => 'string',
                        'description' => 'windows, darwin or linux. Take it from osquery_agents.',
                    ],
                    'table' => [
                        'type'        => 'string',
                        'description' => 'A table name, to get its columns. Empty lists the tables.',
                    ],
                    'search' => [
                        'type'        => 'string',
                        'description' => 'Narrow the table list, e.g. "disk" or "process".',
                    ],
                ],
                'required'   => ['platform'],
            ],
            handler: [self::class, 'runTables'],
            right: 'plugin_glpiosquery_agent',
            source: 'glpiosquery'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runTables(array $arguments): array
    {
        $platform = QueryCatalog::normalisePlatform((string) ($arguments['platform'] ?? ''));
        $wanted   = trim((string) ($arguments['table'] ?? ''));
        $search   = mb_strtolower(trim((string) ($arguments['search'] ?? '')));

        $catalog = QueryCatalog::forPlatform($platform);

        if ($wanted !== '') {
            foreach ($catalog['tables'] as $table) {
                if ((string) $table['name'] !== $wanted) {
                    continue;
                }

                $columns = [];
                foreach ((array) ($table['columns'] ?? []) as $column) {
                    $columns[] = [
                        'name'        => (string) ($column['name'] ?? ''),
                        'type'        => (string) ($column['type'] ?? ''),
                        'description' => (string) ($column['description'] ?? ''),
                    ];
                }

                return [
                    'table'       => $wanted,
                    'description' => (string) ($table['description'] ?? ''),
                    'columns'     => $columns,
                ];
            }

            return [
                'error' => sprintf('There is no table called %s on %s.', $wanted, $platform),
            ];
        }

        $names = [];
        foreach ($catalog['tables'] as $table) {
            $name = (string) $table['name'];

            if ($search === '' || str_contains(mb_strtolower($name), $search)) {
                $names[] = $name;
            }
        }

        return [
            'platform' => $platform,
            'tables'   => array_slice($names, 0, 200),
            'total'    => count($names),
        ];
    }

    // ----------------------------------------------------------- live query

    private static function live(): Tool
    {
        return new Tool(
            name: 'osquery_live',
            description: 'Run a read-only osquery SQL query on one or more enrolled machines and '
                . 'return the rows. This is how to find out what a machine is doing right now: '
                . 'disk space and free space, memory and what is using it, running processes and '
                . 'services, installed software and patches, logged-in users, startup items, '
                . 'network connections, certificates, scheduled tasks. It reaches real endpoints '
                . 'belonging to an entity, so ask when it will answer the question rather than '
                . 'to see what turns up. Only SELECT is accepted. Machines that are asleep or '
                . 'off the network will not answer, and the result says how many did not.',
            schema: [
                'type'       => 'object',
                'properties' => [
                    'sql' => [
                        'type'        => 'string',
                        'description' => 'One SELECT statement, e.g. '
                            . 'SELECT path, resident_size FROM processes ORDER BY resident_size '
                            . 'DESC LIMIT 10',
                    ],
                    'agent_ids' => [
                        'type'        => 'string',
                        'description' => 'Comma-separated agent ids from osquery_agents.',
                    ],
                ],
                'required'   => ['sql', 'agent_ids'],
            ],
            handler: [self::class, 'runLive'],
            // The console's own gate. Free-form SQL is granted to nobody by
            // default in this plugin, so this tool grants exactly nothing that
            // the technician could not already do by typing it themselves.
            right: 'plugin_glpiosquery_rawsql',
            right_level: UPDATE,
            source: 'glpiosquery'
        );
    }

    /** @param array<string,mixed> $arguments */
    public static function runLive(array $arguments): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $sql = trim((string) ($arguments['sql'] ?? ''));

        // The same validator the console uses. Returned as a result rather than
        // thrown, because a rejected query is something the model can fix on
        // the next turn if it is told why.
        $rejection = QueryCatalog::reject($sql);
        if ($rejection !== null) {
            return ['error' => $rejection];
        }

        $ids = [];
        foreach (explode(',', (string) ($arguments['agent_ids'] ?? '')) as $id) {
            $id = (int) trim($id);
            if ($id > 0) {
                $ids[] = $id;
            }
        }

        if ($ids === []) {
            return ['error' => 'Name at least one agent id. Use osquery_agents to find them.'];
        }

        // Entity scoping in SQL, not in a filter afterwards: an agent belonging
        // to another entity must not be reachable by guessing its id, and the
        // cheapest place to enforce that is where the ids are resolved.
        $permitted = [];
        foreach (
            $DB->request([
                'SELECT' => ['id', 'entities_id'],
                'FROM'   => Agent::getTable(),
                'WHERE'  => ['id' => $ids, 'is_deleted' => 0]
                    + getEntitiesRestrictCriteria(Agent::getTable(), 'entities_id', '', true),
            ]) as $row
        ) {
            $permitted[(int) $row['id']] = (int) $row['entities_id'];
        }

        if ($permitted === []) {
            return ['error' => 'None of those agents exist in an entity you can see.'];
        }

        $campaigns_id = Campaign::launch(
            'Assistant: ' . mb_substr($sql, 0, 60),
            $sql,
            array_keys($permitted),
            (int) Session::getLoginUserID(),
            (int) reset($permitted)
        );

        if ($campaigns_id <= 0) {
            return ['error' => 'The query could not be dispatched.'];
        }

        return self::collect($campaigns_id, count($permitted));
    }

    /**
     * Wait for replies, then report what came back and what did not.
     *
     * Bounded, and the bound is reported. A campaign is asynchronous — agents
     * poll on their own schedule — so the honest answer to "what did the fleet
     * say" is almost never "all of it". Returning the rows that arrived as
     * though they were the whole picture is the failure this is written to
     * avoid: a model told "no machine has the file" when three never answered
     * will say the file is gone.
     *
     * @return array<string,mixed>
     */
    private static function collect(int $campaigns_id, int $targeted): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $deadline = microtime(true) + self::WAIT_SECONDS;

        do {
            $responded = 0;
            $failed    = 0;

            foreach (
                $DB->request([
                    'SELECT' => ['state', 'COUNT' => 'id AS n'],
                    'FROM'   => Campaign::TARGET_TABLE,
                    'WHERE'  => ['plugin_glpiosquery_campaigns_id' => $campaigns_id],
                    'GROUPBY' => ['state'],
                ]) as $row
            ) {
                if ((string) $row['state'] === 'done') {
                    $responded = (int) $row['n'];
                } elseif ((string) $row['state'] === 'failed') {
                    $failed = (int) $row['n'];
                }
            }

            if ($responded + $failed >= $targeted) {
                break;
            }

            usleep(self::POLL_MS * 1000);
        } while (microtime(true) < $deadline);

        $rows = [];
        foreach (
            $DB->request([
                'FROM'  => Campaign::ROW_TABLE,
                'WHERE' => ['plugin_glpiosquery_campaigns_id' => $campaigns_id],
                'LIMIT' => self::MAX_ROWS + 1,
            ]) as $row
        ) {
            $decoded = json_decode((string) $row['row_data'], true);
            $rows[]  = ['agent_id' => (int) $row['plugin_glpiosquery_agents_id']]
                + (is_array($decoded) ? $decoded : ['raw' => (string) $row['row_data']]);
        }

        $truncated = count($rows) > self::MAX_ROWS;
        if ($truncated) {
            $rows = array_slice($rows, 0, self::MAX_ROWS);
        }

        $silent = $targeted - $responded - $failed;

        return [
            'rows'       => $rows,
            'targeted'   => $targeted,
            'answered'   => $responded,
            'failed'     => $failed,
            'no_reply'   => $silent,
            'truncated'  => $truncated,
            'note'       => $silent > 0
                ? sprintf(
                    '%d machine(s) did not answer within %d seconds. They may be asleep or off '
                    . 'the network — do not read their silence as an empty result.',
                    $silent,
                    self::WAIT_SECONDS
                )
                : ($rows === [] ? 'Every machine answered, and none returned any rows.' : ''),
        ];
    }
}
