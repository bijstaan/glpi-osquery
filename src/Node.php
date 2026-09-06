<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;
use GLPIKey;

/**
 * An enrolled osqueryd node.
 *
 * Deliberately not a CommonDBTM: everything here runs on the hot path of the
 * TLS endpoints (the whole fleet hits byNodeKey() every distributed_interval),
 * so it stays as plain indexed queries. The GLPI-object layer for the UI sits
 * on top of this, not underneath it.
 */
final class Node
{
    public const TABLE = 'glpi_plugin_glpiosquery_agents';

    /**
     * Node keys are bearer credentials, so only the hash is stored — the same
     * reasoning as a password. A leaked database should not hand over the
     * fleet's identities.
     */
    public static function hashKey(string $node_key): string
    {
        return hash('sha256', $node_key);
    }

    /** One agent row by primary key, or null. */
    public static function byId(int $id): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach ($DB->request(['FROM' => self::TABLE, 'WHERE' => ['id' => $id], 'LIMIT' => 1]) as $row) {
            return $row;
        }

        return null;
    }

    public static function byNodeKey(string $node_key): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $rows = $DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => [
                'node_key_hash' => self::hashKey($node_key),
                'is_active'     => 1,
                'is_deleted'    => 0,
            ],
            'LIMIT' => 1,
        ]);

        foreach ($rows as $row) {
            return $row;
        }

        return null;
    }

    /**
     * Handle an /enroll request.
     *
     * Returns the freshly minted node key, or null if the secret is not valid.
     * Re-enrolment of a machine we already know (same deviceid) rotates the key
     * on the existing row rather than creating a second agent — osquery
     * re-enrols on database loss, reinstall, or an explicit node_invalid, and
     * none of those are a new computer.
     */
    public static function enroll(array $payload): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $secret = (string) ($payload['enroll_secret'] ?? '');
        $enroll = EnrollSecret::match($secret);
        if ($enroll === null) {
            return null;
        }

        $details    = $payload['host_details'] ?? [];
        $system     = $details['system_info']  ?? [];
        $os         = $details['os_version']   ?? [];
        $osq        = $details['osquery_info'] ?? [];
        $identifier = (string) ($payload['host_identifier'] ?? ($system['hostname'] ?? 'unknown'));

        $deviceid  = self::deviceId($identifier, (string) ($system['uuid'] ?? ''));
        $node_key  = bin2hex(random_bytes(24));
        $now       = date('Y-m-d H:i:s');

        $fields = [
            'name'            => $identifier,
            'node_key_hash'   => self::hashKey($node_key),
            'host_identifier' => $identifier,
            'hardware_uuid'   => (string) ($system['uuid'] ?? ''),
            'hardware_serial' => (string) ($system['hardware_serial'] ?? ''),
            'platform'        => (string) ($os['platform'] ?? ''),
            'platform_like'   => (string) ($os['platform_like'] ?? ''),
            'os_name'         => (string) ($os['name'] ?? ''),
            'os_version'      => (string) ($os['version'] ?? ''),
            'osquery_version' => (string) ($osq['version'] ?? ''),
            'instance_id'     => (string) ($osq['instance_id'] ?? ''),
            'last_seen'       => $now,
            'is_active'       => 1,
            'date_mod'        => $now,
        ];

        $existing = self::byDeviceId($deviceid);
        if ($existing !== null) {
            $DB->update(self::TABLE, $fields, ['id' => $existing['id']]);
        } else {
            $DB->insert(self::TABLE, $fields + [
                'deviceid'                            => $deviceid,
                'entities_id'                         => (int) $enroll['entities_id'],
                'plugin_glpiosquery_enrollsecrets_id' => (int) $enroll['id'],
                'enrolled_at'                         => $now,
                'date_creation'                       => $now,
            ]);
        }

        EnrollSecret::countEnrolment((int) $enroll['id']);

        return $node_key;
    }

    /**
     * Enroll the supervisor, issuing it a credential of its own.
     *
     * The supervisor and osqueryd are separate clients that happen to run on
     * the same machine. Giving them one credential would mean the supervisor's
     * enrolment rotating osqueryd's node key — silently cutting off inventory
     * and live queries until osqueryd noticed and re-enrolled. So this creates
     * or updates the agent row and issues an `agent_token`, leaving
     * `node_key_hash` untouched.
     *
     * @return string|null the token, or null if the secret was not accepted
     */
    public static function enrollSupervisor(array $payload): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $enroll = EnrollSecret::match((string) ($payload['enroll_secret'] ?? ''));
        if ($enroll === null) {
            return null;
        }

        $identifier = (string) ($payload['host_identifier'] ?? 'unknown');
        $deviceid   = self::deviceId($identifier, (string) ($payload['hardware_uuid'] ?? ''));
        $token      = bin2hex(random_bytes(24));
        $now        = date('Y-m-d H:i:s');

        $fields = [
            'agent_token_hash' => self::hashKey($token),
            'agent_version'    => mb_substr((string) ($payload['agent_version'] ?? ''), 0, 32),
            'arch'             => mb_substr((string) ($payload['arch'] ?? ''), 0, 16),
            'remote_addr'      => Endpoint::remoteAddress(),
            'last_seen'        => $now,
            'date_mod'         => $now,
        ];

        // The port the agent's own status listener answers on, so GLPI's device
        // page knows where to reach it.
        $port = (int) ($payload['listen_port'] ?? 0);
        if ($port > 0 && $port < 65536) {
            $fields['listen_port'] = $port;
        }

        $existing = self::byDeviceId($deviceid);
        if ($existing !== null) {
            $DB->update(self::TABLE, $fields, ['id' => $existing['id']]);
        } else {
            // The supervisor can start before osqueryd has ever enrolled, so
            // the row may not exist yet. node_key_hash is left blank until
            // osqueryd enrolls for itself.
            $DB->insert(self::TABLE, $fields + [
                'name'                                => $identifier,
                'node_key_hash'                       => '',
                'deviceid'                            => $deviceid,
                'host_identifier'                     => $identifier,
                'hardware_uuid'                       => (string) ($payload['hardware_uuid'] ?? ''),
                'platform'                            => (string) ($payload['platform'] ?? ''),
                'entities_id'                         => (int) $enroll['entities_id'],
                'plugin_glpiosquery_enrollsecrets_id' => (int) $enroll['id'],
                'enrolled_at'                         => $now,
                'date_creation'                       => $now,
            ]);
        }

        EnrollSecret::countEnrolment((int) $enroll['id']);

        return $token;
    }

    public static function byAgentToken(string $token): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($token === '') {
            return null;
        }

        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => [
                    'agent_token_hash' => self::hashKey($token),
                    'is_active'        => 1,
                    'is_deleted'       => 0,
                ],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    public static function byDeviceId(string $deviceid): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach ($DB->request(['FROM' => self::TABLE, 'WHERE' => ['deviceid' => $deviceid], 'LIMIT' => 1]) as $row) {
            return $row;
        }

        return null;
    }

    /**
     * A stable inventory device id.
     *
     * GLPI keys its Agent records on this string, so it must survive reinstalls
     * of the machine's osquery but differ between machines. Hostname alone is
     * neither (it collides and it changes), so it is qualified with a digest of
     * the hardware UUID.
     */
    public static function deviceId(string $identifier, string $hardware_uuid): string
    {
        $clean = preg_replace('/[^A-Za-z0-9._-]/', '-', $identifier) ?: 'host';
        $seed  = $hardware_uuid !== '' ? $hardware_uuid : $identifier;

        return sprintf('osquery-%s-%s', $clean, substr(hash('sha256', $seed), 0, 12));
    }

    /**
     * Build the config document served to an agent.
     *
     * Only queries whose platform matches are included, and the platform is
     * repeated in each schedule entry so osquery filters them again on its own
     * side. `options` here override the agent's command-line flags — verified
     * behaviour, and the reason a fleet can be retuned centrally without
     * touching a single endpoint.
     */
    public static function configFor(array $agent): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $platform = (string) ($agent['platform'] ?? '');
        $schedule = [];
        $provides = Extension::tablesOn((int) ($agent['id'] ?? 0));

        $rows = $DB->request([
            'SELECT' => [
                'q.name AS qname', 'q.sql_query', 'q.query_interval', 'q.is_snapshot', 'q.platform',
                'q.min_agent_version', 'q.requires_table',
            ],
            'FROM'   => 'glpi_plugin_glpiosquery_queries AS q',
            'INNER JOIN' => [
                'glpi_plugin_glpiosquery_packs AS p' => [
                    'ON' => [
                        'q' => 'plugin_glpiosquery_packs_id',
                        'p' => 'id',
                    ],
                ],
            ],
            'WHERE'  => ['q.is_active' => 1, 'p.is_active' => 1],
        ]);

        foreach ($rows as $row) {
            if (!self::platformMatches((string) $row['platform'], $platform)) {
                continue;
            }

            // Withhold queries the agent's bundle cannot answer. A query
            // selecting from an extension table reaches an older agent as
            // "no such table" once per interval, forever — indistinguishable
            // from a genuine fault, and multiplied by the whole fleet for the
            // length of a rollout.
            if (!self::versionAtLeast($agent, (string) ($row['min_agent_version'] ?? ''))) {
                continue;
            }

            // The same withholding, decided by capability rather than by
            // version. A version floor could only ever speak for the extension
            // this project bundles; an extension an administrator published
            // says nothing about the agent's version, so the endpoint is asked
            // instead — see Extension::tablesOn(). Until its first discovery
            // result arrives an agent provides nothing, which withholds the
            // query for one config cycle rather than sending it somewhere it
            // would fail.
            $needs = trim((string) ($row['requires_table'] ?? ''));
            if ($needs !== '' && !in_array($needs, $provides, true)) {
                continue;
            }

            $entry = [
                'query'    => $row['sql_query'],
                'interval' => (int) $row['query_interval'],
                'snapshot' => (bool) $row['is_snapshot'],
            ];
            if ($row['platform'] !== 'all' && $row['platform'] !== '') {
                $entry['platform'] = $row['platform'];
            }

            $schedule[$row['qname']] = $entry;
        }

        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);

        return [
            'schedule' => $schedule,
            // Only flags osquery actually honours from a config are sent.
            //
            // Anything osquery classes as CLI-only (config_refresh,
            // logger_plugin, distributed_plugin, disable_distributed) is
            // ignored when it arrives this way, and osqueryd warns about each
            // one on every config fetch. Worse, sending them implies to an
            // administrator that changing the value here retunes the fleet,
            // when in fact only the agent's flagfile decides it.
            'options'  => [
                'distributed_interval'   => (int) ($settings['distributed_interval'] ?? 10),
                'logger_tls_period'      => (int) ($settings['logger_tls_period'] ?? 10),
                'schedule_splay_percent' => 10,
            ],
            'node_invalid' => false,
        ];
    }

    /**
     * @param string $want  the query's platform spec: 'all' or a comma list
     * @param string $have  the agent's osquery platform value
     */
    /**
     * Whether an agent is new enough to be given a query.
     *
     * An agent that has never reported a version is treated as too old: it is
     * running a bundle that predates version reporting, which is precisely the
     * kind that will not have a recent extension either.
     */
    public static function versionAtLeast(array $agent, string $minimum): bool
    {
        $minimum = ltrim(trim($minimum), 'v');
        if ($minimum === '') {
            return true; // no floor set
        }

        $running = ltrim(trim((string) ($agent['agent_version'] ?? '')), 'v');
        if ($running === '') {
            return false;
        }

        return version_compare($running, $minimum, '>=');
    }

    public static function platformMatches(string $want, string $have): bool
    {
        $want = trim($want);
        if ($want === '' || $want === 'all') {
            return true;
        }
        if ($have === '') {
            // Platform unknown (pre-enrolment detail missing): serve it and let
            // osquery's own platform filter decide, rather than silently
            // collecting nothing.
            return true;
        }

        foreach (explode(',', $want) as $candidate) {
            $candidate = trim($candidate);
            if ($candidate === $have) {
                return true;
            }
            // osquery reports specific distributions (ubuntu, rhel, …) whose
            // platform_like is the family the query was written against.
            if ($candidate === 'linux' && in_array($have, ['ubuntu', 'debian', 'rhel', 'centos', 'fedora', 'arch', 'suse', 'amzn'], true)) {
                return true;
            }
        }

        return false;
    }

    /** Update the mutable per-request columns without a full object load. */
    public static function touch(int $id, array $fields): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::TABLE, $fields + ['date_mod' => date('Y-m-d H:i:s')], ['id' => $id]);
    }
}
