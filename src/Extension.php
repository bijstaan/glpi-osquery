<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Session;

/**
 * osquery extensions published by an instance administrator.
 *
 * osquery extensions are standalone executables that register tables over the
 * extension manager's socket — nothing about them has to be compiled into this
 * project's agent. The agent bundles one (`glpi-edid.ext`) because it is
 * versioned with the agent and belongs to it; anything an administrator writes
 * arrives through here instead, and is installed into a directory the agent
 * keeps outside the versioned bundle so a self-update does not erase it.
 *
 * ## Who may do this
 *
 * Publishing an extension hands every targeted endpoint a binary that osqueryd
 * runs as root. That is the largest power this plugin grants — larger than
 * free-form SQL, which is at least confined to osquery's read-only tables — so
 * it takes two things, not one:
 *
 *   - the `plugin_glpiosquery_extension` right, granted to nobody by default;
 *   - a session that can see the whole instance (`Session::canViewAllEntities`).
 *
 * The second is the point. The right on its own is grantable to an
 * entity-scoped profile, and an entity administrator holding it could then
 * push binaries to their own machines. Requiring a session whose active
 * entities cover every entity is GLPI's own expression of "root administrator"
 * and it cannot be satisfied by a delegated profile, whose `glpiactiveentities`
 * is by construction a subset. So scope can be *targeted* per entity, while
 * remaining something only the instance's own administrators decide.
 *
 * On a single-entity installation that check is trivially true, which is
 * correct: there is no delegation there to protect against.
 *
 * ## What an endpoint provides
 *
 * The tables an extension registers are discovered from the fleet rather than
 * declared by whoever published it. osquery can be asked directly — see
 * DefaultPacks' `sys_extension_tables` — which means the console learns an
 * administrator's tables and their columns without anybody uploading a schema,
 * and a query can be gated on the table actually being present rather than on
 * a version number that only ever described our own bundle.
 */
final class Extension
{
    public const TABLE = 'glpi_plugin_glpiosquery_extensions';

    /** The discovery query whose snapshot tells us what an endpoint provides. */
    public const DISCOVERY_QUERY = 'sys_extension_tables';

    public const RIGHT = 'plugin_glpiosquery_extension';

    /**
     * May the current session publish and scope extensions?
     *
     * Both halves are required; see the class docblock for why the right alone
     * is deliberately not enough.
     */
    public static function canManage(): bool
    {
        return (bool) Session::haveRight(self::RIGHT, UPDATE)
            && Session::canViewAllEntities();
    }

    /**
     * A name that is safe as both a database key and a filename on disk.
     *
     * The agent writes the extension to `<name>.ext`, so anything that could
     * escape a directory or collide with the bundled extension is refused here
     * rather than sanitised into something the administrator did not ask for.
     */
    public static function validName(string $name): bool
    {
        return (bool) preg_match('/^[a-z0-9][a-z0-9_-]{1,62}[a-z0-9]$/', $name);
    }

    /**
     * Extensions an agent should be running, in the agent's own terms.
     *
     * Entity matching deliberately does not go through Targeting::resolve().
     * That helper intersects everything with `$_SESSION['glpiactiveentities']`
     * so that a human operator can never widen their own scope — exactly right
     * for a console request, and exactly wrong here, where the caller is an
     * agent on an unauthenticated endpoint with no session at all. Borrowing it
     * would resolve every scope to the empty set and fail silently.
     *
     * @return array<int,array<string,mixed>> extension rows, scoped to the agent
     */
    public static function scopedTo(array $agent): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $entity = (int) ($agent['entities_id'] ?? 0);

        $out = [];
        foreach (
            $DB->request([
                'FROM'  => self::TABLE,
                'WHERE' => ['is_active' => 1],
                'ORDER' => ['name'],
            ]) as $row
        ) {
            if (self::covers($row, $entity)) {
                $out[] = $row;
            }
        }

        return $out;
    }

    /** Does an extension's entity scope reach this agent's entity? */
    public static function covers(array $extension, int $entity): bool
    {
        $root = (int) ($extension['entities_id'] ?? 0);

        if ($root === $entity) {
            return true;
        }

        if (empty($extension['is_recursive'])) {
            return false;
        }

        return in_array($entity, getSonsOf('glpi_entities', $root), true);
    }

    /**
     * The complete set of extensions an agent should have installed.
     *
     * Returned as a list rather than as an "update available" instruction: the
     * agent has to be able to *remove* an extension that was unscoped or
     * deactivated, and it can only know to do that by being told the whole
     * desired set. An empty list is a meaningful answer, not a no-op.
     *
     * @return array<int,array<string,mixed>>
     */
    public static function manifestFor(array $agent, string $arch): array
    {
        $platform = QueryCatalog::normalisePlatform((string) ($agent['platform'] ?? ''));

        $out = [];
        foreach (self::scopedTo($agent) as $extension) {
            $package = self::activePackage((string) $extension['name'], $platform, $arch);
            if ($package === null) {
                // Published for other platforms but not this one. Not an error:
                // an extension reading /sys has no business on Windows.
                continue;
            }

            $out[] = [
                'name'    => (string) $extension['name'],
                'version' => (string) $package['version'],
                'url'     => (string) $package['url'],
                'sha256'  => (string) $package['sha256'],
                'size'    => (int) $package['size'],
            ];
        }

        return $out;
    }

    /** The newest active binary published for one extension on one platform. */
    public static function activePackage(string $name, string $platform, string $arch): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'FROM'  => AgentUpdate::PACKAGE_TABLE,
                'WHERE' => [
                    'kind'      => AgentUpdate::KIND_EXTENSION,
                    'name'      => $name,
                    'platform'  => $platform,
                    'arch'      => $arch,
                    'is_active' => 1,
                ],
                'ORDER' => ['id DESC'],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }

    /**
     * Create or update an extension's identity and scope.
     *
     * @param array $fields name, label, entities_id, is_recursive, is_active, comment
     * @return string|null an error message, or null on success
     */
    public static function save(array $fields): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $name = strtolower(trim((string) ($fields['name'] ?? '')));

        if (!self::validName($name)) {
            return __('The name must be 3–64 characters of lowercase letters, digits, dash or underscore.', 'glpiosquery');
        }

        // The bundled extension is not ours to let anyone else redefine, and a
        // published binary landing on its filename would be installed over it
        // on the next reconcile.
        if ($name === 'glpi-edid') {
            return __('That name belongs to the extension bundled with the agent.', 'glpiosquery');
        }

        $row = [
            'name'         => $name,
            'label'        => trim((string) ($fields['label'] ?? '')) ?: null,
            'entities_id'  => (int) ($fields['entities_id'] ?? 0),
            'is_recursive' => !empty($fields['is_recursive']) ? 1 : 0,
            'is_active'    => !empty($fields['is_active']) ? 1 : 0,
            'comment'      => trim((string) ($fields['comment'] ?? '')) ?: null,
            'date_mod'     => date('Y-m-d H:i:s'),
        ];

        $existing = self::byName($name);
        if ($existing !== null) {
            $DB->update(self::TABLE, $row, ['id' => (int) $existing['id']]);
            return null;
        }

        $row['date_creation'] = date('Y-m-d H:i:s');
        $DB->insert(self::TABLE, $row);

        return null;
    }

    public static function byName(string $name): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request(['FROM' => self::TABLE, 'WHERE' => ['name' => $name], 'LIMIT' => 1]) as $row
        ) {
            return $row;
        }

        return null;
    }

    /** @return array<int,array<string,mixed>> */
    public static function all(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach ($DB->request(['FROM' => self::TABLE, 'ORDER' => ['name']]) as $row) {
            $out[] = $row;
        }

        return $out;
    }

    // ------------------------------------------------------------- discovery

    /**
     * The extension-provided tables one agent actually has, from its own mouth.
     *
     * This is what a query is gated on. It is deliberately the endpoint's
     * answer rather than anything the server believes it published: an
     * extension can be installed and still fail to register — a table-name
     * collision leaves the losing extension retrying forever — and a query
     * withheld on the strength of a successful *download* would then be sent to
     * a machine that cannot answer it.
     *
     * @return array<int,string> table names
     */
    public static function tablesOn(int $agents_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'SELECT' => ['data'],
                'FROM'   => ResultIngest::SNAPSHOT_TABLE,
                'WHERE'  => [
                    'plugin_glpiosquery_agents_id' => $agents_id,
                    'query_name'                   => self::DISCOVERY_QUERY,
                ],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            $rows = json_decode((string) $row['data'], true);

            return is_array($rows) ? self::tableNames($rows) : [];
        }

        return [];
    }

    /** @param array<int,array<string,mixed>> $rows discovery result rows */
    private static function tableNames(array $rows): array
    {
        $names = [];
        foreach ($rows as $row) {
            $name = trim((string) ($row['table_name'] ?? ''));
            if ($name !== '') {
                $names[$name] = true;
            }
        }

        return array_keys($names);
    }

    /**
     * Fold a discovery result into what the console knows about extension tables.
     *
     * osquery reports an extension by the name it registered itself under,
     * chosen inside somebody else's source, which has no obligation to match
     * the name it was published as here. In practice it usually does bar
     * punctuation, so a fold of case, dashes and underscores matches it — and
     * where it does not, an endpoint running exactly one published extension
     * still gives an unambiguous answer, because everything registered there
     * that the bundled extension does not provide has to belong to it.
     *
     * Anything left over contributes its tables to the console catalogue, which
     * reads the snapshots directly, but is not attributed to an extension.
     * Guessing would put a wrong table list in front of an administrator, which
     * is worse than showing none.
     *
     * @param array<int,array<string,mixed>> $rows discovery result rows
     */
    public static function recordDiscovery(int $agents_id, array $rows): void
    {
        $bundled = [];
        foreach (QueryCatalog::bundledExtensionTables() as $name) {
            $bundled[$name] = true;
        }

        // osquery extension name => the tables it registered here.
        $groups = [];
        foreach ($rows as $row) {
            $table = trim((string) ($row['table_name'] ?? ''));
            $owner = trim((string) ($row['extension'] ?? ''));
            if ($table === '' || $owner === '' || isset($bundled[$table])) {
                continue;
            }
            $groups[$owner][$table] = true;
        }

        if ($groups === []) {
            return;
        }

        $published = [];
        foreach (self::all() as $extension) {
            $published[self::fold((string) $extension['name'])] = (string) $extension['name'];
        }

        $unmatched = [];
        foreach ($groups as $owner => $tables) {
            $name = $published[self::fold($owner)] ?? null;
            if ($name === null) {
                $unmatched[$owner] = $tables;
                continue;
            }

            self::storeTables($name, array_keys($tables));
        }

        // The fallback, and only where it cannot be wrong.
        if (count($unmatched) !== 1) {
            return;
        }

        $agent = Node::byId($agents_id);
        $installed = $agent === null ? [] : self::installedOn($agent);
        if (count($installed) !== 1) {
            return;
        }

        self::storeTables($installed[0], array_keys(reset($unmatched)));
    }

    /** Case and punctuation folded, so `acme-widgets` and `acme_widgets` are one name. */
    private static function fold(string $name): string
    {
        return str_replace(['-', '_'], '', strtolower(trim($name)));
    }

    /** @param array<int,string> $tables */
    private static function storeTables(string $name, array $tables): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        sort($tables);

        $DB->update(
            self::TABLE,
            [
                'provided_tables' => $tables === [] ? null : json_encode($tables),
                'date_mod'        => date('Y-m-d H:i:s'),
            ],
            ['name' => $name]
        );
    }

    /**
     * Which published extensions an agent says it has on disk.
     *
     * Reported by the agent on check-in rather than inferred from what was
     * offered: an offer is not an installation, and the gap between the two is
     * exactly what an administrator watching a rollout needs to see.
     *
     * @return array<int,string> extension names
     */
    public static function installedOn(array $agent): array
    {
        $raw = json_decode((string) ($agent['extensions_json'] ?? ''), true);
        if (!is_array($raw)) {
            return [];
        }

        $out = [];
        foreach ($raw as $entry) {
            $name = trim((string) ($entry['name'] ?? ''));
            if ($name !== '') {
                $out[] = $name;
            }
        }

        sort($out);

        return $out;
    }

    /**
     * Extensions an agent was given but which are not registering any table.
     *
     * The common cause is a table name already claimed by another extension:
     * osquery refuses the duplicate, the losing extension exits, and its
     * watchdog starts it again — forever, with nothing visible in GLPI. A
     * crash-on-start looks identical from here, which is fine, because the
     * administrator's next step is the same either way.
     *
     * @return array<int,string>
     */
    public static function silentOn(array $agent): array
    {
        $installed = self::installedOn($agent);
        if ($installed === []) {
            return [];
        }

        $tables = self::tablesOn((int) $agent['id']);
        if ($tables === []) {
            // Nothing has been discovered yet at all. Absence of a discovery
            // snapshot is not evidence of failure — it is the normal state for
            // the first few minutes after an agent enrols.
            return [];
        }

        $bundled = [];
        foreach (QueryCatalog::bundledExtensionTables() as $name) {
            $bundled[$name] = true;
        }

        foreach ($tables as $name) {
            if (!isset($bundled[$name])) {
                // Something published is registering. Saying *which* would need
                // the attribution this cannot do, so one healthy extension
                // among several suppresses the warning for all of them rather
                // than accusing an arbitrary one.
                return [];
            }
        }

        // Discovery ran, the bundled extension registered, and nothing else
        // did — so every published extension on this endpoint is failing.
        return $installed;
    }

    /**
     * Record what an agent reports having installed.
     *
     * @param array<int,array<string,mixed>> $extensions [{name, version}]
     */
    public static function recordInstalled(int $agents_id, array $extensions): void
    {
        $clean = [];
        foreach ($extensions as $entry) {
            $name = strtolower(trim((string) ($entry['name'] ?? '')));
            if (!self::validName($name) && $name !== 'glpi-edid') {
                continue;
            }
            $clean[] = [
                'name'    => $name,
                'version' => mb_substr(trim((string) ($entry['version'] ?? '')), 0, 32),
            ];
        }

        usort($clean, static fn($a, $b) => strcmp($a['name'], $b['name']));

        Node::touch($agents_id, ['extensions_json' => json_encode($clean)]);
    }

    /**
     * Remove an extension and every binary published for it.
     *
     * Agents uninstall it on their next check-in, because the desired set they
     * are handed simply stops mentioning it.
     */
    public static function delete(int $id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $row = null;
        foreach ($DB->request(['FROM' => self::TABLE, 'WHERE' => ['id' => $id], 'LIMIT' => 1]) as $found) {
            $row = $found;
        }
        if ($row === null) {
            return;
        }

        $DB->delete(AgentUpdate::PACKAGE_TABLE, [
            'kind' => AgentUpdate::KIND_EXTENSION,
            'name' => (string) $row['name'],
        ]);
        $DB->delete(self::TABLE, ['id' => $id]);
    }
}
