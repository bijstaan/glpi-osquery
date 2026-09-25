<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;

/**
 * Agent self-update.
 *
 * The server is the authority on what version the fleet should run; agents ask
 * and are told. Two things make that safe to do to thousands of machines you
 * cannot physically reach:
 *
 * **Staged rollout.** Each agent belongs to a stable ring derived from its own
 * device id, so raising the rollout percentage always reaches the same machines
 * first and in the same order. A bad build is discovered on 5% of the estate
 * rather than all of it, and an agent never oscillates between "update" and
 * "don't" as the percentage moves.
 *
 * **Verified payloads.** The manifest carries a SHA-256 for every package. The
 * agent must verify before installing — a self-updater that trusts whatever it
 * downloads is a remote code execution channel into every endpoint you own,
 * and the fact that it speaks TLS to its own server is not sufficient.
 */
final class AgentUpdate
{
    public const PACKAGE_TABLE = 'glpi_plugin_glpiosquery_packages';

    public const KIND_AGENT   = 'agent';
    public const KIND_OSQUERY = 'osquery';
    public const KIND_EXTENSION = 'extension';

    /**
     * Which rollout ring an agent falls in (0–99).
     *
     * Derived from the device id so it is stable for the life of the machine
     * and independent of database ids, which would otherwise cluster
     * recently-enrolled agents into the same ring.
     */
    public static function ringFor(string $deviceid): int
    {
        return (int) (hexdec(substr(hash('sha256', $deviceid), 0, 8)) % 100);
    }

    /**
     * Build the update instruction for a checking-in agent.
     *
     * @param array  $agent   the agent row
     * @param string $arch    reported by the agent (amd64, arm64, …)
     * @param array  $current ['agent' => '1.2.0', 'osquery' => '5.19.0']
     */
    public static function manifestFor(array $agent, string $arch, array $current): array
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);

        // `packages` is a map keyed by kind. PHP serialises an empty array as
        // a JSON array (`[]`) rather than an object (`{}`), which is a
        // different type to a strict client — and this is the *common* case,
        // since most check-ins have nothing to install. Getting it wrong made
        // every no-op response unparseable, which in turn stopped agents ever
        // confirming an update as healthy. Normalised to an object below.
        $response = [
            'update_available' => false,
            'packages'         => [],
            // Told to every agent so the fleet's check-in rate stays tunable
            // from one place even for agents that are already current.
            'check_interval'   => max(300, (int) ($settings['update_check_interval'] ?? 3600)),
            // Refreshed on every check-in so changing the list in GLPI reaches
            // the fleet without touching an endpoint.
            'trusted_addresses' => self::trustedAddresses(),
        ];

        // Extensions are answered before any of the agent-rollout gates below,
        // and deliberately so. `update_enabled` and the rollout ring exist to
        // stage *this project's* agent version across a fleet; an extension is
        // not a version of anything, it is a capability an administrator has
        // scoped to a set of entities, and making its arrival depend on whether
        // agent auto-update happens to be switched on would mean a rollout that
        // silently does nothing with no indication why.
        //
        // The list is the complete desired set for this agent, not a list of
        // changes: an empty array instructs the agent to uninstall everything,
        // which is how deactivating or unscoping an extension actually removes
        // it from an endpoint. The host-side opt-out still applies, on the
        // agent, where a machine that refuses server-supplied binaries refuses
        // these too.
        $response['extensions'] = Extension::manifestFor($agent, $arch);

        if (empty($settings['update_enabled'])) {
            return self::normalise($response);
        }

        $percent = max(0, min(100, (int) ($settings['rollout_percent'] ?? 0)));
        $ring    = self::ringFor((string) ($agent['deviceid'] ?? ''));

        // Outside the current wave: answer honestly that there is nothing to do
        // rather than withholding a version the agent can see elsewhere.
        if ($ring >= $percent) {
            $response['ring'] = $ring;
            $response['rollout_percent'] = $percent;
            return self::normalise($response);
        }

        $platform = QueryCatalog::normalisePlatform((string) ($agent['platform'] ?? ''));

        foreach ([self::KIND_AGENT, self::KIND_OSQUERY] as $kind) {
            $package = self::activePackage($kind, $platform, $arch);
            if ($package === null) {
                continue;
            }

            $running = (string) ($current[$kind] ?? '');
            if ($running !== '' && self::sameVersion($running, (string) $package['version'])) {
                continue;
            }

            $response['packages'][$kind] = [
                'version' => $package['version'],
                'url'     => $package['url'],
                'sha256'  => $package['sha256'],
                'size'    => (int) $package['size'],
            ];
            $response['update_available'] = true;
        }

        $response['ring'] = $ring;
        $response['rollout_percent'] = $percent;

        return self::normalise($response);
    }

    /**
     * Addresses permitted to query an agent's status listener.
     *
     * @return array<int,string>
     */
    public static function trustedAddresses(): array
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $raw      = (string) ($settings['agent_trusted_addresses'] ?? '');

        $out = [];
        foreach (preg_split('/[\s,;]+/', $raw) ?: [] as $entry) {
            $entry = trim($entry);
            if ($entry !== '') {
                $out[] = $entry;
            }
        }

        return $out;
    }

    /** Keep `packages` a JSON object even when empty. */
    private static function normalise(array $response): array
    {
        if ($response['packages'] === []) {
            $response['packages'] = new \stdClass();
        }

        return $response;
    }

    private static function sameVersion(string $a, string $b): bool
    {
        return ltrim(trim($a), 'v') === ltrim(trim($b), 'v');
    }

    public static function activePackage(string $kind, string $platform, string $arch): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'FROM'  => self::PACKAGE_TABLE,
                'WHERE' => [
                    'kind'      => $kind,
                    'name'      => '',
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
     * Register a built bundle so agents can be offered it.
     *
     * Replaces any existing row for the same kind/platform/arch/version rather
     * than adding a second one: re-publishing after a rebuild is the normal way
     * to correct a wrong checksum, and a table that grew a row each time would
     * leave the truth decided by insertion order.
     *
     * @param array $fields kind, version, platform, arch, url, sha256, size
     * @return string|null an error message, or null on success
     */
    public static function publish(array $fields): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $kind    = trim((string) ($fields['kind'] ?? ''));
        $version = ltrim(trim((string) ($fields['version'] ?? '')), 'v');
        $arch    = trim((string) ($fields['arch'] ?? ''));

        // Matched exactly rather than normalised. QueryCatalog::normalisePlatform
        // folds anything unrecognised to "linux", which is right for an agent
        // reporting its distribution ("ubuntu", "fedora") and wrong here: a typo
        // would be silently published as a Linux package and offered to Linux
        // machines. The same applies to the architecture — agents report exactly
        // amd64 or arm64, so anything else produces a package no machine will
        // ever match, with nothing to indicate why.
        $platform = strtolower(trim((string) ($fields['platform'] ?? '')));
        $url      = trim((string) ($fields['url'] ?? ''));
        $sha256   = strtolower(trim((string) ($fields['sha256'] ?? '')));
        $size     = (int) ($fields['size'] ?? 0);

        if (!in_array($kind, [self::KIND_AGENT, self::KIND_OSQUERY, self::KIND_EXTENSION], true)) {
            return __('Unknown package kind.', 'glpiosquery');
        }

        // An extension package is one binary belonging to a named extension,
        // where agent and osqueryd packages are singular by nature. Publishing
        // one for a name that has not been created leaves a binary no agent can
        // ever be offered, so it is refused rather than stored.
        $name = strtolower(trim((string) ($fields['name'] ?? '')));
        if ($kind === self::KIND_EXTENSION) {
            if (!Extension::validName($name)) {
                return __('An extension package needs the name of a published extension.', 'glpiosquery');
            }
            if (Extension::byName($name) === null) {
                return __('No extension is registered under that name.', 'glpiosquery');
            }
        } else {
            $name = '';
        }
        if ($version === '') {
            return __('A version is required.', 'glpiosquery');
        }
        if (!in_array($platform, ['linux', 'darwin', 'windows'], true)) {
            return __('Platform must be linux, darwin or windows.', 'glpiosquery');
        }
        if (!in_array($arch, ['amd64', 'arm64'], true)) {
            return __('Architecture must be amd64 or arm64.', 'glpiosquery');
        }

        // HTTPS only. The agent verifies the checksum after download, so a plain
        // HTTP URL would not let an attacker plant a payload — but it would let
        // one see exactly which version every machine on the path is fetching,
        // which is reconnaissance handed over for free.
        if (!preg_match('#^https://#i', $url)) {
            return __('The package URL must be https.', 'glpiosquery');
        }
        if (!preg_match('/^[0-9a-f]{64}$/', $sha256)) {
            return __('The SHA-256 must be 64 hexadecimal characters.', 'glpiosquery');
        }
        if ($size <= 0) {
            return __('The package size is required, in bytes.', 'glpiosquery');
        }

        $row = [
            'kind'      => $kind,
            'name'      => $name,
            'version'   => $version,
            'platform'  => $platform,
            'arch'      => $arch,
            'url'       => $url,
            'sha256'    => $sha256,
            'size'      => $size,
            'is_active' => 1,
        ];

        $existing = null;
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::PACKAGE_TABLE,
                'WHERE'  => [
                    'kind'     => $kind,
                    'name'     => $name,
                    'platform' => $platform,
                    'arch'     => $arch,
                    'version'  => $version,
                ],
                'LIMIT'  => 1,
            ]) as $found
        ) {
            $existing = (int) $found['id'];
        }

        if ($existing !== null) {
            $DB->update(self::PACKAGE_TABLE, $row, ['id' => $existing]);
            return null;
        }

        $row['date_creation'] = date('Y-m-d H:i:s');
        $DB->insert(self::PACKAGE_TABLE, $row);

        return null;
    }

    /**
     * Record what an agent says it is running.
     *
     * Version drift is the thing an operator most needs to see about a fleet
     * that updates itself, so it is stored on the agent rather than inferred.
     */
    public static function recordVersions(int $agents_id, string $agent_version, string $osquery_version, string $arch): void
    {
        $fields = [
            'last_update_check' => date('Y-m-d H:i:s'),
        ];

        if ($agent_version !== '') {
            $fields['agent_version'] = mb_substr($agent_version, 0, 32);
        }
        if ($osquery_version !== '') {
            $fields['osquery_version'] = mb_substr($osquery_version, 0, 32);
        }
        if ($arch !== '') {
            $fields['arch'] = mb_substr($arch, 0, 16);
        }

        Node::touch($agents_id, $fields);
    }

    /**
     * Fleet version spread, for the settings page.
     *
     * @return array<int,array{version:string,cpt:int}>
     */
    public static function versionSpread(string $column = 'agent_version'): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach (
            $DB->request([
                'SELECT'  => [
                    $column,
                    new \Glpi\DBAL\QueryExpression('COUNT(*) AS ' . $DB->quoteName('cpt')),
                ],
                'FROM'    => Node::TABLE,
                'WHERE'   => ['is_deleted' => 0],
                'GROUPBY' => [$column],
                'ORDER'   => ['cpt DESC'],
            ]) as $row
        ) {
            $out[] = [
                'version' => (string) ($row[$column] ?? ''),
                'cpt'     => (int) $row['cpt'],
            ];
        }

        return $out;
    }
}
