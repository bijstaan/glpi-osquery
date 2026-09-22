<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery\Inventory;

/**
 * Resolves the logins an endpoint reports to the logins GLPI knows.
 *
 * GLPI attaches an imported asset to a user by matching `content.users[].login`
 * against `glpi_users.name` exactly (Glpi\Inventory\MainAsset\MainAsset::
 * prepareForUsers). That works when the account name on the machine is the
 * account name in GLPI, and stops working the moment a directory is involved:
 * Entra provisions users into GLPI under their UPN, `mkilgore@example.com`,
 * while the machine knows the same person as `mkilgore`. Nothing matched, the
 * asset was attached to nobody, and the only visible symptom was an empty user
 * field on an otherwise complete inventory.
 *
 * Core cannot be made to do this: its one piece of leniency goes the other way,
 * splitting a UPN in the document to match a bare name in GLPI. So the document
 * is rewritten before it is handed over, carrying the login GLPI will recognise.
 *
 * The passes widen deliberately and stop at the first that produces exactly one
 * user. An ambiguous login is left as the endpoint reported it: attaching a
 * machine to the wrong person is worse than attaching it to nobody, because
 * nobody is visibly missing and a wrong name is not.
 */
final class UserMatch
{
    /**
     * Rewrite the users section of an inventory document in place.
     *
     * @param array<string,mixed> $document
     * @return array<string,mixed>
     */
    public static function apply(array $document): array
    {
        if (empty($document['content']['users']) || !is_array($document['content']['users'])) {
            return $document;
        }

        foreach ($document['content']['users'] as $i => $user) {
            $login = trim((string) ($user['login'] ?? ''));
            if ($login === '') {
                continue;
            }

            $resolved = self::glpiLoginFor($login);
            if ($resolved === null || $resolved === $login) {
                continue;
            }

            $document['content']['users'][$i]['login'] = $resolved;

            // The domain is dropped along with the rewrite. GLPI appends it to
            // the asset's contact field as `login@domain`, and the resolved
            // login is already a UPN — `mkilgore@example.com@AzureAD` is not a
            // thing anyone wants to read.
            unset($document['content']['users'][$i]['domain']);
        }

        return $document;
    }

    /**
     * The GLPI login for an account name an endpoint reported, or null.
     */
    public static function glpiLoginFor(string $login): ?string
    {
        // A machine-local account is a fact about the machine, not a person in
        // the directory, and `administrator` exists on every Windows box in the
        // estate. Matching one to a GLPI user of the same name would attach
        // half the fleet to whoever holds that account.
        if (self::isLocalAccount($login)) {
            return null;
        }

        // Windows reports DOMAIN\user in some tables and the bare name in
        // others; the domain is carried separately, so the prefix is noise.
        if (($slash = strrpos($login, '\\')) !== false) {
            $login = substr($login, $slash + 1);
        }

        if ($login === '') {
            return null;
        }

        // 1. The name as given. The common case, and the one core already
        //    handles — repeated here so a match here costs no further queries.
        if (self::userExists($login)) {
            return $login;
        }

        // 2. The name as the local part of a UPN: `mkilgore` matching the user
        //    Entra provisioned as `mkilgore@example.com`.
        if (strpos($login, '@') === false) {
            $unique = self::onlyUser(['name' => ['LIKE', self::escapeLike($login) . '@%']]);
            if ($unique !== null) {
                return $unique;
            }

            // 3. Same idea through the address book, for a directory that
            //    provisions names in one form and addresses in another.
            $unique = self::onlyUserByEmail(self::escapeLike($login) . '@%');
            if ($unique !== null) {
                return $unique;
            }

            return null;
        }

        // 4. The endpoint reported a UPN that GLPI does not hold verbatim: try
        //    its local part, which is the form a non-directory GLPI would have.
        $local = substr($login, 0, (int) strpos($login, '@'));
        if ($local !== '' && self::userExists($local)) {
            return $local;
        }

        return null;
    }

    /**
     * Accounts that exist identically on every machine and mean nobody.
     *
     * Deliberately short: this is for the built-in accounts, not a filter on
     * service accounts an administrator may legitimately want attached.
     */
    private static function isLocalAccount(string $login): bool
    {
        static $builtin = [
            'administrator', 'admin', 'guest', 'defaultaccount', 'wdagutilityaccount',
            'root', 'nobody', 'daemon', 'system',
        ];

        return in_array(mb_strtolower(trim($login)), $builtin, true);
    }

    private static function userExists(string $name): bool
    {
        return self::onlyUser(['name' => $name]) !== null;
    }

    /**
     * The one active user matching a condition, or null if there are none or
     * more than one.
     *
     * @param array<string,mixed> $where
     */
    private static function onlyUser(array $where): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $names = [];
        foreach (
            $DB->request([
                'SELECT' => ['name'],
                'FROM'   => 'glpi_users',
                'WHERE'  => $where + ['is_deleted' => 0, 'is_active' => 1],
                'LIMIT'  => 2,
            ]) as $row
        ) {
            $names[] = (string) $row['name'];
        }

        return count($names) === 1 ? $names[0] : null;
    }

    /** The one active user whose email matches a pattern, or null. */
    private static function onlyUserByEmail(string $pattern): ?string
    {
        /** @var \DBmysql $DB */
        global $DB;

        $names = [];
        foreach (
            $DB->request([
                'SELECT'     => ['glpi_users.name'],
                'FROM'       => 'glpi_useremails',
                'INNER JOIN' => [
                    'glpi_users' => [
                        'ON' => [
                            'glpi_useremails' => 'users_id',
                            'glpi_users'      => 'id',
                        ],
                    ],
                ],
                'WHERE'      => [
                    'glpi_useremails.email' => ['LIKE', $pattern],
                    'glpi_users.is_deleted' => 0,
                    'glpi_users.is_active'  => 1,
                ],
                'LIMIT'      => 2,
            ]) as $row
        ) {
            $names[] = (string) $row['name'];
        }

        return count($names) === 1 ? $names[0] : null;
    }

    /**
     * Escape a login for use inside a LIKE pattern.
     *
     * Not decoration: `_` is a single-character wildcard, and service accounts
     * are full of underscores — `svc_backup@%` would otherwise match
     * `svcXbackup@example.com` and resolve to the wrong person.
     */
    public static function escapeLike(string $value): string
    {
        return str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $value);
    }
}
