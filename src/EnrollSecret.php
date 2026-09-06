<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use GLPIKey;

/**
 * Enrollment secrets.
 *
 * A secret is a *bootstrap* credential: it is shared by every machine an admin
 * installs from one command line, so it is treated as low-trust. It buys
 * exactly one thing — the right to obtain a node key — and can be scoped to an
 * entity, expired, and revoked without touching agents that already enrolled.
 *
 * Storage keeps both a SHA-256 hash (for lookup, since the encrypted form is
 * non-deterministic and cannot be matched) and a GLPIKey-encrypted copy, so
 * the UI can re-display the install command later without ever holding the
 * plaintext at rest.
 */
final class EnrollSecret
{
    public const TABLE = 'glpi_plugin_glpiosquery_enrollsecrets';

    /**
     * Find the active, unexpired secret matching a presented value.
     *
     * The lookup is by hash so it is a single indexed hit regardless of how
     * many secrets exist.
     */
    public static function match(string $presented): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $presented = trim($presented);
        if ($presented === '') {
            return null;
        }

        $rows = $DB->request([
            'FROM'  => self::TABLE,
            'WHERE' => [
                'secret_hash' => hash('sha256', $presented),
                'is_active'   => 1,
            ],
            'LIMIT' => 1,
        ]);

        foreach ($rows as $row) {
            if (!empty($row['expires_at']) && strtotime($row['expires_at']) < time()) {
                return null;
            }
            return $row;
        }

        return null;
    }

    /**
     * Create a secret, returning [id, plaintext]. The plaintext is returned
     * once, here, because it is needed to build the install command; after this
     * it only exists encrypted.
     */
    public static function create(string $name, int $entities_id = 0, ?string $expires_at = null): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $plain = bin2hex(random_bytes(24));
        $now   = date('Y-m-d H:i:s');

        $DB->insert(self::TABLE, [
            'name'          => $name,
            'secret_hash'   => hash('sha256', $plain),
            'secret_enc'    => (new GLPIKey())->encrypt($plain),
            'entities_id'   => $entities_id,
            'is_active'     => 1,
            'expires_at'    => $expires_at,
            'date_creation' => $now,
            'date_mod'      => $now,
        ]);

        return ['id' => $DB->insertId(), 'secret' => $plain];
    }

    /** Recover the plaintext for display in the install command. */
    public static function reveal(array $row): ?string
    {
        if (empty($row['secret_enc'])) {
            return null;
        }

        try {
            return (new GLPIKey())->decrypt($row['secret_enc']);
        } catch (\Throwable $e) {
            // A rotated GLPI key makes old secrets unreadable. That is
            // recoverable (issue a new secret), so it must not be fatal.
            return null;
        }
    }

    public static function countEnrolment(int $id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(
            self::TABLE,
            ['enroll_count' => new \QueryExpression('enroll_count + 1')],
            ['id' => $id]
        );
    }
}
