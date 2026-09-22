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

        $id = (int) $DB->insertId();

        // The scope is only real once GLPI can act on it — see syncEntityRule.
        // is_recursive is the column default rather than a parameter, because
        // nothing offers to create a non-recursive secret yet.
        self::syncEntityRule([
            'id'           => $id,
            'name'         => $name,
            'entities_id'  => $entities_id,
            'is_recursive' => 1,
        ]);

        return ['id' => $id, 'secret' => $plain];
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

    /**
     * The inventory tag carried by every agent that enrolled with this secret.
     *
     * Derived from the id rather than the name so that renaming a secret does
     * not orphan the rule that routes it, and so the value is stable for the
     * life of the secret. Null for id 0, which is an agent that enrolled before
     * the id was recorded.
     */
    public static function tagFor(int $id): ?string
    {
        return $id > 0 ? 'osq-' . $id : null;
    }

    /** The rule uuid this plugin owns for a secret — also how it finds it again. */
    private static function ruleUuid(int $id): string
    {
        return 'glpiosquery-enroll-' . $id;
    }

    /**
     * Keep an entity rule that routes this secret's agents to its entity.
     *
     * An imported asset's entity is decided by the entity rules and nothing
     * else: GLPI reads no entity from the inventory document, and falls back to
     * the inventory configuration's default when no rule matches, which is the
     * root entity on a stock install. A secret scoped to a sub-entity therefore
     * produced assets in the root — correct as far as GLPI was concerned, and
     * wrong in every way that matters to whoever issued the secret.
     *
     * So the scope is expressed where GLPI will read it. The rule is an
     * ordinary one, visible and editable under Administration > Rules > Rules
     * for assigning an item to an entity, which is also where an administrator
     * would look to find out why an asset landed where it did.
     *
     * Two things worth knowing. The rule is appended rather than put first,
     * because entity rules stop at the first match and jumping ahead of rules
     * an administrator wrote is not this plugin's call — if they already have a
     * catch-all, theirs wins and that is their decision to revisit. And a
     * secret scoped to the root entity gets no rule at all: the root is already
     * where an unmatched inventory lands, so a rule saying so would be noise in
     * a collection where order carries meaning.
     */
    public static function syncEntityRule(array $secret): void
    {
        $id       = (int) ($secret['id'] ?? 0);
        $entities = (int) ($secret['entities_id'] ?? 0);
        $tag      = self::tagFor($id);

        if ($tag === null || $entities <= 0) {
            return;
        }

        $rule     = new \RuleImportEntity();
        $existing = self::ruleIdFor($id);

        if ($existing !== null) {
            // The secret's entity is the source of truth, so a rule that has
            // drifted from it is corrected — but only its action. Anything else
            // an administrator changed about the rule is theirs to keep.
            self::setRuleAction($existing, $entities, (int) ($secret['is_recursive'] ?? 1));
            return;
        }

        $rules_id = $rule->add([
            'name'        => sprintf(__('osquery enrolment: %s', 'glpiosquery'), (string) ($secret['name'] ?? $tag)),
            'sub_type'    => \RuleImportEntity::class,
            'match'       => 'AND',
            'is_active'   => 1,
            'entities_id' => 0,
            'uuid'        => self::ruleUuid($id),
            'comment'     => __('Created by the osquery plugin, so that agents enrolled with this secret are imported into the entity the secret was issued for. Deleting it sends them to the default entity instead.', 'glpiosquery'),
        ]);

        if (!$rules_id) {
            return;
        }

        $criteria = new \RuleCriteria();
        $criteria->add([
            'rules_id'  => $rules_id,
            'criteria'  => 'tag',
            'condition' => \Rule::PATTERN_IS,
            'pattern'   => $tag,
        ]);

        self::setRuleAction((int) $rules_id, $entities, (int) ($secret['is_recursive'] ?? 1));
    }

    /** Point a rule's actions at an entity, replacing whatever they said before. */
    private static function setRuleAction(int $rules_id, int $entities_id, int $is_recursive): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $action = new \RuleAction();

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => \RuleAction::getTable(),
                'WHERE'  => ['rules_id' => $rules_id, 'field' => ['entities_id', 'is_recursive']],
            ]) as $row
        ) {
            $action->delete(['id' => (int) $row['id']]);
        }

        $action->add([
            'rules_id'    => $rules_id,
            'action_type' => 'assign',
            'field'       => 'entities_id',
            'value'       => $entities_id,
        ]);

        // Recursive secrets produce assets the child entities can see, which is
        // what "this secret covers the sub-tree" has to mean once the asset
        // exists.
        $action->add([
            'rules_id'    => $rules_id,
            'action_type' => 'assign',
            'field'       => 'is_recursive',
            'value'       => $is_recursive > 0 ? 1 : 0,
        ]);
    }

    /** The id of the rule this plugin created for a secret, if it still exists. */
    public static function ruleIdFor(int $id): ?int
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => \Rule::getTable(),
                'WHERE'  => ['uuid' => self::ruleUuid($id), 'sub_type' => \RuleImportEntity::class],
                'LIMIT'  => 1,
            ]) as $row
        ) {
            return (int) $row['id'];
        }

        return null;
    }

    /**
     * Drop the rule for a secret. Used when the plugin is uninstalled, and when
     * a secret is revoked: a rule matching a tag no agent can obtain any more
     * is a trap for whoever reads the collection next.
     */
    public static function dropEntityRule(int $id): void
    {
        $rules_id = self::ruleIdFor($id);
        if ($rules_id === null) {
            return;
        }

        (new \RuleImportEntity())->delete(['id' => $rules_id], true);
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
