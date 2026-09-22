<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

use GlpiPlugin\Glpiosquery\DefaultPacks;
use GlpiPlugin\Glpiosquery\InventorySync;
use GlpiPlugin\Glpiosquery\TicketEvidence;
use GlpiPlugin\Glpiosquery\Warranty;

/**
 * Install: create the plugin tables, register rights, seed the default
 * inventory packs and register the cron tasks.
 *
 * Table notes:
 *  - `node_key` is a bearer credential, so only its hash is stored. Same for
 *    enrollment secrets, which additionally keep a GLPIKey-encrypted copy so
 *    the UI can re-display the install command.
 *  - `snapshots` holds the latest snapshot per (agent, query). osquery snapshot
 *    results are full state, so newest always wins and there is nothing to
 *    merge — the assembler just reads the current set.
 *  - `interval` is a MySQL reserved word; the column is `query_interval`.
 */
function plugin_glpiosquery_install()
{
    /** @var DBmysql $DB */
    global $DB;

    $charset = 'utf8mb4';
    $collate = 'utf8mb4_unicode_ci';

    // ---------------------------------------------------------------- secrets
    if (!$DB->tableExists('glpi_plugin_glpiosquery_enrollsecrets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_enrollsecrets` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL,
                `secret_hash` VARCHAR(64) NOT NULL,
                `secret_enc` TEXT NULL,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 1,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `expires_at` TIMESTAMP NULL DEFAULT NULL,
                `enroll_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `secret_hash` (`secret_hash`),
                KEY `entities_id` (`entities_id`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ----------------------------------------------------------------- agents
    // One row per enrolled osqueryd. `has_pending` is checked on every
    // distributed/read by the whole fleet, so it is indexed alongside node_key.
    if (!$DB->tableExists('glpi_plugin_glpiosquery_agents')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_agents` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL,
                `node_key_hash` VARCHAR(64) NOT NULL,
                `deviceid` VARCHAR(255) NOT NULL,
                `host_identifier` VARCHAR(255) NULL,
                `hardware_uuid` VARCHAR(64) NULL,
                `hardware_serial` VARCHAR(255) NULL,
                `platform` VARCHAR(32) NULL,
                `platform_like` VARCHAR(32) NULL,
                `os_name` VARCHAR(128) NULL,
                `os_version` VARCHAR(128) NULL,
                `osquery_version` VARCHAR(32) NULL,
                `instance_id` VARCHAR(64) NULL,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpiosquery_enrollsecrets_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `agents_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `itemtype` VARCHAR(100) NULL,
                `items_id` INT UNSIGNED NULL,
                `enrolled_at` TIMESTAMP NULL DEFAULT NULL,
                `last_seen` TIMESTAMP NULL DEFAULT NULL,
                `last_config_at` TIMESTAMP NULL DEFAULT NULL,
                `last_inventory_at` TIMESTAMP NULL DEFAULT NULL,
                `config_hash` VARCHAR(64) NULL,
                `has_pending` TINYINT NOT NULL DEFAULT 0,
                `accelerate_until` INT NOT NULL DEFAULT 0,
                `inventory_dirty` TINYINT NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `is_deleted` TINYINT NOT NULL DEFAULT 0,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `node_key_hash` (`node_key_hash`),
                UNIQUE KEY `deviceid` (`deviceid`),
                KEY `entities_id` (`entities_id`),
                KEY `has_pending` (`has_pending`),
                KEY `inventory_dirty` (`inventory_dirty`),
                KEY `item` (`itemtype`,`items_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ------------------------------------------------------------ packs/queries
    if (!$DB->tableExists('glpi_plugin_glpiosquery_packs')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_packs` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(190) NOT NULL,
                `description` TEXT NULL,
                `platform` VARCHAR(64) NOT NULL DEFAULT 'all',
                `is_inventory` TINYINT NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `is_default` TINYINT NOT NULL DEFAULT 0,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 1,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `name` (`name`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // `glpi_section` names the inventory.schema.json section this query feeds
    // (empty for plain telemetry queries).
    if (!$DB->tableExists('glpi_plugin_glpiosquery_queries')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_queries` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiosquery_packs_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `name` VARCHAR(190) NOT NULL,
                `sql_query` TEXT NOT NULL,
                `query_interval` INT UNSIGNED NOT NULL DEFAULT 3600,
                `is_snapshot` TINYINT NOT NULL DEFAULT 1,
                `platform` VARCHAR(64) NOT NULL DEFAULT 'all',
                `min_agent_version` VARCHAR(32) NULL,
                `glpi_section` VARCHAR(64) NULL,
                `description` TEXT NULL,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `pack_name` (`plugin_glpiosquery_packs_id`,`name`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // -------------------------------------------------------------- snapshots
    if (!$DB->tableExists('glpi_plugin_glpiosquery_snapshots')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_snapshots` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiosquery_agents_id` INT UNSIGNED NOT NULL,
                `query_name` VARCHAR(190) NOT NULL,
                `unix_time` INT UNSIGNED NOT NULL DEFAULT 0,
                `row_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `data` LONGTEXT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `agent_query` (`plugin_glpiosquery_agents_id`,`query_name`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // -------------------------------------------------------------- campaigns
    if (!$DB->tableExists('glpi_plugin_glpiosquery_campaigns')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_campaigns` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(255) NOT NULL,
                `sql_query` TEXT NOT NULL,
                `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `target_json` TEXT NULL,
                `status` VARCHAR(20) NOT NULL DEFAULT 'running',
                `total_targets` INT UNSIGNED NOT NULL DEFAULT 0,
                `responded` INT UNSIGNED NOT NULL DEFAULT 0,
                `failed` INT UNSIGNED NOT NULL DEFAULT 0,
                `expires_at` TIMESTAMP NULL DEFAULT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `status` (`status`),
                KEY `users_id` (`users_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists('glpi_plugin_glpiosquery_campaigntargets')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_campaigntargets` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiosquery_campaigns_id` INT UNSIGNED NOT NULL,
                `plugin_glpiosquery_agents_id` INT UNSIGNED NOT NULL,
                `state` VARCHAR(20) NOT NULL DEFAULT 'pending',
                `dispatched_at` TIMESTAMP NULL DEFAULT NULL,
                `responded_at` TIMESTAMP NULL DEFAULT NULL,
                `status_code` INT NULL,
                `message` TEXT NULL,
                `wall_time_ms` INT UNSIGNED NULL,
                `row_count` INT UNSIGNED NOT NULL DEFAULT 0,
                PRIMARY KEY (`id`),
                UNIQUE KEY `campaign_agent` (`plugin_glpiosquery_campaigns_id`,`plugin_glpiosquery_agents_id`),
                KEY `agent_state` (`plugin_glpiosquery_agents_id`,`state`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    if (!$DB->tableExists('glpi_plugin_glpiosquery_campaignrows')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_campaignrows` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiosquery_campaigns_id` INT UNSIGNED NOT NULL,
                `plugin_glpiosquery_agents_id` INT UNSIGNED NOT NULL,
                `row_data` TEXT NULL,
                PRIMARY KEY (`id`),
                KEY `campaign` (`plugin_glpiosquery_campaigns_id`),
                KEY `campaign_agent` (`plugin_glpiosquery_campaigns_id`,`plugin_glpiosquery_agents_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ------------------------------------------------------------- statuslogs
    // Capped ring of agent-side status lines, kept for diagnosing a misbehaving
    // endpoint. Pruned by cron.
    if (!$DB->tableExists('glpi_plugin_glpiosquery_statuslogs')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_statuslogs` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `plugin_glpiosquery_agents_id` INT UNSIGNED NOT NULL,
                `severity` INT NOT NULL DEFAULT 0,
                `filename` VARCHAR(190) NULL,
                `line` INT UNSIGNED NULL,
                `message` TEXT NULL,
                `logged_at` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `agent_time` (`plugin_glpiosquery_agents_id`,`logged_at`),
                KEY `severity` (`severity`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ------------------------------------------------------- agent packages
    // Self-update payloads. The SHA-256 is not optional: an agent that installs
    // whatever it downloads is a remote code execution path into every endpoint,
    // and TLS to the right host does not establish that the bytes are the ones
    // the administrator published.
    if (!$DB->tableExists(GlpiPlugin\Glpiosquery\TicketEvidence::TABLE)) {
        $DB->doQuery(
            "CREATE TABLE `" . GlpiPlugin\Glpiosquery\TicketEvidence::TABLE . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `tickets_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `itemtype` VARCHAR(100) NULL,
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `plugin_glpiosquery_agents_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `status` VARCHAR(16) NOT NULL DEFAULT 'pending',
                `trigger_type` VARCHAR(16) NOT NULL DEFAULT 'link',
                `followups_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `rendered_at` TIMESTAMP NULL DEFAULT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `tickets_id` (`tickets_id`),
                KEY `status` (`status`),
                KEY `dedupe` (`tickets_id`,`itemtype`,`items_id`)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        );
    }

    if (!$DB->tableExists(GlpiPlugin\Glpiosquery\AgentUpdate::PACKAGE_TABLE)) {
        $DB->doQuery(
            "CREATE TABLE `" . GlpiPlugin\Glpiosquery\AgentUpdate::PACKAGE_TABLE . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `kind` VARCHAR(16) NOT NULL,
                `version` VARCHAR(32) NOT NULL,
                `platform` VARCHAR(16) NOT NULL,
                `arch` VARCHAR(16) NOT NULL,
                `url` TEXT NOT NULL,
                `sha256` CHAR(64) NOT NULL,
                `size` BIGINT UNSIGNED NOT NULL DEFAULT 0,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `lookup` (`kind`,`platform`,`arch`,`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ---------------------------------------------------------- saved queries
    if (!$DB->tableExists('glpi_plugin_glpiosquery_savedqueries')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_savedqueries` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(190) NOT NULL,
                `description` TEXT NULL,
                `sql_query` TEXT NOT NULL,
                `platform` VARCHAR(64) NOT NULL DEFAULT 'all',
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 1,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `users_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `name` (`name`),
                KEY `entities_id` (`entities_id`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ------------------------------------------------------------ extensions
    // An osquery extension an instance administrator has published for the
    // fleet, as opposed to the one this project bundles with the agent.
    //
    // Identity and policy live here; the binaries themselves are rows in the
    // packages table, one per platform/arch/version. Separating them keeps
    // "who should run this" a property of the extension rather than of a
    // particular build, which is what makes a single scope decision cover
    // every architecture at once.
    //
    // `name` is unique across the instance rather than per entity. An agent
    // belongs to exactly one entity so a per-entity namespace would be safe on
    // the wire, but the people administering this are root administrators
    // looking at one list, and two different things sharing a name in that
    // list is a mistake waiting to be made.
    if (!$DB->tableExists('glpi_plugin_glpiosquery_extensions')) {
        $DB->doQuery(
            "CREATE TABLE `glpi_plugin_glpiosquery_extensions` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `name` VARCHAR(64) NOT NULL,
                `label` VARCHAR(255) NULL,
                `entities_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `is_recursive` TINYINT NOT NULL DEFAULT 1,
                `is_active` TINYINT NOT NULL DEFAULT 1,
                `provided_tables` TEXT NULL,
                `comment` TEXT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `name` (`name`),
                KEY `entities_id` (`entities_id`),
                KEY `is_active` (`is_active`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    // ------------------------------------------------------------- warranties
    // One row per asset the warranty lookup has considered. The warranty
    // itself lives in `glpi_infocoms`, which is the point of the feature; this
    // table holds the three things Infocom has no room for — the full
    // entitlement list behind the single span that was written, the failures
    // (an empty Infocom cannot tell "the vendor has no record" from "the
    // credentials expired"), and the schedule that keeps a nightly pass over a
    // large estate inside a vendor's rate limit.
    //
    // `applied_signature` is a fingerprint of what this plugin last wrote. If
    // the asset's warranty fields no longer match it, a person has edited them
    // and the lookup is recorded but not applied.
    if (!$DB->tableExists(Warranty\Record::TABLE)) {
        $DB->doQuery(
            "CREATE TABLE `" . Warranty\Record::TABLE . "` (
                `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
                `itemtype` VARCHAR(100) NOT NULL,
                `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
                `serial` VARCHAR(255) NOT NULL DEFAULT '',
                `vendor` VARCHAR(32) NOT NULL DEFAULT '',
                `status` VARCHAR(16) NOT NULL DEFAULT '',
                `message` VARCHAR(500) NOT NULL DEFAULT '',
                `product` VARCHAR(255) NOT NULL DEFAULT '',
                `service_level` VARCHAR(255) NOT NULL DEFAULT '',
                `principal_type` VARCHAR(16) NOT NULL DEFAULT '',
                `start_date` DATE NULL DEFAULT NULL,
                `end_date` DATE NULL DEFAULT NULL,
                `is_lifetime` TINYINT NOT NULL DEFAULT 0,
                `is_covered` TINYINT NOT NULL DEFAULT 0,
                `ship_date` DATE NULL DEFAULT NULL,
                `purchase_date` DATE NULL DEFAULT NULL,
                `country` VARCHAR(8) NOT NULL DEFAULT '',
                `entitlement_count` INT UNSIGNED NOT NULL DEFAULT 0,
                `entitlements` MEDIUMTEXT NULL,
                `applied` TINYINT NOT NULL DEFAULT 0,
                `applied_signature` VARCHAR(64) NOT NULL DEFAULT '',
                `checked_at` TIMESTAMP NULL DEFAULT NULL,
                `next_check_at` TIMESTAMP NULL DEFAULT NULL,
                `date_creation` TIMESTAMP NULL DEFAULT NULL,
                `date_mod` TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `item` (`itemtype`,`items_id`),
                KEY `due` (`next_check_at`),
                KEY `vendor` (`vendor`,`status`),
                KEY `end_date` (`end_date`)
            ) ENGINE=InnoDB DEFAULT CHARSET=$charset COLLATE=$collate"
        );
    }

    plugin_glpiosquery_migrate();
    plugin_glpiosquery_install_rights();
    plugin_glpiosquery_install_defaults();
    plugin_glpiosquery_install_crons();

    return true;
}

/**
 * Column additions for installations that predate them.
 *
 * GLPI calls the install hook on upgrade too, so this runs on both paths; each
 * change is guarded so it is safe to repeat.
 */
function plugin_glpiosquery_migrate()
{
    /** @var DBmysql $DB */
    global $DB;

    $table = GlpiPlugin\Glpiosquery\Node::TABLE;

    foreach (
        [
            'agent_version'     => "VARCHAR(32) NULL",
            'arch'              => "VARCHAR(16) NULL",
            'last_update_check' => "TIMESTAMP NULL DEFAULT NULL",
            // Where the endpoint contacts us from, and the port its own status
            // listener answers on — both are needed for GLPI's device page to
            // reach the agent for a live status check.
            'remote_addr'       => "VARCHAR(64) NULL",
            'listen_port'       => "INT UNSIGNED NULL",
            // Needed by CommonDBTM for entity recursion now that agents are a
            // first-class GLPI object with the search engine behind them.
            'is_recursive'      => "TINYINT NOT NULL DEFAULT 0",
            // The supervisor's own credential, separate from osqueryd's node
            // key. They must not share one: re-enrolling to obtain a key would
            // rotate the node key and cut osqueryd off mid-flight.
            'agent_token_hash'  => "VARCHAR(64) NULL",
            // What the agent reports having installed, as published extension
            // names and versions. Stored rather than derived: the server knows
            // what it offered, and the difference between that and what is on
            // disk is the whole of what a rollout's health looks like.
            'extensions_json'   => "TEXT NULL",
        ] as $column => $definition
    ) {
        if (!$DB->fieldExists($table, $column)) {
            $DB->doQuery("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
        }
    }

    // A query that selects from an extension table can only run on an agent
    // whose bundle carries that extension. Without a floor, publishing one
    // makes every not-yet-updated agent in the fleet log "no such table" on
    // every interval — noise an operator cannot tell apart from a real fault,
    // for as long as the rollout takes.

    // Whether a capture happened because an asset was attached or because a
    // technician asked for one. Manual captures skip the dedupe window and are
    // written up as a comparison against the previous reading.
    if ($DB->tableExists(TicketEvidence::TABLE)
        && !$DB->fieldExists(TicketEvidence::TABLE, 'trigger_type')) {
        $DB->doQuery(
            "ALTER TABLE `" . TicketEvidence::TABLE . "` "
            . "ADD COLUMN `trigger_type` VARCHAR(16) NOT NULL DEFAULT 'link'"
        );
    }

    // Ties a live-query campaign back to the ticket capture that launched it,
    // so six probes can be written up as one followup instead of six.
    if (!$DB->fieldExists(GlpiPlugin\Glpiosquery\Campaign::TABLE, 'plugin_glpiosquery_evidences_id')) {
        $DB->doQuery(
            "ALTER TABLE `" . GlpiPlugin\Glpiosquery\Campaign::TABLE . "` "
            . "ADD COLUMN `plugin_glpiosquery_evidences_id` INT UNSIGNED NOT NULL DEFAULT 0, "
            . "ADD KEY `evidences_id` (`plugin_glpiosquery_evidences_id`)"
        );
    }

    if (!$DB->fieldExists('glpi_plugin_glpiosquery_queries', 'min_agent_version')) {
        $DB->doQuery(
            "ALTER TABLE `glpi_plugin_glpiosquery_queries` "
            . "ADD COLUMN `min_agent_version` VARCHAR(32) NULL"
        );
    }

    // Packages gained an identity beyond kind/platform/arch once a kind could
    // have more than one member: there is exactly one agent and one osqueryd,
    // but an instance can publish any number of extensions, and without a name
    // they would all collapse onto the same row.
    if (!$DB->fieldExists(GlpiPlugin\Glpiosquery\AgentUpdate::PACKAGE_TABLE, 'name')) {
        $DB->doQuery(
            "ALTER TABLE `" . GlpiPlugin\Glpiosquery\AgentUpdate::PACKAGE_TABLE . "` "
            . "ADD COLUMN `name` VARCHAR(64) NOT NULL DEFAULT '', "
            . "ADD KEY `name` (`name`)"
        );
    }

    // Which osquery table a query needs before it can be served.
    //
    // `min_agent_version` was the right gate while the only extension in
    // existence shipped inside our own bundle, where a version number really
    // did imply a capability. Once an administrator can publish their own, a
    // version number says nothing about whether the table exists on a given
    // endpoint — only the endpoint can answer that, which it does through the
    // discovery query.
    if (!$DB->fieldExists('glpi_plugin_glpiosquery_queries', 'requires_table')) {
        $DB->doQuery(
            "ALTER TABLE `glpi_plugin_glpiosquery_queries` "
            . "ADD COLUMN `requires_table` VARCHAR(190) NULL"
        );
    }

    // Backfill the capability gate on the two shipped queries that read an
    // extension table. Safe to write unconditionally: the column has just been
    // added, so a non-null value can only be one this block put there.
    foreach (
        [
            'inv_monitor_edid_linux' => 'glpi_edid',
            'sec_block_stack'        => 'glpi_block_stack',
        ] as $query => $table
    ) {
        $DB->update(
            'glpi_plugin_glpiosquery_queries',
            ['requires_table' => $table],
            ['name' => $query, 'requires_table' => null]
        );
    }

    // Seeding only ever *adds* queries a pack is missing, so a shipped query
    // whose SQL changed stays as it was on every existing server — and this one
    // changed to collect the byte and error counters that draw the metrics
    // graphs on each network port. The rewrite is matched against the exact
    // string the previous release shipped, so a query an operator has edited is
    // left alone rather than silently reverted.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['sql_query' => 'SELECT interface, mac, type, mtu, flags, link_speed, speed, '
                      . 'ibytes, obytes, ierrors, oerrors, '
                      . 'description, manufacturer, connection_id, connection_status, '
                      . "enabled, physical_adapter, dhcp_enabled, dhcp_server, pci_slot "
                      . "FROM interface_details WHERE mac != '00:00:00:00:00:00';"],
        [
            'name'      => 'inv_interface_details',
            'sql_query' => 'SELECT interface, mac, type, mtu, flags, link_speed, speed, '
                         . 'description, manufacturer, connection_id, connection_status, '
                         . "enabled, physical_adapter, dhcp_enabled, dhcp_server, pci_slot "
                         . "FROM interface_details WHERE mac != '00:00:00:00:00:00';",
        ]
    );

    // The same rewrite, for the two queries whose filters were POSIX ideas
    // applied to every platform.
    //
    // `logged_in_users.type` is a utmp record type on POSIX, where 'user' is
    // the only one that is a person, and a terminal session state on Windows —
    // 'active', 'disconnected' and so on. Keeping only 'user' therefore matched
    // nothing whatsoever on Windows: the machine reported no users, the
    // last-logged-user fields stayed empty, and the asset was attached to
    // nobody, with no error to suggest the query was the problem.
    //
    // `users.uid` is likewise a POSIX rule: on Windows it is the SID's RID, so
    // a threshold keeps real accounts by luck and service accounts with them.
    // Windows says which is which in `type` — local, roaming or special — and
    // that column is empty on POSIX, so the comparison is a no-op there.
    //
    // Both are matched against the exact strings the previous release shipped,
    // so a query an operator has edited is left alone rather than reverted.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['sql_query' => "SELECT user, tty, host, time, type FROM logged_in_users "
                      . "WHERE user != '' AND type NOT IN "
                      . "('boot_time', 'runlevel', 'new_time', 'old_time', 'init', 'login', 'dead', 'empty');"],
        [
            'name'      => 'inv_logged_in_users',
            'sql_query' => "SELECT user, tty, host, time, type FROM logged_in_users WHERE type = 'user';",
        ]
    );

    // inv_users keeps its SQL and loses Windows, where the uid threshold it
    // filters on is a SID's RID and means nothing. Its replacement there,
    // inv_users_windows, is added to existing packs by the seeding pass, which
    // does add queries a pack is missing.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['platform' => 'linux,darwin'],
        [
            'name'      => 'inv_users',
            'platform'  => 'all',
            'sql_query' => 'SELECT uid, gid, username, description, directory, shell, uuid '
                         . 'FROM users WHERE uid >= 500 OR uid = 0;',
        ]
    );

    // inv_interface_details keeps its name and loses Windows, where half the
    // columns it selects are empty and the MAC filter lets every WAN Miniport
    // through. inv_interface_details_windows replaces it there, and is added to
    // existing packs by the seeding pass. Matched on the SQL the last release
    // shipped, so an edited query keeps whatever platform it was given.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['platform' => 'linux,darwin',
            'sql_query' => 'SELECT interface, mac, type, mtu, flags, link_speed, '
                         . 'ibytes, obytes, ierrors, oerrors, pci_slot '
                         . "FROM interface_details WHERE mac != '00:00:00:00:00:00';"],
        [
            'name'      => 'inv_interface_details',
            'platform'  => 'all',
            'sql_query' => 'SELECT interface, mac, type, mtu, flags, link_speed, speed, '
                         . 'ibytes, obytes, ierrors, oerrors, '
                         . 'description, manufacturer, connection_id, connection_status, '
                         . 'enabled, physical_adapter, dhcp_enabled, dhcp_server, pci_slot '
                         . "FROM interface_details WHERE mac != '00:00:00:00:00:00';",
        ]
    );

    // inv_users and inv_groups lose Linux, where the 500 boundary they filter
    // on is the macOS one: current distros allocate system accounts downwards
    // from 999, so a stock Ubuntu desktop reported systemd-network, polkitd and
    // a dozen more as local users. inv_users_linux and inv_groups_linux replace
    // them there and are added by the seeding pass. Matched on the shipped SQL
    // and platform, so an edited query is left as its operator set it.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['platform' => 'darwin'],
        [
            'name'      => 'inv_users',
            'platform'  => 'linux,darwin',
            'sql_query' => 'SELECT uid, gid, username, description, directory, shell, uuid '
                         . 'FROM users WHERE uid >= 500 OR uid = 0;',
        ]
    );
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['platform' => 'darwin,windows'],
        [
            'name'      => 'inv_groups',
            'platform'  => 'all',
            'sql_query' => 'SELECT gid, groupname, comment FROM groups WHERE gid >= 500 OR gid = 0;',
        ]
    );

    // inv_disk_encryption briefly shipped for Linux too, where it answers for
    // none of the volumes that matter and names the rest differently from
    // mounts; inv_block_stack covers Linux instead.
    $DB->update(
        'glpi_plugin_glpiosquery_queries',
        ['platform' => 'darwin'],
        [
            'name'      => 'inv_disk_encryption',
            'platform'  => 'linux,darwin',
            'sql_query' => 'SELECT name, uuid, encrypted, type, encryption_status, filevault_status '
                         . 'FROM disk_encryption;',
        ]
    );

    // Four shipped saved queries gained Windows and macOS siblings, so the
    // bare names they had became ambiguous — "Connected monitors" now means one
    // of three statements. Renamed rather than left alone because the old name
    // would sit in the list beside its own platform-suffixed siblings, and
    // matched on the shipped SQL so a query an operator edited keeps its name.
    foreach (
        [
            ['Disk space', 'Disk space (Linux/macOS)',
             "SELECT path, type, round((blocks * blocks_size) / 1073741824.0, 1) AS total_gb, "
             . "round((blocks_available * blocks_size) / 1073741824.0, 1) AS free_gb "
             . "FROM mounts WHERE device LIKE '/dev/%' ORDER BY total_gb DESC;"],
            ['Recently installed packages', 'Installed packages (Debian/Ubuntu)',
             'SELECT name, version, arch, size FROM deb_packages ORDER BY name;'],
            ['Disk encryption status', 'Disk encryption (Linux/macOS)',
             'SELECT name, encrypted, type, encryption_status FROM disk_encryption;'],
            ['Connected monitors', 'Connected monitors (Linux)',
             'SELECT connector, preferred_mode, status, bytes FROM glpi_edid;'],
        ] as [$from, $to, $sql]
    ) {
        $DB->update(
            GlpiPlugin\Glpiosquery\SavedQuery::getTable(),
            ['name' => $to],
            ['name' => $from, 'sql_query' => $sql]
        );
    }

    // Existing secrets predate the rule that carries their entity, and the
    // assets they produced are in whatever entity GLPI defaulted to. This puts
    // the routing in place for everything they enrol from here on; assets
    // already imported into the wrong entity have to be moved, because GLPI
    // only moves an asset between entities when a transfer model is configured.
    foreach (
        $DB->request([
            'FROM'  => GlpiPlugin\Glpiosquery\EnrollSecret::TABLE,
            'WHERE' => ['is_active' => 1, ['NOT' => ['entities_id' => 0]]],
        ]) as $secret
    ) {
        GlpiPlugin\Glpiosquery\EnrollSecret::syncEntityRule($secret);
    }
}

/**
 * Inventory assembly runs on a short cycle because it is the step between "the
 * agent reported" and "the asset is current" — anything slower shows up to the
 * user as GLPI being out of date.
 */
function plugin_glpiosquery_install_crons()
{
    CronTask::register(
        InventorySync::class,
        'osqueryInventory',
        60,
        ['state' => CronTask::STATE_WAITING, 'mode' => CronTask::MODE_EXTERNAL]
    );

    CronTask::register(
        InventorySync::class,
        'osqueryMaintenance',
        300,
        ['state' => CronTask::STATE_WAITING, 'mode' => CronTask::MODE_EXTERNAL]
    );

    // Warranty lookups run hourly and do a bounded amount of work each time,
    // rather than nightly and all at once. The resource being spent is a
    // vendor's rate limit, and a trickle is both kinder to it and quicker to
    // surface a credential problem than a single burst at 03:00.
    //
    // Registered whether or not the feature is switched on: the task itself
    // returns immediately while the master switch is off, and a cron that only
    // appears once a setting is saved is one an administrator cannot find in
    // order to schedule it.
    CronTask::register(
        Warranty\Sync::class,
        'warrantyLookup',
        HOUR_TIMESTAMP,
        ['state' => CronTask::STATE_WAITING, 'mode' => CronTask::MODE_EXTERNAL]
    );
}

/**
 * Running a saved query and writing free-form SQL are deliberately separate
 * rights: the first is routine support work, the second is an open window onto
 * every endpoint in the estate.
 */
function plugin_glpiosquery_install_rights()
{
    /** @var DBmysql $DB */
    global $DB;

    $rights = [
        'plugin_glpiosquery_agent'     => READ | UPDATE | DELETE | PURGE,
        'plugin_glpiosquery_pack'      => READ | UPDATE | CREATE | DELETE | PURGE,
        'plugin_glpiosquery_livequery' => READ | UPDATE,
        // Free-form SQL is granted to nobody by default. It is an open window
        // onto every endpoint in the estate and should be a deliberate act of
        // delegation, not something that arrives switched on.
        'plugin_glpiosquery_rawsql'    => 0,
        // Publishing an extension hands every targeted endpoint a binary that
        // osqueryd will execute as root. That is a strictly larger power than
        // free-form SQL, which is at least bounded by osquery's read-only
        // tables, so it starts granted to nobody for the same reason — and
        // Extension::canManage() additionally requires a session that can see
        // the whole instance, so the right alone is not enough.
        'plugin_glpiosquery_extension' => 0,
    ];

    // Only add rights that are not already registered.
    //
    // GLPI runs the install hook on upgrade as well as on first install, and
    // ProfileRight::addProfileRights() inserts unconditionally — so calling it
    // for an existing right raises a duplicate-key error that aborts the whole
    // upgrade. Every plugin update would fail once the plugin had ever been
    // installed.
    $existing = [];
    foreach (
        $DB->request([
            'SELECT'   => ['name'],
            'DISTINCT' => true,
            'FROM'     => 'glpi_profilerights',
            'WHERE'    => ['name' => array_keys($rights)],
        ]) as $row
    ) {
        $existing[(string) $row['name']] = true;
    }

    foreach (array_keys($rights) as $right) {
        if (!isset($existing[$right])) {
            ProfileRight::addProfileRights([$right]);
        }
    }

    // Grant to every profile that can already administer GLPI configuration.
    //
    // Keying off the installing user's session does not work: plugins are
    // routinely installed from the console (`bin/console glpi:plugin:install`),
    // where there is no active profile, and the plugin would then be installed
    // but usable by nobody.
    $targets = [];
    foreach (
        $DB->request([
            'SELECT' => ['profiles_id'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => ['name' => 'config', 'rights' => ['&', UPDATE]],
        ]) as $row
    ) {
        $targets[] = (int) $row['profiles_id'];
    }

    if (isset($_SESSION['glpiactiveprofile']['id'])) {
        $targets[] = (int) $_SESSION['glpiactiveprofile']['id'];
    }

    foreach (array_unique($targets) as $profiles_id) {
        foreach ($rights as $right => $value) {
            if ($value > 0) {
                ProfileRight::updateProfileRights($profiles_id, [$right => $value]);
            }
        }
    }
}

/**
 * Seed default settings and the shipped inventory packs. Idempotent: existing
 * packs are left alone so a reinstall never clobbers local edits.
 */
function plugin_glpiosquery_install_defaults()
{
    $defaults = [
        // The single most important number in the system: live-query latency
        // versus idle load.
        'distributed_interval' => 10,
        // How long targeted agents stay on the accelerated 5s cadence.
        'accelerate_seconds'   => 60,
        'config_refresh'       => 300,
        'logger_tls_period'    => 10,
        // Campaigns stop accepting results after this many seconds.
        'campaign_ttl'         => 900,
        // Agents unseen for this long are shown as offline.
        'offline_after'        => 900,
        'statuslog_retention_days' => 7,
        // Live-query results are the only thing here that grows without bound.
        'campaign_retention_days'  => 30,
        'enroll_auto_accept'   => 1,

        // Self-update. Off by default and at 0% rollout: an administrator
        // should choose to hand the server control of what runs on their
        // endpoints, and choose when it reaches them.
        'update_enabled'        => 0,
        'rollout_percent'       => 0,
        'update_check_interval' => 3600,

        // Addresses GLPI itself contacts agents from, for the device page's
        // live status check. Empty means agents trust only the host in their
        // server URL — which is wrong whenever GLPI sits behind a proxy or is
        // multi-homed, because the request arrives from the app server rather
        // than the name the agent was given.
        'agent_trusted_addresses' => '',

        // Opening tickets for failing machines is off by default: it writes
        // into someone else's helpdesk queue, which should be a deliberate
        // choice rather than a side effect of installing a plugin.
        'compliance_tickets' => 0,
    ] + Warranty\Settings::defaults();

    // Only the keys that are not stored yet.
    //
    // GLPI re-runs the install hook on every version change, and
    // Config::setConfigurationValues() overwrites unconditionally — so seeding
    // the whole list would reset an administrator's tuning on each upgrade,
    // silently and with nothing in the log to say it happened.
    $stored = Config::getConfigurationValues(
        PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT,
        array_keys($defaults)
    );

    $missing = array_diff_key($defaults, $stored);

    if ($missing !== []) {
        Config::setConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT, $missing);
    }

    DefaultPacks::seed();
    GlpiPlugin\Glpiosquery\SavedQuery::seedDefaults();
}

function plugin_glpiosquery_uninstall()
{
    /** @var DBmysql $DB */
    global $DB;

    // Collected before the tables go, because the rules are found by a uuid
    // derived from the secret's id and the deletion below takes the secrets
    // with it.
    $enroll_rule_ids = [];
    if ($DB->tableExists(GlpiPlugin\Glpiosquery\EnrollSecret::TABLE)) {
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => GlpiPlugin\Glpiosquery\EnrollSecret::TABLE,
            ]) as $secret
        ) {
            $rules_id = GlpiPlugin\Glpiosquery\EnrollSecret::ruleIdFor((int) $secret['id']);
            if ($rules_id !== null) {
                $enroll_rule_ids[] = $rules_id;
            }
        }
    }

    foreach (
        [
            'glpi_plugin_glpiosquery_packages',
            'glpi_plugin_glpiosquery_statuslogs',
            'glpi_plugin_glpiosquery_campaignrows',
            'glpi_plugin_glpiosquery_campaigntargets',
            'glpi_plugin_glpiosquery_campaigns',
            'glpi_plugin_glpiosquery_snapshots',
            'glpi_plugin_glpiosquery_queries',
            'glpi_plugin_glpiosquery_packs',
            'glpi_plugin_glpiosquery_agents',
            'glpi_plugin_glpiosquery_savedqueries',
            'glpi_plugin_glpiosquery_enrollsecrets',
            'glpi_plugin_glpiosquery_warranties',
        ] as $table
    ) {
        if ($DB->tableExists($table)) {
            $DB->doQuery("DROP TABLE `$table`");
        }
    }

    CronTask::unregister('glpiosquery');

    // The entity rules this plugin created. Left behind they would route the
    // tag of a secret that no longer exists, in a collection where order
    // carries meaning — dead weight at best, and a puzzle for whoever reads it
    // next. Read before the tables go, hence the order in this function.
    foreach ($enroll_rule_ids as $rules_id) {
        (new RuleImportEntity())->delete(['id' => $rules_id], true);
    }

    foreach (
        [
            'plugin_glpiosquery_agent',
            'plugin_glpiosquery_pack',
            'plugin_glpiosquery_livequery',
            'plugin_glpiosquery_rawsql',
            'plugin_glpiosquery_extension',
        ] as $right
    ) {
        ProfileRight::deleteProfileRights([$right]);
    }

    Config::deleteConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT, [
        'distributed_interval', 'accelerate_seconds', 'config_refresh',
        'logger_tls_period', 'campaign_ttl', 'offline_after',
        'statuslog_retention_days', 'campaign_retention_days', 'enroll_auto_accept',
        'update_enabled', 'rollout_percent', 'update_check_interval',
        'agent_trusted_addresses', 'compliance_tickets',
    ]);

    // Including every vendor credential. Leaving those behind would keep seven
    // support-portal secrets in the database of an instance that no longer has
    // the plugin that reads them.
    Config::deleteConfigurationValues(
        PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT,
        array_keys(Warranty\Settings::defaults())
    );

    return true;
}

/**
 * An asset was attached to a ticket: capture what the machine looks like now.
 *
 * Failure here must never block the link. A technician associating an asset is
 * doing their job; an inability to reach the endpoint is not a reason to refuse
 * it, so everything is contained and logged rather than thrown.
 */
function plugin_glpiosquery_item_linked_to_ticket($item)
{
    if (!($item instanceof Item_Ticket)) {
        return;
    }

    try {
        TicketEvidence::capture(
            (int) $item->fields['tickets_id'],
            (string) $item->fields['itemtype'],
            (int) $item->fields['items_id']
        );
    } catch (\Throwable $e) {
        trigger_error(
            'glpiosquery: could not capture ticket evidence: ' . $e->getMessage(),
            E_USER_WARNING
        );
    }
}

/**
 * An asset was purged: forget what the vendor told us about it.
 *
 * GLPI reuses primary keys, so a lookup row left behind on (itemtype, items_id)
 * would eventually be read as belonging to an unrelated new machine — and it
 * would be read, because the row carries the signature that decides whether
 * this plugin may write that asset's warranty fields.
 */
function plugin_glpiosquery_item_purged($item)
{
    if (!($item instanceof CommonDBTM)) {
        return;
    }

    try {
        Warranty\Record::purgeItem($item->getType(), (int) $item->getID());
    } catch (\Throwable $e) {
        trigger_error(
            'glpiosquery: could not clear the warranty record: ' . $e->getMessage(),
            E_USER_WARNING
        );
    }
}
