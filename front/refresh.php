<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * "Request inventory" from GLPI's device page.
 *
 * GLPI asks the agent (over its own listener) to run an inventory; the agent
 * relays that here. The plugin then rebuilds the asset from the results osquery
 * has already delivered, on the next assembly cycle.
 *
 * What this deliberately does NOT do is force osquery to re-run its collection
 * immediately: osquery owns its schedule, and a button that made every endpoint
 * re-run a full pack on demand would be a convenient way to flatten a fleet.
 * The response says which of the two happened so nobody has to guess.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload = Endpoint::payload();

$agent = Node::byAgentToken((string) ($payload['agent_token'] ?? ''));
if ($agent === null) {
    Endpoint::respond(['error' => 'unknown agent'], 401);
}

// Clearing last_inventory_at puts the agent past the assembly deadline, so the
// next cron run rebuilds it rather than waiting for the settle window.
Node::touch((int) $agent['id'], [
    'inventory_dirty'   => 1,
    'last_inventory_at' => null,
    'last_seen'         => date('Y-m-d H:i:s'),
    'remote_addr'       => Endpoint::remoteAddress(),
]);

Endpoint::respond([
    'accepted' => true,
    'detail'   => 'asset will be rebuilt from the latest collected results on the next assembly cycle',
]);
