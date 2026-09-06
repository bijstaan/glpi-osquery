<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * osquery --config_tls_endpoint
 *
 * Serves the agent's schedule and options. Re-fetched every `config_refresh`
 * seconds, so this is how a pack edit reaches the fleet.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload = Endpoint::payload();
$agent   = Endpoint::requireAgent($payload);

$config = Node::configFor($agent);

// Record which config this agent has, so the UI can show who is behind after a
// pack edit rather than assuming the fleet converged instantly.
Node::touch((int) $agent['id'], [
    'last_seen'      => date('Y-m-d H:i:s'),
    'last_config_at' => date('Y-m-d H:i:s'),
    'config_hash'    => substr(hash('sha256', json_encode($config['schedule'])), 0, 32),
    // Refreshed here rather than on the heartbeat: config fetches are rare
    // enough to be free, and frequent enough to notice a machine moving
    // network.
    'remote_addr'    => Endpoint::remoteAddress(),
]);

Endpoint::respond($config);
