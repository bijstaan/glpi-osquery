<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * osquery --distributed_tls_write_endpoint
 *
 * Live query results. One POST can carry several campaigns' answers, each with
 * its own status, message and timing.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Campaign;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload = Endpoint::payload();
$agent   = Endpoint::requireAgent($payload);

Campaign::ingest(
    (int) $agent['id'],
    (array) ($payload['queries']  ?? []),
    (array) ($payload['statuses'] ?? []),
    (array) ($payload['messages'] ?? []),
    (array) ($payload['stats']    ?? [])
);

Node::touch((int) $agent['id'], ['last_seen' => date('Y-m-d H:i:s')]);

Endpoint::respond(['node_invalid' => false]);
