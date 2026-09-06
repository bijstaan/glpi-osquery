<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * osquery --distributed_tls_read_endpoint
 *
 * The fleet's heartbeat. Every enrolled agent hits this every
 * `distributed_interval` seconds, forever, whether or not anything is
 * happening — so the no-work path is kept to two indexed queries and no
 * further GLPI machinery. Everything expensive lives behind the has_pending
 * flag.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Campaign;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload = Endpoint::payload();
$agent   = Endpoint::requireAgent($payload);

$now      = time();
$response = ['node_invalid' => false];

if (!empty($agent['has_pending'])) {
    $queries = Campaign::dispatchFor((int) $agent['id']);
    if ($queries !== []) {
        $response['queries'] = $queries;
    }
}

// Stay on the accelerated cadence for the rest of the window, even once this
// agent has nothing queued: an operator mid-investigation is usually about to
// ask a second question, and dropping straight back to the lazy interval would
// make the follow-up feel slower than the first.
if ((int) $agent['accelerate_until'] > $now) {
    $response['accelerate'] = (int) $agent['accelerate_until'] - $now;
}

Node::touch((int) $agent['id'], ['last_seen' => date('Y-m-d H:i:s')]);

Endpoint::respond($response);
