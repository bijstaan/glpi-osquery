<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * osquery --enroll_tls_endpoint
 *
 * Trades an enrollment secret for a per-agent node key. This is the only
 * endpoint that accepts the shared secret; everything after it is authenticated
 * per agent.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload  = Endpoint::payload();
$node_key = Node::enroll($payload);

if ($node_key === null) {
    // osquery retries enrollment with backoff, so a rejected secret is not an
    // error state to shout about — but it is worth recording, because a fleet
    // of machines rejecting is how a botched rollout looks.
    trigger_error(
        sprintf('glpiosquery: rejected enrollment from %s', $_SERVER['REMOTE_ADDR'] ?? 'unknown'),
        E_USER_NOTICE
    );
    Endpoint::respond(['node_invalid' => true]);
}

Endpoint::respond(['node_key' => $node_key, 'node_invalid' => false]);
