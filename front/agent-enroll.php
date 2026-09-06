<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Supervisor enrollment.
 *
 * Trades the shared enrollment secret for a credential belonging to the
 * supervisor alone. Deliberately does not touch osqueryd's node key — see
 * Node::enrollSupervisor.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\AgentUpdate;
use GlpiPlugin\Glpiosquery\Endpoint;

$payload = Endpoint::payload();
$token   = Node::enrollSupervisor($payload);

if ($token === null) {
    trigger_error(
        sprintf('glpiosquery: rejected agent enrollment from %s', $_SERVER['REMOTE_ADDR'] ?? 'unknown'),
        E_USER_NOTICE
    );
    Endpoint::respond(['error' => 'invalid enrollment secret'], 401);
}

Endpoint::respond([
    'agent_token'       => $token,
    'trusted_addresses' => AgentUpdate::trustedAddresses(),
]);
