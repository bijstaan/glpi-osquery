<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Agent self-update check-in.
 *
 * The agent reports what it is running; the server answers with what it should
 * be running, if anything, honouring the staged rollout. Authenticated by node
 * key like every other machine endpoint.
 *
 * Deliberately separate from the osquery protocol endpoints: osquery knows
 * nothing about updating itself, and this is our supervisor talking, not
 * osqueryd.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

// Import explicitly: GLPI has its own global \Agent class, so an unqualified
// `Agent` here silently resolves to that one instead.
use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\AgentUpdate;
use GlpiPlugin\Glpiosquery\Endpoint;
use GlpiPlugin\Glpiosquery\Extension;

$payload = Endpoint::payload();

// The supervisor authenticates with its own token; the node key is accepted as
// a fallback so the endpoint stays usable from a stock-osquery deployment that
// has no supervisor of ours.
$agent = Node::byAgentToken((string) ($payload['agent_token'] ?? ''));
if ($agent === null) {
    $agent = Endpoint::requireAgent($payload);
}

$agent_version   = (string) ($payload['agent_version'] ?? '');
$osquery_version = (string) ($payload['osquery_version'] ?? '');
$arch            = (string) ($payload['arch'] ?? '');

AgentUpdate::recordVersions((int) $agent['id'], $agent_version, $osquery_version, $arch);

// What the agent says it actually has on disk, which is not the same thing as
// what it was last offered. A rollout that is downloading but failing to
// install looks identical to a healthy one from the server's side unless the
// endpoint is asked.
$reported = $payload['extensions'] ?? null;
if (is_array($reported)) {
    Extension::recordInstalled((int) $agent['id'], $reported);
    $agent = Node::byId((int) $agent['id']) ?? $agent;
}

Endpoint::respond(AgentUpdate::manifestFor(
    $agent,
    $arch,
    ['agent' => $agent_version, 'osquery' => $osquery_version]
));
