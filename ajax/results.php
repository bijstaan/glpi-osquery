<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Incremental results for a running campaign.
 *
 * The console polls this with the highest row id it already holds, so a long
 * campaign streams in rather than re-sending everything each second.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Node;
use GlpiPlugin\Glpiosquery\Campaign;
use GlpiPlugin\Glpiosquery\Targeting;

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

if (!Targeting::canRun()) {
    http_response_code(403);
    echo json_encode([
        'error' => Targeting::deniedReason(
            'plugin_glpiosquery_livequery',
            __('You are not allowed to run live queries.', 'glpiosquery')
        ),
    ]);
    exit;
}

/** @var DBmysql $DB */
global $DB;

$campaigns_id = (int) ($_GET['campaign'] ?? 0);
$since        = (int) ($_GET['since'] ?? 0);
$limit        = min(2000, max(1, (int) ($_GET['limit'] ?? 500)));

$campaign = null;
foreach ($DB->request(['FROM' => Campaign::TABLE, 'WHERE' => ['id' => $campaigns_id], 'LIMIT' => 1]) as $row) {
    $campaign = $row;
}

if ($campaign === null) {
    http_response_code(404);
    echo json_encode(['error' => __('Unknown campaign.', 'glpiosquery')]);
    exit;
}

// A campaign is visible to the entities its author could reach. Without this a
// user could read another entity's results simply by guessing an id.
$scope = Targeting::entityScope([]);
if (!in_array((int) $campaign['entities_id'], $scope, true) && (int) $campaign['users_id'] !== (int) Session::getLoginUserID()) {
    http_response_code(403);
    echo json_encode(['error' => __('You are not allowed to view this campaign.', 'glpiosquery')]);
    exit;
}

// ------------------------------------------------------------------ new rows
$rows   = [];
$max_id = $since;

foreach (
    $DB->request([
        'SELECT'     => ['r.id', 'r.row_data', 'a.name AS agent_name', 'a.id AS agent_id'],
        'FROM'       => Campaign::ROW_TABLE . ' AS r',
        'INNER JOIN' => [
            Node::TABLE . ' AS a' => ['ON' => ['r' => 'plugin_glpiosquery_agents_id', 'a' => 'id']],
        ],
        'WHERE'      => ['r.plugin_glpiosquery_campaigns_id' => $campaigns_id, 'r.id' => ['>', $since]],
        'ORDER'      => ['r.id'],
        'LIMIT'      => $limit,
    ]) as $row
) {
    $decoded = json_decode((string) $row['row_data'], true);
    $rows[]  = [
        'id'     => (int) $row['id'],
        'agent'  => $row['agent_name'],
        'agent_id' => (int) $row['agent_id'],
        'data'   => is_array($decoded) ? $decoded : [],
    ];
    $max_id = max($max_id, (int) $row['id']);
}

// -------------------------------------------------------------- node states
$states  = ['pending' => 0, 'dispatched' => 0, 'done' => 0, 'failed' => 0, 'expired' => 0];
$errors  = [];
$slowest = null;

foreach (
    $DB->request([
        'SELECT'     => ['t.state', 't.status_code', 't.message', 't.wall_time_ms', 't.row_count', 'a.name AS agent_name'],
        'FROM'       => Campaign::TARGET_TABLE . ' AS t',
        'INNER JOIN' => [
            Node::TABLE . ' AS a' => ['ON' => ['t' => 'plugin_glpiosquery_agents_id', 'a' => 'id']],
        ],
        'WHERE'      => ['t.plugin_glpiosquery_campaigns_id' => $campaigns_id],
    ]) as $target
) {
    $state = (string) $target['state'];
    $states[$state] = ($states[$state] ?? 0) + 1;

    // Per-node failures are surfaced individually: "3 machines could not answer
    // and here is what they said" is actionable, a success count is not.
    if ($state === 'failed' && trim((string) $target['message']) !== '') {
        $errors[] = [
            'agent'   => $target['agent_name'],
            'message' => (string) $target['message'],
        ];
    }

    if ($target['wall_time_ms'] !== null
        && ($slowest === null || (int) $target['wall_time_ms'] > $slowest['wall_time_ms'])) {
        $slowest = [
            'agent'        => $target['agent_name'],
            'wall_time_ms' => (int) $target['wall_time_ms'],
        ];
    }
}

$answered = $states['done'] + $states['failed'];
$total    = (int) $campaign['total_targets'];

echo json_encode([
    'campaign_id' => $campaigns_id,
    'status'      => $campaign['status'],
    'total'       => $total,
    'answered'    => $answered,
    'outstanding' => max(0, $total - $answered),
    'states'      => $states,
    'rows'        => $rows,
    'max_id'      => $max_id,
    'errors'      => array_slice($errors, 0, 25),
    'slowest'     => $slowest,
    'expires_at'  => $campaign['expires_at'],
    'complete'    => in_array($campaign['status'], ['complete', 'expired'], true),
]);
