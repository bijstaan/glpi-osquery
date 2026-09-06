<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Launches a live query campaign.
 *
 * Returns the campaign id plus the agents it was aimed at, so the console can
 * show "asking 34 machines" before any of them have answered — and can be
 * honest later about which ones never did.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Campaign;
use GlpiPlugin\Glpiosquery\QueryCatalog;
use GlpiPlugin\Glpiosquery\SavedQuery;
use GlpiPlugin\Glpiosquery\Targeting;

header('Content-Type: application/json');
// The body below is json_encode output on an explicitly-typed JSON response, so
// nothing in it can be read as markup — but only as long as the browser takes
// the declared type at its word. nosniff is what makes that true.
header('X-Content-Type-Options: nosniff');

if (!Targeting::canRun()) {
    http_response_code(403);
    echo json_encode([
        'error' => Targeting::deniedReason(
            'plugin_glpiosquery_livequery',
            __('You are not allowed to run live queries.', 'glpiosquery')
        ),
        'stale_session' => Targeting::isStaleSessionFor('plugin_glpiosquery_livequery'),
    ]);
    exit;
}

// The console posts form-encoded with the request in a `payload` field, so the
// CSRF token can travel as a form field too (see console.js). A raw JSON body
// is still accepted, which keeps the endpoint usable from scripts and curl.
if (isset($_POST['payload'])) {
    $payload = json_decode((string) $_POST['payload'], true);
} else {
    $payload = json_decode(file_get_contents('php://input') ?: '[]', true);
}

if (!is_array($payload)) {
    $payload = [];
}

$sql = trim((string) ($payload['sql'] ?? ''));

// A saved query may be run by anyone with the live-query right; free-form SQL
// needs the separate raw-SQL right. The distinction is the whole point of
// having two rights, so it is enforced here rather than only hidden in the UI.
$saved_id = (int) ($payload['saved_query_id'] ?? 0);
$is_saved = false;

if ($saved_id > 0) {
    $saved = SavedQuery::sqlFor($saved_id);

    // The SQL comes from the database, never from the request. Trusting a
    // client-supplied query alongside a saved id would make the whole
    // distinction between the two rights decorative: anyone holding only the
    // safe right could send arbitrary SQL with any saved id attached.
    if ($saved === null) {
        http_response_code(404);
        echo json_encode(['error' => __('That saved query no longer exists.', 'glpiosquery')]);
        exit;
    }

    $sql      = (string) $saved['sql_query'];
    $is_saved = true;

    if (trim((string) ($payload['name'] ?? '')) === '') {
        $payload['name'] = (string) $saved['name'];
    }
}

if (!$is_saved && !Targeting::canRunRawSql()) {
    http_response_code(403);
    echo json_encode([
        'error' => Targeting::deniedReason(
            'plugin_glpiosquery_rawsql',
            __('You may only run saved queries. Writing your own SQL needs the free-form query right.', 'glpiosquery')
        ),
        'stale_session' => Targeting::isStaleSessionFor('plugin_glpiosquery_rawsql'),
    ]);
    exit;
}

if (($reason = QueryCatalog::reject($sql)) !== null) {
    http_response_code(422);
    echo json_encode(['error' => $reason]);
    exit;
}

$filters = [
    'entities'    => (array) ($payload['entities'] ?? []),
    'groups'      => (array) ($payload['groups'] ?? []),
    'platforms'   => (array) ($payload['platforms'] ?? []),
    'agents'      => (array) ($payload['agents'] ?? []),
    'items'       => (array) ($payload['items'] ?? []),
    'online_only' => !empty($payload['online_only']),
];

$agents = Targeting::resolve($filters);
if ($agents === []) {
    echo json_encode([
        'campaign_id' => null,
        'targeted'    => 0,
        'warning'     => __('No agents match this target.', 'glpiosquery'),
    ]);
    exit;
}

$name = trim((string) ($payload['name'] ?? ''));
if ($name === '') {
    $name = mb_substr(preg_replace('/\s+/', ' ', $sql) ?? $sql, 0, 120);
}

$campaigns_id = Campaign::launch(
    $name,
    $sql,
    array_column($agents, 'id'),
    (int) Session::getLoginUserID(),
    (int) ($_SESSION['glpiactive_entity'] ?? 0)
);

$settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);

echo json_encode([
    'campaign_id' => $campaigns_id,
    'targeted'    => count($agents),
    // The console shows this so the wait is explained rather than mysterious:
    // agents answer on their next check-in, not instantly.
    'check_in_interval' => (int) ($settings['distributed_interval'] ?? 10),
    'evented_tables'    => QueryCatalog::eventedTablesIn($sql),
    // Echoed back so the console can show exactly what ran, which matters when
    // the query executed is the stored one rather than what is in the editor.
    'sql'               => $sql,
]);
