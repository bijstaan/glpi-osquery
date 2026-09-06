<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Serves the osquery schema catalog to the console's editor.
 *
 * Optionally narrowed to one platform (`?platform=linux`), which the
 * per-computer console does so an operator is never offered a table that
 * cannot exist on the machine they are looking at.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\QueryCatalog;
use GlpiPlugin\Glpiosquery\Targeting;

Session::checkRight('plugin_glpiosquery_livequery', READ);

$platform = isset($_GET['platform']) ? (string) $_GET['platform'] : null;
$catalog  = QueryCatalog::withDiscovered($platform);

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
// The catalog only changes when the pinned osquery version does or when a
// published extension's tables are discovered, so let the browser keep it
// rather than re-shipping 270 KB on every console visit. The window is short
// enough that an administrator who has just rolled out an extension does not
// have to be told to hard-refresh.
header('Cache-Control: private, max-age=300');

echo json_encode([
    'osquery_version' => $catalog['osquery_version'],
    'tables'          => $catalog['tables'],
    'can_raw_sql'     => Targeting::canRunRawSql(),
]);
