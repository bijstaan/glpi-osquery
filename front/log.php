<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * osquery --logger_tls_endpoint
 *
 * Receives scheduled query results and agent status lines. Result batches are
 * the inventory feed; status lines are kept briefly for diagnosis.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Endpoint;
use GlpiPlugin\Glpiosquery\ResultIngest;

$payload = Endpoint::payload();
$agent   = Endpoint::requireAgent($payload);

$log_type = (string) ($payload['log_type'] ?? 'result');
$data     = $payload['data'] ?? [];

if (!is_array($data)) {
    Endpoint::respond(['node_invalid' => false]);
}

if ($log_type === 'status') {
    ResultIngest::status((int) $agent['id'], $data);
} else {
    ResultIngest::results((int) $agent['id'], $data);
}

Endpoint::respond(['node_invalid' => false]);
