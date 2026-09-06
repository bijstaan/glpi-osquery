<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

/**
 * Compliance across the fleet, derived from the security-posture pack.
 */

require_once(__DIR__ . '/../../../front/_check_webserver_config.php');

use GlpiPlugin\Glpiosquery\Agent;
use GlpiPlugin\Glpiosquery\Compliance;
use GlpiPlugin\Glpiosquery\ComplianceMenu;

Session::checkRight(Agent::$rightname, READ);

Html::header(
    __('osquery compliance', 'glpiosquery'),
    $_SERVER['PHP_SELF'],
    class_exists(\GlpiPlugin\Glpinav\Nav::class)
        ? \GlpiPlugin\Glpinav\Nav::sector(ComplianceMenu::class, 'admin')
        : 'admin',
    ComplianceMenu::class
);

$checks = Compliance::checks();
$fleet  = Compliance::fleet();

$totals = [];
foreach (array_keys($checks) as $key) {
    $totals[$key] = [Compliance::PASS => 0, Compliance::FAIL => 0, Compliance::UNKNOWN => 0];
}

foreach ($fleet as $entry) {
    foreach ($entry['results'] as $key => $result) {
        $totals[$key][$result['state']]++;
    }
}

echo "<div class='container-fluid glpiosquery-surface mt-3'>";

// ------------------------------------------------------------------ summary
echo "<div class='row row-cards mb-3'>";
foreach ($checks as $key => $check) {
    $t = $totals[$key];
    echo "<div class='col-md-4'><div class='card'><div class='card-body'>";
    echo "<h4 class='card-title'>" . htmlspecialchars($check['label']) . "</h4>";
    echo "<div class='d-flex gap-3'>";
    echo "<div><span class='badge bg-green'>" . $t[Compliance::PASS] . "</span> " . __('pass', 'glpiosquery') . "</div>";
    echo "<div><span class='badge bg-red'>" . $t[Compliance::FAIL] . "</span> " . __('fail', 'glpiosquery') . "</div>";
    echo "<div><span class='badge bg-secondary'>" . $t[Compliance::UNKNOWN] . "</span> " . __('unknown', 'glpiosquery') . "</div>";
    echo "</div>";
    echo "<div class='text-muted small mt-2'>" . htmlspecialchars($check['description']) . "</div>";
    echo "</div></div></div>";
}
echo "</div>";

// Unknown is called out rather than folded into a pass rate: a fleet reported
// as compliant when a third of it could not be assessed is a false assurance.
$unknown = array_sum(array_column($totals, Compliance::UNKNOWN));
if ($unknown > 0) {
    echo "<div class='alert alert-secondary'>"
       . sprintf(
           __('%s checks could not be assessed — usually an agent that has not reported that data yet, '
            . 'or a machine whose root volume sits behind a device-mapper node. They are counted separately '
            . 'and never as a pass.', 'glpiosquery'),
           $unknown
       )
       . "</div>";
}

// -------------------------------------------------------------------- table
echo "<div class='card'><div class='table-responsive'>";
echo "<table class='table table-hover card-table'>";
echo "<thead><tr><th>" . __('Agent', 'glpiosquery') . "</th><th>" . __('Platform', 'glpiosquery') . "</th>";
foreach ($checks as $check) {
    echo "<th>" . htmlspecialchars($check['label']) . "</th>";
}
echo "</tr></thead><tbody>";

$badges = [
    Compliance::PASS    => "<span class='badge bg-green'>" . __('pass', 'glpiosquery') . "</span>",
    Compliance::FAIL    => "<span class='badge bg-red'>" . __('fail', 'glpiosquery') . "</span>",
    Compliance::UNKNOWN => "<span class='badge bg-secondary'>" . __('unknown', 'glpiosquery') . "</span>",
];

foreach ($fleet as $entry) {
    $agent = $entry['agent'];
    echo "<tr>";
    echo "<td><a href='" . Html::cleanInputText(GlpiPlugin\Glpiosquery\Url::to('front/agent.form.php?id=' . (int) $agent['id'])) . "'>"
       . htmlspecialchars((string) $agent['name']) . "</a></td>";
    echo "<td class='text-muted'>" . htmlspecialchars(trim((string) $agent['os_name'] . ' ' . (string) $agent['os_version'])) . "</td>";

    foreach (array_keys($checks) as $key) {
        echo "<td>";
        if (!isset($entry['results'][$key])) {
            // The check does not apply to this platform: say so rather than
            // showing a pass or a failure for something never assessed.
            echo "<span class='text-muted small'>" . __('n/a', 'glpiosquery') . "</span>";
        } else {
            echo $badges[$entry['results'][$key]['state']];
            $detail = $entry['results'][$key]['detail'];
            if ($detail !== '') {
                echo "<div class='text-muted small'>" . htmlspecialchars($detail) . "</div>";
            }
        }
        echo "</td>";
    }
    echo "</tr>";
}

if ($fleet === []) {
    echo "<tr><td colspan='" . (count($checks) + 2) . "' class='text-muted'>"
       . __('No agents to assess yet.', 'glpiosquery') . "</td></tr>";
}

echo "</tbody></table></div></div>";
echo "</div>";

Html::footer();
