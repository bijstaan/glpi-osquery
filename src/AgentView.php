<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Config;
use Html;
use Session;

/**
 * Rendering for the agent management screens.
 *
 * Kept apart from the Agent model so the model stays about data and rights,
 * and so the hot-path code never pulls presentation in behind it.
 */
final class AgentView
{
    /** Fleet summary shown above the list. */
    public static function showFleetSummary(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $window   = max(60, (int) ($settings['offline_after'] ?? 900));
        $cutoff   = date('Y-m-d H:i:s', time() - $window);

        $total = $online = $quarantined = $never = 0;
        $stale_inventory = 0;
        $stale_before = date('Y-m-d H:i:s', time() - 86400);

        foreach (
            $DB->request([
                'SELECT' => ['last_seen', 'is_active', 'last_inventory_at'],
                'FROM'   => Node::TABLE,
                'WHERE'  => ['is_deleted' => 0, 'entities_id' => Targeting::entityScope([])],
            ]) as $row
        ) {
            $total++;
            if (!$row['is_active']) {
                $quarantined++;
                continue;
            }
            if ($row['last_seen'] === null) {
                $never++;
            } elseif ($row['last_seen'] > $cutoff) {
                $online++;
            }
            if ($row['last_inventory_at'] === null || $row['last_inventory_at'] < $stale_before) {
                $stale_inventory++;
            }
        }

        $offline = max(0, $total - $online - $quarantined - $never);

        $cards = [
            ['label' => __('Agents', 'glpiosquery'),       'value' => $total,       'class' => 'bg-blue'],
            ['label' => __('Online', 'glpiosquery'),        'value' => $online,      'class' => 'bg-green'],
            ['label' => __('Offline', 'glpiosquery'),       'value' => $offline,     'class' => 'bg-orange'],
            ['label' => __('Never checked in', 'glpiosquery'), 'value' => $never,    'class' => 'bg-secondary'],
            ['label' => __('Quarantined', 'glpiosquery'),   'value' => $quarantined, 'class' => 'bg-red'],
            // Not an error state by itself — the shipped packs collect daily —
            // but a machine that has not inventoried in 24h alongside being
            // online usually means a query is failing.
            ['label' => __('No inventory in 24h', 'glpiosquery'), 'value' => $stale_inventory, 'class' => 'bg-yellow'],
        ];

        echo "<div class='row row-cards mb-3'>";
        foreach ($cards as $card) {
            echo "<div class='col-6 col-md-2'>";
            echo "<div class='card'><div class='card-body p-2 text-center'>";
            echo "<div class='h1 m-0'>" . (int) $card['value'] . "</div>";
            echo "<div class='text-muted small'>" . htmlspecialchars($card['label']) . "</div>";
            echo "</div>";
            echo "<div class='progress progress-sm card-progress'>"
               . "<div class='progress-bar " . $card['class'] . "' style='width:100%'></div></div>";
            echo "</div></div>";
        }
        echo "</div>";

        self::showVersionSpread();
    }

    /**
     * Version spread across the fleet.
     *
     * The single most useful thing to see about a self-updating fleet, because
     * it is where a stalled or rolled-back update becomes visible.
     */
    private static function showVersionSpread(): void
    {
        $agent   = AgentUpdate::versionSpread('agent_version');
        $osquery = AgentUpdate::versionSpread('osquery_version');

        if ($agent === [] && $osquery === []) {
            return;
        }

        echo "<div class='row mb-3'>";
        foreach (
            [
                [__('Agent versions', 'glpiosquery'), $agent],
                [__('osquery versions', 'glpiosquery'), $osquery],
            ] as [$title, $spread]
        ) {
            echo "<div class='col-md-6'><div class='card'>";
            echo "<div class='card-header py-2'><h4 class='card-title mb-0'>" . $title . "</h4></div>";
            echo "<div class='card-body p-2'>";
            if ($spread === []) {
                echo "<span class='text-muted'>" . __('No agents yet.', 'glpiosquery') . "</span>";
            }
            foreach ($spread as $row) {
                $label = $row['version'] !== '' ? $row['version'] : __('unknown', 'glpiosquery');
                echo "<span class='badge bg-blue-lt me-2 mb-1'>"
                   . htmlspecialchars($label) . " <strong>" . $row['cpt'] . "</strong></span>";
            }
            echo "</div></div></div>";
        }
        echo "</div>";
    }

    /** The single-agent form. */
    public static function showForm(Agent $agent): void
    {
        $settings = Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $window   = max(60, (int) ($settings['offline_after'] ?? 900));
        $f        = $agent->fields;

        echo "<div class='card'><div class='card-body'>";

        echo "<div class='d-flex align-items-center mb-3 gap-2'>";
        echo "<h3 class='m-0'>" . htmlspecialchars((string) $f['name']) . "</h3>";
        echo Agent::statusBadge($f['last_seen'] ?? null, $window, (bool) $f['is_active'], (bool) $f['is_deleted']);
        echo "</div>";

        $item = $agent->getLinkedItem();

        $rows = [
            __('Device id', 'glpiosquery')       => $f['deviceid'],
            __('Inventoried asset', 'glpiosquery') => $item !== null
                ? $item->getLink()
                : "<span class='text-muted'>" . __('not yet inventoried', 'glpiosquery') . "</span>",
            __('Platform', 'glpiosquery')        => trim(($f['os_name'] ?? '') . ' ' . ($f['os_version'] ?? '')) ?: $f['platform'],
            __('Architecture', 'glpiosquery')    => $f['arch'],
            __('Agent version', 'glpiosquery')   => $f['agent_version'],
            __('osquery version', 'glpiosquery') => $f['osquery_version'],
            __('Address', 'glpiosquery')         => $f['remote_addr'],
            __('Serial number')                  => $f['hardware_serial'],
            __('Hardware UUID', 'glpiosquery')   => $f['hardware_uuid'],
            __('Enrolled', 'glpiosquery')        => $f['enrolled_at'] ? Html::convDateTime($f['enrolled_at']) : '',
            __('Last check-in', 'glpiosquery')   => $f['last_seen'] ? Html::convDateTime($f['last_seen']) : '',
            __('Last config fetch', 'glpiosquery') => $f['last_config_at'] ? Html::convDateTime($f['last_config_at']) : '',
            __('Last inventory', 'glpiosquery')  => $f['last_inventory_at'] ? Html::convDateTime($f['last_inventory_at']) : '',
        ];

        echo "<div class='row'>";
        foreach ($rows as $label => $value) {
            $value = (string) $value;
            echo "<div class='col-md-4 mb-3'>";
            echo "<div class='text-muted small'>" . htmlspecialchars($label) . "</div>";
            echo "<div>" . ($value !== '' ? $value : "<span class='text-muted'>&mdash;</span>") . "</div>";
            echo "</div>";
        }
        echo "</div>";

        self::showExtensions($f);

        if (Session::haveRight(Agent::$rightname, UPDATE)) {
            self::showActions($agent);
        }

        echo "</div></div>";
    }

    /**
     * Published extensions on this endpoint, and whether they are working.
     *
     * "Installed" is what the agent says is on disk; "providing" is what
     * osquery says actually registered. They come apart in the case that
     * matters — an extension whose table name is already taken is refused by
     * osquery and then restarted forever by its watchdog, so it downloads
     * cleanly, installs cleanly, and does nothing. Showing only what was
     * offered would report that endpoint as healthy.
     *
     * @param array<string,mixed> $agent the agent row
     */
    private static function showExtensions(array $agent): void
    {
        $installed = Extension::installedOn($agent);
        if ($installed === []) {
            return;
        }

        $silent  = Extension::silentOn($agent);
        $bundled = array_flip(QueryCatalog::bundledExtensionTables());

        $published = [];
        foreach (Extension::tablesOn((int) $agent['id']) as $table) {
            if (!isset($bundled[$table])) {
                $published[] = $table;
            }
        }

        echo "<div class='mt-2'>";
        echo "<div class='text-muted small'>" . __('Published extensions', 'glpiosquery') . "</div>";
        echo "<div>";
        foreach ($installed as $name) {
            $failing = in_array($name, $silent, true);
            echo "<span class='badge me-1 " . ($failing ? "bg-red" : "bg-green") . "'>"
               . htmlspecialchars($name) . "</span>";
        }
        echo "</div>";

        if ($silent !== []) {
            echo "<div class='text-danger small mt-1'>"
               . __('Installed but registering no tables. The usual cause is a table name already '
                  . 'claimed by another extension: osquery refuses the duplicate and the extension '
                  . 'restarts in a loop.', 'glpiosquery')
               . "</div>";
        } elseif ($published !== []) {
            echo "<div class='text-muted small mt-1'>"
               . htmlspecialchars(sprintf(__('Providing: %s', 'glpiosquery'), implode(', ', $published)))
               . "</div>";
        }

        echo "</div>";
    }

    private static function showActions(Agent $agent): void
    {
        $csrf = Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
        $id   = (int) $agent->getID();

        echo "<hr>";
        echo "<div class='d-flex gap-2 flex-wrap'>";

        echo "<form method='post' class='d-inline'>" . $csrf
           . "<input type='hidden' name='id' value='$id'>";
        if ($agent->fields['is_active']) {
            echo "<button type='submit' name='quarantine' value='1' class='btn btn-outline-danger'>"
               . "<i class='ti ti-shield-off me-1'></i>" . __('Quarantine', 'glpiosquery') . "</button>";
        } else {
            echo "<button type='submit' name='reinstate' value='1' class='btn btn-outline-success'>"
               . "<i class='ti ti-shield-check me-1'></i>" . __('Reinstate', 'glpiosquery') . "</button>";
        }
        echo "</form>";

        echo "<form method='post' class='d-inline'>" . $csrf
           . "<input type='hidden' name='id' value='$id'>"
           . "<button type='submit' name='reenroll' value='1' class='btn btn-outline-secondary'>"
           . "<i class='ti ti-refresh me-1'></i>" . __('Force re-enrolment', 'glpiosquery') . "</button></form>";

        echo "<form method='post' class='d-inline'>" . $csrf
           . "<input type='hidden' name='id' value='$id'>"
           . "<button type='submit' name='reinventory' value='1' class='btn btn-outline-primary'>"
           . "<i class='ti ti-cloud-download me-1'></i>" . __('Rebuild inventory', 'glpiosquery') . "</button></form>";

        echo "</div>";

        echo "<p class='text-muted small mt-2'>"
           . __('Quarantine stops the agent being accepted without deleting anything it has reported. '
              . 'Force re-enrolment clears its credentials so it enrols again with its secret.', 'glpiosquery')
           . "</p>";
    }

    /** What this agent has actually collected. */
    public static function showSnapshots(Agent $agent): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        echo "<div class='table-responsive'>";
        echo "<table class='table table-hover'>";
        echo "<thead><tr>"
           . "<th>" . __('Query', 'glpiosquery') . "</th>"
           . "<th>" . __('Rows', 'glpiosquery') . "</th>"
           . "<th>" . __('Collected', 'glpiosquery') . "</th>"
           . "<th>" . __('Feeds', 'glpiosquery') . "</th>"
           . "</tr></thead><tbody>";

        $sections = [];
        foreach (
            $DB->request([
                'SELECT' => ['name', 'glpi_section'],
                'FROM'   => 'glpi_plugin_glpiosquery_queries',
            ]) as $row
        ) {
            $sections[(string) $row['name']] = (string) ($row['glpi_section'] ?? '');
        }

        $any = false;
        foreach (
            $DB->request([
                'FROM'  => ResultIngest::SNAPSHOT_TABLE,
                'WHERE' => ['plugin_glpiosquery_agents_id' => $agent->getID()],
                'ORDER' => ['query_name'],
            ]) as $row
        ) {
            $any = true;
            $name = (string) $row['query_name'];

            echo "<tr>";
            echo "<td><code>" . htmlspecialchars($name) . "</code></td>";
            // A zero-row snapshot is a real answer, not a gap: the query ran and
            // the machine genuinely has none of that thing.
            echo "<td>" . (int) $row['row_count'] . "</td>";
            echo "<td>" . Html::convDateTime((string) $row['date_mod']) . "</td>";
            echo "<td class='text-muted'>" . htmlspecialchars($sections[$name] ?? '') . "</td>";
            echo "</tr>";
        }

        if (!$any) {
            echo "<tr><td colspan='4' class='text-muted'>"
               . __('Nothing collected yet. Scheduled queries run on their own interval after the agent starts.', 'glpiosquery')
               . "</td></tr>";
        }

        echo "</tbody></table></div>";
    }

    /** Recent warnings and errors reported by the endpoint. */
    public static function showStatusLog(Agent $agent): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        echo "<div class='table-responsive'>";
        echo "<table class='table table-sm table-hover'>";
        echo "<thead><tr>"
           . "<th>" . __('When', 'glpiosquery') . "</th>"
           . "<th>" . __('Severity', 'glpiosquery') . "</th>"
           . "<th>" . __('Source', 'glpiosquery') . "</th>"
           . "<th>" . __('Message', 'glpiosquery') . "</th>"
           . "</tr></thead><tbody>";

        $any = false;
        foreach (
            $DB->request([
                'FROM'  => ResultIngest::STATUS_TABLE,
                'WHERE' => ['plugin_glpiosquery_agents_id' => $agent->getID()],
                'ORDER' => ['logged_at DESC'],
                'LIMIT' => 200,
            ]) as $row
        ) {
            $any = true;
            $severity = (int) $row['severity'];

            echo "<tr>";
            echo "<td class='text-nowrap'>" . Html::convDateTime((string) $row['logged_at']) . "</td>";
            echo "<td>" . ($severity >= 2
                ? "<span class='badge bg-red'>" . __('Error') . "</span>"
                : "<span class='badge bg-orange'>" . __('Warning') . "</span>") . "</td>";
            echo "<td><code class='small'>" . htmlspecialchars((string) $row['filename']) . "</code></td>";
            echo "<td class='small'>" . htmlspecialchars((string) $row['message']) . "</td>";
            echo "</tr>";
        }

        if (!$any) {
            echo "<tr><td colspan='4' class='text-muted'>"
               . __('No warnings or errors reported. Only severity warning and above is kept — osquery '
                  . 'logs an informational line for every scheduled query, and storing all of it would '
                  . 'cost more than it tells you.', 'glpiosquery')
               . "</td></tr>";
        }

        echo "</tbody></table></div>";
    }
}
