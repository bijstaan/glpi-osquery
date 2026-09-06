<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use Html;
use Session;

/**
 * Markup for the live-query console.
 *
 * One renderer serves both placements — the fleet-wide console under Setup and
 * the tab on an individual Computer — because they differ only in how targets
 * are chosen. Anything else would drift.
 */
final class ConsoleView
{
    /**
     * @param array $options {
     *   mode:      'global'|'device'
     *   items:     array   device mode: [['itemtype'=>'Computer','items_id'=>11]]
     *   platform:  string  device mode: narrows completions to that machine's OS
     *   agent:     ?array  device mode: the agent row, for the status line
     *   initial:   string  starting SQL
     * }
     */
    public static function render(array $options = []): void
    {
        $mode     = $options['mode'] ?? 'global';
        // GLPI's own idiom for keeping two consoles on one page from sharing a
        // DOM id. Not a token and never checked against anything, so mt_rand is
        // the right tool: predicting it buys an attacker the ability to guess an
        // element id they can already read out of the document.
        $rand     = mt_rand();
        $root_id  = "osq-console-$rand";
        $editor_id = "osq-editor-$rand";

        $can_raw = Targeting::canRunRawSql();

        // Monaco's stylesheet is bundled with GLPI but is not loaded globally —
        // only pages that use an editor pull it in. Without it the editor still
        // renders, which makes the omission easy to miss, but the suggest
        // widget loses its absolute positioning and the completion list stacks
        // every row on top of the first.
        //
        // Both paths are unprefixed: Html::css adds root_doc itself.
        echo Html::css('/lib/monaco.min.css', [], false);
        echo Html::css(
            Url::path('css/console.css'),
            ['version' => Url::assetVersion('css/console.css')],
            false
        );
        echo "<div id='" . htmlspecialchars($root_id) . "' class='osq-console glpiosquery-surface'>";

        if (!$can_raw) {
            // Say so up front rather than letting someone compose a query and
            // meet a 403 on Run — and if the cause is a session that predates
            // the permission, say that instead, because the admin screens will
            // show the right as granted and the denial looks inexplicable.
            $stale = Targeting::isStaleSessionFor('plugin_glpiosquery_rawsql');
            echo "<div class='alert " . ($stale ? 'alert-warning' : 'alert-info') . "'>";
            echo $stale
                ? __('You have the free-form query right, but this session was opened before it was '
                   . 'granted and still has the old permissions. Sign out and back in to use the editor.', 'glpiosquery')
                : __('You can run saved queries. Writing your own SQL requires the free-form query right.', 'glpiosquery');
            echo "</div>";
        }

        if ($mode === 'device') {
            self::renderDeviceHeader($options['agent'] ?? null);
        }

        echo "<div class='row g-3'>";

        // ------------------------------------------------------ schema browser
        echo "<div class='col-lg-3'>";
        echo "<div class='card h-100'>";
        echo "<div class='card-header py-2'><h4 class='card-title mb-0'>"
           . __('osquery tables', 'glpiosquery')
           . " <span class='badge bg-secondary' data-osq-schema-count>0</span></h4></div>";
        echo "<div class='card-body p-2'>";
        echo "<input type='search' class='form-control form-control-sm mb-2' data-osq-schema-filter "
           . "placeholder='" . __('Filter tables…', 'glpiosquery') . "'>";
        echo "<div class='list-group list-group-flush' data-osq-schema-list "
           . "style='max-height: 420px; overflow-y: auto;'></div>";
        echo "</div></div>";
        echo "</div>";

        // -------------------------------------------------------------- editor
        echo "<div class='col-lg-9'>";

        if ($mode === 'global') {
            self::renderTargets();
        }

        self::renderSavedQueries($options);

        echo "<div class='card mb-2'>";
        echo "<div id='" . htmlspecialchars($editor_id) . "' style='height: 190px; border-bottom: 1px solid var(--tblr-border-color);'></div>";
        echo "<div class='card-body py-2 d-flex align-items-center gap-2'>";
        echo "<button type='button' class='btn btn-primary' data-osq-run>"
           . "<i class='ti ti-player-play me-1'></i>" . __('Run', 'glpiosquery')
           . " <span class='text-white-50 ms-1 small'>Ctrl+&crarr;</span></button>";
        echo "<button type='button' class='btn btn-outline-secondary' data-osq-stop disabled>"
           . __('Stop watching', 'glpiosquery') . "</button>";
        echo "<button type='button' class='btn btn-outline-secondary' data-osq-export disabled>"
           . "<i class='ti ti-download me-1'></i>" . __('Export CSV', 'glpiosquery') . "</button>";
        echo "<div class='ms-auto text-muted small'>"
           . sprintf(__('%s rows', 'glpiosquery'), "<span data-osq-rowcount>0</span>")
           . "</div>";
        echo "</div></div>";

        echo "<div class='alert' data-osq-status style='display:none'></div>";

        // Progress is shown as answered-of-targeted, never as a bare success
        // count: an operator needs to see who did not reply.
        echo "<div data-osq-progress style='display:none'>";
        echo "<div class='d-flex justify-content-between small text-muted mb-1'>";
        echo "<span>" . sprintf(
            __('%1$s of %2$s agents answered', 'glpiosquery'),
            "<strong data-osq-answered>0</strong>",
            "<span data-osq-total>0</span>"
        ) . "</span>";
        echo "</div>";
        echo "<div class='progress mb-2' style='height:4px'>"
           . "<div class='progress-bar' data-osq-bar style='width:0%'></div></div>";
        echo "</div>";

        echo "<div class='alert alert-warning' data-osq-errors style='display:none'></div>";

        echo "<div class='card'><div class='table-responsive' style='max-height: 480px; overflow:auto;'>";
        echo "<table class='table table-sm table-hover card-table' data-osq-results>";
        echo "<thead></thead><tbody></tbody>";
        echo "</table>";
        echo "</div></div>";

        echo "</div>"; // col
        echo "</div>"; // row
        echo "</div>"; // root

        self::renderScript($root_id, $editor_id, $options);
    }

    private static function renderDeviceHeader(?array $agent): void
    {
        if ($agent === null) {
            return;
        }

        $settings = \Config::getConfigurationValues(PLUGIN_GLPIOSQUERY_CONFIG_CONTEXT);
        $offline  = (int) ($settings['offline_after'] ?? 900);
        $seen     = !empty($agent['last_seen']) ? strtotime((string) $agent['last_seen']) : 0;
        $online   = $seen > time() - $offline;

        echo "<div class='d-flex align-items-center gap-2 mb-3'>";
        echo $online
            ? "<span class='badge bg-green'>" . __('Online', 'glpiosquery') . "</span>"
            : "<span class='badge bg-secondary'>" . __('Offline', 'glpiosquery') . "</span>";
        echo "<span class='text-muted small'>";
        echo sprintf(
            __('osquery %1$s on %2$s — last check-in %3$s', 'glpiosquery'),
            htmlspecialchars((string) ($agent['osquery_version'] ?? '?')),
            htmlspecialchars((string) ($agent['platform'] ?? '?')),
            $seen > 0 ? Html::convDateTime(date('Y-m-d H:i:s', $seen)) : __('never', 'glpiosquery')
        );
        echo "</span>";

        if (!$online) {
            echo "<span class='text-warning small'>"
               . __('An offline agent will answer when it next checks in, or the query will time out.', 'glpiosquery')
               . "</span>";
        }
        echo "</div>";
    }

    /**
     * The saved query picker.
     *
     * Shown to everyone with the live-query right, because these are the only
     * queries a user without the free-form right may run at all.
     */
    private static function renderSavedQueries(array $options): void
    {
        $platform = QueryCatalog::normalisePlatform((string) ($options['platform'] ?? ''));
        $queries  = SavedQuery::selectable($platform !== '' ? $platform : null);

        if ($queries === []) {
            return;
        }

        echo "<div class='card mb-2'><div class='card-body py-2 d-flex align-items-center gap-2'>";
        echo "<label class='form-label mb-0 text-nowrap'>" . __('Saved query', 'glpiosquery') . "</label>";
        echo "<select class='form-select form-select-sm' data-osq-saved style='max-width:26rem'>";
        echo "<option value=''>" . __('— choose —', 'glpiosquery') . "</option>";
        foreach ($queries as $query) {
            echo "<option value='" . (int) $query['id'] . "'>"
               . htmlspecialchars((string) $query['name']) . "</option>";
        }
        echo "</select>";
        echo "<span class='text-muted small' data-osq-saved-description></span>";
        echo "</div></div>";
    }

    private static function renderTargets(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        echo "<div class='card mb-2'><div class='card-body py-2'>";
        echo "<div class='row g-2 align-items-end'>";

        // Entities: only those the operator is active in — this is the ceiling
        // on what any campaign can reach, so it is never a free-text field.
        $scope = Targeting::entityScope([]);
        echo "<div class='col-md-4'>";
        echo "<label class='form-label small mb-1'>" . __('Entities') . "</label>";
        echo "<select class='form-select form-select-sm' data-osq-entities multiple size='3'>";
        if ($scope !== []) {
            foreach (
                $DB->request([
                    'SELECT' => ['id', 'completename'],
                    'FROM'   => 'glpi_entities',
                    'WHERE'  => ['id' => $scope],
                    'ORDER'  => ['completename'],
                ]) as $entity
            ) {
                echo "<option value='" . (int) $entity['id'] . "'>"
                   . htmlspecialchars((string) $entity['completename']) . "</option>";
            }
        }
        echo "</select>";
        echo "<div class='form-text'>" . __('Empty = everything you can see', 'glpiosquery') . "</div>";
        echo "</div>";

        echo "<div class='col-md-4'>";
        echo "<label class='form-label small mb-1'>" . __('Groups') . "</label>";
        echo "<select class='form-select form-select-sm' data-osq-groups multiple size='3'>";
        if ($scope !== []) {
            foreach (
                $DB->request([
                    'SELECT' => ['id', 'completename'],
                    'FROM'   => 'glpi_groups',
                    'WHERE'  => ['entities_id' => $scope],
                    'ORDER'  => ['completename'],
                    'LIMIT'  => 500,
                ]) as $group
            ) {
                echo "<option value='" . (int) $group['id'] . "'>"
                   . htmlspecialchars((string) $group['completename']) . "</option>";
            }
        }
        echo "</select>";
        echo "<div class='form-text'>" . __('Matched on the inventoried asset', 'glpiosquery') . "</div>";
        echo "</div>";

        echo "<div class='col-md-2'>";
        echo "<label class='form-label small mb-1'>" . __('Platform', 'glpiosquery') . "</label>";
        echo "<select class='form-select form-select-sm' data-osq-platforms multiple size='3'>";
        foreach (['linux' => 'Linux', 'darwin' => 'macOS', 'windows' => 'Windows'] as $value => $label) {
            echo "<option value='$value'>$label</option>";
        }
        echo "</select>";
        echo "</div>";

        echo "<div class='col-md-2'>";
        echo "<label class='form-check form-switch'>";
        echo "<input class='form-check-input' type='checkbox' data-osq-online checked>";
        echo "<span class='form-check-label small'>" . __('Online agents only', 'glpiosquery') . "</span>";
        echo "</label>";
        echo "</div>";

        echo "</div></div></div>";
    }

    /** @return array<int,array<string,mixed>> */
    private static function savedQueryPayload(array $options): array
    {
        $platform = QueryCatalog::normalisePlatform((string) ($options['platform'] ?? ''));
        $out = [];

        foreach (SavedQuery::selectable($platform !== '' ? $platform : null) as $query) {
            $out[] = [
                'id'          => (int) $query['id'],
                'name'        => (string) $query['name'],
                'description' => (string) ($query['description'] ?? ''),
                'sql'         => (string) $query['sql_query'],
            ];
        }

        return $out;
    }

    private static function renderScript(string $root_id, string $editor_id, array $options): void
    {
        $config = [
            'rootId'     => $root_id,
            'editorId'   => $editor_id,
            'mode'       => $options['mode'] ?? 'global',
            'items'      => $options['items'] ?? [],
            'platform'   => QueryCatalog::normalisePlatform((string) ($options['platform'] ?? '')),
            'initialSql' => $options['initial'] ?? "SELECT * FROM system_info;",
            'savedQueries' => self::savedQueryPayload($options),
            'canRawSql'    => $can_raw,
            'endpoints'  => [
                'schema'  => Url::to('ajax/schema.php'),
                'launch'  => Url::to('ajax/launch.php'),
                'results' => Url::to('ajax/results.php'),
            ],
        ];

        $json = json_encode($config, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

        global $CFG_GLPI;
        $root = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/');
        $monaco_module = json_encode($root . '/js/modules/Monaco/MonacoEditor.js');

        // public/js/console.js is served as /plugins/glpiosquery/js/console.js
        // (unprefixed here — Html::script adds root_doc). The explicit version
        // is what stops browsers pinning an old copy: see Url::assetVersion.
        echo Html::script(
            Url::path('js/console.js'),
            ['version' => Url::assetVersion('js/console.js')],
            false
        );

        // GLPI only defines window.GLPI.Monaco on pages that import its module;
        // it is not a global that happens to be there.
        //
        // The import is a *dynamic* import inside a classic script rather than
        // a <script type="module"> block, because this same markup is served
        // into an AJAX-loaded tab on the Computer form. Injected HTML does not
        // execute module scripts, so a module block works on the standalone
        // console page and silently does nothing in the tab — while still
        // resolving through the page's importmap either way.
        echo "<script>
            (function () {
                function boot() {
                    if (!window.GlpiOsquery || !window.GLPI || !window.GLPI.Monaco) {
                        window.setTimeout(boot, 50);
                        return;
                    }
                    window.GlpiOsquery.start($json);
                }

                import($monaco_module).then(boot).catch(function (e) {
                    var el = document.getElementById(" . json_encode($root_id) . ");
                    if (el) {
                        el.insertAdjacentHTML('afterbegin',
                            '<div class=\"alert alert-danger\">' +
                            'The query editor could not be loaded: ' + String(e) + '</div>');
                    }
                });
            })();
        </script>";
    }
}
