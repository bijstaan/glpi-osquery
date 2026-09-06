<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonDBTM;
use CommonGLPI;
use GlpiPlugin\Glpiosquery\Inventory\Edid;
use Html;
use Session;

/**
 * "Display details" tab on a Monitor.
 *
 * GLPI's monitor model has room for a size and some connection flags and
 * nothing else: no resolution, no connector, no manufacture date, nowhere for
 * the raw EDID. All of that is collected and then discarded at the point the
 * asset is written, which is a shame because it is the part an engineer
 * actually wants when they are looking at a display.
 *
 * So it is shown here instead, decoded from the EDID the agent reported.
 */
class MonitorTab extends CommonGLPI
{
    public static $rightname = 'plugin_glpiosquery_agent';

    public static function getTypeName($nb = 0)
    {
        return __('Display details', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-device-desktop';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM || !Session::haveRight(self::$rightname, READ)) {
            return '';
        }

        // No tab where there is nothing to show — an empty panel on every
        // monitor in the estate is noise.
        return self::findEdid($item) === null ? '' : self::getTypeName();
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM) {
            return false;
        }

        $found = self::findEdid($item);
        if ($found === null) {
            return false;
        }

        self::render($found['edid'], $found['row'], $found['agent']);

        return true;
    }

    /**
     * Locate the EDID block this monitor was built from.
     *
     * Matching is on what the decode produced — manufacturer, model name and
     * serial — because that is exactly what the inventory used to create the
     * asset, so the two agree by construction.
     *
     * @return array{edid:array,row:array,agent:array}|null
     */
    public static function findEdid(CommonDBTM $monitor): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($monitor->isNewItem()) {
            return null;
        }

        $name         = trim((string) ($monitor->fields['name'] ?? ''));
        $serial       = trim((string) ($monitor->fields['serial'] ?? ''));
        $manufacturer = '';
        if (!empty($monitor->fields['manufacturers_id'])) {
            $manufacturer = (string) \Dropdown::getDropdownName(
                'glpi_manufacturers',
                (int) $monitor->fields['manufacturers_id']
            );
        }

        // Only agents on machines this monitor is actually attached to.
        //
        // Searching every agent would be wrong twice over: on one machine the
        // same panel is reported by more than one agent (whichever row is found
        // first wins, which is why a stale one can shadow a current one), and
        // across an estate two people with the same monitor model would match
        // each other's hardware, since a panel without a serial has nothing
        // else to tell them apart.
        $agents = self::agentsFor($monitor);
        if ($agents === []) {
            return null;
        }

        foreach (
            $DB->request([
                'SELECT'     => ['s.data', 's.plugin_glpiosquery_agents_id', 'a.name AS agent_name', 'a.id AS agent_id'],
                'FROM'       => ResultIngest::SNAPSHOT_TABLE . ' AS s',
                'INNER JOIN' => [
                    Node::TABLE . ' AS a' => ['ON' => ['s' => 'plugin_glpiosquery_agents_id', 'a' => 'id']],
                ],
                'WHERE'      => [
                    's.query_name' => ['inv_monitor_edid', 'inv_monitor_edid_linux'],
                    's.plugin_glpiosquery_agents_id' => $agents,
                ],
                // Newest collection first, so a current reading always wins over
                // one taken before the agent learned to report more.
                'ORDER'      => ['s.date_mod DESC'],
            ]) as $snapshot
        ) {
            $rows = json_decode((string) $snapshot['data'], true);
            if (!is_array($rows)) {
                continue;
            }

            foreach ($rows as $row) {
                $edid = Edid::parse((string) ($row['data'] ?? ''));
                if ($edid === null) {
                    continue;
                }

                $matches = ($serial !== '' && $serial === (string) $edid['serial'])
                    || ($name !== '' && $name === (string) $edid['name'])
                    || ($manufacturer !== '' && $name !== ''
                        && $manufacturer === (string) $edid['manufacturer']);

                if ($matches) {
                    return [
                        'edid'  => $edid,
                        'row'   => $row,
                        'agent' => [
                            'id'   => (int) $snapshot['agent_id'],
                            'name' => (string) $snapshot['agent_name'],
                        ],
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Agents running on the machines this monitor is connected to.
     *
     * @return array<int,int>
     */
    private static function agentsFor(CommonDBTM $monitor): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        // GLPI 11 renamed the peripheral link table; fall back rather than
        // fatally assuming one name.
        $link_table = null;
        foreach (['glpi_assets_assets_peripheralassets', 'glpi_computers_items'] as $candidate) {
            if ($DB->tableExists($candidate)) {
                $link_table = $candidate;
                break;
            }
        }
        if ($link_table === null) {
            return [];
        }

        $hosts = [];
        if ($link_table === 'glpi_assets_assets_peripheralassets') {
            foreach (
                $DB->request([
                    'SELECT' => ['itemtype_asset', 'items_id_asset'],
                    'FROM'   => $link_table,
                    'WHERE'  => [
                        'itemtype_peripheral' => $monitor->getType(),
                        'items_id_peripheral' => $monitor->getID(),
                    ],
                ]) as $row
            ) {
                $hosts[] = [(string) $row['itemtype_asset'], (int) $row['items_id_asset']];
            }
        } else {
            foreach (
                $DB->request([
                    'SELECT' => ['computers_id'],
                    'FROM'   => $link_table,
                    'WHERE'  => ['itemtype' => $monitor->getType(), 'items_id' => $monitor->getID()],
                ]) as $row
            ) {
                $hosts[] = ['Computer', (int) $row['computers_id']];
            }
        }

        if ($hosts === []) {
            return [];
        }

        $or = [];
        foreach ($hosts as [$itemtype, $items_id]) {
            $or[] = ['itemtype' => $itemtype, 'items_id' => $items_id];
        }

        $agents = [];
        foreach (
            $DB->request([
                'SELECT' => ['id'],
                'FROM'   => Node::TABLE,
                'WHERE'  => [['OR' => $or], 'is_deleted' => 0],
            ]) as $row
        ) {
            $agents[] = (int) $row['id'];
        }

        return $agents;
    }

    private static function render(array $edid, array $row, array $agent): void
    {
        $connector = Edid::connector((string) ($row['path'] ?? ''));

        // The kernel's preferred mode is more trustworthy than anything decoded
        // here, because a native timing can live in a DisplayID extension block
        // this parser does not read.
        $preferred = trim((string) ($row['preferred_mode'] ?? ''));

        $fields = [
            __('Manufacturer')                  => $edid['manufacturer'],
            __('Model', 'glpiosquery')          => $edid['name'],
            __('Product code', 'glpiosquery')   => $edid['product_code'],
            __('Serial number')                 => $edid['serial'],
            __('Alternate serial', 'glpiosquery') => $edid['alt_serial'],
            __('Resolution', 'glpiosquery')     => $preferred !== ''
                ? $preferred . ' <span class="text-muted small">(' . __('kernel preferred mode', 'glpiosquery') . ')</span>'
                : (string) $edid['resolution'],
            __('Screen size', 'glpiosquery')    => $edid['size_inches'] > 0 ? $edid['size_inches'] . '"' : '',
            __('Connector', 'glpiosquery')      => $connector['port'],
            __('Connection', 'glpiosquery')     => $edid['interface'] ?: $connector['kind'],
            __('Signal', 'glpiosquery')         => $edid['digital'] ? __('Digital', 'glpiosquery') : __('Analog', 'glpiosquery'),
            __('Manufactured', 'glpiosquery')   => isset($edid['year'])
                ? (isset($edid['week']) ? sprintf(__('week %1$s of %2$s', 'glpiosquery'), $edid['week'], $edid['year']) : (string) $edid['year'])
                : '',
            __('EDID version', 'glpiosquery')   => $edid['edid_version'],
            __('Connector state', 'glpiosquery') => (string) ($row['status'] ?? ''),
            __('Reported by', 'glpiosquery')    => '<a href="' . Url::to('front/agent.form.php?id=' . $agent['id']) . '">'
                                                 . htmlspecialchars($agent['name']) . '</a>',
        ];

        echo "<div class='card glpiosquery-surface'><div class='card-body'>";
        echo "<div class='row'>";
        foreach ($fields as $label => $value) {
            $value = trim((string) $value);
            if ($value === '') {
                continue;
            }
            echo "<div class='col-md-3 mb-3'>";
            echo "<div class='text-muted small'>" . htmlspecialchars($label) . "</div>";
            echo "<div>" . $value . "</div>";
            echo "</div>";
        }
        echo "</div>";

        $hex = preg_replace('/\s+/', '', (string) ($row['data'] ?? '')) ?? '';
        if ($hex !== '') {
            echo "<details class='mt-2'>";
            echo "<summary class='text-muted'>"
               . sprintf(__('Raw EDID (%s bytes)', 'glpiosquery'), (int) (strlen($hex) / 2))
               . "</summary>";
            echo "<pre class='mt-2 small' style='white-space:pre-wrap;word-break:break-all'>"
               . htmlspecialchars(strtoupper(chunk_split($hex, 32, "\n")))
               . "</pre>";
            echo "<p class='text-muted small'>"
               . __('GLPI stores this block on the monitor, but has no field for the resolution, '
                  . 'connector or manufacture date decoded from it — which is why they are shown here.', 'glpiosquery')
               . "</p>";
            echo "</details>";
        }

        echo "</div></div>";
    }
}
