<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonGLPI;
use Html;
use Session;
use Ticket;

/**
 * "Machine state" tab on a ticket.
 *
 * Exists for the second capture rather than the first. The first is automatic;
 * what a technician needs is a way to take another reading after doing
 * something — freeing memory, adding RAM, clearing a disk — so the ticket
 * carries evidence that the work had an effect, rather than an assertion that
 * it did.
 */
class TicketEvidenceTab extends CommonGLPI
{
    public static $rightname = 'plugin_glpiosquery_agent';

    public static function getTypeName($nb = 0)
    {
        return __('Machine state', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-stethoscope';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!($item instanceof Ticket) || !Session::haveRight(self::$rightname, READ)) {
            return '';
        }

        // No tab where there is no osquery-managed asset: an empty panel on a
        // ticket about a printer is a dead end, not a feature.
        if (self::assetsFor((int) $item->getID()) === []) {
            return '';
        }

        return self::getTypeName();
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!($item instanceof Ticket)) {
            return false;
        }

        $tickets_id = (int) $item->getID();
        $assets     = self::assetsFor($tickets_id);
        if ($assets === []) {
            return false;
        }

        /** @var \DBmysql $DB */
        global $DB;

        echo "<div class='p-3 glpiosquery-surface'>";

        echo "<p class='text-muted'>"
           . __('Takes a fresh reading from the machine and posts it to the timeline. '
              . 'When there is an earlier capture on this ticket, the followup leads with '
              . 'what changed — which is how a fix is shown rather than asserted.', 'glpiosquery')
           . "</p>";

        foreach ($assets as $asset) {
            $name = $asset['name'] !== '' ? $asset['name'] : ('#' . $asset['items_id']);

            echo "<div class='card mb-3'><div class='card-body'>";
            echo "<h4 class='h5'>" . htmlspecialchars($name) . "</h4>";

            if ($asset['agents_id'] === 0) {
                echo "<p class='text-muted'>"
                   . __('This asset has no osquery agent, so it cannot be asked.', 'glpiosquery')
                   . "</p></div></div>";
                continue;
            }

            echo "<form method='post' action='" . Url::to('front/evidence.php') . "'>";
            echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
            echo Html::hidden('tickets_id', ['value' => $tickets_id]);
            echo Html::hidden('itemtype', ['value' => $asset['itemtype']]);
            echo Html::hidden('items_id', ['value' => $asset['items_id']]);
            echo "<button class='btn btn-primary' name='capture_now' value='1'>"
               . "<i class='ti ti-stethoscope me-1'></i>"
               . __('Capture now', 'glpiosquery') . "</button>";
            echo "</form>";

            // Every capture for this asset on this ticket, so the technician can
            // see that a reading is still in flight rather than pressing again.
            echo "<table class='table table-sm mt-3'><thead><tr>"
               . "<th>" . __('Captured', 'glpiosquery') . "</th>"
               . "<th>" . __('Trigger', 'glpiosquery') . "</th>"
               . "<th>" . __('State', 'glpiosquery') . "</th></tr></thead><tbody>";

            $any = false;
            foreach (
                $DB->request([
                    'FROM'  => TicketEvidence::TABLE,
                    'WHERE' => [
                        'tickets_id' => $tickets_id,
                        'itemtype'   => $asset['itemtype'],
                        'items_id'   => $asset['items_id'],
                    ],
                    'ORDER' => ['id DESC'],
                    'LIMIT' => 20,
                ]) as $row
            ) {
                $any = true;
                $state = (string) $row['status'] === TicketEvidence::PENDING
                    ? "<span class='badge bg-secondary'>" . __('collecting…', 'glpiosquery') . "</span>"
                    : "<span class='badge bg-green'>" . htmlspecialchars((string) $row['status']) . "</span>";

                echo "<tr><td>" . htmlspecialchars((string) $row['date_creation']) . "</td>";
                echo "<td>" . ((string) $row['trigger_type'] === TicketEvidence::MANUAL
                    ? __('on request', 'glpiosquery')
                    : __('asset attached', 'glpiosquery')) . "</td>";
                echo "<td>" . $state . "</td></tr>";
            }

            if (!$any) {
                echo "<tr><td colspan='3' class='text-muted'>"
                   . __('Nothing captured yet.', 'glpiosquery') . "</td></tr>";
            }

            echo "</tbody></table>";
            echo "</div></div>";
        }

        echo "</div>";

        return true;
    }

    /**
     * osquery-managed assets on a ticket.
     *
     * @return array<int,array{itemtype:string,items_id:int,name:string,agents_id:int}>
     */
    private static function assetsFor(int $tickets_id): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($tickets_id <= 0) {
            return [];
        }

        $out = [];
        foreach (
            $DB->request([
                'SELECT' => ['itemtype', 'items_id'],
                'FROM'   => 'glpi_items_tickets',
                'WHERE'  => ['tickets_id' => $tickets_id, 'itemtype' => 'Computer'],
            ]) as $link
        ) {
            $agents_id = 0;
            $name      = '';

            foreach (
                $DB->request([
                    'SELECT' => ['id', 'name'],
                    'FROM'   => Node::TABLE,
                    'WHERE'  => [
                        'itemtype'   => $link['itemtype'],
                        'items_id'   => (int) $link['items_id'],
                        'is_deleted' => 0,
                        'is_active'  => 1,
                    ],
                    'LIMIT'  => 1,
                ]) as $agent
            ) {
                $agents_id = (int) $agent['id'];
                $name      = (string) $agent['name'];
            }

            if ($agents_id === 0) {
                continue;
            }

            $out[] = [
                'itemtype'  => (string) $link['itemtype'],
                'items_id'  => (int) $link['items_id'],
                'name'      => $name,
                'agents_id' => $agents_id,
            ];
        }

        return $out;
    }
}
