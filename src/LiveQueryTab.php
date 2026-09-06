<?php
/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Bijstaan
 */

namespace GlpiPlugin\Glpiosquery;

use CommonDBTM;
use CommonGLPI;
use Session;

/**
 * "Live query" tab on an inventoried asset.
 *
 * Targets exactly the machine being viewed, and narrows the editor's
 * completions to that machine's platform — offering a Linux box `bitlocker_info`
 * would be teaching the operator something untrue about the asset in front of
 * them.
 */
class LiveQueryTab extends CommonGLPI
{
    public static $rightname = 'plugin_glpiosquery_livequery';

    public static function getTypeName($nb = 0)
    {
        return __('Live query', 'glpiosquery');
    }

    public static function getIcon()
    {
        return 'ti ti-terminal-2';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if (!Session::haveRight(self::$rightname, READ)) {
            return '';
        }

        // No tab at all on assets that have no osquery agent — an empty console
        // on a machine that cannot answer is a dead end, not a feature.
        if (!$item instanceof CommonDBTM || self::agentFor($item) === null) {
            return '';
        }

        return self::getTypeName();
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if (!$item instanceof CommonDBTM) {
            return false;
        }

        $agent = self::agentFor($item);
        if ($agent === null) {
            return false;
        }

        ConsoleView::render([
            'mode'     => 'device',
            'agent'    => $agent,
            'platform' => (string) ($agent['platform'] ?? ''),
            'items'    => [[
                'itemtype' => $item->getType(),
                'items_id' => (int) $item->getID(),
            ]],
            'initial'  => "SELECT * FROM system_info;",
        ]);

        return true;
    }

    /** The osquery agent reporting for an asset, if there is one. */
    public static function agentFor(CommonDBTM $item): ?array
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($item->isNewItem()) {
            return null;
        }

        foreach (
            $DB->request([
                'FROM'  => Node::TABLE,
                'WHERE' => [
                    'itemtype'   => $item->getType(),
                    'items_id'   => (int) $item->getID(),
                    'is_deleted' => 0,
                    'is_active'  => 1,
                ],
                'LIMIT' => 1,
            ]) as $row
        ) {
            return $row;
        }

        return null;
    }
}
